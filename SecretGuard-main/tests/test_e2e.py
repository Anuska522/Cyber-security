"""End-to-End Verification: Pre-commit workflow, multi-format serialization, and Latency SLAs."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest
import respx
from click.testing import CliRunner

from secretguard.cli import main
from secretguard.config.manager import ConfigManager
from secretguard.config.models import SecretGuardConfig
from secretguard.core.models import DiffLine, ScanContext
from secretguard.gateway.dispatcher import ProviderDispatcher
from secretguard.gateway.key_manager import KeyRotationManager
from secretguard.ingest.git_diff import GitDiffParser
from secretguard.orchestrator import ScanOrchestrator
from secretguard.reporting.json_formatter import JsonReportFormatter
from secretguard.reporting.sarif import SarifReportFormatter
from secretguard.reporting.terminal import TerminalReportFormatter
from secretguard.router.policy import AdaptiveRoutingPolicy
from secretguard.verifier.evaluator import ContextualVerifier


@respx.mock
def test_end_to_end_pre_commit_orchestration_with_ai() -> None:
    """Verify complete pre-commit lifecycle with mixed credentials, AI routing, and report formats."""
    # 1. Setup mock endpoint for Groq AI verification
    respx.post("https://api.groq.com/openai/v1/chat/completions").mock(
        return_value=respx.MockResponse(
            status_code=200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "is_secret": True,
                                    "confidence": 0.94,
                                    "explanation": "High entropy production API token identified.",
                                    "remediation": "Revoke and migrate to environment variables.",
                                }
                            )
                        }
                    }
                ]
            },
        )
    )

    # 2. Configure KeyRotationManager and ContextualVerifier with mock credentials
    key_manager = KeyRotationManager(initial_keys={"groq": ["gsk_e2e_test_key_abc123"]})
    dispatcher = ProviderDispatcher(key_manager=key_manager)
    routing_policy = AdaptiveRoutingPolicy()
    verifier = ContextualVerifier(
        routing_policy=routing_policy,
        key_manager=key_manager,
        provider_client=dispatcher,
    )

    # 3. Simulate staged git diff with mixed credentials:
    # - Valid AWS Key (deterministic regex match)
    # - Dummy placeholder (candidate pre-filter suppression)
    # - Ambiguous high-entropy production token (AI verification)
    synthetic_diff = """diff --git a/services/client.py b/services/client.py
index 0000000..1111111 100644
--- a/services/client.py
+++ b/services/client.py
@@ -1,3 +1,6 @@
+AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
+DATABASE_PASSWORD = "YOUR_API_KEY_HERE"
+API_AUTH_TOKEN = "dGhpcyBpcyBhbiBhbWJpZ3VvdXMgdG9rZW4gZXhhbXBsZQ=="
"""

    class MockDiffIngester:
        def stream_diff_lines(self, context: ScanContext):
            parser = GitDiffParser()
            yield from parser.parse_diff_stream(synthetic_diff.splitlines(keepends=True))

    orchestrator = ScanOrchestrator(
        git_ingester=MockDiffIngester(),
        verifier=verifier,
    )

    context = ScanContext(target_path=".", is_pre_commit=True, diff_mode=True)
    report = orchestrator.run_scan(context)

    # 4. Assert summary metrics and exit code blocking
    assert report.summary.exit_code == 1
    assert report.summary.total_lines_scanned == 3
    assert report.summary.total_files_scanned == 1
    assert report.summary.candidates_filtered == 1  # YOUR_API_KEY_HERE filtered
    assert report.summary.ai_verified_count == 1  # ambiguous token routed to AI
    assert report.summary.true_positive_count == 2  # AWS key + AI-verified token

    # 5. Multi-Format Report Serialization Validation
    terminal_formatter = TerminalReportFormatter(use_color=True)
    terminal_out = terminal_formatter.format_report(report)
    assert "[Regex]" in terminal_out
    assert "[AI Verified]" in terminal_out
    assert "AKIAIOSFODNN7EXAMPLE" not in terminal_out  # Redacted
    assert "DETECTED 2 POTENTIAL SECRET(S)" in terminal_out
    assert "Process Exit Status:" in terminal_out

    json_formatter = JsonReportFormatter(indent=2)
    json_out = json_formatter.format_report(report)
    parsed_json = json.loads(json_out)
    assert parsed_json["summary"]["true_positive_count"] == 2
    assert parsed_json["summary"]["exit_code"] == 1
    assert len(parsed_json["findings"]) == 3

    sarif_formatter = SarifReportFormatter(indent=2)
    sarif_out = sarif_formatter.format_report(report)
    parsed_sarif = json.loads(sarif_out)
    assert parsed_sarif["version"] == "2.1.0"
    assert len(parsed_sarif["runs"][0]["results"]) == 2  # Only active secrets in SARIF


def test_git_pre_commit_cli_workflow(tmp_path: Path) -> None:
    """Verify real git pre-commit workflow: staged secret triggers exit code 1; clean commit passes with 0."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    # Initialize git repo and identity
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "SecretGuard Tester"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "tester@secretguard.io"], cwd=repo_dir, check=True)

    # Initial commit
    init_file = repo_dir / "README.md"
    init_file.write_text("# Project\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True)

    # Stage a file with an exposed AWS secret
    secret_file = repo_dir / "aws.py"
    secret_file.write_text('AWS_SECRET_KEY = "AKIA1234567890ABCDEF"\n', encoding="utf-8")
    subprocess.run(["git", "add", "aws.py"], cwd=repo_dir, check=True)

    # Run CLI in pre-commit mode - must fail with exit code 1
    runner = CliRunner()
    result_fail = runner.invoke(main, ["scan", str(repo_dir), "--pre-commit"])
    assert result_fail.exit_code == 1
    assert "SG-AWS-001" in result_fail.output
    assert "DETECTED 1 POTENTIAL SECRET(S)" in result_fail.output

    # Fix the violation and re-stage clean code
    secret_file.write_text('AWS_KEY = os.environ.get("AWS_KEY")\n', encoding="utf-8")
    subprocess.run(["git", "add", "aws.py"], cwd=repo_dir, check=True)

    # Run CLI in pre-commit mode - must pass with exit code 0
    result_pass = runner.invoke(main, ["scan", str(repo_dir), "--pre-commit"])
    assert result_pass.exit_code == 0
    assert "SCAN CLEAN" in result_pass.output


@respx.mock
def test_latency_sla_benchmarks() -> None:
    """Verify deterministic scan completes < 1,000ms and pre-commit with AI verification completes < 3,000ms."""
    # Synthetic diff with 500 lines (simulating realistic pre-commit payload)
    lines = ["diff --git a/large_file.py b/large_file.py\n", "--- a/large_file.py\n", "+++ b/large_file.py\n", "@@ -0,0 +1,500 @@\n"]
    for i in range(1, 499):
        lines.append(f"+def compute_{i}():\n+    return {i} * 42\n")
    lines.append('+AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"\n')
    large_diff_content = "".join(lines)

    class LargeDiffIngester:
        def stream_diff_lines(self, context: ScanContext):
            parser = GitDiffParser()
            yield from parser.parse_diff_stream(large_diff_content.splitlines(keepends=True))

    # Benchmark 1: Pure deterministic scan SLA < 1,000 ms
    orchestrator_det = ScanOrchestrator(git_ingester=LargeDiffIngester())
    t0 = time.perf_counter()
    report_det = orchestrator_det.run_scan(ScanContext(target_path=".", is_pre_commit=True, diff_mode=True))
    latency_det_ms = (time.perf_counter() - t0) * 1000.0

    assert report_det.summary.true_positive_count == 1
    assert latency_det_ms < 1000.0, f"Deterministic diff scan exceeded SLA: {latency_det_ms:.2f}ms >= 1000ms"

    # Benchmark 2: Scan with AI Verification SLA < 3,000 ms
    def mock_delayed_response(request):
        time.sleep(0.05)  # 50ms synthetic network latency simulation
        return respx.MockResponse(
            status_code=200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "is_secret": True,
                                    "confidence": 0.95,
                                    "explanation": "Valid secret token.",
                                    "remediation": "Rotate token immediately.",
                                }
                            )
                        }
                    }
                ]
            },
        )

    respx.post("https://api.groq.com/openai/v1/chat/completions").mock(side_effect=mock_delayed_response)

    key_manager = KeyRotationManager(initial_keys={"groq": ["gsk_benchmark_key_123"]})
    dispatcher = ProviderDispatcher(key_manager=key_manager)
    verifier = ContextualVerifier(key_manager=key_manager, provider_client=dispatcher)

    # Diff with ambiguous token triggering AI route
    ai_diff_lines = [
        "diff --git a/auth.py b/auth.py\n",
        "--- a/auth.py\n",
        "+++ b/auth.py\n",
        "@@ -0,0 +1,2 @@\n",
        '+secret_token = "dGhpcyBpcyBhbiBhbWJpZ3VvdXMgdG9rZW4gZXhhbXBsZQ=="\n',
    ]

    class AIDiffIngester:
        def stream_diff_lines(self, context: ScanContext):
            parser = GitDiffParser()
            yield from parser.parse_diff_stream(ai_diff_lines)

    orchestrator_ai = ScanOrchestrator(git_ingester=AIDiffIngester(), verifier=verifier)
    t1 = time.perf_counter()
    report_ai = orchestrator_ai.run_scan(ScanContext(target_path=".", is_pre_commit=True, diff_mode=True))
    latency_ai_ms = (time.perf_counter() - t1) * 1000.0

    assert report_ai.summary.ai_verified_count == 1
    assert report_ai.summary.true_positive_count == 1
    assert latency_ai_ms < 3000.0, f"Pre-commit AI verification exceeded SLA: {latency_ai_ms:.2f}ms >= 3000ms"
