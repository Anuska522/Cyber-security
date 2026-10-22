"""Reproducible performance benchmark and empirical characterization script for SecretGuard."""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
from pathlib import Path

# Add SecretGuard source to Python path
repo_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(repo_root / "SecretGuard-main"))

from secretguard.core.models import DiffLine, ScanContext, SecretCandidate
from secretguard.extract.engine import DeterministicExtractionEngine
from secretguard.extract.entropy import ShannonEntropyCalculator
from secretguard.ingest.git_diff import GitDiffParser
from secretguard.router.policy import AdaptiveRoutingPolicy
from secretguard.router.scorer import AmbiguityScorer


def generate_diff(num_lines: int) -> str:
    """Generate synthetic git diff with controlled secrets and non-secrets."""
    header = [
        "diff --git a/app.py b/app.py",
        "index 0000000..abcdef1 100644",
        "--- a/app.py",
        "+++ b/app.py",
        f"@@ -0,0 +1,{num_lines} @@",
    ]
    lines = list(header)
    secret_patterns = {
        5: '+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        12: '+GITHUB_TOKEN = "' + "gh" + 'p_1234567890abcdefghijklmnopqrstuvwxyz"',
        20: '+OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL"',
        35: '+JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"',
        50: '+DB_CONN = "postgres://usr:P@ssw0rd99@db.prod.internal:5432/db"',
        75: '+MOCK_TOKEN = "mock_secret_test_fixture_token_12345"',
        90: '+PLACEHOLDER = "YOUR_API_KEY_HERE"',
    }

    for i in range(1, num_lines + 1):
        mod_idx = i % 100
        if mod_idx in secret_patterns:
            lines.append(secret_patterns[mod_idx])
        else:
            lines.append(f"+    item_{i} = calculate_value({i})  # standard application logic line")
    return "\n".join(lines) + "\n"


def benchmark_latency_and_throughput():
    sizes = [10, 50, 100, 250, 500, 1000]
    results = {}
    engine = DeterministicExtractionEngine()
    parser = GitDiffParser()

    print(f"{'Diff Size (lines)':<18} | {'Avg Latency (ms)':<16} | {'StdDev (ms)':<12} | {'Throughput (lines/s)':<20} | {'Findings':<10}")
    print("-" * 85)

    for sz in sizes:
        diff_text = generate_diff(sz)
        diff_lines_raw = diff_text.splitlines(keepends=True)
        trials = 20
        timings = []
        findings_count = 0

        for _ in range(trials):
            t0 = time.perf_counter()
            parsed = list(parser.parse_diff_stream(diff_lines_raw))
            candidates = []
            for dl in parsed:
                candidates.extend(engine.extract_from_diff_line(dl))
            t1 = time.perf_counter()
            timings.append((t1 - t0) * 1000.0)
            findings_count = len(candidates)

        avg_lat = statistics.mean(timings)
        std_lat = statistics.stdev(timings) if len(timings) > 1 else 0.0
        throughput = (sz / (avg_lat / 1000.0)) if avg_lat > 0 else 0.0

        results[sz] = {
            "avg_latency_ms": round(avg_lat, 3),
            "std_latency_ms": round(std_lat, 3),
            "throughput_lines_per_sec": round(throughput, 1),
            "total_extracted_candidates": findings_count,
        }

        print(f"{sz:<18} | {avg_lat:<16.3f} | {std_lat:<12.3f} | {throughput:<20.1f} | {findings_count:<10}")

    return results


def benchmark_ambiguity_scoring():
    scorer = AmbiguityScorer()
    policy = AdaptiveRoutingPolicy(scorer=scorer)

    test_candidates = [
        # 1. Structured AWS key in production file
        SecretCandidate(
            literal_value="AKIAIOSFODNN7EXAMPLE",
            file_path="src/services/aws_client.py",
            line_number=14,
            surrounding_context='client = boto3.client("s3", aws_access_key_id="AKIAIOSFODNN7EXAMPLE")',
            rule_id="SG-AWS-001",
            entropy_score=3.85,
            heuristic_tags=["aws", "cloud"],
            is_filtered=False,
        ),
        # 2. Structured GitHub token in production file
        SecretCandidate(
            literal_value="gh" + "p_1234567890abcdefghijklmnopqrstuvwxyz",
            file_path="src/utils/github.py",
            line_number=8,
            surrounding_context='token = "' + "gh" + 'p_1234567890abcdefghijklmnopqrstuvwxyz"',
            rule_id="SG-GH-001",
            entropy_score=4.42,
            heuristic_tags=["github"],
            is_filtered=False,
        ),
        # 3. Generic variable with high entropy token
        SecretCandidate(
            literal_value="x9aK81mZbQ092LmqQp0",
            file_path="src/auth.py",
            line_number=45,
            surrounding_context='custom_auth_token = "x9aK81mZbQ092LmqQp0"',
            rule_id="SG-HEUR-001",
            entropy_score=4.15,
            heuristic_tags=["entropy"],
            is_filtered=False,
        ),
        # 4. Token inside test fixture
        SecretCandidate(
            literal_value="AKIAIOSFODNN7EXAMPLE",
            file_path="tests/fixtures/mock_credentials.py",
            line_number=12,
            surrounding_context='mock_aws_key = "AKIAIOSFODNN7EXAMPLE"',
            rule_id="SG-AWS-001",
            entropy_score=3.85,
            heuristic_tags=["aws", "test"],
            is_filtered=False,
        ),
        # 5. Generic token inside mock test fixture
        SecretCandidate(
            literal_value="secret_test_mock_dummy_token_999",
            file_path="tests/unit/test_login.py",
            line_number=22,
            surrounding_context='fake_token = "secret_test_mock_dummy_token_999"',
            rule_id="SG-HEUR-001",
            entropy_score=3.95,
            heuristic_tags=["test"],
            is_filtered=False,
        ),
    ]

    print("\nCandidate Ambiguity Scoring & Routing Breakdown:")
    print("-" * 110)
    print(f"{'Candidate Description':<32} | {'Rule ID':<12} | {'Regex U':<8} | {'H_norm':<8} | {'Ctx Amb':<8} | {'S_amb':<8} | {'Routing Decision':<20}")
    print("-" * 110)

    routing_results = []
    for c in test_candidates:
        u_reg = scorer.calculate_regex_uncertainty(c)
        h_norm = scorer.calculate_normalized_entropy(c)
        a_ctx = scorer.calculate_context_ambiguity(c)
        s_amb = scorer.calculate_ambiguity_score(c)
        route = policy.evaluate_route(c)
        route_str = "Local Deterministic (0ms)" if route is None else f"{route.name} ({route.model_id})"

        routing_results.append({
            "context": c.surrounding_context[:30],
            "rule_id": c.rule_id,
            "regex_uncertainty": u_reg,
            "entropy_normalized": round(h_norm, 3),
            "context_ambiguity": a_ctx,
            "ambiguity_score": s_amb,
            "route": route_str,
        })
        desc = c.surrounding_context[:30] + "..."
        print(f"{desc:<32} | {c.rule_id:<12} | {u_reg:<8.2f} | {h_norm:<8.3f} | {a_ctx:<8.2f} | {s_amb:<8.3f} | {route_str:<20}")

    return routing_results


def main():
    print("=== SECRETGUARD REPRODUCIBLE BENCHMARK RUNNER ===")
    latency_res = benchmark_latency_and_throughput()
    routing_res = benchmark_ambiguity_scoring()

    out_file = Path(__file__).resolve().parent / "benchmark_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "latency_throughput": latency_res,
            "routing_evaluation": routing_res,
        }, f, indent=2)
    print(f"\nSaved raw benchmark data to: {out_file}")


if __name__ == "__main__":
    main()
