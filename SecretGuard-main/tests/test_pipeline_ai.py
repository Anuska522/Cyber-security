"""End-to-end integration test combining DeterministicExtractionEngine with ContextualVerifier."""

from __future__ import annotations

import json
import respx

from secretguard.extract.engine import DeterministicExtractionEngine
from secretguard.gateway.dispatcher import ProviderDispatcher
from secretguard.gateway.key_manager import KeyRotationManager
from secretguard.ingest.git_diff import GitDiffParser
from secretguard.verifier.evaluator import ContextualVerifier

INTEGRATION_DIFF = """diff --git a/services/auth.py b/services/auth.py
index 0000000..1111111 100644
--- a/services/auth.py
+++ b/services/auth.py
@@ -10,0 +11,3 @@
+AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
+api_token = "dGhpcyBpcyBhbiBhbWJpZ3VvdXMgdG9rZW4gZXhhbXBsZQ=="
+api_key = "YOUR_API_KEY"
diff --git a/tests/test_auth.py b/tests/test_auth.py
index 0000000..2222222 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -5,0 +6,1 @@
+mock_key = "dGVzdF9maXh0dXJlX2Zha2Vfc2VjcmV0X2tleV9leGFtcGxl"
"""


@respx.mock
def test_end_to_end_ai_verification_pipeline() -> None:
    """Verify complete pipeline: GitDiffParser -> ExtractionEngine -> ContextualVerifier."""
    endpoint = "https://api.groq.com/openai/v1/chat/completions"

    # Setup mock responses for ambiguous items routed to Groq
    def dynamic_mock(request):
        req_body = json.loads(request.content.decode("utf-8"))
        messages = req_body.get("messages", [])
        user_msg = messages[1]["content"] if len(messages) > 1 else ""

        if "dGVzdF9maXh0dXJl" in user_msg:
            # Test fixture mock
            return respx.MockResponse(
                status_code=200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "is_secret": False,
                                        "confidence": 0.98,
                                        "explanation": "Mock test credential identified in fixture context.",
                                        "remediation": "No remediation required.",
                                    }
                                )
                            }
                        }
                    ]
                },
            )

        # Ambiguous production token
        return respx.MockResponse(
            status_code=200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "is_secret": True,
                                    "confidence": 0.93,
                                    "explanation": "Active production API token with sufficient entropy.",
                                    "remediation": "Rotate token and place in secrets vault.",
                                }
                            )
                        }
                    }
                ]
            },
        )

    respx.post("https://api.groq.com/openai/v1/chat/completions").mock(side_effect=dynamic_mock)
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(side_effect=dynamic_mock)

    # 1. Ingestion: Parse diff stream
    diff_parser = GitDiffParser()
    diff_lines = list(diff_parser.parse_diff_stream(INTEGRATION_DIFF.splitlines(keepends=True)))
    assert len(diff_lines) == 4

    # 2. Deterministic Extraction: Extract candidates including filtered ones
    extraction_engine = DeterministicExtractionEngine()
    candidates = []
    for line in diff_lines:
        candidates.extend(extraction_engine.extract_from_diff_line(line))

    assert len(candidates) >= 4

    # 3. AI Verification: Initialize verifier with key manager and dispatcher
    key_manager = KeyRotationManager(
        initial_keys={
            "groq": ["gsk_integration_test_key_123"],
            "openrouter": ["sk-or-integration_test_key_456"],
        }
    )
    dispatcher = ProviderDispatcher(key_manager=key_manager)
    verifier = ContextualVerifier(key_manager=key_manager, provider_client=dispatcher)

    # Execute verification across all extracted candidates
    verification_results = verifier.verify_batch(candidates)
    assert len(verification_results) == len(candidates)

    # Map results by (literal_value, rule_id) to accurately reflect both structured and heuristic rules
    results_map = {
        (res.candidate.literal_value, res.candidate.rule_id): res
        for res in verification_results
    }

    # Verify Unambiguous AWS Key (SG-AWS-001): resolved locally with zero network calls
    aws_res = results_map[("AKIAIOSFODNN7EXAMPLE", "SG-AWS-001")]
    assert aws_res.resolved_locally is True
    assert aws_res.model_used == "local_deterministic"
    assert aws_res.is_secret is True
    assert aws_res.confidence == 0.95
    assert aws_res.latency_ms == 0.0

    # Verify Ambiguous Production Token: routed to LLM and classified as True
    ambiguous_token = "dGhpcyBpcyBhbiBhbWJpZ3VvdXMgdG9rZW4gZXhhbXBsZQ=="
    token_res = results_map[(ambiguous_token, "SG-HEUR-VAR-001")]
    assert token_res.resolved_locally is False
    assert token_res.is_secret is True
    assert token_res.confidence == 0.93
    assert token_res.model_used in ("llama-3.1-8b-instant", "openai/gpt-4o-mini")

    # Verify Mock Token in Tests: routed to LLM and classified as False (mock)
    mock_token = "dGVzdF9maXh0dXJlX2Zha2Vfc2VjcmV0X2tleV9leGFtcGxl"
    mock_res = results_map[(mock_token, "SG-HEUR-VAR-001")]
    assert mock_res.resolved_locally is False
    assert mock_res.is_secret is False
    assert mock_res.confidence == 0.98
    assert mock_res.model_used == "openai/gpt-4o-mini"

    # Verify Placeholder (YOUR_API_KEY): filtered out deterministically
    placeholder_res = results_map[("YOUR_API_KEY", "SG-HEUR-VAR-001")]
    assert placeholder_res.candidate.is_filtered is True
    assert placeholder_res.is_secret is False
    assert placeholder_res.resolved_locally is True
