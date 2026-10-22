"""Tests for adaptive routing engine: ambiguity scoring, metric components, tiers, and profile locking."""

from __future__ import annotations

import pytest

from secretguard.config.models import SecretGuardConfig
from secretguard.core.models import ModelProfile, SecretCandidate
from secretguard.router.policy import (
    PROFILE_A,
    PROFILE_B,
    PROFILE_C,
    AdaptiveRoutingPolicy,
)
from secretguard.router.scorer import AmbiguityScorer


@pytest.fixture
def scorer() -> AmbiguityScorer:
    """Fixture providing an AmbiguityScorer instance."""
    return AmbiguityScorer()


@pytest.fixture
def policy(scorer: AmbiguityScorer) -> AdaptiveRoutingPolicy:
    """Fixture providing an AdaptiveRoutingPolicy instance."""
    return AdaptiveRoutingPolicy(scorer=scorer)


def test_scorer_regex_uncertainty_metric(scorer: AmbiguityScorer) -> None:
    """Verify that structured vendor rules yield 0.0 uncertainty and heuristic rules yield 1.0."""
    structured_candidate = SecretCandidate(
        literal_value="AKIA1234567890ABCDEF",
        file_path="src/deploy.py",
        line_number=10,
        surrounding_context='aws_access_key_id = "AKIA1234567890ABCDEF"',
        rule_id="SG-AWS-001",
        entropy_score=4.2,
    )
    assert scorer.calculate_regex_uncertainty(structured_candidate) == 0.0

    heuristic_candidate = SecretCandidate(
        literal_value="someGenericSecretString123",
        file_path="src/auth.py",
        line_number=20,
        surrounding_context='custom_var = "someGenericSecretString123"',
        rule_id="SG-HEUR-VAR-001",
        entropy_score=4.5,
    )
    assert scorer.calculate_regex_uncertainty(heuristic_candidate) == 1.0


def test_scorer_normalized_entropy_metric(scorer: AmbiguityScorer) -> None:
    """Verify that entropy is linearly mapped and clamped to [0.0, 1.0] across [3.5, 6.0]."""
    # Low entropy <= 3.5 clamps to 0.0
    low_cand = SecretCandidate(
        literal_value="lowentropy",
        file_path="app.py",
        line_number=1,
        surrounding_context="a = 'lowentropy'",
        rule_id="SG-HEUR-VAR-001",
        entropy_score=3.0,
    )
    assert scorer.calculate_normalized_entropy(low_cand) == 0.0

    # High entropy >= 6.0 clamps to 1.0
    high_cand = SecretCandidate(
        literal_value="vErY!hIgH#eNtRoPy$sTrInG%1234",
        file_path="app.py",
        line_number=1,
        surrounding_context="b = '...' ",
        rule_id="SG-HEUR-VAR-001",
        entropy_score=6.5,
    )
    assert scorer.calculate_normalized_entropy(high_cand) == 1.0

    # Intermediate entropy: (4.75 - 3.5) / (6.0 - 3.5) = 1.25 / 2.5 = 0.5
    mid_cand = SecretCandidate(
        literal_value="mid_entropy_token_val",
        file_path="app.py",
        line_number=1,
        surrounding_context="c = '...'",
        rule_id="SG-HEUR-VAR-001",
        entropy_score=4.75,
    )
    assert pytest.approx(scorer.calculate_normalized_entropy(mid_cand), 1e-4) == 0.5


def test_scorer_context_ambiguity_metric(scorer: AmbiguityScorer) -> None:
    """Verify context ambiguity assigns 1.0 for tests/mocks, 0.2 for explicit keywords, 0.8 for generic."""
    # Test fixture context (1.0)
    test_cand = SecretCandidate(
        literal_value="secret_test_token_12345",
        file_path="tests/fixtures/test_credentials.py",
        line_number=5,
        surrounding_context='mock_password = "secret_test_token_12345"',
        rule_id="SG-HEUR-VAR-001",
        entropy_score=4.5,
    )
    assert scorer.calculate_context_ambiguity(test_cand) == 1.0

    # Explicit sensitive assignment in production code (0.2)
    prod_cand = SecretCandidate(
        literal_value="production_api_token_12345",
        file_path="src/gateway/client.py",
        line_number=15,
        surrounding_context='api_key = "production_api_token_12345"',
        rule_id="SG-HEUR-VAR-001",
        entropy_score=4.5,
    )
    assert scorer.calculate_context_ambiguity(prod_cand) == 0.2

    # Generic identifier in production code (0.8)
    generic_cand = SecretCandidate(
        literal_value="generic_token_value_12345",
        file_path="src/utils/encoder.py",
        line_number=30,
        surrounding_context='param = "generic_token_value_12345"',
        rule_id="SG-HEUR-VAR-001",
        entropy_score=4.5,
    )
    assert scorer.calculate_context_ambiguity(generic_cand) == 0.8


def test_ambiguity_scoring_structured_aws_key_under_0_2(scorer: AmbiguityScorer) -> None:
    """Verify that a structured AWS key with explicit keyword scores in the unambiguous tier (< 0.2)."""
    # RegexUncertainty = 0.0, Entropy = 4.2 -> (4.2 - 3.5)/2.5 = 0.28, ContextAmbiguity = 0.2
    # Score = 0.4(0.0) + 0.3(0.28) + 0.3(0.2) = 0.0 + 0.084 + 0.060 = 0.144 < 0.2
    aws_cand = SecretCandidate(
        literal_value="AKIAIOSFODNN7EXAMPLE",
        file_path="src/aws_config.py",
        line_number=12,
        surrounding_context='aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
        rule_id="SG-AWS-001",
        entropy_score=4.2,
    )
    score = scorer.calculate_ambiguity_score(aws_cand)
    assert score < 0.2
    assert score == pytest.approx(0.144, abs=1e-3)


def test_ambiguity_scoring_generic_name_intermediate_tier(scorer: AmbiguityScorer) -> None:
    """Verify high-entropy token with generic variable scores in low-complexity tier [0.2, 0.6)."""
    # Structured token (RegexUncertainty = 0.0), Entropy = 5.0 -> H_norm = (5.0 - 3.5)/2.5 = 0.6
    # ContextAmbiguity = 0.8 (generic name)
    # Score = 0.4(0.0) + 0.3(0.6) + 0.3(0.8) = 0.18 + 0.24 = 0.42
    jwt_generic = SecretCandidate(
        literal_value="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        file_path="src/services/api.py",
        line_number=45,
        surrounding_context='header_value = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"',
        rule_id="SG-JWT-001",
        entropy_score=5.0,
    )
    score = scorer.calculate_ambiguity_score(jwt_generic)
    assert 0.2 <= score < 0.6
    assert score == pytest.approx(0.42, abs=1e-3)


def test_ambiguity_scoring_ambiguous_test_fixture_high_tier(scorer: AmbiguityScorer) -> None:
    """Verify ambiguous test fixture candidate scores in high-complexity tier (>= 0.6)."""
    # Heuristic rule (RegexUncertainty = 1.0), Entropy = 5.0 -> H_norm = 0.6, ContextAmbiguity = 1.0 (in test)
    # Score = 0.4(1.0) + 0.3(0.6) + 0.3(1.0) = 0.4 + 0.18 + 0.3 = 0.88 >= 0.6
    test_fixture_cand = SecretCandidate(
        literal_value="dGhpcyBpcyBhIHRlc3QgZml4dHVyZSBzZWNyZXQ=",
        file_path="tests/fixtures/mock_auth.py",
        line_number=8,
        surrounding_context='mock_secret = "dGhpcyBpcyBhIHRlc3QgZml4dHVyZSBzZWNyZXQ="',
        rule_id="SG-HEUR-VAR-001",
        entropy_score=5.0,
    )
    score = scorer.calculate_ambiguity_score(test_fixture_cand)
    assert score >= 0.6
    assert score == pytest.approx(0.88, abs=1e-3)


def test_adaptive_routing_policy_unambiguous_tier_returns_none(policy: AdaptiveRoutingPolicy) -> None:
    """Verify that unambiguous candidates (S_amb < 0.2) return None for local resolution."""
    aws_cand = SecretCandidate(
        literal_value="AKIAIOSFODNN7EXAMPLE",
        file_path="src/aws.py",
        line_number=1,
        surrounding_context='aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
        rule_id="SG-AWS-001",
        entropy_score=4.2,
    )
    route = policy.evaluate_route(aws_cand)
    assert route is None


def test_adaptive_routing_policy_low_complexity_routes_profile_a(policy: AdaptiveRoutingPolicy) -> None:
    """Verify that low-complexity ambiguous candidates route to Profile A (Groq Llama-3-8B)."""
    mid_cand = SecretCandidate(
        literal_value="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.xyz123abc456",
        file_path="src/api.py",
        line_number=10,
        surrounding_context='data = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.xyz123abc456"',
        rule_id="SG-JWT-001",
        entropy_score=5.0,
    )
    route = policy.evaluate_route(mid_cand)
    assert route is not None
    assert route.name == "Profile A"
    assert route.provider == "groq"
    assert route.model_id == "llama-3.1-8b-instant"


def test_adaptive_routing_policy_high_complexity_routes_profile_b(policy: AdaptiveRoutingPolicy) -> None:
    """Verify that high-complexity ambiguous candidates route to Profile B (OpenRouter GPT-4o-mini)."""
    high_cand = SecretCandidate(
        literal_value="randomized_mock_secret_token_val_999",
        file_path="tests/mock_service.py",
        line_number=22,
        surrounding_context='mock_secret = "randomized_mock_secret_token_val_999"',
        rule_id="SG-HEUR-VAR-001",
        entropy_score=5.2,
    )
    route = policy.evaluate_route(high_cand)
    assert route is not None
    assert route.name == "Profile B"
    assert route.provider == "openrouter"
    assert route.model_id == "openai/gpt-4o-mini"


def test_profile_locking_overrides_bypass_scoring(policy: AdaptiveRoutingPolicy) -> None:
    """Verify that explicit profile overrides force the designated profile regardless of candidate score."""
    # This candidate would normally evaluate to None (< 0.2)
    unambiguous_cand = SecretCandidate(
        literal_value="AKIAIOSFODNN7EXAMPLE",
        file_path="src/aws.py",
        line_number=1,
        surrounding_context='aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
        rule_id="SG-AWS-001",
        entropy_score=4.2,
    )

    # Force Profile A
    config_a = SecretGuardConfig(profile_override="A")
    route_a = policy.evaluate_route(unambiguous_cand, config=config_a)
    assert route_a is not None
    assert route_a.name == "Profile A"

    # Force Profile B
    config_b = SecretGuardConfig(profile_override="B")
    route_b = policy.evaluate_route(unambiguous_cand, config=config_b)
    assert route_b is not None
    assert route_b.name == "Profile B"

    # Force Profile C
    config_c = SecretGuardConfig(profile_override="C")
    route_c = policy.evaluate_route(unambiguous_cand, config=config_c)
    assert route_c is not None
    assert route_c.name == "Profile C"

    # Test dictionary config override
    route_dict_c = policy.evaluate_route(unambiguous_cand, config={"profile_override": "C"})
    assert route_dict_c is not None
    assert route_dict_c.name == "Profile C"
