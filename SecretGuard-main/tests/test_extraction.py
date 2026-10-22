"""Tests for deterministic extraction subsystem: rules, heuristics, pre-filtering, and context bounding."""

from __future__ import annotations

import pytest

from secretguard.core.models import SecretCandidate
from secretguard.extract.context import extract_bounded_context
from secretguard.extract.engine import DeterministicExtractionEngine
from secretguard.extract.filters import CandidatePreFilter
from secretguard.extract.heuristics import ContextualVariableHeuristic
from secretguard.extract.rules import (
    AWSAccessKeyRule,
    AWSSecretKeyRule,
    AzureTokenRule,
    DatabaseURLRule,
    DiscordTokenRule,
    FirebaseKeyRule,
    GitHubClassicTokenRule,
    GitHubFineGrainedTokenRule,
    GoogleCloudKeyRule,
    JWTRule,
    OpenAILegacyKeyRule,
    OpenAIProjectKeyRule,
    PrivateKeyRule,
    SlackTokenRule,
    StripeKeyRule,
    TwilioKeyRule,
    get_default_rules,
)


@pytest.fixture
def engine() -> DeterministicExtractionEngine:
    """Fixture providing a default extraction engine instance."""
    return DeterministicExtractionEngine()


def test_aws_access_key_extraction() -> None:
    """Verify detection of AWS Access Key ID."""
    rule = AWSAccessKeyRule()
    line = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
    candidates = rule.evaluate(line, file_path="deploy.py", line_number=42)

    assert len(candidates) == 1
    assert candidates[0].literal_value == "AKIAIOSFODNN7EXAMPLE"
    assert candidates[0].rule_id == "SG-AWS-001"
    assert "aws" in candidates[0].heuristic_tags
    assert candidates[0].file_path == "deploy.py"
    assert candidates[0].line_number == 42


def test_aws_secret_key_extraction() -> None:
    """Verify detection of AWS Secret Access Key."""
    rule = AWSSecretKeyRule()
    line = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    candidates = rule.evaluate(line)

    assert len(candidates) == 1
    assert candidates[0].literal_value == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert candidates[0].rule_id == "SG-AWS-002"


def test_github_tokens_extraction() -> None:
    """Verify detection of classic and fine-grained GitHub personal access tokens."""
    classic_rule = GitHubClassicTokenRule()
    line_classic = 'export GITHUB_TOKEN="ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
    classic_matches = classic_rule.evaluate(line_classic)
    assert len(classic_matches) == 1
    assert classic_matches[0].literal_value == "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    assert classic_matches[0].rule_id == "SG-GH-001"

    fine_rule = GitHubFineGrainedTokenRule()
    pat = "github_pat_11ABCD123_4567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345"
    line_fine = f'GITHUB_PAT = "{pat}"'
    fine_matches = fine_rule.evaluate(line_fine)
    assert len(fine_matches) == 1
    assert fine_matches[0].literal_value == pat
    assert fine_matches[0].rule_id == "SG-GH-002"


def test_openai_keys_extraction() -> None:
    """Verify detection of OpenAI legacy and new project/service tokens."""
    legacy_rule = OpenAILegacyKeyRule()
    line_legacy = 'OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL"'
    legacy_matches = legacy_rule.evaluate(line_legacy)
    assert len(legacy_matches) == 1
    assert legacy_matches[0].literal_value == "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL"
    assert legacy_matches[0].rule_id == "SG-OAI-001"

    proj_rule = OpenAIProjectKeyRule()
    proj_token = "sk-proj-abcde12345fghij67890klmno12345pqrst67890uvwxy12345zABCDE67890"
    line_proj = f'client = OpenAI(api_key="{proj_token}")'
    proj_matches = proj_rule.evaluate(line_proj)
    assert len(proj_matches) == 1
    assert proj_matches[0].literal_value == proj_token
    assert proj_matches[0].rule_id == "SG-OAI-002"


def test_google_cloud_key_extraction() -> None:
    """Verify detection of Google Cloud API keys."""
    rule = GoogleCloudKeyRule()
    key = "AIzaSyD-1234567890abcdefghijklmnopqrstu"
    line = f'GCP_KEY = "{key}"'
    candidates = rule.evaluate(line)

    assert len(candidates) == 1
    assert candidates[0].literal_value == key
    assert candidates[0].rule_id == "SG-GCP-001"


def test_slack_token_extraction() -> None:
    """Verify detection of Slack OAuth and bot tokens."""
    rule = SlackTokenRule()
    token = "xo" + "xb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
    line = f'SLACK_BOT_TOKEN = "{token}"'
    candidates = rule.evaluate(line)

    assert len(candidates) == 1
    assert candidates[0].literal_value == token
    assert candidates[0].rule_id == "SG-SLACK-001"


def test_jwt_extraction() -> None:
    """Verify detection of signed JSON Web Tokens."""
    rule = JWTRule()
    jwt_val = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    line = f'Authorization: Bearer {jwt_val}'
    candidates = rule.evaluate(line)

    assert len(candidates) == 1
    assert candidates[0].literal_value == jwt_val
    assert candidates[0].rule_id == "SG-JWT-001"


def test_private_key_header_extraction() -> None:
    """Verify detection of RSA, OpenSSH, and generic private cryptographic key headers."""
    rule = PrivateKeyRule()
    headers = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    ]
    for header in headers:
        candidates = rule.evaluate(header)
        assert len(candidates) == 1
        assert candidates[0].literal_value == header
        assert candidates[0].rule_id == "SG-KEY-001"


def test_azure_stripe_twilio_firebase_discord_extraction() -> None:
    """Verify detection of Azure, Stripe, Twilio, Firebase, and Discord tokens."""
    # Azure
    azure_rule = AzureTokenRule()
    azure_line = 'DefaultEndpointsProtocol=https;AccountName=myacc;AccountKey=abcdefghijklmnopqrstuvwxyz1234567890ABCDEF1234567890=='
    azure_matches = azure_rule.evaluate(azure_line)
    assert len(azure_matches) == 1
    assert azure_matches[0].rule_id == "SG-AZURE-001"

    # Stripe
    stripe_rule = StripeKeyRule()
    stripe_key = "sk" + "_live_51Abcdef1234567890GHIJKL123456"
    stripe_line = f'stripe.api_key = "{stripe_key}"'
    stripe_matches = stripe_rule.evaluate(stripe_line)
    assert len(stripe_matches) == 1
    assert stripe_matches[0].literal_value == stripe_key

    # Twilio
    twilio_rule = TwilioKeyRule()
    twilio_val = "A" + "C1234567890abcdef1234567890abcdef"
    twilio_line = f'TWILIO_ACCOUNT_SID = "{twilio_val}"'
    twilio_matches = twilio_rule.evaluate(twilio_line)
    assert len(twilio_matches) == 1
    assert twilio_matches[0].literal_value == twilio_val

    # Firebase
    firebase_rule = FirebaseKeyRule()
    fb_key = "AAAA1234567:" + ("a" * 140)
    firebase_line = f'FIREBASE_SERVER_KEY = "{fb_key}"'
    firebase_matches = firebase_rule.evaluate(firebase_line)
    assert len(firebase_matches) == 1
    assert firebase_matches[0].literal_value == fb_key

    # Discord
    discord_rule = DiscordTokenRule()
    discord_token = "MTA1OTI4MzYyMTU0ODk1Njg2NQ" + ".GH7Jkl." + "abcdefghijklmnopqrstuvwxyz1234567"
    discord_line = f'DISCORD_TOKEN = "{discord_token}"'
    discord_matches = discord_rule.evaluate(discord_line)
    assert len(discord_matches) == 1
    assert discord_matches[0].literal_value == discord_token


def test_database_url_extraction() -> None:
    """Verify detection of database URLs containing credentials."""
    rule = DatabaseURLRule()
    urls = [
        "postgres://admin_user:SuperPass123!@db.internal.net:5432/production_db",
        "mysql://root:ComplexRoot99#@mysql-cluster:3306/app",
        "mongodb://service_acc:M0ng0Secret@mongo-primary.net:27017/analytics",
    ]
    for url in urls:
        line = f'DATABASE_URL = "{url}"'
        matches = rule.evaluate(line)
        assert len(matches) == 1
        assert matches[0].literal_value == url
        assert matches[0].rule_id == "SG-DB-001"


def test_contextual_variable_heuristic_matching() -> None:
    """Verify identification of credentials in variable assignments via AST and line buffer."""
    heuristic = ContextualVariableHeuristic()
    python_assign = 'client_secret = "8f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c"'
    candidates = heuristic.evaluate(python_assign, file_path="auth.py", line_number=15)

    assert len(candidates) >= 1
    assert candidates[0].literal_value == "8f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c"
    assert "contextual_variable" in candidates[0].heuristic_tags
    assert candidates[0].file_path == "auth.py"
    assert candidates[0].line_number == 15

    # Config style assignment
    config_assign = 'auth_token: "Kj8#mN9$pQ2!vW5^xZ8*"'
    candidates_config = heuristic.evaluate(config_assign)
    assert len(candidates_config) >= 1
    assert candidates_config[0].literal_value == "Kj8#mN9$pQ2!vW5^xZ8*"


def test_candidate_pre_filter_suppresses_placeholders_and_templates() -> None:
    """Verify CandidatePreFilter discards placeholders, templated strings, and non-credential URLs."""
    pre_filter = CandidatePreFilter()

    # Placeholders
    placeholders = [
        "YOUR_API_KEY",
        "dummy_password",
        "example_key",
        "<API_KEY>",
        "changeme",
        "replace_me",
        "my_secret",
    ]
    for ph in placeholders:
        candidate = SecretCandidate(
            literal_value=ph,
            file_path="config.py",
            line_number=1,
            surrounding_context=ph,
            rule_id="SG-HEUR-VAR-001",
            entropy_score=3.5,
        )
        should_filter, reason = pre_filter.should_filter(candidate)
        assert should_filter is True
        assert reason in ("placeholder literal", "templated environment variable")

    # Templated environment variables
    templates = ["${ENV_VAR}", "$SECRET", "{{API_KEY}}", "%{SECRET}", "<SECRET>", "process.env.DB_PASS"]
    for tmpl in templates:
        candidate = SecretCandidate(
            literal_value=tmpl,
            file_path="config.py",
            line_number=1,
            surrounding_context=tmpl,
            rule_id="SG-HEUR-VAR-001",
            entropy_score=3.5,
        )
        should_filter, reason = pre_filter.should_filter(candidate)
        assert should_filter is True
        assert reason == "templated environment variable"

    # Standard URLs lacking credentials
    plain_url = "https://api.github.com/repos/owner/repo"
    url_candidate = SecretCandidate(
        literal_value=plain_url,
        file_path="client.py",
        line_number=10,
        surrounding_context=plain_url,
        rule_id="SG-HEUR-VAR-001",
        entropy_score=4.0,
    )
    should_filter, reason = pre_filter.should_filter(url_candidate)
    assert should_filter is True
    assert reason == "standard http url without credentials"

    # Legitimate secret should NOT be filtered
    real_secret = "8f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c"
    valid_candidate = SecretCandidate(
        literal_value=real_secret,
        file_path="auth.py",
        line_number=5,
        surrounding_context=real_secret,
        rule_id="SG-AWS-002",
        entropy_score=4.5,
    )
    should_filter, reason = pre_filter.should_filter(valid_candidate)
    assert should_filter is False
    assert reason is None


def test_bounded_context_window_strict_200_chars() -> None:
    """Verify surrounding context window is strictly bounded to a maximum of 200 characters."""
    secret = "AKIA1234567890ABCDEF"
    prefix = "A" * 250
    suffix = "B" * 250
    huge_line = f"{prefix}{secret}{suffix}"

    match_start = len(prefix)
    match_end = match_start + len(secret)

    context = extract_bounded_context(huge_line, match_start, match_end, max_window=200)

    assert len(context) <= 200
    assert secret in context

    # Verify model invariant ceiling
    candidate = SecretCandidate(
        literal_value=secret,
        file_path="file.py",
        line_number=1,
        surrounding_context=huge_line,
        rule_id="SG-AWS-001",
        entropy_score=4.5,
    )
    assert len(candidate.surrounding_context) <= 200
