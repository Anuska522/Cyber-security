"""Pre-compiled regex extraction rules library for structured credentials."""

from __future__ import annotations

import re
from typing import Optional, Sequence

from secretguard.core.interfaces import IEntropyCalculator, IExtractionRule
from secretguard.core.models import SecretCandidate
from secretguard.extract.context import extract_bounded_context
from secretguard.extract.entropy import ShannonEntropyCalculator


class BaseRegexRule(IExtractionRule):
    """Base class for pre-compiled regex extraction rules."""

    def __init__(
        self,
        rule_id: str,
        description: str,
        pattern: re.Pattern[str],
        entropy_calculator: Optional[IEntropyCalculator] = None,
        heuristic_tags: Optional[Sequence[str]] = None,
        capture_group: int = 1,
    ) -> None:
        self._rule_id = rule_id
        self._description = description
        self._pattern = pattern
        self._entropy_calculator = entropy_calculator or ShannonEntropyCalculator()
        self._heuristic_tags = list(heuristic_tags or [])
        self._capture_group = capture_group

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def description(self) -> str:
        return self._description

    def evaluate(
        self,
        line: str,
        file_path: str = "",
        line_number: int = 1,
    ) -> list[SecretCandidate]:
        candidates: list[SecretCandidate] = []
        for match in self._pattern.finditer(line):
            try:
                candidate_val = match.group(self._capture_group)
                match_start = match.start(self._capture_group)
                match_end = match.end(self._capture_group)
            except IndexError:
                candidate_val = match.group(0)
                match_start = match.start(0)
                match_end = match.end(0)

            if not candidate_val:
                continue

            entropy = self._entropy_calculator.calculate(candidate_val)
            context = extract_bounded_context(line, match_start, match_end)

            candidate = SecretCandidate(
                literal_value=candidate_val,
                file_path=file_path,
                line_number=line_number,
                surrounding_context=context,
                rule_id=self.rule_id,
                entropy_score=entropy,
                heuristic_tags=list(self._heuristic_tags),
                is_filtered=False,
                filter_reason=None,
            )
            candidates.append(candidate)
        return candidates


class AWSAccessKeyRule(BaseRegexRule):
    """Detects 20-character AWS Access Key IDs."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-AWS-001",
            description="AWS Access Key ID",
            pattern=re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["aws", "cloud_credential"],
            capture_group=1,
        )


class AWSSecretKeyRule(BaseRegexRule):
    """Detects 40-character AWS Secret Access Keys within variable assignment context."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-AWS-002",
            description="AWS Secret Access Key",
            pattern=re.compile(
                r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key|aws_key)[\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?"
            ),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["aws", "cloud_secret"],
            capture_group=1,
        )


class GitHubClassicTokenRule(BaseRegexRule):
    """Detects classic 40-character GitHub Personal Access Tokens."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-GH-001",
            description="GitHub Classic Personal Access Token",
            pattern=re.compile(r"(?<![0-9a-zA-Z])(ghp_[0-9a-zA-Z]{36})(?![0-9a-zA-Z])"),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["github", "vcs_token"],
            capture_group=1,
        )


class GitHubFineGrainedTokenRule(BaseRegexRule):
    """Detects GitHub Fine-Grained Personal Access Tokens."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-GH-002",
            description="GitHub Fine-Grained Personal Access Token",
            pattern=re.compile(r"(?<![0-9a-zA-Z])(github_pat_[0-9a-zA-Z_]{22,255})(?![0-9a-zA-Z])"),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["github", "vcs_token"],
            capture_group=1,
        )


class OpenAILegacyKeyRule(BaseRegexRule):
    """Detects standard 51-character legacy OpenAI API keys."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-OAI-001",
            description="OpenAI API Key (Legacy)",
            pattern=re.compile(r"(?<![a-zA-Z0-9])(sk-[a-zA-Z0-9]{48})(?![a-zA-Z0-9])"),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["openai", "ai_platform"],
            capture_group=1,
        )


class OpenAIProjectKeyRule(BaseRegexRule):
    """Detects new-style OpenAI project and service account API keys."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-OAI-002",
            description="OpenAI Project / Service Account API Key",
            pattern=re.compile(r"(?<![a-zA-Z0-9])(sk-proj-[a-zA-Z0-9_\-]{48,160})(?![a-zA-Z0-9])"),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["openai", "ai_platform"],
            capture_group=1,
        )


class GoogleCloudKeyRule(BaseRegexRule):
    """Detects Google Cloud Platform API Keys."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-GCP-001",
            description="Google Cloud API Key",
            pattern=re.compile(r"(?<![0-9A-Za-z_\-])(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["gcp", "google_api"],
            capture_group=1,
        )


class SlackTokenRule(BaseRegexRule):
    """Detects Slack bot, app, and user OAuth access tokens."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-SLACK-001",
            description="Slack Access Token",
            pattern=re.compile(r"(?<![0-9a-zA-Z])(xox[baprs]-[0-9a-zA-Z_\-]{10,80})(?![0-9a-zA-Z])"),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["slack", "collaboration"],
            capture_group=1,
        )


class JWTRule(BaseRegexRule):
    """Detects signed JSON Web Tokens (JWT)."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-JWT-001",
            description="JSON Web Token (JWT)",
            pattern=re.compile(
                r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
            ),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["jwt", "auth_token"],
            capture_group=1,
        )


class PrivateKeyRule(BaseRegexRule):
    """Detects beginning of private cryptographic keys (RSA, OpenSSH, DSA, EC, etc.)."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-KEY-001",
            description="Cryptographic Private Key Header",
            pattern=re.compile(
                r"(-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP|ENCRYPTED|PRIVATE)?(?:\s+PRIVATE)?\s+KEY-----)"
            ),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["crypto", "private_key"],
            capture_group=1,
        )


class AzureTokenRule(BaseRegexRule):
    """Detects Azure Shared Access Signatures and Account Keys."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-AZURE-001",
            description="Azure Storage Account Key / SAS Token",
            pattern=re.compile(
                r"(?i)(?:AccountKey|SharedAccessKey|SharedAccessSignature|sig)=([A-Za-z0-9+/=]{43,88})"
            ),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["azure", "cloud_secret"],
            capture_group=1,
        )


class StripeKeyRule(BaseRegexRule):
    """Detects Stripe API secret and restricted keys."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-STRIPE-001",
            description="Stripe API Key",
            pattern=re.compile(r"\b((?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,99})\b"),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["stripe", "payment_api"],
            capture_group=1,
        )


class TwilioKeyRule(BaseRegexRule):
    """Detects Twilio Account SIDs and API Keys."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-TWILIO-001",
            description="Twilio API Key / SID",
            pattern=re.compile(r"\b((?:AC|SK)[a-f0-9]{32})\b"),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["twilio", "telephony_api"],
            capture_group=1,
        )


class FirebaseKeyRule(BaseRegexRule):
    """Detects Firebase Cloud Messaging Server Keys."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-FB-001",
            description="Firebase Cloud Messaging Server Key",
            pattern=re.compile(r"\b(AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140})\b"),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["firebase", "google_api"],
            capture_group=1,
        )


class DiscordTokenRule(BaseRegexRule):
    """Detects Discord Bot Tokens."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-DISCORD-001",
            description="Discord Bot Token",
            pattern=re.compile(
                r"\b([MN][A-Za-z0-9]{23,26}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38})\b"
            ),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["discord", "bot_token"],
            capture_group=1,
        )


class DatabaseURLRule(BaseRegexRule):
    """Detects database connection URLs with embedded credentials."""

    def __init__(self, entropy_calculator: Optional[IEntropyCalculator] = None) -> None:
        super().__init__(
            rule_id="SG-DB-001",
            description="Database Connection URL with Credentials",
            pattern=re.compile(
                r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^:\s'\"`]+:[^@\s'\"`]+@[^\s'\"`]+)\b"
            ),
            entropy_calculator=entropy_calculator,
            heuristic_tags=["database", "connection_string"],
            capture_group=1,
        )


def get_default_rules(entropy_calculator: Optional[IEntropyCalculator] = None) -> list[IExtractionRule]:
    """Return all standard pre-compiled credential detection rules."""
    calc = entropy_calculator or ShannonEntropyCalculator()
    return [
        AWSAccessKeyRule(calc),
        AWSSecretKeyRule(calc),
        GitHubClassicTokenRule(calc),
        GitHubFineGrainedTokenRule(calc),
        OpenAILegacyKeyRule(calc),
        OpenAIProjectKeyRule(calc),
        GoogleCloudKeyRule(calc),
        SlackTokenRule(calc),
        JWTRule(calc),
        PrivateKeyRule(calc),
        AzureTokenRule(calc),
        StripeKeyRule(calc),
        TwilioKeyRule(calc),
        FirebaseKeyRule(calc),
        DiscordTokenRule(calc),
        DatabaseURLRule(calc),
    ]
