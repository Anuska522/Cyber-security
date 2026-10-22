"""Core models and interfaces for SecretGuard."""

from secretguard.core.interfaces import (
    ICandidateFilter,
    IConfigProvider,
    IDiffIngester,
    IEntropyCalculator,
    IExtractionRule,
    IKeyPoolManager,
    ILLMProviderClient,
    IReportFormatter,
    IRoutingPolicy,
    IScanOrchestrator,
)
from secretguard.core.models import (
    DiffLine,
    KeyStatus,
    ManagedKey,
    ModelProfile,
    ScanContext,
    ScanReport,
    ScanSummary,
    SecretCandidate,
    VerificationResult,
    mask_credential,
)

__all__ = [
    "DiffLine",
    "ICandidateFilter",
    "IConfigProvider",
    "IDiffIngester",
    "IEntropyCalculator",
    "IExtractionRule",
    "IKeyPoolManager",
    "ILLMProviderClient",
    "IReportFormatter",
    "IRoutingPolicy",
    "IScanOrchestrator",
    "KeyStatus",
    "ManagedKey",
    "ModelProfile",
    "ScanContext",
    "ScanReport",
    "ScanSummary",
    "SecretCandidate",
    "VerificationResult",
    "mask_credential",
]
