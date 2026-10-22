"""SecretGuard remediation subsystem."""

from secretguard.remediation.autofix import (
    QuarantineResult,
    SecretQuarantineManager,
)

__all__ = ["SecretQuarantineManager", "QuarantineResult"]
