"""Configuration exceptions for SecretGuard."""


class ConfigError(Exception):
    """Base exception for all configuration errors."""


class InsecureConfigPermissionsError(ConfigError):
    """Raised when a configuration file has overly permissive POSIX permissions in strict mode."""
