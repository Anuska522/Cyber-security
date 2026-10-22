"""Multi-provider API key rotation manager with lifecycle state transitions and masked logging."""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping, Sequence
from typing import Optional

from secretguard.core.interfaces import IKeyPoolManager
from secretguard.core.models import KeyStatus, ManagedKey, mask_credential

logger = logging.getLogger("secretguard.gateway.key_manager")


class GatewayError(Exception):
    """Base exception for API key rotation gateway failures."""


class AllKeysExhaustedException(GatewayError):
    """Raised when all API keys across all configured providers are throttled or exhausted."""


class KeyRotationManager(IKeyPoolManager):
    """Manages multi-key pools per provider, tracking active, throttled, and exhausted states."""

    def __init__(
        self,
        initial_keys: Optional[Mapping[str, Sequence[str]]] = None,
    ) -> None:
        self._pools: dict[str, list[ManagedKey]] = {}
        self._pointers: dict[str, int] = {}

        if initial_keys:
            for provider, keys in initial_keys.items():
                for key_val in keys:
                    self.add_key(provider, key_val)

    def add_key(self, provider: str, key_value: str) -> None:
        """Register a new key into the designated provider pool."""
        provider_norm = provider.lower().strip()
        if provider_norm not in self._pools:
            self._pools[provider_norm] = []
            self._pointers[provider_norm] = 0

        # Avoid duplicates
        for existing in self._pools[provider_norm]:
            if existing.key_value == key_value:
                return

        self._pools[provider_norm].append(
            ManagedKey(key_value=key_value, provider=provider_norm, status=KeyStatus.ACTIVE)
        )

    def _find_managed_key(self, provider: str, key: str) -> Optional[ManagedKey]:
        """Find the ManagedKey object matching the given provider and raw key string."""
        provider_norm = provider.lower().strip()
        pool = self._pools.get(provider_norm, [])
        for managed in pool:
            if managed.key_value == key:
                return managed
        return None

    def has_any_available_keys(self) -> bool:
        """Check if at least one key across any provider is currently active or cooled down."""
        now = time.time()
        for pool in self._pools.values():
            for managed in pool:
                if managed.is_available(current_time=now):
                    return True
        return False

    def get_active_key(self, provider: str) -> str:
        """Retrieve the current active API key for the provider, rotating past throttled keys."""
        provider_norm = provider.lower().strip()
        now = time.time()

        pool = self._pools.get(provider_norm, [])
        if not pool:
            # Check if any provider has keys at all
            if not self.has_any_available_keys():
                raise AllKeysExhaustedException(
                    f"No API keys configured or all keys exhausted across all providers."
                )
            # Find an alternate available provider
            for alt_provider, alt_pool in self._pools.items():
                for managed in alt_pool:
                    if managed.is_available(current_time=now):
                        return managed.key_value
            raise AllKeysExhaustedException(
                f"No keys available for provider '{provider}' and all fallback pools are exhausted."
            )

        start_idx = self._pointers.get(provider_norm, 0) % len(pool)
        for i in range(len(pool)):
            curr_idx = (start_idx + i) % len(pool)
            managed = pool[curr_idx]
            if managed.is_available(current_time=now):
                self._pointers[provider_norm] = curr_idx
                return managed.key_value

        # All keys in this provider pool are currently THROTTLED or EXHAUSTED
        # Check if another provider has available keys
        for alt_provider, alt_pool in self._pools.items():
            if alt_provider == provider_norm:
                continue
            for managed in alt_pool:
                if managed.is_available(current_time=now):
                    logger.info(
                        "Provider '%s' depleted; falling back to active key on '%s'",
                        provider_norm,
                        alt_provider,
                    )
                    return managed.key_value

        # Global exhaustion across all configured providers
        raise AllKeysExhaustedException(
            f"All API keys across all configured providers ({list(self._pools.keys())}) are throttled or exhausted."
        )

    def record_success(self, provider: str, key: str) -> None:
        """Mark key active and clear consecutive failures upon HTTP 200 response."""
        managed = self._find_managed_key(provider, key)
        if managed:
            managed.mark_active()
            logger.debug(
                "Key %s for provider '%s' confirmed active.",
                managed.masked_key(),
                provider,
            )

    def mark_throttled(
        self,
        provider: str,
        key: str,
        retry_after: float = 60.0,
    ) -> None:
        """Mark key as THROTTLED with cooldown and advance active pointer to next key."""
        provider_norm = provider.lower().strip()
        managed = self._find_managed_key(provider_norm, key)
        backoff = retry_after if retry_after > 0.0 else 60.0

        if managed:
            managed.mark_throttled(cooldown_seconds=backoff)
            logger.warning(
                "Key %s for provider '%s' throttled (HTTP 429). Cooldown: %.1fs.",
                managed.masked_key(),
                provider_norm,
                backoff,
            )

        pool = self._pools.get(provider_norm, [])
        if pool:
            curr_idx = self._pointers.get(provider_norm, 0)
            self._pointers[provider_norm] = (curr_idx + 1) % len(pool)

    def mark_exhausted(self, provider: str, key: str) -> None:
        """Mark key permanently EXHAUSTED for the session and advance active pointer."""
        provider_norm = provider.lower().strip()
        managed = self._find_managed_key(provider_norm, key)

        if managed:
            managed.mark_exhausted()
            logger.error(
                "Key %s for provider '%s' permanently exhausted (HTTP 403 / unrecoverable quota).",
                managed.masked_key(),
                provider_norm,
            )

        pool = self._pools.get(provider_norm, [])
        if pool:
            curr_idx = self._pointers.get(provider_norm, 0)
            self._pointers[provider_norm] = (curr_idx + 1) % len(pool)

    def get_pool_status(self, provider: str) -> list[tuple[str, KeyStatus, Optional[float]]]:
        """Return diagnostic statuses of all keys within a provider pool with masked keys."""
        provider_norm = provider.lower().strip()
        pool = self._pools.get(provider_norm, [])
        return [(m.masked_key(), m.status, m.cooldown_until) for m in pool]
