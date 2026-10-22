"""End-to-end scan pipeline orchestrator coordinating ingestion, extraction, verification, and reporting."""

from __future__ import annotations

import datetime
import logging
import time
from typing import Any, Optional

from secretguard.config.manager import ConfigManager
from secretguard.config.models import SecretGuardConfig
from secretguard.core.interfaces import (
    IConfigProvider,
    IDiffIngester,
    IScanOrchestrator,
)
from secretguard.core.models import (
    ScanContext,
    ScanReport,
    ScanSummary,
    VerificationResult,
)
from secretguard.extract.engine import DeterministicExtractionEngine
from secretguard.gateway.dispatcher import ProviderDispatcher
from secretguard.gateway.key_manager import KeyRotationManager
from secretguard.ingest.fs_scanner import FileSystemScanner
from secretguard.ingest.git_diff import GitDiffParser
from secretguard.logging.logger import get_redaction_filter, log_diagnostic_event
from secretguard.router.policy import AdaptiveRoutingPolicy
from secretguard.verifier.evaluator import ContextualVerifier

logger = logging.getLogger("secretguard.orchestrator")


class ScanOrchestrator(IScanOrchestrator):
    """Orchestrates complete scan lifecycle across ingestion, static extraction, AI verification, and reporting."""

    def __init__(
        self,
        config_provider: Optional[IConfigProvider] = None,
        git_ingester: Optional[IDiffIngester] = None,
        fs_ingester: Optional[IDiffIngester] = None,
        extraction_engine: Optional[DeterministicExtractionEngine] = None,
        verifier: Optional[ContextualVerifier] = None,
    ) -> None:
        self.config_provider = config_provider or ConfigManager()
        self.git_ingester = git_ingester or GitDiffParser()
        self.fs_ingester = fs_ingester or FileSystemScanner()
        self.extraction_engine = extraction_engine or DeterministicExtractionEngine()
        self.verifier = verifier

    def _resolve_verifier(self, config: SecretGuardConfig) -> ContextualVerifier:
        """Instantiate or reuse ContextualVerifier wired with active configuration."""
        if self.verifier is not None:
            return self.verifier

        key_manager = KeyRotationManager(initial_keys=config.provider_keys)
        routing_policy = AdaptiveRoutingPolicy()
        dispatcher = ProviderDispatcher(key_manager=key_manager)
        return ContextualVerifier(
            routing_policy=routing_policy,
            key_manager=key_manager,
            provider_client=dispatcher,
        )

    def run_scan(self, context: ScanContext) -> ScanReport:
        """Execute end-to-end scan lifecycle and return comprehensive ScanReport."""
        start_time = time.perf_counter()
        config: SecretGuardConfig = self.config_provider.get_config()
        verifier = self._resolve_verifier(config)
        redaction_filter = get_redaction_filter()

        # 1. Select Ingestion Strategy
        use_diff = context.is_pre_commit or context.diff_mode
        ingester: IDiffIngester = self.git_ingester if use_diff else self.fs_ingester

        logger.info(
            "Starting SecretGuard scan on %s (diff_mode=%s, pre_commit=%s)",
            context.target_path,
            context.diff_mode,
            context.is_pre_commit,
        )

        # 2. Streaming Ingestion & Static Extraction
        total_lines_scanned = 0
        distinct_files: set[str] = set()
        raw_candidates = []

        extract_start = time.perf_counter()
        for diff_line in ingester.stream_diff_lines(context):
            total_lines_scanned += 1
            distinct_files.add(diff_line.file_path)

            extracted = self.extraction_engine.extract_from_diff_line(diff_line)
            for c in extracted:
                raw_candidates.append(c)
                # Register secret value in logger filter to prevent leakages
                redaction_filter.register_secret(c.literal_value)

        extract_latency_ms = (time.perf_counter() - extract_start) * 1000.0
        log_diagnostic_event(
            "static_extraction_complete",
            {
                "lines": total_lines_scanned,
                "candidates": len(raw_candidates),
                "latency_ms": f"{extract_latency_ms:.2f}",
            },
        )

        # 3. Privacy-Isolated Verification (Adaptive Routing + AI / Deterministic)
        verified_results: list[VerificationResult] = []
        ai_verified_count = 0
        candidates_filtered = 0

        verify_start = time.perf_counter()
        for candidate in raw_candidates:
            if candidate.is_filtered:
                candidates_filtered += 1

            result = verifier.verify(candidate, config=config)
            verified_results.append(result)

            if not result.resolved_locally:
                ai_verified_count += 1

        verify_latency_ms = (time.perf_counter() - verify_start) * 1000.0
        log_diagnostic_event(
            "verification_complete",
            {
                "total_verified": len(verified_results),
                "ai_verified": ai_verified_count,
                "latency_ms": f"{verify_latency_ms:.2f}",
            },
        )

        # 4. Summary & Exit Code Computation
        true_positives = [res for res in verified_results if res.is_secret]
        true_positive_count = len(true_positives)
        exit_code = 1 if true_positive_count > 0 else 0

        total_latency_ms = (time.perf_counter() - start_time) * 1000.0

        summary = ScanSummary(
            total_files_scanned=len(distinct_files),
            total_lines_scanned=total_lines_scanned,
            candidates_extracted=len(raw_candidates),
            candidates_filtered=candidates_filtered,
            ai_verified_count=ai_verified_count,
            true_positive_count=true_positive_count,
            execution_latency_ms=round(total_latency_ms, 2),
            exit_code=exit_code,
        )

        config_dict: dict[str, Any] = {
            "entropy_threshold": config.entropy_threshold,
            "min_candidate_length": config.min_candidate_length,
            "strict_permissions": config.strict_permissions,
            "routing_profile": config.routing_profile,
            "profile_override": config.profile_override,
            "max_context_window": config.max_context_window,
        }

        report = ScanReport(
            findings=verified_results,
            summary=summary,
            scan_target=context.target_path,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            config_used=config_dict,
        )

        logger.info(
            "Scan complete: %d secrets found across %d lines in %.2f ms (exit_code=%d)",
            true_positive_count,
            total_lines_scanned,
            total_latency_ms,
            exit_code,
        )
        return report
