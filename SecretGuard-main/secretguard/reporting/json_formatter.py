"""JSON report serialization for machine consumption and CI/CD integrations."""

from __future__ import annotations

import json
from typing import Any

from secretguard.core.interfaces import IReportFormatter
from secretguard.core.models import ScanReport, VerificationResult, mask_credential


class JsonReportFormatter(IReportFormatter):
    """Serializes complete ScanReport data into structured, schema-compliant JSON format."""

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def _serialize_finding(self, finding: VerificationResult) -> dict[str, Any]:
        """Convert a single VerificationResult instance into JSON-compatible dictionary."""
        c = finding.candidate
        return {
            "is_secret": finding.is_secret,
            "confidence": round(finding.confidence, 4),
            "explanation": finding.explanation,
            "remediation": finding.remediation,
            "model_used": finding.model_used,
            "latency_ms": round(finding.latency_ms, 2),
            "resolved_locally": finding.resolved_locally,
            "candidate": {
                "rule_id": c.rule_id,
                "file_path": c.file_path,
                "line_number": c.line_number,
                "literal_masked": mask_credential(c.literal_value),
                "entropy_score": round(c.entropy_score, 4),
                "surrounding_context": c.surrounding_context,
                "heuristic_tags": list(c.heuristic_tags),
                "is_filtered": c.is_filtered,
                "filter_reason": c.filter_reason,
            },
        }

    def format_report(self, report: ScanReport) -> str:
        """Serialize complete scan report into formatted JSON string."""
        s = report.summary
        payload: dict[str, Any] = {
            "version": "0.3.0",
            "scan_target": report.scan_target,
            "timestamp": report.timestamp,
            "config_used": report.config_used,
            "summary": {
                "total_files_scanned": s.total_files_scanned,
                "total_lines_scanned": s.total_lines_scanned,
                "candidates_extracted": s.candidates_extracted,
                "candidates_filtered": s.candidates_filtered,
                "ai_verified_count": s.ai_verified_count,
                "true_positive_count": s.true_positive_count,
                "execution_latency_ms": round(s.execution_latency_ms, 2),
                "exit_code": s.exit_code,
            },
            "findings": [self._serialize_finding(f) for f in report.findings],
        }

        return json.dumps(payload, indent=self.indent)
