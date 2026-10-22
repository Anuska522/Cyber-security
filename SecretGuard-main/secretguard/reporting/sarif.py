"""SARIF v2.1.0 JSON report formatter for GitHub and GitLab Security Dashboards."""

from __future__ import annotations

import json
from typing import Any

from secretguard.core.interfaces import IReportFormatter
from secretguard.core.models import ScanReport, VerificationResult

SARIF_SCHEMA_V210 = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


class SarifReportFormatter(IReportFormatter):
    """Produces SARIF v2.1.0 formatted payloads for GitHub Advanced Security and GitLab."""

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def _build_rule_metadata(self, findings: list[VerificationResult]) -> list[dict[str, Any]]:
        """Extract unique rule IDs from findings and synthesize SARIF rule descriptors."""
        seen_rules: set[str] = set()
        rules: list[dict[str, Any]] = []

        for f in findings:
            rule_id = f.candidate.rule_id
            if rule_id in seen_rules:
                continue
            seen_rules.add(rule_id)

            rules.append(
                {
                    "id": rule_id,
                    "name": rule_id.replace("-", ""),
                    "shortDescription": {
                        "text": f"SecretGuard credential detection signature: {rule_id}",
                    },
                    "fullDescription": {
                        "text": (
                            f"Identifies exposed credentials and tokens matching signature {rule_id}. "
                            "Hardcoded credentials expose systems to unauthorized access and lateral movement."
                        ),
                    },
                    "defaultConfiguration": {
                        "level": "error",
                    },
                    "properties": {
                        "tags": ["security", "secrets", "credential-exposure"],
                        "precision": "high",
                    },
                }
            )

        return rules

    def _convert_finding_to_result(self, finding: VerificationResult) -> dict[str, Any]:
        """Convert a single VerificationResult into a SARIF result record."""
        c = finding.candidate
        level = "error" if finding.confidence >= 0.8 else "warning"

        return {
            "ruleId": c.rule_id,
            "level": level,
            "message": {
                "text": (
                    f"Exposed secret candidate detected ({c.rule_id}): {finding.explanation}. "
                    f"Remediation: {finding.remediation}"
                ),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": c.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(1, c.line_number),
                            "snippet": {
                                "text": c.surrounding_context,
                            },
                        },
                    },
                }
            ],
            "properties": {
                "confidence": round(finding.confidence, 4),
                "entropy": round(c.entropy_score, 4),
                "modelUsed": finding.model_used,
                "resolvedLocally": finding.resolved_locally,
                "remediation": finding.remediation,
            },
        }

    def format_report(self, report: ScanReport) -> str:
        """Render complete ScanReport into valid SARIF v2.1.0 document string."""
        active_findings = [f for f in report.findings if f.is_secret]
        rules = self._build_rule_metadata(active_findings)
        results = [self._convert_finding_to_result(f) for f in active_findings]

        sarif_doc: dict[str, Any] = {
            "$schema": SARIF_SCHEMA_V210,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecretGuard",
                            "organization": "SecretGuard AppSec",
                            "semanticVersion": "0.3.0",
                            "informationUri": "https://github.com/secretguard/secretguard",
                            "rules": rules,
                        },
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif_doc, indent=self.indent)
