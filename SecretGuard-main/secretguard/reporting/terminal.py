"""Terminal report formatter with structured ANSI styling, badges, and metrics."""

from __future__ import annotations

from typing import Final

from secretguard.core.interfaces import IReportFormatter
from secretguard.core.models import ScanReport, VerificationResult, mask_credential

# ANSI Color and Styling Codes
RESET: Final[str] = "\033[0m"
BOLD: Final[str] = "\033[1m"
DIM: Final[str] = "\033[2m"
RED: Final[str] = "\033[91m"
GREEN: Final[str] = "\033[92m"
YELLOW: Final[str] = "\033[93m"
BLUE: Final[str] = "\033[94m"
MAGENTA: Final[str] = "\033[95m"
CYAN: Final[str] = "\033[96m"
WHITE: Final[str] = "\033[97m"


class TerminalReportFormatter(IReportFormatter):
    """Renders human-readable, ANSI-colored terminal reports with finding cards and summary statistics."""

    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color

    def _c(self, text: str, color_code: str) -> str:
        """Apply color code if coloring is enabled, else return plain text."""
        if not self.use_color:
            return text
        return f"{color_code}{text}{RESET}"

    def _determine_badge(self, finding: VerificationResult) -> str:
        """Construct detection badge: [Regex], [Heuristic], [Entropy], or [AI Verified]."""
        if not finding.resolved_locally:
            return self._c("[AI Verified]", f"{BOLD}{MAGENTA}")

        rule_id = finding.candidate.rule_id
        if "HEUR" in rule_id:
            return self._c("[Heuristic]", f"{BOLD}{CYAN}")
        if "ENTROPY" in rule_id or finding.candidate.entropy_score >= 4.5:
            return self._c("[Entropy]", f"{BOLD}{BLUE}")
        return self._c("[Regex]", f"{BOLD}{YELLOW}")

    def format_finding_card(self, index: int, finding: VerificationResult) -> str:
        """Render a single finding card with code snippet, confidence, and remediation."""
        c = finding.candidate
        badge = self._determine_badge(finding)
        conf_pct = f"{finding.confidence * 100:.1f}%"
        masked_val = mask_credential(c.literal_value)
        masked_context = c.surrounding_context.replace(c.literal_value, masked_val)

        lines = [
            f"{self._c(f'Finding #{index}', f'{BOLD}{RED}')} {badge} {self._c(c.rule_id, BOLD)}",
            f"  {self._c('Location:', DIM)}     {c.file_path}:{c.line_number}",
            f"  {self._c('Candidate:', DIM)}    {masked_val} (entropy: {c.entropy_score:.2f})",
            f"  {self._c('Confidence:', DIM)}   {conf_pct} (evaluated via {finding.model_used})",
            f"  {self._c('Context:', DIM)}",
            f"    {self._c(masked_context, YELLOW)}",
            f"  {self._c('Explanation:', DIM)}  {finding.explanation}",
            f"  {self._c('Remediation:', DIM)}  {self._c(finding.remediation, GREEN)}",
            "",
        ]
        return "\n".join(lines)

    def format_report(self, report: ScanReport) -> str:
        """Format complete scan report into ANSI terminal presentation."""
        output_blocks: list[str] = []

        # Banner Header
        banner = [
            self._c("=" * 72, DIM),
            f"{self._c('SecretGuard', f'{BOLD}{CYAN}')} Enterprise Secret Scanner — Report",
            f"{self._c('Target:', DIM)} {report.scan_target}  |  {self._c('Timestamp:', DIM)} {report.timestamp}",
            self._c("=" * 72, DIM),
            "",
        ]
        output_blocks.append("\n".join(banner))

        # Filter active findings (is_secret == True)
        active_findings = [f for f in report.findings if f.is_secret]

        if not active_findings:
            clean_msg = [
                self._c("✓ SCAN CLEAN: No hardcoded secrets detected.", f"{BOLD}{GREEN}"),
                f"  Scanned {report.summary.total_files_scanned} files across {report.summary.total_lines_scanned} lines.",
                "",
            ]
            output_blocks.append("\n".join(clean_msg))
        else:
            header_finding = [
                self._c(f"✕ DETECTED {len(active_findings)} POTENTIAL SECRET(S):", f"{BOLD}{RED}"),
                self._c("-" * 72, DIM),
                "",
            ]
            output_blocks.append("\n".join(header_finding))

            for idx, finding in enumerate(active_findings, start=1):
                output_blocks.append(self.format_finding_card(idx, finding))

        # Execution Summary Statistics
        s = report.summary
        models_used = sorted(list({f.model_used for f in report.findings}))
        models_str = ", ".join(models_used) if models_used else "None"

        summary_lines = [
            self._c("-" * 72, DIM),
            self._c("Execution Summary Statistics:", BOLD),
            f"  {self._c('Files Scanned:', DIM):<28} {s.total_files_scanned}",
            f"  {self._c('Lines Scanned:', DIM):<28} {s.total_lines_scanned}",
            f"  {self._c('Candidates Extracted:', DIM):<28} {s.candidates_extracted}",
            f"  {self._c('Placeholders Suppressed:', DIM):<28} {s.candidates_filtered}",
            f"  {self._c('AI Verified Items:', DIM):<28} {s.ai_verified_count}",
            f"  {self._c('True Positives Confirmed:', DIM):<28} {self._c(str(s.true_positive_count), BOLD if s.true_positive_count == 0 else f'{BOLD}{RED}')}",
            f"  {self._c('Profiles / Models Active:', DIM):<28} {models_str}",
            f"  {self._c('Elapsed Scan Latency:', DIM):<28} {s.execution_latency_ms:.2f} ms",
            f"  {self._c('Process Exit Status:', DIM):<28} {s.exit_code}",
            self._c("=" * 72, DIM),
        ]
        output_blocks.append("\n".join(summary_lines))

        return "\n".join(output_blocks)
