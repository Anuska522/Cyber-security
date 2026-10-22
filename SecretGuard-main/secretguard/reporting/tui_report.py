"""Cyber-minimalist TUI report formatter adhering to IReportFormatter with box drawing and zero emojis."""

from __future__ import annotations

from typing import Optional

from secretguard.core.interfaces import IReportFormatter
from secretguard.core.models import ScanReport, VerificationResult
from secretguard.tui.theme import (
    BOX_BL,
    BOX_BR,
    BOX_H,
    BOX_TL,
    BOX_TR,
    BOX_V,
    GLYPH_DIAMOND,
    GLYPH_FAILURE,
    GLYPH_SEPARATOR,
    GLYPH_SUCCESS,
    RGB_AMBER,
    RGB_CYBER_CYAN,
    RGB_ELECTRIC_MAGENTA,
    RGB_EMERALD,
    RGB_MUTED_ZINC,
    RGB_OFF_WHITE,
    RGB_ROSE,
    color_text,
    fg_rgb,
    strip_ansi,
)


class TuiReportFormatter(IReportFormatter):
    """Formats ScanReport into a cyber-minimalist, terminal-appliance presentation."""

    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color

    def format_clean_notice(self, latency_seconds: float) -> str:
        """Render the calming single-line clean scan notification.

        Example:
        ◈ SecretGuard :: Repository verified clean (0.24s)
        """
        if not self.use_color:
            return f"{GLYPH_DIAMOND} SecretGuard {GLYPH_SEPARATOR} Repository verified clean ({latency_seconds:.2f}s)"

        glyph = color_text(GLYPH_DIAMOND, RGB_CYBER_CYAN, bold=True)
        title = color_text("SecretGuard", RGB_OFF_WHITE, bold=True)
        sep = color_text(GLYPH_SEPARATOR, RGB_MUTED_ZINC)
        status = color_text("Repository verified clean", RGB_EMERALD)
        lat = color_text(f"({latency_seconds:.2f}s)", RGB_MUTED_ZINC)
        return f"{glyph} {title} {sep} {status} {lat}"

    def format_report(self, report: ScanReport) -> str:
        """Format complete scan report adhering to IReportFormatter."""
        summary = report.summary
        latency_sec = summary.execution_latency_ms / 1000.0

        # If zero true positives, output calming clean notice
        if summary.true_positive_count == 0:
            return self.format_clean_notice(latency_sec)

        box_width = 72
        b_color = fg_rgb(RGB_CYBER_CYAN) if self.use_color else ""
        reset_seq = "\033[0m" if self.use_color else ""
        v_edge = f"{b_color}{BOX_V}{reset_seq}" if self.use_color else BOX_V

        header_title = f"SecretGuard Interception Report ({summary.true_positive_count} detected)"
        title_str = color_text(header_title, RGB_OFF_WHITE, bold=True) if self.use_color else header_title
        dashes_right = max(box_width - len(header_title) - 6, 2)

        top_border = f"{b_color}{BOX_TL}{BOX_H} {title_str} {b_color}{BOX_H * dashes_right}{BOX_TR}{reset_seq}"
        bottom_border = f"{b_color}{BOX_BL}{BOX_H * (box_width - 2)}{BOX_BR}{reset_seq}"

        lines: list[str] = [top_border]

        def add_box_line(content: str = "") -> None:
            clean_len = len(strip_ansi(content))
            pad = max(box_width - 4 - clean_len, 0)
            lines.append(f"{v_edge}  {content}{' ' * pad}{v_edge}")

        add_box_line()

        # Render each true positive finding
        true_positives = [f for f in report.findings if f.is_secret]
        for idx, finding in enumerate(true_positives, 1):
            cand = finding.candidate
            badge_text = self._badge(cand.rule_id, finding.resolved_locally)

            if self.use_color:
                heading = f"{color_text(f'Finding #{idx}', RGB_ROSE, bold=True)}  {badge_text}  {color_text(cand.rule_id, RGB_OFF_WHITE, bold=True)}"
            else:
                heading = f"Finding #{idx}  {badge_text}  {cand.rule_id}"
            add_box_line(heading)

            loc_str = f"{cand.file_path}:{cand.line_number}"
            add_box_line(self._field("Location:   ", loc_str))

            cand_str = f"{cand.masked_literal} (entropy: {cand.entropy_score:.2f})"
            add_box_line(self._field("Candidate:  ", cand_str))

            conf_pct = f"{finding.confidence * 100:.1f}% ({finding.model_used})"
            add_box_line(self._field("Confidence: ", conf_pct))

            # Masked context line
            masked_ctx = self._mask_context(cand.context_window, cand.literal_value, cand.masked_literal)
            add_box_line(self._field("Context:    ", masked_ctx[: box_width - 18]))

            add_box_line(self._field("Action:     ", finding.remediation[: box_width - 18]))
            add_box_line()

        lines.append(bottom_border)

        # Bottom summary line
        status_label = "Blocked" if summary.exit_code == 1 else "Clean"
        status_color = RGB_ROSE if summary.exit_code == 1 else RGB_EMERALD

        if self.use_color:
            sep = color_text(f"  {GLYPH_SEPARATOR}  ", RGB_MUTED_ZINC)
            c_files = f"{color_text('Files:', RGB_MUTED_ZINC)} {color_text(str(summary.total_files_scanned), RGB_OFF_WHITE)}"
            c_lines = f"{color_text('Lines:', RGB_MUTED_ZINC)} {color_text(str(summary.total_lines_scanned), RGB_OFF_WHITE)}"
            c_secrets = f"{color_text('Secrets:', RGB_MUTED_ZINC)} {color_text(str(summary.true_positive_count), RGB_ROSE, bold=True)}"
            c_status = f"{color_text('Status:', RGB_MUTED_ZINC)} {color_text(status_label, status_color, bold=True)}"
            c_lat = f"{color_text('Latency:', RGB_MUTED_ZINC)} {color_text(f'{summary.execution_latency_ms:.1f}ms', RGB_OFF_WHITE)}"
            summary_bar = f"\n{c_files}{sep}{c_lines}{sep}{c_secrets}{sep}{c_status}{sep}{c_lat}\n"
        else:
            summary_bar = (
                f"\nFiles: {summary.total_files_scanned}  {GLYPH_SEPARATOR}  "
                f"Lines: {summary.total_lines_scanned}  {GLYPH_SEPARATOR}  "
                f"Secrets: {summary.true_positive_count}  {GLYPH_SEPARATOR}  "
                f"Status: {status_label}  {GLYPH_SEPARATOR}  "
                f"Latency: {summary.execution_latency_ms:.1f}ms\n"
            )

        lines.append(summary_bar)
        return "\n".join(lines)

    def _badge(self, rule_id: str, resolved_locally: bool) -> str:
        if not resolved_locally:
            text = "[AI Verified]"
            return color_text(text, RGB_ELECTRIC_MAGENTA, bold=True) if self.use_color else text
        if rule_id.startswith("SG-HEUR"):
            text = "[Heuristic]"
            return color_text(text, RGB_AMBER, bold=True) if self.use_color else text
        text = "[Regex]"
        return color_text(text, RGB_CYBER_CYAN, bold=True) if self.use_color else text

    def _field(self, label: str, value: str) -> str:
        if not self.use_color:
            return f"  {label} {value}"
        return f"  {color_text(label, RGB_MUTED_ZINC)} {color_text(value, RGB_OFF_WHITE)}"

    def _mask_context(self, context: str, literal: str, masked: str) -> str:
        clean = context.strip().replace("\n", " ")
        if literal in clean:
            return clean.replace(literal, masked)
        return clean
