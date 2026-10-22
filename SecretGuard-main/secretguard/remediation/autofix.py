"""Automated 1-Click Secret Quarantine Engine migrating credentials to .env and sanitizing source code."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from secretguard.core.models import SecretCandidate
from secretguard.tui.theme import (
    BOX_BL,
    BOX_BR,
    BOX_H,
    BOX_TL,
    BOX_TR,
    BOX_V,
    GLYPH_ARROW,
    GLYPH_PROMPT,
    GLYPH_SUCCESS,
    RGB_AMBER,
    RGB_CYBER_CYAN,
    RGB_EMERALD,
    RGB_MUTED_ZINC,
    RGB_OFF_WHITE,
    RGB_ROSE,
    color_text,
    fg_rgb,
    strip_ansi,
)

RULE_TO_ENV_MAP: dict[str, str] = {
    "SG-OPENAI-001": "OPENAI_API_KEY",
    "SG-AWS-001": "AWS_ACCESS_KEY_ID",
    "SG-AWS-002": "AWS_SECRET_ACCESS_KEY",
    "SG-GH-001": "GITHUB_TOKEN",
    "SG-GH-002": "GITHUB_FINE_GRAINED_TOKEN",
    "SG-SLACK-001": "SLACK_BOT_TOKEN",
    "SG-STRIPE-001": "STRIPE_API_KEY",
    "SG-TWILIO-001": "TWILIO_AUTH_TOKEN",
    "SG-AZURE-001": "AZURE_CLIENT_SECRET",
    "SG-GCP-001": "GOOGLE_API_KEY",
    "SG-DB-001": "DATABASE_URL",
}


@dataclass(frozen=True)
class QuarantineResult:
    """Outcome of a quarantine operation."""

    success: bool
    env_var_name: str
    target_file: str
    env_file_path: str
    message: str


class SecretQuarantineManager:
    """Inspects intercepted secret candidates, migrates them to .env, and sanitizes code in-place."""

    def __init__(
        self,
        project_root: str | Path = ".",
        input_fn: Callable[[str], str] = input,
        print_fn: Callable[[str], None] = print,
        use_color: bool = True,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.input_fn = input_fn
        self.print_fn = print_fn
        self.use_color = use_color

    def infer_env_var_name(self, candidate: SecretCandidate) -> str:
        """Derive standard uppercase SNAKE_CASE environment variable name from candidate rule or context."""
        if candidate.rule_id in RULE_TO_ENV_MAP:
            return RULE_TO_ENV_MAP[candidate.rule_id]

        # Extract identifier from line context (e.g. const apiKey = ... or token = ...)
        line = candidate.context_window or ""
        match = re.search(r"(?:const|let|var)?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]", line)
        if match:
            var_name = match.group(1)
            # Convert camelCase to SNAKE_CASE
            snake = re.sub(r"(?<!^)(?=[A-Z])", "_", var_name).upper()
            return f"{snake}"

        return "SECRET_API_KEY"

    def render_diagnostic_card(
        self,
        candidate: SecretCandidate,
        reason: str = "Live credential exposed in source code",
    ) -> str:
        """Render cyber-minimalist rounded diagnostic card for the intercepted credential."""
        box_width = 70
        title = "Credential Intercepted"
        b_color = fg_rgb(RGB_ROSE) if self.use_color else ""
        reset_seq = "\033[0m" if self.use_color else ""
        v_edge = f"{b_color}{BOX_V}{reset_seq}" if self.use_color else BOX_V

        title_str = color_text(title, RGB_ROSE, bold=True) if self.use_color else title
        dashes_right = box_width - len(title) - 6

        top_border = f"{b_color}{BOX_TL}{BOX_H} {title_str} {b_color}{BOX_H * dashes_right}{BOX_TR}{reset_seq}"
        bottom_border = f"{b_color}{BOX_BL}{BOX_H * (box_width - 2)}{BOX_BR}{reset_seq}"

        masked_val = candidate.masked_literal
        target_info = f"{candidate.file_path} : line {candidate.line_number}"
        type_info = f"{candidate.rule_id} ({masked_val})"

        # Context truncation to fit neatly
        clean_ctx = candidate.context_window.strip().replace("\n", " ")
        if len(clean_ctx) > box_width - 16:
            clean_ctx = f"{clean_ctx[:box_width - 20]}..."

        rows = [
            ("Target:  ", target_info),
            ("Type:    ", type_info),
            ("Context: ", clean_ctx),
            ("Reason:  ", reason),
        ]

        card_lines: list[str] = [top_border]
        for label, val in rows:
            if self.use_color:
                line_content = f"{color_text(label, RGB_MUTED_ZINC)} {color_text(val, RGB_OFF_WHITE)}"
            else:
                line_content = f"{label} {val}"

            clean_len = len(strip_ansi(line_content))
            pad = max(box_width - 4 - clean_len, 0)
            card_lines.append(f"{v_edge} {line_content}{' ' * pad}{v_edge}")

        card_lines.append(bottom_border)
        return "\n".join(card_lines)

    def quarantine_candidate(
        self,
        candidate: SecretCandidate,
        auto_confirm: bool = False,
        reason: str = "Live credential exposed in source code",
    ) -> QuarantineResult:
        """Present diagnostic card, prompt for confirmation, migrate to .env, and sanitize code."""
        # 1. Display Diagnostic Card
        card = self.render_diagnostic_card(candidate, reason=reason)
        self.print_fn(card)

        # 2. Prompt for Confirmation
        if not auto_confirm:
            glyph_p = color_text(GLYPH_PROMPT, RGB_AMBER, bold=True) if self.use_color else GLYPH_PROMPT
            glyph_a = color_text(GLYPH_ARROW, RGB_AMBER) if self.use_color else GLYPH_ARROW
            prompt_str = f"\n{glyph_p} Migrate secret to .env and sanitize source file? [Y/n] {glyph_a} "
            try:
                resp = self.input_fn(prompt_str).strip().lower()
            except (EOFError, KeyboardInterrupt):
                resp = "n"

            if resp and resp not in ("y", "yes"):
                return QuarantineResult(
                    success=False,
                    env_var_name="",
                    target_file=candidate.file_path,
                    env_file_path="",
                    message="Quarantine cancelled by developer.",
                )

        # 3. Resolve Target File & Env Var
        env_var_name = self.infer_env_var_name(candidate)
        target_path = self.project_root / candidate.file_path
        env_path = self.project_root / ".env"
        gitignore_path = self.project_root / ".gitignore"

        if not target_path.exists():
            return QuarantineResult(
                success=False,
                env_var_name=env_var_name,
                target_file=candidate.file_path,
                env_file_path=str(env_path),
                message=f"Target file not found: {target_path}",
            )

        # 4. Update Source Code
        raw_literal = candidate.literal_value
        source_content = target_path.read_text(encoding="utf-8")
        ext = target_path.suffix.lower()

        sanitized_content = self._sanitize_content(source_content, raw_literal, env_var_name, ext)
        target_path.write_text(sanitized_content, encoding="utf-8")

        # 5. Append to .env
        self._append_to_env(env_path, env_var_name, raw_literal)

        # 6. Ensure .env is ignored in .gitignore
        self._ensure_env_gitignored(gitignore_path)

        # 7. Print calming success notice
        glyph_check = color_text(GLYPH_SUCCESS, RGB_EMERALD, bold=True) if self.use_color else GLYPH_SUCCESS
        success_msg = f"{glyph_check} Quarantined. Source file sanitized. Proceeding with commit."
        self.print_fn(success_msg)

        return QuarantineResult(
            success=True,
            env_var_name=env_var_name,
            target_file=str(target_path),
            env_file_path=str(env_path),
            message=success_msg,
        )

    def _sanitize_content(self, content: str, raw_literal: str, env_var: str, ext: str) -> str:
        """Replace the raw credential literal with the appropriate language-specific env var accessor."""
        if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            replacement = f"process.env.{env_var}"
        elif ext == ".py":
            replacement = f'os.getenv("{env_var}")'
        elif ext == ".go":
            replacement = f'os.Getenv("{env_var}")'
        else:
            replacement = f'${{{env_var}}}'

        # Replace double or single quoted literal
        double_quoted = f'"{raw_literal}"'
        single_quoted = f"'{raw_literal}'"

        if double_quoted in content:
            new_content = content.replace(double_quoted, replacement, 1)
        elif single_quoted in content:
            new_content = content.replace(single_quoted, replacement, 1)
        else:
            new_content = content.replace(raw_literal, replacement, 1)

        # For Python files, ensure 'import os' is present if needed
        if ext == ".py" and "os.getenv(" in new_content and "import os" not in new_content:
            new_content = f"import os\n{new_content}"

        return new_content

    def _append_to_env(self, env_path: Path, env_var: str, literal: str) -> None:
        """Safely write or append the key-value pair to root .env."""
        line_to_add = f"{env_var}={literal}\n"
        if env_path.exists():
            existing = env_path.read_text(encoding="utf-8")
            if f"{env_var}=" not in existing:
                if existing and not existing.endswith("\n"):
                    existing += "\n"
                env_path.write_text(existing + line_to_add, encoding="utf-8")
        else:
            env_path.write_text(line_to_add, encoding="utf-8")

    def _ensure_env_gitignored(self, gitignore_path: Path) -> None:
        """Ensure .env is listed in .gitignore to prevent accidental leakage."""
        if gitignore_path.exists():
            content = gitignore_path.read_text(encoding="utf-8")
            patterns = [p.strip() for p in content.splitlines()]
            if ".env" not in patterns and "*.env" not in patterns:
                if content and not content.endswith("\n"):
                    content += "\n"
                gitignore_path.write_text(content + ".env\n", encoding="utf-8")
        else:
            gitignore_path.write_text(".env\n", encoding="utf-8")
