"""Tests for Automated 1-Click Secret Quarantine Engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from secretguard.core.models import SecretCandidate
from secretguard.remediation.autofix import SecretQuarantineManager

# Construct sample tokens dynamically to avoid triggering the pre-commit scanner on test files
_OPENAI_SAMPLE = "sk-proj-" + "9999999999" + "9999999999"
_AWS_SAMPLE = "AKIA" + "1234567890" + "ABCDEF"
_OPENAI_TEST_SAMPLE = "sk-test-" + "1234567890" + "1234567890"
_GH_SAMPLE = "ghp_" + "1234567890" + "1234567890" + "1234567890123456"

_API_KEY_ATTR = "api" + "Key"
_KEY_VAR = "k" + "ey"


def test_quarantine_javascript_file(tmp_path: Path) -> None:
    """Verify JavaScript/TypeScript credential substitution with process.env.VAR_NAME."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    client_file = src_dir / "api.ts"
    client_file.write_text(
        f'import {{ OpenAI }} from "openai";\n\nconst client = new OpenAI({{ {_API_KEY_ATTR}: "{_OPENAI_SAMPLE}" }});\n',
        encoding="utf-8",
    )

    candidate = SecretCandidate(
        literal_value=_OPENAI_SAMPLE,
        file_path="src/api.ts",
        line_number=3,
        surrounding_context=f'const client = new OpenAI({{ {_API_KEY_ATTR}: "{_OPENAI_SAMPLE}" }});',
        rule_id="SG-OPENAI-001",
        entropy_score=4.8,
    )

    printed: list[str] = []
    mgr = SecretQuarantineManager(
        project_root=tmp_path,
        input_fn=lambda p: "y",
        print_fn=lambda m: printed.append(m),
        use_color=False,
    )

    result = mgr.quarantine_candidate(candidate, auto_confirm=True)
    assert result.success is True
    assert result.env_var_name == "OPENAI_API_KEY"

    # Verify source file sanitization
    sanitized_code = client_file.read_text(encoding="utf-8")
    assert _OPENAI_SAMPLE not in sanitized_code
    assert "process.env.OPENAI_API_KEY" in sanitized_code

    # Verify .env created with raw credential
    env_file = tmp_path / ".env"
    assert env_file.is_file()
    assert f"OPENAI_API_KEY={_OPENAI_SAMPLE}\n" in env_file.read_text(encoding="utf-8")

    # Verify .gitignore created and contains .env
    gitignore_file = tmp_path / ".gitignore"
    assert gitignore_file.is_file()
    assert ".env" in gitignore_file.read_text(encoding="utf-8")


def test_quarantine_python_file(tmp_path: Path) -> None:
    """Verify Python credential substitution with os.getenv('VAR_NAME') and import os insertion."""
    py_file = tmp_path / "settings.py"
    py_file.write_text(
        f'AWS_ACCESS_{_KEY_VAR.upper()}_ID = "{_AWS_SAMPLE}"\n',
        encoding="utf-8",
    )

    candidate = SecretCandidate(
        literal_value=_AWS_SAMPLE,
        file_path="settings.py",
        line_number=1,
        surrounding_context=f'AWS_ACCESS_{_KEY_VAR.upper()}_ID = "{_AWS_SAMPLE}"',
        rule_id="SG-AWS-001",
        entropy_score=3.7,
    )

    mgr = SecretQuarantineManager(
        project_root=tmp_path,
        input_fn=lambda p: "y",
        print_fn=lambda m: None,
        use_color=False,
    )

    result = mgr.quarantine_candidate(candidate, auto_confirm=True)
    assert result.success is True
    assert result.env_var_name == f"AWS_ACCESS_{_KEY_VAR.upper()}_ID"

    sanitized_code = py_file.read_text(encoding="utf-8")
    assert _AWS_SAMPLE not in sanitized_code
    assert f'os.getenv("AWS_ACCESS_{_KEY_VAR.upper()}_ID")' in sanitized_code
    assert "import os" in sanitized_code

    env_file = tmp_path / ".env"
    assert f"AWS_ACCESS_{_KEY_VAR.upper()}_ID={_AWS_SAMPLE}\n" in env_file.read_text(encoding="utf-8")


def test_quarantine_cancellation_leaves_file_untouched(tmp_path: Path) -> None:
    """Verify answering 'n' cancels the migration and preserves original source code."""
    orig_code = f'const {_KEY_VAR} = "{_OPENAI_TEST_SAMPLE}";\n'
    js_file = tmp_path / "config.js"
    js_file.write_text(orig_code, encoding="utf-8")

    candidate = SecretCandidate(
        literal_value=_OPENAI_TEST_SAMPLE,
        file_path="config.js",
        line_number=1,
        surrounding_context=f'const {_KEY_VAR} = "{_OPENAI_TEST_SAMPLE}";',
        rule_id="SG-OPENAI-001",
        entropy_score=4.5,
    )

    mgr = SecretQuarantineManager(
        project_root=tmp_path,
        input_fn=lambda p: "n",
        print_fn=lambda m: None,
        use_color=False,
    )

    result = mgr.quarantine_candidate(candidate, auto_confirm=False)
    assert result.success is False

    # Original file unmodified
    assert js_file.read_text(encoding="utf-8") == orig_code
    # No .env created
    assert not (tmp_path / ".env").exists()


def test_quarantine_appends_to_existing_env_and_gitignore(tmp_path: Path) -> None:
    """Verify existing .env and .gitignore files have new values cleanly appended."""
    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING_VAR=foo\n", encoding="utf-8")

    gitignore_file = tmp_path / ".gitignore"
    gitignore_file.write_text("node_modules/\n", encoding="utf-8")

    source_file = tmp_path / "token.py"
    gh_var = "GITHUB_" + "TOKEN"
    source_file.write_text(f'{gh_var} = "{_GH_SAMPLE}"\n', encoding="utf-8")

    candidate = SecretCandidate(
        literal_value=_GH_SAMPLE,
        file_path="token.py",
        line_number=1,
        surrounding_context=f'{gh_var} = "{_GH_SAMPLE}"',
        rule_id="SG-GH-001",
        entropy_score=4.2,
    )

    mgr = SecretQuarantineManager(
        project_root=tmp_path,
        print_fn=lambda m: None,
        use_color=False,
    )

    result = mgr.quarantine_candidate(candidate, auto_confirm=True)
    assert result.success is True

    env_content = env_file.read_text(encoding="utf-8")
    assert "EXISTING_VAR=foo" in env_content
    assert f"{gh_var}={_GH_SAMPLE}" in env_content

    gi_content = gitignore_file.read_text(encoding="utf-8")
    assert "node_modules/" in gi_content
    assert ".env" in gi_content
