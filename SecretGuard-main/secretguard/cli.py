"""Unified command-line interface for SecretGuard secret scanner and pre-commit hook."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Optional, Sequence

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stdin, "reconfigure"):
        try:
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

import click
import yaml

from secretguard.config.exceptions import ConfigError
from secretguard.config.manager import ConfigManager
from secretguard.config.models import SecretGuardConfig
from secretguard.core.models import ScanContext
from secretguard.logging.logger import setup_logging
from secretguard.orchestrator import ScanOrchestrator
from secretguard.remediation.autofix import SecretQuarantineManager
from secretguard.reporting.json_formatter import JsonReportFormatter
from secretguard.reporting.sarif import SarifReportFormatter
from secretguard.reporting.terminal import TerminalReportFormatter
from secretguard.reporting.tui_report import TuiReportFormatter
from secretguard.tui.banner import render_banner
from secretguard.tui.statusline import render_statusline
from secretguard.tui.wizard import DEFAULT_CONFIG_PATH, run_autopilot_wizard


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version="0.3.0", prog_name="SecretGuard")
def main(ctx: click.Context) -> None:
    """SecretGuard: Enterprise-grade lightweight CLI secret scanner and pre-commit hook."""
    if ctx.invoked_subcommand is None:
        click.echo(render_banner())
        click.echo(render_statusline())
        click.echo("")
        click.echo("  Run 'secretguard scan' to verify repository security.")
        click.echo("  Run 'secretguard autopilot' to configure automated hooks.")


@main.command("autopilot")
@click.option(
    "--repo",
    "-r",
    default=".",
    help="Target repository directory (default: current directory).",
)
def autopilot_command(repo: str) -> None:
    """Launch the minimal 3-question Autopilot onboarding wizard."""
    run_autopilot_wizard(repo_path=repo)


@main.command("scan")
@click.argument("path", default=".", type=click.Path(exists=False))
@click.option(
    "--pre-commit",
    is_flag=True,
    default=False,
    help="Intercept staged pre-commit hunks via git diff --cached.",
)
@click.option(
    "--format",
    "-f",
    "report_format",
    type=click.Choice(["terminal", "json", "sarif", "tui"], case_sensitive=False),
    default="terminal",
    help="Output serialization format (default: terminal).",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Destination file path to write the formatted report.",
)
@click.option(
    "--profile",
    "-p",
    type=click.Choice(["auto", "A", "B", "C"], case_sensitive=False),
    default="auto",
    help="Target LLM verification profile tier (default: auto).",
)
@click.option(
    "--quarantine",
    "-q",
    is_flag=True,
    default=False,
    help="Interactively quarantine intercepted secrets into .env and sanitize code.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose diagnostic pipeline event logging.",
)
@click.option(
    "--debug",
    "-d",
    is_flag=True,
    default=False,
    help="Enable detailed low-level debug logging.",
)
@click.option(
    "--ignore",
    "-i",
    "ignore_patterns",
    multiple=True,
    help="Additional glob pattern(s) to ignore during scanning.",
)
def scan_command(
    path: str,
    pre_commit: bool,
    report_format: str,
    output_file: Optional[str],
    profile: str,
    quarantine: bool,
    verbose: bool,
    debug: bool,
    ignore_patterns: Sequence[str],
) -> None:
    """Scan local repositories, directories, or staged Git diffs for hardcoded secrets."""
    setup_logging(verbose=verbose, debug=debug)

    target_path = Path(path).resolve()
    if not target_path.exists() and not pre_commit:
        click.echo(f"Error: Target path does not exist: {target_path}", err=True)
        sys.exit(2)

    try:
        config_manager = ConfigManager(base_dir=target_path if target_path.is_dir() else target_path.parent)
        config: SecretGuardConfig = config_manager.get_config()

        # Apply CLI profile override if explicitly provided
        if profile.upper() != "AUTO":
            config.profile_override = profile.upper()

        # Combine ignore patterns
        combined_ignores = list(config.ignore_patterns)
        combined_ignores.extend(ignore_patterns)

        scan_context = ScanContext(
            target_path=str(target_path),
            is_pre_commit=pre_commit,
            diff_mode=pre_commit,
            ignore_patterns=combined_ignores,
        )

        orchestrator = ScanOrchestrator(config_provider=config_manager)
        report = orchestrator.run_scan(scan_context)

        # Select target formatter
        fmt_lower = report_format.lower()
        if fmt_lower == "json":
            formatter = JsonReportFormatter()
        elif fmt_lower == "sarif":
            formatter = SarifReportFormatter()
        elif fmt_lower == "tui":
            formatter = TuiReportFormatter()
        else:
            formatter = TerminalReportFormatter()

        rendered = formatter.format_report(report)

        if output_file is not None:
            out_path = Path(output_file).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
            if fmt_lower not in ("terminal", "tui"):
                click.echo(f"Report written to {out_path}")
        else:
            click.echo(rendered)

        # Trigger 1-click quarantine if requested
        if report.summary.true_positive_count > 0 and quarantine:
            quarantine_mgr = SecretQuarantineManager(project_root=target_path)
            all_quarantined = True
            for finding in report.findings:
                if finding.is_secret:
                    res = quarantine_mgr.quarantine_candidate(finding.candidate)
                    if not res.success:
                        all_quarantined = False
            if all_quarantined:
                sys.exit(0)

        # Return exit code: 0 if clean, 1 if secrets detected
        sys.exit(report.summary.exit_code)

    except ConfigError as err:
        click.echo(f"Configuration Error: {err}", err=True)
        sys.exit(2)
    except Exception as err:
        click.echo(f"Fatal Execution Failure: {err}", err=True)
        sys.exit(2)


@main.command("install-hook")
@click.option(
    "--repo",
    "-r",
    type=click.Path(file_okay=False, dir_okay=True),
    default=".",
    help="Target repository directory (default: current directory).",
)
def install_hook_command(repo: str) -> None:
    """Install SecretGuard as an automated executable Git pre-commit hook."""
    repo_dir = Path(repo).resolve()
    git_dir = repo_dir / ".git"

    if not git_dir.is_dir():
        curr = repo_dir
        while curr.parent != curr:
            if (curr / ".git").is_dir():
                repo_dir = curr
                git_dir = repo_dir / ".git"
                break
            curr = curr.parent

    if not git_dir.is_dir():
        click.echo(f"Error: No Git repository found at {repo_dir}", err=True)
        sys.exit(2)

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    script_content = (
        "#!/usr/bin/env sh\n"
        "# Auto-generated by SecretGuard\n"
        "set -e\n"
        "if command -v secretguard >/dev/null 2>&1; then\n"
        "    exec secretguard scan --pre-commit\n"
        "elif [ -f SecretGuard-main/.venv/Scripts/secretguard.exe ]; then\n"
        "    exec SecretGuard-main/.venv/Scripts/secretguard.exe scan --pre-commit\n"
        "elif [ -f .venv/Scripts/secretguard.exe ]; then\n"
        "    exec .venv/Scripts/secretguard.exe scan --pre-commit\n"
        "elif [ -f SecretGuard-main/.venv/bin/secretguard ]; then\n"
        "    exec SecretGuard-main/.venv/bin/secretguard scan --pre-commit\n"
        "elif [ -f .venv/bin/secretguard ]; then\n"
        "    exec .venv/bin/secretguard scan --pre-commit\n"
        "elif command -v python >/dev/null 2>&1; then\n"
        "    exec python run.py scan --pre-commit\n"
        "else\n"
        "    exec python3 run.py scan --pre-commit\n"
        "fi\n"
    )

    try:
        hook_path.write_text(script_content, encoding="utf-8")

        # Set POSIX executable permissions (0755: rwxr-xr-x)
        if os.name != "nt":
            hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH | stat.S_IRUSR | stat.S_IWUSR)

        click.echo(f"✔ Successfully installed SecretGuard pre-commit hook to {hook_path}")
        sys.exit(0)
    except OSError as err:
        click.echo(f"Error installing pre-commit hook: {err}", err=True)
        sys.exit(2)


@main.command("init")
def init_command() -> None:
    """Interactive onboarding wizard to configure API keys and default routing profile."""
    click.echo("Welcome to SecretGuard Configuration Wizard!")
    click.echo("This wizard will configure your API provider keys in ~/.config/secretguard/config.yaml\n")

    groq_key = click.prompt("Groq API Key (leave empty to skip)", default="", show_default=False).strip()
    openrouter_key = click.prompt("OpenRouter API Key (leave empty to skip)", default="", show_default=False).strip()
    gemini_key = click.prompt("Google Gemini API Key (leave empty to skip)", default="", show_default=False).strip()
    together_key = click.prompt("Together AI API Key (leave empty to skip)", default="", show_default=False).strip()

    profile = click.prompt(
        "Default Routing Profile [auto/A/B/C]",
        type=click.Choice(["auto", "A", "B", "C"], case_sensitive=False),
        default="auto",
    ).strip().upper()

    provider_keys: dict[str, list[str]] = {}
    if groq_key:
        provider_keys["groq"] = [groq_key]
    if openrouter_key:
        provider_keys["openrouter"] = [openrouter_key]
    if gemini_key:
        provider_keys["google"] = [gemini_key]
    if together_key:
        provider_keys["together"] = [together_key]

    config_data = {
        "entropy_threshold": 4.2,
        "min_candidate_length": 8,
        "strict_permissions": True,
        "routing_profile": profile,
        "provider_keys": provider_keys,
    }

    config_dir = Path.home() / ".config" / "secretguard"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "config.yaml"

    try:
        with config_file.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(config_data, handle, sort_keys=False)

        # Enforce strict 0600 POSIX permissions (owner read/write only)
        if os.name != "nt":
            config_file.chmod(0o600)

        click.echo(f"\n✔ Configuration saved to {config_file} with secure 0600 permissions.")
        sys.exit(0)
    except OSError as err:
        click.echo(f"Error saving configuration: {err}", err=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
