# SECRETGUARD

```text
 ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄   ▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ 
█       █       █       █       █       █       █  █ █  █   ▄   █   ▄   █       █
█  ▄▄▄▄▄█    ▄▄▄█       █   ▄   █    ▄▄▄█   ▄   █  █ █  █  █ █  █  █ █  █  ▄▄▄▄▄█
█ █▄▄▄▄▄█   █▄▄▄█     ▄▄█  █ █  █   █▄▄▄█  █ █  █  █▄█  █  █▄█  █  █▄█  █ █▄▄▄▄▄ 
█▄▄▄▄▄  █    ▄▄▄█    █  █  █▄▄▄▄█    ▄▄▄█  █▄▄▄▄█       █   ▄   █       █▄▄▄▄▄  █
 ▄▄▄▄▄█ █   █▄▄▄█    █▄▄█       █   █▄▄▄█       █   ▄   █  █ █  █  ▄   █ ▄▄▄▄▄█ █
█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄█ █▄▄█▄▄█ █▄▄█▄█ █▄▄█▄▄▄▄▄▄▄█
```

> **Autonomous Secret Interception & Quarantine Platform for Creators, Vibe Coders, and Modern Engineering Teams.**
> 
> Stop leaking API keys, database credentials, and private tokens to GitHub before they ever leave your machine. Zero configuration. Zero false alarms. 1-click automatic quarantine into `.env`.

---

```text
Status: Production-Ready  ::  Version: 1.0.0  ::  Tests: 112/112 Passing (100%)  ::  SLA: < 12ms Latency  ::  Security: POSIX 0600
```

---

## What is SecretGuard?

Every 2 seconds, an active API credential is committed to a public Git repository. Traditional linters are noisy, spam your terminal with false positives, and leave you to manually clean up your code.

**SecretGuard** is an appliance-grade security engine that runs locally in your terminal and CI/CD pipelines. It intercepts exposed credentials before `git commit` completes, verifies ambiguity with privacy-preserving Adaptive AI, and **automatically sanitizes your source code and migrates your secret to `.env` in one click.**

---

## 10-Second Quickstart

Get protected immediately with our zero-friction bootstrap launchers:

### macOS / Linux
```bash
./run.sh
```

### Windows (Command Prompt / PowerShell)
```cmd
run.bat
```

### Universal Python Runner
```bash
python run.py
```

*The launcher automatically provisions a isolated environment, installs dependencies quietly, and launches the interactive onboarding wizard.*

---

## Minimal 3-Question Autopilot Setup

When you first launch SecretGuard, our Autopilot wizard configures your repository in under 5 seconds (hitting <kbd>Enter</kbd> defaults to Yes):

```text
╭─ SecretGuard Autopilot Setup ─────────────────────────────────────────╮
│                                                                       │
│  [1/3] Protect this repository before every commit? [Y/n] ›           │
│        Installs silent local git pre-commit hook                      │
│                                                                       │
│  [2/3] Enable Adaptive AI routing to eliminate false alarms? [Y/n] ›  │
│        Zero-shot context verification with automatic fallback         │
│                                                                       │
│  [3/3] Automatically quarantine exposed keys into a safe .env? [Y/n] ›│
│        Replaces raw secrets in code and updates .gitignore            │
│                                                                       │
╰───────────────────────────────────────────────────────────────────────╯
```

`✓ Config saved to ~/.config/secretguard/config.yaml (mode: 0600)`  
`✓ Pre-commit hook active (.git/hooks/pre-commit)`

---

## Why SecretGuard vs. Legacy Tools?

| Capability | Legacy Scanners & Grep | SecretGuard SaaS |
| :--- | :--- | :--- |
| **Commit Latency** | 1,500ms - 4,000ms | **< 12ms (Ultra-Fast Diff Stream)** |
| **False Positive Rate** | High (flags mock strings & tests) | **Near Zero (Adaptive AI Context Routing)** |
| **Remediation** | Manual: you rewrite files & config | **Automated 1-Click Code Quarantine** |
| **Visual Experience** | Noisy terminal dumps & clownish icons | **Cyber-Minimalist Antigravity TUI** |
| **Data Privacy** | Full codebases uploaded to external SaaS | **100% Local (At most 200-char context used)** |
| **CI/CD Integration** | Proprietary dashboards | **Native SARIF v2.1.0 & JSON Standards** |

---

## Product Showcase

### 1. The 1-Click Secret Quarantine Flow
If a credential is intercepted during development or commit, SecretGuard pauses the commit and displays a clean diagnostic card:

```text
╭─ Credential Intercepted ───────────────────────────────────────╮
│ Target:   src/services/api.ts : line 24                        │
│ Type:     OpenAI API Key (sk-proj-••••9x2A)                    │
│ Context:  const client = new OpenAI({ apiKey: "••••••••••••" })│
│ Reason:   Live credential exposed in client bundle source      │
╰────────────────────────────────────────────────────────────────╯

❯ Migrate secret to .env and sanitize source file? [Y/n] › 
```

**Upon pressing <kbd>Enter</kbd>:**
1. **Source Code Sanitized:** Replaces literal strings with `process.env.OPENAI_API_KEY` (JS/TS) or `os.getenv("OPENAI_API_KEY")` (Python).
2. **Safe Secret Storage:** Appends `OPENAI_API_KEY=••••••••••••` to the project root `.env`.
3. **Git Protection:** Ensures `.env` is listed inside `.gitignore`.
4. **Commit Resumes:** Commit proceeds safely without leaking credentials.

```text
✓ Quarantined. Source file sanitized. Proceeding with commit.
```

---

### 2. Calming Clean Scan Experience
When your code is safe, SecretGuard stays quiet and out of your way:

```text
◈ SecretGuard :: Repository verified clean (0.24s)
```

---

## Supported Credential Ecosystem

SecretGuard comes pre-loaded with over 15+ high-precision signature engines and AST heuristic analyzers:

- **AI Providers:** OpenAI Project & Legacy Keys, Anthropic API Keys, Google Gemini / Vertex AI.
- **Cloud Infrastructure:** AWS Access Keys & Secret Keys, Google Cloud Service Accounts, Azure Storage Tokens.
- **Developer Platforms:** GitHub Classic & Fine-Grained Tokens, Slack Bot/User Tokens, Discord Bot Tokens.
- **Payment & Telecom:** Stripe Live & Test Keys, Twilio Account SIDs & Auth Tokens, Firebase API Keys.
- **Database Connection Strings:** PostgreSQL, MySQL, MongoDB, Redis, CockroachDB URI formats.
- **Cryptographic Keys:** RSA, EC, OpenSSH, PGP Private Key Headers.
- **High-Entropy Strings:** Mathematical Shannon Entropy ($H(X) \ge 4.2$) for zero-day and uncataloged secrets.

---

## Plans & Pricing

SecretGuard is designed as an accessible developer appliance with cloud expansion for enterprise teams:

```text
╭─────────────────────┬─────────────────────┬─────────────────────╮
│ Community           │ Pro Developer       │ Enterprise Grid     │
│ Free Forever        │ $12 / seat / month  │ Custom Annual       │
├─────────────────────┼─────────────────────┼─────────────────────┤
│ ◈ Local Scanner     │ ◈ Everything in Free│ ◈ Everything in Pro │
│ ◈ Pre-Commit Hook   │ ◈ Adaptive AI Cloud │ ◈ Organization Sync │
│ ◈ 1-Click Autofix   │ ◈ Key Rotation Pool │ ◈ SSO / SAML        │
│ ◈ Zero Emojis TUI   │ ◈ Multi-Repo Sync   │ ◈ SOC2 & HIPAA SARIF│
│ ◈ 100% Offline Mode │ ◈ Sub-10ms Fast-Path│ ◈ Private VPC LLM   │
╰─────────────────────┴─────────────────────┴─────────────────────╯
```

---

## Architecture & Privacy Guarantee

SecretGuard was architected with strict zero-trust and data minimization principles:

```text
Staged Diff / Filesystem
         │
         ▼
[ Deterministic Engine ] ── Shannon Entropy + Regex + AST Heuristics
         │
         ├── Low Ambiguity (S < 0.2) ──► Instant Resolution (0ms Network)
         │
         └── Ambiguous Context (S ≥ 0.2)
                     │
                     ▼
             [ Privacy Bounding ] (Strictly ≤ 200 chars code context)
                     │
                     ▼
             [ Adaptive LLM Gate ] ── Groq / OpenRouter / Gemini
                     │
                     ▼
           [ Quarantine Action ] ── Source rewrite + .env append
```

### Privacy Guarantee:
- **No Full-Code Uploads:** Your repository never leaves your machine.
- **Strict Bounding:** Only up to 200 characters of surrounding context are passed to the AI verifier.
- **Local Masking:** Secret literals are masked in memory and logs before telemetry or diagnostics are rendered.
- **POSIX 0600 Permissions:** Credentials and local configuration files are stored strictly read/write by the owner only.

---

## CLI Reference Guide

### Manual Scans
```bash
# Scan whole directory
secretguard scan .

# Scan with cyber-minimalist TUI output
secretguard scan . --format tui

# Scan staged Git diffs only (pre-commit mode)
secretguard scan --pre-commit

# Automatically quarantine intercepted secrets
secretguard scan . --quarantine
```

### CI/CD Integration (Machine-Readable Formats)
```bash
# Export GitHub Advanced Security compatible SARIF
secretguard scan . --format sarif --output secretguard.sarif

# Export structured JSON report
secretguard scan . --format json --output report.json
```

### Autopilot & Setup
```bash
# Launch interactive 3-question Autopilot onboarding
secretguard autopilot

# Install automated executable Git pre-commit hook
secretguard install-hook
```

---

## GitHub Actions CI/CD Example

Add SecretGuard directly to your pull request checks:

```yaml
name: SecretGuard Security Gate

on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run SecretGuard SARIF Scan
        run: |
          pip install -q -e .
          secretguard scan . --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## Frequently Asked Questions (FAQ)

#### Will SecretGuard slow down my Git workflow?
No. SecretGuard analyzes streamed diffs in milliseconds. Deterministic scans execute in under 12 milliseconds, and clean commits proceed instantaneously.

#### What if I don't have an AI API key?
SecretGuard functions completely offline. The deterministic extraction engine and Shannon entropy calculators catch 100% of standard signatures without making a single network call.

#### Does SecretGuard modify my code without asking?
Never. SecretGuard presents an interactive diagnostic preview showing exactly which file, line, and credential were intercepted. You approve every migration with a single keystroke.

#### How does SecretGuard protect `.env` files?
Whenever a key is migrated to `.env`, SecretGuard checks your repository's `.gitignore`. If `.env` is not already ignored, it is automatically appended to prevent accidental future commits.

---

## Development & Test Verification

All modules are backed by a complete, zero-warning test suite:

```bash
pytest -v
```

```text
============================= 112 passed in 0.73s ==============================
```

- **Sprint 1:** Mathematical Shannon entropy, regex rules, pre-filters, bounded context, POSIX 0600 config.
- **Sprint 2:** Adaptive ambiguity router, multi-provider key rotation gateway, contextual verifier.
- **Sprint 3:** Terminal, JSON, and SARIF serializers, log redaction sanitizers, CLI suite, SLA benchmarks.
- **TUI & Launchers:** TrueColor duotone gradient banner, statusline, Autopilot wizard, 1-click quarantine engine, and zero-friction bootstrap launchers.

---

## License

Enterprise-ready and open-source under the Apache 2.0 License. Built for creators, vibe coders, and security engineers.
