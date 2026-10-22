# Repository Inventory: SecretGuard

**Date of Reconnaissance:** 2026-10-22  
**Target Repository:** `SecretGuard` (commit state / current workspace snapshot)  
**Host Platform:** Windows 11 (64-bit, Build 10.0.26300), Python 3.13 / 3.11 virtualenv  

---

## 1. Project Purpose & High-Level Scope

SecretGuard is an autonomous, privacy-preserving credential interception and quarantine engine tailored for Git pre-commit hooks and local CI/CD pipelines. Its primary goal is to prevent the accidental leakage of API keys, tokens, and database credentials to version control systems before commits are finalized, eliminating the alert fatigue and manual remediation overhead common in traditional static scanners.

### Core Value Propositions Identified:
1. **Low-Latency Streaming Diff Processing:** Scans staged Git diff hunks directly rather than whole git revision trees, maintaining sub-millisecond to sub-15ms processing times on routine commits.
2. **Deterministic Extraction + Context Bounding:** Pre-filters known non-secrets and extracts candidates with regex and Shannon entropy, isolating exactly $\le 200$ characters of surrounding code context.
3. **Adaptive Ambiguity Scoring:** Computes an ambiguity score $S_{amb} \in [0, 1]$ based on regex uncertainty, normalized Shannon entropy, and syntactic context indicators (distinguishing production assignments from test/mock fixtures).
4. **Tiered Resolution Policy:** Unambiguous candidates ($S_{amb} < 0.20$) resolve locally with zero network calls; ambiguous candidates route to lightweight (Profile A) or high-reasoning (Profile B) LLMs.
5. **Automated 1-Click Code Remediation (Quarantine):** In-place AST-like rewriting of source files (e.g., replacing raw string literals with `os.getenv(...)` in Python or `process.env[...]` in JS/TS) combined with appending to `.env` and `.gitignore`.
6. **Machine-Readable Standard Exports:** Native SARIF v2.1.0 and JSON serializers for GitHub Advanced Security and enterprise SIEM ingestion.

---

## 2. Directory Structure and Module Mapping

```
SecretGuard-main/
├── pyproject.toml                         # Project metadata, dependencies, entry points
├── README.md                              # Public documentation, CLI guide, architectural claims
├── run.py / run.sh / run.bat              # Zero-friction bootstrapping and venv delegation scripts
├── secretguard/                           # Core Python package
│   ├── core/
│   │   ├── interfaces.py                  # Abstract interfaces (IExtractionRule, IRoutingPolicy, etc.)
│   │   └── models.py                      # Data models (SecretCandidate, DiffLine, Finding, ModelProfile)
│   ├── config/
│   │   └── settings.py                    # YAML configuration loader with POSIX 0600 permission checks
│   ├── extract/
│   │   ├── context.py                     # Context boundary extractor (strictly <= 200 characters)
│   │   ├── engine.py                      # Deterministic extraction engine coordinating rules & pre-filters
│   │   ├── entropy.py                     # Shannon entropy calculator (H(X) = -sum(P*log2(P)))
│   │   ├── filters.py                     # Candidate pre-filters (placeholders, uuid, hex, templates)
│   │   └── rules.py                       # Pre-compiled vendor regex rules (AWS, GitHub, OpenAI, etc.)
│   ├── gateway/
│   │   ├── dispatcher.py                  # Provider dispatcher (Groq, OpenRouter, Gemini)
│   │   └── key_manager.py                 # Multi-key rotation, HTTP 429 throttle backoff, 403 exhaustion
│   ├── ingest/
│   │   ├── fs_scanner.py                  # Line-by-line filesystem scanner without full buffer loading
│   │   ├── git_diff.py                    # Unified diff parser filtering for '+' hunk additions only
│   │   └── ignore.py                      # Matcher for .gitignore and .secretguardignore rules
│   ├── logging/
│   │   └── redaction.py                   # Redaction filter scrubbing detected tokens from logging records
│   ├── remediation/
│   │   └── autofix.py                     # 1-Click secret quarantine engine, AST regex replacement, .env append
│   ├── reporting/
│   │   ├── json_formatter.py              # Structured JSON scan report generator
│   │   ├── sarif.py                       # OASIS SARIF v2.1.0 compliant schema serializer
│   │   └── terminal.py                    # ANSI terminal summary formatter
│   ├── router/
│   │   ├── policy.py                      # Adaptive routing policy (Unambiguous, Profile A, Profile B)
│   │   └── scorer.py                      # Mathematical ambiguity scoring engine
│   ├── tui/
│   │   ├── banner.py                      # TrueColor duotone gradient header and statusline
│   │   ├── theme.py                       # Unicode box drawing glyphs and RGB color definitions
│   │   └── wizard.py                      # 3-question Autopilot onboarding wizard
│   ├── verifier/
│   │   └── context_verifier.py            # LLM prompt composer and JSON verification evaluator
│   ├── orchestrator.py                    # Central coordinator bridging ingest, extract, route, and report
│   └── cli.py                             # Command-line entry points (scan, autopilot, install-hook)
└── tests/                                 # Pytest automated test suite (19 test modules, 112 test cases)
```

---

## 3. Key Concrete Classes and Symbol References

| Module | Primary Symbol / Class | Verified File Path | Purpose |
| :--- | :--- | :--- | :--- |
| `core.models` | `SecretCandidate` | `secretguard/core/models.py` | Encapsulates literal value, file, line, entropy score, context window, filter flags |
| `extract.entropy` | `ShannonEntropyCalculator` | `secretguard/extract/entropy.py` | Implements $H(X) = -\sum P(x)\log_2 P(x)$, checks threshold $\ge 4.2$ |
| `extract.rules` | `BaseRegexRule` & sub-rules | `secretguard/extract/rules.py` | 15+ vendor regex patterns (`SG-AWS-001`, `SG-GH-001`, `SG-OAI-001`, etc.) |
| `extract.context` | `extract_bounded_context` | `secretguard/extract/context.py` | Bounds surrounding code to strictly $\le 200$ characters around candidate |
| `router.scorer` | `AmbiguityScorer` | `secretguard/router/scorer.py` | Evaluates $S_{amb} = w_1 U_{regex} + w_2 H_{norm} + w_3 A_{ctx}$ |
| `router.policy` | `AdaptiveRoutingPolicy` | `secretguard/router/policy.py` | Maps $S_{amb}$ to Local Deterministic ($<0.2$), Profile A ($[0.2, 0.6)$), Profile B ($\ge 0.6$) |
| `gateway.key_manager`| `KeyManager` | `secretguard/gateway/key_manager.py` | Manages rotation pools, rate-limit backoffs, and secret masking in error logs |
| `remediation.autofix` | `SecretQuarantineManager` | `secretguard/remediation/autofix.py`| Sanitizes code in-place, appends to `.env`, ensures `.gitignore` inclusion |
| `ingest.git_diff` | `GitDiffParser` | `secretguard/ingest/git_diff.py` | Parses unified diff streams, targeting added lines (`+`) only |
| `reporting.sarif` | `SarifFormatter` | `secretguard/reporting/sarif.py` | Serializes findings into OASIS SARIF v2.1.0 standard schema |

---

## 4. Dependencies and Runtime Requirements

- **Runtime:** Python 3.11+ (verified running under Python 3.13 / 3.11 virtualenv).
- **Core Libraries:** `pydantic` (model validation), `pyyaml` (configuration parsing), `pytest` (test execution).
- **Network Optionality:** The core deterministic extraction and local quarantine run completely offline without external network access. LLM verification requires an API key for Groq, OpenRouter, or Gemini if enabled.

---

## 5. Test Suite and Existing Evaluation Tooling

- **Test Suite Location:** `tests/`
- **Executed Command:** `pytest -v`
- **Result:** 109 Passed, 3 Skipped (POSIX 0600 file permission tests, which gracefully skip on Windows OS), 0 Failed.
- **Micro-benchmarks:** `tests/test_benchmark.py` includes a 100-line synthetic diff test asserting execution in $< 1,000$ ms.
- **Reproducible Benchmark Suite Created:** `paper/scripts/run_benchmarks.py` measures latency, throughput, and ambiguity routing across diff scales from 10 to 1,000 lines.
