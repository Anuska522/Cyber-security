# SecretGuard Evidence Ledger

**Audit Date:** 2026-10-22  
**Evaluation Standard:** Strict Multi-Class Grounded Evidence Ledger  
**Classification Categories:**
- `IMPLEMENTED`: Verified by direct inspection of repository source code, AST, and classes.
- `MEASURED`: Supported by reproducible execution logs, micro-benchmarks, or automated tests.
- `CITED`: Supported by verified peer-reviewed or authoritative literature with active DOI/URL.
- `INFERRED`: Plausible derivation or engineering rationale clearly qualified as non-proven.
- `MISSING`: Proposed capability, unmeasured metric, or external empirical claim requiring evaluation.

---

## 1. Summary of Evidence Table

| Claim ID | Claim Summary | Evidence Class | Primary Source / Artifact / Test | Confidence | Missing Validation / Next Step |
| :--- | :--- | :---: | :--- | :---: | :--- |
| **CLM-01** | Sub-15ms deterministic scanning latency for typical Git commits ($\le 100$ lines) | `MEASURED` | `paper/scripts/run_benchmarks.py`, `tests/test_benchmark.py`: 5.646ms for 100 lines | High | Cross-platform measurements on Linux/macOS and under heavy disk I/O load. |
| **CLM-02** | Throughput scales linearly up to 1,000 diff lines ($\sim 17,000$ lines/sec) | `MEASURED` | `paper/scripts/benchmark_results.json`: 1,000 lines processed in 58.199ms | High | Large-scale multi-megabyte monorepo diffs ($> 50,000$ lines). |
| **CLM-03** | 100% test pass rate on supported platform (109 passed, 3 skipped on Windows) | `MEASURED` | Pytest run: `109 passed, 3 skipped in 8.64s` | Complete | Run on POSIX Linux environment to verify 3 skipped `chmod 0600` tests. |
| **CLM-04** | Streaming diff ingestion parses additions only, ignoring deletions and unchanged context | `IMPLEMENTED` | `secretguard/ingest/git_diff.py`: `GitDiffParser.parse_diff_stream()` | High | Edge cases with binary diff hunks or unusual Git rename formats. |
| **CLM-05** | Pre-filters suppress non-secret false alarms (UUID, placeholders, hex digests) | `IMPLEMENTED` | `secretguard/extract/filters.py`: `CandidateFilter.should_filter()` | High | Quantify false-negative risk of overly aggressive placeholder regexes. |
| **CLM-06** | Mathematical Shannon entropy calculation with length $\ge 8$ and $H \ge 4.2$ cutoff | `IMPLEMENTED` | `secretguard/extract/entropy.py`: `ShannonEntropyCalculator` | High | Empirical distribution of entropy scores across production vs test secrets. |
| **CLM-07** | Privacy-preserving bounded context strictly limited to $\le 200$ characters | `IMPLEMENTED` | `secretguard/extract/context.py`: `extract_bounded_context()` | High | Verify token count variability across different programming languages. |
| **CLM-08** | Ambiguity score $S_{amb} = w_1 U_{regex} + w_2 \hat{H} + w_3 A_{ctx}$ discriminates test fixtures from prod | `MEASURED` | `paper/scripts/run_benchmarks.py`: AWS key in prod ($S=0.102$) vs test ($S=0.342$) | High | Optimization of weights $w_1, w_2, w_3$ via logistic regression on SecretBench. |
| **CLM-09** | Three-tier routing policy directs unambiguous candidates locally (0ms network) | `MEASURED` | `secretguard/router/policy.py`: candidate with $S=0.102$ yields `None` (Local) | High | Measure network cost savings in production developer cohorts. |
| **CLM-10** | Key manager provides round-robin rotation, HTTP 429 backoff, and 403 exhaustion failover | `IMPLEMENTED` | `secretguard/gateway/key_manager.py`: `KeyManager` | High | Live multi-tenant deployment under concurrent burst load. |
| **CLM-11** | 1-Click secret quarantine sanitizes Python (`os.getenv`) and JS/TS (`process.env`), appends to `.env` | `IMPLEMENTED` | `secretguard/remediation/autofix.py`: `SecretQuarantineManager` | High | AST-based refactoring for complex multi-line string templates and Go/Java/Rust. |
| **CLM-12** | Automatic appending of `.env` to `.gitignore` when migrating secrets | `IMPLEMENTED` | `secretguard/remediation/autofix.py:migrate_to_env()` | High | Monorepo support where `.gitignore` resides in parent or sibling directories. |
| **CLM-13** | OASIS SARIF v2.1.0 standard reporting for GitHub Advanced Security compatibility | `IMPLEMENTED` | `secretguard/reporting/sarif.py`: `SarifFormatter.format_report()` | High | Ingestion test directly in GitHub Security tab via CodeQL Action upload. |
| **CLM-14** | Secret leakage on GitHub occurs in thousands of repositories daily | `CITED` | Meli et al. (NDSS 2019): > 100,000 repositories, thousands of secrets leaked daily | High | Longitudinal update for 2024–2026 developer volumes. |
| **CLM-15** | Overly generic regex and entropy are the dominant causes of secret scanner false positives | `CITED` | Basak et al. (ESEM 2023): evaluation of 9 tools on SecretBench / FPSecretBench | High | N/A (Standard established empirical result). |
| **CLM-16** | Developer fatigue from static analysis false alarms leads to tool abandonment | `CITED` | Johnson et al. (ICSE 2013): interviews with 20 developers on SAST usability | High | N/A (Foundational software engineering study). |
| **CLM-17** | SecretGuard achieves "Near Zero False Alarms" across arbitrary open-source repositories | `MISSING` | Marketing claim in `README.md`; unverified across full SecretBench benchmark | Low | Comprehensive empirical evaluation against SecretBench / FPSecretBench needed. |
| **CLM-18** | Superiority over legacy scanners (TruffleHog, Gitleaks) in production accuracy | `MISSING` | Unmeasured comparative head-to-head precision/recall on identical ground truth | Low | Controlled comparative trial under identical hardware and dataset conditions. |

---

## 2. Claim-by-Claim Detailed Evidence Record

### CLM-01: Sub-15ms Commit Latency
- **Exact Claim:** Deterministic static scanning executes in under 15ms (README claims $< 12$ms) for standard staged diffs.
- **Evidence Class:** `MEASURED`
- **Measurement Details:** Run via `paper/scripts/run_benchmarks.py` using Python 3.13 on Windows 11. Over 20 trials, a 100-line synthetic unified diff with 6 active secrets completed in an average of $5.646 \pm 0.090$ ms. A 50-line diff completed in $3.028 \pm 0.227$ ms.
- **Status:** Verified and documented.

### CLM-08: Ambiguity Scoring Discrimination
- **Exact Claim:** The mathematical ambiguity score $S_{amb}$ effectively separates unambiguous credentials from test mocks and ambiguous identifiers.
- **Evidence Class:** `MEASURED`
- **Measurement Details:**
  - Production AWS Key: $U_{reg}=0, H_{norm}=0.140, A_{ctx}=0.2 \implies S_{amb}=0.102$ (Local Tier).
  - Mock AWS Key in Test File: $U_{reg}=0, H_{norm}=0.140, A_{ctx}=1.0 \implies S_{amb}=0.342$ (Profile A Tier).
  - Generic High-Entropy Token in Test: $U_{reg}=1.0, H_{norm}=0.180, A_{ctx}=1.0 \implies S_{amb}=0.754$ (Profile B Tier).
- **Status:** Verified in code and micro-benchmarks.

### CLM-17 & CLM-18: Comparative Precision and "Zero False Alarm" Claims
- **Exact Claim:** "Near Zero False Alarms" and superiority over Gitleaks/TruffleHog.
- **Evidence Class:** `MISSING`
- **Audit Assessment:** The current repository contains unit tests, launcher tests, and synthetic diff micro-benchmarks. It does not contain an evaluation on an external ground-truth corpus (e.g., SecretBench). Therefore, claims of "zero false alarms" or absolute empirical superiority cannot be made in the scientific manuscript without qualifying them as intended design goals or documenting the evaluation gap.
