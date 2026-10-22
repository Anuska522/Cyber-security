# Manuscript Outline & Evidence Mapping

**Title:** SecretGuard: Autonomous, Privacy-Preserving Secret Interception and Tiered Ambiguity Quarantine for Version Control Systems  
**Format:** IEEE/ACM Systems & Software Engineering Style (Generic LaTeX Article, Modular Structure)  
**Target Structure:**
- Abstract
- 1. Introduction
- 2. Related Work & Background
- 3. Architecture & Methodology
- 4. Implementation Details
- 5. Empirical Evaluation & Micro-benchmarks
- 6. Discussion & Threats to Validity
- 7. Limitations & Evaluation Gaps
- 8. Conclusion

---

## Section-by-Section Design & Evidence Mapping

### Abstract
- **Goal:** Summarize the problem of developer secret leakage, why existing static linters induce alert fatigue or unacceptable commit latency, and introduce SecretGuard's hybrid tiered architecture and 1-click remediation.
- **Evidence Used:** Meli et al. \cite{meli2019howbad}, Basak et al. \cite{basak2023comparative}, measured commit latency ($5.65$ ms on 100-line diffs), $S_{amb}$ equation.

### 1. Introduction
- **Goal:** Establish the motivation (shift-left security at git pre-commit boundary), developer friction and fatigue \cite{johnson2013why}, define RQ1, RQ2, and RQ3, and list the four primary contributions.
- **Evidence Used:** Evidence Ledger CLM-01 through CLM-16.

### 2. Related Work & Background
- **Goal:** Survey regex/entropy scanners, baseline differential scanners, active verifiers, and LLM-augmented scanners; present the 6-dimension comparative matrix.
- **Evidence Used:** `paper/related_work.md`, verified citations \cite{meli2019howbad, basak2023comparative, johnson2013why, shannon1948mathematical, shahriyar2025secret, rice2018gitleaks, ayrey2016trufflehog, yelp2019detectsecrets}.

### 3. Architecture & Methodology
- **Goal:** Detail the five pipeline stages: diff streaming ingestion, deterministic candidate extraction, mathematical ambiguity scoring ($S_{amb}$), adaptive tiered routing, and automated quarantine.
- **Evidence Used:** Code evidence from `secretguard/ingest/git_diff.py`, `secretguard/extract/engine.py`, `secretguard/router/scorer.py`, `secretguard/router/policy.py`, `secretguard/remediation/autofix.py`. Architectural TikZ diagram.

### 4. Implementation Details
- **Goal:** Concrete implementation facts: language runtime (Python 3.11+), zero-allocation streaming generators, strict $\le 200$-character bounded context window, round-robin key manager with 429 throttle backoff and 403 failover, POSIX 0600 file permission enforcement, and OASIS SARIF v2.1.0 telemetry export.
- **Evidence Used:** Symbols and paths from `paper/repo_inventory.md`.

### 5. Empirical Evaluation & Micro-benchmarks
- **Goal:** Present the reproducible micro-benchmark results answering RQ1, RQ2, and RQ3:
  - Table 1: Latency & Throughput across diff sizes (10 to 1,000 lines).
  - Table 2: Candidate ambiguity scoring and routing distribution across test vs prod fixtures.
  - Test suite verification: 112 test cases (109 passed, 3 skipped on Windows).
  - Latency scaling plot (TikZ/PGFPlots).
- **Evidence Used:** `paper/scripts/benchmark_results.json`, `tests/`.

### 6. Discussion & Threats to Validity
- **Goal:** Discuss trade-offs: latency vs semantic depth; privacy bounding vs full-context comprehension; AST refactoring risks; threats to internal, external, and construct validity.
- **Evidence Used:** `paper/method_and_architecture.md`, `paper/evidence_ledger.md`.

### 7. Limitations & Evaluation Gaps
- **Goal:** Transparently document what has NOT yet been validated: absence of full SecretBench ground-truth evaluation, multi-language AST coverage beyond Python and JS/TS, and the proposed benchmark protocol.
- **Evidence Used:** `paper/evaluation_gaps.md`.

### 8. Conclusion
- **Goal:** Recapitulate the system achievements and future directions.
