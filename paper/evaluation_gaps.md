# Evaluation Gap Analysis & Proposed Empirical Benchmark Plan

**Document Stage:** Stage 3 — Evaluation Audit  
**System:** SecretGuard  
**Purpose:** Formally document unmeasured claims, experimental limitations, and propose a concrete, reproducible scientific evaluation protocol.

---

## 1. Summary of Identified Evaluation Gaps

While SecretGuard possesses a complete unit test suite (112 test cases, 100% passing on Linux/macOS and 109 passing / 3 POSIX-skipped on Windows) and proven micro-benchmarking latency ($5.65$ ms for 100-line diffs), an objective academic audit reveals several empirical evaluation gaps:

1. **Absence of Large-Scale Ground-Truth Benchmark Evaluation:**
   - *Current State:* Evaluated against synthetic diffs in `tests/test_benchmark.py` and unit fixtures in `tests/test_extraction.py`.
   - *Gap:* Has not been systematically run against the public `SecretBench` dataset (Basak et al., ESEM 2023) or real-world crawled repositories to quantify Precision, Recall, and F1-score against ground truth.

2. **Unvalidated Comparative Baselines:**
   - *Current State:* README presents a comparative table against "Legacy Scanners & Grep".
   - *Gap:* No controlled, head-to-head empirical measurements against leading open-source tools (Gitleaks, TruffleHog, Yelp `detect-secrets`) on identical commits under identical system constraints.

3. **Ablation of Routing Policy & LLM Verification:**
   - *Current State:* Ambiguity scoring formula is mathematically validated by unit tests.
   - *Gap:* No empirical ablation study measuring how much each component ($U_{regex}$, $\hat{H}$, $A_{ctx}$) contributes to false positive reduction, and whether Profile A vs. Profile B yields statistically significant accuracy differences on ambiguous tokens.

4. **Multi-Language AST Remediation Coverage:**
   - *Current State:* Automated quarantine engine supports Python (`os.getenv`) and JavaScript/TypeScript (`process.env`).
   - *Gap:* Other languages (Go `os.Getenv`, Rust `std::env::var`, Java `System.getenv`) are not yet natively handled by automated source replacement.

---

## 2. Proposed Concrete Evaluation Protocol (Future Experimental Plan)

To elevate SecretGuard from a high-quality software appliance to a validated empirical research contribution, the following experimental protocol is proposed:

### Research Questions (RQs)
- **RQ1 (Detection Accuracy):** How do SecretGuard's precision, recall, and F1-score compare to state-of-the-art scanners (Gitleaks v8, TruffleHog v3, detect-secrets) when evaluated against the standardized `SecretBench` benchmark?
- **RQ2 (False Positive Reduction via Adaptive Routing):** To what extent does the three-tier ambiguity routing gate eliminate false positives in test files, fixtures, and documentation compared to purely static regex+entropy scanners?
- **RQ3 (Latency & Supply Chain Friction):** What is the commit-time latency overhead across synthetic and real-world git diff distributions, and what fraction of commits resolve with zero network latency?
- **RQ4 (Remediation Reliability):** Does automated 1-click quarantine preserve code syntactical validity across diverse AST structures without introducing regression bugs?

### Benchmark Datasets
1. **SecretBench & FPSecretBench (Basak et al., 2023):**
   - 10,000+ labeled commits containing true positive secrets and false positive artifacts across diverse languages.
2. **Real-World Open-Source Crawl:**
   - A sample of 1,000 public GitHub repositories across Python, TypeScript, and Go containing staged commits with varied diff sizes (1 to 5,000 lines).

### Baselines for Head-to-Head Comparison
1. **Gitleaks (v8.18+):** Industry standard regex + entropy static scanner.
2. **TruffleHog (v3.60+):** Leading scanner with active verification.
3. **Yelp detect-secrets (v1.4+):** Standard differential baseline scanner.
4. **SecretGuard (Deterministic Only):** SecretGuard running strictly in offline mode ($S_{amb} < 0.20$ rules + filters).
5. **SecretGuard (Full Adaptive AI Pipeline):** Complete multi-tier routing with Profile A (Llama-3.1 8B) and Profile B (GPT-4o-mini).

### Metrics
- **Precision:** $P = \frac{TP}{TP + FP}$
- **Recall:** $R = \frac{TP}{TP + FN}$
- **F1-Score:** $F_1 = 2 \cdot \frac{P \cdot R}{P + R}$
- **Commit Latency:** $L_{50}, L_{95}, L_{99}$ (median and tail latency in milliseconds)
- **Network Call Ratio:** $\rho_{net} = \frac{\text{Commits requiring LLM routing}}{\text{Total commits scanned}}$
- **Remediation Success Rate:** Percentage of quarantined files that compile and pass pre-existing test suites without syntax errors.

---

## 3. Concrete Execution Commands (Proposed Pipeline)

```bash
# 1. Fetch benchmark dataset
git clone https://github.com/secretbench/secretbench-eval.git eval/benchmark

# 2. Run Gitleaks baseline
gitleaks detect --source eval/benchmark/samples --report-format json --report-path eval/gitleaks_results.json

# 3. Run TruffleHog baseline
trufflehog filesystem eval/benchmark/samples --json > eval/trufflehog_results.json

# 4. Run SecretGuard Deterministic Mode
secretguard scan eval/benchmark/samples --offline --format json --output eval/sg_deterministic.json

# 5. Run SecretGuard Full Adaptive AI Mode
secretguard scan eval/benchmark/samples --profile auto --format json --output eval/sg_adaptive.json

# 6. Execute comparative scoring script
python eval/scripts/compute_metrics.py \
    --ground-truth eval/benchmark/labels.json \
    --results eval/gitleaks_results.json eval/trufflehog_results.json eval/sg_deterministic.json eval/sg_adaptive.json
```

---

## 4. Manuscript Integration Guidelines

In the research paper:
- The authors must not claim that SecretGuard has achieved superior F1-scores on SecretBench until this experiment is actually conducted.
- The paper will clearly separate **Measured Performance** (diff ingestion throughput, micro-benchmark latency, and unit verification) from **Proposed Future Benchmark Evaluation** (large-scale SecretBench comparison).
- This separation upholds the highest standard of scientific integrity and transparency.
