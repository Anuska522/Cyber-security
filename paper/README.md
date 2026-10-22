# SecretGuard Research Paper Artifacts

This directory contains the academic research manuscript, experimental evidence ledger, evaluation gaps analysis, reproducible benchmark scripts, figures, and bibliography for:

> **SecretGuard: Autonomous, Privacy-Preserving Secret Interception and Tiered Ambiguity Quarantine for Version Control Systems**

---

## 1. Directory Structure

```
paper/
├── main.tex                       # Master LaTeX document (IEEETran format)
├── references.bib                 # Verified academic bibliography
├── sections/                      # Modular LaTeX section files
│   ├── abstract.tex               # Abstract
│   ├── introduction.tex           # Section 1: Introduction & Research Questions
│   ├── related_work.tex           # Section 2: Related Work & Prior Art Taxonomy
│   ├── method.tex                 # Section 3: System Architecture & Methodology
│   ├── implementation.tex         # Section 4: Implementation Details & Invariants
│   ├── evaluation.tex             # Section 5: Empirical Evaluation & Benchmarks
│   ├── discussion.tex             # Section 6: Discussion & Threats to Validity
│   ├── limitations.tex            # Section 7: Limitations & Proposed Protocol
│   └── conclusion.tex             # Section 8: Conclusion
├── figures/                       # Vector diagrams and charts
│   ├── architecture.tikz          # TikZ system architecture diagram
│   └── latency_chart.tikz         # PGFPlots latency scaling graph
├── scripts/                       # Reproducibility scripts & raw benchmark data
│   ├── run_benchmarks.py          # Automated benchmark execution harness
│   └── benchmark_results.json     # Measured raw latency and routing data
├── repo_inventory.md              # Stage 1: Repository reconnaissance & module mapping
├── method_and_architecture.md     # Stage 2: Technical reconstruction of algorithms
├── evidence_ledger.md             # Stage 3: Grounded evidence ledger (CLM-01 to CLM-18)
├── evaluation_gaps.md             # Stage 3: Identified gaps and proposed evaluation protocol
├── research_positioning.md        # Stage 4: Research questions & contribution discipline
├── related_work.md                # Stage 5: Detailed literature review & comparison table
├── outline.md                     # Stage 6: Manuscript outline & claim-to-evidence map
├── audit_report.md                # Stage 10: Independent skeptical paper audit
└── README.md                      # This guide
```

---

## 2. Reproducibility & Build Instructions

### 2.1 Compiling the LaTeX Manuscript to PDF
To compile `main.tex` into `main.pdf` using the local MiKTeX/TeX Live toolchain:

```powershell
# Navigate to the paper directory
cd paper

# Run full multi-pass compilation with BibTeX
pdflatex -interaction=nonstopmode --enable-installer main.tex
bibtex main
pdflatex -interaction=nonstopmode --enable-installer main.tex
pdflatex -interaction=nonstopmode --enable-installer main.tex
```

### 2.2 Re-running the Performance Benchmarks
To regenerate the empirical latency and throughput measurements recorded in Table 1 and Figure 2:

```powershell
# From the repository root
.\SecretGuard-main\.venv\Scripts\python.exe paper/scripts/run_benchmarks.py
```
This writes fresh raw measurement metrics to `paper/scripts/benchmark_results.json`.

### 2.3 Executing the Complete Test Suite
To verify the 112 system test cases:

```powershell
cd SecretGuard-main
.\.venv\Scripts\pytest.exe -v
```

---

## 3. Academic Integrity & Evidence Grounding

All quantitative claims made in the manuscript are strictly backed by measured data:
- **Diff Scanning Latency:** Measured at $5.65$\,ms for 100-line unified diffs ($17,700$ lines/second throughput).
- **Ambiguity Scoring:** Empirically verified across production vs. test fixtures ($S_{amb} = 0.102$ for production AWS keys vs. $0.342$ for mock test keys).
- **Zero Fabrication:** The manuscript explicitly refrains from claiming benchmark superiority on external datasets (such as `SecretBench`) until full comparative trials are performed, as documented in `paper/evaluation_gaps.md`.
