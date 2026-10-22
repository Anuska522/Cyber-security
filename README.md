# SecretGuard: Autonomous Secret Interception & Research Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Tests: 112/112 Passing](https://img.shields.io/badge/tests-112%2F112%20passing-brightgreen.svg)]()
[![Paper: IEEE TSE Format](https://img.shields.io/badge/paper-IEEE%20Format-red.svg)](paper/main.pdf)

> **SecretGuard: Autonomous, Privacy-Preserving Secret Interception and Tiered Ambiguity Quarantine for Version Control Systems**

SecretGuard is an appliance-grade credential interception and quarantine engine tailored for Git pre-commit hooks and CI/CD pipelines. It resolves the fundamental tension between fast deterministic regex linters and slow cloud LLM verifiers through a three-tier architecture, streaming diff ingestion, mathematical Shannon entropy validation, and closed-form ambiguity scoring.

---

## 📂 Repository Structure

- **[`paper/`](paper/)**: Full academic research manuscript, LaTeX sources, figures, benchmarks, and reproducibility ledger.
  - [`paper/main.pdf`](paper/main.pdf): Compiled research paper.
  - [`paper/main.tex`](paper/main.tex): Master IEEETran document.
  - [`paper/sections/`](paper/sections/): Modular manuscript sections (Abstract, Intro, Related Work, Method, Implementation, Evaluation, Discussion, Limitations, Conclusion).
  - [`paper/scripts/`](paper/scripts/): Micro-benchmark reproducibility scripts and raw measurements.
  - [`paper/evidence_ledger.md`](paper/evidence_ledger.md): 18 empirical evidence claims grounded in code.
  - [`paper/audit_report.md`](paper/audit_report.md): Independent skeptical reproducibility and verification audit.
- **[`SecretGuard-main/`](SecretGuard-main/)**: Core SecretGuard codebase, CLI, TUI, AST refactoring engine, and 112 automated test cases.
- **`run.bat` / `run.sh` / `run.py`**: Zero-friction bootstrap launchers for Windows, macOS, and Linux.

---

## 🚀 Quickstart

### Launch the Interactive Interface

**Windows:**
```cmd
run.bat
```

**macOS / Linux:**
```bash
chmod +x run.sh && ./run.sh
```

**Cross-Platform Python:**
```bash
python run.py
```

---

## 📊 Key Research Findings

1. **Deterministic Latency (RQ1):**
   - Standard 100-line unified diffs are analyzed in **5.65 ms** (~17,700 lines/second).
   - Strict linear scaling ($R^2 > 0.999$) well below interactive pre-commit thresholds ($15\text{ ms}$).

2. **Mathematical Ambiguity Scoring (RQ2):**
   $$S_{amb} = w_1 U_{regex} + w_2 \hat{H} + w_3 A_{ctx}$$
   - Production secrets ($S_{amb} < 0.20$) are blocked locally with **0 ms network latency**.
   - Ambiguous candidates ($0.20 \le S_{amb} < 0.60$) route to lightweight edge models.
   - Complex test fixtures ($S_{amb} \ge 0.60$) route to deep-reasoning verification tiers.

3. **Autonomous 1-Click Remediation (RQ3):**
   - AST-based in-place code sanitization migrating credentials to `os.getenv(...)` or `process.env[...]`.
   - Automatic `.env` safe-appending with `.gitignore` enforcement.

---

## 📜 Academic Citation

```bibtex
@article{saha2026secretguard,
  title={SecretGuard: Autonomous, Privacy-Preserving Secret Interception and Tiered Ambiguity Quarantine for Version Control Systems},
  author={Saha, Anuska},
  journal={IEEE Transactions on Software Engineering},
  year={2026}
}
```

---

## 🛡️ License

MIT License. See individual module headers and LICENSE files for details.
