# Research Positioning & Contribution Boundaries: SecretGuard

**Document Stage:** Stage 4 — Research Question & Contribution Discipline  
**System:** SecretGuard  
**Paper Type Selection:** **Systems & Software Artifact Paper**  

---

## 1. Selected Paper Genre & Rationale

SecretGuard is most defensibly positioned as a **Systems and Software Artifact Paper** in the area of Developer Security / DevSecOps and Software Engineering.

**Why not a purely Empirical Study?**  
The repository does not currently contain a multi-month longitudinal human study or a million-commit dataset crawl. Positioning it as an empirical study would risk overclaiming.

**Why a Systems Paper?**  
The core intellectual contribution of SecretGuard is architectural and algorithmic:
1. Designing a tiered secret interception pipeline that addresses the fundamental tension between **developer latency** (must run in milliseconds during `git commit`) and **false alarm reduction** (which typically requires expensive semantic analysis).
2. Devising a lightweight, closed-form mathematical ambiguity metric ($S_{amb}$) that separates deterministic local decisions from ambiguous tokens, enabling intelligent routing without uploading entire codebases to cloud LLMs.
3. Coupling detection with automated, language-aware AST-level quarantine and Git ignore management.

---

## 2. Primary Research Questions (RQs)

The manuscript is structured around three focused research questions:

- **RQ1 (Architectural Feasibility):** Can a pre-commit secret interception engine achieve sub-15ms scanning latency on routine code commits while incorporating multi-pattern regex extraction, Shannon entropy calculation, and syntactic context pre-filtering?
- **RQ2 (Ambiguity Routing & Privacy Bounding):** How can a hybrid security engine mathematically discriminate between unambiguous credentials, test mocks, and ambiguous tokens to safely minimize external LLM invocations and restrict context exposure to $\le 200$ characters?
- **RQ3 (Autonomous Remediation Viability):** What is the design and operational viability of an automated 1-click secret quarantine mechanism that refactors source code into environment variable lookups while guaranteeing version control exclusion?

---

## 3. Defensible Research Contributions

The manuscript will claim the following contributions, each backed by implementation and reproducible verification:

1. **A Cyber-Minimalist, Low-Latency Pre-Commit Architecture:**  
   A streaming unified diff parser and deterministic extraction engine that operates on commit additions with a measured latency of $5.65$ ms on 100-line diffs ($\sim 17,000$ lines/second throughput).
2. **A Formal Mathematical Ambiguity Scoring & Tiered Routing Framework:**  
   The formulation of $S_{amb} = w_1 U_{regex} + w_2 \hat{H} + w_3 A_{ctx}$, which resolves unambiguous credentials with 0ms network overhead and adaptively escalates ambiguous candidates to specialized model profiles.
3. **A Privacy-Bounded Context Isolation Principle:**  
   A strict $\le 200$-character windowing mechanism ensuring zero full-code uploads, paired with multi-provider key rotation, rate-limit backoff, and local log token redaction.
4. **An End-to-End Autonomous Quarantine & Standards Reporting Pipeline:**  
   A 1-click remediation subsystem supporting Python and JavaScript/TypeScript code refactoring, synchronized `.env` migration, `.gitignore` enforcement, and OASIS SARIF v2.1.0 telemetry export.

---

## 4. Claims That MUST NOT Be Made (Boundaries and Exclusions)

To maintain scientific integrity and prevent reviewer rejection:

1. **DO NOT CLAIM "Global Novelty of Regex + Entropy":**  
   Regex and Shannon entropy have been used in TruffleHog (Ayrey, 2016) and Gitleaks (Rice, 2018). The contribution lies in the *mathematical ambiguity scoring, tiered routing, and integrated quarantine*, not the invention of entropy or regex.
2. **DO NOT CLAIM "Empirically Proven Near-Zero False Alarms Across All Repositories":**  
   While the pre-filters and ambiguity router effectively suppress mock indicators in unit tests, claiming "near-zero false alarms" globally without a benchmark on SecretBench is unverified marketing speech.
3. **DO NOT CLAIM "Empirical Superiority Over TruffleHog / Gitleaks":**  
   No head-to-head empirical trial against these tools was run in the current repository. The paper will contrast design capabilities and trade-offs rather than asserting benchmark superiority.
4. **DO NOT CLAIM Full Support for All Programming Languages:**  
   The automated code refactoring is implemented and tested for Python (`os.getenv`) and JavaScript/TypeScript (`process.env`). Other languages must be documented as future extensions.
