# ONE-SHOT ANTIGRAVITY BOOTSTRAP: SET UP EVERYTHING AND GENERATE THE RESEARCH PAPER

You are operating inside the user's currently open local repository in Google Antigravity. Execute this entire task end-to-end. Do not merely explain steps or provide commands for the user to run manually. Perform the setup you can safely perform, verify each result, then execute the installed research-paper skill on this repository.

## Overall objective

Set up a usable repository-to-research-paper workflow from scratch, including:
1. Inspecting the OS, shell, repository, existing files, Git status, and available tools.
2. Installing or enabling a LaTeX editor extension in Antigravity if supported.
3. Installing or detecting a local LaTeX distribution/compiler.
4. Installing the exact project skill `repo-to-research-paper` with the instructions embedded below.
5. Verifying the skill is written to the correct location and can be invoked.
6. Running the complete workflow on the current repository.
7. Creating the paper source, bibliography, figures, scripts, evidence notes, audit report, and compiled PDF when the environment supports it.
8. Reporting what actually succeeded, what failed, and what remains incomplete.

Do not stop after setup. Continue through research and manuscript generation in this same run, unless a genuine blocker requires user interaction.

## Safety and autonomy rules

- First inspect the operating system, repository root, current Git status, and whether the expected files already exist. Preserve all existing user changes.
- Do not reset Git, rewrite history, delete project files, commit/push, submit the paper, expose secrets, or upload private source code to external services.
- Do not overwrite an existing `SKILL.md`, manuscript, bibliography, or paper artifact without reading it and preserving useful content. If the target skill exists, compare it with the embedded version and update only when safe; report differences.
- Do not install software using an untrusted script or bypass security prompts. Prefer official Antigravity/extension marketplace and official OS package managers.
- Do not claim an extension, compiler, package, or PDF works until you have verified it.
- If an installation needs administrator permission, a GUI confirmation, restart, license acceptance, or user approval, perform all safe preparatory steps and give the user the exact remaining action. Continue other work meanwhile.
- Use the machine's actual OS. Do not run macOS commands on Linux/Windows or vice versa.
- Avoid installing a huge LaTeX distribution if a suitable one is already available. Explain disk impact before starting a large install where possible.
- Use web research only through available browsing/search capabilities. Do not invent sources if browsing is unavailable.

## Phase A — Discover the environment

1. Identify OS/version, architecture, shell, repository root, available package managers, Git status, and installed tools (`latexmk`, `pdflatex`, `xelatex`, `lualatex`, `bibtex`, `biber`, Python/R/Node as relevant to the repo).
2. Inspect Antigravity's available extension/customization mechanism. Determine whether LaTeX Workshop is already installed and whether the configured marketplace supports it.
3. Inspect existing paper directories, skill files, `README` files, local instructions, dependency manifests, tests, datasets, reports, and previous research.
4. Do not assume the project domain or programming language.

## Phase B — Set up LaTeX editing and compilation

1. If LaTeX Workshop is installed, verify it. If not, attempt to install it through Antigravity's supported Extensions UI/marketplace, using the official extension by James Yu when available. Do not assume VS Code extension compatibility automatically means Antigravity compatibility.
2. If marketplace installation is unavailable, try the official Open VSX listing or document the limitation and use terminal-based compilation as a fallback. Do not download arbitrary VSIX files from untrusted sources.
3. Detect whether a local LaTeX compiler already exists. If one exists, use it and avoid duplicate installations.
4. If no compiler exists, choose a suitable official installation path for this OS. On macOS with Homebrew, a possible full distribution is `brew install --cask mactex-no-gui`; it is large, so check available disk space and explain the size before installing. On other operating systems, use the official TeX Live/MiKTeX distribution instructions and the available package manager where appropriate. Do not install without necessary user authorization.
5. Refresh the current shell PATH if appropriate, then verify actual compiler paths and versions.
6. Do not let an unavailable extension block the paper: terminal compilation is an acceptable fallback. If a compiler cannot be installed, still produce valid LaTeX sources and document exact build instructions and the blocker.

## Phase C — Install the exact project skill

Create this directory in the current repository:

`.agents/skills/repo-to-research-paper/`

Write the exact `SKILL.md` content supplied in the section `EMBEDDED SKILL CONTENT` below to:

`.agents/skills/repo-to-research-paper/SKILL.md`

Preserve the YAML front matter and all Markdown content exactly. If the skill already exists, read it first and avoid destructive replacement; reconcile differences safely. Verify the resulting file exists and its opening metadata is correct.

Also check Antigravity's documented global skill directory for this installed version. Only install a global copy if the path is confirmed by the editor's own documentation or built-in skill references. Do not guess global paths. A project-level `.agents/skills/` copy is the required baseline.

If Antigravity requires a reload for discovery, reload only if safe and possible. Otherwise continue by explicitly reading and following the skill file. Do not falsely claim that automatic discovery or slash-command registration has been verified if it has not.

## Phase D — Execute the skill now

After installing the skill, immediately read the complete file and execute its entire workflow against the current repository. Do not merely tell the user to invoke it later. Treat the embedded skill as the authoritative detailed workflow.

The paper must be created under `paper/`, preserving existing source and user work. Reuse relevant prior reports and results after checking them. The deliverable should include, as appropriate to the actual project:

- `paper/main.tex`
- `paper/references.bib`
- modular section files under `paper/sections/`
- figures/diagrams under `paper/figures/`
- reproducible scripts under `paper/scripts/`
- `paper/repo_inventory.md`
- `paper/method_and_architecture.md`
- `paper/evidence_ledger.md`
- `paper/evaluation_gaps.md`
- `paper/research_positioning.md`
- `paper/related_work.md`
- `paper/outline.md`
- `paper/README.md`
- `paper/audit_report.md`
- a compiled `paper/main.pdf` if the compiler is available

Adapt this list to the project's actual research domain and any existing artifacts. Do not create meaningless boilerplate files merely to match the list.

Use available browsing/search tools for the literature review. Verify citations against authoritative sources. Do not claim novelty based solely on code inspection or limited search results. Run appropriate existing tests and bounded evaluations where safe. Never invent results. If experimental evidence is insufficient, report that gap and provide a concrete experiment plan.

## Phase E — Compile, inspect, and audit

1. Compile the LaTeX project with the available toolchain. Use multiple passes and BibTeX/Biber when required by the template.
2. Fix compilation errors and meaningful warnings where practical. Check missing citations, undefined references, figure/table numbering, bibliography entries, and obvious layout problems.
3. Verify the PDF exists and inspect its metadata/size; if possible, render or open pages to check layout rather than relying only on a zero exit code.
4. Run or re-run relevant tests/benchmark scripts only where appropriate, bounded, and safe. Record actual commands and outcomes.
5. Perform a skeptical final audit against the implementation, logs, results, tests, and sources.
6. Do not say “publication-ready,” “fully verified,” or “zero issues” unless those claims are justified by a specific, documented verification standard.

## Phase F — Final response

When finished, report concisely:
- Which setup steps succeeded (extension, compiler, skill installation/discovery).
- The exact path to `paper/main.pdf` and the main editable source files.
- The literature-review scope and citation verification status.
- Tests and experiments actually run, with outcomes.
- Compilation status and any warnings.
- Critical unresolved research/evaluation gaps.
- Any setup action that still requires the user (for example, approving an installer or restarting Antigravity).

Do not stop at a progress update. Finish every safe and feasible step in this run.

---

# EMBEDDED SKILL CONTENT

The following is the complete skill content to write verbatim to `.agents/skills/repo-to-research-paper/SKILL.md`.

```markdown
---
name: repo-to-research-paper
description: Turn an existing software or research repository into an evidence-grounded academic paper. Use when asked to inspect a repository, recover its implemented methods and architecture, evaluate existing results, conduct a related-work search, and create a compilable LaTeX manuscript without fabricating claims, citations, or measurements.
---

# Repository-to-Research-Paper Workflow

## Objective

Create a technically accurate, evidence-grounded, reproducible LaTeX paper from the current repository. The repository is the primary source for what was implemented. It is not, by itself, evidence that a method is novel or experimentally superior.

Work autonomously through all stages that can be completed safely. Do not stop after making an outline or a partial draft. If a required fact, experiment, target venue, or external source is unavailable, record the gap explicitly and continue with the remaining work. Never conceal a gap by inventing a value or making an unsupported claim.

## Non-negotiable rules

1. **Inspect before writing.** Map the repository and read relevant code, tests, configuration, documentation, and evaluation scripts before drafting paper sections.
2. **Keep paper work isolated.** Put new manuscript artifacts in `paper/` unless the repository already has a clear paper-writing directory. Do not refactor, rename, or modify the product/source implementation merely to make the paper easier to write. Do not overwrite existing paper files without inspecting and preserving them.
3. **Evidence for every technical claim.** Maintain a claim ledger. For implementation claims, record file paths and relevant symbols or line ranges. For quantitative claims, record the actual results file, test output, command, dataset, and settings that support them.
4. **Never fabricate.** Do not invent experiments, baselines, datasets, sample sizes, performance numbers, confidence intervals, citations, author details, affiliations, ethical approvals, or venue acceptance. Do not present planned experiments as completed work.
5. **Separate evidence classes.** Label each substantial claim as one of: `IMPLEMENTED` (verified in code), `MEASURED` (supported by actual run data), `CITED` (supported by a verified source), `INFERRED` (reasonable interpretation, stated cautiously), or `MISSING` (requires confirmation/evidence). Do not turn an `INFERRED` or `MISSING` item into a proven result.
6. **Verify related work.** Search for primary papers and official sources using available web/research tools. Check that each citation exists and that its metadata and cited finding are accurate. If browsing is unavailable, mark the literature review as unverified rather than fabricating references.
7. **Do not assert novelty from absence of evidence.** Code inspection cannot establish that nobody has done the same thing. Compare against the closest verified prior work and express novelty narrowly. If the comparison is inconclusive, say so.
8. **Use real figures.** Generate charts from actual data or diagrams from verified architecture. Do not create decorative plots that imply measurements that do not exist. Label conceptual diagrams as conceptual.
9. **Reproducibility matters.** Record commands, environment, versions, parameters, data provenance, and random seeds where available. Distinguish tests that passed from experiments that establish scientific performance.
10. **Be careful with private information.** Do not copy secrets, credentials, private endpoints, personal data, or unrelated proprietary information into the paper. Check the repository for sensitive material before including snippets or configuration.
11. **Do not claim perfect or publication-ready status.** Report what was actually inspected, built, tested, and verified. A successful LaTeX build is not proof of scientific validity.
12. **No destructive operations.** Do not delete user files, reset Git state, rewrite history, push commits, or run expensive/destructive jobs without explicit authorization. Do not change the application implementation unless the user separately requests it.

## Required staged workflow

### Stage 1 — Repository reconnaissance

- Inspect the root directory, directory tree, README, project instructions, package/build manifests, architecture documentation, tests, sample data, experiment scripts, CI configuration, and Git status.
- Exclude generated dependencies and build artifacts from broad scans (for example, `node_modules`, `.git`, virtual environments, `target`, `dist`, caches, and large generated files). Do not assume a directory is irrelevant without checking its purpose.
- Read actual implementation paths rather than relying only on README descriptions.
- Identify existing manuscripts, citations, paper templates, experiment logs, datasets, figures, benchmarks, and previous results. Preserve and reuse them where valid.
- Create `paper/repo_inventory.md` with the project purpose, modules, data flow, important entry points, algorithms, dependencies, tests, evaluation tooling, available results, and unresolved questions. Include concrete file paths and symbol names.

### Stage 2 — Technical reconstruction

- Reconstruct how the system works from input to output. Trace important calls and data flow through implementation.
- Describe algorithms, design decisions, system boundaries, assumptions, failure handling, complexity, and limitations only where evidence supports them.
- Distinguish intended behavior from behavior verified in code and behavior validated by tests.
- Create `paper/method_and_architecture.md` containing the most defensible technical description and source evidence.

### Stage 3 — Evidence and evaluation audit

- Discover all existing test results, benchmark outputs, logs, metrics, datasets, and experiment configurations.
- Run only relevant, non-destructive, reasonably bounded existing tests or evaluation scripts where the environment allows it. Do not silently alter the implementation to make results better.
- Preserve command output or summarize it with enough information to reproduce the run. Record failures as well as successes.
- If there are no valid quantitative experiments, do not manufacture results. Instead, create `paper/evaluation_gaps.md` with a concrete proposed evaluation plan: research questions/hypotheses, datasets, baselines, metrics, ablations, repeated runs/statistical analysis where appropriate, and commands or implementation steps needed. Clearly label these as proposed, not completed.
- Create `paper/evidence_ledger.md`. For every proposed paper contribution, record: exact claim; evidence class; supporting file paths, symbols, logs or source citations; confidence; and missing validation.

### Stage 4 — Research question and contribution discipline

- Infer a small set of candidate research questions from the actual system, but do not decide that the system is a research contribution merely because it has many features.
- Determine the most defensible paper type: empirical study, systems paper, methods paper, dataset/tool paper, or software-artifact paper.
- Identify which contributions are demonstrated, which are implementation details, and which require comparative experiments or novelty verification.
- If the user has not specified a target venue, do not pretend to follow a specific conference's rules. Prepare a clean generic LaTeX article and note that formatting can be adapted later.
- Create `paper/research_positioning.md` with the candidate research question, contribution statements, boundaries, and a list of claims that should not be made yet.

### Stage 5 — Related-work search and citation verification

- Search scholarly and authoritative sources for the closest related methods, systems, benchmarks, and prior art. Prefer original papers, proceedings, journals, arXiv records, official project papers, and standards over secondary summaries.
- Search using multiple formulations of the core problem, implementation techniques, claimed differentiators, and adjacent fields.
- For each candidate citation, verify title, authors, year, venue or repository, and DOI/arXiv/official URL when available. Read enough of the source to ensure the paper supports the associated statement.
- Compare this project against the closest work using consistent dimensions: problem, method, inputs/outputs, assumptions, datasets, evaluation, strengths, and limitations.
- Do not claim exhaustive global novelty unless the search was genuinely broad and its limits are described. Never use an unverified BibTeX entry.
- Create `paper/related_work.md` and `paper/references.bib`. Store source URLs/DOIs in the working notes. Mark unresolved references clearly and do not cite them as verified.

### Stage 6 — Paper design and claim review

- Create `paper/outline.md` with section goals and the evidence each section will use.
- Create a claim-to-evidence table before drafting. Every important contribution, comparison, numerical result, and superiority claim must map to actual evidence or be removed/qualified.
- Design the narrative around the research question and evidence, not around a feature-by-feature product tour.
- Include appropriate limitations, threats to validity, reproducibility details, and ethical/privacy considerations where relevant.
- If the available evidence only supports a technical report or system description rather than an empirical research paper, state this in `paper/audit_report.md` and write the strongest honest version possible.

### Stage 7 — Write LaTeX source

Create or update this structure as appropriate:

- `paper/main.tex`
- `paper/references.bib`
- `paper/sections/abstract.tex`
- `paper/sections/introduction.tex`
- `paper/sections/related_work.tex`
- `paper/sections/method.tex`
- `paper/sections/implementation.tex` (if useful)
- `paper/sections/evaluation.tex`
- `paper/sections/discussion.tex`
- `paper/sections/limitations.tex`
- `paper/sections/conclusion.tex`
- `paper/figures/`
- `paper/README.md`

Adapt the section set to the paper type; do not force irrelevant sections. Use a conventional, clean LaTeX article unless an authentic venue template is available and appropriate. Split content into files for maintainability. Use `\cite{...}` keys backed by `references.bib`. Do not use fake placeholder citations. Use explicit `TODO` markers only for genuinely missing author metadata, venue requirements, or evidence; keep them listed in the audit report.

The abstract and introduction must not make claims stronger than the evaluation supports. A software implementation, a passing test suite, or a working demo is not alone evidence of scientific superiority.

### Stage 8 — Figures, tables, and reproducibility artifacts

- Prefer reproducible diagrams and charts generated from source data with scripts saved under `paper/scripts/` where practical.
- Ensure every plotted number can be traced to a result file or a documented calculation.
- Include captions that define abbreviations, metrics, conditions, and sample sizes where applicable.
- Include a reproducibility section or appendix with environment, versions, execution commands, data provenance/access, configuration, and limitations, as relevant to the field.
- Do not include screenshots of code as substitutes for a method description unless the figure genuinely needs a user-interface screenshot.

### Stage 9 — Build and technical validation

- Detect the available LaTeX toolchain. If `latexmk`, `pdflatex`, `xelatex`, `lualatex`, BibTeX, or Biber is available, use the appropriate tool to compile the paper.
- Fix LaTeX errors and warnings that affect correctness: missing citations, undefined references, broken figures, overfull lines, incorrect bibliography setup, and template errors.
- If the toolchain is unavailable, do not claim the PDF compiled. Provide the exact command needed and record the blocker.
- Check citation keys against the bibliography; check that every bibliography entry is cited when intended; inspect section references, equation/figure/table numbering, URLs, and page layout if a PDF can be generated.
- Do not commit build artifacts unless the repository convention requires them. Keep LaTeX source and reproducibility scripts.

### Stage 10 — Independent paper audit

Conduct a final pass as a skeptical reviewer. Check:

- Does every factual claim have code, data, or literature evidence?
- Are contributions distinct from routine engineering implementation?
- Is the closest related work represented fairly?
- Are comparisons methodologically fair and measured under comparable conditions?
- Are metrics, datasets, test conditions, baselines, and sample sizes fully specified?
- Are limitations and negative/failed findings reported honestly?
- Are references real and correctly matched to the statements they support?
- Do all figures/tables come from actual evidence or clearly labelled conceptual diagrams?
- Can another person reproduce the reported process from the instructions provided?
- Does the paper accidentally include secrets or confidential details?
- Does the manuscript overstate novelty, causal conclusions, generality, or performance?

Create `paper/audit_report.md` with checks performed, results, compile/test commands and outcomes, unresolved blockers, unsupported claims removed or softened, and the work still needed before submission.

## Completion criteria

Do not declare completion until:

1. Repository reconnaissance and the evidence ledger are complete to the extent the available repository permits.
2. Related work has been searched and each included citation has been checked, or literature verification limitations are clearly recorded.
3. The manuscript source exists and all major sections are drafted without fabricated evidence.
4. The LaTeX build has succeeded, or the exact environment/toolchain blocker is documented.
5. The independent audit report exists and distinguishes completed checks from unverified items.
6. The final response summarizes created files, evidence actually validated, build/test outcomes, and remaining scientific gaps. Never say “zero issues,” “perfect,” or “publication-ready” unless a specific, defensible standard has actually been met.

## Working style

- Use a plan and keep persistent notes so progress survives context limits.
- Work in small, reviewable steps; inspect generated diffs.
- Use concise academic writing, define domain-specific terms, and avoid promotional or product-marketing language.
- Prefer concrete descriptions of mechanisms and evidence over generic claims such as “robust,” “novel,” “efficient,” or “state-of-the-art.”
- Do not ask the user questions that the repository or authoritative sources can answer. If a genuinely essential decision is missing, continue with the safest generic option and record the decision needed.
```

---

# EXECUTION TRIGGER

Begin now. Inspect the environment, set up the LaTeX tooling and skill, verify each setup step, and execute the skill's complete workflow on the currently open repository. Do not ask the user to paste a second prompt. If a required action cannot be completed without user approval or an unavailable capability, document that exact blocker and continue all other feasible work.
