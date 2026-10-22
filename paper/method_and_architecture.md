# Technical Reconstruction: Method & Architecture of SecretGuard

**Document Stage:** Stage 2 — Technical Reconstruction  
**System Analyzed:** SecretGuard Local Pre-Commit & Pipeline Security Engine  
**Primary Source Evidence:** `SecretGuard-main/secretguard/`  

---

## 1. System Pipeline Overview

SecretGuard operates as an autonomous, multi-stage pipeline designed to intercept credential leakage at the earliest boundary of the software supply chain: the developer's local machine before a Git commit is created, or within CI/CD pull request workflows.

The complete lifecycle of a scanned commit traverses five stages:
1. **Diff Streaming Ingestion (`secretguard.ingest`)**
2. **Deterministic Candidate Extraction & Pre-Filtering (`secretguard.extract`)**
3. **Adaptive Ambiguity Scoring & Routing (`secretguard.router`)**
4. **Contextual Verification Gateway (`secretguard.gateway` & `secretguard.verifier`)**
5. **Interactive Remediation & Standards Reporting (`secretguard.remediation` & `secretguard.reporting`)**

```
+---------------------------------------------------------------------------------+
|                                 STAGED GIT DIFF                                 |
+---------------------------------------------------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
| 1. INGESTION: GitDiffParser (Streams added '+' lines; skips context & removals) |
+---------------------------------------------------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
| 2. DETERMINISTIC ENGINE: BaseRegexRule (15+ vendor rules) + Shannon Entropy     |
|    - Filters placeholders, UUIDs, hex sequences, template tokens                |
|    - Extracts bounded context window (strictly <= 200 characters)               |
+---------------------------------------------------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
| 3. AMBIGUITY SCORER: S_amb = w1*U_regex + w2*H_norm + w3*A_ctx                  |
+---------------------------------------------------------------------------------+
           |                                                      |
    (S_amb < 0.20)                                         (S_amb >= 0.20)
           |                                                      |
           v                                                      v
+----------------------+                       +----------------------------------+
| UNAMBIGUOUS TIER     |                       | AMBIGUOUS TIER (Adaptive Routing)|
| Local Resolution     |                       | - 0.2 <= S < 0.6 -> Profile A    |
| (0ms Network Latency)|                       | - S >= 0.6       -> Profile B    |
+----------------------+                       +----------------------------------+
           |                                                      |
           |                                                      v
           |                                   +----------------------------------+
           |                                   | PRIVACY-PRESERVED LLM VERIFIER   |
           |                                   | - KeyManager rotation & throttle |
           |                                   | - Structured JSON zero-shot test |
           +-------------------+---------------+----------------------------------+
                               |
                               v
+---------------------------------------------------------------------------------+
| 4. DECISION & REMEDIATION (SecretQuarantineManager)                             |
|    - Intercept commit with cyber-minimalist TUI card                            |
|    - 1-Click migration: sanitize source code, append to .env, update .gitignore |
|    - Generate OASIS SARIF v2.1.0 or JSON diagnostic report                      |
+---------------------------------------------------------------------------------+
```

---

## 2. Ingestion & Pre-Filtering Mechanisms

### 2.1 Git Diff Streaming
Implemented in `GitDiffParser` (`secretguard/ingest/git_diff.py`). Rather than scanning the entire filesystem or historical Git tree, the parser processes the unified diff stream produced by `git diff --cached` (or supplied via standard input / test harness).
- It extracts file path targets from `diff --git a/... b/...` and `+++ b/...`.
- It ignores deleted lines (`-`) and unchanged context lines (` `).
- Only additions (`+`) are yielded as `DiffLine` structures containing `file_path`, `line_number`, and `content`.
- Bounded memory footprint: lines are processed as a generator, preventing full-file memory buffering.

### 2.2 Ignore Matching
Implemented in `IgnoreMatcher` (`secretguard/ingest/ignore.py`). Evaluates candidate paths against `.gitignore` and optional `.secretguardignore` rules using fnmatch semantics. Files matching ignore patterns or standard binary/minified patterns (e.g., `*.min.js`, `*.lock`, `node_modules/`, `dist/`) are discarded immediately.

---

## 3. Deterministic Extraction Engine

Implemented in `DeterministicExtractionEngine` (`secretguard/extract/engine.py`).

### 3.1 Pre-Compiled Regex Signature Rules
The engine maintains over 15 pre-compiled regex signatures subclassing `BaseRegexRule` (`secretguard/extract/rules.py`):
- `SG-AWS-001`: AWS Access Key ID (`AKIA[0-9A-Z]{16}`)
- `SG-AWS-002`: AWS Secret Access Key (40 alphanumeric chars in variable assignment context)
- `SG-GH-001`: GitHub Personal Access Token Classic (`ghp_[a-zA-Z0-9]{36}`)
- `SG-GH-002`: GitHub Fine-Grained Token (`github_pat_[a-zA-Z0-9_]{82}`)
- `SG-OAI-001`: OpenAI Legacy / Standard API Key (`sk-[a-zA-Z0-9]{48}`)
- `SG-OAI-002`: OpenAI Project Key (`sk-proj-[a-zA-Z0-9-_]{48,}`)
- `SG-GCP-001`: Google API Key (`AIza[0-9A-Za-z\\-_]{35}`)
- `SG-SLACK-001`: Slack Bot/User Token (`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}`)
- `SG-JWT-001`: JSON Web Token header + payload (`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}`)
- `SG-KEY-001`: Cryptographic Private Key Headers (`-----BEGIN (?:RSA|OPENSSH|EC|PGP) PRIVATE KEY-----`)
- `SG-AZURE-001`: Azure Client Secret assignment heuristics
- `SG-STRIPE-001`: Stripe Live/Test Secret Keys (`(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24}`)
- `SG-TWILIO-001`: Twilio Auth Token (`[0-9a-fA-F]{32}`)
- `SG-FB-001`: Firebase Cloud Messaging Key
- `SG-DISCORD-001`: Discord Bot Token
- `SG-DB-001`: Database URI Connection Strings (`(?:postgres|mysql|mongodb|redis)://...`)

### 3.2 Candidate Pre-Filters
Implemented in `CandidateFilter` (`secretguard/extract/filters.py`). Candidates matched by heuristics or regex are checked against known non-secret patterns to suppress false alarms before scoring:
- Placeholder indicators (`YOUR_API_KEY`, `EXAMPLE`, `DUMMY`, `CHANGE_ME`, `FIXME`, `<TOKEN>`, `${ENV_VAR}`)
- Canonical UUID formats (`[0-9a-f]{8}-[0-9a-f]{4}-...`)
- Pure hex digest strings (git commit hashes, MD5/SHA256 checksums)
- Repeated uniform strings with entropy below cutoff

### 3.3 Shannon Entropy Calculation
Implemented in `ShannonEntropyCalculator` (`secretguard/extract/entropy.py`).
Given candidate string $X = (x_1, x_2, \dots, x_N)$ of length $N$:
$$H(X) = -\sum_{x \in \mathcal{A}} P(x) \log_2 P(x)$$
where $P(x) = \frac{\text{count}(x)}{N}$ and $\mathcal{A}$ is the distinct character set of $X$. Strings with length $\ge 8$ and $H(X) \ge 4.2$ are classified as high-entropy candidates.

### 3.4 Strict Privacy Bounding
Implemented in `extract_bounded_context` (`secretguard/extract/context.py`). To guarantee that proprietary code is not leaked to external verification services, surrounding context is strictly limited:
$$\text{context\_window} \le 200 \text{ characters}$$
The context window is symmetrically centered around the matched literal with leading/trailing whitespace trimmed.

---

## 4. Adaptive Ambiguity Scoring & Routing Policy

Implemented in `AmbiguityScorer` (`secretguard/router/scorer.py`) and `AdaptiveRoutingPolicy` (`secretguard/router/policy.py`).

### 4.1 Mathematical Formulation of Ambiguity Score
The aggregate ambiguity score $S_{amb}(c) \in [0.0, 1.0]$ for candidate $c$ is computed as:
$$S_{amb}(c) = \text{clamp}\Big( w_1 \cdot U_{regex}(c) + w_2 \cdot \hat{H}(c) + w_3 \cdot A_{ctx}(c),\; 0.0,\; 1.0 \Big)$$
where the validated default weights are:
- $w_1 = 0.4$ (Regex uncertainty weight)
- $w_2 = 0.3$ (Normalized entropy weight)
- $w_3 = 0.3$ (Contextual ambiguity weight)

#### Term 1: Regex Uncertainty ($U_{regex}$)
$$U_{regex}(c) = \begin{cases} 0.0, & \text{if } c.\text{rule\_id} \in \text{STRUCTURED\_RULE\_IDS} \\ 1.0, & \text{otherwise (heuristic or generic rule)} \end{cases}$$

#### Term 2: Normalized Entropy ($\hat{H}$)
Normalized over the range $[H_{min}, H_{max}] = [3.5, 6.0]$:
$$\hat{H}(c) = \text{clamp}\left( \frac{H(c) - 3.5}{6.0 - 3.5},\; 0.0,\; 1.0 \right)$$

#### Term 3: Contextual Ambiguity ($A_{ctx}$)
$$A_{ctx}(c) = \begin{cases}
1.0, & \text{if file path or context contains mock/test indicators (e.g., `test`, `mock`, `fixture`, `dummy`)} \\
0.2, & \text{if context matches explicit sensitive keywords (e.g., `password`, `secret`, `api_key`, `access_token`)} \\
0.8, & \text{otherwise (generic identifiers or raw string literals)}
\end{cases}$$

### 4.2 Routing Policy Tiers
Based on $S_{amb}(c)$, the candidate is routed through one of three tiers:
1. **Unambiguous Tier ($S_{amb} < 0.20$):**
   Candidate matches a strict vendor prefix in a production code file with sensitive keyword assignment.
   **Action:** Immediate local resolution (flagged as verified secret, zero network latency, 0ms overhead).
2. **Low-Complexity Ambiguous Tier ($0.20 \le S_{amb} < 0.60$):**
   Candidate has partial ambiguity (e.g., structured token in a test file, or high-entropy generic token in production code).
   **Action:** Routed to **Model Profile A** (fast, low-cost model: Groq `llama-3.1-8b-instant`, max 150 tokens, 2.0s timeout).
3. **High-Complexity Ambiguous Tier ($S_{amb} \ge 0.60$):**
   Candidate has high ambiguity (e.g., generic heuristic match embedded inside a test fixture or complex template).
   **Action:** Routed to **Model Profile B** (high-reasoning model: OpenRouter `openai/gpt-4o-mini` or Claude 3.5 Sonnet, max 200 tokens, 2.0s timeout).

---

## 5. Verification Gateway & Key Management

Implemented in `KeyManager` (`secretguard/gateway/key_manager.py`) and `ProviderDispatcher` (`secretguard/gateway/dispatcher.py`).
- **Round-Robin Rotation:** Balances traffic across multiple registered API keys.
- **Adaptive Backoff on HTTP 429:** When a rate limit is reached, the key is throttled with exponential backoff and the dispatcher shifts to the next available key.
- **Fail-Safe Quota Exhaustion:** On HTTP 403 or exhausted pools, the gateway marks the key exhausted and safely falls back to local deterministic resolution without breaking the developer's commit workflow.
- **Credential Masking in Error Traces:** Raw credentials in memory or error strings are scrubbed before logging.

---

## 6. Remediation & Automated Quarantine Engine

Implemented in `SecretQuarantineManager` (`secretguard/remediation/autofix.py`).
When a verified credential is confirmed for quarantine, SecretGuard executes a 3-step atomic remediation:
1. **Language-Aware Source Code Sanitization:**
   - Detects target file language based on extension (`.py`, `.js`, `.ts`, `.tsx`, `.jsx`).
   - For Python: replaces the raw string literal `"<SECRET>"` with `os.getenv("<VAR_NAME>")`.
   - For JavaScript/TypeScript: replaces `"<SECRET>"` with `process.env.<VAR_NAME>`.
   - Automatically derives `<VAR_NAME>` from the rule ID (e.g., `SG-AWS-001` $\to$ `AWS_ACCESS_KEY_ID`) or identifier context.
2. **Safe Key Migration:**
   - Appends `<VAR_NAME>=<LITERAL_SECRET>` to `.env` in the repository root.
3. **Git Leakage Prevention:**
   - Inspects `.gitignore`. If `.env` is absent, appends `.env` to `.gitignore` to prevent the environment file from ever being committed.
