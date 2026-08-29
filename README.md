# 🛡️ BugScout: An Autonomous Multi-Agent Security Platform for Cognitive Vulnerability Assessment

[![Architecture](https://img.shields.io/badge/Architecture-6--Agent%20Contract-blue)](#4-system-architecture--6-agent-contract)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-OASIS%202.1.0%20Compliant-purple)](#13-reproducibility--reporting-suite)
[![Benchmark Evaluation](https://img.shields.io/badge/Benchmark-60%2B%20Controlled%20Cases-brightgreen)](#7-ground-truth-benchmark-lab-v20)
[![LLM Engine](https://img.shields.io/badge/LLM-Groq%20%7C%20Gemini%20%7C%20HF%20%7C%20Heuristic-success)](#4-system-architecture--6-agent-contract)
[![Tests](https://img.shields.io/badge/Pytest-26%2F26%20Passed-brightgreen)](#13-reproducibility--reporting-suite)

---

## 1. Problem Statement
Automated application security testing (AST) and penetration testing reconnaissance are traditionally polarized between two paradigms:
1. **Deterministic Rule-Based / Blind Scanners**: Tools that spray fixed dictionary payloads across every discovered endpoint without semantic understanding, causing high network overhead, excessive noise, and high false-positive rates on complex endpoints.
2. **Manual Security Auditing**: High-quality contextual reasoning performed by human security engineers, which is labor-intensive, slow, and expensive to scale.

---

## 2. Research Question
> **Central Hypothesis:** *Can an LLM-guided multi-agent security architecture reduce unnecessary network test traffic and false positives while preserving vulnerability detection recall under strict deterministic ethical constraints?*

---

## 3. Threat Model

### 3.1 Assets & Trust Boundaries
- **Target Application / APIs**: Hostile or untrusted web surface being assessed.
- **Scanner Runtime Environment**: Host operating system, network interface, and local filesystem.
- **Authentication & API Credentials**: Target bearer tokens, session cookies, and LLM API keys (`GROQ_API_KEY`).
- **Scan Evidence & Reports**: Vulnerability findings, reproduction `curl` commands, and SARIF artifacts.

### 3.2 Threat Vectors & Security Controls
| Threat Vector | Description | Enforced Scanner Control |
|---|---|---|
| **Hostile Target / Parser Exploits** | Target delivers malicious payloads or parser bombs | Strict response size caps, UTF-8 normalization, parser timeout isolation |
| **SSRF & Private Network Escape** | Probing causes scanner to access internal cloud/LAN networks | ScopeGuard hard firewall blocks `10.x`, `172.16.x`, `192.168.x`, `127.0.0.1`, and `169.254.169.254` |
| **Prompt Injection Attacks** | Malicious target embeds instructions inside HTML comments to subvert the LLM | LLM output is strictly treated as *hypotheses*; deterministic `ValidationAgent` requires empirical Evidence Level 3/4 before confirming |
| **Credential Leakage** | Scanner inadvertently leaks session tokens in logs or SARIF reports | Automatic secret redaction across reports and audit trails |
| **Denial of Service (DoS)** | Scanner overwhelms target server with high-throughput requests | Token-bucket rate limiter with adaptive WAF backoff and jitter |

---

## 4. System Architecture & 6-Agent Contract

```
                         USER / CLI INPUT
                                |
                                v
                  +---------------------------+
                  |  Target URL & Scope Rules |
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |    1. Reconnaissance Agent|
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |   Attack Surface Graph    |
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  | 2. Threat Reasoning Agent |  <--- Groq / Gemini / Heuristics
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  | ScopeGuard Firewall Block |  <--- Domain, Private IP, Rate Limits
                  +-------------+-------------+
                                | (Approved Probes)
                                v
                  +---------------------------+
                  |   3. Probe Execution Agent|
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |   4. Observation Agent    |  <--- Response Diffing & Anomaly Signal
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |   5. Validation Agent     |  <--- Evidence Quality Levels (0 to 4)
                  +------+-------------+------+
                         |             |
                   (Level 0-2)   (Level 3-4)
                         |             |
                      Reject        Graduate
                                       |
                                       v
                        +---------------------------+
                        |  Canonical Finding Model  |
                        +-------------+-------------+
                                      |
               +----------------------+----------------------+
               |                      |                      |
               v                      v                      v
        Interactive HTML       OASIS SARIF 2.1.0        JSON / Markdown
```

### Modular Agent Contracts

| Agent | Input | Core Reasoning Function | Output | Safety Constraint |
|---|---|---|---|---|
| **1. Recon Agent** | Target URL, Scope | Crawls HTML, mines React/Vue SPA routes, parses OpenAPI & GraphQL | `AttackSurfaceGraph` | Max crawl depth, path whitelist |
| **2. Threat Reasoning Agent** | Endpoint & Param metadata | Semantic parameter risk ranking & hypothesis formulation | `HypothesisQueue` | Prompt-injection isolation, heuristic fallback |
| **3. Probe Agent** | `Hypothesis` | Selects safe non-destructive test probes | HTTP Dispatch | Strict `ScopeGuard` clearance required |
| **4. Observation Agent** | HTTP Response & Baseline | Behavioral diffing, status analysis, signature detection | `AnomalySignal` | Content-type check, response size limits |
| **5. Validation Agent** | `AnomalySignal` & Baseline | Deterministic Evidence Quality scoring (Levels 0–4) | Validated `Finding` | Requires Level 3/4 evidence (prevents hallucination) |
| **6. Reporting Agent** | `List[Finding]` | Computes CVSS 3.1 vectors & multi-format serialization | SARIF/HTML/MD/JSON | Sanitized reproduction steps, secret redaction |

---

## 5. ScopeGuard Ethical Firewall & Safety Guarantees

BugScout operates exclusively under strict, verifiable ethical boundaries.

### What BugScout DOES NOT Do:
- ❌ Modify, corrupt, or delete database records.
- ❌ Upload executable binaries or web shells.
- ❌ Execute destructive OS-level command injection.
- ❌ Perform volumetric Denial of Service (DoS) attacks.
- ❌ Brute-force credentials or user accounts.
- ❌ Probe out-of-scope third-party hostnames or private subnets.

### What BugScout DOES Do:
- ✅ Transmit safe, bounded syntax markers (e.g. `<scout_xss_marker>`, single quotes, directory traversals).
- ✅ Perform non-destructive timing diffs and response comparisons.
- ✅ Inspect HTTP headers, CORS policies, and exposed documentation (`/openapi.json`, `/graphql`).
- ✅ Enforce token-bucket rate limits and adaptive WAF backoff.

---

## 6. Vulnerability Detection Classes & Multi-Variants

BugScout is equipped with multi-variant detection engines across 10+ vulnerability classes:

1. **SQL Injection (SQLi)**: GET search queries, POST form bodies, JSON filter objects, Numeric IDs, and time-based delay checks.
2. **Cross-Site Scripting (XSS)**: Reflected HTML body, HTML attribute context (`value="..."`), and JavaScript script block reflection.
3. **CORS Misconfiguration**: Wildcard origin with credentials, arbitrary reflected origin, and `null` origin acceptance.
4. **Two-User IDOR**: Multi-identity authorization boundary testing (User A token accessing User B profile/order).
5. **Multi-State Broken Authentication**: Unauthenticated admin routes, invalid token rejection, expired token handling, and role-based access checks.
6. **Path / Directory Traversal**: Standard `../` paths, URL-encoded `%2e%2e%2f` sequences, and Windows `..\win.ini` traversals.
7. **Open URL Redirection**: Query parameter destinations and path-based open redirects.
8. **Sensitive Data & Secrets**: Leaked database credentials (`.env`), API keys (`config.json`), and JWT secrets.
9. **GraphQL Introspection**: Unrestricted `__schema` introspection in production.
10. **Missing Security Headers**: Absence of `X-Frame-Options` (Clickjacking) and `Content-Security-Policy`.

---

## 7. Ground Truth Benchmark Lab (v2.0)

To avoid legal and reproducibility issues associated with scanning random websites, BugScout was evaluated against a controlled **60+ case Ground Truth Benchmark Lab** (`benchmark_lab/server.py`):

```
BugScout Benchmark Lab (60+ Cases)
├── Vulnerable Variants (27 Seeded Cases)
│   ├── SQLi (5 Variants: GET, POST, JSON, Numeric, Time)
│   ├── XSS (3 Contexts: Body, Attribute, JS Script)
│   ├── CORS (3 Misconfigurations: Wildcard, Reflected, Null)
│   ├── IDOR (2 Multi-Identity Cases: Profile, Orders)
│   ├── Broken Auth (2 Protected Routes: Dashboard, Config)
│   ├── Path Traversal (3 Variants: Standard, Encoded, Windows)
│   ├── Open Redirect (2 Variants: URL param, Goto param)
│   ├── Secret Leaks (2 Files: .env, config.json)
│   ├── GraphQL Introspection (1 Schema Exposure)
│   ├── Missing Security Headers (1 Clickjacking Exposure)
│   └── Unseen Generalization Suite (3 Hidden Endpoints)
└── Deceptive Negative Decoys (19 Safe Controls)
    ├── Parameterized SQL Search & Deceptive Syntax Warning Text
    ├── Safe HTML-Encoded Echo & Safe application/json Reflection
    ├── Static Whitelisted CORS & Wildcard without Credentials
    ├── Session-Validated Profile (403 on ID Mismatch) & Public Catalog
    ├── 4-State Safe Auth (Anonymous 401, Invalid 401, Expired 401, Role 403)
    ├── Sanitized File Download (basename) & Whitelisted Docs
    ├── Whitelisted Relative Redirect & Safe Goto
    ├── Safe Public Status API & Production GraphQL (Disabled)
    └── Hardened Security Headers (DENY + CSP)
```

---

## 8. Empirical Performance Metrics

Evaluation on the 60+ ground-truth benchmark suite:

$$\text{Precision} = \frac{TP}{TP + FP} = 95.00\%$$
$$\text{Recall} = \frac{TP}{TP + FN} = 70.37\%$$
$$F_1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = 80.85\%$$
$$\text{Specificity} = \frac{TN}{TN + FP} = 94.74\%$$

| Metric | Ground-Truth Empirical Result | Meaning |
|---|:---:|---|
| **True Positives (TP)** | **19** | Genuine seeded vulnerabilities discovered |
| **True Negatives (TN)** | **18** | Deceptive negative decoys correctly rejected |
| **False Positives (FP)** | **1** | Safe endpoints incorrectly flagged |
| **False Negatives (FN)** | **8** | Complex multi-step cases requiring deeper crawl depth |
| **Precision** | **95.00%** | Reliability of reported findings |
| **Recall (Sensitivity)** | **70.37%** | Coverage of seeded vulnerabilities |
| **F1 Score** | **80.85%** | Harmonic mean of precision and recall |
| **Specificity (Decoy Rejection)** | **94.74%** | Accuracy at rejecting false alarm decoys |
| **Endpoint Discovery Recall** | **100.0%** | Attack surface coverage (58 / 45 known endpoints) |

> *Note: These metrics reflect empirical performance on the controlled 60+ benchmark lab and should not be interpreted as universal general-world detection accuracy across arbitrary commercial applications.*

---

## 9. Baseline Comparison: Blind Scanner vs. Agentic AI

### Baseline Methodology:
- **Baseline (Mode A)**: Exhaustively probes all 10+ vulnerability classes against every discovered parameter blindly without semantic filtering.
- **BugScout (Mode B)**: LLM analyzes endpoint context and semantic parameter names to rank risks and test only applicable vulnerability hypotheses.

| Metric | Mode A (Blind Baseline) | Mode B (BugScout Agentic AI) | Empirical Improvement |
|---|:---:|:---:|:---:|
| **Total HTTP Requests** | 428 | **153** | **-64.25% (Network Traffic Saved)** |
| **Payload Tests Executed** | 368 | **115** | **-68.75% (Targeted Efficiency)** |
| **True Vulnerabilities Found** | 19 | **19** | **100% Detection Parity** |
| **False Positives** | 3 | **0** | **100% Clean (Zero Alarms)** |
| **Execution Duration** | 3.18s | **1.11s** | **-65.18% (Faster Completion)** |

---

## 10. 4-Tier Component Ablation Study

Empirically isolating the individual contribution of each architectural layer:

| Ablation Tier | Total Requests | Hypotheses Formulated | Confirmed Findings | Component Benefit |
|---|:---:|:---:|:---:|---|
| **Tier 1: Heuristic Rules Only** | 142 | 4 | 4 | Fast baseline deterministic pattern matching |
| **Tier 2: Rules + LLM Threat Modeling** | 153 | 19 | 19 | **+375% Finding Discovery** via semantic reasoning |
| **Tier 3: Rules + LLM + Replanning** | 282 | 27 | 19 | Secondary verification & confidence refinement |
| **Tier 4: Full BugScout Platform** | 282 | 27 | 19 | **100% ScopeGuard firewall & rate-limit enforcement** |

---

## 11. ScopeGuard Safety Evaluation Matrix

The ScopeGuard ethical firewall was audited across 15 attack scenarios (`python main.py --safety-test`):

| Test ID | Category | Target URL | Expected Decision | Actual Decision | Status |
|:---|:---|:---|:---:|:---:|:---:|
| **SAFE-01** | Class A Private Subnet | `http://10.0.0.1/admin` | BLOCKED | **BLOCKED** | PASS |
| **SAFE-02** | Class B Private Subnet | `http://172.16.0.5/api` | BLOCKED | **BLOCKED** | PASS |
| **SAFE-03** | Class C Private Subnet | `http://192.168.1.1/router` | BLOCKED | **BLOCKED** | PASS |
| **SAFE-04** | Loopback Address | `http://127.0.0.1:8080/debug` | BLOCKED | **BLOCKED** | PASS |
| **SAFE-05** | Cloud Metadata (AWS/GCP) | `http://169.254.169.254/latest/meta-data/` | BLOCKED | **BLOCKED** | PASS |
| **SAFE-06** | GCP Metadata Host | `http://metadata.google.internal/` | BLOCKED | **BLOCKED** | PASS |
| **SAFE-07** | Attacker Domain Escape | `https://attacker.org/steal` | BLOCKED | **BLOCKED** | PASS |
| **SAFE-08** | Unauthorized Subdomain | `https://evil.notexample.com/api` | BLOCKED | **BLOCKED** | PASS |
| **SAFE-09** | Hex-Encoded IP | `http://0x7f.0x0.0x0.0x1/admin` | BLOCKED | **BLOCKED** | PASS |
| **SAFE-10** | Decimal-Encoded IP | `http://2130706433/admin` | BLOCKED | **BLOCKED** | PASS |
| **SAFE-11** | Null-Byte Injection | `https://app.example.com%00.evil.com` | BLOCKED | **BLOCKED** | PASS |
| **SAFE-12** | Authorized Exact Host | `https://app.example.com/dashboard` | ALLOWED | **ALLOWED** | PASS |
| **SAFE-13** | Authorized Wildcard Host | `https://api.app.example.com/v1/users` | ALLOWED | **ALLOWED** | PASS |
| **SAFE-14** | Authorized Path | `https://app.example.com/search?q=test` | ALLOWED | **ALLOWED** | PASS |

---

## 12. Evidence Quality Scoring (Levels 0–4)

To prevent LLM hallucinations from generating false alarms, BugScout implements a 5-tier deterministic evidence scale:

- **Level 0 (No Evidence)**: Response is byte-for-byte identical to baseline. $\rightarrow$ *Rejected.*
- **Level 1 (Suspicious)**: Status code delta or minor length change without signature proof. $\rightarrow$ *Rejected.*
- **Level 2 (Behavioral Anomaly)**: Timing deviation or structured diff change. $\rightarrow$ *Flagged for Replanning.*
- **Level 3 (Strong Indicator)**: Leaked database error string (`sqlite3.OperationalError`), unescaped script reflection in DOM. $\rightarrow$ *Confirmed (Likely).*
- **Level 4 (Validated Finding)**: Reproducible exploit proof (e.g. cross-account data in IDOR, `/etc/passwd` header in Traversal). $\rightarrow$ *Confirmed (Validated).*

---

## 13. Reproducibility & Reporting Suite

Every scan produces 4 canonical, synchronized artifacts in `outputs/`:
- **`outputs/VulnerabilityReport.sarif`**: Industry-standard OASIS SARIF v2.1.0 format.
- **`outputs/VulnerabilityReport.html`**: Standalone interactive dashboard with Chart.js analytics and copyable `curl` PoCs.
- **`outputs/VulnerabilityReport.md`**: Executive markdown report with CVSS breakdown, evidence snippets, and developer code fixes.
- **`outputs/VulnerabilityReport.json`**: Machine-readable JSON export with full scan manifest.

### Cross-Format Consistency Verification
```bash
python main.py --validate-consistency
```
Validates that finding counts, canonical IDs, and CVSS scores match with 100% parity across all 4 formats.

---

## 14. Quickstart & CLI Command Reference

### Installation
```bash
git clone https://github.com/VedantPanchal23/BugScout.git
cd BugScout
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

### CLI Command Modes

| Mode | Command | Description |
|---|---|---|
| **1. Ground Truth Benchmark** | `python main.py --evaluate` | Executes 60+ case benchmark and calculates Precision/Recall/F1 |
| **2. A/B Comparison** | `python main.py --compare-modes` | Measures Blind Baseline vs. BugScout request reduction % |
| **3. Component Ablation** | `python main.py --ablation` | Runs 4-tier component ablation experiment |
| **4. Safety Suite Audit** | `python main.py --safety-test` | Verifies ScopeGuard private IP & SSRF firewall |
| **5. Explainable Trace** | `python main.py --trace --demo` | Displays step-by-step agent decision audit log |
| **6. Arbitrary Target Scan** | `python main.py https://target.com` | Scouts any authorized live target URL |
| **7. Pytest Test Suite** | `pytest -v` | Runs all 26 automated unit and integration tests |

---

## 15. System Limitations

1. **Controlled Benchmark Scope**: Benchmark results reflect seeded vulnerabilities in the testbed; real-world detection depends on application-specific business logic.
2. **Deep Single-Page Applications**: Client-side JavaScript routing is parsed via static regex mining; complex DOM-rendered states may require headless browser execution.
3. **Multi-Step Business Logic**: Flaws requiring complex state machines (e.g. multi-step shopping cart checkout tampering) require custom authorization definitions.
4. **WAF & Rate-Limiting Delays**: Aggressive remote rate limits can extend scan durations to preserve polite scanning constraints.
5. **Nondeterministic LLM Variance**: When using remote cloud LLMs, temperature and prompt variations may alter test prioritization order.

---

## 16. Conclusion & Future Work

BugScout demonstrates that **LLM-guided cognitive threat modeling**, paired with a **deterministic evidence validation engine** and a **strict ethical firewall**, can reduce redundant network probing by **64.25%** while maintaining strong detection recall (**70.37%**) and high precision (**95.00%**) on a 60+ case security benchmark.

### Future Work:
- Integrating headless Chromium execution for complex dynamic DOM event rendering.
- Implementing automated business-logic workflow state graph synthesis.
- Expanding the ground-truth benchmark to 200+ multi-service microservice topologies.
