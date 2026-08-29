# 🛡️ BugScout: An LLM-Guided Multi-Agent Security Testing and Attack Surface Discovery Platform

[![Architecture](https://img.shields.io/badge/Architecture-7--Stage%20Policy%20Engine-blue)](#4-system-architecture--policy-engine)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-OASIS%202.1.0%20Compliant-purple)](#13-reproducibility--reporting-suite)
[![Benchmark Evaluation](https://img.shields.io/badge/Benchmark-46%20Labeled%20Cases-brightgreen)](#7-ground-truth-benchmark-lab-46-cases)
[![LLM Engine](https://img.shields.io/badge/LLM-Groq%20%7C%20Gemini%20%7C%20HF%20%7C%20Heuristic-success)](#4-system-architecture--policy-engine)
[![Tests](https://img.shields.io/badge/Pytest-28%2F28%20Passed-brightgreen)](#14-quickstart--cli-command-reference)

---

## 🎯 Headline Research Results

```
                         BUGSCOUT RESULTS

        ┌─────────────────────────────────────────┐
        │          64.25% fewer HTTP requests     │
        └────────────────────┬────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
          BugScout                       Baseline
        153 requests                   428 requests

       Recall: 70.37%                 Recall: 81.48%
      Precision: 95.00%              Precision: 88.00%
       19/27 detected                 22/27 detected
```

> **Key Research Finding:** BugScout achieves **12.42 vs. 5.14 detected vulnerabilities per 100 HTTP requests (a 2.42× higher detection yield per request)** and increases precision from 88.00% to 95.00%, trading an **11.11-percentage-point recall delta** (70.37% vs. 81.48%) for a **64.25% reduction in total HTTP probing traffic**.

---

## 1. Problem Statement
Automated application security testing (AST) and penetration testing reconnaissance are traditionally divided between two paradigms:
1. **Blind / Dictionary Scanners**: Deterministic tools that exhaustively spray predefined dictionary payloads across all reachable parameters without contextual comprehension. This causes high outbound network overhead, server noise, and elevated false positive rates on complex endpoints.
2. **Manual Security Auditing**: High-quality contextual threat modeling performed by human security engineers, which is labor-intensive, slow, and expensive to scale.

---

## 2. Research Question
> **Central Hypothesis:** *Can LLM-guided threat prioritization reduce probing traffic while preserving detection performance relative to a predefined blind-testing baseline under deterministic safety constraints?*

### Experimental Outcome: Partially Supported
The evaluation **partially supports** the hypothesis. BugScout reduced HTTP probing traffic by **64.25%** and improved precision from **88.00% to 95.00%**, but this came with an **11.11-percentage-point reduction in recall** (81.48% for the blind baseline vs. 70.37% for BugScout).

### Primary & Secondary Success Criteria
- **Primary Metric**: Vulnerability detection recall achieved at a bounded HTTP request budget.
- **Secondary Metrics**: Precision, $F_1$ score, detection yield per 100 HTTP requests, execution latency, and zero observed out-of-scope requests in the safety test suite.

---

## 3. Threat Model

### 3.1 Attacker-Controlled Inputs & Trust Boundaries
| Component | Trust Level | Examples / Attack Surface |
|---|---|---|
| **Target Application Surface** | Untrusted | HTML bodies, script blocks, query params, JSON bodies, HTTP headers, API error strings |
| **LLM Output (Hypotheses)** | Untrusted / Advisory | Parameter vulnerability hypotheses, candidate test plans (must be validated before probing) |
| **Policy Engine & ScopeGuard** | Trusted / Authoritative | Scope definitions (`scope.yaml`), IP blacklist, rate limiter, URL path normalizer |
| **Probe & Validation Engine** | Trusted / Deterministic | Static non-destructive probe library, response diffing engine, Evidence Level (0–4) validator |

### 3.2 Threat Vectors & Enforced Security Controls
| Threat Vector | Description | Enforced Scanner Control |
|---|---|---|
| **Private Subnet / SSRF Escape** | Probing causes scanner to access internal cloud/LAN networks | ScopeGuard hard firewall blocks `10.x`, `172.16.x`, `192.168.x`, `127.0.0.1`, and `169.254.169.254` |
| **Target-Side Prompt Injection (T16)** | Malicious target embeds instructions in HTML to subvert the LLM | LLM output is strictly treated as *hypotheses*; deterministic `ValidationAgent` requires empirical Evidence Level 3/4 before confirming |
| **Cross-Domain Redirect Escape** | Target returns `302 Found` to an attacker-controlled external host | `ScopeGuard.validate_redirect()` inspects redirect destination before following |
| **Denial of Service (DoS)** | Scanner overwhelms target server with high-throughput requests | Token-bucket rate limiter with adaptive WAF backoff and jitter |

---

## 4. System Architecture & Policy Engine

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
                  |    1. Reconnaissance Agent|  (Deterministic)
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |   Attack Surface Graph    |
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  | 2. Threat Reasoning Agent |  (LLM: Groq / Gemini / Heuristics)
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |  3. Policy Orchestrator   |  (Deterministic Budget & Priority Ordering)
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  | 4. ScopeGuard Enforcement |  (Deterministic IP, SSRF & Rate Limits)
                  +-------------+-------------+
                                | (Approved Probes)
                                v
                  +---------------------------+
                  |   5. Probe Execution Agent|  (Deterministic Static Payloads)
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |   6. Observation Agent    |  (Deterministic Response Diffing)
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |   7. Validation Agent     |  (Deterministic Evidence Levels 0 to 4)
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

### Deterministic vs. LLM Agent Boundaries

| Agent | Technology Type | Role & Responsibility | Security Constraints |
|---|---|---|---|
| **1. Recon Agent** | **Deterministic** | Crawls HTML, mines React/Vue SPA routes, parses OpenAPI & GraphQL | Max crawl depth, path whitelist |
| **2. Threat Reasoning Agent** | **LLM-Guided** | Semantic parameter risk ranking & hypothesis formulation | Prompt-injection isolation, heuristic fallback |
| **3. Policy Orchestrator** | **Deterministic** | Enforces probe budgets, duplicate filtering, stopping criteria | Budget caps, priority queue |
| **4. ScopeGuard Layer** | **Deterministic** | Hard firewall against private IPs, SSRF, cloud metadata, redirects | Inviolable boundary check |
| **5. Probe Execution Agent** | **Deterministic** | Dispatches non-destructive static syntax markers | Gated strictly by ScopeGuard |
| **6. Observation Agent** | **Deterministic** | Behavioral diffing, status analysis, signature detection | Content-type check, response size limits |
| **7. Validation Agent** | **Deterministic** | Evidence Quality scoring (Levels 0–4) | Requires Level 3/4 evidence (prevents hallucination) |
| **8. Reporting Agent** | **Deterministic** | Computes CVSS 3.1 vectors & multi-format serialization | Sanitized reproduction steps, secret redaction |

---

## 5. ScopeGuard Ethical Boundary & Safety Guarantees

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

## 7. Ground Truth Benchmark Lab (46 Cases)

The benchmark contains **46 labeled evaluation cases: 27 seeded vulnerability instances and 19 deceptive negative cases** (`benchmark_lab/server.py`):

```
BugScout Benchmark Lab (46 Labeled Cases)
├── Vulnerable Instances (27 Seeded Cases)
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
└── Deceptive Negative Cases (19 Safe Controls)
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

## 8. Empirical Performance Metrics (46-Case Benchmark)

Step-by-step arithmetic on the 46 labeled evaluation cases:

$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{19}{19 + 1} = 95.00\%$$

$$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{19}{19 + 8} = 70.37\%$$

$$F_1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = 2 \times \frac{0.95 \times 0.7037}{0.95 + 0.7037} = 80.85\%$$

$$\text{Specificity} = \frac{\text{TN}}{\text{TN} + \text{FP}} = \frac{18}{18 + 1} = 94.74\%$$

| Metric | Ground-Truth Empirical Result | Meaning |
|---|:---:|---|
| **True Positives (TP)** | **19** | Genuine seeded vulnerabilities discovered |
| **True Negatives (TN)** | **18** | Deceptive negative decoys correctly rejected |
| **False Positives (FP)** | **1** | Safe endpoints incorrectly flagged (deceptive redirect) |
| **False Negatives (FN)** | **8** | Complex multi-step cases requiring deeper crawl depth |
| **Precision** | **95.00%** | Reliability of reported findings |
| **Recall (Sensitivity)** | **70.37%** | Coverage of seeded vulnerabilities (Moderate Recall) |
| **F1 Score** | **80.85%** | Harmonic mean of precision and recall |
| **Specificity (Decoy Rejection)** | **94.74%** | Accuracy at rejecting false alarm decoys |
| **Endpoint Discovery** | **58 endpoints** | 45 baseline seeded routes + 13 dynamically mined endpoints |

### Category-Level Recall Breakdown

| Vulnerability Category | Seeded Present | Detected (TP) | Recall (%) | Safe Decoys (TN) | False Alarms (FP) |
|---|:---:|:---:|:---:|:---:|:---:|
| **SQL Injection (SQLi)** | 5 | 4 | **80.00%** | 2 | 0 |
| **Cross-Site Scripting (XSS)** | 3 | 2 | **66.67%** | 2 | 0 |
| **CORS Misconfiguration** | 3 | 3 | **100.00%** | 2 | 0 |
| **Insecure Direct Object Ref (IDOR)** | 2 | 2 | **100.00%** | 2 | 0 |
| **Broken Authentication** | 2 | 2 | **100.00%** | 4 | 0 |
| **Path Traversal** | 3 | 2 | **66.67%** | 2 | 0 |
| **Open URL Redirection** | 2 | 1 | **50.00%** | 2 | 1 |
| **Sensitive Data Exposure** | 2 | 2 | **100.00%** | 1 | 0 |
| **GraphQL Introspection** | 1 | 1 | **100.00%** | 1 | 0 |
| **Missing Security Headers** | 1 | 1 | **100.00%** | 1 | 0 |
| **Unseen Generalization Suite** | 3 | 1 | **33.33%** | 0 | 0 |
| **Total** | **27** | **19** | **70.37%** | **19** | **1** |

---

## 9. Baseline Comparison: Blind Scanner vs. Agentic AI

### Baseline Methodology:
- **Blind Baseline (Mode A)**: Exhaustively sprays dictionary payloads across all endpoints without semantic filtering.
- **BugScout Agentic AI (Mode B)**: LLM analyzes parameter semantics to test only high-confidence vulnerability hypotheses.
- **Workload**: Evaluated against the exact same **27 seeded vulnerability instances**.

| Metric | Blind Baseline | BugScout Agentic AI | Empirical Trade-Off / Comparison |
|---|:---:|:---:|:---:|
| **HTTP Requests** | 428 | **153** | **-64.25% (Traffic Saved)** |
| **Payload Tests Executed** | 368 | **115** | **-68.75% (Targeted)** |
| **Vulnerabilities Detected** | **22 / 27** | **19 / 27** | **-11.11 percentage points recall** |
| **Recall** | **81.48%** | **70.37%** | Relative recall reduction: -13.64% |
| **Precision** | 88.00% | **95.00%** | **+7.00% (High Precision)** |
| **False Positives** | 3 | **1** | **-66.7% FP Reduction (1 vs. 3)** |
| **Detection Yield / 100 Requests** | 5.14 | **12.42** | **2.42x Higher Yield per Request** |
| **Relative Detection Yield** | 1.00× | **2.42×** | **+141.6% Yield Efficiency** |
| **Duration** | 3.18s | **1.11s** | **-65.18% (Faster Completion)** |

---

## 10. Cost-Recall Pareto Frontier Experiment

Evaluating recall scaling across varying HTTP request probe budgets (`python main.py --budget-curve`):

| Probe Budget / Configuration | HTTP Requests | Vulnerabilities Found | Recall (%) | Efficiency (Vulns / 100 Reqs) | Pareto Status |
|---|:---:|:---:|:---:|:---:|:---:|
| **Minimal Recon Budget** | 48 | 8 / 27 | 29.63% | 16.67 | Sub-optimal |
| **Lightweight Budget** | 96 | 14 / 27 | 51.85% | 14.58 | Sub-optimal |
| **BugScout Standard Single-Pass** | **153** | **19 / 27** | **70.37%** | **12.42** | **Optimal Operating Point** |
| **Extended Exploration Budget** | 198 | 19 / 27 | 70.37% | 9.60 | Diminishing Returns |
| **BugScout Deep Replanning** | 282 | 19 / 27 | 70.37% | 6.74 | Diminishing Returns |
| **Exhaustive Blind Dictionary Baseline** | 428 | 22 / 27 | 81.48% | 5.14 | Diminishing Returns |

```text
Empirical Cost-Recall Curve Visualization:
Recall
100% |                                              * (Blind Baseline: 428 reqs -> 81.48%)
 80% |                        * (BugScout Standard: 153 reqs -> 70.37%)
 60% |              * (100 reqs -> 51.85%)
 40% |        * (50 reqs -> 29.63%)
 20% |
  0% +-------------------------------------------------------------------->
       0     50    100    150    200    250    300    350    400    450
                              HTTP Request Traffic
```

---

## 11. 4-Tier Component Ablation Study

| Ablation Tier | Total Requests | Hypotheses Formulated | Confirmed Findings | Component Delta / Scientific Finding |
|---|:---:|:---:|:---:|---|
| **Tier 1: Heuristic Rules Only** | 142 | 4 | 4 | Baseline Deterministic Pattern Matching |
| **Tier 2: Rules + LLM Threat Modeling** | 153 | 19 | 19 | **+15 Findings (+375.0% relative improvement via LLM)** |
| **Tier 3: Rules + LLM + Replanning** | 282 | 27 | 19 | +8 Hypotheses (Deepens exploration; increases requests) |
| **Tier 4: Full BugScout Platform** | 282 | 27 | 19 | Enforces ScopeGuard boundary & rate limits |

> **Scientific Finding on Replanning:** Adding adaptive replanning (Tier 3) deepens hypothesis exploration (19 $\rightarrow$ 27 hypotheses) but increases request traffic from 153 to 282 requests without increasing final confirmed findings on this testbed. This demonstrates that replanning increases exploratory breadth, but requires multi-payload mutation suites to convert secondary hypotheses into confirmed vulnerabilities.

---

## 12. Root Cause Taxonomy for 8 False Negatives

| Missed Case ID | Vulnerability Name | Why Missed / Root Cause | Responsible Agent | Proposed Future Improvement |
|:---:|:---|:---|:---:|:---|
| **SQLi-V05** | Time-Based Blind SQLi | Timing delay thresholds require multi-stage baseline diffing | ObservationAgent | Statistical response time distribution analyzer |
| **XSS-V03** | JS Script-Context XSS | Reflection inside quoted JS variable requires DOM context parser | ObservationAgent | JavaScript lexical token reflection matcher |
| **TRAV-V03** | Windows Path Traversal | Operating system heuristic prioritized `/etc/passwd` over `win.ini` | ThreatReasoningAgent | Cross-platform OS traversal payload rotation |
| **RED-V02** | Goto Path Open Redirect | Secondary redirection path parameter unrecognized by crawler | ReconAgent | Expand parameter ontology to include routing terms |
| **AUTH-V02** | Broken Auth Config | Privileged config endpoint required deeper route enumeration | ReconAgent | Recursive privileged route dictionary fuzzing |
| **UNSEEN-01** | Hidden Catalog SQLi | Obfuscated path requires multi-step state graph exploration | ReconAgent | State-machine workflow exploration graph |
| **UNSEEN-02** | Hidden Portal XSS | Dynamic DOM interaction required to reveal query reflection | ReconAgent | Headless Chromium DOM rendering integration |
| **UNSEEN-03** | Hidden Legacy Traversal | Non-standard query parameter requiring blind parameter fuzzing | ThreatReasoningAgent | Probabilistic parameter discovery engine |

---

## 13. ScopeGuard Safety Suite Audit (16 Tests)

All 16 defined ScopeGuard safety tests passed under the evaluated configurations (`python main.py --safety-test`):

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
| **SAFE-15** | Target-Side Prompt Injection (T16) | `https://app.example.com/comments` | DEFENDED | **DEFENDED** | PASS |
| **SAFE-16** | Cross-Domain Redirect Escape | `https://app.example.com/redirect?to=https://evil.attacker.com` | BLOCKED | **BLOCKED** | PASS |

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
| **1. Ground Truth Benchmark** | `python main.py --evaluate` | Executes 46-case benchmark with category breakdown & false negatives |
| **2. Cost-Recall Budget Curve** | `python main.py --budget-curve` | Evaluates recall scaling across HTTP request probe budgets |
| **3. A/B Baseline Comparison** | `python main.py --compare-modes` | Measures Blind Baseline vs. BugScout traffic efficiency |
| **4. Component Ablation** | `python main.py --ablation` | Runs 4-tier component ablation experiment |
| **5. Repeated 5-Run Stability** | `python main.py --repeated-eval` | Computes statistical mean and sample std dev ($\mu \pm \sigma$) |
| **6. Safety Suite Audit** | `python main.py --safety-test` | Audits 16 ScopeGuard private IP, prompt injection, and redirect checks |
| **7. Explainable Trace** | `python main.py --trace --demo` | Displays step-by-step agent decision audit log |
| **8. Arbitrary Target Scan** | `python main.py https://target.com` | Scouts any authorized live target URL with pre-flight banner |
| **9. Pytest Test Suite** | `pytest -v` | Runs all 28 automated unit and integration tests |

---

## 15. System Limitations

1. **Controlled Benchmark Scope**: Benchmark results reflect seeded vulnerabilities in the testbed; real-world detection depends on application-specific business logic.
2. **Benchmark Leakage Risk**: Synthetic testbeds may favor structured parameters; hidden unseen evaluation suites are used to verify generalization.
3. **Multi-User Authentication Coverage**: Authorization flaws (IDOR, privilege escalation) require pre-configured user credentials and cannot be assessed from unauthenticated crawling alone.
4. **Deep Single-Page Applications**: Client-side JavaScript routing is parsed via static regex mining; complex DOM-rendered states may require headless browser execution.
5. **Rate-Limiting & Latency**: Remote rate limits and WAF throttles can extend scan durations to preserve polite scanning constraints.

---

## 16. Conclusion & Future Work

BugScout provides an experimentally evaluated LLM-guided multi-agent security testing architecture in which LLM reasoning is restricted to threat prioritization while network execution, scope enforcement, observation, evidence validation, and reporting remain deterministic.

On the 46-case controlled benchmark, BugScout detected 19 of 27 seeded vulnerabilities and produced one false positive, corresponding to 70.37% recall and 95.00% precision. In the unified baseline experiment, BugScout reduced HTTP requests from 428 to 153, a 64.25% reduction, while increasing detection yield from 5.14 to 12.42 detected vulnerabilities per 100 requests, approximately a 2.42× improvement in detection yield per request.

However, the efficiency improvement involved a measurable recall trade-off: the blind baseline detected 22/27 vulnerabilities (81.48% recall), compared with 19/27 (70.37%) for BugScout. Therefore, the current results **partially support** the research hypothesis rather than demonstrating that lower probing traffic can be achieved with no loss in detection performance.

The results suggest that LLM-guided threat prioritization can substantially reduce probing volume while maintaining high precision, but additional work is required to recover missed vulnerabilities without eliminating the observed efficiency advantage.

### 4-Phase Future Work Roadmap:

#### Phase 1 — Recall Improvement
- Expand the benchmark to 100+ labeled cases.
- Analyze and address the eight current false negatives.
- Implement authenticated multi-user state-machine testing.
- Integrate headless Chromium execution for dynamic DOM behavior.

#### Phase 2 — Efficiency Optimization
- Introduce cost-aware dynamic probe selection.
- Implement adaptive per-endpoint probe budgets.
- Evaluate recall as a function of HTTP-request budget.
- Develop cost/recall curves to identify the optimal operating point.

#### Phase 3 — Robustness & Safety
- Add DNS-rebinding defenses and redirect-chain enforcement.
- Expand prompt-injection resilience testing.
- Measure LLM failure and fallback behavior.
- Evaluate repeated runs under deterministic and nondeterministic inference settings.

#### Phase 4 — Generalization
- Evaluate across Django, Spring Boot, Laravel, and other application stacks.
- Expand testing to GraphQL and microservice architectures.
- Introduce a hidden benchmark split to measure generalization to previously unseen vulnerability patterns.
