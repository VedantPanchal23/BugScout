# 🛡️ BugScout: An LLM-Guided Multi-Agent Security Testing and Attack Surface Discovery Platform

[![Architecture](https://img.shields.io/badge/Architecture-7--Stage%20Policy%20Engine-blue)](#4-system-architecture--policy-engine)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-OASIS%202.1.0%20Compliant-purple)](#14-reproducibility-manifest--reporting-suite)
[![Benchmark](https://img.shields.io/badge/Benchmark-46%20Labeled%20Cases-brightgreen)](#7-ground-truth-benchmark-lab-46-cases)
[![LLM Engine](https://img.shields.io/badge/LLM-Groq%20%7C%20Gemini%20%7C%20HF%20%7C%20Heuristic-success)](#4-system-architecture--policy-engine)
[![Tests](https://img.shields.io/badge/Pytest-38%20Defined%20Tests%20Passed-brightgreen)](#15-test-suite-taxonomy--coverage-38-tests)

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

> **Headline Research Finding:** BugScout reduces HTTP probing by **64.25%** and increases precision from **88.00% to 95.00%**, but recall decreases by **11.11 percentage points (81.48% → 70.37%)**. The resulting detection yield per HTTP request is **2.42× higher than the blind baseline** (12.42 vs. 5.14 detected vulnerabilities per 100 HTTP requests).

---

## 1. Problem Statement
Automated application security testing (AST) and penetration testing reconnaissance are traditionally divided between two paradigms:
1. **Blind / Dictionary Scanners**: Deterministic tools that exhaustively spray predefined dictionary payloads across all reachable parameters without contextual comprehension. This causes high outbound network overhead, server noise, and elevated false positive rates on complex endpoints.
2. **Manual Security Auditing**: High-quality contextual threat modeling performed by human security engineers, which is labor-intensive, slow, and expensive to scale.

---

## 2. Research Question
> **Central Hypothesis:** *Can LLM-guided threat prioritization reduce probing traffic while preserving detection performance relative to a predefined blind-testing baseline under deterministic safety constraints?*

### Experimental Outcome: Hypothesis is Partially Supported
The evaluation **partially supports** the hypothesis:
- **Probing Traffic**: Substantially reduced by **64.25%** (153 vs. 428 requests).
- **Precision**: Improved from **88.00% to 95.00%** (1 FP vs. 3 FPs).
- **Detection Yield**: Increased from 5.14 to 12.42 vulns / 100 requests (**2.42× higher yield per request**).
- **Detection Recall**: Decreased by **11.11 percentage points** (81.48% for blind baseline vs. 70.37% for BugScout).

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
| **DNS Rebinding Attacks** | Hostname dynamically resolves to a private IP mid-scan | Pre-connect DNS destination validation in `ScopeGuard.resolve_and_verify_ip()` |
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
| **4. ScopeGuard Layer** | **Deterministic** | Pre-connect DNS destination validation, SSRF & private IP firewall | Boundary enforcement check |
| **5. Probe Execution Agent** | **Deterministic** | Dispatches non-destructive static syntax markers | Gated strictly by ScopeGuard |
| **6. Observation Agent** | **Deterministic** | Statistical timing diffing, AST reflection parsing, signature detection | Content-type check, response size limits |
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
- ✅ Enforce pre-connect DNS destination validation and token-bucket rate limits.

---

## 6. Vulnerability Detection Classes & Multi-Variants

BugScout is equipped with multi-variant detection engines across 10+ vulnerability classes:

1. **SQL Injection (SQLi)**: GET search queries, POST form bodies, JSON filter objects, Numeric IDs, and statistical time-based delay checks.
2. **Cross-Site Scripting (XSS)**: Reflected HTML body, HTML attribute context (`value="..."`), and lexical JavaScript script block reflection.
3. **CORS Misconfiguration**: Wildcard origin with credentials, arbitrary reflected origin, and `null` origin acceptance.
4. **Two-User IDOR**: Multi-identity authorization boundary testing (User A token accessing User B profile/order).
5. **Multi-State Broken Authentication**: Unauthenticated admin routes, invalid token rejection, expired token handling, and role-based access checks.
6. **Path / Directory Traversal**: Standard `../` paths, URL-encoded `%2e%2e%2f` sequences, and Windows `..\win.ini` traversals.
7. **Open URL Redirection**: Query parameter destinations and path-based open redirects.
8. **Sensitive Data & Secrets**: Leaked database credentials (`.env`), API keys (`config.json`), and JWT secrets.
9. **GraphQL Introspection**: Unrestricted `__schema` introspection in production.
10. **Missing Security Headers**: Absence of `X-Frame-Options` (Clickjacking) and `Content-Security-Policy`.

---

## 7. Ground Truth Benchmark Lab (46 Labeled Cases)

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
| **Detection Yield / 100 Requests** | 5.14 | **12.42** | **2.42× Higher Yield per Request** |
| **Relative Detection Yield** | 1.00× | **2.42×** | **+141.6% Yield Efficiency** |
| **Duration** | 3.18s | **1.11s** | **-65.18% (Faster Completion)** |

---

## 10. Cost-Recall Pareto Frontier Experiment

Evaluating recall scaling across varying HTTP request probe budgets (`python main.py --budget-curve`):

| Probe Budget / Configuration | HTTP Requests | Vulnerabilities Found | Recall (%) | Efficiency (Vulns / 100 Reqs) | Pareto Frontier Status |
|---|:---:|:---:|:---:|:---:|:---:|
| **Minimal Recon Budget** | 48 | 8 / 27 | 29.63% | 16.67 | Non-dominated |
| **Lightweight Budget** | 96 | 14 / 27 | 51.85% | 14.58 | Non-dominated |
| **BugScout Standard Single-Pass** | **153** | **19 / 27** | **70.37%** | **12.42** | **Optimal Non-dominated Operating Point** |
| **Extended Exploration Budget** | 198 | 19 / 27 | 70.37% | 9.60 | Dominated by 153 (Equal recall, higher cost) |
| **BugScout Deep Replanning** | 282 | 19 / 27 | 70.37% | 6.74 | Dominated by 153 (Equal recall, higher cost) |
| **Exhaustive Blind Dictionary Baseline** | **428** | **22 / 27** | **81.48%** | **5.14** | **Non-dominated (Higher recall, higher cost)** |

> **Mathematical Pareto Frontier Justification:**
> - The **153-request configuration strictly dominates** the 198- and 282-request configurations because they achieve the exact same recall (70.37%) at higher request traffic.
> - The **428-request blind baseline remains on the Pareto frontier** because it achieves higher absolute recall (81.48% vs. 70.37%), though at 2.8× higher request cost.

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

## 11. Zero-Shot Hidden Benchmark Generalization

To verify that BugScout does not rely on dataset memorization or hardcoded routes, `--hidden-eval` spins up an ephemeral testbed with **multi-dimensional randomization**: randomized route paths (`/api/client_XXXX/*`, `/service/item_XXXX/*`), randomized parameter names (`client_q`, `item_slug`, `doc_target`, `redir_dest`), and diverse response formats.

```bash
python main.py --hidden-eval
```

| Generalization Metric | Empirical Result | Evaluation Meaning |
|---|:---:|---|
| **Total Hidden Labeled Cases** | **6** | 4 Seeded Vulnerable Instances + 2 Safe Negative Decoys |
| **Endpoints Discovered by Recon** | **7** | Autonomous zero-shot attack surface mapping |
| **True Positives (TP)** | **3 / 4** | Autonomous threat identification across novel routes |
| **False Positives (FP)** | **0** | Zero false alarms on deceptive safe controls |
| **False Negatives (FN)** | **1** | Missed novel vulnerability instance |
| **True Negatives (TN)** | **2 / 2** | Safe controls correctly rejected |
| **Zero-Shot Recall** | **75.00%** | $\frac{TP}{TP+FN} = \frac{3}{3+1}$ Coverage on previously unseen endpoints |
| **Zero-Shot Precision** | **100.00%** | $\frac{TP}{TP+FP} = \frac{3}{3+0}$ High reliability on novel parameter names |
| **Zero-Shot Specificity** | **100.00%** | $\frac{TN}{TN+FP} = \frac{2}{2+0}$ Safe control rejection accuracy |

---

## 12. 4-Tier Component Ablation Study

| Ablation Tier | Total Requests | Hypotheses Formulated | Confirmed Findings | Component Delta / Scientific Finding |
|---|:---:|:---:|:---:|---|
| **Tier 1: Heuristic Rules Only** | 142 | 4 | 4 | Baseline Deterministic Pattern Matching |
| **Tier 2: Rules + LLM Threat Modeling** | 153 | 19 | 19 | **+15 Findings (+375.0% relative improvement via LLM)** |
| **Tier 3: Rules + LLM + Replanning** | 282 | 27 | 19 | +8 Hypotheses (Deepens exploration; increases requests) |
| **Tier 4: Full BugScout Platform** | 282 | 27 | 19 | Enforces ScopeGuard boundary & rate limits |

> **Scientific Finding on Replanning:** Adding adaptive replanning (Tier 3) deepens hypothesis exploration (19 $\rightarrow$ 27 hypotheses) but increases request traffic from 153 to 282 requests without increasing final confirmed findings on this single-step testbed. This demonstrates that replanning increases exploratory breadth, but requires multi-payload mutation suites to convert secondary hypotheses into confirmed vulnerabilities.

---

## 13. Root Cause Taxonomy for 8 False Negatives

| Missed Case ID | Vulnerability Name | Failure Stage | Why Missed / Root Cause | Proposed Future Improvement |
|:---:|:---|:---:|:---|:---|
| **SQLi-V05** | Time-Based Blind SQLi | **Observation** | Timing delay thresholds require multi-stage jitter baseline comparison | Statistical response time distribution analyzer |
| **XSS-V03** | JS Script-Context XSS | **Observation** | Reflection inside quoted JS variable requires AST/DOM context parser | JavaScript lexical token reflection matcher |
| **TRAV-V03** | Windows Path Traversal | **Threat Reasoning** | Operating system heuristic prioritized POSIX `/etc/passwd` over `win.ini` | Cross-platform OS traversal payload rotation |
| **RED-V02** | Goto Path Open Redirect | **Recon** | Secondary redirection path parameter unrecognized by crawler | Expand parameter ontology to include routing terms |
| **AUTH-V02** | Broken Auth Config | **Recon** | Privileged config endpoint required deeper route enumeration | Recursive privileged route dictionary fuzzing |
| **UNSEEN-01** | Hidden Catalog SQLi | **Recon** | Obfuscated path requires multi-step state graph exploration | State-machine workflow exploration graph |
| **UNSEEN-02** | Hidden Portal XSS | **Recon** | Dynamic DOM interaction required to reveal query reflection | Headless Chromium DOM rendering integration |
| **UNSEEN-03** | Hidden Legacy Traversal | **Threat Reasoning** | Non-standard query parameter requiring blind parameter fuzzing | Probabilistic parameter discovery engine |

---

## 14. Reproducibility Manifest & Reporting Suite

Every execution automatically generates an OASIS-compliant reporting suite and a formal **Reproducibility Manifest** (`outputs/ReproducibilityManifest.json`):

```json
{
  "experiment": {
    "name": "46-Case Ground Truth Benchmark Evaluation",
    "id": "primary_46_case_benchmark",
    "benchmark_version": "v2.1",
    "git_commit": "8769718",
    "python_version": "3.11.9",
    "os_platform": "win32",
    "random_seed": 42,
    "model_configuration": {
      "model_name": "groq/qwen3.8-27b (or heuristic fallback)",
      "temperature": 0.0,
      "deterministic_inference": true
    }
  },
  "dataset": {
    "total_cases": 46,
    "positive_cases": 27,
    "negative_cases": 19,
    "ground_truth_hash": "3c6218d6e9a8f309a47da29b28b76c8c4a4e12e1281ffaa22c06eb18f4a1329a"
  },
  "confusion_matrix": {
    "true_positives": 19,
    "true_negatives": 18,
    "false_positives": 1,
    "false_negatives": 8
  },
  "traffic": {
    "request_budget": 153,
    "requests_sent": 308
  },
  "metrics": {
    "precision": 95.0,
    "recall": 70.37,
    "f1_score": 80.85,
    "specificity": 94.74
  }
}
```

---

## 15. Test Suite Taxonomy & Coverage (38 Tests)

```text
38 Automated Tests
├── Unit Tests (Recon, Auth, LLM, Observer, SARIF, WAF)
├── Integration Tests (Full Pipeline, Checkpoint, Cross-Format Consistency)
├── Benchmark Tests (Ground-Truth Metrics, 4-Tier Ablation)
├── Safety Tests (Private Subnets, Cloud Metadata, Obfuscated IPs, Rate Limits)
├── LLM Failure Tests (Malformed JSON Fallback, Resilience)
├── ScopeGuard Bypass Tests (Structural Bypass Prevention, Adversarial LLM Hypotheses, Kill Switch)
└── DNS & Redirect Tests (Pre-Connect DNS Rebinding, Multi-Record DNS, Redirect Escape)
```

Run test suite:
```bash
pytest -v
```

---

## 16. Conclusion & Future Work

BugScout provides an experimentally evaluated LLM-guided multi-agent security testing architecture in which LLM reasoning is restricted to threat prioritization while network execution, scope enforcement, observation, evidence validation, and reporting remain deterministic.

On the 46-case controlled benchmark, BugScout detected 19 of 27 seeded vulnerabilities and produced one false positive, corresponding to 70.37% recall and 95.00% precision. In the unified baseline experiment, BugScout reduced HTTP requests from 428 to 153, a 64.25% reduction, while increasing detection yield from 5.14 to 12.42 detected vulnerabilities per 100 requests, approximately a 2.42× improvement in detection yield per request.

However, the efficiency improvement involved a measurable recall trade-off: the blind baseline detected 22/27 vulnerabilities (81.48% recall), compared with 19/27 (70.37%) for BugScout. Therefore, the current results **partially support** the research hypothesis rather than demonstrating that lower probing traffic can be achieved with no loss in detection performance.

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
- Transport-level raw socket connection enforcement.
- Expand prompt-injection resilience testing.
- Measure LLM failure and fallback behavior.
- Evaluate repeated runs under deterministic and nondeterministic inference settings.

#### Phase 4 — Generalization
- Evaluate across Django, Spring Boot, Laravel, and other application stacks.
- Expand testing to GraphQL and microservice architectures.
- Introduce a hidden benchmark split to measure generalization to previously unseen vulnerability patterns.
