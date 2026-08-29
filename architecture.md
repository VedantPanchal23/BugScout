# Architecture — Autonomous Bug Bounty Scout

## System Overview
The system is a multi-agent pipeline built on Antigravity. Each agent has a single responsibility. Agents communicate via a shared state object (the Mission Context) that is passed forward through the pipeline and updated after each agent's execution cycle. The loop is: Recon → Hypothesize → Test → Observe → Synthesize, with a Scope Guard running as a cross-cutting layer on every outbound action.

## Agent Roster

### 1. ReconAgent
**Responsibility:** Map the full attack surface of the target.
**Actions:**
- Fetch and parse robots.txt, sitemap.xml, OpenAPI/Swagger specs
- Crawl linked pages up to configurable depth
- Extract all endpoints, HTTP methods, query parameters, request bodies, headers
- Identify authentication mechanisms (cookie-based, Bearer token, API key)
- Detect tech stack fingerprints (Server header, X-Powered-By, error messages)

**Output:** `EndpointMap` — structured list of all discovered endpoints with metadata

---

### 2. HypothesisAgent
**Responsibility:** Generate ranked vulnerability hypotheses per endpoint.
**Actions:**
- For each endpoint in `EndpointMap`, reason about applicable vulnerability classes
- Rank hypotheses by likelihood given endpoint characteristics (e.g. a numeric `id` param → IDOR candidate)
- Output a prioritized test queue

**Vulnerability classes covered (v1):**
- SQL Injection
- Reflected / Stored XSS
- IDOR (Insecure Direct Object Reference)
- SSRF
- Broken Authentication / Missing Auth checks
- Security Misconfigurations (verbose errors, directory listing)
- Sensitive Data Exposure (tokens in responses, verbose stack traces)

**Output:** `HypothesisQueue` — ordered list of (endpoint, vulnerability_class, confidence_score, rationale)

---

### 3. PayloadAgent
**Responsibility:** Craft and execute test payloads for each hypothesis.
**Actions:**
- Select appropriate payload templates per vulnerability class
- Mutate payloads based on endpoint context (parameter type, expected format)
- Execute HTTP requests against target
- All outbound requests pass through ScopeGuard before firing

**Output:** `TestResults` — list of (hypothesis, payload_sent, response_code, response_body_snippet, anomaly_flag)

---

### 4. ObserverAgent
**Responsibility:** Analyze PayloadAgent results and detect evidence of vulnerabilities.
**Actions:**
- Diff response against baseline (normal request vs. payload request)
- Detect anomaly signals: unexpected status codes, response time deltas, error message content, reflected input, redirect chains
- Assign a confirmed / likely / unlikely / false-positive label to each result
- Flag high-confidence findings for immediate escalation to ReportAgent

**Output:** `FindingsList` — annotated test results with evidence and confidence labels

---

### 5. ReportAgent
**Responsibility:** Synthesize all findings into a structured vulnerability report.
**Actions:**
- Group findings by severity (Critical / High / Medium / Low / Informational)
- Write reproduction steps for each confirmed finding
- Estimate CVSS score per finding
- Generate executive summary
- Output markdown report + machine-readable JSON

**Output:** `VulnerabilityReport.md` + `VulnerabilityReport.json`

---

### 6. ScopeGuard (Cross-cutting)
**Responsibility:** Enforce ethical and scope boundaries on every outbound action.
**Actions:**
- Validate every URL before any agent fires a request
- Block requests to any host not in the user-defined scope
- Block payload classes the user has explicitly excluded
- Log every blocked action with reason
- Hard kill-switch: if ScopeGuard blocks more than N requests in a row, halt pipeline and alert user

**This is not optional and cannot be bypassed by any agent.**

---

## Mission Context (Shared State)
```json
{
  "target": "https://example.com",
  "scope": {
    "allowed_hosts": ["example.com"],
    "allowed_paths": ["/api/*", "/login", "/products/*"],
    "excluded_test_types": []
  },
  "endpoint_map": [],
  "hypothesis_queue": [],
  "test_results": [],
  "findings": [],
  "report": null
}
```
Every agent reads from and writes to this object. Antigravity manages the orchestration loop.

---

## Agentic Loop
User Input (target + scope)
↓
ReconAgent
↓
HypothesisAgent
↓
PayloadAgent ←→ ScopeGuard (every request)
↓
ObserverAgent
↓
ReportAgent
↓
Final Report Output


Replanning: If ObserverAgent detects a high-confidence finding mid-loop, it can push new hypotheses back into the HypothesisQueue, triggering a secondary PayloadAgent cycle for deeper exploration of that attack surface. This is the core agentic loop behavior.

---

## Tech Stack
| Layer | Choice |
|---|---|
| Agent Framework | Antigravity |
| LLM Backend | Open-source model via Hugging Face (Mistral / Qwen / DeepSeek) |
| HTTP Client | Python `httpx` (async) |
| HTML Parser | `BeautifulSoup4` |
| OpenAPI Parser | `prance` or `openapi-spec-validator` |
| Report Output | Markdown + JSON |
| State Store | In-memory Python dict (v1), Redis (v2) |
| Runtime | Local Python env / Google Colab compatible |

---

## Directory Structure
BugScout/
├── agents/
│ ├── recon_agent.py
│ ├── hypothesis_agent.py
│ ├── payload_agent.py
│ ├── observer_agent.py
│ ├── report_agent.py
│ └── scope_guard.py
├── core/
│ ├── mission_context.py
│ ├── pipeline.py
│ └── loop.py
├── payloads/
│ ├── sqli.txt
│ ├── xss.txt
│ ├── ssrf.txt
│ └── idor.txt
├── outputs/
│ ├── VulnerabilityReport.md
│ └── VulnerabilityReport.json
├── config/
│ └── scope.yaml
├── main.py
└── README.md