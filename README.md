# 🛡️ BugScout — Autonomous Bug Bounty & Attack Surface Scout

> **An Agentic AI Security Pipeline that autonomously explores attack surfaces, formulates vulnerability hypotheses, executes safe non-destructive test probes, and produces structured CVSS-scored vulnerability reports.**

![Agentic AI Pipeline](https://img.shields.io/badge/Architecture-Multi--Agent%20Pipeline-blue)
![Zero-Cost](https://img.shields.io/badge/Zero--Cost-Groq%20%7C%20Gemini%20%7C%20HF%20%7C%20Offline-success)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📌 Executive Overview

Penetration testing and bug bounty recon are traditionally manual, labor-intensive workflows. Existing automated scanners (Burp Suite, Nikto) rely on rigid rule-based pattern matching, while chat-based LLM assistants lack autonomous execution loops.

**BugScout** bridges this gap as an **autonomous multi-agent system** with a tight feedback loop:
\text{Recon} \longrightarrow \text{Hypothesize} \longrightarrow \text{Test} \longrightarrow \text{Observe} \longrightarrow \text{Replan / Refine} \longrightarrow \text{Report}

All outbound requests are strictly governed by **ScopeGuard** — a cross-cutting ethical firewall that enforces target boundaries, prevents SSRF against internal/private infrastructure, rate limits traffic, and contains an automated kill-switch.

---

## 🤖 Agentic Architecture

`mermaid
flowchart TD
    User(["User / CLI"]) --> ScopeFile["Scope Config (scope.yaml)"]
    ScopeFile --> SG["ScopeGuard (Ethical Boundary Layer)"]

    subgraph Agentic_Pipeline["BugScout Agentic Pipeline"]
        Recon["1. ReconAgent\n• robots.txt & sitemaps\n• OpenAPI / Swagger\n• HTML Crawler & JS Mining"]
        Hypothesis["2. HypothesisAgent\n• OWASP Risk Correlation\n• Parameter Reasoning\n• Queue Prioritization"]
        Payload["3. PayloadAgent\n• Contextual Probe Crafting\n• Safe Payload Mutation\n• Rate-Limited Dispatch"]
        Observer["4. ObserverAgent\n• SQL Syntax Anomaly Detection\n• Reflection Analysis (XSS)\n• Baseline Differential Engine"]
        Report["5. ReportAgent\n• CVSS 3.1 Base Scoring\n• Reproduction Curl PoCs\n• Markdown & JSON Reports"]

        Recon -->|"EndpointMap"| Hypothesis
        Hypothesis -->|"HypothesisQueue"| Payload
        Payload -->|"HTTP Probes"| SG
        SG -->|"Filtered & Rate-Limited"| Target[("Target Web App / API")]
        Target -->|"Responses"| Payload
        Payload -->|"TestResults"| Observer
        
        Observer -.->|"Secondary Hypotheses (Replanning)"| Hypothesis
        Observer -->|"Confirmed Findings"| Report
    end

    Report --> OutMD["outputs/VulnerabilityReport.md"]
    Report --> OutJSON["outputs/VulnerabilityReport.json"]
    Report --> RichUI["Rich Terminal Summary"]
`

### Agent Roster & Responsibilities

| Agent | Responsibility | Core Actions |
|---|---|---|
| **ReconAgent** | Attack Surface Discovery | Parses obots.txt, sitemap.xml, OpenAPI/Swagger specifications, recursively crawls links/forms, extracts JS endpoints via regex, fingerprints tech stack headers. |
| **HypothesisAgent** | Threat Modeling & Prioritization | Analyzes parameter semantics (id, search, url, ole, dmin), computes risk confidence, ranks test queue. Supports free LLM augmentation (Groq / Gemini / HF / Offline Heuristics). |
| **PayloadAgent** | Safe Probe Execution | Selects non-destructive probes (payloads/*.txt), contextually injects into query params, JSON bodies, and headers, routes all requests through ScopeGuard. |
| **ObserverAgent** | Anomaly Detection & Replanning | Differential baseline response analysis, SQL database error signatures (MySQL, SQLite, Postgres, Oracle), unescaped reflection detection, credentials/secret leak detection. Dispatches secondary hypotheses if anomalies require confirmation. |
| **ReportAgent** | Intelligence Synthesis | Calculates CVSS 3.1 base scores & vector strings, generates step-by-step reproduction instructions, raw evidence snippets, remediation guidance, and outputs Markdown + JSON reports. |
| **ScopeGuard** | Ethical Firewall & Safety Layer | Hard blocks out-of-scope hosts, path wildcards, private IP ranges (RFC 1918, link-local, cloud metadata), enforces token-bucket rate limiting, and triggers a kill-switch on consecutive violations. |

---

## ⚡ Zero-Cost LLM Strategy

BugScout operates with **zero paid API dependencies**. The modular LLM engine (core/llm.py) offers a 4-tier fallback hierarchy:

1. **Built-in Offline Security Intelligence Engine** (*Default & Zero Setup*): Deterministic OWASP vulnerability correlation rules. 100% offline, zero latency, zero cost.
2. **Groq Cloud Free Tier** (GROQ_API_KEY): Ultra-fast inference with Llama 3.3 70B / 8B.
3. **Google Gemini Free Tier** (GEMINI_API_KEY): Generative reasoning via gemini-2.5-flash.
4. **Hugging Face Free Inference API** (HF_TOKEN): Serverless open-source models.
5. **Local Ollama** (OLLAMA_HOST): Run local models like llama3 or qwen2.5-coder.

---

## 🚀 Quickstart & Installation

### 1. Prerequisites & Virtual Environment Setup
Ensure you have Python 3.11+ installed.

`ash
# Clone the repository
git clone https://github.com/VedantPanchal23/BugScout.git
cd BugScout

# Create and activate Python 3.11 virtual environment
py -3.11 -m venv .venv

# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
`

### 2. Run Built-in Live Demo (One-Click)
BugScout includes a self-contained deliberately vulnerable test target (mock_target/server.py):

`ash
python main.py --demo
`

### 3. Run Against a Custom Authorized Target
1. Configure your target and allowed scope in config/scope.yaml:
   `yaml
   target: "http://your-authorized-app.com"
   allowed_hosts:
     - "your-authorized-app.com"
   allowed_paths:
     - "/api/*"
     - "/search"
   max_requests_per_minute: 60
   `
2. Execute the autonomous scout:
   `ash
   python main.py --config config/scope.yaml
   `

---

## 🧪 Testing & Verification

Run the comprehensive unit and integration test suite:

`ash
pytest -v
`

Test coverage includes:
- 	ests/test_scope_guard.py: Scope matching, path prefix wildcards, private IP blocks, metadata protection, payload validation, and kill-switch activation.
- 	ests/test_recon.py: Endpoint registration, sitemap/robots parsing, and JavaScript regex endpoint extraction.
- 	ests/test_observer.py: SQLi database error regex detection, XSS reflection verification, and .env secret leak detection.
- 	ests/test_full_pipeline.py: End-to-end multi-agent execution against the mock target.

---

## ⚖️ Ethical & Legal Compliance

> [!CAUTION]
> **Authorized Testing Only:** BugScout is engineered strictly for authorized security assessments, CTF challenges, developer self-assessments, and bug bounty programs with explicit written scope authorization.

- **Non-Destructive Probes Only:** BugScout does not execute destructive queries (DROP, DELETE, TRUNCATE), denial-of-service payloads, or password spraying attacks.
- **SSRF Safeguard:** Outbound probes to internal IP ranges (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, 127.0.0.0/8, 169.254.169.254) are hard-blocked by default.
- **Scope Integrity:** Any request outside llowed_hosts or llowed_paths is intercepted before touching the network.
