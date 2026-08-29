# 🛡️ BugScout — Autonomous Bug Bounty & Attack Surface Scout (Enterprise v3.0)

> **An Advanced, Production-Grade Agentic AI Security Platform that autonomously explores attack surfaces, formulates vulnerability hypotheses using LLM reasoning, executes safe non-destructive test probes, and produces structured CVSS-scored vulnerability reports, interactive HTML dashboards, and OASIS SARIF 2.1.0 compliance artifacts.**

![Agentic AI Pipeline](https://img.shields.io/badge/Architecture-Multi--Agent%20Pipeline-blue)
![SARIF 2.1.0](https://img.shields.io/badge/SARIF-OASIS%202.1.0%20Compliant-purple)
![LLM Backends](https://img.shields.io/badge/LLM-Groq%20%7C%20Gemini%20%7C%20HF%20%7C%20Offline-success)
![Vulnerabilities](https://img.shields.io/badge/OWASP%20Coverage-10%2B%20Classes-red)
![WAF Resilient](https://img.shields.io/badge/WAF-Adaptive%20Polite%20Mode-orange)
![Docker](https://img.shields.io/badge/Docker-Multi--Container%20Compose-blue)
![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-brightgreen)

---

## 📌 Executive Overview

Penetration testing and bug bounty recon are traditionally manual, labor-intensive workflows. Existing automated scanners (Burp Suite, Nikto) rely on rigid rule-based pattern matching, while chat-based LLM assistants lack autonomous execution loops.

**BugScout** bridges this gap as an **enterprise-grade autonomous multi-agent system** with a tight feedback loop:
$$\text{Dynamic Auth} \longrightarrow \text{Recon} \longrightarrow \text{Hypothesize} \longrightarrow \text{Test} \longrightarrow \text{Observe} \longrightarrow \text{Replan / Refine} \longrightarrow \text{Report (SARIF/HTML/JSON/MD)}$$

All outbound requests are strictly governed by **ScopeGuard** — a cross-cutting ethical firewall that enforces target boundaries, prevents SSRF against internal/private infrastructure, rate limits traffic, and contains an automated kill-switch.

---

## 🤖 Advanced Multi-Agent Architecture

```mermaid
flowchart TD
    User(["User / CI/CD / CLI"]) --> ScopeFile["Scope Config (scope.yaml)"]
    ScopeFile --> Auth["Dynamic Auth Manager\n(JWT, OAuth, Form Login)"]
    ScopeFile --> SG["ScopeGuard (Obfuscation Hardened)"]
    ScopeFile --> WAF["WAF & Adaptive Throttler\n(Cloudflare, AWS WAF, Akamai)"]

    subgraph Agentic_Pipeline["BugScout Enterprise Multi-Agent Pipeline"]
        Recon["1. ReconAgent\n• robots.txt & sitemaps\n• OpenAPI (JSON/YAML)\n• GraphQL Discovery\n• SPA Route Miner\n• Security Headers & CORS Audit"]
        Hypothesis["2. HypothesisAgent\n• Cognitive LLM Prompt-Chaining\n• Multi-Parameter Threat Modeling\n• Queue Prioritization"]
        Payload["3. PayloadAgent\n• Contextual Probe Crafting\n• 10+ Vulnerability Dictionaries\n• Auth Token & Cookie Replay\n• Rate-Limited Dispatch"]
        Observer["4. ObserverAgent\n• CORS Misconfig Detector\n• Security Header / Clickjacking Analyzer\n• GraphQL Schema Leaks\n• SQLi, XSS, IDOR, SSRF, Traversal\n• Agentic Replanning Controller"]
        Report["5. ReportAgent\n• CVSS 3.1 Base Scoring\n• Markdown (.md) Report\n• JSON (.json) API Export\n• Interactive HTML Dashboard\n• SARIF 2.1.0 Standard Export"]

        Recon -->|"EndpointMap + Headers + Specs"| Hypothesis
        Hypothesis -->|"Prioritized HypothesisQueue"| Payload
        Payload -->|"HTTP Probes"| SG
        SG -->|"Rate-Limited & Filtered"| Target[("Target Web App / API")]
        Target -->|"Responses"| Payload
        Payload -->|"TestResults"| Observer
        
        Observer -.->|"Secondary Hypotheses (Replanning)"| Hypothesis
        Observer -->|"Confirmed Findings"| Report
    end

    Report --> OutMD["outputs/VulnerabilityReport.md"]
    Report --> OutJSON["outputs/VulnerabilityReport.json"]
    Report --> OutHTML["outputs/VulnerabilityReport.html (Interactive Dashboard)"]
    Report --> OutSARIF["outputs/VulnerabilityReport.sarif (GitHub Code Scanning)"]
    Report --> RichUI["Rich Terminal Summary Table"]
```

### Agent Roster & Responsibilities

| Agent | Responsibility | Core Capabilities |
|---|---|---|
| **AuthManager** | Session Lifecycle | Pre-flight automated authentication (JWT, OAuth, Form login), token extraction from JSON payload, cookie capture, transparent re-authentication upon HTTP 401s. |
| **WAFDetector** | Politeness & Evasion | Fingerprints Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity; detects 429/403 rate limits and dynamically activates Polite Mode with exponential backoff & jitter. |
| **ReconAgent** | Attack Surface Discovery | Parses `robots.txt`, `sitemap.xml`, OpenAPI/Swagger specifications, discovers GraphQL endpoints, extracts SPA client routes (React/Vue), audits security headers (`X-Frame-Options`, `CSP`), fingerprints tech stack headers. |
| **HypothesisAgent** | Threat Modeling & Prioritization | Cognitive LLM reasoning (Groq / Gemini) analyzing parameter semantics (`id`, `search`, `url`, `role`, `file`), correlates with 10+ OWASP risk vectors, ranks test queue. |
| **PayloadAgent** | Safe Probe Execution | Selects non-destructive probes (`payloads/*.txt`), contextually mutates query params, JSON bodies, and headers, replays session cookies, routes all requests through `ScopeGuard`. |
| **ObserverAgent** | Anomaly Detection & Replanning | Detects CORS misconfigurations, missing security headers / clickjacking exposure, GraphQL schema leaks, open redirects, path traversals, SQLi database error patterns, unescaped XSS reflections, and IDOR differentials. Triggers secondary feedback cycles. |
| **ReportAgent** | Intelligence Synthesis | Calculates CVSS 3.1 base scores & vector strings, generates step-by-step reproduction instructions, raw evidence snippets, remediation code, and outputs **SARIF 2.1.0**, **Interactive HTML Dashboards**, Markdown, and JSON. |
| **ScopeGuard** | Ethical Firewall & Safety Layer | Hard blocks out-of-scope hosts, path wildcards, private IP ranges (RFC 1918, link-local, cloud metadata `169.254.169.254`), normalizes Unicode NFKC, null-bytes (`%00`), double-encoding, enforces token-bucket rate limiting, and triggers a kill-switch on consecutive violations. |

---

## 🎯 Supported Vulnerability Classes (10+ Vectors)

1. **SQL Injection (SQLi)**: Error-based and time-based boolean anomaly detection across MySQL, SQLite, PostgreSQL, MSSQL, Oracle.
2. **Reflected Cross-Site Scripting (XSS)**: Unescaped HTML/DOM reflection marker tracking.
3. **CORS Misconfiguration**: Arbitrary untrusted origin reflection combined with `Access-Control-Allow-Credentials: true`.
4. **Missing Critical Security Headers / Clickjacking**: Missing `X-Frame-Options` and `Content-Security-Policy: frame-ancestors`.
5. **GraphQL Schema Introspection**: Disclosed `__schema` definitions leaking backend queries, types, and fields.
6. **Insecure Direct Object Reference (IDOR)**: Differential object identifier data exposure without session authorization.
7. **Open URL Redirection**: Unvalidated external domain redirection via HTTP 301/302 `Location` headers.
8. **Path / Directory Traversal**: Local file inclusion sequences targeting system configuration files.
9. **Exposed Environment & Secret Credentials**: Publicly accessible `.env`, API keys, database credentials, JWT secrets.
10. **Broken Authentication on Privileged Routes**: Administrative routes accessible without valid authentication tokens.

---

## ⚡ Zero-Cost LLM Engine

BugScout operates with **zero paid API dependencies**. The modular LLM engine (`core/llm.py`) supports:

1. **Groq Cloud API** (`GROQ_API_KEY`): Ultra-fast inference with `qwen/qwen3.8-27b`, `openai/gpt-oss-120b`, or `llama-3.3-70b-versatile`.
2. **Google Gemini Free Tier** (`GEMINI_API_KEY`): Generative reasoning via `gemini-2.5-flash`.
3. **Hugging Face Free Inference API** (`HF_TOKEN`): Serverless open-source models.
4. **Local Ollama** (`OLLAMA_HOST`): Run local models like `llama3` or `qwen2.5-coder`.
5. **Built-in Offline Security Intelligence Engine**: Deterministic OWASP correlation rules (100% offline, zero latency, zero setup).

---

## 🚀 Quickstart & Installation

### 1. Prerequisites & Virtual Environment Setup
Ensure you have Python 3.11+ installed.

```bash
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
```

### 2. Configure Environment (Optional for Cloud LLMs)
Create a `.env` file from `.env.example`:
```bash
GROQ_API_KEY=your_groq_key_here
```

### 3. Run Built-in Live Demo (One-Click)
BugScout includes a self-contained deliberately vulnerable test target (`mock_target/server.py`):

```bash
python main.py --demo
```

### 4. Resume an Interrupted Scan
```bash
python main.py --demo --resume
```

---

## 🐳 Docker & Containerization

Run BugScout in an isolated container environment using Docker Compose:

```bash
# Build and run both mock target and autonomous scout
docker-compose up --build
```

---

## 📊 Comprehensive Reporting Suite

BugScout generates 4 synchronized report formats in `outputs/`:
- **`VulnerabilityReport.sarif`**: Standard OASIS SARIF v2.1.0 format. Upload directly to GitHub Security tab, GitLab, Jira, or DefectDojo.
- **`VulnerabilityReport.html`**: Standalone interactive dashboard with Chart.js analytics, real-time search, severity filters, and one-click copyable `curl` commands.
- **`VulnerabilityReport.md`**: Professional Markdown report with CVSS breakdown, reproduction steps, technical evidence, and code remediation.
- **`VulnerabilityReport.json`**: Machine-readable full scan metadata, discovered endpoints, and findings.

---

## 🧪 Testing & Verification

Run the comprehensive unit, edge-case, and integration test suite:

```bash
pytest -v
```

Test coverage includes:
- `tests/test_sarif.py`: Validates SARIF 2.1.0 JSON schema and GitHub Code Scanning compatibility.
- `tests/test_checkpoint.py`: Validates atomic state persistence and scan resume (`--resume`).
- `tests/test_auth_manager.py`: Tests automated pre-flight login and JWT token extraction.
- `tests/test_waf_detector.py`: Tests WAF fingerprinting (Cloudflare/AWS) and adaptive rate limit throttling.
- `tests/test_scope_guard_hardening.py`: Tests Unicode NFKC normalization, null-byte stripping, and double-decode traversal hardening.
- `tests/test_scope_guard.py`: Scope matching, path prefix wildcards, private IP blocks, metadata protection, payload validation, and kill-switch.
- `tests/test_recon.py`: Endpoint registration, sitemap/robots parsing, SPA client routing, and JavaScript regex endpoint extraction.
- `tests/test_observer.py`: CORS misconfig, missing headers, GraphQL introspection, Open Redirect, Path Traversal, SQLi, XSS, and credential leaks.
- `tests/test_llm.py`: Tests offline heuristic engine and live Groq LLM integration.
- `tests/test_full_pipeline.py`: End-to-end multi-agent execution against the mock target.

---

## ⚖️ Ethical & Legal Compliance

> [!CAUTION]
> **Authorized Testing Only:** BugScout is engineered strictly for authorized security assessments, CTF challenges, developer self-assessments, and bug bounty programs with explicit written scope authorization.

- **Non-Destructive Probes Only:** BugScout does not execute destructive queries (`DROP`, `DELETE`, `TRUNCATE`), denial-of-service payloads, or password spraying attacks.
- **SSRF Safeguard:** Outbound probes to internal IP ranges (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, `127.0.0.0/8`, `169.254.169.254`) are hard-blocked by default.
- **Scope Integrity:** Any request outside `allowed_hosts` or `allowed_paths` is intercepted before touching the network.
