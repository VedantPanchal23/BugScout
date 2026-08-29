# Security & Access — Autonomous Bug Bounty Scout

## Ethical Use Policy
This tool is built exclusively for authorized security testing. Use is permitted only against:
- Applications you own or have deployed yourself
- CTF (Capture The Flag) challenge targets
- Bug bounty program targets where the target URL is explicitly listed in-scope by the program
- Staging/development environments with explicit written permission from the system owner

**Any use against systems without explicit authorization is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, India's IT Act Section 66, and equivalent laws in most jurisdictions. The authors accept zero liability for unauthorized use.**

---

## ScopeGuard — Technical Enforcement

### Scope Definition
Before any agent executes, the user must provide a `scope.yaml` file:

```yaml
target: "https://juice-shop.example.com"
allowed_hosts:
  - "juice-shop.example.com"
allowed_paths:
  - "/api/*"
  - "/rest/*"
  - "/login"
excluded_test_types:
  - "brute_force"
  - "dos"
max_requests_per_minute: 30
max_total_requests: 500
```

No defaults are permissive. If `scope.yaml` is missing or malformed, the pipeline does not start.

### Enforcement Rules
- Every URL constructed by any agent is validated against `allowed_hosts` and `allowed_paths` before the request fires
- Wildcard matching is exact-prefix only — `/api/*` does not match `/api-internal/`
- Any request to an IP address (not hostname) is blocked by default
- Requests to private IP ranges (10.x, 192.168.x, 172.16–31.x, 127.x) are hard-blocked regardless of scope definition — this prevents SSRF against internal infrastructure during testing
- If ScopeGuard blocks 10 consecutive requests, the pipeline halts and prints a scope violation summary before exiting

### Blocked Payload Classes (always off, not configurable)
- Credential brute-forcing / password spraying
- Denial-of-service payloads
- Payloads targeting third-party services (CDNs, auth providers, payment processors)
- File upload payloads that attempt remote code execution on the host running the agent

---

## Rate Limiting
The agent enforces its own request rate limit (configurable in `scope.yaml`, default 30 req/min). This prevents:
- Accidental DoS on low-capacity targets
- Triggering WAF bans that invalidate the rest of the test run
- Behavior that looks indistinguishable from a real attack to monitoring systems

---

## Data Handling
- All test payloads, responses, and findings are stored locally only
- No data is sent to any external service except the target itself and the LLM backend
- If using a cloud LLM API, response bodies sent for analysis should be truncated to avoid leaking sensitive target data into third-party systems
- Outputs directory should be treated as sensitive — add `outputs/` to `.gitignore` before pushing to any public repo

---

## Responsible Disclosure
If this tool discovers a real vulnerability in a bug bounty target:
1. Stop further testing on that vulnerability class immediately
2. Document the finding using the generated report
3. Submit via the program's official disclosure channel
4. Do not share, publish, or discuss the finding publicly until the program confirms resolution or the disclosure deadline passes

---

## .gitignore Minimum (security-relevant)
outputs/
config/scope.yaml
*.log
.env


---

## Legal Reference by Region
| Region | Relevant Law |
|---|---|
| India | IT Act 2000, Section 66 — unauthorized computer access |
| USA | Computer Fraud and Abuse Act (CFAA) |
| EU | Directive on Attacks Against Information Systems (2013/40/EU) |
| UK | Computer Misuse Act 1990 |

When in doubt: if you do not have written permission, do not run the tool against that target.