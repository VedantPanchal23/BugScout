# BugScout - Academic Reproducibility Guide

## 1. Quick Reproduction Steps

### Environment Setup
```bash
git clone https://github.com/VedantPanchal23/BugScout.git
cd BugScout
python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows:
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### Automated Verification
```bash
# 1. Run full unit, integration, and security regression test suite (42 tests)
pytest -v

# 2. Run Ground-Truth Primary Benchmark (46 cases)
python main.py --evaluate

# 3. Run A/B Single-Pass Baseline Comparison (-64.25% traffic reduction)
python main.py --compare-modes

# 4. Run Pareto Frontier Optimization Analysis
python main.py --budget-curve

# 5. Run 4-Tier Component Ablation Study
python main.py --ablation

# 6. Run 5-Run Statistical Stability Evaluation
python main.py --repeated-eval

# 7. Run Zero-Shot Hidden Generalization Benchmark
python main.py --hidden-eval

# 8. Run ScopeGuard Ethical Firewall Safety Suite (16 attack vectors)
python main.py --safety-test
```

---

## 2. Artifacts & Outputs

All evaluation commands generate structured JSON, Markdown, HTML, and SARIF artifacts in `outputs/`:
- `VulnerabilityReport.sarif`: OASIS SARIF 2.1.0 standard log.
- `VulnerabilityReport.html`: Interactive dashboard with XSS-sanitized findings.
- `VulnerabilityReport.md`: Markdown summary.
- `VulnerabilityReport.json`: Canonical findings export.
- `ReproducibilityManifest.json`: Cryptographic manifest containing SHA-256 ground truth hashes and environment metadata.
