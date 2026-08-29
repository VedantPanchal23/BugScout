# BugScout - Experiment Integrity & Benchmark Accounting Report

## 1. Experimental Design & Traffic Disambiguation

### Disambiguation of Request Counts
During evaluation, BugScout records distinct request counts depending on the experimental protocol:
- **A/B Baseline Single-Pass Experiment**: **153 HTTP requests** (single-iteration scan on 46 cases).
- **Full Autonomous Benchmark Run**: **308 HTTP requests** (2-iteration recursive replanning mission with deep reconnaissance and verification passes).
- **Repeated Stability Evaluation (5 Runs)**: **1,540 total HTTP requests** (5 consecutive runs of 308 requests each).

### Blind Baseline Definition
The "Blind Baseline" is a deterministic, heuristic crawler and fuzzer that systematically probes every identified query and form parameter with standard security payloads without semantic threat modeling or risk tiering. It sends 428 requests on the same 46 ground-truth cases.

---

## 2. Confusion Matrix & Detection Metrics

### Primary 46-Case Ground Truth Benchmark (`primary_46_case_benchmark`)
- **Total Seeded Cases**: 46
  - **Positive (Vulnerable) Instances**: 27
  - **Negative (Decoy / Non-Vulnerable) Instances**: 19
- **True Positives (TP)**: 19
- **True Negatives (TN)**: 18
- **False Positives (FP)**: 1 (Deceptive redirect decoy)
- **False Negatives (FN)**: 8

```text
Precision   = TP / (TP + FP) = 19 / (19 + 1) = 95.00%
Recall      = TP / (TP + FN) = 19 / (19 + 8) = 70.37%
F1 Score    = 2 * (P * R) / (P + R)          = 80.85%
Specificity = TN / (TN + FP) = 18 / (18 + 1) = 94.74%
```

### A/B Baseline Comparison Metrics (Single-Pass)
- **Baseline**: 428 requests, 22/27 vulnerabilities detected (81.48% recall, 88.00% precision, 3.18s latency).
- **BugScout**: 153 requests, 19/27 vulnerabilities detected (70.37% recall, 95.00% precision, 1.96s latency).
- **Traffic Reduction**: `-64.25%` (275 requests saved).
- **Detection Yield**: `12.42` vs. `5.14` vulnerabilities / 100 requests (**2.42x higher yield per request**).
- **Empirical Cost-Recall Trade-off**: BugScout reduces outbound traffic by 64.25% with a modest trade-off of -11.11 percentage points recall (70.37% vs. 81.48%).

---

## 3. Statistical Stability Evaluation (5 Runs)

| Run Index | Precision (%) | Recall (%) | F1 Score (%) | Outbound Requests | Latency (s) |
|:---:|:---:|:---:|:---:|:---:|:---:|
| Run #1 | 95.00% | 70.37% | 80.85% | 308 | 0.84s |
| Run #2 | 95.00% | 70.37% | 80.85% | 308 | 0.91s |
| Run #3 | 95.00% | 70.37% | 80.85% | 308 | 0.88s |
| Run #4 | 95.00% | 70.37% | 80.85% | 308 | 0.95s |
| Run #5 | 95.00% | 70.37% | 80.85% | 308 | 0.86s |

**Distribution**:
- **Precision**: `95.00% +/- 0.00%` (Zero classification variance under deterministic inference)
- **Recall**: `70.37% +/- 0.00%` (Zero classification variance under deterministic inference)
- **F1 Score**: `80.85% +/- 0.00%`
- **Requests**: `308.00 +/- 0.00 requests`
- **Latency**: `0.89s +/- 0.06s` (I/O latency variation)

---

## 4. Preliminary Zero-Shot Hidden Evaluation (`hidden_generalization_benchmark`)
- **Total Ephemeral Cases**: 6 (4 Vulnerable Instances, 2 Negative Decoys)
- **Endpoints Discovered**: 8
- **True Positives (TP)**: 3
- **True Negatives (TN)**: 2
- **False Positives (FP)**: 0
- **False Negatives (FN)**: 1
- **Zero-Shot Precision**: `100.00%`
- **Zero-Shot Recall**: `75.00%`
- **Zero-Shot Specificity**: `100.00%`
