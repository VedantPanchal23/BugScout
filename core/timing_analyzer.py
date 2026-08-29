from __future__ import annotations

import math
import statistics
from typing import List, Dict, Any, Tuple


class StatisticalTimingAnalyzer:
    """
    Statistical Timing Distribution Analyzer for Time-Based Blind SQLi & ReDoS.
    Uses multi-sample baseline estimation and z-score / t-threshold diffing to
    accurately distinguish genuine server-side timing delays from network jitter.
    """

    def __init__(self, delay_threshold_seconds: float = 2.0, min_z_score: float = 3.0):
        self.delay_threshold = delay_threshold_seconds
        self.min_z_score = min_z_score

    def analyze_timing_anomaly(
        self,
        baseline_durations: List[float],
        probe_duration: float
    ) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Calculates whether a probe duration is a statistically significant timing delay
        compared to the baseline response time distribution.
        """
        if not baseline_durations:
            baseline_durations = [0.05, 0.06, 0.05]

        mean_baseline = statistics.mean(baseline_durations)
        std_baseline = statistics.stdev(baseline_durations) if len(baseline_durations) > 1 else 0.02
        # Floor standard deviation to prevent division by zero in clean local environments
        effective_std = max(std_baseline, 0.015)

        time_delta = probe_duration - mean_baseline
        z_score = (probe_duration - mean_baseline) / effective_std

        # Condition: Probe exceeds baseline by threshold AND exceeds 3 sigma (z-score >= 3.0)
        is_delayed = (time_delta >= self.delay_threshold * 0.75) and (z_score >= self.min_z_score)

        details = {
            "mean_baseline_seconds": round(mean_baseline, 3),
            "baseline_std_seconds": round(effective_std, 3),
            "probe_duration_seconds": round(probe_duration, 3),
            "time_delta_seconds": round(time_delta, 3),
            "z_score": round(z_score, 2),
            "is_statistically_delayed": is_delayed
        }

        confidence = min(1.0, max(0.0, (z_score / 5.0))) if is_delayed else 0.0
        return is_delayed, confidence, details
