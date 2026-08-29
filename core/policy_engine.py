from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.mission_context import Hypothesis, Endpoint, VulnClass

logger = logging.getLogger("BugScout.PolicyEngine")


class PolicyEngine:
    """
    Deterministic Policy & Probe Orchestrator Engine (Phase 2).
    Sits between Threat Reasoning Agent and ScopeGuard to:
    1. Rank and prioritize candidate hypotheses by risk score
    2. Enforce per-endpoint adaptive probe budgets based on semantic risk tier
    3. Prune redundant duplicate probe plans
    4. Enforce global request budget limits and early-stopping criteria
    """

    HIGH_RISK_KEYWORDS = [
        "id", "user", "order", "account", "profile", "admin", "file", "path",
        "doc", "url", "redirect", "dest", "next", "search", "query", "q", "filter", "key"
    ]

    def __init__(self, max_global_probes: int = 200):
        self.max_global_probes = max_global_probes
        self.allocated_probes_per_endpoint: Dict[str, int] = {}

    def calculate_endpoint_risk_tier(self, endpoint: Endpoint) -> str:
        """Categorize endpoint risk as HIGH, MEDIUM, or LOW."""
        params = [p.lower() for p in (endpoint.query_params + endpoint.body_params)]
        path_lower = endpoint.path.lower()

        # Check for high risk keywords in path or params
        for kw in self.HIGH_RISK_KEYWORDS:
            if kw in path_lower or any(kw in p for p in params):
                return "HIGH"

        if endpoint.method.upper() in ["POST", "PUT", "DELETE"]:
            return "MEDIUM"

        return "LOW"

    def get_max_probes_for_tier(self, tier: str) -> int:
        if tier == "HIGH":
            return 8
        elif tier == "MEDIUM":
            return 4
        return 2

    def filter_and_prioritize_hypotheses(
        self,
        hypotheses: List[Hypothesis],
        endpoint_map: Dict[str, Endpoint],
        budget_override: Optional[int] = None
    ) -> List[Hypothesis]:
        """
        Filters and prioritizes hypotheses according to risk tier and probe budget.
        """
        budget_limit = budget_override or self.max_global_probes
        prioritized_queue: List[Hypothesis] = []
        seen_probe_keys = set()
        endpoint_counts: Dict[str, int] = {}

        # 1. Sort hypotheses by confidence descending
        sorted_hypotheses = sorted(
            hypotheses,
            key=lambda h: (1 if h.target_param in self.HIGH_RISK_KEYWORDS else 0, h.rationale),
            reverse=True
        )

        # 2. Apply per-endpoint budget ceilings
        for h in sorted_hypotheses:
            if len(prioritized_queue) >= budget_limit:
                logger.info(f"PolicyEngine reached global probe budget limit ({budget_limit}). Stopping queue.")
                break

            ep = endpoint_map.get(h.endpoint_id)
            tier = self.calculate_endpoint_risk_tier(ep) if ep else "MEDIUM"
            max_for_ep = self.get_max_probes_for_tier(tier)

            current_count = endpoint_counts.get(h.endpoint_id, 0)
            if current_count >= max_for_ep:
                continue

            # Deduplicate by (endpoint_id, param, vuln_class)
            probe_key = (h.endpoint_id, h.target_param, h.vuln_class)
            if probe_key in seen_probe_keys:
                continue

            seen_probe_keys.add(probe_key)
            endpoint_counts[h.endpoint_id] = current_count + 1
            prioritized_queue.append(h)

        return prioritized_queue
