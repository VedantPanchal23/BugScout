from __future__ import annotations

from typing import List, Dict, Set
from agents.base_agent import BaseAgent
from core.mission_context import Finding, EvidenceLevel, Confidence, VulnClass


class ValidationAgent(BaseAgent):
    """
    Deterministic Verification & Finding Graduation Layer.
    Sits between the Observation Agent and the Reporting Agent.
    Evaluates evidence quality (Evidence Levels 0-4), rejects false alarms/hallucinations,
    enforces canonical deduplication, and attaches explainability rationale.
    """

    def __init__(self, name: str, context, scope_guard=None, llm=None):
        super().__init__(name, context, scope_guard, llm)

    async def run(self) -> List[Finding]:
        self.log(f"Starting deterministic evidence validation on candidate findings (Iteration {self.context.current_iteration})...")
        raw_findings = list(self.context.findings)
        validated_findings: List[Finding] = []
        seen_keys: Set[str] = set()

        for f in raw_findings:
            dedup_key = f"{f.vuln_class.value}:{f.affected_endpoint}:{f.parameter or 'none'}"
            if dedup_key in seen_keys:
                self.context.record_audit(
                    agent="ValidationAgent",
                    action="Deduplicate",
                    target=f.affected_endpoint,
                    decision="SKIP",
                    reason=f"Duplicate finding already registered for key '{dedup_key}'."
                )
                continue

            # Deterministic Evidence Quality Filter
            # Only Level 3 (Strong Indicator) and Level 4 (Validated Proof) graduate into confirmed findings
            if f.evidence_level in [EvidenceLevel.LEVEL_3_STRONG, EvidenceLevel.LEVEL_4_VALIDATED]:
                # Assign explainability rationale if not already populated
                if not f.why_tested:
                    f.why_tested = self._derive_why_tested(f)
                if not f.why_reported:
                    f.why_reported = self._derive_why_reported(f)

                seen_keys.add(dedup_key)
                validated_findings.append(f)

                self.context.record_audit(
                    agent="ValidationAgent",
                    action="Validate Finding",
                    target=f.affected_endpoint,
                    decision="CONFIRMED",
                    reason=f"Evidence Level {f.evidence_level.value} met threshold ({f.evidence_level.name}).",
                    evidence_level=f.evidence_level.value
                )
            else:
                self.context.record_audit(
                    agent="ValidationAgent",
                    action="Reject Finding",
                    target=f.affected_endpoint,
                    decision="REJECTED",
                    reason=f"Evidence Level {f.evidence_level.value} ({f.evidence_level.name}) below Level 3 validation threshold.",
                    evidence_level=f.evidence_level.value
                )

        self.context.findings = validated_findings
        self.log(f"Validation complete: {len(validated_findings)} verified findings graduated to canonical reporting model.")
        return validated_findings

    def _derive_why_tested(self, f: Finding) -> str:
        param_desc = f"parameter '{f.parameter}'" if f.parameter else "the endpoint structure"
        return f"Threat reasoning agent prioritized {f.vuln_class.value} testing on {param_desc} due to semantic keyword matches and input vector surface."

    def _derive_why_reported(self, f: Finding) -> str:
        return f"Deterministic observation confirmed anomalous behavioral evidence matching {f.cwe_id} signature (Evidence Level {f.evidence_level.value})."
