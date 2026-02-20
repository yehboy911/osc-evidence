"""CP08 — Source-to-Target Traceability"""

from __future__ import annotations
from typing import List, Set
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, MANUAL


class CP08SourceTraceability(CheckpointBase):
    checkpoint_id = "CP08"
    name = "Source-to-Target Traceability"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        target_sources_findings = self._findings_for(pr, "target_sources")

        # Targets that have explicit target_sources() calls
        traced_targets: Set[str] = set()
        evidence: List[Evidence] = []

        for f in target_sources_findings:
            parts = f.args_text.split()
            if parts:
                traced_targets.add(parts[0])
            evidence.append(self._to_evidence(
                f, "Source files explicitly mapped to target"
            ))

        # Count targets that lack explicit source mapping
        no_trace: List[Evidence] = []
        for t in pr.targets:
            if t.target_type in ("INTERFACE", "CUSTOM"):
                continue
            if t.name not in traced_targets:
                no_trace.append(Evidence(
                    snippet=f"add_library/executable({t.name} {t.target_type} ...)",
                    line_no=t.line_no, file=t.file,
                    note=f"Target '{t.name}' has no explicit target_sources() — sources inlined in add_library/executable",
                ))

        if not evidence and not no_trace:
            return self._na("No targets found to assess source traceability.")

        if evidence and not no_trace:
            return self._pass(
                "All targets have explicit target_sources() mappings — clear source traceability",
                evidence=evidence,
            )

        if not evidence:
            return self._manual(
                "No target_sources() calls found — source-to-target mapping relies on inline argument lists",
                evidence=no_trace,
                notes=[
                    "Consider using target_sources() for explicit source mapping",
                    "Inline source lists in add_library/add_executable are acceptable but harder to audit",
                ],
            )

        return self._pass(
            "Most targets use target_sources() — source traceability is adequate",
            evidence=evidence,
        )
