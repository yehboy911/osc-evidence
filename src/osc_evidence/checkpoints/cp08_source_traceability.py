"""CP08 — Source-to-Target Traceability"""

from __future__ import annotations

from typing import List, Set

from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, MANUAL, PASS


class CP08SourceTraceability(CheckpointBase):
    checkpoint_id = "CP08"
    name = "Source-to-Target Traceability"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        target_sources_findings = self._findings_for(pr, "target_sources")

        # Targets that have explicit target_sources() calls
        traced_targets: Set[str] = set()
        ts_evidence: List[Evidence] = []

        for f in target_sources_findings:
            parts = f.args_text.split()
            if parts:
                traced_targets.add(parts[0])
            ts_evidence.append(self._to_evidence(
                f, "Source files explicitly mapped to target via target_sources()"
            ))

        # Assess remaining targets
        inline_evidence: List[Evidence] = []
        no_trace: List[Evidence] = []

        for t in pr.targets:
            if t.target_type in ("INTERFACE", "CUSTOM"):
                continue
            if t.name in traced_targets:
                continue
            if t.source_files:
                # Inline sources in add_library/add_executable — traceability exists
                src_list = ", ".join(t.source_files[:5])
                if len(t.source_files) > 5:
                    src_list += f", … (+{len(t.source_files) - 5} more)"
                inline_evidence.append(Evidence(
                    snippet=f"add_library/executable({t.name} {t.target_type} {' '.join(t.source_files[:3])} ...)",
                    line_no=t.line_no, file=t.file,
                    note=f"Target '{t.name}' has {len(t.source_files)} inline source(s): {src_list}",
                ))
            else:
                no_trace.append(Evidence(
                    snippet=f"add_library/executable({t.name} {t.target_type} ...)",
                    line_no=t.line_no, file=t.file,
                    note=f"Target '{t.name}' has no visible sources — may use set_target_properties or generator expressions",
                ))

        all_evidence = ts_evidence + inline_evidence

        if not all_evidence and not no_trace:
            return self._na("No targets found to assess source traceability.")

        if not no_trace:
            return self._pass(
                "All targets have traceable source files (via target_sources() or inline args)",
                evidence=all_evidence,
            )

        if not all_evidence:
            return self._manual(
                "No source files visible for any target — source-to-target mapping cannot be confirmed",
                evidence=no_trace,
                notes=[
                    "Use target_sources() or list source files inline in add_library/add_executable",
                    "Generator expressions (e.g. $<TARGET_OBJECTS:...>) cannot be statically resolved",
                ],
            )

        return self._pass(
            "Most targets have traceable sources; some targets use generator expressions or external sources",
            evidence=all_evidence + no_trace,
        )
