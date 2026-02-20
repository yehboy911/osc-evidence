"""CP09 — Conditional Build Guards"""

from __future__ import annotations
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, MANUAL


class CP09ConditionalGuards(CheckpointBase):
    checkpoint_id = "CP09"
    name = "Conditional Build Guards"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        subdirs = self._findings_for(pr, "add_subdirectory")
        if not subdirs:
            return self._na("No add_subdirectory() calls found.")

        guarded: List[Evidence] = []
        unguarded: List[Evidence] = []

        for f in subdirs:
            if f.is_unconditional():
                unguarded.append(self._to_evidence(
                    f, "add_subdirectory called unconditionally — always included"
                ))
            else:
                stack_summary = " > ".join(
                    f"{fr.branch}({fr.condition})" for fr in f.condition_stack
                )
                guarded.append(self._to_evidence(
                    f, f"Guarded by: {stack_summary}"
                ))

        if not unguarded:
            return self._pass(
                "All add_subdirectory() calls are inside conditional blocks",
                evidence=guarded,
            )
        if guarded:
            return self._manual(
                "Mix of conditional and unconditional add_subdirectory() calls — review unguarded includes",
                evidence=guarded + unguarded,
                notes=["Unguarded subdirectories are always compiled in — verify none are GPL-only"],
            )
        return self._manual(
            "All add_subdirectory() calls are unconditional — verify each directory's license",
            evidence=unguarded,
            notes=["Consider guarding optional/third-party subdirectories with if() checks"],
        )
