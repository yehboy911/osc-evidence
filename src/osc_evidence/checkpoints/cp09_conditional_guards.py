"""CP09 — Conditional Build Guards"""

from __future__ import annotations

from typing import List

from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, MANUAL, PASS


class CP09ConditionalGuards(CheckpointBase):
    checkpoint_id = "CP09"
    name = "Conditional Build Guards"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        subdirs = self._findings_for(pr, "add_subdirectory")
        if not subdirs:
            return self._na("No add_subdirectory() calls found.")

        guarded: List[Evidence] = []
        core_unguarded: List[Evidence] = []
        risky_unguarded: List[Evidence] = []

        for f in subdirs:
            is_test_or_tp = f.subtype in ("test_dir", "third_party_dir")

            if not f.is_unconditional():
                stack_summary = " > ".join(
                    f"{fr.branch}({fr.condition})" for fr in f.condition_stack
                )
                guarded.append(self._to_evidence(
                    f, f"Guarded by: {stack_summary}"
                ))
            elif is_test_or_tp:
                # Unconditional test or third-party subdirectory — needs review
                kind = "test" if f.subtype == "test_dir" else "third-party"
                risky_unguarded.append(self._to_evidence(
                    f, f"Unconditional {kind} subdirectory — verify this directory is not GPL-licensed or should be optional"
                ))
            else:
                # Core subdirectory unconditional — expected and fine
                core_unguarded.append(self._to_evidence(
                    f, "Core subdirectory included unconditionally — expected"
                ))

        if not risky_unguarded:
            return self._pass(
                "All test and third-party subdirectories are inside conditional blocks",
                evidence=guarded + core_unguarded,
            )
        if guarded or core_unguarded:
            return self._manual(
                "Some test or third-party subdirectories are included unconditionally — review required",
                evidence=guarded + core_unguarded + risky_unguarded,
                notes=[
                    "Unconditional test/third-party subdirectories are always compiled in",
                    "Verify none of these directories contain GPL-only components",
                    "Consider guarding with: option(BUILD_TESTING \"\" OFF) / if(BUILD_TESTING)",
                ],
            )
        return self._manual(
            "All test/third-party add_subdirectory() calls are unconditional — verify each directory's license",
            evidence=risky_unguarded,
            notes=["Guard optional/third-party subdirectories with if() checks"],
        )
