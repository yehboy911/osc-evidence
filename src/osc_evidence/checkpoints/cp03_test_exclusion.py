"""CP03 — Test Suite Exclusion"""

from __future__ import annotations
from typing import List
from ..cmake_parser import ParseResult, RawFinding
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, MANUAL


class CP03TestExclusion(CheckpointBase):
    checkpoint_id = "CP03"
    name = "Test Suite Exclusion"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        test_subdirs = [
            f for f in self._findings_for(pr, "add_subdirectory")
            if f.subtype == "test_dir"
        ]
        test_targets = [t for t in pr.targets if t.is_test]

        if not test_subdirs and not test_targets:
            return self._na("No test directories or test targets detected.")

        guarded: List[Evidence] = []
        unguarded: List[Evidence] = []

        for f in test_subdirs:
            has_excl = "EXCLUDE_FROM_ALL" in f.args_text.upper()
            guarded_cond = f.is_guarded_by("BUILD_TESTING") or f.is_guarded_by("ENABLE_TESTING")
            if has_excl or guarded_cond:
                note = (
                    "Test directory guarded by EXCLUDE_FROM_ALL"
                    if has_excl
                    else f"Test directory inside if({f.condition_stack[-1].condition if f.condition_stack else '?'})"
                )
                guarded.append(self._to_evidence(f, note))
            else:
                unguarded.append(self._to_evidence(
                    f, "Test directory included unconditionally — not guarded by BUILD_TESTING"
                ))

        for t in test_targets:
            if t.exclude_from_all:
                guarded.append(Evidence(
                    snippet=f"add_{'library' if t.target_type != 'EXECUTABLE' else 'executable'}({t.name} ... EXCLUDE_FROM_ALL ...)",
                    line_no=t.line_no, file=t.file,
                    note=f"Test target '{t.name}' has EXCLUDE_FROM_ALL",
                ))
            else:
                unguarded.append(Evidence(
                    snippet=f"{t.name} [{t.target_type}]",
                    line_no=t.line_no, file=t.file,
                    note=f"Test target '{t.name}' not excluded from default build",
                ))

        if not unguarded:
            return self._pass(
                "All test directories and targets are guarded or excluded from default install",
                evidence=guarded,
            )
        return self._manual(
            "Some test directories are included unconditionally — verify they are not installed",
            evidence=guarded + unguarded,
            notes=[
                "Wrap test subdirectory inclusions with: if(BUILD_TESTING) ... endif()",
                "Or add EXCLUDE_FROM_ALL to add_subdirectory(tests EXCLUDE_FROM_ALL)",
            ],
        )
