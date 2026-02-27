"""CP03 — Test Suite Exclusion"""

from __future__ import annotations

from typing import List, Optional

from ..cmake_parser import ParseResult, RawFinding
from .base import CheckpointBase, CheckpointResult, Evidence, MANUAL, PASS


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

        # Query the default value of BUILD_TESTING from the symbol table
        bt_default: Optional[str] = pr.symbols.get("BUILD_TESTING")

        guarded: List[Evidence] = []
        unguarded: List[Evidence] = []

        for f in test_subdirs:
            has_excl = "EXCLUDE_FROM_ALL" in f.args_text.upper()
            guarded_by_bt = f.is_guarded_by("BUILD_TESTING")
            guarded_by_et = f.is_guarded_by("ENABLE_TESTING")

            if has_excl:
                guarded.append(self._to_evidence(
                    f, "Test directory guarded by EXCLUDE_FROM_ALL"
                ))
            elif guarded_by_bt:
                # Guard quality depends on the default value
                if bt_default and bt_default.upper() == "OFF":
                    guarded.append(self._to_evidence(
                        f, f"Test directory inside if(BUILD_TESTING) — BUILD_TESTING defaults to OFF"
                    ))
                else:
                    default_note = f" (defaults to {bt_default})" if bt_default else " (default not found — may be ON)"
                    unguarded.append(self._to_evidence(
                        f, f"Test directory guarded by BUILD_TESTING{default_note} — may be included by default"
                    ))
            elif guarded_by_et:
                guarded.append(self._to_evidence(
                    f, f"Test directory inside if({f.condition_stack[-1].condition if f.condition_stack else 'ENABLE_TESTING'})"
                ))
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
                "Wrap test subdirectory inclusions with: option(BUILD_TESTING \"\" OFF) / if(BUILD_TESTING)",
                "Or add EXCLUDE_FROM_ALL to add_subdirectory(tests EXCLUDE_FROM_ALL)",
            ],
        )
