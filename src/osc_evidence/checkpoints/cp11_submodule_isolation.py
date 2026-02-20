"""CP11 — Third-Party Submodule Isolation"""

from __future__ import annotations
import re
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, MANUAL

_THIRD_PARTY = re.compile(
    r"(third.?party|vendor|extern(?:al)?|deps?|thirdparty|3rdparty)",
    re.IGNORECASE,
)


class CP11SubmoduleIsolation(CheckpointBase):
    checkpoint_id = "CP11"
    name = "Third-Party Submodule Isolation"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        third_party_subdirs = [
            f for f in self._findings_for(pr, "add_subdirectory")
            if f.subtype == "third_party_dir" or _THIRD_PARTY.search(f.args_text)
        ]

        if not third_party_subdirs:
            return self._na("No third-party subdirectory inclusions detected.")

        isolated: List[Evidence] = []
        not_isolated: List[Evidence] = []

        for f in third_party_subdirs:
            has_excl = "EXCLUDE_FROM_ALL" in f.args_text.upper()
            guarded = f.is_guarded_by("VENDOR") or f.is_guarded_by("USE_SYSTEM") or \
                      f.is_guarded_by("ENABLE") or f.is_guarded_by("WITH_") or \
                      (len(f.condition_stack) > 0)
            if has_excl:
                isolated.append(self._to_evidence(
                    f, "Third-party directory uses EXCLUDE_FROM_ALL — isolated from default build"
                ))
            elif guarded:
                stack_summary = " > ".join(
                    f"{fr.branch}({fr.condition})" for fr in f.condition_stack
                )
                isolated.append(self._to_evidence(
                    f, f"Third-party directory is conditional: {stack_summary}"
                ))
            else:
                not_isolated.append(self._to_evidence(
                    f, "Third-party directory included unconditionally without EXCLUDE_FROM_ALL"
                ))

        if not not_isolated:
            return self._pass(
                "All third-party subdirectories are isolated (EXCLUDE_FROM_ALL or conditional)",
                evidence=isolated,
            )
        return self._manual(
            "Some third-party directories lack isolation — verify licenses of unconditionally included components",
            evidence=isolated + not_isolated,
            notes=[
                "Use: add_subdirectory(third_party/foo EXCLUDE_FROM_ALL)",
                "Or guard with: if(USE_SYSTEM_FOO) ... else() add_subdirectory(...) endif()",
            ],
        )
