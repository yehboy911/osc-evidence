"""CP07 — Install Scope Exclusion"""

from __future__ import annotations
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, MANUAL


class CP07InstallScope(CheckpointBase):
    checkpoint_id = "CP07"
    name = "Install Scope Exclusion"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        installs = self._findings_for(pr, "install")
        if not installs:
            return self._na("No install() commands found.")

        excluded: List[Evidence] = []
        included: List[Evidence] = []

        for f in installs:
            if f.subtype == "excluded":
                excluded.append(self._to_evidence(
                    f, "Install target uses EXCLUDE_FROM_ALL"
                ))
            else:
                # Check if it's a test/sample target
                args_lower = f.args_text.lower()
                if any(kw in args_lower for kw in ("test", "sample", "example", "demo")):
                    included.append(self._to_evidence(
                        f, "Test/sample target in install() without EXCLUDE_FROM_ALL"
                    ))
                else:
                    included.append(self._to_evidence(
                        f, "Component included in install set"
                    ))

        # If test/sample targets are included in install without exclusion → MANUAL
        test_included = [
            e for e in included
            if "Test/sample" in e.note
        ]
        if test_included:
            return self._manual(
                "Test or sample targets included in install scope — verify these are not GPL-licensed",
                evidence=excluded + included,
                notes=["Add EXCLUDE_FROM_ALL to install() for test/sample components"],
            )
        if included:
            return self._manual(
                "Install targets found — verify no GPL-only components are distributed",
                evidence=excluded + included,
            )
        return self._pass(
            "All install targets use EXCLUDE_FROM_ALL — no unintended GPL exposure",
            evidence=excluded,
        )
