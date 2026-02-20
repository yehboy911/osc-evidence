"""CP04 — Proprietary Codec Detection"""

from __future__ import annotations
import re
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, FAIL

_NONFREE_PATTERN = re.compile(
    r"(--enable-nonfree|nonfree|non.free|proprietary.codec|"
    r"--enable-libfdk.aac|--enable-libfaac|commercial)",
    re.IGNORECASE,
)
_SAFE_DISABLE = re.compile(r"--disable-nonfree", re.IGNORECASE)


class CP04ProprietaryCodec(CheckpointBase):
    checkpoint_id = "CP04"
    name = "Proprietary Codec Detection"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        all_findings = pr.findings
        fail_ev: List[Evidence] = []
        pass_ev: List[Evidence] = []

        for f in all_findings:
            expanded, _ = pr.symbols.expand(f.args_text)
            if _NONFREE_PATTERN.search(expanded):
                if _SAFE_DISABLE.search(expanded):
                    pass_ev.append(self._to_evidence(
                        f, "Non-free explicitly disabled"
                    ))
                else:
                    fail_ev.append(self._to_evidence(
                        f, "Proprietary/non-free codec flag detected"
                    ))

        if not fail_ev and not pass_ev:
            return self._pass(
                "No proprietary codec or non-free flags detected in build configuration"
            )
        if fail_ev:
            return self._fail(
                "Proprietary codec or non-free flag detected — may violate GPL redistribution terms",
                evidence=fail_ev + pass_ev,
            )
        return self._pass(
            "Non-free codec references found but explicitly disabled",
            evidence=pass_ev,
        )
