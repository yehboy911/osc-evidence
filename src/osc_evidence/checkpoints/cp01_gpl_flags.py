"""CP01 — GPL Build Flags"""

from __future__ import annotations
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, FAIL, MANUAL


class CP01GplFlags(CheckpointBase):
    checkpoint_id = "CP01"
    name = "GPL Build Flags"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        eps = self._findings_for(pr, "ExternalProject_Add")
        if not eps:
            return self._na("No ExternalProject_Add calls found.")

        disable_found: List[Evidence] = []
        enable_found: List[Evidence] = []
        manual_found: List[Evidence] = []

        for f in eps:
            if f.subtype == "disable_gpl":
                disable_found.append(self._to_evidence(
                    f, "GPL explicitly disabled via configure flag"
                ))
            elif f.subtype == "enable_gpl":
                enable_found.append(self._to_evidence(
                    f, "GPL explicitly ENABLED — triggers GPL obligations on distribution"
                ))
            elif f.subtype in ("gpl_flag", "nonfree"):
                manual_found.append(self._to_evidence(
                    f, "GPL-related flag detected — verify whether it enables or disables GPL"
                ))

        if enable_found:
            return self._fail(
                "GPL features explicitly enabled in ExternalProject configure command",
                evidence=enable_found + disable_found + manual_found,
            )
        if disable_found and not manual_found:
            return self._pass(
                "GPL features explicitly disabled via --disable-gpl in configure command",
                evidence=disable_found,
            )
        if manual_found or disable_found:
            return self._manual(
                "Mixed or ambiguous GPL configure flags — manual review required",
                evidence=disable_found + manual_found,
                notes=["Verify each --enable-*/--disable-* flag in CONFIGURE_COMMAND"],
            )
        return self._na("No GPL configure flags found in ExternalProject_Add calls.")
