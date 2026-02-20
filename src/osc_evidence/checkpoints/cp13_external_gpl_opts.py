"""CP13 — ExternalProject GPL Options"""

from __future__ import annotations
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, MANUAL


class CP13ExternalGplOpts(CheckpointBase):
    checkpoint_id = "CP13"
    name = "ExternalProject GPL Options"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        eps = self._findings_for(pr, "ExternalProject_Add")
        if not eps:
            return self._na("No ExternalProject_Add() calls found.")

        with_configure: List[Evidence] = []
        without_configure: List[Evidence] = []

        for f in eps:
            has_configure = "CONFIGURE_COMMAND" in f.args_text.upper()
            if has_configure:
                with_configure.append(self._to_evidence(
                    f, "ExternalProject has CONFIGURE_COMMAND — build options are explicitly set"
                ))
            else:
                without_configure.append(self._to_evidence(
                    f, "ExternalProject has no CONFIGURE_COMMAND — uses default CMake configure"
                ))

        if not without_configure:
            return self._pass(
                "All external projects have explicit CONFIGURE_COMMAND — build options are documented",
                evidence=with_configure,
            )
        return self._manual(
            "Some external projects lack CONFIGURE_COMMAND — default build options may enable GPL features",
            evidence=with_configure + without_configure,
            notes=[
                "Add CONFIGURE_COMMAND to each ExternalProject_Add() to explicitly control build flags",
                "Include --disable-gpl or equivalent flags where applicable",
            ],
        )
