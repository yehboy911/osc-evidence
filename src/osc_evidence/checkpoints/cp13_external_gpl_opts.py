"""CP13 — ExternalProject GPL Options"""

from __future__ import annotations

from typing import List

from .. import license_patterns
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, MANUAL, PASS


class CP13ExternalGplOpts(CheckpointBase):
    checkpoint_id = "CP13"
    name = "ExternalProject GPL Options"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        eps = self._findings_for(pr, "ExternalProject_Add")
        if not eps:
            return self._na("No ExternalProject_Add() calls found.")

        with_configure: List[Evidence] = []
        gpl_lgpl_no_configure: List[Evidence] = []
        other_no_configure: List[Evidence] = []

        for f in eps:
            has_configure = "CONFIGURE_COMMAND" in f.args_text.upper()
            parts = f.args_text.split()
            ep_name = parts[0] if parts else ""
            cls = license_patterns.classify_name(ep_name) or license_patterns.classify_name(f.args_text)
            label = license_patterns.label_for(cls) if cls else None

            if has_configure:
                note = "ExternalProject has CONFIGURE_COMMAND — build options are explicitly set"
                if cls:
                    note += f" [{label} library]"
                with_configure.append(self._to_evidence(f, note))
            else:
                if cls:
                    gpl_lgpl_no_configure.append(self._to_evidence(
                        f,
                        f"{label} ExternalProject '{ep_name}' has no CONFIGURE_COMMAND — "
                        f"default build may enable GPL/proprietary features",
                    ))
                else:
                    other_no_configure.append(self._to_evidence(
                        f, f"ExternalProject '{ep_name}' has no CONFIGURE_COMMAND — uses default CMake configure"
                    ))

        if not gpl_lgpl_no_configure and not other_no_configure:
            return self._pass(
                "All external projects have explicit CONFIGURE_COMMAND — build options are documented",
                evidence=with_configure,
            )

        notes = [
            "Add CONFIGURE_COMMAND to each ExternalProject_Add() to explicitly control build flags",
            "Include --disable-gpl or equivalent flags where applicable",
        ]
        if gpl_lgpl_no_configure:
            notes.insert(0, "GPL/LGPL external projects without CONFIGURE_COMMAND are high priority — review immediately")

        return self._manual(
            "Some external projects lack CONFIGURE_COMMAND — default build options may enable GPL features",
            evidence=with_configure + gpl_lgpl_no_configure + other_no_configure,
            notes=notes,
        )
