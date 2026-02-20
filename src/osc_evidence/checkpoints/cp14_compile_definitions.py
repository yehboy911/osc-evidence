"""CP14 — Compile Definitions"""

from __future__ import annotations
import re
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, MANUAL

_GPL_DEF = re.compile(
    r"\b(GPL|LGPL|HAVE_GPL|USE_GPL|ENABLE_GPL|GPL_VERSION|FFMPEG_GPL|"
    r"NONFREE|PROPRIETARY|WITH_GPL)\b",
    re.IGNORECASE,
)


class CP14CompileDefinitions(CheckpointBase):
    checkpoint_id = "CP14"
    name = "Compile Definitions"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        defs = self._findings_for(pr, "target_compile_definitions")
        if not defs:
            return self._na("No target_compile_definitions() calls found.")

        gpl_defs: List[Evidence] = []
        clean_defs: List[Evidence] = []

        for f in defs:
            expanded, unresolved = pr.symbols.expand(f.args_text)
            if _GPL_DEF.search(expanded):
                note = "GPL-related compile definition"
                if unresolved:
                    note += f" (unresolved vars: {', '.join(unresolved)})"
                gpl_defs.append(self._to_evidence(f, note))
            else:
                clean_defs.append(self._to_evidence(
                    f, "No GPL-related identifiers in compile definitions"
                ))

        if not gpl_defs:
            return self._pass(
                "No GPL-related compile definitions found",
                evidence=clean_defs,
            )
        return self._manual(
            "GPL-related compile definitions detected — verify whether they enable GPL code paths",
            evidence=gpl_defs + clean_defs,
            notes=[
                "Determine whether each GPL compile definition enables or disables GPL features",
                "Confirm no proprietary module relies on GPL-enabled code paths",
            ],
        )
