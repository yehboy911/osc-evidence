"""CP05 — GPL/LGPL Library Identification"""

from __future__ import annotations

from typing import List

from .. import license_patterns
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, MANUAL


def _classify_note(text: str, base_note: str) -> str:
    cls = license_patterns.classify_name(text)
    if cls == "gpl":
        return f"{base_note} — matches GPL pattern"
    if cls == "lgpl":
        return f"{base_note} — matches LGPL pattern"
    if cls == "gpl_or_lgpl":
        return f"{base_note} — matches GPL-or-LGPL pattern (depends on build config)"
    return base_note


class CP05GplLibId(CheckpointBase):
    checkpoint_id = "CP05"
    name = "GPL/LGPL Library Identification"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        gpl_lgpl_targets = [
            t for t in pr.targets if license_patterns.has_gpl_lgpl(t.name)
        ]
        gpl_lgpl_links = [
            f for f in self._findings_for(pr, "target_link_libraries")
            if license_patterns.has_gpl_lgpl(f.args_text)
        ]
        gpl_lgpl_eps = [
            f for f in self._findings_for(pr, "ExternalProject_Add")
            if license_patterns.has_gpl_lgpl(f.args_text)
        ]

        if not gpl_lgpl_targets and not gpl_lgpl_links and not gpl_lgpl_eps:
            return self._na(
                "No known GPL or LGPL library names detected in CMake build system."
            )

        evidence: List[Evidence] = []

        for t in gpl_lgpl_targets:
            note = _classify_note(
                t.name,
                f"Target name matches GPL/LGPL library pattern: {t.name}",
            )
            evidence.append(Evidence(
                snippet=f"add_library/executable({t.name} {t.target_type} ...)",
                line_no=t.line_no, file=t.file,
                note=note,
            ))
        for f in gpl_lgpl_links:
            evidence.append(self._to_evidence(
                f, _classify_note(f.args_text, "GPL/LGPL library name found in link command")
            ))
        for f in gpl_lgpl_eps:
            evidence.append(self._to_evidence(
                f, _classify_note(f.args_text, "GPL/LGPL library name found in ExternalProject_Add")
            ))

        return self._manual(
            "GPL/LGPL-associated library names detected — legal counsel must confirm license obligations",
            evidence=evidence,
            notes=[
                "Identify the exact license (GPL v2, v2+, v3, LGPL v2.1, etc.) for each library",
                "Confirm whether the project distributes these libraries or only uses them at runtime",
                "For GPL-or-LGPL libraries (e.g. FFmpeg), confirm the build configuration used",
            ],
        )
