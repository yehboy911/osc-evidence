"""CP05 — GPL Library Identification"""

from __future__ import annotations
import re
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, MANUAL

_GPL_NAMES = re.compile(
    r"\b(gpl|ffmpeg|x264|x265|libx264|libx265|openh264|libopenh264|"
    r"lame|libmp3lame|faac|xvid|libxvid|divx|libdivx|gpac|"
    r"libavcodec|libavformat|libavutil|libav)\b",
    re.IGNORECASE,
)


class CP05GplLibId(CheckpointBase):
    checkpoint_id = "CP05"
    name = "GPL Library Identification"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        gpl_targets = [
            t for t in pr.targets if _GPL_NAMES.search(t.name)
        ]
        gpl_links = [
            f for f in self._findings_for(pr, "target_link_libraries")
            if _GPL_NAMES.search(f.args_text)
        ]
        gpl_eps = [
            f for f in self._findings_for(pr, "ExternalProject_Add")
            if _GPL_NAMES.search(f.args_text)
        ]

        if not gpl_targets and not gpl_links and not gpl_eps:
            return self._na("No known GPL library names detected in CMake build system.")

        evidence: List[Evidence] = []

        for t in gpl_targets:
            evidence.append(Evidence(
                snippet=f"add_library/executable({t.name} {t.target_type} ...)",
                line_no=t.line_no, file=t.file,
                note=f"Target name matches GPL library pattern: {t.name}",
            ))
        for f in gpl_links:
            evidence.append(self._to_evidence(
                f, "GPL library name found in link command"
            ))
        for f in gpl_eps:
            evidence.append(self._to_evidence(
                f, "GPL library name found in ExternalProject_Add"
            ))

        return self._manual(
            "GPL-associated library names detected — legal counsel must confirm license obligations",
            evidence=evidence,
            notes=[
                "Identify the exact license (GPL v2, v2+, v3, LGPL v2.1, etc.) for each library",
                "Confirm whether the project distributes these libraries or only uses them at runtime",
            ],
        )
