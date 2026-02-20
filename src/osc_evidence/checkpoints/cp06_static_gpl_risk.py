"""CP06 — Static Linking GPL Risk"""

from __future__ import annotations
import re
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, FAIL, MANUAL

_GPL_NAMES = re.compile(
    r"\b(gpl|ffmpeg|x264|x265|libx264|libx265|openh264|lame|libmp3lame|"
    r"faac|xvid|libxvid|libav|libavcodec|libavformat|libavutil)\b",
    re.IGNORECASE,
)
_STATIC_KW = re.compile(r"\bSTATIC\b")


class CP06StaticGplRisk(CheckpointBase):
    checkpoint_id = "CP06"
    name = "Static Linking GPL Risk"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        # Check add_library STATIC for GPL-named targets
        static_gpl_targets = [
            t for t in pr.targets
            if t.target_type == "STATIC" and _GPL_NAMES.search(t.name)
        ]
        # Check target_link_libraries subtype static_gpl
        static_links = self._findings_for_subtype(pr, "static_gpl")

        if not static_gpl_targets and not static_links:
            # Look for any STATIC targets linked to GPL libs
            links = self._findings_for(pr, "target_link_libraries")
            gpl_links = [f for f in links if _GPL_NAMES.search(f.args_text)]
            static_targets = [t for t in pr.targets if t.target_type == "STATIC"]
            if not gpl_links and not static_targets:
                return self._na("No static linking to GPL libraries detected.")
            if not gpl_links:
                return self._pass(
                    "No GPL libraries found in static link commands",
                    evidence=[],
                )

        fail_ev: List[Evidence] = []
        for t in static_gpl_targets:
            fail_ev.append(Evidence(
                snippet=f"add_library({t.name} STATIC ...)",
                line_no=t.line_no, file=t.file,
                note=f"GPL-named library '{t.name}' compiled as STATIC archive",
            ))
        for f in static_links:
            fail_ev.append(self._to_evidence(
                f, "Static link to GPL library — entire binary must be GPL-licensed"
            ))

        if fail_ev:
            return self._fail(
                "Static linking to GPL library detected — distributing this binary requires GPL source disclosure",
                evidence=fail_ev,
            )
        return self._pass(
            "No static GPL library links detected"
        )
