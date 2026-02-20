"""CP02 — LGPL Dynamic Linking"""

from __future__ import annotations
import re
from typing import List
from ..cmake_parser import ParseResult, RawFinding
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, FAIL, MANUAL

_LGPL_NAMES = re.compile(
    r"\b(lgpl|ffmpeg|avcodec|avformat|avutil|swresample|swscale|avfilter|"
    r"libav|libvorbis|libogg|libopus|libflac|libsndfile|libunistring|"
    r"libgpg-error|libgcrypt|gnutls|nettle|hogweed|libffi)\b",
    re.IGNORECASE,
)
_SHARED = re.compile(r"\bSHARED\b")
_STATIC = re.compile(r"\bSTATIC\b")


class CP02LgplLinking(CheckpointBase):
    checkpoint_id = "CP02"
    name = "LGPL Dynamic Linking"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        links = self._findings_for(pr, "target_link_libraries")
        lgpl_links = [f for f in links if _LGPL_NAMES.search(f.args_text)]

        # Also check add_library for SHARED vs STATIC type
        lgpl_targets = [
            t for t in pr.targets if _LGPL_NAMES.search(t.name)
        ]

        if not lgpl_links and not lgpl_targets:
            return self._na("No LGPL-related libraries detected in link commands.")

        fail_evidence: List[Evidence] = []
        pass_evidence: List[Evidence] = []
        manual_evidence: List[Evidence] = []

        # Check target type (SHARED vs STATIC)
        for t in lgpl_targets:
            if t.target_type == "STATIC":
                fail_evidence.append(Evidence(
                    snippet=f"add_library({t.name} STATIC ...)",
                    line_no=t.line_no, file=t.file,
                    note=f"LGPL library '{t.name}' built as STATIC — may trigger copyleft",
                ))
            elif t.target_type == "SHARED":
                pass_evidence.append(Evidence(
                    snippet=f"add_library({t.name} SHARED ...)",
                    line_no=t.line_no, file=t.file,
                    note=f"LGPL library '{t.name}' built as SHARED — dynamic linking is LGPL-compliant",
                ))

        # Check link commands
        for f in lgpl_links:
            if f.subtype == "static_gpl":
                fail_evidence.append(self._to_evidence(
                    f, "Static link to LGPL library — triggers stronger copyleft obligations"
                ))
            elif f.subtype in ("shared_gpl", "visibility_set"):
                pass_evidence.append(self._to_evidence(
                    f, "Dynamic/scoped link to LGPL library — compliant"
                ))
            else:
                manual_evidence.append(self._to_evidence(
                    f, "LGPL library linked — link type unclear, manual review needed"
                ))

        if fail_evidence:
            return self._fail(
                "Static linking to LGPL library detected — may require source disclosure",
                evidence=fail_evidence + pass_evidence + manual_evidence,
            )
        if pass_evidence and not manual_evidence:
            return self._pass(
                "All LGPL-related libraries linked dynamically — LGPL compliant",
                evidence=pass_evidence,
            )
        return self._manual(
            "LGPL libraries present but linking type requires manual verification",
            evidence=pass_evidence + manual_evidence,
            notes=["Confirm all LGPL library links use SHARED targets or dynamic linking"],
        )
