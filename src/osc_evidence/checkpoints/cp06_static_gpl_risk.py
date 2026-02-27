"""CP06 — Static Linking GPL Risk (Redesign)

Two-layer analysis:
  Layer 1: GPL component subdir analysis — check CMake targets within
           confirmed GPL component directories for STATIC type.
  Layer 2: Main project static link analysis — scan target_link_libraries
           for references to confirmed GPL/LGPL component names.

Requires gpl_components (List[GplComponent]) to be injected by the
checkpoint engine. Without confirmed components, returns N/A.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set

from ..cmake_parser import ParseResult, RawFinding
from ..gpl_scanner import GplComponent
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, FAIL, MANUAL


# Known name variants for GPL/LGPL components
_NAME_VARIANTS: Dict[str, List[str]] = {
    "cygwin": ["cygwin", "cygwin1", "cygiconv", "cygiconv-2"],
    "xorriso": ["xorriso"],
    "ffmpeg": ["ffmpeg", "avcodec", "avformat", "avutil", "swresample", "swscale",
               "avfilter", "libavcodec", "libavformat", "libavutil",
               "libavfilter", "libswresample", "libswscale"],
    "blowfish": ["blowfish", "bf", "libblowfish"],
    "pegasus": ["pegasus"],
    "pthreads-w32": ["pthreads", "pthread", "pthreads-w32", "pthreadvc2"],
}

_STATIC_KW = re.compile(r"\bSTATIC\b")
_SHARED_KW = re.compile(r"\bSHARED\b")


def _build_name_set(components: List[GplComponent]) -> Dict[str, GplComponent]:
    """Build a mapping of all name variants -> GplComponent for matching."""
    name_map: Dict[str, GplComponent] = {}
    for comp in components:
        # Add the canonical name
        name_map[comp.name.lower()] = comp
        # Add known variants
        for base, variants in _NAME_VARIANTS.items():
            if comp.name.lower() == base or comp.name.lower().startswith(base):
                for v in variants:
                    name_map[v.lower()] = comp
    return name_map


def _extract_linked_names(args_text: str) -> List[str]:
    """Extract library names from a target_link_libraries args_text."""
    # Remove CMake keywords
    skip = {"PUBLIC", "PRIVATE", "INTERFACE", "IMPORTED", "STATIC", "SHARED",
            "OPTIMIZED", "DEBUG", "GENERAL"}
    tokens = re.split(r"[\s;,()]+", args_text)
    return [t for t in tokens if t and t.upper() not in skip]


class CP06StaticGplRisk(CheckpointBase):
    checkpoint_id = "CP06"
    name = "Static Linking GPL Risk"

    # Injected by checkpoint engine
    gpl_components: List[GplComponent] = []

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        components = self.gpl_components
        if not components:
            return self._na(
                "No GPL/LGPL components confirmed — provide SBOM CSV "
                "(--sbom) or ensure LICENSE/COPYING files are present "
                "in the source tree."
            )

        name_map = _build_name_set(components)
        fail_ev: List[Evidence] = []
        manual_ev: List[Evidence] = []
        pass_ev: List[Evidence] = []

        # --- Layer 1: GPL component subdir analysis ---
        for comp in components:
            if not comp.source_path or comp.source_path == ".":
                continue
            # Find targets within the component's source directory
            subdir_targets = [
                t for t in pr.targets
                if t.file.startswith(comp.source_path + "/")
                or t.file.startswith(comp.source_path + "\\")
            ]
            for t in subdir_targets:
                if t.target_type == "STATIC":
                    fail_ev.append(Evidence(
                        snippet=f"add_library({t.name} STATIC ...)",
                        line_no=t.line_no,
                        file=t.file,
                        note=(
                            f"{comp.license} component '{comp.name}' built as "
                            f"STATIC — confirmed via {comp.confirmed_by}"
                        ),
                    ))

        # --- Layer 2: Main project static link to GPL components ---
        link_findings = self._findings_for(pr, "target_link_libraries")

        for finding in link_findings:
            linked_names = _extract_linked_names(finding.args_text)
            for lib_name in linked_names:
                comp = name_map.get(lib_name.lower())
                if comp is None:
                    continue

                has_static = bool(_STATIC_KW.search(finding.args_text))
                has_shared = bool(_SHARED_KW.search(finding.args_text))

                confirmed_note = (
                    f"Links to {comp.license} component '{comp.name}' "
                    f"(confirmed via {comp.confirmed_by})"
                )

                ev = self._to_evidence(finding, confirmed_note)

                if has_static:
                    # Any GPL/LGPL + STATIC → FAIL
                    fail_ev.append(ev)
                elif has_shared:
                    if comp.classification == "lgpl":
                        # LGPL + SHARED → PASS (dynamic linking compliant)
                        pass_ev.append(Evidence(
                            snippet=finding.snippet,
                            line_no=finding.line_no,
                            file=finding.file,
                            note=(
                                f"LGPL component '{comp.name}' linked as SHARED "
                                f"— dynamic linking is LGPL-compliant"
                            ),
                        ))
                    else:
                        # GPL + SHARED → MANUAL (dynamic linking doesn't exempt GPL)
                        manual_ev.append(Evidence(
                            snippet=finding.snippet,
                            line_no=finding.line_no,
                            file=finding.file,
                            note=(
                                f"GPL component '{comp.name}' linked as SHARED "
                                f"— dynamic linking does NOT exempt GPL obligations"
                            ),
                        ))
                else:
                    # No explicit link type — MANUAL
                    manual_ev.append(Evidence(
                        snippet=finding.snippet,
                        line_no=finding.line_no,
                        file=finding.file,
                        note=(
                            f"Links to {comp.license} component '{comp.name}' "
                            f"— link type (static/shared) unclear from CMake"
                        ),
                    ))

        # --- Determine verdict ---
        if fail_ev:
            return self._fail(
                "Static linking to GPL/LGPL library detected — "
                "distributing this binary requires source disclosure",
                evidence=fail_ev + manual_ev,
            )

        if manual_ev:
            return self._manual(
                "GPL/LGPL component references found but link type is unclear "
                "or GPL component uses dynamic linking (does not exempt GPL)",
                evidence=manual_ev + pass_ev,
                notes=[
                    "Verify whether linking is static or dynamic for each flagged component.",
                    "GPL obligations apply regardless of link type; LGPL allows dynamic linking.",
                ],
            )

        if pass_ev:
            return self._pass(
                "GPL/LGPL components confirmed; all linkage is LGPL-compliant "
                "(dynamic linking only)",
                evidence=pass_ev,
            )

        # Components confirmed but no links found in CMake
        comp_names = ", ".join(c.name for c in components)
        return self._pass(
            f"GPL/LGPL components confirmed ({comp_names}) but no static "
            f"linking to these components detected in CMake build files",
        )
