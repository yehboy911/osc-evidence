"""CP12 — Linking Visibility"""

from __future__ import annotations

import re
from typing import List

from .. import license_patterns
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, FAIL, MANUAL, PASS

_VIS = re.compile(r"\b(PRIVATE|PUBLIC|INTERFACE)\b")


class CP12LinkVisibility(CheckpointBase):
    checkpoint_id = "CP12"
    name = "Linking Visibility"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        links = self._findings_for(pr, "target_link_libraries")
        if not links:
            return self._na("No target_link_libraries() calls found.")

        with_vis: List[Evidence] = []
        gpl_public: List[Evidence] = []
        gpl_lgpl_no_vis: List[Evidence] = []
        without_vis: List[Evidence] = []

        for f in links:
            has_vis = bool(_VIS.search(f.args_text))
            is_gpl_lgpl = license_patterns.has_gpl_lgpl(f.args_text)
            cls = license_patterns.classify_name(f.args_text) if is_gpl_lgpl else None
            label = license_patterns.label_for(cls) if cls else "GPL/LGPL"

            if has_vis:
                vis_matches = _VIS.findall(f.args_text)
                vis_set = set(vis_matches)
                note = f"Link visibility: {', '.join(sorted(vis_set))}"
                if is_gpl_lgpl and "PUBLIC" in vis_set:
                    note += f" — {label} dependency with PUBLIC visibility propagates obligations to consumers"
                    gpl_public.append(self._to_evidence(f, note))
                else:
                    with_vis.append(self._to_evidence(f, note))
            else:
                if is_gpl_lgpl:
                    gpl_lgpl_no_vis.append(self._to_evidence(
                        f,
                        f"{label} library linked without PRIVATE/PUBLIC/INTERFACE — "
                        f"propagation scope cannot be determined",
                    ))
                else:
                    without_vis.append(self._to_evidence(
                        f, "No PRIVATE/PUBLIC/INTERFACE qualifier — legacy CMake style"
                    ))

        if gpl_lgpl_no_vis:
            return self._fail(
                "GPL/LGPL library linked without visibility qualifier — dependency propagation scope is unknown",
                evidence=gpl_lgpl_no_vis + gpl_public + with_vis + without_vis,
            )
        if gpl_public:
            return self._manual(
                "GPL/LGPL dependency linked with PUBLIC visibility — obligations propagate to all consumers",
                evidence=gpl_public + with_vis + without_vis,
                notes=[
                    "PUBLIC: dependency is exposed to all consumers (may propagate GPL/LGPL obligations)",
                    "PRIVATE: dependency is not exposed to consumers (preferred for GPL isolation)",
                    "Review whether GPL/LGPL PUBLIC links are intentional",
                ],
            )
        if not without_vis:
            return self._pass(
                "All target_link_libraries() calls use explicit visibility (PRIVATE/PUBLIC/INTERFACE)",
                evidence=with_vis,
            )
        if with_vis:
            return self._manual(
                "Mix of qualified and unqualified link commands — verify GPL propagation scope",
                evidence=with_vis + without_vis,
                notes=[
                    "PRIVATE: dependency is not exposed to consumers (preferred for GPL isolation)",
                    "PUBLIC: dependency is exposed to all consumers (may propagate GPL obligations)",
                    "INTERFACE: exposed only via header include paths",
                    "Add visibility qualifiers to all target_link_libraries() calls",
                ],
            )
        return self._manual(
            "No link visibility qualifiers found — GPL dependency scope cannot be determined statically",
            evidence=without_vis,
            notes=["Add PRIVATE/PUBLIC/INTERFACE to all target_link_libraries() calls"],
        )
