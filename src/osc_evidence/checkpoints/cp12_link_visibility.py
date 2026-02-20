"""CP12 — Linking Visibility"""

from __future__ import annotations
import re
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, MANUAL

_VIS = re.compile(r"\b(PRIVATE|PUBLIC|INTERFACE)\b")


class CP12LinkVisibility(CheckpointBase):
    checkpoint_id = "CP12"
    name = "Linking Visibility"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        links = self._findings_for(pr, "target_link_libraries")
        if not links:
            return self._na("No target_link_libraries() calls found.")

        with_vis: List[Evidence] = []
        without_vis: List[Evidence] = []

        for f in links:
            if _VIS.search(f.args_text):
                vis_matches = _VIS.findall(f.args_text)
                note = f"Link visibility: {', '.join(set(vis_matches))}"
                with_vis.append(self._to_evidence(f, note))
            else:
                without_vis.append(self._to_evidence(
                    f, "No PRIVATE/PUBLIC/INTERFACE qualifier — legacy CMake style"
                ))

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
