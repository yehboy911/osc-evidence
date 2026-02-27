"""CP02 — LGPL Dynamic Linking (expanded to GPL+LGPL)"""

from __future__ import annotations

from typing import List

from .. import license_patterns
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, FAIL, MANUAL, PASS

_SHARED = __import__("re").compile(r"\bSHARED\b")
_STATIC = __import__("re").compile(r"\bSTATIC\b")


class CP02LgplLinking(CheckpointBase):
    checkpoint_id = "CP02"
    name = "LGPL Dynamic Linking"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        links = self._findings_for(pr, "target_link_libraries")
        gpl_lgpl_links = [f for f in links if license_patterns.has_gpl_lgpl(f.args_text)]

        # Also check add_library for SHARED vs STATIC type
        gpl_lgpl_targets = [
            t for t in pr.targets if license_patterns.has_gpl_lgpl(t.name)
        ]

        if not gpl_lgpl_links and not gpl_lgpl_targets:
            return self._na("No GPL or LGPL-related libraries detected in link commands.")

        fail_evidence: List[Evidence] = []
        pass_evidence: List[Evidence] = []
        manual_evidence: List[Evidence] = []

        # Check target type (SHARED vs STATIC)
        for t in gpl_lgpl_targets:
            cls = license_patterns.classify_name(t.name)
            label = license_patterns.label_for(cls)
            if t.target_type == "STATIC":
                fail_evidence.append(Evidence(
                    snippet=f"add_library({t.name} STATIC ...)",
                    line_no=t.line_no, file=t.file,
                    note=f"{label} library '{t.name}' built as STATIC — triggers copyleft obligations",
                ))
            elif t.target_type == "SHARED":
                if cls == "gpl":
                    # Dynamic linking does not exempt GPL
                    manual_evidence.append(Evidence(
                        snippet=f"add_library({t.name} SHARED ...)",
                        line_no=t.line_no, file=t.file,
                        note=f"GPL library '{t.name}' built as SHARED — dynamic linking does not exempt GPL obligations",
                    ))
                else:
                    pass_evidence.append(Evidence(
                        snippet=f"add_library({t.name} SHARED ...)",
                        line_no=t.line_no, file=t.file,
                        note=f"{label} library '{t.name}' built as SHARED — dynamic linking is LGPL-compliant",
                    ))

        # Check link commands
        for f in gpl_lgpl_links:
            cls = license_patterns.classify_name(f.args_text)
            label = license_patterns.label_for(cls)
            if f.subtype == "static_gpl":
                fail_evidence.append(self._to_evidence(
                    f, f"Static link to {label} library — triggers stronger copyleft obligations"
                ))
            elif f.subtype in ("shared_gpl", "visibility_set"):
                if cls == "gpl":
                    manual_evidence.append(self._to_evidence(
                        f, f"Dynamic link to GPL library — dynamic linking does not exempt GPL; source disclosure required"
                    ))
                else:
                    pass_evidence.append(self._to_evidence(
                        f, f"Dynamic/scoped link to {label} library — compliant"
                    ))
            else:
                manual_evidence.append(self._to_evidence(
                    f, f"{label} library linked — link type unclear, manual review needed"
                ))

        if fail_evidence:
            return self._fail(
                "Static linking to GPL/LGPL library detected — source disclosure required",
                evidence=fail_evidence + pass_evidence + manual_evidence,
            )
        if manual_evidence:
            return self._manual(
                "GPL/LGPL libraries present — linking type or license obligations require manual verification",
                evidence=pass_evidence + manual_evidence,
                notes=[
                    "GPL: dynamic linking does not exempt from source disclosure — verify full compliance",
                    "LGPL: SHARED/dynamic linking is compliant; STATIC linking requires disclosure",
                    "Confirm all GPL/LGPL library links use the correct linking mode",
                ],
            )
        if pass_evidence:
            return self._pass(
                "All LGPL-related libraries linked dynamically — LGPL compliant",
                evidence=pass_evidence,
            )
        return self._na("No GPL/LGPL linking issues detected.")
