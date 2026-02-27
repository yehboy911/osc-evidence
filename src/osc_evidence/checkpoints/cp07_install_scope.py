"""CP07 — Install Scope Exclusion"""

from __future__ import annotations

import re
from typing import List, Optional, Set

from .. import license_patterns
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, FAIL, MANUAL, PASS

_COMPONENT_KW = re.compile(r"\bCOMPONENT\s+(\S+)", re.IGNORECASE)
# Install sub-command keywords that end a TARGETS list
_INSTALL_KW = frozenset({
    "FILES", "PROGRAMS", "DIRECTORY", "SCRIPT", "CODE",
    "COMPONENT", "DESTINATION", "PERMISSIONS", "CONFIGURATIONS",
    "RENAME", "OPTIONAL", "EXCLUDE_FROM_ALL", "RUNTIME",
    "LIBRARY", "ARCHIVE", "NAMELINK_ONLY", "NAMELINK_SKIP",
    "PRIVATE_HEADER", "PUBLIC_HEADER", "RESOURCE", "TARGETS",
})


def _extract_install_targets(args_text: str) -> Set[str]:
    """Extract target names from the TARGETS list of an install() command."""
    targets: Set[str] = set()
    parts = args_text.split()
    in_targets = False
    for p in parts:
        up = p.upper()
        if up == "TARGETS":
            in_targets = True
            continue
        if up in _INSTALL_KW:
            in_targets = False
            continue
        if in_targets:
            targets.add(p)
    return targets


def _component_of(args_text: str) -> Optional[str]:
    """Return the COMPONENT value from an install() args string, or None."""
    m = _COMPONENT_KW.search(args_text)
    return m.group(1) if m else None


class CP07InstallScope(CheckpointBase):
    checkpoint_id = "CP07"
    name = "Install Scope Exclusion"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        installs = self._findings_for(pr, "install")
        if not installs:
            return self._na("No install() commands found.")

        test_target_names: Set[str] = {t.name for t in pr.targets if t.is_test}

        excluded: List[Evidence] = []
        gpl_fail: List[Evidence] = []
        lgpl_manual: List[Evidence] = []
        test_manual: List[Evidence] = []
        included: List[Evidence] = []

        for f in installs:
            if f.subtype == "excluded":
                excluded.append(self._to_evidence(
                    f, "Install target uses EXCLUDE_FROM_ALL"
                ))
                continue

            install_targets = _extract_install_targets(f.args_text)
            component = _component_of(f.args_text)
            component_note = f" [COMPONENT={component}]" if component else ""
            args_lower = f.args_text.lower()

            # Check for GPL/LGPL names in install targets
            gpl_lgpl_targets = {
                t for t in install_targets if license_patterns.has_gpl_lgpl(t)
            }
            for t_name in sorted(gpl_lgpl_targets):
                cls = license_patterns.classify_name(t_name)
                label = license_patterns.label_for(cls)
                is_runtime = component and component.upper() in ("RUNTIME", "BIN")
                if cls == "gpl" and is_runtime:
                    gpl_fail.append(self._to_evidence(
                        f, f"GPL target '{t_name}' installed to Runtime component — full GPL source disclosure required{component_note}"
                    ))
                elif cls in ("lgpl", "gpl_or_lgpl") and is_runtime:
                    lgpl_manual.append(self._to_evidence(
                        f, f"{label} target '{t_name}' installed to Runtime component — verify compliance{component_note}"
                    ))
                else:
                    lgpl_manual.append(self._to_evidence(
                        f, f"{label} target '{t_name}' in install() — verify license obligations{component_note}"
                    ))

            # Cross-reference against known test targets
            test_targets_found = install_targets & test_target_names
            if not test_targets_found:
                # Fall back to name-based heuristic
                if any(kw in args_lower for kw in ("test", "sample", "example", "demo")):
                    test_targets_found = {"(name-matched)"}

            if test_targets_found and not gpl_lgpl_targets:
                test_manual.append(self._to_evidence(
                    f, f"Test/sample target in install() without EXCLUDE_FROM_ALL{component_note}"
                ))
            elif not gpl_lgpl_targets and not test_targets_found:
                included.append(self._to_evidence(
                    f, f"Component included in install set{component_note}"
                ))

        if gpl_fail:
            return self._fail(
                "GPL library installed to Runtime component — full GPL source disclosure required for distribution",
                evidence=gpl_fail + lgpl_manual + test_manual + included + excluded,
            )
        if lgpl_manual or test_manual:
            return self._manual(
                "GPL/LGPL or test targets included in install scope — verify compliance obligations",
                evidence=lgpl_manual + test_manual + included + excluded,
                notes=[
                    "Add EXCLUDE_FROM_ALL to install() for test/sample components",
                    "For GPL targets in Runtime component: full source disclosure required",
                    "For LGPL targets: confirm dynamic linking is used",
                ],
            )
        if included:
            return self._manual(
                "Install targets found — verify no GPL-only components are distributed",
                evidence=excluded + included,
            )
        return self._pass(
            "All install targets use EXCLUDE_FROM_ALL — no unintended GPL exposure",
            evidence=excluded,
        )
