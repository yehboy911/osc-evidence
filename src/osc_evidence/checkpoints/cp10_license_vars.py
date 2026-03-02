"""CP10 — Extlibs Component Audit

Discovers pre-compiled OSS components bundled under **/extlibs/**/include/
directories, cross-references them against the SBOM-confirmed GPL/LGPL list,
and flags undocumented risks or SBOM gaps.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Set

from ..cmake_parser import ParseResult
from ..gpl_scanner import GplComponent
from ..license_patterns import classify_name, label_for
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, FAIL, MANUAL

# Stems that are infrastructure headers, not component names
_SKIP_STEMS = {"config", "version", "buildinfo", "platform"}

# Platform path segment mapping
_WIN_SEGMENTS = {"win64", "win32", "win", "windows", "x64"}
_LINUX_SEGMENTS = {"linux_x64", "linux", "linux64", "unix"}


@dataclass
class ExtlibComponent:
    """A component discovered under an extlibs/include/ directory."""
    name: str
    include_path: str       # relative path (e.g. "extlibs/WIN64/include/openssl")
    platform_hint: str      # "windows" | "linux" | "common"


class CP10ExtlibsAudit(CheckpointBase):
    checkpoint_id = "CP10"
    name = "Extlibs Component Audit"

    # Injected by CheckpointEngine
    source_dir: str = ""
    gpl_components: List[GplComponent] = []
    sbom_all_names: Set[str] = field(default_factory=set)

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        if not self.source_dir:
            return self._na("No source directory provided for extlibs scan.")

        components = self._discover_extlib_components()

        if not components:
            return self._na(
                "No extlibs/include/ directories found — "
                "pre-compiled component audit not applicable."
            )

        # Build lookup: prefer full SBOM name set; fall back to GPL/LGPL subset
        sbom_names = self.sbom_all_names if self.sbom_all_names else {c.name for c in self.gpl_components}
        no_sbom = not sbom_names and len(self.gpl_components) == 0

        evidence: List[Evidence] = []
        has_fail = False
        has_manual = False

        for comp in components:
            classification = classify_name(comp.name)
            in_sbom = comp.name in sbom_names

            if classification is not None:
                # GPL/LGPL component detected
                license_label = label_for(classification)
                if in_sbom:
                    evidence.append(Evidence(
                        snippet=f"extlibs component: {comp.name}",
                        line_no=0,
                        file=comp.include_path,
                        note=f"{license_label} component — confirmed in SBOM, tracked",
                    ))
                elif no_sbom:
                    has_manual = True
                    evidence.append(Evidence(
                        snippet=f"extlibs component: {comp.name}",
                        line_no=0,
                        file=comp.include_path,
                        note=f"{license_label} component — no SBOM provided; "
                             f"run with --sbom to confirm tracking",
                    ))
                else:
                    has_fail = True
                    evidence.append(Evidence(
                        snippet=f"extlibs component: {comp.name}",
                        line_no=0,
                        file=comp.include_path,
                        note=f"{license_label} component bundled in extlibs "
                             f"but NOT listed in SBOM — compliance gap",
                    ))
            else:
                # Non-GPL component
                if in_sbom:
                    evidence.append(Evidence(
                        snippet=f"extlibs component: {comp.name}",
                        line_no=0,
                        file=comp.include_path,
                        note="Non-GPL/LGPL component — confirmed in SBOM",
                    ))
                elif no_sbom:
                    has_manual = True
                    evidence.append(Evidence(
                        snippet=f"extlibs component: {comp.name}",
                        line_no=0,
                        file=comp.include_path,
                        note="License unknown — no SBOM provided; "
                             "run with --sbom to confirm tracking",
                    ))
                else:
                    has_manual = True
                    evidence.append(Evidence(
                        snippet=f"extlibs component: {comp.name}",
                        line_no=0,
                        file=comp.include_path,
                        note="Component not in SBOM — potential SBOM gap; "
                             "verify license and add to SBOM if distributed",
                    ))

        if has_fail:
            return self._fail(
                "GPL/LGPL component(s) found in extlibs but missing from SBOM — "
                "undocumented copyleft risk",
                evidence=evidence,
            )

        if has_manual:
            notes = []
            if no_sbom:
                notes.append(
                    "No SBOM was provided. Run with --sbom <csv> to enable "
                    "cross-reference and reduce MANUAL findings."
                )
            else:
                notes.append(
                    "Some extlibs components are not listed in the SBOM. "
                    "Verify their licenses and add them if they are distributed."
                )
            return self._manual(
                f"Extlibs audit found {len(components)} component(s) — "
                f"some require human review for SBOM completeness",
                evidence=evidence,
                notes=notes,
            )

        return self._pass(
            f"All {len(components)} extlibs component(s) are tracked in SBOM",
            evidence=evidence,
        )

    def _discover_extlib_components(self) -> List[ExtlibComponent]:
        """Walk source_dir for extlibs/**/include/ directories and collect components."""
        source_root = os.path.abspath(self.source_dir)
        found: dict[str, ExtlibComponent] = {}  # dedup by name

        for dirpath, dirnames, filenames in os.walk(source_root):
            basename = os.path.basename(dirpath)
            if basename != "include":
                continue

            rel_path = os.path.relpath(dirpath, source_root)
            parts = rel_path.replace("\\", "/").lower().split("/")
            if "extlibs" not in parts:
                continue

            # Infer platform from path segments
            platform_hint = "common"
            for seg in parts:
                if seg in _WIN_SEGMENTS:
                    platform_hint = "windows"
                    break
                if seg in _LINUX_SEGMENTS:
                    platform_hint = "linux"
                    break

            # Collect immediate subdirectories as component names
            for subdir in dirnames:
                name = subdir.lower()
                if name in _SKIP_STEMS or name.startswith("."):
                    continue
                comp_rel = os.path.relpath(
                    os.path.join(dirpath, subdir), source_root
                )
                if name not in found:
                    found[name] = ExtlibComponent(
                        name=name,
                        include_path=comp_rel,
                        platform_hint=platform_hint,
                    )

            # Collect top-level .h/.hpp files as components
            for fname in filenames:
                if not (fname.endswith(".h") or fname.endswith(".hpp")):
                    continue
                stem = os.path.splitext(fname)[0].lower()
                if stem in _SKIP_STEMS or stem.startswith("."):
                    continue
                comp_rel = os.path.relpath(dirpath, source_root)
                if stem not in found:
                    found[stem] = ExtlibComponent(
                        name=stem,
                        include_path=comp_rel,
                        platform_hint=platform_hint,
                    )

            # Don't recurse into include/ subdirectories
            dirnames.clear()

        return sorted(found.values(), key=lambda c: c.name)
