"""CP15 — Runtime Download Risk"""

from __future__ import annotations

import os
import re
from typing import Dict, List

from .. import license_patterns
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, MANUAL, KNOWN_ISSUE

_DLL_PATTERN = re.compile(
    r'\b(msvcp|vcruntime|vccorlib|concrt)[\d_]*\.dll\b', re.IGNORECASE
)
_KNOWN_MSVC_DLLS = frozenset({
    "msvcp140.dll", "vcruntime140_1.dll", "vcruntime140.dll",
})
_SCAN_EXTS = {".cmake", ".txt", ".bat", ".ps1", ".py", ".sh"}
_SKIP_DIRS = {"build", ".git", "__pycache__", "node_modules"}


class CP15RuntimeDownload(CheckpointBase):
    checkpoint_id = "CP15"
    name = "Runtime Download Risk"

    source_dir: str = ""  # injected by CheckpointEngine via hasattr pattern

    def _scan_dll_refs(self) -> Dict[str, List[str]]:
        """Walk source_dir for MSVC runtime DLL references.

        Returns dict mapping dll_name_lower → list of relative file paths.
        """
        refs: Dict[str, List[str]] = {}
        root = os.path.abspath(self.source_dir)

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".") and d not in _SKIP_DIRS
            ]
            for fname in filenames:
                _, ext = os.path.splitext(fname)
                if fname != "CMakeLists.txt" and ext.lower() not in _SCAN_EXTS:
                    continue
                fpath = os.path.join(dirpath, fname)
                try:
                    text = open(fpath, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                for m in _DLL_PATTERN.finditer(text):
                    dll_lower = m.group(0).lower()
                    rel = os.path.relpath(fpath, root)
                    refs.setdefault(dll_lower, [])
                    if rel not in refs[dll_lower]:
                        refs[dll_lower].append(rel)
        return refs

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        fetch_decl = self._findings_for(pr, "FetchContent_Declare")
        fetch_avail = self._findings_for(pr, "FetchContent_MakeAvailable")
        ext_proj = self._findings_for(pr, "ExternalProject_Add")

        all_downloads = fetch_decl + fetch_avail + ext_proj
        if not all_downloads:
            # Check for implicit MSVC runtime DLL references before returning N/A
            if self.source_dir:
                dll_refs = self._scan_dll_refs()
                if dll_refs:
                    found_set = set(dll_refs.keys())
                    unknown = found_set - {d.lower() for d in _KNOWN_MSVC_DLLS}
                    evidence = [
                        Evidence(
                            snippet=dll,
                            line_no=0,
                            file=files[0],
                            note=(
                                f"Copied/installed from MSVC compiler dir; "
                                f"found in {len(files)} location(s)"
                            ),
                        )
                        for dll, files in sorted(dll_refs.items())
                    ]
                    if not unknown:
                        return self._known_issue(
                            "Microsoft Visual C++ Runtime DLLs copied from local MSVC "
                            "compiler directory via file(COPY)/install(FILES) — acquired "
                            "implicitly at build time, not via CMake download mechanisms.",
                            evidence=evidence,
                            notes=[
                                "KNOWN ISSUE: msvcp140.dll / vcruntime140_1.dll / "
                                "vcruntime140.dll are covered by the Microsoft Visual C++ "
                                "Redistributable license.",
                                "Verify the MSVC Redist license is referenced in product "
                                "documentation.",
                                "No GPL/LGPL source-disclosure obligation applies to these "
                                "components.",
                            ],
                        )
                    else:
                        return self._manual(
                            "Implicit DLL dependencies detected — includes names outside "
                            "the known MSVC runtime set; additional review required.",
                            evidence=evidence,
                            notes=[
                                f"Unknown DLL (not recognized as MSVC runtime): {d}"
                                for d in sorted(unknown)
                            ],
                        )
            return self._na(
                "No runtime download mechanisms detected "
                "(FetchContent / ExternalProject_Add)."
            )

        evidence: List[Evidence] = []

        for f in fetch_decl:
            parts = f.args_text.split()
            name = parts[0] if parts else ""
            cls = license_patterns.classify_name(name) or license_patterns.classify_name(f.args_text)
            if cls:
                label = license_patterns.label_for(cls)
                note = f"FetchContent_Declare downloads {label}-licensed source at configure time — high compliance risk"
            else:
                note = "FetchContent_Declare downloads source at configure time"
            evidence.append(self._to_evidence(f, note))

        for f in fetch_avail:
            cls = license_patterns.classify_name(f.args_text)
            if cls:
                label = license_patterns.label_for(cls)
                note = f"FetchContent_MakeAvailable activates {label}-licensed content"
            else:
                note = "FetchContent_MakeAvailable activates declared content"
            evidence.append(self._to_evidence(f, note))

        for f in ext_proj:
            parts = f.args_text.split()
            name = parts[0] if parts else "unknown"
            has_url = "URL" in f.args_text.upper() or "GIT_REPOSITORY" in f.args_text.upper()
            if has_url:
                cls = license_patterns.classify_name(name) or license_patterns.classify_name(f.args_text)
                if cls:
                    label = license_patterns.label_for(cls)
                    note = f"ExternalProject '{name}' downloads {label}-licensed source at build time — verify compliance obligations"
                else:
                    note = f"ExternalProject '{name}' downloads external source at build time"
                evidence.append(self._to_evidence(f, note))

        if not evidence:
            return self._na("External projects found but none download external source.")

        return self._manual(
            "Build-time or configure-time source downloads detected — verify license of each downloaded component",
            evidence=evidence,
            notes=[
                "List each downloaded component and its SPDX license identifier",
                "GPL/LGPL downloads carry source disclosure obligations for the entire distributed product",
                "Verify the download URL is from a trusted, known-license source",
                "Consider pinning to a specific commit hash or release tag for reproducibility",
                "FetchContent and ExternalProject components may not appear in static SBOM — verify dynamically",
            ],
        )
