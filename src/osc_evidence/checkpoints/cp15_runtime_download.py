"""CP15 — Runtime Download Risk"""

from __future__ import annotations
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, MANUAL


class CP15RuntimeDownload(CheckpointBase):
    checkpoint_id = "CP15"
    name = "Runtime Download Risk"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        fetch_decl = self._findings_for(pr, "FetchContent_Declare")
        fetch_avail = self._findings_for(pr, "FetchContent_MakeAvailable")
        ext_proj = self._findings_for(pr, "ExternalProject_Add")

        all_downloads = fetch_decl + fetch_avail + ext_proj
        if not all_downloads:
            return self._na("No runtime download mechanisms detected (FetchContent / ExternalProject_Add).")

        evidence: List[Evidence] = []

        for f in fetch_decl:
            evidence.append(self._to_evidence(
                f, "FetchContent_Declare downloads source at configure time"
            ))
        for f in fetch_avail:
            evidence.append(self._to_evidence(
                f, "FetchContent_MakeAvailable activates declared content"
            ))
        for f in ext_proj:
            parts = f.args_text.split()
            name = parts[0] if parts else "unknown"
            # Check for URL or GIT_REPOSITORY
            has_url = "URL" in f.args_text.upper() or "GIT_REPOSITORY" in f.args_text.upper()
            if has_url:
                evidence.append(self._to_evidence(
                    f, f"ExternalProject '{name}' downloads external source at build time"
                ))

        if not evidence:
            return self._na("External projects found but none download external source.")

        return self._manual(
            "Build-time or configure-time source downloads detected — verify license of each downloaded component",
            evidence=evidence,
            notes=[
                "List each downloaded component and its SPDX license identifier",
                "Verify the download URL is from a trusted, known-license source",
                "Consider pinning to a specific commit hash or release tag for reproducibility",
                "FetchContent and ExternalProject components may not appear in static SBOM — verify dynamically",
            ],
        )
