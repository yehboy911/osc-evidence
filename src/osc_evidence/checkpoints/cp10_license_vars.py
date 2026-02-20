"""CP10 — License Variable Declarations"""

from __future__ import annotations
from typing import List
from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, PASS, MANUAL


class CP10LicenseVars(CheckpointBase):
    checkpoint_id = "CP10"
    name = "License Variable Declarations"

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        license_findings = [
            f for f in pr.findings
            if f.subtype == "license_var"
        ]

        if not license_findings:
            return self._manual(
                "No license variable declarations found — license type is not documented in CMake build system",
                notes=[
                    "Add: set(SPDX_LICENSE \"MIT\") or set(LICENSE \"Apache-2.0\") to root CMakeLists.txt",
                    "This provides machine-readable license metadata for SBOM generation",
                ],
            )

        evidence: List[Evidence] = []
        for f in license_findings:
            evidence.append(self._to_evidence(
                f, f"License variable declared via {f.command}()"
            ))

        return self._pass(
            "License variable(s) declared in CMake build system — license type is documented",
            evidence=evidence,
        )
