"""
checkpoint_engine.py
====================
Runs all 15 checkpoints in order and returns results.
"""

from __future__ import annotations
from typing import List

from .cmake_parser import ParseResult
from .checkpoints.base import CheckpointResult
from .checkpoints.cp01_gpl_flags import CP01GplFlags
from .checkpoints.cp02_lgpl_linking import CP02LgplLinking
from .checkpoints.cp03_test_exclusion import CP03TestExclusion
from .checkpoints.cp04_proprietary_codec import CP04ProprietaryCodec
from .checkpoints.cp05_gpl_lib_id import CP05GplLibId
from .checkpoints.cp06_static_gpl_risk import CP06StaticGplRisk
from .checkpoints.cp07_install_scope import CP07InstallScope
from .checkpoints.cp08_source_traceability import CP08SourceTraceability
from .checkpoints.cp09_conditional_guards import CP09ConditionalGuards
from .checkpoints.cp10_license_vars import CP10LicenseVars
from .checkpoints.cp11_submodule_isolation import CP11SubmoduleIsolation
from .checkpoints.cp12_link_visibility import CP12LinkVisibility
from .checkpoints.cp13_external_gpl_opts import CP13ExternalGplOpts
from .checkpoints.cp14_compile_definitions import CP14CompileDefinitions
from .checkpoints.cp15_runtime_download import CP15RuntimeDownload


_ALL_CHECKPOINTS = [
    CP01GplFlags(),
    CP02LgplLinking(),
    CP03TestExclusion(),
    CP04ProprietaryCodec(),
    CP05GplLibId(),
    CP06StaticGplRisk(),
    CP07InstallScope(),
    CP08SourceTraceability(),
    CP09ConditionalGuards(),
    CP10LicenseVars(),
    CP11SubmoduleIsolation(),
    CP12LinkVisibility(),
    CP13ExternalGplOpts(),
    CP14CompileDefinitions(),
    CP15RuntimeDownload(),
]


class CheckpointEngine:
    def run_all(self, parse_result: ParseResult) -> List[CheckpointResult]:
        results: List[CheckpointResult] = []
        for cp in _ALL_CHECKPOINTS:
            try:
                result = cp.run(parse_result)
            except Exception as exc:
                from .checkpoints.base import CheckpointResult, MANUAL
                result = CheckpointResult(
                    checkpoint_id=cp.checkpoint_id,
                    name=cp.name,
                    verdict=MANUAL,
                    legal_translation=f"Checkpoint error: {exc}",
                    manual_notes=[f"Internal error during evaluation: {exc}"],
                )
            results.append(result)
        return results
