"""
checkpoint_engine.py
====================
Runs all 15 checkpoints in order and returns results.
"""

from __future__ import annotations
from typing import List, Optional

from .cmake_parser import ParseResult
from .checkpoints.base import CheckpointResult
from .gpl_scanner import GplComponent
from typing import Set
from .checkpoints.cp01_gpl_flags import CP01GplFlags
from .checkpoints.cp02_lgpl_linking import CP02LgplLinking
from .checkpoints.cp03_test_exclusion import CP03TestExclusion
from .checkpoints.cp04_proprietary_codec import CP04ProprietaryCodec
from .checkpoints.cp05_gpl_lib_id import CP05GplLibId
from .checkpoints.cp06_static_gpl_risk import CP06StaticGplRisk
from .checkpoints.cp07_install_scope import CP07InstallScope
from .checkpoints.cp08_source_traceability import CP08SourceTraceability
from .checkpoints.cp09_conditional_guards import CP09ConditionalGuards
from .checkpoints.cp10_license_vars import CP10ExtlibsAudit
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
    CP10ExtlibsAudit(),
    CP11SubmoduleIsolation(),
    CP12LinkVisibility(),
    CP13ExternalGplOpts(),
    CP14CompileDefinitions(),
    CP15RuntimeDownload(),
]


class CheckpointEngine:
    def run_all(
        self,
        parse_result: ParseResult,
        config_h_path: Optional[str] = None,
        gpl_components: Optional[List[GplComponent]] = None,
        source_dir: Optional[str] = None,
        sbom_all_names: Optional[Set[str]] = None,
    ) -> List[CheckpointResult]:
        results: List[CheckpointResult] = []
        for cp in _ALL_CHECKPOINTS:
            try:
                # Inject config_h_path into checkpoints that support it
                if config_h_path is not None and hasattr(cp, "config_h_path"):
                    cp.config_h_path = config_h_path
                # Inject gpl_components into CP06/CP10
                if hasattr(cp, "gpl_components"):
                    cp.gpl_components = gpl_components or []
                # Inject source_dir into CP10
                if source_dir is not None and hasattr(cp, "source_dir"):
                    cp.source_dir = source_dir
                # Inject full SBOM name set into CP10
                if sbom_all_names is not None and hasattr(cp, "sbom_all_names"):
                    cp.sbom_all_names = sbom_all_names
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
