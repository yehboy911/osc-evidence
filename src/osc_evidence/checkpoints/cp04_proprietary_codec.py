"""CP04 — Proprietary Codec Detection"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, FAIL, PASS

_NONFREE_PATTERN = re.compile(
    r"(--enable-nonfree|nonfree|non.free|proprietary.codec|"
    r"--enable-libfdk.aac|--enable-libfaac|commercial)",
    re.IGNORECASE,
)
_SAFE_DISABLE = re.compile(r"--disable-nonfree", re.IGNORECASE)

# config.h macros for nonfree detection
_CFG_H_NONFREE = re.compile(
    r"#\s*define\s+(CONFIG_NONFREE|CONFIG_LIBFDK_AAC)\s+(\d+)",
    re.IGNORECASE,
)


class CP04ProprietaryCodec(CheckpointBase):
    checkpoint_id = "CP04"
    name = "Proprietary Codec Detection"

    # Injected by CheckpointEngine when --config-h is provided
    config_h_path: Optional[str] = None

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        config_h_evidence = self._check_config_h()

        all_findings = pr.findings
        fail_ev: List[Evidence] = []
        pass_ev: List[Evidence] = []

        for f in all_findings:
            expanded, _ = pr.symbols.expand(f.args_text)
            if _NONFREE_PATTERN.search(expanded):
                if _SAFE_DISABLE.search(expanded):
                    pass_ev.append(self._to_evidence(
                        f, "Non-free explicitly disabled"
                    ))
                else:
                    fail_ev.append(self._to_evidence(
                        f, "Proprietary/non-free codec flag detected"
                    ))

        # config.h findings take priority
        if config_h_evidence:
            cfg_fail = [e for e in config_h_evidence if "ENABLED" in e.note]
            cfg_pass = [e for e in config_h_evidence if "disabled" in e.note.lower()]
            if cfg_fail:
                return self._fail(
                    "config.h confirms non-free codec is enabled — violates GPL redistribution terms",
                    evidence=cfg_fail + cfg_pass + fail_ev + pass_ev,
                )
            if cfg_pass and not fail_ev:
                return self._pass(
                    "config.h confirms non-free features are disabled in this FFmpeg build",
                    evidence=cfg_pass + pass_ev,
                )

        if not fail_ev and not pass_ev and not config_h_evidence:
            return self._pass(
                "No proprietary codec or non-free flags detected in build configuration"
            )
        if fail_ev:
            return self._fail(
                "Proprietary codec or non-free flag detected — may violate GPL redistribution terms",
                evidence=fail_ev + pass_ev + config_h_evidence,
            )
        return self._pass(
            "Non-free codec references found but explicitly disabled",
            evidence=pass_ev + config_h_evidence,
        )

    def _check_config_h(self) -> List[Evidence]:
        """Parse config.h for nonfree indicators if a path was provided."""
        if not self.config_h_path:
            return []
        try:
            text = Path(self.config_h_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        evidence: List[Evidence] = []
        for m in _CFG_H_NONFREE.finditer(text):
            macro, value = m.group(1), m.group(2)
            if value == "1":
                evidence.append(Evidence(
                    snippet=m.group(0).strip(),
                    line_no=0,
                    file=self.config_h_path,
                    note=f"{macro}=1 — non-free codec ENABLED in this build",
                ))
            else:
                evidence.append(Evidence(
                    snippet=m.group(0).strip(),
                    line_no=0,
                    file=self.config_h_path,
                    note=f"{macro}=0 — non-free codec disabled",
                ))
        return evidence
