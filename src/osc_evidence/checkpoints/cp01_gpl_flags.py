"""CP01 — GPL Build Flags"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from ..cmake_parser import ParseResult
from .base import CheckpointBase, CheckpointResult, Evidence, FAIL, MANUAL, PASS

# config.h macros that indicate GPL or nonfree build
_CFG_H_GPL = re.compile(
    r"#\s*define\s+(CONFIG_GPL|CONFIG_GPLV3|CONFIG_VERSION3|CONFIG_LGPLV3)\s+(\d+)",
    re.IGNORECASE,
)
_CFG_H_GPL_LIB = re.compile(
    r"#\s*define\s+(CONFIG_LIBX264|CONFIG_LIBX265|CONFIG_LIBXVID)\s+(\d+)",
    re.IGNORECASE,
)
_CFG_H_LICENSE = re.compile(
    r'#\s*define\s+FFMPEG_LICENSE\s+"([^"]+)"',
    re.IGNORECASE,
)


class CP01GplFlags(CheckpointBase):
    checkpoint_id = "CP01"
    name = "GPL Build Flags"

    # Injected by CheckpointEngine when --config-h is provided
    config_h_path: Optional[str] = None

    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        config_h_evidence = self._check_config_h()

        eps = self._findings_for(pr, "ExternalProject_Add")

        disable_found: List[Evidence] = []
        enable_found: List[Evidence] = []
        manual_found: List[Evidence] = []

        for f in eps:
            if f.subtype == "disable_gpl":
                disable_found.append(self._to_evidence(
                    f, "GPL explicitly disabled via configure flag"
                ))
            elif f.subtype == "enable_gpl":
                enable_found.append(self._to_evidence(
                    f, "GPL explicitly ENABLED — triggers GPL obligations on distribution"
                ))
            elif f.subtype in ("gpl_flag", "nonfree"):
                manual_found.append(self._to_evidence(
                    f, "GPL-related flag detected — verify whether it enables or disables GPL"
                ))

        # config.h findings take highest priority
        if config_h_evidence:
            fail_cfg = [e for e in config_h_evidence if "ENABLED" in e.note or "GPL-only lib" in e.note]
            pass_cfg = [e for e in config_h_evidence if "disabled" in e.note.lower()]
            if fail_cfg:
                return self._fail(
                    "config.h confirms GPL features are enabled in this FFmpeg build",
                    evidence=fail_cfg + pass_cfg + enable_found + disable_found + manual_found,
                )
            if pass_cfg and not enable_found and not manual_found:
                return self._pass(
                    "config.h confirms GPL features are disabled in this FFmpeg build",
                    evidence=pass_cfg + disable_found,
                )
            return self._manual(
                "config.h present but GPL status is ambiguous — manual review required",
                evidence=config_h_evidence + enable_found + disable_found + manual_found,
                notes=["Inspect FFMPEG_LICENSE, CONFIG_GPL, and CONFIG_LIBX264/X265 in config.h"],
            )

        if not eps:
            return self._na("No ExternalProject_Add calls found.")

        if enable_found:
            return self._fail(
                "GPL features explicitly enabled in ExternalProject configure command",
                evidence=enable_found + disable_found + manual_found,
            )
        if disable_found and not manual_found:
            return self._pass(
                "GPL features explicitly disabled via --disable-gpl in configure command",
                evidence=disable_found,
            )
        if manual_found or disable_found:
            return self._manual(
                "Mixed or ambiguous GPL configure flags — manual review required",
                evidence=disable_found + manual_found,
                notes=["Verify each --enable-*/--disable-* flag in CONFIGURE_COMMAND"],
            )
        return self._na("No GPL configure flags found in ExternalProject_Add calls.")

    def _check_config_h(self) -> List[Evidence]:
        """Parse config.h for GPL/nonfree indicators if a path was provided."""
        if not self.config_h_path:
            return []
        try:
            text = Path(self.config_h_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return [Evidence(
                snippet=f"config.h: {self.config_h_path}",
                line_no=0,
                file=self.config_h_path,
                note=f"Cannot read config.h: {self.config_h_path}",
            )]

        evidence: List[Evidence] = []

        # FFMPEG_LICENSE string
        m = _CFG_H_LICENSE.search(text)
        if m:
            lic = m.group(1)
            note = f"FFMPEG_LICENSE = \"{lic}\""
            if "GPL" in lic.upper() and "LGPL" not in lic.upper():
                note += " — GPL build confirmed"
            evidence.append(Evidence(
                snippet=m.group(0).strip(),
                line_no=0,
                file=self.config_h_path,
                note=note,
            ))

        # CONFIG_GPL / CONFIG_GPLV3 / etc.
        for m in _CFG_H_GPL.finditer(text):
            macro, value = m.group(1), m.group(2)
            if value == "1":
                evidence.append(Evidence(
                    snippet=m.group(0).strip(),
                    line_no=0,
                    file=self.config_h_path,
                    note=f"{macro}=1 — GPL feature ENABLED in this build",
                ))
            else:
                evidence.append(Evidence(
                    snippet=m.group(0).strip(),
                    line_no=0,
                    file=self.config_h_path,
                    note=f"{macro}=0 — GPL feature disabled",
                ))

        # GPL-only library switches
        for m in _CFG_H_GPL_LIB.finditer(text):
            macro, value = m.group(1), m.group(2)
            if value == "1":
                evidence.append(Evidence(
                    snippet=m.group(0).strip(),
                    line_no=0,
                    file=self.config_h_path,
                    note=f"{macro}=1 — GPL-only lib enabled, triggers GPL obligations",
                ))

        return evidence
