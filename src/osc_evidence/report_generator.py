"""
report_generator.py
===================
Renders the compliance audit results as a Markdown document.

Output language: English (for legal counsel Dennis).
"""

from __future__ import annotations

import datetime
from typing import List

from .cmake_parser import CmakeTarget, ParseResult
from .checkpoints.base import CheckpointResult, PASS, FAIL, MANUAL, NA


# Tier grouping for report display
_TIERS = [
    ("Tier 1: GPL/LGPL Direct Risk Detection", ["CP01", "CP02", "CP04", "CP05", "CP06"]),
    ("Tier 2: Build System Hygiene", ["CP03", "CP07", "CP08", "CP09", "CP10", "CP11", "CP12"]),
    ("Tier 3: External Source Tracking", ["CP13", "CP14", "CP15"]),
]

_VERDICT_BADGE = {
    PASS:   "**PASS**",
    FAIL:   "**FAIL**",
    MANUAL: "_MANUAL_",
    NA:     "N/A",
}


class ReportGenerator:
    def __init__(
        self,
        source_dir: str,
        parse_result: ParseResult,
        checkpoint_results: List[CheckpointResult],
    ) -> None:
        self.source_dir = source_dir
        self.pr = parse_result
        self.results = checkpoint_results
        self.generated = datetime.date.today().isoformat()

    def render(self) -> str:
        parts = [
            self._header(),
            self._summary_table(),
            self._checkpoint_table(),
            self._build_graph(),
            self._manual_section(),
            self._parser_warnings(),
        ]
        return "\n\n".join(p for p in parts if p)

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _header(self) -> str:
        return (
            "# OSC Compliance Report\n\n"
            f"- **Generated:** {self.generated}\n"
            f"- **Source Directory:** `{self.source_dir}`\n"
            f"- **CMake Files Scanned:** {self.pr.files_scanned}\n"
            f"- **Targets Found:** {len(self.pr.targets)}\n"
            f"- **Findings Collected:** {len(self.pr.findings)}"
        )

    def _summary_table(self) -> str:
        counts = {PASS: 0, FAIL: 0, MANUAL: 0, NA: 0}
        for r in self.results:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1

        rows = "\n".join(
            f"| {v} | {counts[v]} |"
            for v in (PASS, FAIL, MANUAL, NA)
        )

        results_by_id = {r.checkpoint_id: r for r in self.results}

        tier_rows: List[str] = []
        for tier_label, cp_ids in _TIERS:
            tc = {PASS: 0, FAIL: 0, MANUAL: 0, NA: 0}
            for cp_id in cp_ids:
                r = results_by_id.get(cp_id)
                if r:
                    tc[r.verdict] = tc.get(r.verdict, 0) + 1
            tier_rows.append(
                f"| {tier_label} | {tc[PASS]} | {tc[FAIL]} | {tc[MANUAL]} | {tc[NA]} |"
            )

        return (
            "## Summary\n\n"
            "| Status | Count |\n"
            "|--------|-------|\n"
            + rows
            + "\n\n### Per-Tier Breakdown\n\n"
            "| Tier | PASS | FAIL | MANUAL | N/A |\n"
            "|------|------|------|--------|-----|\n"
            + "\n".join(tier_rows)
        )

    def _checkpoint_table(self) -> str:
        results_by_id = {r.checkpoint_id: r for r in self.results}

        table_header = (
            "| Checkpoint | Status | Legal Translation | Evidence (Code Snippet) | Line | File |\n"
            "|---|---|---|---|---|---|"
        )

        sections: List[str] = ["## OSC Compliance Checkpoints"]

        for tier_label, cp_ids in _TIERS:
            rows: List[str] = []
            for cp_id in cp_ids:
                r = results_by_id.get(cp_id)
                if not r:
                    continue
                badge = _VERDICT_BADGE.get(r.verdict, r.verdict)
                ev = r.primary_evidence()
                if ev:
                    snippet = self._escape_md(ev.snippet[:120])
                    line = "—" if ev.line_no == 0 else str(ev.line_no)
                    file_ = self._short_path(ev.file)
                else:
                    snippet = "—"
                    line = "—"
                    file_ = "—"
                legal = self._escape_md(r.legal_translation)
                cp_label = f"{r.checkpoint_id} — {r.name}"
                rows.append(
                    f"| {cp_label} | {badge} | {legal} | `{snippet}` | {line} | {file_} |"
                )
            if rows:
                sections.append(f"### {tier_label}\n\n{table_header}\n" + "\n".join(rows))

        return "\n\n".join(sections)

    def _build_graph(self) -> str:
        if not self.pr.targets:
            return ""

        lines = ["## Build Graph Summary", ""]
        for t in sorted(self.pr.targets, key=lambda x: x.file):
            label = f"[{t.target_type}]"
            tags: List[str] = []
            if t.is_test:
                tags.append("TEST target")
            if t.exclude_from_all:
                tags.append("EXCLUDE_FROM_ALL")
            tag_str = f" ({', '.join(tags)})" if tags else ""
            lines.append(
                f"- Target `{t.name}` {label} — `{t.file}` line {t.line_no}{tag_str}"
            )
        return "\n".join(lines)

    def _manual_section(self) -> str:
        manual_results = [r for r in self.results if r.verdict == MANUAL]
        fail_results = [r for r in self.results if r.verdict == FAIL]

        if not manual_results and not fail_results:
            return ""

        # Build lookup: checkpoint_id → tier label
        cp_to_tier = {}
        for tier_label, cp_ids in _TIERS:
            for cp_id in cp_ids:
                cp_to_tier[cp_id] = tier_label

        parts = ["## Action Items"]

        for verdict_label, result_set in [
            ("FAIL — Immediate Attention Required", fail_results),
            ("MANUAL — Human Review Required", manual_results),
        ]:
            if not result_set:
                continue
            parts.append(f"\n### {verdict_label}\n")

            # Group results by tier, preserving tier order
            tier_groups: List[tuple] = []
            seen_tiers: set = set()
            for tier_label, cp_ids in _TIERS:
                tier_results = [r for r in result_set if r.checkpoint_id in cp_ids]
                if tier_results:
                    tier_groups.append((tier_label, tier_results))

            for tier_label, tier_results in tier_groups:
                parts.append(f"#### {tier_label}\n")
                for r in tier_results:
                    parts.append(f"##### {r.checkpoint_id} — {r.name}\n")
                    parts.append(f"**Finding:** {r.legal_translation}\n")
                    if r.verdict == MANUAL and r.manual_notes:
                        for note in r.manual_notes:
                            parts.append(f"- {note}")
                        parts.append("")
                    for ev in r.evidence:
                        loc = f"— {ev.file}" if ev.line_no == 0 else f"— {ev.file} line {ev.line_no}"
                        parts.append(f"- `{self._escape_md(ev.snippet[:120])}` {loc}")
                        if ev.note:
                            parts.append(f"  - *{ev.note}*")
                    parts.append("")

        return "\n".join(parts)

    def _parser_warnings(self) -> str:
        if not self.pr.warnings:
            return ""
        lines = ["## Parser Warnings", ""]
        for w in self.pr.warnings:
            lines.append(f"- {w}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _escape_md(text: str) -> str:
        """Escape pipe characters so they don't break Markdown tables."""
        return text.replace("|", "\\|").replace("\n", " ")

    @staticmethod
    def _short_path(path: str) -> str:
        """Shorten long paths for display."""
        parts = path.replace("\\", "/").split("/")
        if len(parts) <= 3:
            return path
        return "…/" + "/".join(parts[-2:])
