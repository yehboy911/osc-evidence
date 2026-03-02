"""
base.py
=======
Abstract base class and result dataclass for all OSC checkpoints.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

from ..cmake_parser import ParseResult, RawFinding


# Allowed verdict values
PASS = "PASS"
FAIL = "FAIL"
MANUAL = "MANUAL"
NA = "N/A"
KNOWN_ISSUE = "KNOWN ISSUE"


@dataclass
class Evidence:
    """A single piece of evidence supporting a checkpoint verdict."""
    snippet: str          # code snippet shown in report
    line_no: int
    file: str
    note: str = ""        # human-readable legal interpretation


@dataclass
class CheckpointResult:
    checkpoint_id: str           # e.g. "CP01"
    name: str                    # e.g. "GPL Build Flags"
    verdict: str                 # PASS | FAIL | MANUAL | N/A
    legal_translation: str       # one sentence for the legal column
    evidence: List[Evidence] = field(default_factory=list)
    manual_notes: List[str] = field(default_factory=list)

    def primary_evidence(self) -> Optional[Evidence]:
        return self.evidence[0] if self.evidence else None


class CheckpointBase(ABC):
    """All checkpoints inherit from this class."""

    checkpoint_id: str = ""
    name: str = ""

    def run(self, parse_result: ParseResult) -> CheckpointResult:
        return self._evaluate(parse_result)

    @abstractmethod
    def _evaluate(self, pr: ParseResult) -> CheckpointResult:
        ...

    # Convenience constructors
    def _pass(self, legal: str, evidence: List[Evidence] = None) -> CheckpointResult:
        return CheckpointResult(
            checkpoint_id=self.checkpoint_id,
            name=self.name,
            verdict=PASS,
            legal_translation=legal,
            evidence=evidence or [],
        )

    def _fail(self, legal: str, evidence: List[Evidence] = None) -> CheckpointResult:
        return CheckpointResult(
            checkpoint_id=self.checkpoint_id,
            name=self.name,
            verdict=FAIL,
            legal_translation=legal,
            evidence=evidence or [],
        )

    def _manual(
        self, legal: str, evidence: List[Evidence] = None, notes: List[str] = None
    ) -> CheckpointResult:
        return CheckpointResult(
            checkpoint_id=self.checkpoint_id,
            name=self.name,
            verdict=MANUAL,
            legal_translation=legal,
            evidence=evidence or [],
            manual_notes=notes or [],
        )

    def _known_issue(
        self, legal: str, evidence: List[Evidence] = None, notes: List[str] = None
    ) -> CheckpointResult:
        return CheckpointResult(
            checkpoint_id=self.checkpoint_id,
            name=self.name,
            verdict=KNOWN_ISSUE,
            legal_translation=legal,
            evidence=evidence or [],
            manual_notes=notes or [],
        )

    def _na(self, legal: str = "No relevant CMake constructs found.") -> CheckpointResult:
        return CheckpointResult(
            checkpoint_id=self.checkpoint_id,
            name=self.name,
            verdict=NA,
            legal_translation=legal,
        )

    @staticmethod
    def _findings_for(pr: ParseResult, command: str) -> List[RawFinding]:
        return [f for f in pr.findings if f.command == command]

    @staticmethod
    def _findings_for_subtype(pr: ParseResult, subtype: str) -> List[RawFinding]:
        return [f for f in pr.findings if f.subtype == subtype]

    @staticmethod
    def _to_evidence(finding: RawFinding, note: str = "") -> Evidence:
        return Evidence(
            snippet=finding.snippet,
            line_no=finding.line_no,
            file=finding.file,
            note=note,
        )
