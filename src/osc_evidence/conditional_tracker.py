"""
conditional_tracker.py
======================
Stack-based if/elseif/else/endif tracker for CMake conditional blocks.

Each RawFinding carries a snapshot of the condition stack at the point
where it was discovered, allowing downstream checkpoints to determine
whether a construct is unconditional or guarded.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ConditionFrame:
    """One level of a CMake if/endif block."""
    condition: str          # raw text of the if(...) expression
    branch: str             # "if" | "elseif" | "else"
    line_no: int
    is_negated: bool = False   # True when condition starts with NOT


class ConditionalTracker:
    """
    Tracks CMake if/elseif/else/endif nesting.

    Usage::

        tracker = ConditionalTracker()
        for line_no, line in enumerate(lines, 1):
            tracker.feed(line_no, line)
            stack_snapshot = tracker.snapshot()
            # ... emit finding with stack_snapshot

    The *snapshot* is a shallow copy of the current stack; it is safe to
    store alongside a RawFinding without aliasing issues.
    """

    def __init__(self) -> None:
        self._stack: List[ConditionFrame] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def feed(self, line_no: int, text: str) -> None:
        """Process one (already-stripped) CMake line."""
        lower = text.lower().lstrip()

        if lower.startswith("if(") or lower.startswith("if ("):
            cond = self._extract_arg(text)
            negated = cond.lstrip().upper().startswith("NOT ")
            self._stack.append(ConditionFrame(
                condition=cond,
                branch="if",
                line_no=line_no,
                is_negated=negated,
            ))

        elif lower.startswith("elseif(") or lower.startswith("elseif ("):
            cond = self._extract_arg(text)
            negated = cond.lstrip().upper().startswith("NOT ")
            if self._stack:
                self._stack[-1] = ConditionFrame(
                    condition=cond,
                    branch="elseif",
                    line_no=line_no,
                    is_negated=negated,
                )

        elif lower.startswith("else(") or lower == "else()":
            if self._stack:
                top = self._stack[-1]
                self._stack[-1] = ConditionFrame(
                    condition=top.condition,
                    branch="else",
                    line_no=line_no,
                    is_negated=not top.is_negated,
                )

        elif lower.startswith("endif(") or lower == "endif()":
            if self._stack:
                self._stack.pop()

    def snapshot(self) -> List[ConditionFrame]:
        """Return a shallow copy of the current stack."""
        return list(self._stack)

    def depth(self) -> int:
        return len(self._stack)

    def is_unconditional(self) -> bool:
        return len(self._stack) == 0

    def is_guarded_by(self, keyword: str) -> bool:
        """Return True if any frame in the stack contains *keyword* (case-insensitive)."""
        kw = keyword.upper()
        return any(kw in frame.condition.upper() for frame in self._stack)

    def stack_summary(self) -> str:
        """Human-readable one-liner of the current stack."""
        if not self._stack:
            return "(unconditional)"
        parts = []
        for frame in self._stack:
            parts.append(f"{frame.branch}({frame.condition})")
        return " > ".join(parts)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_arg(text: str) -> str:
        """Extract the argument of the outermost CMake command call."""
        start = text.find("(")
        end = text.rfind(")")
        if start == -1:
            return text
        if end == -1 or end <= start:
            return text[start + 1:].strip()
        return text[start + 1:end].strip()
