"""
symbol_table.py
===============
Tracks CMake option() and set() variable declarations.

Supports partial ${VAR} substitution: known variables are expanded,
unknown ones are left as-is and flagged so callers can emit MANUAL verdicts.
"""

from __future__ import annotations

import re
from typing import Dict, Optional, Set, Tuple


_VAR_REF = re.compile(r"\$\{([^}]+)\}")


class SymbolTable:
    """
    Simple key→value store built from CMake ``option()`` and ``set()`` calls.

    ``option(FOO "description" ON)``  → stores FOO=ON
    ``set(MY_VAR some_value)``        → stores MY_VAR=some_value
    """

    def __init__(self) -> None:
        self._vars: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Population
    # ------------------------------------------------------------------

    def process_option(self, args_text: str) -> None:
        """Parse the argument list of an option() call."""
        parts = args_text.split()
        if not parts:
            return
        name = parts[0]
        default = parts[-1] if len(parts) >= 3 else "OFF"
        self._vars[name] = default

    def process_set(self, args_text: str) -> None:
        """Parse the argument list of a set() call."""
        parts = args_text.split(None, 1)
        if len(parts) < 2:
            return
        name = parts[0]
        value = parts[1].strip().strip('"')
        # Cache / parent scope keywords are not values
        for kw in ("CACHE", "PARENT_SCOPE", "FORCE"):
            idx = value.find(kw)
            if idx != -1:
                value = value[:idx].strip()
                break
        self._vars[name] = value

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def get(self, name: str) -> Optional[str]:
        return self._vars.get(name)

    def expand(self, text: str) -> Tuple[str, Set[str]]:
        """
        Expand all ``${VAR}`` references in *text*.

        Returns ``(expanded_text, unresolved_vars)`` where *unresolved_vars*
        is the set of variable names that could not be resolved.
        """
        unresolved: Set[str] = set()

        def replacer(m: re.Match) -> str:
            var = m.group(1)
            if var in self._vars:
                return self._vars[var]
            unresolved.add(var)
            return m.group(0)  # leave ${VAR} in place

        expanded = _VAR_REF.sub(replacer, text)
        return expanded, unresolved

    def all_vars(self) -> Dict[str, str]:
        return dict(self._vars)

    def __contains__(self, name: str) -> bool:
        return name in self._vars

    def __len__(self) -> int:
        return len(self._vars)
