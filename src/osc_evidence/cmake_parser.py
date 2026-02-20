"""
cmake_parser.py
===============
CMake parser for OSC evidence gathering.

Walks a source tree, reads every CMakeLists.txt, and emits:
  - CmakeTarget  — every add_library / add_executable / add_custom_target
  - RawFinding   — every OSC-relevant CMake construct

Also populates a SymbolTable (option/set) and a ConditionalTracker per file.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from .conditional_tracker import ConditionFrame as ConditionalFrame, ConditionalTracker
from .symbol_table import SymbolTable


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CmakeTarget:
    name: str
    target_type: str          # SHARED | STATIC | EXECUTABLE | CUSTOM | INTERFACE | OBJECT
    file: str                 # relative path to CMakeLists.txt
    line_no: int
    is_test: bool = False
    exclude_from_all: bool = False
    platform: str = "common"  # common | windows | linux


@dataclass
class RawFinding:
    """One OSC-relevant construct found in a CMakeLists.txt."""
    command: str              # e.g. "ExternalProject_Add", "target_link_libraries"
    subtype: str              # e.g. "disable_gpl", "shared_link", ""
    args_text: str            # raw argument text (may contain ${VAR})
    file: str                 # relative path
    line_no: int
    snippet: str              # the actual source line(s) as a short excerpt
    condition_stack: List[ConditionalFrame] = field(default_factory=list)
    unresolved_vars: List[str] = field(default_factory=list)

    def is_unconditional(self) -> bool:
        return len(self.condition_stack) == 0

    def is_guarded_by(self, keyword: str) -> bool:
        kw = keyword.upper()
        return any(kw in f.condition.upper() for f in self.condition_stack)


@dataclass
class ParseResult:
    targets: List[CmakeTarget] = field(default_factory=list)
    findings: List[RawFinding] = field(default_factory=list)
    symbols: SymbolTable = field(default_factory=SymbolTable)
    warnings: List[str] = field(default_factory=list)
    files_scanned: int = 0


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Targets
_RE_ADD_LIBRARY = re.compile(
    r"^\s*add_library\s*\((.+)\)", re.IGNORECASE | re.DOTALL
)
_RE_ADD_EXECUTABLE = re.compile(
    r"^\s*add_executable\s*\((.+)\)", re.IGNORECASE | re.DOTALL
)
_RE_ADD_CUSTOM_TARGET = re.compile(
    r"^\s*add_custom_target\s*\((.+)\)", re.IGNORECASE | re.DOTALL
)

# Variable declarations
_RE_OPTION = re.compile(r"^\s*option\s*\((.+)\)", re.IGNORECASE | re.DOTALL)
_RE_SET = re.compile(r"^\s*set\s*\((.+)\)", re.IGNORECASE | re.DOTALL)

# OSC-relevant commands
_RE_EP_ADD = re.compile(
    r"^\s*ExternalProject_Add\s*\((.+)\)", re.IGNORECASE | re.DOTALL
)
_RE_FETCH_DECLARE = re.compile(
    r"^\s*FetchContent_Declare\s*\((.+)\)", re.IGNORECASE | re.DOTALL
)
_RE_FETCH_MAKEAVAIL = re.compile(
    r"^\s*FetchContent_MakeAvailable\s*\((.+)\)", re.IGNORECASE | re.DOTALL
)
_RE_TARGET_LINK = re.compile(
    r"^\s*target_link_libraries\s*\((.+)\)", re.IGNORECASE | re.DOTALL
)
_RE_TARGET_SOURCES = re.compile(
    r"^\s*target_sources\s*\((.+)\)", re.IGNORECASE | re.DOTALL
)
_RE_TARGET_COMPILE_DEFS = re.compile(
    r"^\s*target_compile_definitions\s*\((.+)\)", re.IGNORECASE | re.DOTALL
)
_RE_ADD_SUBDIR = re.compile(
    r"^\s*add_subdirectory\s*\((.+)\)", re.IGNORECASE | re.DOTALL
)
_RE_INSTALL = re.compile(
    r"^\s*install\s*\((.+)\)", re.IGNORECASE | re.DOTALL
)

# GPL/LGPL keyword patterns (used in sub-analysis)
_GPL_KEYWORDS = re.compile(
    r"\b(gpl|lgpl|x264|x265|ffmpeg|openh264|lame|faac|xvid|divx|libav)\b",
    re.IGNORECASE,
)
_GPL_FLAGS = re.compile(
    r"--(enable|disable)-(gpl|nonfree|version3|libx264|libx265|libfdk[_-]aac|libopenh264|libxvid|libmp3lame)",
    re.IGNORECASE,
)
_NONFREE = re.compile(r"(nonfree|non[_-]free|proprietary_codec)", re.IGNORECASE)
_LICENSE_VAR = re.compile(
    r"\b(LICENSE|SPDX_LICENSE|LICENSE_TYPE|LICENSE_ID|COMPONENT_LICENSE)\b",
    re.IGNORECASE,
)
_STATIC_KW = re.compile(r"\bSTATIC\b")
_SHARED_KW = re.compile(r"\bSHARED\b")
_EXCL_FROM_ALL = re.compile(r"\bEXCLUDE_FROM_ALL\b", re.IGNORECASE)
_BUILD_TESTING = re.compile(r"\bBUILD_TESTING\b", re.IGNORECASE)
_CONFIGURE_CMD = re.compile(r"\bCONFIGURE_COMMAND\b", re.IGNORECASE)
_LINK_VIS = re.compile(r"\b(PRIVATE|PUBLIC|INTERFACE)\b")
_TEST_NAMES = re.compile(
    r"(test|tests|spec|specs|gtest|gmock|catch|sample|example|demo|bench)",
    re.IGNORECASE,
)
_THIRD_PARTY = re.compile(
    r"(third.?party|vendor|extern|external|deps?|thirdparty)",
    re.IGNORECASE,
)
_SKIP_TARGET_TYPES = {"IMPORTED", "INTERFACE", "OBJECT", "ALIAS"}
_SKIP_DIR_NAMES = frozenset({
    # Previous additions
    "vm", "vms",
    # Line 16 — Directories to remove
    "test", "tests", "unittests", "unit-test", "cts",
    "sample", "samples", "example", "examples", "demo",
    "prebuilts", "sdk", "pdk", "toolchain", "tools", "ccu_tool",
    "development", "template", "spec", "assets", "images", "etc",
    "internal-prebuilds", "integration-test",
    "compilercommon", "compiler", "compilationtests",
    "developers", "compatibility", "ndk", "dummy",
    "resources", "data", "libffi_msvc", "libffi_osx",
    "cmake", "logs", "models", "results", "m4",
    "patches", "config", "sound", "video", "autoconf",
    "doc", "docs", "autotest", "tutorial", "tutorials",
    "icons", "build-aux", "build",
})
_SKIP_DIR_PREFIXES = ("kernel-",)  # matches kernel-4.19, kernel-5.10, etc.
_BUILTIN_EXCLUDE_PREFIXES = (
    "kernel",                    # line 19: kernel/
    "motorola/build",            # line 17
    "motorola/build_tools",      # line 17
    "vendor/google",             # GMS
    "vendor/partner_gms",        # GMS
    "vendor/partner_modules",    # GMS
    "vendor/softbank/preloads",  # 3rd-app
    "vendor/vzw/preloads",       # 3rd-app
    "platform_testing",          # line 18
)


def _matches_any_prefix(rel_path: str, prefixes: tuple) -> bool:
    """True if rel_path equals or is a descendant of any prefix path."""
    for p in prefixes:
        if rel_path == p or rel_path.startswith(p + "/"):
            return True
    return False


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class CMakeParser:
    """
    Walk a source directory and parse all CMakeLists.txt files.

    Returns a ParseResult containing targets, findings, and symbols.
    """

    def __init__(self, source_dir: str, exclude_dirs: List[str] = None) -> None:
        self.source_dir = Path(source_dir).resolve()
        # Normalise to forward-slash relative prefixes for comparison
        self._exclude_prefixes = tuple(
            p.replace("\\", "/").strip("/")
            for p in (exclude_dirs or [])
        )

    def parse(self) -> ParseResult:
        result = ParseResult()
        for cmake_file in self._find_cmake_files():
            rel = str(cmake_file.relative_to(self.source_dir))
            try:
                self._parse_file(cmake_file, rel, result)
                result.files_scanned += 1
            except (OSError, UnicodeDecodeError) as exc:
                result.warnings.append(f"Cannot read {rel}: {exc}")
        return result

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    def _find_cmake_files(self) -> Iterator[Path]:
        all_prefixes = _BUILTIN_EXCLUDE_PREFIXES + self._exclude_prefixes

        for root, dirs, files in os.walk(self.source_dir):
            rel_root = Path(root).relative_to(self.source_dir)
            rel_str = str(rel_root).replace("\\", "/")

            # 1. Name-based pruning: hidden, skip-list, and prefix-match (e.g. kernel-*)
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".")
                and d.lower() not in _SKIP_DIR_NAMES
                and not any(d.lower().startswith(p) for p in _SKIP_DIR_PREFIXES)
            ]

            # 2. Path-based pruning: built-in rules + CLI --exclude flags
            if all_prefixes:
                dirs[:] = [
                    d for d in dirs
                    if not _matches_any_prefix(
                        str(rel_root / d).replace("\\", "/"), all_prefixes
                    )
                ]
                # Also skip processing files in the current root if it's excluded
                if rel_str != "." and _matches_any_prefix(rel_str, all_prefixes):
                    continue

            for fname in files:
                if fname == "CMakeLists.txt":   # .cmake files excluded per lines 13/21
                    yield Path(root) / fname

    # ------------------------------------------------------------------
    # Per-file parsing
    # ------------------------------------------------------------------

    def _parse_file(
        self, path: Path, rel_path: str, result: ParseResult
    ) -> None:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        lines = raw.splitlines()
        tracker = ConditionalTracker()
        # Pass result.symbols so option()/set() are global across all files
        symbols = result.symbols

        # Multi-line accumulation state
        accumulated: List[str] = []
        acc_start_line: int = 0
        paren_depth: int = 0

        for line_no, line in enumerate(lines, 1):
            # Feed tracker BEFORE we consume the line so that the stack
            # reflects the state *at* this line.
            stripped = line.strip()

            # Skip pure comment lines
            if stripped.startswith("#"):
                continue

            # Strip inline comments
            code = self._strip_comment(stripped)
            if not code:
                tracker.feed(line_no, stripped)
                continue

            # Update conditional tracker
            tracker.feed(line_no, code)

            # Multi-line accumulation
            if paren_depth == 0:
                accumulated = [code]
                acc_start_line = line_no
            else:
                accumulated.append(code)

            paren_depth += code.count("(") - code.count(")")

            if paren_depth > 0:
                continue  # keep accumulating

            # We have a complete statement
            full_text = " ".join(accumulated)
            accumulated = []
            paren_depth = 0

            self._dispatch(
                full_text,
                rel_path,
                acc_start_line,
                tracker,
                symbols,
                result,
            )

    # ------------------------------------------------------------------
    # Command dispatch
    # ------------------------------------------------------------------

    def _dispatch(
        self,
        text: str,
        rel_path: str,
        line_no: int,
        tracker: ConditionalTracker,
        symbols: SymbolTable,
        result: ParseResult,
    ) -> None:
        stack = tracker.snapshot()

        # --- Variable declarations (populate symbol table) ---
        m = _RE_OPTION.match(text)
        if m:
            symbols.process_option(m.group(1))
            # Check if it's a license variable
            if _LICENSE_VAR.search(m.group(1)):
                self._emit(result, "option", "license_var", m.group(1),
                           rel_path, line_no, text, stack, symbols)
            return

        m = _RE_SET.match(text)
        if m:
            symbols.process_set(m.group(1))
            args = m.group(1)
            if _LICENSE_VAR.search(args):
                self._emit(result, "set", "license_var", args,
                           rel_path, line_no, text, stack, symbols)
            return

        # --- Targets ---
        m = _RE_ADD_LIBRARY.match(text)
        if m:
            self._handle_add_library(m.group(1), rel_path, line_no, stack, result)
            return

        m = _RE_ADD_EXECUTABLE.match(text)
        if m:
            self._handle_add_executable(m.group(1), rel_path, line_no, stack, result)
            return

        m = _RE_ADD_CUSTOM_TARGET.match(text)
        if m:
            args = m.group(1).split()
            if args:
                name = args[0]
                is_test = bool(_TEST_NAMES.search(name))
                excl = "EXCLUDE_FROM_ALL" in m.group(1).upper()
                result.targets.append(CmakeTarget(
                    name=name, target_type="CUSTOM",
                    file=rel_path, line_no=line_no,
                    is_test=is_test, exclude_from_all=excl,
                ))
            return

        # --- ExternalProject_Add ---
        m = _RE_EP_ADD.match(text)
        if m:
            args = m.group(1)
            subtype = self._ep_subtype(args, symbols)
            self._emit(result, "ExternalProject_Add", subtype, args,
                       rel_path, line_no, text, stack, symbols)
            return

        # --- FetchContent ---
        m = _RE_FETCH_DECLARE.match(text)
        if m:
            self._emit(result, "FetchContent_Declare", "runtime_download",
                       m.group(1), rel_path, line_no, text, stack, symbols)
            return

        m = _RE_FETCH_MAKEAVAIL.match(text)
        if m:
            self._emit(result, "FetchContent_MakeAvailable", "runtime_download",
                       m.group(1), rel_path, line_no, text, stack, symbols)
            return

        # --- target_link_libraries ---
        m = _RE_TARGET_LINK.match(text)
        if m:
            args = m.group(1)
            subtype = self._link_subtype(args, symbols)
            self._emit(result, "target_link_libraries", subtype, args,
                       rel_path, line_no, text, stack, symbols)
            return

        # --- target_sources ---
        m = _RE_TARGET_SOURCES.match(text)
        if m:
            self._emit(result, "target_sources", "source_traceability",
                       m.group(1), rel_path, line_no, text, stack, symbols)
            return

        # --- target_compile_definitions ---
        m = _RE_TARGET_COMPILE_DEFS.match(text)
        if m:
            args = m.group(1)
            subtype = "gpl_define" if _GPL_KEYWORDS.search(args) else "compile_def"
            self._emit(result, "target_compile_definitions", subtype, args,
                       rel_path, line_no, text, stack, symbols)
            return

        # --- add_subdirectory ---
        m = _RE_ADD_SUBDIR.match(text)
        if m:
            args = m.group(1)
            subtype = self._subdir_subtype(args, tracker)
            self._emit(result, "add_subdirectory", subtype, args,
                       rel_path, line_no, text, stack, symbols)
            return

        # --- install ---
        m = _RE_INSTALL.match(text)
        if m:
            args = m.group(1)
            excl = _EXCL_FROM_ALL.search(args)
            subtype = "excluded" if excl else "included"
            self._emit(result, "install", subtype, args,
                       rel_path, line_no, text, stack, symbols)
            return

    # ------------------------------------------------------------------
    # Target handlers
    # ------------------------------------------------------------------

    def _handle_add_library(
        self, args_text: str, rel_path: str, line_no: int,
        stack: list, result: ParseResult
    ) -> None:
        parts = args_text.split()
        if not parts:
            return
        name = parts[0]
        # Determine type
        ttype = "STATIC"  # CMake default
        for p in parts[1:]:
            UP = p.upper()
            if UP in ("SHARED", "STATIC", "MODULE", "INTERFACE", "OBJECT", "ALIAS"):
                ttype = UP
                break
        if ttype in _SKIP_TARGET_TYPES:
            return
        excl = _EXCL_FROM_ALL.search(args_text) is not None
        is_test = bool(_TEST_NAMES.search(name))
        result.targets.append(CmakeTarget(
            name=name, target_type=ttype,
            file=rel_path, line_no=line_no,
            is_test=is_test, exclude_from_all=excl,
        ))

    def _handle_add_executable(
        self, args_text: str, rel_path: str, line_no: int,
        stack: list, result: ParseResult
    ) -> None:
        parts = args_text.split()
        if not parts:
            return
        name = parts[0]
        excl = _EXCL_FROM_ALL.search(args_text) is not None
        is_test = bool(_TEST_NAMES.search(name))
        result.targets.append(CmakeTarget(
            name=name, target_type="EXECUTABLE",
            file=rel_path, line_no=line_no,
            is_test=is_test, exclude_from_all=excl,
        ))

    # ------------------------------------------------------------------
    # Subtype classifiers
    # ------------------------------------------------------------------

    def _ep_subtype(self, args: str, symbols: SymbolTable) -> str:
        expanded, _ = symbols.expand(args)
        if _GPL_FLAGS.search(expanded):
            flags = _GPL_FLAGS.findall(expanded)
            for action, lib in flags:
                if action.lower() == "disable" and lib.lower() in ("gpl", "nonfree"):
                    return "disable_gpl"
                if action.lower() == "enable" and lib.lower() in ("gpl", "nonfree"):
                    return "enable_gpl"
            return "gpl_flag"
        if _NONFREE.search(expanded):
            return "nonfree"
        if _CONFIGURE_CMD.search(expanded):
            return "has_configure"
        return "external_project"

    def _link_subtype(self, args: str, symbols: SymbolTable) -> str:
        expanded, _ = symbols.expand(args)
        has_gpl = bool(_GPL_KEYWORDS.search(expanded))
        has_vis = bool(_LINK_VIS.search(expanded))
        if has_gpl and _STATIC_KW.search(expanded):
            return "static_gpl"
        if has_gpl and _SHARED_KW.search(expanded):
            return "shared_gpl"
        if has_gpl:
            return "gpl_link"
        if has_vis:
            return "visibility_set"
        return "link"

    def _subdir_subtype(self, args: str, tracker: ConditionalTracker) -> str:
        is_test = bool(_TEST_NAMES.search(args))
        is_third_party = bool(_THIRD_PARTY.search(args))
        guarded = not tracker.is_unconditional()
        excl = _EXCL_FROM_ALL.search(args) is not None
        if is_test:
            return "test_dir"
        if is_third_party:
            return "third_party_dir"
        return "subdir"

    # ------------------------------------------------------------------
    # Finding emitter
    # ------------------------------------------------------------------

    def _emit(
        self,
        result: ParseResult,
        command: str,
        subtype: str,
        args_text: str,
        rel_path: str,
        line_no: int,
        full_line: str,
        stack: list,
        symbols: SymbolTable,
    ) -> None:
        _, unresolved = symbols.expand(args_text)
        snippet = full_line[:200]  # cap snippet length
        result.findings.append(RawFinding(
            command=command,
            subtype=subtype,
            args_text=args_text,
            file=rel_path,
            line_no=line_no,
            snippet=snippet,
            condition_stack=stack,
            unresolved_vars=sorted(unresolved),
        ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_comment(line: str) -> str:
        """Remove CMake # comments, respecting quoted strings."""
        in_quote = False
        result = []
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '"':
                in_quote = not in_quote
            if ch == "#" and not in_quote:
                break
            result.append(ch)
            i += 1
        return "".join(result).strip()
