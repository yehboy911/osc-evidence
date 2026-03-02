"""
gpl_scanner.py
==============
Confirms which project components are GPL/LGPL via two methods:

1. LICENSE file scanning — walks source tree for LICENSE/COPYING files
2. SBOM CSV parsing — reads OSC-format SBOM CSVs

Used by CP06 to scope static-linking analysis to confirmed GPL/LGPL
components only, eliminating false positives from name-matching heuristics.

LXCE product structure reference:
  - extlibs/ = pre-compiled headers + libs (no CMakeLists.txt inside)
  - Linking happens in main project CMakeLists, not in extlibs dirs
  - SBOM CSVs (win.csv, linux.csv) at tool root in OSC format
  - GPL source tarballs in misc/source/ for redistribution compliance
"""

from __future__ import annotations

import csv
import io
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

# LICENSE/COPYING file names to scan
_LICENSE_NAMES = {
    "LICENSE", "COPYING", "LICENSE.txt", "COPYING.txt",
    "LICENSE.md", "COPYING.md", "LICENSE.MIT", "LICENCE",
    "LICENCE.txt",
}

# Patterns to detect GPL/LGPL in license file content
_GPL_TEXT = re.compile(
    r"GNU\s+GENERAL\s+PUBLIC\s+LICENSE|GPL-[23]\.0|"
    r"\bGPLv[23]\b",
    re.IGNORECASE,
)
_LGPL_TEXT = re.compile(
    r"GNU\s+LESSER\s+GENERAL\s+PUBLIC\s+LICENSE|LGPL-[23]\.[01]|"
    r"\bLGPLv[23]\b",
    re.IGNORECASE,
)

# SPDX-style identifiers in SBOM license column
_SPDX_LGPL = re.compile(r"\bLGPL\b", re.IGNORECASE)
_SPDX_GPL = re.compile(r"\bGPL\b", re.IGNORECASE)

# Licenses to skip in SBOM parsing
_SKIP_LICENSES = {"PROPRIETARY", "IGNORE", "NOT DISTRIBUTED", ""}

# Version suffix pattern for name normalization
_VERSION_SUFFIX = re.compile(r"[-_][\d]+(?:\.[\d]+)*(?:[-_.]\w+)*$")

# Alias expansion patterns for SBOM ↔ extlibs name matching
_PARENS_CONTENT = re.compile(r'\(([^)]+)\)')   # captures text inside (...)
_LIB_PREFIX     = re.compile(r'^lib(.+)$')     # strips leading "lib"


@dataclass
class GplComponent:
    """A confirmed GPL/LGPL component found via LICENSE file or SBOM CSV."""
    name: str                    # e.g. "cygwin", "xorriso", "blowfish"
    license: str                 # e.g. "LGPL-3.0", "GPL-3.0"
    classification: str          # "gpl" | "lgpl" | "gpl_or_lgpl"
    source_path: str             # relative path within source tree
    confirmed_by: str            # "license_file" | "sbom_csv"


def _normalize_name(name: str) -> str:
    """Normalize component name: lowercase, strip version suffixes."""
    n = name.strip().lower()
    n = _VERSION_SUFFIX.sub("", n)
    return n


def _expand_sbom_name_aliases(name: str) -> "set[str]":
    """Return all plausible filesystem aliases for a normalized SBOM component name.

    Handles three common mismatches:
      - snmp++            → also add 'snmp'          (strip ++ suffix)
      - libssh2           → also add 'ssh2'           (strip lib prefix)
      - websocket++(websocketpp) → also add 'websocketpp' (extract parenthetical)
    """
    aliases: set[str] = {name}

    # Extract parenthetical alternatives and strip parens from base
    parens_found = _PARENS_CONTENT.findall(name)
    for alt in parens_found:
        aliases.add(alt.strip().lower())
    base_no_parens = _PARENS_CONTENT.sub("", name).strip()
    if base_no_parens:
        aliases.add(base_no_parens)

    # Strip ++ / + suffix from each alias so far
    for a in list(aliases):
        stripped = a.rstrip('+').strip()
        if stripped and stripped != a:
            aliases.add(stripped)

    # Strip lib prefix from each alias so far
    for a in list(aliases):
        m = _LIB_PREFIX.match(a)
        if m:
            aliases.add(m.group(1))

    return aliases


def _classify_license_spdx(license_str: str) -> str:
    """Classify a license string as gpl, lgpl, or gpl_or_lgpl."""
    has_lgpl = bool(_SPDX_LGPL.search(license_str))
    has_gpl = bool(_SPDX_GPL.search(license_str))
    if has_lgpl and has_gpl:
        return "gpl_or_lgpl"
    if has_lgpl:
        return "lgpl"
    if has_gpl:
        return "gpl"
    return "gpl"  # fallback — caller already filtered for GPL presence


def scan_license_files(source_dir: str) -> List[GplComponent]:
    """Walk source tree for LICENSE/COPYING files and identify GPL/LGPL components.

    Reads first 30 lines of each license file to detect GPL/LGPL text.
    Component name is derived from the containing directory's basename.
    """
    results: List[GplComponent] = []
    source_root = os.path.abspath(source_dir)

    for dirpath, dirnames, filenames in os.walk(source_root):
        # Skip hidden dirs, build dirs, .git
        dirnames[:] = [
            d for d in dirnames
            if not d.startswith(".") and d not in {"build", "__pycache__", "node_modules"}
        ]

        for fname in filenames:
            if fname not in _LICENSE_NAMES:
                continue

            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    header_lines = []
                    for i, line in enumerate(f):
                        if i >= 30:
                            break
                        header_lines.append(line)
                header = "".join(header_lines)
            except OSError:
                continue

            is_lgpl = bool(_LGPL_TEXT.search(header))
            is_gpl = bool(_GPL_TEXT.search(header))

            if not is_gpl and not is_lgpl:
                continue

            # Derive component name from directory
            rel_dir = os.path.relpath(dirpath, source_root)
            dir_basename = os.path.basename(dirpath)
            comp_name = _normalize_name(dir_basename)

            # Determine license string and classification
            if is_lgpl:
                classification = "lgpl"
                # Try to extract specific SPDX from header
                m = re.search(r"LGPL-[\d.]+", header)
                lic = m.group(0) if m else "LGPL"
            elif is_gpl:
                classification = "gpl"
                m = re.search(r"GPL-[\d.]+", header)
                lic = m.group(0) if m else "GPL"
            else:
                continue

            # If both GPL and LGPL found, LGPL takes precedence (more specific)
            if is_lgpl and is_gpl:
                classification = "gpl_or_lgpl"

            results.append(GplComponent(
                name=comp_name,
                license=lic,
                classification=classification,
                source_path=rel_dir,
                confirmed_by="license_file",
            ))

    return results


def parse_sbom_csv(csv_path: str) -> List[GplComponent]:
    """Parse an OSC-format SBOM CSV and extract GPL/LGPL components.

    OSC CSV format:
    - Rows 1-27: metadata (product name, version, scan tool, etc.)
    - Header row: starts with "OSS Component Name" (possibly multi-line cell)
    - Data rows follow header
    - Key columns: A=name, B=version, C=license, D=link, E=source_path
    """
    results: List[GplComponent] = []

    try:
        # Handle UTF-8 BOM
        with open(csv_path, "r", encoding="utf-8-sig", errors="replace") as f:
            content = f.read()
    except OSError:
        return results

    reader = csv.reader(io.StringIO(content))
    header_found = False

    for row in reader:
        if not row:
            continue

        # Look for header row
        if not header_found:
            cell0 = row[0].strip().replace("\n", " ")
            if cell0.upper().startswith("OSS COMPONENT NAME"):
                header_found = True
            continue

        # Parse data row
        if len(row) < 3:
            continue

        comp_name = row[0].strip()
        # version = row[1].strip() if len(row) > 1 else ""
        license_str = row[2].strip() if len(row) > 2 else ""
        source_path = row[4].strip() if len(row) > 4 else ""

        if not comp_name:
            continue
        if license_str.upper() in _SKIP_LICENSES:
            continue

        # Filter for GPL/LGPL only
        if not _SPDX_GPL.search(license_str):
            continue

        classification = _classify_license_spdx(license_str)

        results.append(GplComponent(
            name=_normalize_name(comp_name),
            license=license_str,
            classification=classification,
            source_path=source_path,
            confirmed_by="sbom_csv",
        ))

    return results


def build_sbom_name_set(sbom_paths: Optional[List[str]]) -> "set[str]":
    """Return a set of ALL normalized component names present in the SBOM CSVs.

    Unlike build_gpl_set(), this includes non-GPL/LGPL components so that
    CP10 can distinguish "in SBOM (any license)" from "not in SBOM at all".
    """
    names: set[str] = set()
    if not sbom_paths:
        return names

    for csv_path in sbom_paths:
        try:
            with open(csv_path, "r", encoding="utf-8-sig", errors="replace") as f:
                content = f.read()
        except OSError:
            continue

        reader = csv.reader(io.StringIO(content))
        header_found = False
        for row in reader:
            if not row:
                continue
            if not header_found:
                if row[0].strip().replace("\n", " ").upper().startswith("OSS COMPONENT NAME"):
                    header_found = True
                continue
            comp_name = row[0].strip()
            if not comp_name:
                continue
            license_str = row[2].strip() if len(row) > 2 else ""
            if license_str.upper() in _SKIP_LICENSES:
                continue
            names.update(_expand_sbom_name_aliases(_normalize_name(comp_name)))

    return names


def build_gpl_set(
    source_dir: str,
    sbom_paths: Optional[List[str]] = None,
) -> List[GplComponent]:
    """Build a merged, deduplicated list of confirmed GPL/LGPL components.

    Runs LICENSE file scan + all SBOM CSV parses.
    SBOM data takes precedence over LICENSE file scan (more authoritative).
    """
    components: List[GplComponent] = []

    # Method 1: LICENSE file scan
    components.extend(scan_license_files(source_dir))

    # Method 2: SBOM CSV parsing
    if sbom_paths:
        for csv_path in sbom_paths:
            components.extend(parse_sbom_csv(csv_path))

    # Deduplicate by normalized name — SBOM takes precedence
    seen: dict[str, GplComponent] = {}
    for comp in components:
        key = comp.name
        existing = seen.get(key)
        if existing is None:
            seen[key] = comp
        elif comp.confirmed_by == "sbom_csv" and existing.confirmed_by != "sbom_csv":
            seen[key] = comp  # SBOM overrides LICENSE file

    return list(seen.values())
