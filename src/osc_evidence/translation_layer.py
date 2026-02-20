"""
translation_layer.py
====================
Pure data: (cmake_command, finding_subtype) → legal verdict hint.

Adding a new legal judgment requires only a new dict entry.
"""

from __future__ import annotations
from typing import Dict, Optional, Tuple

from .checkpoints.base import PASS, FAIL, MANUAL, NA


# Key: (command, subtype)
# Value: (default_verdict, legal_translation_template)
VERDICT_MAP: Dict[Tuple[str, str], Tuple[str, str]] = {
    # ExternalProject_Add
    ("ExternalProject_Add", "disable_gpl"):
        (PASS, "GPL features explicitly disabled via configure flag"),
    ("ExternalProject_Add", "enable_gpl"):
        (FAIL, "GPL features explicitly enabled — distribution triggers GPL obligations"),
    ("ExternalProject_Add", "gpl_flag"):
        (MANUAL, "GPL-related configure flag found — verify whether it enables or disables GPL code"),
    ("ExternalProject_Add", "nonfree"):
        (FAIL, "Non-free/proprietary codec flag detected — may violate GPL redistribution terms"),
    ("ExternalProject_Add", "has_configure"):
        (MANUAL, "External project has CONFIGURE_COMMAND — review flags for GPL options"),
    ("ExternalProject_Add", "external_project"):
        (MANUAL, "External project downloaded at build time — verify source license"),

    # FetchContent
    ("FetchContent_Declare", "runtime_download"):
        (MANUAL, "Source code fetched at build time — verify license of downloaded component"),
    ("FetchContent_MakeAvailable", "runtime_download"):
        (MANUAL, "FetchContent_MakeAvailable activates runtime download — verify license"),

    # target_link_libraries
    ("target_link_libraries", "static_gpl"):
        (FAIL, "Static linking to GPL library detected — static linking triggers full GPL obligations"),
    ("target_link_libraries", "shared_gpl"):
        (PASS, "Dynamic linking to GPL/LGPL library — LGPL dynamic linking is compliant"),
    ("target_link_libraries", "gpl_link"):
        (MANUAL, "GPL-related library linked — verify whether SHARED or STATIC"),
    ("target_link_libraries", "visibility_set"):
        (PASS, "Link visibility (PRIVATE/PUBLIC/INTERFACE) explicitly declared"),
    ("target_link_libraries", "link"):
        (MANUAL, "Library linked without visibility qualifier — verify scope"),

    # target_sources
    ("target_sources", "source_traceability"):
        (PASS, "Source files explicitly listed — clear source-to-target traceability"),

    # target_compile_definitions
    ("target_compile_definitions", "gpl_define"):
        (MANUAL, "GPL-related compile definition found — verify whether it enables GPL code paths"),
    ("target_compile_definitions", "compile_def"):
        (PASS, "Compile definitions set — no GPL-related identifiers detected"),

    # add_subdirectory
    ("add_subdirectory", "test_dir"):
        (MANUAL, "Test directory included — verify it is guarded by BUILD_TESTING or EXCLUDE_FROM_ALL"),
    ("add_subdirectory", "third_party_dir"):
        (MANUAL, "Third-party directory included — verify isolation (EXCLUDE_FROM_ALL recommended)"),
    ("add_subdirectory", "subdir"):
        (PASS, "Subdirectory included unconditionally — no special GPL concern detected"),

    # install
    ("install", "excluded"):
        (PASS, "Install target explicitly excluded from default install (EXCLUDE_FROM_ALL)"),
    ("install", "included"):
        (MANUAL, "Install target included — verify whether GPL components are in install set"),

    # option / set (license variables)
    ("option", "license_var"):
        (PASS, "License variable declared via option() — license type is configurable"),
    ("set", "license_var"):
        (PASS, "License variable explicitly set in CMake — license type is documented in build system"),
}


def lookup(command: str, subtype: str) -> Optional[Tuple[str, str]]:
    """Return (verdict, legal_translation) or None if not in the map."""
    return VERDICT_MAP.get((command, subtype))


def get_verdict(command: str, subtype: str, default: str = MANUAL) -> str:
    entry = VERDICT_MAP.get((command, subtype))
    return entry[0] if entry else default


def get_legal(command: str, subtype: str, default: str = "Manual review required.") -> str:
    entry = VERDICT_MAP.get((command, subtype))
    return entry[1] if entry else default
