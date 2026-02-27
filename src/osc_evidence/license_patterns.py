"""
license_patterns.py
===================
Centralized GPL/LGPL library name patterns for OSC evidence checkpoints.

Used by CP02, CP05, CP07, CP12, CP13, CP15 to consistently identify
GPL-only, LGPL-only, and dual-license (GPL-or-LGPL) libraries.
"""

from __future__ import annotations

import re
from typing import Optional


# GPL-only libraries — linking requires full GPL source disclosure
_GPL_ONLY = re.compile(
    r"\b(x264|libx264|x265|libx265|xvid|libxvid|divx|libdivx|gpac|faac|lame|libmp3lame|"
    r"xorriso)\b",
    re.IGNORECASE,
)

# LGPL-only libraries — dynamic linking is typically LGPL-compliant
_LGPL_ONLY = re.compile(
    r"\b(libvorbis|libogg|libopus|libflac|libsndfile|libffi|gnutls|nettle|hogweed|"
    r"libunistring|libgpg-error|libgcrypt|cygwin|cygwin1|cygiconv)\b",
    re.IGNORECASE,
)

# Libraries that can be either GPL or LGPL depending on build configuration
_GPL_OR_LGPL = re.compile(
    r"\b(ffmpeg|avcodec|avformat|avutil|swresample|swscale|avfilter|openh264|libopenh264|"
    r"libavcodec|libavformat|libavutil|libavfilter|libswresample|libswscale)\b",
    re.IGNORECASE,
)

# Combined pattern matching any GPL or LGPL library name
_ALL_GPL_LGPL = re.compile(
    r"\b(x264|libx264|x265|libx265|xvid|libxvid|divx|libdivx|gpac|faac|lame|libmp3lame|"
    r"xorriso|"
    r"libvorbis|libogg|libopus|libflac|libsndfile|libffi|gnutls|nettle|hogweed|"
    r"libunistring|libgpg-error|libgcrypt|cygwin|cygwin1|cygiconv|"
    r"ffmpeg|avcodec|avformat|avutil|swresample|swscale|avfilter|openh264|libopenh264|"
    r"libavcodec|libavformat|libavutil|libavfilter|libswresample|libswscale)\b",
    re.IGNORECASE,
)


def classify_name(text: str) -> Optional[str]:
    """Classify a library name or text snippet by its license category.

    Returns:
        "gpl"         — matches a known GPL-only library
        "lgpl"        — matches a known LGPL-only library
        "gpl_or_lgpl" — matches a library that can be either (e.g. FFmpeg)
        None          — no match
    """
    if _GPL_ONLY.search(text):
        return "gpl"
    if _LGPL_ONLY.search(text):
        return "lgpl"
    if _GPL_OR_LGPL.search(text):
        return "gpl_or_lgpl"
    return None


def has_gpl_lgpl(text: str) -> bool:
    """True if text contains any known GPL or LGPL library name."""
    return bool(_ALL_GPL_LGPL.search(text))


def label_for(classification: Optional[str]) -> str:
    """Human-readable label for a classification result."""
    return {
        "gpl": "GPL",
        "lgpl": "LGPL",
        "gpl_or_lgpl": "GPL-or-LGPL",
    }.get(classification or "", "GPL/LGPL")
