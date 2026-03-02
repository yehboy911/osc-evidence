"""
cli.py
======
Entry point: osc-evidence audit <source_dir> [--output report.md]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from .cmake_parser import CMakeParser
from .checkpoint_engine import CheckpointEngine
from .report_generator import ReportGenerator
from .gpl_scanner import build_gpl_set, build_sbom_name_set


def _infer_report_name(source_dir: str) -> str:
    """Generate a report filename from the project name and version.

    Priority order:
    1. project(... VERSION x.y.z) in top-level CMakeLists.txt
    2. Version-like component in parent directory path segments
    3. Fallback: <ProjectName>-compliance-report.md
    """
    p = Path(source_dir).resolve()
    project_name = p.name
    version = None

    # 1. Try project(... VERSION x.y.z) in top-level CMakeLists.txt
    cmake_main = p / "CMakeLists.txt"
    if cmake_main.exists():
        try:
            m = re.search(
                r'\bproject\s*\([^)]*\bVERSION\s+([\d.]+)',
                cmake_main.read_text(errors='replace'),
                re.IGNORECASE,
            )
            if m:
                version = m.group(1)
        except OSError:
            pass

    # 2. Fall back: walk parent path components for a version number
    if not version:
        for part in reversed(p.parts[:-1]):
            m = re.search(r'(\d+\.\d+(?:\.\d+)*)', part)
            if m:
                version = m.group(1)
                break

    return (
        f"{project_name}-v{version}-report.md"
        if version
        else f"{project_name}-compliance-report.md"
    )


def _build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="osc-evidence",
        description="OSC GPL/LGPL compliance evidence generator",
    )
    sub = root.add_subparsers(dest="command", required=True)

    audit = sub.add_parser(
        "audit",
        help="Scan a CMake source tree and generate a compliance report",
    )
    audit.add_argument(
        "source_dir",
        metavar="SOURCE_DIR",
        help="Root directory of the CMake project to audit",
    )
    audit.add_argument(
        "--output", "-o",
        metavar="FILE",
        default=None,
        help="Write Markdown report to FILE (default: auto-generated from project name/version)",
    )
    audit.add_argument(
        "--exclude", "-e",
        metavar="DIR",
        action="append",
        default=[],
        dest="exclude",
        help="Exclude directory path prefix(es) from scanning (repeatable). "
             "Path is relative to SOURCE_DIR. Example: --exclude modularization/build/tools",
    )
    audit.add_argument(
        "--config-h",
        metavar="FILE",
        default=None,
        dest="config_h",
        help="Path to FFmpeg config.h for enhanced GPL/nonfree detection (CP01/CP04)",
    )
    audit.add_argument(
        "--sbom",
        metavar="FILE",
        action="append",
        default=[],
        dest="sbom_paths",
        help="OSC-format SBOM CSV for GPL/LGPL component confirmation (repeatable)",
    )
    audit.add_argument(
        "--no-interactive",
        action="store_true",
        default=False,
        dest="no_interactive",
        help="Disable the interactive enhanced-scan menu (for CI/scripts)",
    )
    return root


def main(argv: list = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        return _run_audit(args)

    parser.print_help()
    return 1


def _run_audit(args: argparse.Namespace) -> int:
    source_dir = Path(args.source_dir).resolve()
    if not source_dir.is_dir():
        print(f"ERROR: Source directory not found: {source_dir}", file=sys.stderr)
        return 1

    print(f"Scanning: {source_dir}", file=sys.stderr)
    if args.exclude:
        print(f"Excluding: {', '.join(args.exclude)}", file=sys.stderr)
    cmake_parser = CMakeParser(str(source_dir), exclude_dirs=args.exclude)
    parse_result = cmake_parser.parse()

    print(
        f"Parsed {len(parse_result.targets)} targets, "
        f"{len(parse_result.findings)} findings "
        f"from {parse_result.files_scanned} CMakeLists.txt files",
        file=sys.stderr,
    )

    if parse_result.warnings:
        for w in parse_result.warnings:
            print(f"  WARNING: {w}", file=sys.stderr)

    config_h_path = args.config_h
    sbom_paths = list(args.sbom_paths)

    # Interactive menu for enhanced scan options (skipped when --no-interactive
    # is set, all options already supplied, or stdout is not a terminal)
    has_all_opts = config_h_path is not None and sbom_paths
    if not has_all_opts and not args.no_interactive and sys.stdin.isatty():
        try:
            from .interactive_menu import (
                MenuOption, prompt_config_h, prompt_sbom_csv, show_menu,
            )
            opts = []
            if config_h_path is None:
                opts.append(MenuOption(
                    "config_h",
                    "FFmpeg config.h scan — detect --enable-gpl / --enable-nonfree (CP01/CP04)",
                    selected=False,
                ))
            if not sbom_paths:
                opts.append(MenuOption(
                    "sbom_csv",
                    "SBOM CSV for GPL confirmation — provide OSC SBOM CSV path(s) (CP06)",
                    selected=False,
                ))
            if opts:
                chosen = show_menu(opts)
                for opt in chosen:
                    if opt.key == "config_h" and opt.selected:
                        config_h_path = prompt_config_h()
                    elif opt.key == "sbom_csv" and opt.selected:
                        sbom_paths = prompt_sbom_csv()
        except Exception:
            pass  # non-fatal; proceed without enhanced scan

    # Build confirmed GPL/LGPL component list (LICENSE scan + SBOM CSV)
    gpl_components = build_gpl_set(str(source_dir), sbom_paths or None)
    sbom_all_names = build_sbom_name_set(sbom_paths or None)
    if gpl_components:
        print(
            f"GPL/LGPL components confirmed: "
            f"{', '.join(c.name + ' (' + c.license + ')' for c in gpl_components)}",
            file=sys.stderr,
        )

    engine = CheckpointEngine()
    results = engine.run_all(
        parse_result,
        config_h_path=config_h_path,
        gpl_components=gpl_components,
        source_dir=str(source_dir),
        sbom_all_names=sbom_all_names,
    )

    generator = ReportGenerator(
        source_dir=str(source_dir),
        parse_result=parse_result,
        checkpoint_results=results,
    )
    report = generator.render()

    if args.output:
        out_path = Path(args.output)
    else:
        out_path = Path(_infer_report_name(str(source_dir)))
    out_path.write_text(report, encoding="utf-8")
    print(f"Report written to: {out_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
