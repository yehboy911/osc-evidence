"""
cli.py
======
Entry point: osc-evidence audit <source_dir> [--output report.md]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .cmake_parser import CMakeParser
from .checkpoint_engine import CheckpointEngine
from .report_generator import ReportGenerator


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
        help="Write Markdown report to FILE (default: print to stdout)",
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

    engine = CheckpointEngine()
    results = engine.run_all(parse_result)

    generator = ReportGenerator(
        source_dir=str(source_dir),
        parse_result=parse_result,
        checkpoint_results=results,
    )
    report = generator.render()

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(report, encoding="utf-8")
        print(f"Report written to: {out_path}", file=sys.stderr)
    else:
        print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
