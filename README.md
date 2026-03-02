# osc-evidence

**OSC GPL/LGPL Compliance Evidence Generator**

Scans a CMake project's build system and produces a professional Markdown report with 15 legal checkpoints (PASS / FAIL / MANUAL / N/A) — ready to submit to legal counsel.

## Install

```bash
# Standard install (pipx not available on this machine — use pip3 / miniconda)
pip3 install -e "/Users/OwenYeh/Claude Code/osc-evidence-master"

# After bumping pyproject.toml version, force reinstall:
pip3 install -e "/Users/OwenYeh/Claude Code/osc-evidence-master" --force-reinstall
```

## Usage

```bash
# Print report to stdout
osc-evidence audit /path/to/cmake/project

# Write report to file
osc-evidence audit /path/to/cmake/project --output report.md

# Exclude one or more subdirectory prefixes from scanning (relative to SOURCE_DIR)
osc-evidence audit /path/to/cmake/project --exclude modularization/build/tools
osc-evidence audit /path/to/cmake/project -e third_party/llvm -e build

# Enhanced scan: provide FFmpeg config.h for CP01/CP04
osc-evidence audit /path/to/project --config-h /path/to/config.h

# Enhanced scan: provide SBOM CSV(s) for GPL/LGPL confirmation (CP06/CP10)
osc-evidence audit /path/to/project --sbom win.csv --sbom linux.csv

# CI mode: skip the interactive menu
osc-evidence audit /path/to/project --no-interactive --output report.md
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--output / -o FILE` | Write report to FILE (default: auto-generated from project name/version) |
| `--exclude / -e DIR` | Exclude directory prefix (repeatable) |
| `--config-h FILE` | FFmpeg config.h for enhanced GPL/nonfree detection (CP01/CP04) |
| `--sbom FILE` | OSC SBOM CSV for GPL/LGPL confirmation (repeatable, CP06/CP10) |
| `--no-interactive` | Disable curses menu (for CI/scripts) |

## What It Checks

### Tier 1: GPL/LGPL Direct Risk Detection

| ID | Checkpoint | Detects |
|----|-----------|---------|
| CP01 | GPL Build Flags | `--disable-gpl` / `--enable-gpl` in ExternalProject configure; config.h `#define HAVE_GPL` |
| CP02 | GPL/LGPL Dynamic Linking | GPL/LGPL libs (pattern + SBOM-confirmed) built as SHARED vs STATIC — GPL+STATIC→FAIL, GPL+SHARED→MANUAL |
| CP04 | Proprietary Codec Detection | `--enable-nonfree`, `proprietary_codecs`; config.h `#define HAVE_NONFREE` |
| CP05 | GPL/LGPL Library Identification | Targets/links matching GPL/LGPL name patterns (ffmpeg, x264, x265, gstreamer, etc.) |
| CP06 | Static Linking GPL Risk | Two-layer analysis: (1) GPL component subdir STATIC targets, (2) main project links to confirmed GPL names |

### Tier 2: Build System Hygiene

| ID | Checkpoint | Detects |
|----|-----------|---------|
| CP03 | Test Suite Exclusion | Test dirs guarded by `BUILD_TESTING` / `EXCLUDE_FROM_ALL`; tracks BUILD_TESTING default |
| CP07 | Install Scope Exclusion | `install()` cross-referenced against test targets + COMPONENT analysis |
| CP08 | Source-to-Target Traceability | Inline `source_files` counted as traceable; only targets with no sources → MANUAL |
| CP09 | Conditional Build Guards | `add_subdirectory()` inside `if()` blocks; only flags test/third-party unconditional subdirs |
| CP10 | Extlibs Component Audit | Discovers pre-compiled OSS under `**/extlibs/**/include/`; cross-references against SBOM |
| CP11 | Third-Party Submodule Isolation | `third_party/` dirs with `EXCLUDE_FROM_ALL` |
| CP12 | Linking Visibility | `PRIVATE`/`PUBLIC`/`INTERFACE` in `target_link_libraries`; GPL/LGPL-aware — FAIL on no visibility, MANUAL on GPL+PUBLIC |

### Tier 3: External Source Tracking

| ID | Checkpoint | Detects |
|----|-----------|---------|
| CP13 | ExternalProject GPL Options | `ExternalProject_Add` with `CONFIGURE_COMMAND`; prioritizes GPL/LGPL EPs without CONFIGURE_COMMAND |
| CP14 | Compile Definitions | `target_compile_definitions` with GPL/LGPL names; expanded LGPL regex |
| CP15 | Runtime Download Risk | `FetchContent_Declare` / `ExternalProject_Add` with URL; also scans source for MSVC runtime DLL references — known DLLs → KNOWN ISSUE, unknown DLLs → MANUAL |

## Enhanced Scan Options

### FFmpeg config.h (`--config-h`)

If the audited project builds FFmpeg, pass the generated `config.h` to unlock deeper detection in CP01 and CP04. The file is scanned for `#define` lines like `HAVE_GPL`, `CONFIG_GPL`, `HAVE_NONFREE`, etc.

```bash
osc-evidence audit /path/to/project --config-h /path/to/ffmpeg/config.h
```

### SBOM CSV (`--sbom`)

Provide one or more OSC-format SBOM CSV files to confirm GPL/LGPL components. The GPL scanner parses these CSVs and cross-references against LICENSE files found in the source tree. Confirmed GPL/LGPL components are injected into CP06 (static linking analysis) and CP10 (extlibs audit).

```bash
osc-evidence audit /path/to/project --sbom windows_sbom.csv --sbom linux_sbom.csv
```

## Interactive Menu

When run in a terminal (stdin is a tty), osc-evidence presents a curses-based checkbox menu offering enhanced scan options not yet supplied via CLI flags. Users can toggle options with arrow keys and space, then confirm with Enter.

- **FFmpeg config.h scan** — detect `--enable-gpl` / `--enable-nonfree`
- **SBOM CSV for GPL confirmation** — provide OSC SBOM CSV path(s)

The menu is skipped when:
- `--no-interactive` is passed (recommended for CI pipelines)
- All enhanced options are already supplied via CLI flags
- stdin is not a tty

Falls back to plain text input if the curses library is unavailable.

## Report Tier Grouping

The report organizes checkpoints into three tiers by risk category:

| Tier | Checkpoints | Focus |
|------|------------|-------|
| Tier 1: GPL/LGPL Direct Risk Detection | CP01, CP02, CP04, CP05, CP06 | Direct GPL/LGPL compliance risks |
| Tier 2: Build System Hygiene | CP03, CP07, CP08, CP09, CP10, CP11, CP12 | Build system best practices |
| Tier 3: External Source Tracking | CP13, CP14, CP15 | External dependency management |

Both the checkpoint tables and action items sections are grouped by tier.

## Verdict Types

| Verdict | Meaning |
|---------|---------|
| **PASS** | Relevant CMake construct found and satisfies the legal requirement |
| **FAIL** | Compliance risk confirmed — immediate attention required |
| _MANUAL_ | Human review required — cannot be auto-determined from CMake alone |
| _KNOWN ISSUE_ | Implicit build-time dependency with a documented license (e.g. MSVC runtime DLLs) — no source-disclosure obligation, but must appear in product documentation |
| N/A | No relevant CMake construct found — checkpoint not applicable to this project |

## Report Format

```markdown
# OSC Compliance Report

- **Generated:** 2026-02-27
- **Source Directory:** `/path/to/project`
- **CMake Files Scanned:** 12
- **Targets Found:** 8
- **Findings Collected:** 34

## Summary
| Status | Count |
|--------|-------|
| PASS   | 9     |
| FAIL   | 0     |
| MANUAL | 4     |
| KNOWN ISSUE | 1 |
| N/A    | 1     |

### Per-Tier Breakdown
| Tier | PASS | FAIL | MANUAL | KNOWN ISSUE | N/A |
|------|------|------|--------|-------------|-----|
| Tier 1: GPL/LGPL Direct Risk Detection | 3 | 0 | 2 | 0 | 0 |
| Tier 2: Build System Hygiene | 5 | 0 | 1 | 0 | 1 |
| Tier 3: External Source Tracking | 1 | 0 | 1 | 1 | 0 |

## OSC Compliance Checkpoints

### Tier 1: GPL/LGPL Direct Risk Detection
| Checkpoint | Status | Legal Translation | Evidence (Code Snippet) | Line | File |
...

### Tier 2: Build System Hygiene
...

### Tier 3: External Source Tracking
...

## Build Graph Summary
...

## Action Items

### FAIL — Immediate Attention Required
#### Tier 1: GPL/LGPL Direct Risk Detection
...

### KNOWN ISSUE — Implicit Build-Time Dependency
#### Tier 3: External Source Tracking
...

### MANUAL — Human Review Required
#### Tier 2: Build System Hygiene
...

## Parser Warnings
...
```

## Architecture

```
src/osc_evidence/
├── cli.py                  # argparse: audit subcommand, interactive menu orchestration
├── cmake_parser.py         # Walks source tree; emits CmakeTarget + RawFinding + SymbolTable
├── gpl_scanner.py          # LICENSE file scan + SBOM CSV parsing → List[GplComponent]
├── license_patterns.py     # Centralized GPL/LGPL regex; classify_name(), has_gpl_lgpl()
├── interactive_menu.py     # Curses-based checkbox menu for enhanced scan options
├── symbol_table.py         # option()/set() variable table + ${VAR} expansion
├── conditional_tracker.py  # Stack-based if/elseif/else/endif tracker
├── translation_layer.py    # (command, subtype) → (verdict, legal text) dict
├── checkpoint_engine.py    # Runs all 15 checkpoints, injects config_h/gpl_components/source_dir
├── report_generator.py     # English Markdown output with tier-based grouping
└── checkpoints/
    ├── base.py             # CheckpointBase, CheckpointResult, Evidence
    ├── cp01_gpl_flags.py
    ├── cp02_lgpl_linking.py
    ├── cp03_test_exclusion.py
    ├── cp04_proprietary_codec.py
    ├── cp05_gpl_lib_id.py
    ├── cp06_static_gpl_risk.py
    ├── cp07_install_scope.py
    ├── cp08_source_traceability.py
    ├── cp09_conditional_guards.py
    ├── cp10_license_vars.py
    ├── cp11_submodule_isolation.py
    ├── cp12_link_visibility.py
    ├── cp13_external_gpl_opts.py
    ├── cp14_compile_definitions.py
    └── cp15_runtime_download.py
```

## Requirements

- Python 3.8+
- No external dependencies (pure stdlib)

## License

MIT License — Copyright (c) 2026 Owen Yeh. See [LICENSE](LICENSE).
