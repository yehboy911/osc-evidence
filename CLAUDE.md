# osc-evidence — CLAUDE.md

## Purpose

`osc-evidence` is a Python CLI tool that scans a CMake project's build system and generates a professional Markdown compliance report with 15 legal checkpoints (PASS / FAIL / MANUAL / N/A).

It is designed to produce "code-level evidence" for GPL/LGPL compliance audits — output goes directly to legal counsel.

## Install & Run

```bash
# Install (requires pip3 / pipx)
pipx install -e "/Users/OwenYeh/Claude Code/osc-evidence-master"
# or fallback:
pip3 install -e "/Users/OwenYeh/Claude Code/osc-evidence-master"

# Print report to stdout
osc-evidence audit /path/to/cmake/project

# Write report to file
osc-evidence audit /path/to/cmake/project --output report.md

# Exclude subdirectory prefix(es) from scanning (relative to SOURCE_DIR, repeatable)
osc-evidence audit /path/to/cmake/project --exclude modularization/build/tools
osc-evidence audit /path/to/cmake/project -e third_party/llvm -e build

# Enhanced scan: FFmpeg config.h for CP01/CP04
osc-evidence audit /path/to/project --config-h /path/to/config.h

# Enhanced scan: SBOM CSV(s) for GPL/LGPL confirmation (CP06/CP10)
osc-evidence audit /path/to/project --sbom win.csv --sbom linux.csv

# CI mode: skip interactive menu
osc-evidence audit /path/to/project --no-interactive --output report.md

# Run without installing
python3 "/Users/OwenYeh/Claude Code/osc-evidence-master/src/osc_evidence/cli.py" audit /path/to/project
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--output / -o FILE` | Write report to file (default: stdout) |
| `--exclude / -e DIR` | Exclude directory prefix (repeatable) |
| `--config-h FILE` | FFmpeg config.h for enhanced GPL/nonfree detection (CP01/CP04) |
| `--sbom FILE` | OSC SBOM CSV for GPL/LGPL confirmation (repeatable, CP06/CP10) |
| `--no-interactive` | Disable curses menu (for CI/scripts) |

## Module Map

```
src/osc_evidence/
├── cli.py                  # argparse: audit subcommand, interactive menu orchestration
├── cmake_parser.py         # Walks source tree; emits CmakeTarget + RawFinding + SymbolTable
├── gpl_scanner.py          # LICENSE file scan + SBOM CSV parsing → List[GplComponent]
├── license_patterns.py     # Centralized GPL/LGPL regex; classify_name(), has_gpl_lgpl()
├── interactive_menu.py     # Curses-based checkbox menu for enhanced scan options; fallback to text input
├── symbol_table.py         # option()/set() variable table + ${VAR} expansion
├── conditional_tracker.py  # Stack-based if/elseif/else/endif tracker
├── translation_layer.py    # (command, subtype) → (verdict, legal text) dict
├── checkpoint_engine.py    # Runs all 15 checkpoints, injects config_h/gpl_components/source_dir
├── report_generator.py     # English Markdown output with tier-based grouping
└── checkpoints/
    ├── base.py             # CheckpointBase, CheckpointResult, Evidence
    ├── cp01_gpl_flags.py   # ExternalProject CONFIGURE_COMMAND --disable/enable-gpl; config.h scan
    ├── cp02_lgpl_linking.py        # GPL/LGPL SHARED vs STATIC; GPL+STATIC→FAIL, GPL+SHARED→MANUAL
    ├── cp03_test_exclusion.py      # BUILD_TESTING / EXCLUDE_FROM_ALL guards; tracks default value
    ├── cp04_proprietary_codec.py   # --enable-nonfree, proprietary_codecs; config.h scan
    ├── cp05_gpl_lib_id.py          # GPL/LGPL library name pattern matching
    ├── cp06_static_gpl_risk.py     # Two-layer: GPL subdir STATIC targets + main project links
    ├── cp07_install_scope.py       # install() cross-ref against test targets + COMPONENT analysis
    ├── cp08_source_traceability.py # Inline source_files counted as traceable
    ├── cp09_conditional_guards.py  # Only flags test/third-party unconditional subdirs
    ├── cp10_license_vars.py        # Extlibs Component Audit — **/extlibs/**/include/ discovery
    ├── cp11_submodule_isolation.py # third_party/ with EXCLUDE_FROM_ALL
    ├── cp12_link_visibility.py     # GPL/LGPL-aware visibility; FAIL on no visibility
    ├── cp13_external_gpl_opts.py   # Prioritizes GPL/LGPL EPs without CONFIGURE_COMMAND
    ├── cp14_compile_definitions.py # Expanded LGPL regex (USE_LGPL, ENABLE_LGPL, etc.)
    └── cp15_runtime_download.py    # Labels GPL/LGPL downloads in evidence notes
```

## Report Sections (rendered order)

1. **Header** — Generated date, Source Directory, CMake Files Scanned, Targets Found, Findings Collected
2. **Summary** — PASS / FAIL / MANUAL / N/A counts + **Per-Tier Breakdown** table
3. **OSC Compliance Checkpoints** — grouped by tier:
   - Tier 1: GPL/LGPL Direct Risk Detection (CP01, CP02, CP04, CP05, CP06)
   - Tier 2: Build System Hygiene (CP03, CP07, CP08, CP09, CP10, CP11, CP12)
   - Tier 3: External Source Tracking (CP13, CP14, CP15)
4. **Build Graph Summary** — one bullet per target (type, file, line, TEST/EXCLUDE_FROM_ALL tags)
5. **Action Items** — FAIL subsection then MANUAL subsection, each grouped by tier
6. **Parser Warnings** — emitted when the CMake parser encounters unexpected syntax (omitted if none)

## 15 Checkpoints Summary

| ID | Name | Key CMake Constructs |
|----|------|----------------------|
| CP01 | GPL Build Flags | ExternalProject_Add CONFIGURE_COMMAND --disable/enable-gpl; config.h #define |
| CP02 | LGPL Dynamic Linking | add_library SHARED/STATIC for GPL/LGPL names; GPL+STATIC→FAIL, GPL+SHARED→MANUAL |
| CP03 | Test Suite Exclusion | add_subdirectory(tests) guarded by BUILD_TESTING; tracks default value |
| CP04 | Proprietary Codec Detection | --enable-nonfree, proprietary_codecs; config.h #define |
| CP05 | GPL/LGPL Library Identification | Target/link names matching GPL/LGPL patterns via license_patterns.py |
| CP06 | Static Linking GPL Risk | Two-layer: (1) GPL subdir STATIC targets, (2) main project links to confirmed GPL names |
| CP07 | Install Scope Exclusion | install() cross-ref against test targets + COMPONENT analysis |
| CP08 | Source-to-Target Traceability | Inline source_files counted as traceable; no sources → MANUAL |
| CP09 | Conditional Build Guards | add_subdirectory() in if() blocks; only test/third-party unconditional subdirs flagged |
| CP10 | Extlibs Component Audit | Discovers pre-compiled OSS under **/extlibs/**/include/; cross-refs against SBOM + classify_name() |
| CP11 | Third-Party Submodule Isolation | add_subdirectory(third_party/...) EXCLUDE_FROM_ALL |
| CP12 | Linking Visibility | PRIVATE/PUBLIC/INTERFACE in target_link_libraries; GPL/LGPL-aware |
| CP13 | ExternalProject GPL Options | ExternalProject_Add with CONFIGURE_COMMAND; GPL/LGPL EPs prioritized |
| CP14 | Compile Definitions | target_compile_definitions with GPL/LGPL names; expanded LGPL regex |
| CP15 | Runtime Download Risk | FetchContent_Declare / ExternalProject_Add with URL; labels GPL/LGPL |

## Key Design Decisions

### Output Language
**English** — this tool's reports go to English-speaking legal counsel (Dennis).
Do NOT change report strings to Traditional Chinese.

### N/A vs PASS
- `N/A` = no relevant CMake construct found (avoids false PASS)
- `PASS` = relevant construct found AND it satisfies the legal requirement

### Tier Grouping
Presentation-only concern in `report_generator.py`. The `_TIERS` constant maps checkpoint IDs to display tiers. Checkpoint logic is unaware of tiers — grouping happens entirely at report render time.

### GPL Scanner
`gpl_scanner.py` confirms GPL/LGPL components via two methods:
1. **LICENSE file scan** — walks source tree for LICENSE/COPYING files, classifies via `license_patterns.py`
2. **SBOM CSV parsing** — reads OSC-format CSV, matches license column against GPL/LGPL patterns

Returns `List[GplComponent]` (dataclass with `name`, `license`, `source` fields). Results are injected into CP06 and CP10 by `CheckpointEngine`.

### License Patterns
Centralized regex in `license_patterns.py`:
- `_GPL_ONLY` — matches GPL-only names (ffmpeg, x264, xorriso, etc.)
- `_LGPL_ONLY` — matches LGPL-only names (qt, cygwin, etc.)
- `_GPL_OR_LGPL` — matches either
- `_ALL_GPL_LGPL` — combined pattern
- `classify_name(name)` → `"GPL"` / `"LGPL"` / `None`
- `has_gpl_lgpl(name)` → `bool`

All checkpoints use these shared patterns instead of maintaining their own regex.

### Interactive Menu
`interactive_menu.py` provides a curses-based checkbox menu for enhanced scan options. Activated when stdin is a tty and not all options are supplied via CLI flags. `--no-interactive` disables it entirely. Falls back to plain text prompts if curses is unavailable.

### Adding a New Legal Rule
1. Add a regex or pattern to `cmake_parser.py` (if a new CMake command is needed)
2. Add an entry to `translation_layer.py`: `("command", "subtype"): (verdict, "legal text")`
3. Create or update a checkpoint in `checkpoints/cpXX_*.py`
4. Register the checkpoint class in `checkpoint_engine.py`

### Adding a New Checkpoint
1. Create `checkpoints/cpNN_name.py` inheriting `CheckpointBase`
2. Set `checkpoint_id = "CPNN"` and `name = "Human-Readable Name"`
3. Implement `_evaluate(self, pr: ParseResult) -> CheckpointResult`
4. Add instance to `_ALL_CHECKPOINTS` list in `checkpoint_engine.py`
5. If the checkpoint needs injected data (config_h, gpl_components, source_dir), add a class attribute and `CheckpointEngine.run_all()` will inject via `hasattr` pattern

### ConditionalTracker
- `tracker.feed(line_no, line)` — call for every non-comment line
- `tracker.snapshot()` → `List[ConditionFrame]` — attach to each RawFinding
- `finding.is_guarded_by("BUILD_TESTING")` — check if wrapped in a specific condition
- `finding.is_unconditional()` — True if no surrounding if/endif

### SymbolTable
- Populated from `option()` and `set()` calls across all files
- `symbols.expand(text)` → `(expanded_str, unresolved_var_set)`
- Unresolved vars → checkpoint should emit MANUAL verdict, not PASS/FAIL

## License

MIT — Copyright (c) 2026 Owen Yeh. `LICENSE` file is in the repo root.
`pyproject.toml` references it as `license = { file = "LICENSE" }`.
