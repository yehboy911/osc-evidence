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

# Run without installing
python3 "/Users/OwenYeh/Claude Code/osc-evidence-master/src/osc_evidence/cli.py" audit /path/to/project
```

## Module Map

```
src/osc_evidence/
├── cli.py                  # argparse: audit subcommand
├── cmake_parser.py         # Walks source tree; emits CmakeTarget + RawFinding
├── symbol_table.py         # option()/set() variable table + ${VAR} expansion
├── conditional_tracker.py  # Stack-based if/elseif/else/endif tracker
├── translation_layer.py    # (command, subtype) → (verdict, legal text) dict
├── checkpoint_engine.py    # Runs all 15 checkpoints, catches errors
├── report_generator.py     # English Markdown output
└── checkpoints/
    ├── base.py             # CheckpointBase, CheckpointResult, Evidence
    ├── cp01_gpl_flags.py   # ExternalProject CONFIGURE_COMMAND --disable/enable-gpl
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

## Report Sections (rendered order)

1. **Header** — Generated date, Source Directory, CMake Files Scanned, Targets Found, Findings Collected
2. **Summary** — PASS / FAIL / MANUAL / N/A counts
3. **OSC Compliance Checkpoints** — table: Checkpoint | Status | Legal Translation | Evidence (Code Snippet) | Line | File
4. **Build Graph Summary** — one bullet per target (type, file, line, TEST/EXCLUDE_FROM_ALL tags)
5. **Action Items** — FAIL subsection then MANUAL subsection (omitted if neither present)
6. **Parser Warnings** — emitted when the CMake parser encounters unexpected syntax (omitted if none)

## Key Design Decisions

### Output Language
**English** — this tool's reports go to English-speaking legal counsel (Dennis).
Do NOT change report strings to Traditional Chinese.

### N/A vs PASS
- `N/A` = no relevant CMake construct found (avoids false PASS)
- `PASS` = relevant construct found AND it satisfies the legal requirement

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

### ConditionalTracker
- `tracker.feed(line_no, line)` — call for every non-comment line
- `tracker.snapshot()` → `List[ConditionFrame]` — attach to each RawFinding
- `finding.is_guarded_by("BUILD_TESTING")` — check if wrapped in a specific condition
- `finding.is_unconditional()` — True if no surrounding if/endif

### SymbolTable
- Populated from `option()` and `set()` calls across all files
- `symbols.expand(text)` → `(expanded_str, unresolved_var_set)`
- Unresolved vars → checkpoint should emit MANUAL verdict, not PASS/FAIL

## 15 Checkpoints Summary

| ID | Name | Key CMake Constructs |
|----|------|----------------------|
| CP01 | GPL Build Flags | ExternalProject_Add CONFIGURE_COMMAND --disable/enable-gpl |
| CP02 | LGPL Dynamic Linking | add_library SHARED/STATIC for LGPL names |
| CP03 | Test Suite Exclusion | add_subdirectory(tests) guarded by BUILD_TESTING |
| CP04 | Proprietary Codec Detection | --enable-nonfree, proprietary_codecs |
| CP05 | GPL Library Identification | Target/link names matching gpl/ffmpeg/x264/etc. |
| CP06 | Static Linking GPL Risk | STATIC link to GPL libraries |
| CP07 | Install Scope Exclusion | install() with/without EXCLUDE_FROM_ALL |
| CP08 | Source-to-Target Traceability | target_sources() presence |
| CP09 | Conditional Build Guards | add_subdirectory() inside if() blocks |
| CP10 | License Variable Declarations | set(SPDX_LICENSE ...) / set(LICENSE ...) |
| CP11 | Third-Party Submodule Isolation | add_subdirectory(third_party/...) EXCLUDE_FROM_ALL |
| CP12 | Linking Visibility | PRIVATE/PUBLIC/INTERFACE in target_link_libraries |
| CP13 | ExternalProject GPL Options | ExternalProject_Add with CONFIGURE_COMMAND |
| CP14 | Compile Definitions | target_compile_definitions with GPL names |
| CP15 | Runtime Download Risk | FetchContent_Declare / ExternalProject_Add with URL |

## License

MIT — Copyright (c) 2026 Owen Yeh. `LICENSE` file is in the repo root.
`pyproject.toml` references it as `license = { file = "LICENSE" }`.
