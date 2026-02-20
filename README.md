# osc-evidence

**OSC GPL/LGPL Compliance Evidence Generator**

Scans a CMake project's build system and produces a professional Markdown report with 15 legal checkpoints (PASS / FAIL / MANUAL / N/A) — ready to submit to legal counsel.

## Install

```bash
pipx install -e .
# or
pip3 install -e .
```

## Usage

```bash
# Print report to stdout
osc-evidence audit /path/to/cmake/project

# Write report to file
osc-evidence audit /path/to/cmake/project --output report.md
```

## What It Checks

| ID | Checkpoint | Detects |
|----|-----------|---------|
| CP01 | GPL Build Flags | `--disable-gpl` / `--enable-gpl` in ExternalProject configure |
| CP02 | LGPL Dynamic Linking | LGPL libs built as SHARED vs STATIC |
| CP03 | Test Suite Exclusion | Test dirs guarded by `BUILD_TESTING` / `EXCLUDE_FROM_ALL` |
| CP04 | Proprietary Codec Detection | `--enable-nonfree`, `proprietary_codecs` |
| CP05 | GPL Library Identification | Targets/links matching ffmpeg, x264, x265, etc. |
| CP06 | Static Linking GPL Risk | `STATIC` links to GPL libraries |
| CP07 | Install Scope Exclusion | `install()` with/without `EXCLUDE_FROM_ALL` |
| CP08 | Source-to-Target Traceability | `target_sources()` presence |
| CP09 | Conditional Build Guards | `add_subdirectory()` inside `if()` blocks |
| CP10 | License Variable Declarations | `set(SPDX_LICENSE ...)` / `set(LICENSE ...)` |
| CP11 | Third-Party Submodule Isolation | `third_party/` dirs with `EXCLUDE_FROM_ALL` |
| CP12 | Linking Visibility | `PRIVATE`/`PUBLIC`/`INTERFACE` in `target_link_libraries` |
| CP13 | ExternalProject GPL Options | `ExternalProject_Add` with `CONFIGURE_COMMAND` |
| CP14 | Compile Definitions | `target_compile_definitions` with GPL names |
| CP15 | Runtime Download Risk | `FetchContent_Declare` / `ExternalProject_Add` with URL |

## Report Format

```markdown
# OSC Compliance Report
- Generated: 2026-02-20
- Source Directory: /path/to/project

## Summary
| Status | Count |
| PASS   | 9     |
| FAIL   | 0     |
| MANUAL | 5     |
| N/A    | 1     |

## OSC Compliance Checkpoints
| Checkpoint | Status | Legal Translation | Evidence | Line | File |
...

## Build Graph Summary
...

## Action Items
...
```

## Requirements

- Python 3.8+
- No external dependencies (pure stdlib)
