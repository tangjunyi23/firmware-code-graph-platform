---
name: ida-decompile
description: "Use when user asks to decompile/反编译 a binary file. Runs IDA Pro headless decompilation, producing per-function .c files with call-graph metadata. Suitable for ELF, PE, Mach-O binaries of any architecture."
---

# IDA Headless Decompile Skill

Perform headless decompilation of binary files using IDA Pro. Outputs per-function `.c` files with caller/callee metadata.

## Usage

```bash
# Basic (output to <binary_dir>/decompile-export/)
~/.codex/skills/ida-decompile/ida-decompile.sh <binary_path>

# Specify output directory
~/.codex/skills/ida-decompile/ida-decompile.sh <binary_path> <output_dir>
```

## Output Structure

```
<output_dir>/
├── decompile/              # Per-function .c files (with callers/callees metadata)
├── function_index.txt      # Function call-graph index
├── strings.txt             # String table (address + content)
├── imports.txt             # Import table
├── exports.txt             # Export table
├── memory/                 # Memory hexdump (1MB chunks)
├── <binary>.i64            # IDA database
├── decompile_failed.txt    # Functions that failed to decompile
└── decompile_skipped.txt   # Skipped functions
```

## Notes

- Large binaries (100MB+) may take hours
- SCRIPT_TIMEOUT is set to 0 (infinite) automatically
- INP.py plugin is auto-installed from GitHub on first run
