---
name: rizin-scripting
description: >-
  Script Rizin via rz-pipe and companion CLIs: rz-bin, rz-asm, rz-diff,
  rz-hash, rz-find, and rz-ax.
---

# Rizin scripting and companion tools

## rz-pipe

Language bindings live in [rizinorg/rz-pipe](https://github.com/rizinorg/rz-pipe) (Python package `rzpipe`, plus other languages). Typical Python pattern:

```python
import rzpipe
rz = rzpipe.open("/path/to/binary")
rz.cmd("aaa")
funcs = rz.cmdj("aflj")
info = rz.cmdj("iIj")
rz.quit()
```

One-shot without a persistent session:

```sh
rizin -qc 'aaa; aflj' /path/to/binary
```

Use `cmdj` / `*j` commands for structured output. Prefer querying `*?` help inside the session over inventing flags.

## Companion tools

| Tool | Role | Common flags (see man pages) |
| --- | --- | --- |
| `rz-bin` | Binary metadata extraction | `-I` info, `-S` sections, `-i` imports, `-z` strings, `-e` entrypoints, `-j` JSON |
| `rz-asm` | Assemble / disassemble | `-a arch`, `-b bits`, `-d` disassemble hex, `-l` length |
| `rz-diff` | Diff files / binaries | compare two paths; see `rz-diff -h` |
| `rz-hash` | Block hashing | `-a algorithm`, `-s string`, `-x hex` |
| `rz-find` | Pattern search in files/dirs | `-x hex`, string search options |
| `rz-ax` | Base / expression converter | expressions, `-h` for bases and formats |

Examples:

```sh
rz-bin -j -I -S -i -z ./binary
rz-asm -a x86 -b 64 'mov rax, 1'
rz-asm -a x86 -b 64 -d 4889c7
rz-hash -a sha256 ./binary
rz-ax 0x1000 + 0x20
rz-diff ./a.bin ./b.bin
```

Man pages under `binrz/man/` (`rz-bin.1`, `rz-asm.1`, `rz-diff.1`, `rz-hash.1`, `rz-find.1`, `rz-ax.1`) are authoritative for flags.
