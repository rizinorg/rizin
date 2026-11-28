---
name: rizin-disasm-analysis
description: >-
  Disassembly and static analysis in Rizin: auto-analysis (aaa), function
  listing (afl), function disassembly (pdf), xrefs (axt), and visual graphs (VV).
---

# Rizin disassembly and analysis

## Auto-analysis

| Command | Purpose |
| --- | --- |
| `aa` | Analyze flags starting with `sym.` and entry |
| `aaa` | Full standard analysis (calls, refs, emulation, signatures) |
| `aaaa` | Experimental / heavier analysis (avoid unless needed) |

CLI shortcut: `rizin -A file` runs deep analysis (`aaa`). Headless:

```sh
rizin -qc 'aaa; aflj' /path/to/binary
```

## Functions and disassembly

| Command | Purpose |
| --- | --- |
| `afl` / `aflj` | List functions (JSON with `j`) |
| `pdf` / `pdfj` | Disassemble the function at the current seek |
| `pd <N>` / `pdj <N>` | Disassemble `N` instructions |
| `axt` / `axtj` | Cross-references **to** the current seek |
| `axf` / `axfj` | Cross-references **from** the current seek |

Seek with `s <addr>` or a temporary seek `@ <addr>`:

```
aaa
aflj
s sym.main          # or s 0x401000
pdf
axt @ sym.imp.puts
```

Rizin expects `@ <addr>` for temporary seeks; do not pass a bare address as a trailing positional argument to `pdf` / `axt`.

## Graphs

- `VV` — interactive visual mode focused on the function graph (TTY UI; alias for `V V`). Prefer non-interactive alternatives in headless agent sessions.
- For scripted CFG output use analysis/print graph commands (see `ag?`), e.g. function graphs via `agf`, rather than `VV`.

## Tips

- Prefer `*j` JSON (`aflj`, `pdfj`, `axtj`) for parsing.
- After `aaa`, start from `afl` / entry (`ie`) / `sym.main` before reading every function.
- Extended help: `aaa?`, `afl??`, `pdf??`, `axt??`.
