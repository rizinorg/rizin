---
name: rizin-binary-triage
description: >-
  Quick binary triage with Rizin: open with analysis (-A), and inspect
  format info, sections, strings, imports, and entrypoints (i*, iI, iS, iz, ii, ie).
---

# Rizin binary triage

Use for a first pass on an unknown executable before deeper analysis.

## Open and analyze

```sh
rizin -A /path/to/binary          # runs deep auto-analysis (aaa)
rizin -qc 'iIj; iSj; izj; iij; iej' /path/to/binary
```

`-A` is documented in `rizin -h` / `binrz/man/rizin.1` as running analysis equivalent to `aaa`. Prefer `-qc '...'` for one-shot headless queries.

Outside an interactive session, the same metadata is available via `rz-bin`:

```sh
rz-bin -Ij /path/to/binary        # binary info (JSON)
rz-bin -Sj /path/to/binary        # sections
rz-bin -zj /path/to/binary        # strings
rz-bin -ij /path/to/binary        # imports
rz-bin -ej /path/to/binary        # entrypoints
```

## Info commands (`i` family)

| Command | Purpose |
| --- | --- |
| `i` / `ia` | File info / summary of imports, exports, sections, … |
| `iI` / `iIj` | Binary info (arch, bits, baddr, …); `j` for JSON |
| `iS` / `iSj` | Sections (`iSS` for segments) |
| `iz` / `izj` | Strings from the binary string table |
| `izz` / `izzj` | Strings scanned across the whole file |
| `izx` / `izxj` | Strings that have xrefs |
| `ii` / `iij` | Imports |
| `ie` / `iej` | Entrypoints (`iee` for init/fini-style entries) |
| `iE` / `iEj` | Exports |
| `is` / `isj` | Symbols |
| `il` / `ilj` | Linked libraries |

Query live help with `i?` / `iI??` rather than guessing flags.

## Practical sequence

1. `rizin -A binary` or `rizin -qc 'aaa; iIj' binary`
2. Skim `iIj`, `iSj`, `iej`, `iij`
3. Sample strings: `izj` (or `izzj` if the table looks empty)
4. Hand off interesting addresses to disassembly/xref skills (`pdf`, `axt`)
