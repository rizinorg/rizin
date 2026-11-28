---
name: rizin-search
description: >-
  Search inside binaries with Rizin: generic search (/), hex patterns (/x),
  and ROP gadgets (/R). Companion: rz-find for file/directory scans.
---

# Rizin searching

## In-session search

| Command | Purpose |
| --- | --- |
| `/` | Search for bytes, regexps, patterns (see `/?`) |
| `/x <hex>` | Raw hexadecimal pattern search |
| `/z "<str>"` | String search (optional encoding/flags; see `/z??`) |
| `/R` | Search / list / query ROP gadgets |

Examples:

```
/x 9090c3
/z "HTTP"
/R pop rdi; ret
```

Append `j` where supported for JSON (e.g. `/xj`, `/zj`). Restrict range with eval/search config or `@` modifiers as documented in `/?` / `e??` (`search.from`, `search.to`, …).

## Outside rizin: `rz-find`

```sh
rz-find -x 9090c3 /path/to/binary
rz-find -s 'password' /path/to/dir
```

See `binrz/man/rz-find.1` for `-x` (hex), string modes, and recursive directory search.

## Tips

- Run `aaa` first when you need hits correlated with functions/xrefs.
- Large `/R` scans can be slow on big code sections; narrow the range when possible.
- Help: `/?`, `/x??`, `/R??`.
