---
name: rizin-patching
description: >-
  Patch binaries in Rizin: reopen writable (oo+ or -w), write hex (wx),
  and assemble into place (wa).
---

# Rizin patching and writing

## Open writable

```sh
rizin -w /path/to/binary          # open in write mode (-w)
```

Inside a session that was opened read-only:

```
oo+                               # reopen current file in write mode
```

`oo+` is defined in `cmd_open` as “Reopen current file or file <fd> in write mode”. Writes modify the mapped file; keep backups.

## Write bytes and instructions

| Command | Purpose |
| --- | --- |
| `wx <hex>` | Write hexadecimal bytes at the current offset |
| `wa <asm>` | Assemble instruction(s) and write at the current offset |

Examples:

```
s 0x401000
wx 90c3                    # nop; ret (example x86)
wa nop; ret                # assemble then write (arch from asm.arch/bits)
```

Verify with `px` / `pd` after writing. For one-shot patches:

```sh
rizin -w -qc 's 0x401000; wx 90c3; q' /path/to/binary
```

## Safety

- Confirm `asm.arch` / `asm.bits` before `wa`.
- Prefer smallest change (`wx` for known opcodes, `wa` when assembling).
- Help: `oo?`, `wx??`, `wa??`.
