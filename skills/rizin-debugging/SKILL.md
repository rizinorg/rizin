---
name: rizin-debugging
description: >-
  Debug programs with Rizin: start with rizin -d, set breakpoints (db),
  continue (dc), inspect registers (dr), and step (ds).
---

# Rizin debugging

## Start a debug session

```sh
rizin -d /path/to/binary
rizin -d /path/to/binary arg1 arg2
rizin -d <pid>                 # attach to a running process
```

`-d` is documented in `binrz/man/rizin.1`. For a backend without spawning, `-D <backend>` sets `cfg.debug=true`.

## Core commands

| Command | Purpose |
| --- | --- |
| `db` | Add a breakpoint at the current offset (`dbl` lists; see `db?`) |
| `db @ <addr>` | Breakpoint at address via temporary seek (e.g. `db @ sym.main`) |
| `dc` | Continue execution |
| `dr` | Show / manipulate CPU registers (`dr?` for subcommands) |
| `ds` | Step one instruction (`ds <n>` steps `n`; see `ds?`) |

Typical loop:

```
db @ entry0        # or db @ sym.main / db @ 0x...
dc
dr
ds
pdf                # context at current PC after breaking
```

## Notes

- Debugging executes the target. Prefer a sandbox for untrusted binaries.
- Register names depend on arch (`rax` vs `r0`, …); use `dr` / `drr` output rather than hard-coding.
- Help: `db??`, `dc?`, `dr??`, `ds??`. Do not confuse debug `ds` with unrelated shell commands of the same prefix outside debug mode.
