---
name: rizin-analysis
description: >-
  Analyzes binaries statically using Rizin >= 0.10.0 / dev (rizin CLI, rzpipe
  Python API, rz-ghidra decompiler, and rz-bin, rz-find, rz-diff, rz-sign,
  rz-ar, rz-ax, rz-hash, rz-asm companion tools) in headless mode with
  .rzdb project session files. Use when disassembling or decompiling
  binaries with Rizin (pdg/pdgj), using CLI modifiers (@ temporary seek, ~
  internal grep/JSON filter, | pipes) or scripting macros (( / .( / ..(),
  evaluating expressions (%) or structured binary formats (pf), computing
  statistical entropy/chi-square/serial-correlation metrics (ph), managing C
  types/structs/noreturn/type-xrefs (t/td/tx/tn), hunting ROP/COP/JOP gadgets
  (/R, /C, /J) or byte patterns (/p), comparing bytes/code in-CLI (c*) or across
  files (rz-diff), recovering C++ vtables or Golang symbols, or running static
  RzIL micro-emulation (aez*). Don't use for live dynamic malware execution or
  non-Rizin disassemblers.
license: LGPL-3.0-only
---

# Rizin Headless Binary Analysis (`rizin`, `rzpipe` & `rz-ghidra`)

Use this skill to perform static binary analysis, reverse engineering, decompilation, and automated configuration/indicator extraction using **Rizin** (`rizin` CLI, `rzpipe` Python bindings, `rz-ghidra` decompiler plugin, and `rz-*` companion tools) in headless mode.

> **Minimum Version Requirement (`Rizin >= 0.10.0` / current `dev`):** This skill targets **Rizin `>= 0.10.0`** (either built from current `dev` or after the `0.10.0` release when it is out). It does **not** apply to the `0.9.x` series, which misses several important features and fixes documented here (including the rewritten `pf` grammar with width-qualified/endian-cased specifiers like `x4`, the tree-sitter `%` `RzNum` expression engine, Go `ABIInternal`/`ABI0` prologue voting and preloaded `types-golang-*.sdb` runtime types, and RzIL fixes).

## 1. CLI Command Modifiers (`@`, `~`, `|`) & Core Principles

### Universal CLI Modifiers (`@` Temporary Seek, `~` Internal Grep, `|` Pipes)

Every Rizin command can be suffixed with `@` (temporary seek/state override), `~` (built-in grep, table slicer, and JSON selector), and `|` (shell pipe or plain-text output):

1. **`@` — Temporary Seek & State Overrides (Applied to Any Command, Restored Afterward):**
   Instead of mutating the current seek with `s <addr>` before running a command, append `@ <target>` to any command (`cmd?` or `@?` for full help). Multiple `@` modifiers can be chained:
   - `@ <addr_or_expr>` — Temporarily seek to an address, symbol/flag name, or `%` math expression (e.g., `pd 10 @ sym.main`, `px 32 @ rsp + 0x20`).
   - `@! <blocksize>` — Temporarily override the command block size `$b` without changing global `b` (e.g., `ph entropy @! 0x1000 @ 0x401000`, `p8 @! $FS @ sym.main`).
   - `@(<from> <to>)` — Temporarily set `analysis.from`/`search.from` and `*.to` address range bounds for the command.
   - `@a:<arch>[:<bits>]` and `@b:<bits>` — Temporarily switch architecture and/or bitness (e.g., `pd 4 @a:arm:16 @ 0x401000`).
   - `@e:<k>=<v>[,<k2>=<v2>]` — Temporarily override `e` configuration variables for a single command without changing the global session configuration (e.g., `/zj "http" li utf8 @e:search.prefix=str_search,search.str.min_length=4`, `pd 8 @e:asm.bytes=false,asm.cmt.il=true @ sym.main`).
   - `@f:<file>`, `@s:<string>`, `@v:<value>`, `@x:<hexpairs>` — Temporarily map the command buffer to file contents, an ASCII string, an integer value (sized by `asm.bits` and ordered by `cfg.bigendian`), or raw hexpairs (e.g., `ph sha256 @s:hello`, `pd 2 @x:4831c0c3`).
   - `@r:<reg>` — Temporarily seek to the current value of register `<reg>` (e.g., `px 64 @r:rsp`).

2. **`~` — Built-in Grep, Column/Line Slicing & JSON Path Selector (`~?`):**
   Filter, slice, sort, count, or extract JSON from any command directly inside Rizin without spawning external shell processes:
   - `cmd~<word>` — Filter lines containing `<word>` (smartcase by default: case-insensitive unless `<word>` contains uppercase letters).
   - `cmd~+<word>` / `cmd~!<word>` — Case-insensitive filter (`~+`) or inverted/negated filter (`~!` excludes matching lines).
   - `cmd~<w1>,<w2>` / `cmd~&<w1>,<w2>` — Match lines containing `<w1>` **OR** `<w2>` (`~w1,w2`), or both `<w1>` **AND** `<w2>` (`~&w1,w2`).
   - `cmd~^<word>` / `cmd~<word>$` — Anchor match to beginning (`^`) or end (`$`) of line.
   - `cmd~[n]` / `cmd~[n-m]` / `cmd~[i,j]` — Select specific whitespace-delimited column(s) `n` (`0`-indexed), column range `n-m`, or column list `i,j`.
   - `cmd~:n` / `cmd~:-n` / `cmd~:s..e` — Slice output by line index: line `n`, last `n` lines (`:-n`), or line range `s..e` (e.g., `afl~:0..10`).
   - `cmd~$[n]` / `cmd~$![n]` — Sort lines numerically by column `n` ascending (`~$[n]`) or descending (`~$![n]`).
   - `cmd~?` / `cmd~?.` — Count matching lines (`~?`) or characters (`~?.`).
   - `cmd~{}` / `cmd~{<jq_like_path>}` — Pretty-print JSON output (`iIj~{}`) or extract nested JSON fields/projections (`iIj~{arch}`, `aflj~{.[] | {name,offset}}`).

3. **`|` — Shell Pipes & Plain-Text Output:**
   - `<cmd> | <program>` — Pipe a Rizin command's `stdout` into an external shell command (e.g., `pd 40 @ sym.main | grep call`, `aflj | jq '.[0]'`).
   - `<cmd> |` (trailing pipe with no program) — Temporarily disable `scr.html` and `scr.color` for `<cmd>`, emitting clean uncolored plain text.
   - Multiple commands are chained sequentially with `;` (e.g., `s sym.main; pdf`).

### Core Headless Principles & Session Rules

1. **Drive Rizin via Persistent Sessions (`rz-pipe` or Rizin MCP), Never Repeated `rizin -qc` Calls:**
   Always interact with Rizin through a persistent session using the **Rizin MCP server** (when available) or **`rz-pipe` (`rzpipe`)** in Python. Do **not** run `rizin -qc "<cmd>"` via the command line in a loop across a project: `-q` quits Rizin immediately after `<cmd>` runs (so any in-memory state or changes from `<cmd>` are lost unless `Ps` is executed), and repeatedly loading and saving the project on every command incurs heavy startup overhead.
2. **Preserve `stderr` for Errors and Command Help (Do Not Blindly Pass `-2`):**
   Rizin prints command syntax errors (`ERROR: Command '...' does not exist`) and automatic command help fallbacks to `stderr`. Suppressing `stderr` with `-2` blinds agents to failed commands and fallback help output.
   - **In `rzpipe` (`rz-pipe` >= 0.5 / PR #61):** Open without `-2` (`rz = rzpipe.open(path)`). `rzpipe` pipes `stdout` and `stderr` separately: `rz.cmdj("<cmd>")` reads `stdout` cleanly without `stderr` interference, while `rz.cmd("<cmd>", ret_stderr=True)` captures `stderr` diagnostics and automatic fallback help when a command fails or produces no `stdout` (explicit `<cmd>?` and `?* <prefix>` help commands print to `stdout`).
3. **Use `aaa` for a One-Time Full Analysis and Save the Session with `Ps`:**
   Standard analysis is `aaa` (full standard analysis: calls, references, strings/Go recovery, signatures) or `aa` (fast: symbols and entrypoints). **Never recommend `aaaa`** (`aaaa` is experimental analysis and slow/noisy).
   - A `.rzdb` file is a **session save file**, only written when `Ps [<file.rzdb>]` is explicitly run (it is **not** an automatic cache).
   - Run `aaa` once when starting a new session in `rzpipe` / MCP, and run `Ps <project.rzdb>` to save the current session state (functions, xrefs, types, `afn` renames, `afvt` variable types, `tn` noreturn attributes, and `CC` comments).
   - **Version-control or snapshot `.rzdb` saves:** Create multiple numbered/named saves (`Ps step1_initial.rzdb`, `Ps step2_typed.rzdb`) or run `git commit` after every `Ps` save (optionally with `e prj.compress=false` for uncompressed SDB text diffs) so the user or agent can roll back to an earlier project state if needed.
4. **Prefer JSON Output (`*j`) for Programmatic Parsing:**
   Append `j` to Rizin commands (`iIj`, `iSj`, `iij`, `izj`, `izxj`, `aflj`, `pdfj`, `pdj`, `pdgj`, `axtj`, `axfj`, `pxj`, `afvlj`, `avj`, `flj`) to obtain structured JSON output and parse it via `rz.cmdj("<cmd>")`.
5. **Use Table Queries (`<cmd>t:...`) for Server-Side Filtering, Sorting & Slicing:**
   Append `t` to commands (`aflt`, `afvlt`, `flt`, `omlt`, `/zt`, `/xt`, `/Rt`, or default table commands `iz`, `izz`, `izx`, `ii`, `iS`) and chain colon-separated `:col/op/val` operations (`aflt:size/gt/500:size/sort/rev:*/head/20`, with optional `:json`, `:csv`, or `:quiet` output modifiers) to filter large tables inside Rizin before returning output.
6. **Prefer `rz-ghidra` (`pdg` / `pdgj`) for Decompilation When Present:**
   Before falling back to raw disassembly (`pdfj` / `pdrj` / `pdj` / `pi`) or RzIL (`plf` / `aez`), check whether the `rz-ghidra` core plugin (`ghidra`) is loaded (`Lcq~^ghidra$`, `Lct:name/eq/ghidra:json`, or `Lcj`) and use `pdg @ <addr>` / `pdgj @ <addr>` for function-level recovery.

## 2. Core Rizin Command & Syntax Reference

Rizin uses structured, consistent command trees (`librz/core/cmd_descs/*.yaml`). Always use native Rizin syntax and argument order:

| Operation | Rizin Syntax | Notes & Argument Order |
| :--- | :--- | :--- |
| **Temporary Seek & Modifiers** | `<cmd> @ <addr>`, `@! <sz>`, `@e:<k>=<v>`, `@x:<hex>`, `@s:<str>`, `@f:<file>`, `@a:<arch>:<bits>` | Applies to any command and restores prior state immediately after. |
| **Internal Grep & Pipes** | `<cmd>~<pat>`, `~+<pat>`, `~!<pat>`, `~[col]`, `~:line`, `~{}`, `<cmd> \| <prog>`, `<cmd> \|` | `~` filters/slices/formats internally; trailing `\|` strips ANSI color/HTML. |
| **Scripting Macros (`(` / `.(`)** | `(<name> [<args>]; <cmds>)`, `(`, `(-<name>`, `.(<name> [<args>])`, `..(<name> [<arg_sets>...])` | Named parameter interpolation uses `${<arg>}` (not `$0`); `..(` runs macro across `N`-tuples of args. |
| **Auto-Analysis Level** | `aa` or `aaa` | `aa` (symbols + entry) or `aaa` (full standard analysis). Never use `aaaa`. |
| **Analysis Config Variables** | `e analysis.in=...`, `e analysis.strings=true`, `e analysis.hasnext=true` | Config namespace is `analysis.*` (inspect all with `el analysis.`). |
| **List Config Vars & Spaces** | `el [key]` / `elj [key]`, `el~+<kw>`; `es` | `el` lists config variables with descriptions (`elj` as JSON, `el~+<kw>` searches settings); `es` lists config spaces. |
| **Command Help & Full Catalog** | `<cmd>?`, `<cmd>??`, `?* [<cmd>]` / `?*j [<cmd>]`, `?*~+<kw>`, `?+` | `<cmd>?` short summary; `<cmd>??` extended help (`details`/`Examples`); `?*~+<kw>` greps summaries; `?+` dumps full command tree JSON (never run interactive `?**` / `?***` / `?**e` in headless mode). |
| **Math & Expression Engine (`%`)** | `% <expr>`, `%j <expr>`, `%v <expr>`, `%p <vaddr>`, `%P <paddr>`, `%$`, `%b64[-]` | Replaced legacy `?` math commands; supports `u8..u128` bitvectors, `addr:le32` deref, and `entropy(addr,n)`. |
| **Table Query Filtering** | `aflt:size/gt/500:size/sort/rev:*/head/20:json` | Colon-separated `:col/op/val`, `t` suffix (`aflt`), descending is `sort/rev`, slice is `*/head/N`. |
| **String & Regex Search** | `/z[jqt] <pattern> [<flags>=l] [<enc>] [@e:search.prefix=<pfx>]` | E.g., `/zj "http" li utf8 @e:search.prefix=str_search`, `/zj "https?://" r utf8`, `/zj "cmd" l utf16le`. |
| **String Search Config Vars** | `e search.prefix=hit`, `e search.str.min_length=8`, `e search.str.max_length=256`, `e str.encoding=utf8` | Also `e str.search.mode=auto` (`auto`, `rosections`, `raw`); override per-command via `@e:search.prefix=...`. |
| **ROP / COP / JOP Gadget Search** | `/R[jqt]`, `/R/[jqt]`, `/Rk[jqt]`, `/Rg[j]`, `/Rs[j]`, `/Rl[j]` (and `/C*`, `/J*`); `pdp` | `/R` = ROP, `/C` = call-oriented (COP), `/J` = jump-oriented (JOP); `/Rk` queries RzIL register constraints. |
| **Pattern & Block Similarity Search** | `/p <patternsize>`, `/P <patternsize>` | `/p` finds repeating byte patterns of `<patternsize>`; `/P` finds blocks similar to current block. |
| **Statistical & Hash Analysis** | `phl[jqt]`, `ph <algo> @! <sz> @ <addr>`, `/ce[j]`, `/cef[j]` | `entropy`, `entropy_fract`, `minentropy`, `chisquare`, `serialcorr` (discover via `phl~entro`, `phl~chi`, `phl~seri`). |
| **In-CLI Comparison (`c*`)** | `c <str>`, `cx <hex>`, `cX <addr>`, `cc <addr>`, `ccd <addr>`, `cf <file>`, `cu[1248d] <addr>` | In-session counterpart to `rz-diff` for comparing bytes, hexpairs, hexdumps, disassembly, and files. |
| **Micro-Emulation VM (RzIL)** | `aezi`, `aezs`, `aezse[j]`, `aezsu`, `aezsue`, `aezv[j]`, `plf`, `plF` | Always use **RzIL** (`aez*` VM emulation, `plf`/`plF` function RzIL listing) for static micro-emulation and lifting. |
| **Instruction Analysis (`ao`)** | `ao[j] [<N>]`, `aoi[<N>]`, `aoip[<N>]`, `aod`, `aoda` | Analyzes instruction properties (operands, size, type, cycles); `aoi`/`aoip` prints instruction RzIL expressions. |
| **Disassembly (`pd*` / `pi*`)** | `pd[jqt] [<N>]`, `pdf[js]`, `pdr[j.]`, `pi [<N>]`, `pif[j]`, `pifc[j]`, `pir[j]`, `piu[q]` | `pd*` prints annotated disassembly; `pi*` prints compact instruction mnemonics/operands (or JSON). |
| **Type Management (`t*`)** | `t[j]`, `td "<C>"`, `tdf`, `to <h>`, `tr <old> <new>`, `tc`, `ts[j]`, `tu[j]`, `te[j]`, `tt[j]`, `tf[j]` | `tx`/`txf`/`txl`/`txg` for type xrefs; `tn`/`tn-` for `noreturn` functions; `tp`/`tpv`/`tpx` to cast data. |
| **Cast Address to C Type** | `tp <type> @ <addr>` (text) / `pfj '?(<type>) <name>' @ <addr>` (JSON) | `tp` prints formatted struct fields; `pfj '?(<type>) <name>'` returns field offsets/sizes/values as JSON; `tsj <type>` lists member types. |
| **Formatted Print (`pf` / `pfj` / `pfn`)** | `u1/u2/u4/u8`, `d1/d2/d4/d8`, `x1/x2/x4/x8`, `f2/f4/f8`, `p4/p8`, `z(utf16le)`, `t(unix32)`, `G(le)` | Explicit sized/parameterised specifiers (lowercase = LE, uppercase = BE); `pfn <name> "<fmt>"` defines named formats, `pf.[j] <name>` prints them (`pf- <name>` deletes). |
| **Rename Local Variable / Arg** | `afvn <new_name> <old_name> @ <addr>` | `<new_name>` comes **first**, `<old_name>` comes **second**. |
| **List Function Variables** | `afvl` / `afvlj` / `afvlt` | Lists all register (`reg`) and stack (`stack`) variables and arguments. |
| **List Flags / Xrefs / Hints / Maps** | `fl` / `flj` / `flt`, `axl` / `axlj`, `ahl` / `ahlj`, `oml` / `omlj` / `omlt`, `ol` / `olj` | Explicit `l` subcommand lists all items (`j` for JSON, `t` for table). |
| **Comments** | `CC <text> @ <addr>` or `CCu <text> @ <addr>`; `CClj` / `CCfj @ <addr>` | `CCu` sets unique comment; `CClj` lists all comments as JSON; `CCfj` lists function comments. |
| **Seek History Undo / Redo** | `shu` (undo) / `shr` (redo) | `shj` lists seek history as JSON. |
| **Project Save / Open** | `Ps [<path.rzdb>]` / `Po <path.rzdb>` / `Poo <path.rzdb>` / CLI `-p <path.rzdb>` | Saves (`Ps`) or loads (`Po` / `Poo` / `-p`) session state in a `.rzdb` file (`e prj.compress=false` for plain-text SDB). |
| **Define Structure Offset in Asm** | `aht <struct.member> @ <insn_addr>` | Use `ahts <offset>` to list matching struct members for a numeric displacement. |
| **Link Global Typed Variable** | `avga <name> <type> @ <addr>`; `aat` | `avgp <name>` prints global value; `avglj` lists globals as JSON; `aat` propagates struct offsets. |
| **C++ Vtables, RTTI & Devirt** | `avj`, `avra`, `avrr`, `aclj`, `avD @ <func_addr>` | `avD` (uppercase `D`) devirtualizes virtual calls in the current function. |
| **FLIRT Signatures** | `Fs <file>`, `Fa [<filter>]`, `Fc <file>`, `Fd <file>`, `Fl[t]` | All FLIRT signature commands live under `F`. |
| **Binary Diffing CLI (`rz-diff`)** | `rz-diff -d myers\|leven\|ssdeep [-j] a b`, `rz-diff -t functions [-j] a b` | `rz-diff -t graphs -0 <fcn> a b` outputs CFG Graphviz DOT diff. |
| **Companion CLI Binaries** | `rz-bin`, `rz-find`, `rz-diff`, `rz-hash`, `rz-asm`, `rz-ax`, `rz-sign`, `rz-ar`, `rz-gg`, `rz-run` | Standalone headless CLI utilities (`-j` for JSON output). |
| **Python Bindings** | `import rzpipe` | `rz.cmd(cmd, ret_stderr=True)`, `rz.cmdj(cmd)`, `rz.cmdJ(cmd)`. |

### Searching Rizin Help Reliably (Headless-Safe)

1. **Short Help (`<cmd>?`) vs. Extended Help (`<cmd>??`):**
   - `<cmd>?` prints the command summary or subcommand table (e.g., `/z?`, `afv?`, `La?`).
   - `<cmd>??` prints the **full extended help**, including `description`, `details`, argument `choices`, `Encodings`, `Regex Flags`, and `Examples` (e.g., `/z??`, `w??`, `La??`, `e??`).
2. **Searching Command Summaries (`?*`) and Settings (`el`):**
   - `?*~+<keyword>` — Case-insensitively search all command names, argument signatures, and 1-line summaries across the entire command tree (e.g., `?*~+noreturn`, `?*~+entropy`).
   - `?* <prefix>~+<keyword>` (or `<prefix>?*~+<keyword>`) — Restrict summary search to a command subtree (e.g., `?* a~+xref`, `?* /~+regex`).
   - `el~+<keyword>` (or `elj`) — Case-insensitively search all `e` configuration variable names and descriptions (e.g., `el~+prefix`, `el~+ghidra`).
3. **Searching the Entire Help Catalog (`?+` Including Descriptions, Examples & Group Nodes):**
   - `?*` only prints 1-line summaries, and `?*j` only visits executable leaf commands (skipping `details`/`Examples` attached to group descriptors like `/z`).
   - `?+` exports the **entire** `RzCmd` descriptor tree (`summary`, `description`, `args`, `choices`, and `details`/`Examples` across all leaf, group, and `@`/`~`/`|` modifier nodes) as a single minified JSON line.
   - **Gotcha:** Because `?+` is a single ~1 MB JSON line, `?+~<keyword>` matches the entire line. Pipe `?+` to `jq` inside the Rizin session (or traverse `rz.cmdj("?+")` in `rzpipe`) to search the whole help:
     ```bash
     # Search all command summaries, descriptions, details, and examples case-insensitively:
     ?+ | jq -r '.. | objects | select(.cmd?) | select((.summary + " " + .description + " " + (.details | tostring)) | test("search.prefix"; "i")) | "\(.cmd)\(.args_str) # \(.summary)"'
     ```
4. **Never Run Interactive HUD Help (`?**`, `?***`, `?**e`) in Headless Mode:**
   - `?**` and `?***` launch `rz_cons_hud()` and **hang waiting for TTY input** in headless/agent mode; `?**e` fails with `Hud mode requires scr.interactive=true.` Always use `?*~+<kw>`, `<cmd>??`, `el~+<kw>`, or `?+` instead.

## 3. Expression Engine (`%` / `RzNum`) & Structured Binary Formatting (`pf` / `RzFormat`)

Rizin overhauled both its expression evaluator (`%`, documented in `doc/math.md`) and its binary format parser (`pf`, documented in `doc/pf.md`). Do **not** use legacy single-letter `pf` specifiers or legacy `?v` / `[4:addr]` math syntax.

### 1. Changed `%` Expression Evaluator Syntax (`doc/math.md`)

All math, base conversion, address translation, and expression evaluation commands live under **`%`** (`%?`), replacing the legacy `?` evaluator:
- **Core `%` commands:**
  - `% <expr>` / `%j <expr>` — Evaluate `<expr>` and display all representations (`int64`, `uint64`, `hex`, `octal`, `binary`, `float`, `bytes`, `string`) as text or JSON.
  - `%v <expr>` / `%vx <expr>` — Print only the evaluated result (`%vx` forces 8-digit hex output).
  - `%p <vaddr>` / `%P <paddr>` — Translate virtual address to physical file offset (`%p`), or physical offset to virtual address (`%P`).
  - `%$ [<var>]` — List all built-in `$` state variables (`$$` current seek, `$b` block size, `$F` function start, `$FS` function size, `$FE` function end, `$FB` function BBs, `$S` section offset, `$SS` section size, `$j` jump target, `$f` fail addr, `$v` opcode immediate, `$?` last comparison result), or print the value of `<var>` (`%$j` does not exist).
  - `%b64 <str>` / `%b64- <b64>` — Base64 encode or decode a string.
  - `%B` / `%Bj` / `%Bt` — Inspect `[from, to)` address boundaries for the active `search.in` mode (`%Bj @e:search.in=io.maps`, `%Bj @e:search.in=bin.sections.x`, `%Bj @e:search.in=analysis.fcn`, etc.).
- **New `RzNum` Expression Capabilities vs. Legacy Syntax:**
  - **4 Value Kinds:** 64-bit unsigned integer (`ut64`), IEEE-754 `double` (`1.5`, `1e-3`, `nan`, `inf`), arbitrary-precision **bignums** (`big`, promoted automatically for integer literals exceeding 64 bits), and **fixed-width modular bitvectors** via `u8`, `u16`, `u32`, `u64`, `u128` suffixes (e.g., `% 200u8 + 100u8` wraps modulo 256 to `0x2c`; `% len(0u32)` -> `32`).
  - **Unit & String Literals:** IEC/SI byte suffixes (`4KiB`, `2MiB`, `1GB`, `500KB`) and string-as-bytes bitvector literals (`% "ABCD"`).
  - **Persistent Session Variables & Statement Sequencing:** Bind variables across commands with `x = 0x401000` (or `let x = 0x401000`) and chain statements inside a quoted `%` expression with `;` (e.g., `% "key = 0x403000:le32; key ^ 0xdeadbeef"` — quote the expression so Rizin's CLI parser does not split on `;` before passing it to `%`).
  - **Extended Operators:** Exponentiation (`**`), logarithm (`x log y`), bitwise rotate left/right (`<<<`, `>>>`), explicit two's-complement signed division/modulo/shift (`sdiv`, `smod`, `sar`), and C ternary (`cond ? a : b`, which also lifts to RzIL `ite`).
  - **Typed Memory Dereference (`<literal_addr>:<spec>`):** Dereference target memory directly on **numeric address literals** inside expressions using `[le|be]?[s]?(8|16|32|64|128)` for integers (unsigned by default, `s` for sign-extended) or `[le|be]?f(16|32|64|128)` for IEEE-754 floats (endianness defaults to `cfg.bigendian`; bare `<literal_addr>:` defaults to `asm.bits`). Note: `:<spec>` attaches only to numeric literals (not parenthesized expressions `($$ + 8):be64` or symbol names `entry0:le32`), do **not** write `:u32` (use `:32` or `:le32`), and max dereference width is `128` bits. Examples:
    ```bash
    % 0x403000:le32 + 0x10       # Read 32-bit LE uint at 0x403000 and add 0x10 (replaces legacy [4:0x403000])
    % 0x403008:be64              # Read 64-bit BE uint at 0x403008
    % 0x403000:s16               # Read sign-extended 16-bit integer at 0x403000
    % 0x403000:lef32             # Read 32-bit LE IEEE-754 float at 0x403000
    % 0x403000:128               # Read 128-bit bitvector at 0x403000
    ```
  - **Built-in Pure & IO-Backed Host Functions:**
    - Pure functions: `min(a, b)`, `max(a, b)`, `abs(x)`, `popcount(x)`, `len(x)` (bit width).
    - IO-backed functions over `(addr, size)` in the open binary (`size` capped at `0x10000` / 64 KiB; use `ph <algo> @! <size> @ <addr>` for buffers `> 64 KiB`): `entropy(addr, n)` (`0.0..8.0`), `temperature(addr, n)` (`0.0..100.0` scaled entropy), `md5(addr, n)`, `sha1(addr, n)`, `sha256(addr, n)`, `sha384(addr, n)`, `sha512(addr, n)`, `hash(addr, n)`, `adler32(addr, n)`, `xxhash(addr, n)`, `crc(addr, n [, width])`, `crc8(addr, n)`, `crc16(addr, n)`, `crc32(addr, n)`, `crc64(addr, n)`.
    ```bash
    % sha256($$, $FS)            # 256-bit SHA-256 bitvector of the current function
    % "entropy($$, $FS) > 7.2"   # Returns 1 if current function entropy > 7.2 (quote `>` so CLI does not redirect to a file)
    ```

### 2. Changed `pf` Structured Binary Format Syntax (`doc/pf.md`)

`pf` (`pf`, `pfj`, `pfo`, `pfn`, `pf-`, `pf.`, `pfc`, `pfd`, `pfv`, `pfw`, `pfs`) uses explicit width-qualified and parameterised specifiers:
- **What Changed Compared to Legacy Versions:**
  - **Single-letter integer/float/string specifiers are deprecated and emit warnings:** Do **not** use legacy `b` (`u1`), `w` (`u2`), `d` (`d4`), `q` (`u8`), `x` (`x4`), `X` (`x1`), `i` (`d4`), `o` (`o4`), `f` (`f4`), `F` (`f8`), `C` (`c`), `t` (`t(unix32)`), `T` (`T(unix32)`), or `Z` (`z(utf16le)` or `z(utf16be)`).
  - **Case encodes endianness directly on every multi-byte specifier:** Lowercase is **little-endian** (`u2`, `u4`, `u8`, `d4`, `x4`, `f4`, `t(unix32)`, `G(le)`), and uppercase is **big-endian** (`U2`, `U4`, `U8`, `D4`, `X4`, `F4`, `T(unix32)`, `G(be)`).
  - **Standalone `<` and `>` endian switches are removed:** Use explicit uppercase/lowercase specifiers, or use context-endian `n1`/`n2`/`n4`/`n8` (which inherit endianness from `cfg.bigendian` or from an enclosing `V(...,e=be)` / `B(...,e=be)`).
  - **Named formats use `pfn` to define/list, `pf-` to delete, and `pf.` to print:** `pfn <name> "<fmt>"` registers a named format (`pfn` lists all named formats, `pf- <name>` deletes one, `pf-*` deletes all), while `pf.[j] [<name>]` prints data at the current seek using a registered named format.
  - **Removed legacy constructs:** `.pf*` (executing format output as Rizin commands), `pfw.` (leading dot when writing fields — use `pfw <fmt_name>.<field> <val>` directly), and `r (regname)` register reading.
- **Canonical `pf` Specifier Reference:**

| Category | Canonical `pf` Specifiers | Description & Examples |
| :--- | :--- | :--- |
| **Integers (LE / BE)** | `{u,d,x,o,b}{1,2,4,8}` (LE) / `{U,D,X,O,B}{1,2,4,8}` (BE) | Unsigned (`u`), signed (`d`), hex (`x`), octal (`o`), binary (`b`) of `1, 2, 4, 8` bytes. |
| **Context-Endian Ints** | `n1`, `n2`, `n4`, `n8` | Unsigned integers whose endianness comes from `cfg.bigendian` or enclosing `V(...,e=le\|be)`. |
| **Floats (LE / BE)** | `f2`, `f4`, `f8` (LE) / `F2`, `F4`, `F8` (BE) | IEEE-754 half (`f2`), single (`f4`), and double (`f8`) precision floats. |
| **Strings & Encodings** | `z`, `z(<enc>)`, `[N]z`, `z[W]`, `z(<enc>)[<W>b]`, `s`, `c` | `z` = NUL-terminated string; `<enc>` = `ascii`, `utf8`, `utf16le`, `utf16be`, `utf32le`, `ibm037`, etc.; `[32]z` = fixed 32-byte string; `z[2]` / `z(utf16le)[2b]` = length-prefixed string (`W` in `1,2,4,8`; `b` = prefix in bytes, e.g. BSTR); `s` = `char*` pointer; `c` = single ASCII char. |
| **Timestamps & GUIDs** | `t(<kind>)` (LE) / `T(<kind>)` (BE); `G` / `G(ms\|le\|be)` | `<kind>` = `unix32`, `unix64`, `unixms`, `unixus`, `unixns`, `filetime`, `dos`, `hfs`, `oletime`, `webkit`, `cocoa`. |
| **Pointers & Deref** | `p`, `p2`, `p4`, `p8`; `*<spec>` | `p` uses `asm.bits`; `*<spec>` dereferences a pointer (`*u4`, `*z(utf8)`, `*?(my_struct)`). |
| **Bitfields & Packed Bits** | `B{1,2,4,8}(K=V,...)`, `B4 (enum_t)name`, `:N`, `:N<`, `:N>` | Inline bitmask flags (`B4(R=1,W=2,X=4) perms`), typed bitfield (`B4 (perm)flags`), or packed C bitfields (`:4:4 nibble_lo nibble_hi`). |
| **Enums & Structs** | `E (enum_t)f`, `[1\|2\|4\|8]E (enum_t)f`, `?(struct_t) f` | Resolve enum member names (`E (cmd_id)op` or `[2]E (cmd_id)op`) or nest registered `pfn` / `td` structs (`?(hdr_t) hdr`). |
| **TLV & Bitvectors** | `V(t=u1,l=u2,e=le,h=v,d=tbl)`, `v(N[,lsb\|msb])` | Parse Type-Length-Value streams (`h=v` value-len or `h=l` total-len) or arbitrary `N`-bit bitvectors. |
| **Arrays, Skip & Align** | `[N]<T>`, `[@<len_field>]<T>`, `.` / `[N].`, `@N`, `0...` | Fixed array `[16]u1`, dynamic array sized by an earlier field `[@count]u4`, skip `.`, align `@4`, union `0`. |

```bash
# Parse a config header with magic, UTF-16LE BSTR, Win32 FILETIME, inline bitflags, and dynamic array (quote format strings containing `(...)` or `[...]`):
pfj "x4z(utf16le)[2b]t(filetime)B4(SSL=1,PROXY=2,PERSIST=4)u2[@count]u4" magic mutex compiled_at flags count ports @ 0x403000
pfj "x4x4d4z(utf8)*z" magic key1 sid title c2_url_ptr @ 0x403000  # Includes *z pointer-to-string dereference

# Define a named format (`pfn`), print it (`pf.` / `pf.j`), promote it to `RzTypeDB` (`tdf`), or write to a field (`pfw`):
pfn c2_pkt "x4u2u2[@len]u1 magic cmd len body"
pfs c2_pkt                                    # Print size in bytes of a registered `pfn` format (or inline `pf` format string)
pf.j c2_pkt @ 0x403000                        # Print memory at 0x403000 using registered named format `c2_pkt` as JSON
tdf c2_pkt c2_pkt                             # Promote saved `pfn` format into `RzTypeDB`
tdf pkt_hdr "x4u2u2z magic cmd_id payload_len tag"  # Or promote an inline `pf` format string directly into `RzTypeDB`
pfw c2_pkt.cmd 0x05 @ 0x403000                # Write 0x05 to field `cmd` (requires `-w` or `e io.cache=true`)
```

## 4. Persistent Session Management (`rz-pipe` / MCP), `.rzdb` Saves (`Ps`) & Stderr Visibility

### 1. Why You Must Use `rz-pipe` (`rzpipe`) or Rizin MCP (Never Loop `rizin -qc ...`)
- **Do not spawn `rizin -p <file.rzdb> -qc "<cmd>" <binary>` in a loop:** Every CLI invocation starts a new process, deserializes the entire `.rzdb` session file, executes one command, and exits immediately without persisting any state changes unless `Ps` was explicitly called.
- **Keep a single persistent session open:** Use a **Rizin MCP** server (when available) or a persistent **`rzpipe.open(...)`** instance in Python so the binary is loaded once and all analysis, renames, comments, types, and RzIL VM state stay live in memory across queries.

### 2. Saving & Versioning `.rzdb` Session Files (`Ps`, `Po`, `e prj.compress=false`)
- **`.rzdb` is an explicit session save file, not an automatic cache:** Opening a project with `-p <file.rzdb>` (or `Po <file.rzdb>`) loads the saved state into memory, and nothing is written back to disk until you explicitly run `Ps [<file.rzdb>]`.
- **Save multiple checkpoints or commit `.rzdb` to Git so the user can revert:** Before and after major analysis phases (initial `aaa`, bulk function/variable renaming, struct/type application, or memory patching), either save numbered/named `.rzdb` snapshots (`Ps sample_01_initial.rzdb`, `Ps sample_02_typed.rzdb`) or commit the `.rzdb` file to a Git repository after each `Ps`.
- **Tip for Git-tracked `.rzdb` projects:** Set `e prj.compress=false` before running `Ps` when storing `.rzdb` in Git so the project file is written as an uncompressed plain-text SDB database rather than a gzip blob, producing readable diffs across commits.

### 3. Persistent In-Process `rzpipe` Session Pattern

Keep one `rzpipe` session open across queries and do **not** pass `-2` so `ret_stderr=True` can retrieve command errors and help output (`rz-pipe` PR #61):

```python
import hashlib, os, subprocess, rzpipe
from pathlib import Path

def open_session(binary_path: str, project_file: str | None = None, git_versioned: bool = False) -> tuple[rzpipe.open, str]:
    if project_file is None:
        sha256 = hashlib.sha256(Path(binary_path).read_bytes()).hexdigest()
        project_file = f"{sha256}.rzdb"
    if os.path.exists(project_file):
        rz = rzpipe.open(binary_path, flags=["-p", project_file])
    else:
        rz = rzpipe.open(binary_path)
        if git_versioned:
            rz.cmd("e prj.compress=false")
        rz.cmd("aaa")
        rz.cmd(f"Ps {project_file}")
    return rz, project_file

def checkpoint_save(rz: rzpipe.open, project_file: str, commit_msg: str | None = None) -> None:
    """Save the current session to `.rzdb` and optionally commit it to git for rollback."""
    rz.cmd(f"Ps {project_file}")
    if commit_msg:
        subprocess.run(["git", "add", project_file], check=False)
        subprocess.run(["git", "commit", "-m", commit_msg], check=False)

rz, project_file = open_session(binary_path, git_versioned=True)
info = rz.cmdj("iIj")                                    # JSON commands read stdout cleanly
funcs = rz.cmdj("aflj")
help_out = rz.cmd("aez?")                                # Explicit '<cmd>?' help writes to stdout
diag = rz.cmd("af @ 0x401000", ret_stderr=True)          # ret_stderr=True captures stderr errors/fallback help
checkpoint_save(rz, project_file, "Save function analysis and renames")
rz.quit()
```

## 5. JSON Command Reference (`cmd` / `cmdj`)

| Analysis Task | Rizin Command (`cmd` / `cmdj`) | Key JSON Fields |
| :--- | :--- | :--- |
| **Binary Metadata** | `iIj` | `arch`, `bits`, `os`, `bintype`, `baddr`, `canary`, `nx`, `pie`, `stripped`, `static`, `compiler`, `lang` |
| **Segments / Sections** | `iSSj` (segments) / `iSj` (sections) | `name`, `vaddr`, `vsize`, `paddr`, `size`, `perm`, `type` |
| **Entry Points** | `iej` | `vaddr`, `paddr`, `baddr`, `laddr`, `hvaddr`, `haddr`, `type` |
| **Imports / Exports** | `iij` / `iEj` | `iij`: `ordinal`, `bind`, `type`, `name`, `plt`; `iEj`: `name`, `flagname`, `vaddr`, `size`, `type` |
| **Strings (`RzBin`)** | `izj` (data) / `izzj` (whole bin) / `izxj` (with xrefs) | `vaddr`, `paddr`, `string`, `length`, `size`, `section`, `type` (`izxj` adds `flag`, `xref-from`) |
| **String Search (`RzSearch`)** | `/zj <pattern> <flags> <enc> [@e:search.prefix=<pfx>]` | `address`, `size`, `flag` (`<search.prefix>.string.<enc>.<N>`, default `hit`), `detail` (does **not** populate `izz`) |
| **Byte / Hex Search** | `/xj <hex_pattern> [@e:search.prefix=<pfx>]` | `address`, `size`, `flag` (`<search.prefix>.bytes.<N>`); supports `.` nibble wildcards (e.g. `/xj 8b0485........5dc3`) |
| **ROP / COP / JOP Search** | `/Rj [str]`, `/Rkj <constraints>`, `/Cj`, `/Jj` | Array of gadget dicts (`ret_addr`, `size`, `stack_change`, `instructions`, `modified_registers`) |
| **Statistical / Hash Digest** | `ph <algo> @! <len> @ <addr>` / `phlj` | `ph` prints raw float/hex digest (`algo`: `entropy`, `entropy_fract`, `minentropy`, `chisquare`, `serialcorr`, `sha256`, ...); `phlj` lists all algorithms as JSON |
| **List Functions** | `aflj` | `offset`, `name`, `size`, `realsz`, `nbbs`, `cc`, `calltype`, `signature`, `codexrefs`, `callrefs`, `datarefs`, `indegree` |
| **Function Details & Vars** | `afij @ <addr>` / `afvlj @ <addr>` | `afvlj` dict: `{"stack": [...], "reg": [...], "eval_pending": [...]}` with `name`, `arg`, `type`, `storage` |
| **Disassemble Function** | `pdfj @ <addr>` or `pdrj @ <addr>` | `pdfj` returns `{"name", "size", "addr", "ops": [...]}`; `pdrj` returns `[...]` (list of op dicts directly) |
| **Disassemble N Instrs** | `pdj <N> @ <addr>` | Array of instruction dicts (`offset`, `bytes`, `opcode`, `disasm`, `ptr`, `val`, `jump`, `fail`, `fcn_addr`) |
| **Instruction Analysis** | `aoj <N> @ <addr>` | `addr`, `opcode`, `disasm`, `mnemonic`, `bytes`, `size`, `type`, `opex`, `rzil` |
| **Decompile (`rz-ghidra`)** | `pdg @ <addr>` / `pdgj @ <addr>` | `code` (C string) and `annotations[]` (`start`, `end`, `type`, `offset`, `name`) |
| **Xrefs TO / FROM Address** | `axtj @ <addr>` / `axfj @ <addr>` | Array of `{"from": <int>, "to": <int>, "type": "CALL" \| "CODE" \| "DATA" \| "STRING"}` |
| **Function + Delta Lookup** | `afd @ <addr>` / `afoj @ <addr>` | `afd`: `"<fcn_name> + <delta>"`; `afoj`: `{"address": <fcn_start_va>}` |
| **Read Raw Bytes** | `p8 <len> @ <addr>` / `pxj <len> @ <addr>` | Hex string (`p8`) or list of `0..255` ints (`pxj`) |
| **Types & Noreturn** | `tj`, `tsj [<s_name>]`, `tuj`, `tej`, `ttj`, `tfj`, `tnj` | `tsj` dumps struct member names/types; `tfj` dumps function prototypes; `tnj` lists `noreturn` functions |
| **List / Set Flags** | `flj` / `f <name> [<size>] @ <addr>` | `flj`: `[{"name", "realname", "size", "offset"}]` |
| **List / Set Comments** | `CClj` / `CCu <text> @ <addr>` | `CClj`: `[{"offset", "type", "name"}]` (`CCfj @ <addr>` for current function) |
| **Math / Base Evaluation** | `%j <expr>` / `%p <vaddr>` / `%P <paddr>` | `%j`: `{"int64", "uint64", "hex", "binary", ...}`; `%p`: physical offset |

## 6. `rz-ghidra` Decompiler & SLEIGH Integration (`pdg*`)

The `rz-ghidra` core plugin (`libcore_ghidra.so`) embeds the native **Ghidra C++ decompiler** and **SLEIGH disassembler/P-code lifter** directly into Rizin (`pdg?`). Prefer `pdg` / `pdgj` for function decompilation whenever `rz-ghidra` is present:

```bash
Lcq~^ghidra$                   # Check if rz-ghidra is loaded (prints "ghidra" if present, empty if absent)
Lct:name/eq/ghidra:json        # Structured JSON check (`[{"name":"ghidra",...}]` or `[]`)
```

### 1. `pdg*` Command Reference
| Command | Purpose |
| :--- | :--- |
| `pdg @ <addr>` | Decompile the function at `<addr>` into C pseudocode |
| `pdgj @ <addr>` | Decompile the function at `<addr>` as structured JSON (`RzAnnotatedCode`: `code` + `annotations[]`) |
| `pdgo @ <addr>` | Decompile side-by-side with instruction virtual addresses (`0x... \| <C line>`) |
| `pdg* @ <addr>` | Emit decompiled statements as Rizin `CCu base64:... @ 0x...` comment commands |
| `pdgx @ <addr>` | Dump raw Ghidra decompiler XML for the current function (`pdgd` for debug XML) |
| `pdgs` / `pdgss` | List all available SLEIGH language IDs (`pdgs`) or print the auto-matched SLEIGH ID (`pdgss`, e.g. `x86:LE:64:default`) |
| `pdgsd [<N>] @ <addr>` | Disassemble `N` instructions with Ghidra SLEIGH and print their raw **P-code** operations |
| `pdga` | Switch Rizin's active `asm.arch` and `analysis` plugins to Ghidra SLEIGH (`e asm.arch=ghidra`) |

### 2. Parsing `pdgj` (`RzAnnotatedCode`) to Map C Code Back to Assembly Offsets
`pdgj` returns `{"code": "<full C code>", "annotations": [...]}` (or `{"errors": [...]}` if no function exists at the seek address). Each item in `annotations` marks a byte slice `code[start:end]` with one of:
- `{"start": s, "end": e, "type": "offset", "offset": <insn_vaddr>}` — maps a token/statement directly to the underlying instruction VA.
- `{"start": s, "end": e, "type": "function_name", "name": "<callee>", "offset": <callee_vaddr>}`
- `{"start": s, "end": e, "type": "global_variable" | "constant_variable", "offset": <data_vaddr>}`
- `{"start": s, "end": e, "type": "local_variable" | "function_parameter", "name": "<var_name>"}`
- `{"start": s, "end": e, "type": "syntax_highlight", "syntax_highlight": "keyword" | "datatype" | ...}`

```python
dec = rz.cmdj(f"pdgj @ 0x{func_va:x}") or {}
if "errors" in dec:
    rz.cmd(f"af @ 0x{func_va:x}")  # Ensure a function is defined at func_va before calling pdgj
    dec = rz.cmdj(f"pdgj @ 0x{func_va:x}") or {}
code = dec.get("code", "")
for ann in dec.get("annotations", []):
    if ann.get("type") in ("function_name", "global_variable", "constant_variable"):
        print(f"{ann['type']:18s} {code[ann['start']:ann['end']]:30s} -> 0x{ann['offset']:x}")
```

### 3. Enriching `rz-ghidra` Output with Rizin Types, Variables, Globals, Noreturn & Comments
`rz-ghidra` queries `RzCore` (`RizinScope`, `RizinTypeFactory`, `RizinCommentDatabase`) on every `pdg` / `pdgj` call. Modifying Rizin metadata immediately refines the decompiled C output without re-running `aaa`:

```bash
afn mw_rc4_crypt @ 0x140001200                                                # 1. Rename function
afc ms @ 0x140001200                                                          # 2. Set calling convention (see `afcl` for arch list)
afs "void mw_rc4_crypt(uint8_t *state, uint8_t *buf, size_t len)" @ 0x140001200 # 3. Set C prototype
tn mw_fatal_exit                                                              # 4. Mark custom panic/exit wrapper as noreturn
td "struct c2_config { uint32_t magic; uint16_t port; char host[64]; };"      # 5. Define C struct (RizinTypeFactory)
afvn cfg_ptr var_18h @ 0x140001500                                            # 6. Rename var (new_name FIRST!)
afvt cfg_ptr "struct c2_config *" @ 0x140001500                               # 7. Retype variable
avga g_config c2_config @ 0x140008000                                         # 8. Bind typed global (RizinScope)
CCu "RC4 PRGA keystream xor" @ 0x14000124a                                    # 9. Add comment (RizinCommentDatabase)
pdg @ 0x140001500                                                             # 10. Re-decompile with updated metadata
```

### 4. `ghidra.*` Configuration Variables (`el ghidra.`)
- `e ghidra.lang=x86:LE:64:default` — Override auto-detected SLEIGH language ID (`pdgs` lists all IDs).
- `e ghidra.sleighhome=/path/to/sleigh` — Path to SLEIGH `.sla`/`.pspec`/`.cspec` definitions.
- `e ghidra.rawptr=true` — Show unknown globals as raw addresses (`false` to synthesize global symbols).
- `e ghidra.ropropagate=true` — Propagate read-only memory values as constants during decompilation.
- `e ghidra.maximplref=2` — Max references to an expression before introducing an explicit temporary variable.
- `e ghidra.verbose=false` — Silence `[rz-ghidra]` header warnings in decompiled output.

## 7. Type Management (`t*`), Type Xrefs (`tx`), Noreturn (`tn`), Variables & C++ Vtables

Rizin maintains a full C type database (`RzTypeDB`, queried and modified via `t?`) that drives disassembly hints (`aht`), structure casting (`tp`), `pf` formatting (`tdf`), and `rz-ghidra` decompilation (`pdg`).

### 1. Complete `t*` Type Management Reference

| Task | Rizin Command (`t?`) | Description |
| :--- | :--- | :--- |
| **List / Inspect Types** | `t` / `tj`, `t <type>`, `tc [<type>]`, `tcd [<type>]` | List all loaded types (`t`/`tj`), show `pf` format for `<type>`, or dump C declarations (`tc`, `tcd` single-line). |
| **Define Type from C / `pf`** | `td "<C_decl>"`, `tdf <name> <pf_fmt>` | Parse a C `struct`, `union`, `enum`, or `typedef` declaration (`td`), or promote a `pf` format into a C type (`tdf`). |
| **Load Header / SDB Files** | `to <path.h>`, `tos <path.sdb>` | Parse C header file (`to`; respects `e dir.types`) or load SDB type database (`tos`). |
| **Rename or Delete Types** | `tr <old_name> <new_name>`, `t- <type>`, `t-*` | `tr` renames `<old_name>` and updates **all** structs, unions, typedefs, and functions referencing it; `t-` deletes. |
| **Structures & Unions** | `ts[j] [<name>]`, `tsc <name>`, `tsd <name>`, `tu[j] [<name>]`, `tuc <name>`, `tud <name>` | List structs (`ts`/`tsj`) or unions (`tu`/`tuj`), or print C definition (`tsc`/`tuc` multi-line, `tsd`/`tud` single-line). |
| **Enums & Bitfields** | `te[j] [<enum> [<val>]]`, `teb <enum> <member>`, `tec [<enum>]`, `tef <val>` | List enums (`te`/`tej`), lookup member by value (`te <enum> 0x2`), get bitmask (`teb`), or find all enums matching `<val>` (`tef`). |
| **Typedefs & Prototypes** | `tt[j] [<name>]`, `ttc [<name>]`, `tf[j] [<func>]`, `tfc <func> [<cc>]`, `tf- <func>` | Inspect typedefs (`tt`/`ttj`) and function prototypes (`tf`/`tfj`) or calling conventions (`tfc`, `tcc[j]`) in `RzTypeDB`. |
| **Type Cross-References (`tx`)** | `tx [<type>]`, `txf [<addr>]`, `txl`, `txg` | `tx <type>`: functions using `<type>` (`tx` with no args lists every function and its types); `txf`: types used in function at `<addr>`; `txl`: all types used by any function; `txg`: render type xref graph. |
| **Noreturn Functions (`tn`)** | `tn[j] [<name_or_addr>]`, `tn- <name_or_addr>...`, `tn-*` | List (`tn`/`tnj`), mark a function/address (`tn <name_or_addr>`), or unmark (`tn-`) functions as `noreturn`. |
| **Cast & Print Memory/Values** | `tp <type> [<addr_or_var>]`, `tpv <type> [<val>]`, `tpx <type> <hexpairs>` | Format memory at `<addr>` or stack/reg `<var>` (`tp`), an immediate scalar (`tpv`), or raw hexpairs (`tpx`) as `<type>`. |
| **Atomic Typeclasses (`tk`)** | `tk <type>`, `tkl[jt]`, `tks <type> <class>` | Query, list, or assign atomic typeclass (`Num`, `Integral`, `Floating`, `Address`, `Signed Integral`, `Unsigned Integral`). |

```bash
# 1. Define C types, enums, and structs, then cast memory and propagate offsets:
td "enum pkt_cmd { CMD_PING = 1, CMD_EXEC = 2, CMD_UPLOAD = 4 };"
td "struct bot_ctx { uint8_t pad[520]; char sid[4]; uint32_t xor_key; };"
tsj bot_ctx                                               # Dump struct member names and types as JSON
tp bot_ctx @ 0x140008000                                  # Cast and print formatted struct at <addr>
pfj '?(bot_ctx) ctx' @ 0x140008000                        # Cast and dump struct fields (offset, size, value) at <addr> as JSON
avga g_ctx bot_ctx @ 0x140008000; avgp g_ctx; aat         # Bind global struct, print it, and propagate field offsets
ahts 0x208                                                # List all struct members across RzTypeDB matching displacement 0x208
aht bot_ctx.sid @ 0x140002b3e                             # Apply struct member offset hint to instruction operand
tr bot_ctx mw_bot_context                                 # Rename type globally across all referencing types & functions

# 2. Query type cross-references (`tx*`) to find every function touching a struct or type:
tx mw_bot_context                                         # List all functions referencing `mw_bot_context`
txf @ 0x140001500                                         # List all types used by the function at 0x140001500
txl                                                       # List all types referenced by at least one function

# 3. Manage `noreturn` functions (`tn*`) so CFG recovery and `pdg` stop after custom exit/panic stubs:
tn 0x140005120; tn sym.mw_abort                           # Mark address or symbol as noreturn (one target per `tn` call)
tnj                                                       # List all noreturn functions/addresses as JSON
af- @ 0x140001500; af @ 0x140001500                       # Re-analyze caller so trailing dead bytes are truncated
```

### 2. Inspecting & Typing Function Variables (`afv`)
```bash
afvlj @ 0x401000                        # List all register & stack variables/args as JSON (`afvlt` for table)
afvn decrypt_key var_18h @ 0x401000     # Rename `var_18h` -> `decrypt_key` (NOTE: new_name is first!)
afvt decrypt_key uint32_t @ 0x401000    # Set variable type (immediately visible to `pdg`, `tx`, and `afvlj`)
aat @ 0x401000                          # Convert immediate operands in function to linked struct offsets
afvR decrypt_key @ 0x401000             # List instructions reading variable (`afvW` for writes, `afvxj` for JSON)
```

### 3. C++ Virtual Tables / RTTI (`av`, `acl`) & FLIRT Signatures (`F`)
```bash
avj                                     # List all discovered C++ virtual tables as JSON
avra; avrr; aclj                        # Parse RTTI, recover C++ classes, and list classes/vtables/methods as JSON
avD @ 0x401000                          # Devirtualize C++ virtual method calls in function at current offset
Fs /path/to/library.sig; Fa             # Apply FLIRT signature file (.sig/.pat) or scan built-in sigdb
```

## 8. Statistical Analysis of Compressed & Encrypted Data (`ph`, `/ce`, `%`)

To distinguish encrypted payloads (RC4/AES/ChaCha20/custom stream ciphers) from compressed archives (zlib/LZMA/zstd/UPX) or high-entropy code/tables, use Rizin's built-in statistical digest plugins (`phl`, `ph`, `/ce`, `/cef`, `%`, and `rz-hash`):

### 1. Discovering Statistical Algorithms (`phl`)
```text
[0x100000960]> phl~chi
chisquare      LGPL3      xvilka                         Chi-square goodness-of-fit vs uniform
[0x100000960]> phl~entro
entropy        LGPL3      deroad                         Entropy [0.0-8.0] range
entropy_fract  LGPL3      deroad                         Fractional entropy [0.0-1.0] range
minentropy     LGPL3      xvilka                         Min-entropy [0.0-8.0] range
[0x100000960]> phl~seri
serialcorr     LGPL3      xvilka                         Serial correlation coefficient [-1.0-1.0]
```

### 2. Interpreting the 5 Statistical Metrics Together
| Algorithm (`ph <algo>`) | Range | What It Measures & How to Distinguish Encryption vs. Compression |
| :--- | :--- | :--- |
| **`entropy`** | `[0.0 - 8.0]` | **Shannon entropy** (bits per byte). Plaintext/code is typically `4.5 - 6.5`; both compressed and encrypted data score `> 7.2` (so Shannon entropy alone cannot separate compression from encryption). |
| **`entropy_fract`** | `[0.0 - 1.0]` | Normalized fractional Shannon entropy (`entropy / 8.0`). |
| **`minentropy`** | `[0.0 - 8.0]` | **Min-entropy** ($-\log_2(\max P(X_i))$): worst-case predictability determined by the single most frequent byte value. True ciphertext has `minentropy` close to `entropy` (`> 7.0`); compressed streams or XOR-padded blobs with frequent header/dictionary/zero bytes show a noticeably lower `minentropy` than `entropy`. |
| **`chisquare`** | `[0.0 - +inf)` | **Chi-square ($\chi^2$) goodness-of-fit vs. uniform distribution** (255 degrees of freedom; ideal uniform random mean $\approx 255$). Strong encryption / CSPRNG output stays near `[200 - 310]`, whereas compressed streams (Deflate/LZMA) exhibit skewed byte histograms (`chisquare > 350 - 1000+`) despite having `entropy > 7.8`. |
| **`serialcorr`** | `[-1.0 - 1.0]` | **Serial correlation coefficient** between adjacent bytes $(b_i, b_{i+1})$. Uniformly encrypted/random data is near `0.0` (`|serialcorr| < 0.05`); structured tables, uncompressed media, or weak byte-wise transforms show non-zero adjacent correlation. |

### 3. Running Statistical Analysis in CLI, `rzpipe`, and `rz-hash`
```bash
# Compute metrics over a specific address and block size using `@! <size> @ <addr>` (`ph` outputs the raw float/hex digest):
ph entropy @! 0x4000 @ 0x140008000
ph chisquare @! 0x4000 @ 0x140008000
ph minentropy @! $SS @ $S                 # Min-entropy of the current section ($S = section start, $SS = section size)
ph serialcorr @! $SS @ $S                 # Serial correlation of the current section

# Search for blocks within a specific entropy range across `search.in` (`/ce` and `/cef`):
/cej 7.5 8.0 512                          # Find 512-byte blocks with Shannon entropy in [7.5, 8.0] as JSON
/cefj 0.90 1.0 256                        # Find 256-byte blocks with fractional entropy in [0.90, 1.0] as JSON

# Evaluate entropy directly inside `%` / `%j` expressions (up to 64 KiB):
%j entropy(0x140008000, 0x4000)           # Float Shannon entropy [0.0-8.0] as JSON
%j temperature(0x140008000, 0x4000)       # Scaled entropy percentage [0.0-100.0] as JSON

# Compute all 5 metrics in one shot from the shell via `rz-hash`:
rz-hash -j -a entropy,entropy_fract,minentropy,chisquare,serialcorr sample.bin
```

```python
# Automated per-section encryption vs. compression classifier in rzpipe:
# `ph <algo>` prints a bare decimal float for statistical algorithms, so `rz.cmdj(...)` parses it directly into a Python `float`.
for sec in rz.cmdj("iSj") or []:
    if sec.get("size", 0) >= 256 and sec.get("vaddr"):
        va, sz = sec["vaddr"], sec["size"]
        ent = rz.cmdj(f"ph entropy @! {sz} @ {va}")
        min_e = rz.cmdj(f"ph minentropy @! {sz} @ {va}")
        chi = rz.cmdj(f"ph chisquare @! {sz} @ {va}")
        sc = rz.cmdj(f"ph serialcorr @! {sz} @ {va}")
        print(f"{sec['name']:10s} sz={sz:8d} H={ent:.3f} Hmin={min_e:.3f} chi2={chi:8.2f} serialcorr={sc:+.4f}")
```

## 9. Searching: Strings (`/z`), Patterns (`/p`, `/P`) & ROP/COP/JOP Gadgets (`/R`, `/C`, `/J`)

### 1. String Discovery (`iz` / `izz` / `izx`) vs. String Searching (`/z`)

Rizin has two separate string subsystems. Mixing them up causes missed indicators:
1. **`RzBin` String Tables (`iz`, `izz`, `izx`)**:
   - Populated when the binary loads (`iz` = data sections, `izz` = whole file, `izx` = strings with cross-references).
   - Controlled by `e str.encoding` (`ascii`, `utf8`, `utf16le`, `utf16be`, `utf32le`, `guess`), `e search.str.min_length`, `e search.str.max_length`, and `e str.search.mode` (`auto`, `rosections`, `raw`).
   - With `e str.search.reload=true` (enabled by default), updating `e search.str.min_length=...` or `e str.encoding=...` automatically rescans `iz`/`izz` on the next query.
2. **`RzSearch` Pattern & Regex String Search (`/z` / `/zj` / `/zt`)**:
   - Syntax: `/z[jqt] <pattern> [<regex_flags>=l] [<encoding>=settings]`
     - `<regex_flags>`: `l` (literal default), `r` (PCRE2 regex), `e` (extended regex), `i` (case-insensitive), `m` (multiline), `d` (dotall).
     - `<encoding>`: `ascii`, `utf8`, `utf16le`, `utf16be`, `utf32le`, `utf32be`, `mutf8`, `ibm037`, etc.
   - **Critical Gotcha 1 (`/z` does NOT update `izz`, and uses `search.prefix` for flags)**: Strings matched by `/z` are recorded in the `search` flagspace as `<search.prefix>.string.<encoding>.<N>` (default `hit.string.<encoding>.<N>`) and returned directly by `/zj` (`[{"address": ..., "size": ..., "flag": "hit.string.utf8.0", "detail": ...}]`). They **never** appear in `iz` or `izz` output.
   - **Critical Gotcha 2 (Specify `<encoding>` explicitly and scope multi-pass searches with `@e:search.prefix=...`)**: By default `str.encoding` is `"guess"`, which is slow and emits a warning during `/z`. Also `/z` skips matches shorter than `e search.str.min_length` (default `4`), and consecutive searches overwrite `hit.*` flags unless scoped with `@e:search.prefix=<name>`:
     ```bash
     /zj "http" li utf8 @e:search.prefix=str_search                        # Flags named str_search.string.utf8.<N>; search.prefix stays "hit"
     /zj "http" li utf16le @e:search.prefix=wstr_search                    # Separate flag prefix for UTF-16LE hits
     /zj "https?://[a-zA-Z0-9./_:-]+" ri utf8 @e:search.prefix=url_search  # Case-insensitive PCRE2 regex search in UTF-8
     /zj "ELF" l utf8 @e:search.prefix=hdr_search,search.str.min_length=3  # Temporarily lower min_length to 3 for a single search
     fl~str_search.                                                        # List only flags from the `str_search` pass
     ```

### 2. Repeating Pattern Search (`/p`), Block Similarity (`/P`), Bytes (`/x`), Assembly (`/a*`) & Crypto (`/c*`)
- **`/p <patternsize>`** — Search across `search.in` for repeating byte patterns of `<patternsize>` bytes (useful for identifying multi-byte XOR keys, repeating NOP sleds, or fixed-stride table entries).
- **`/P <patternsize>`** — Search for byte blocks of `<patternsize>` similar to the data at the current seek offset.
- **`/x[jqt] <hexpairs>`** — Search for raw bytes with `.` nibble wildcards (e.g., `/xj 488d0d........e8`), or `/x <hex> <mask>` with explicit bitmask.
- **`/a[jqt] <asm>`** / **`/aa[j] <substr>`** / **`/ac[j] <substr>`** / **`/ad[j] <ins1;ins2>`** / **`/ad/a <regex>`** — Assemble `<asm>` and search for matching opcodes (`/aj jmp esp`), or disassemble across `search.in` and match instruction text case-insensitively (`/aaj call qword [rax`), case-sensitively (`/acj`), consecutive instruction pairs (`/adj`), or by regex (`/ad/a`).
- **`/c*` (Cryptographic & Entropy Search)** — Search for crypto material (`/cm[j] [<type>]`), block hashes (`/ch[j] <algo> <digest>`), or blocks in an entropy range (`/ce[j] <min> <max> <blk_sz>`, `/cef[j] <min> <max> <blk_sz>`).
- **`/m[jqt] [<magic_file>]`** — Search for embedded file headers/magic signatures (PE, ELF, ZIP, LZMA, certificates).

### 3. ROP (`/R`), COP (`/C`) & JOP (`/J`) Gadget Search and RzIL Semantic Queries

Rizin provides three dedicated gadget search families across executable maps (`e search.in=bin.sections.x` or `io.maps.x`):
- **`/R`** — **ROP** (Return-Oriented Programming: gadgets ending in `ret` / `retf` / `retn`).
- **`/C`** — **COP** (Call-Oriented Programming: gadgets ending in indirect `call reg` / `call [reg + disp]`).
- **`/J`** — **JOP** (Jump-Oriented Programming: dispatcher/trampoline gadgets ending in indirect `jmp reg` / `jmp [reg + disp]`).

All three families (`/R*`, `/C*`, `/J*`) share the exact same subcommand structure (`j` = JSON, `q` = quiet one-line, `t` = table queryable):

| Subcommand (`/R*`, `/C*`, `/J*`) | Purpose & Syntax | Example |
| :--- | :--- | :--- |
| **`/R[jqt] [<filter-str>]`** | List all gadgets matching optional substring `<filter-str>` (likewise `/C[jqt]`, `/J[jqt]`). | `/Rj pop rdi` / `/Cj mov rdi` / `/Jqt jmp rax` |
| **`/R/[jqt] [<regex>]`** | Search gadgets by regular expression (`e gadget.len` controls max instructions per gadget, default `5`). | `/R/j "pop r(di\|si); ret"` |
| **`/Rk[jqt] <constraints>`** | **RzIL semantic constraint search**: simulates gadgets and finds those satisfying register equations (`reg=const`, `reg=reg`, `reg=reg OP const`, `reg=reg OP reg`, `reg++`, `reg--`, `reg+=val`). | `/Rkj rax=0` or `/Rkj rdi=rsi,rax=rbx+8` |
| **`/Rg[j] [<addr>]`** | Analyze gadget(s) semantically via RzIL (reports `modified_registers`, `stack_change`, `size`, `ret_addr`). | `/Rgj 0x401230` |
| **`/Rs[j] "<cond>"`** | Filter gadgets by stack pointer delta condition (`=`, `<`, `>`, `<=`, `>=`). | `/Rsj "<0x40"` or `/Rsj =0x10` |
| **`/Rl[j] "<cond>"`** | Filter gadgets by total gadget byte length condition. | `/Rlj "<0x10"` |
| **`/R-`** / **`/C-`** / **`/J-`** | Clear the internal ROP/COP/JOP gadget cache. | `/R-` |
| **`pdp[j] [<limit>]`** | Disassemble a ROP chain by treating words at the current seek offset as a sequence of gadget addresses. | `pdp 8 @ 0x7fffffffe000` |

- **Gadget configuration (`el gadget.`):** `e gadget.len=5` (max instructions per gadget), `e gadget.subchains=false` (emit every suffix sub-gadget), `e gadget.conditional=false` (include conditional branches), `e gadget.comments=false`, `e gadget.cache=true` (cache RzIL gadget analysis for `/Rk`, `/Rg`, `/Rs`, `/Rl`).

## 10. In-CLI Comparison Commands (`c*` — Interactive Counterpart to `rz-diff`)

While `rz-diff` compares two files from the shell, the **`c*` command tree** (`c?`) compares bytes, hexpairs, bit patterns, hexdumps, disassembled functions, and external files **inside an active Rizin session** (and sets `$? = 0` on match or `$? = 1` on mismatch for scripting):

| Command (`c?`) | Purpose & Usage |
| :--- | :--- |
| **`c[j] <string>`** | Compare escaped string against bytes at current seek offset `$$` (sets `$?`). |
| **`cx[j] <hexpairs>`** | Compare hexpair pattern against bytes at `$$` (supports `.` nibble wildcards, e.g., `cx 4889..4883`). |
| **`cX[j] <addr>`** | Hexdiff bytes at current seek `$$` (size `$b`) against bytes at `<addr>`. |
| **`ca[j] <addr> <len>`** | Compare `<len>` bytes at `<addr>` against `<len>` bytes at current seek `$$`. |
| **`cb[j] <num> <n>`** | Compare `1..8` bytes at `$$` against integer `<num>` (endian-aware via `cfg.bigendian`). |
| **`c1 <addr>`** | Compare 8 bits (1 byte) at `$$` with `<addr>` at the individual bit level. |
| **`cc <addr>`** / **`ccc <addr>`** | Side-by-side column hexdump diff between `$$` and `<addr>` (`ccc` shows **only** differing lines). |
| **`ccd [<addr>]`** | Side-by-side **disassembly diff** between instructions at `$$` and `<addr>`. |
| **`cf[j] <file>`** | Compare contents of on-disk `<file>` against memory at current seek `$$` (ideal for verifying dumped/unpacked sections against disk). |
| **`cu <addr>`** / **`cu1`..`cu8`** | Unified diff (`---`/`+++`) of raw bytes (`cu`/`cu1`), words (`cu2`), dwords (`cu4`), or qwords (`cu8`) between `$$` and `<addr>` (over block size `$b`). |
| **`cud <addr>`** | Unified diff of **disassembled instructions** between `$$` and `<addr>` (over block size `$b`). |
| **`cw <sz> <cmd>`** / **`cwl` / `cwu` / `cwr` / `cwx`** | Memory comparison watchers: register a watcher (`cw`), list (`cwl`), update snapshots after RzIL step (`cwu`), reset (`cwr`), or remove (`cwx`). |

```bash
# Compare two similar functions or code stubs inside the same binary:
ccd 0x402100 @! 0x80 @ 0x401500          # Side-by-side disassembly diff of 0x80 bytes at 0x401500 vs 0x402100
cud 0x402100 @! 0x80 @ 0x401500          # Unified disassembly diff between 0x401500 and 0x402100
ccc 0x403200 @! 0x100 @ 0x403000         # Show only differing hexdump lines between two 256-byte tables
cfj unpacked_stage.bin @! 0x1000 @ $S    # Compare on-disk file against mapped section at $S as JSON
```

## 11. Server-Side Table Queries (`<cmd>t:...:json`), Macros (`(` / `.(`) & Iterators (`@@`)

On large (20MB+) Go, Rust, or statically linked C++ binaries, running `aflj` or `izzj` dumps megabytes of JSON. Use Rizin's **colon-separated table query syntax** (`<cmd>[:<col>/<op>/<val>...][:<output_mode>]`) to filter, sort, and slice inside Rizin before serializing to JSON:

- **Table-mode commands:** Append `t` to commands whose default mode is not already a table (`aflt`, `afvlt`, `ablt`, `avglt`, `flt`, `omlt`, `/zt`, `/xt`, `/Rt`, `/Ct`, `/Jt`, `phlt`, `tklt`). For `i*` commands (`iz`, `izz`, `izx`, `ii`, `iE`, `is`, `iS`, `iSS`, `il`, `ir`, `ic`), table mode is already the default (`iz:...` and `izt:...` both work). When a command takes arguments (such as `/zt`, `/xt`, or `/Rt`), attach the `:query:json` suffix directly to the command token before the arguments (e.g. `/zt:*/head/10:json "http" li utf8`). To inspect exact column names for any table command, print its header row with `<cmd>t~:0` (e.g. `aflt~:0` or `iz~:0`; note that `<cmd>t:?` is not valid table syntax).
- **Operators:**
  - Numeric comparisons: `eq`, `ne`, `gt`, `ge`, `lt`, `le` (e.g. `size/gt/500`).
  - String matching & length: `str` (contains substring), `strlen`, `minlen`, `maxlen`, `eq`, `ne` (e.g. `name/str/decrypt`, `string/minlen/8`).
  - Sorting & deduplication: `<col>/sort` (ascending) or `<col>/sort/rev` (descending — **not** `dec`), `<col>/sortlen` or `<col>/sortlen/rev`, `<col>/uniq`.
  - Slicing & columns: `*/head/<N>`, `*/tail/<N>`, `*/page/<P>/<N>`, `<col1>/cols/<col2>/<col3>`.
  - Output format: `:json`, `:csv`, `:fancy`, `:simple`, `:quiet` (no headers; combine with `<col>/cols:quiet` for bare column values).

```bash
aflt:size/gt/500:size/sort/rev:*/head/20:json  # Top 20 largest functions > 500 bytes as JSON
aflt:name/str/main:json                        # Functions whose name contains "main" as JSON
izz:len/ge/8:string/str/http:json              # Whole-binary strings >= 8 chars containing "http" as JSON
izx:string/str/http:json                       # Strings with cross-references containing "http" as JSON
ii:name/str/Virtual:json                       # Imports containing "Virtual" as JSON
/zt:*/head/20:json "http" li utf8              # First 20 UTF-8 search hits as JSON
```

### Scripting Macros (`(`, `(-`, `.(...)`, `..(...)`)
Define reusable, parameterized command sequences inside a Rizin session (`(?`, `.?`):
- `(<name> [<arg0> <arg1> ...]; <cmd1>; <cmd2>; ...)` — Define (or update) a macro named `<name>`. Arguments are substituted into `<cmds>` before execution using **`${<arg-name>}`** (not positional `$0`/`$1`).
- `(<name> [<arg0> ...]; <cmds>)(<val0> ...)` — Define `<name>` and immediately call it once with `<val0> ...`.
- `(` — List all defined macros (standard text output only; `(j` does not exist).
- `(-<name>` — Remove a defined macro named `<name>` (no space after `(-`).
- `.(<name> [<val0> <val1> ...])` — Call macro `<name>` once with the given arguments.
- `..(<name> <set1_arg0> <set1_arg1> <set2_arg0> <set2_arg1> ...)` — Call macro `<name>` multiple times in a single command, consuming `N` arguments per invocation (where `N` is the macro's parameter count).

### Batch Iterators (`@@`)
Chain operations inside a single Rizin invocation without Python round-trips (`@@?`):
- `@@F` — iterate over every function (`afva @@F`).
- `@@f:<glob>` — iterate over matching flags (`pdj 6 @@f:sym.go.main.*`).
- `@@c:<cmd>` — iterate over addresses output by `<cmd>` (`axtj @@c:ii:name/str/Virtual:vaddr/cols:quiet`).
- `@@b` / `@@i` — iterate over basic blocks of the current function (`@@b`) or instructions of the current basic block (`@@i`; chain `@@i @@b` for all instructions in a function).

## 12. Headless Micro-Emulation & Lifting with RzIL (`aez*`, `plf`, `aoi`)

Rizin uses **RzIL** (BAP Core Theory / SMT bitvector intermediate language) for instruction semantics and micro-emulation (`aez?`). Use the RzIL Virtual Machine to resolve stack strings, XOR/RC4 loops, lookup tables, or computed pointers statically without executing the binary natively:

### 1. RzIL Lifting & Emulation Commands
- `plf @ <addr>` / `plF @ <addr>` — Print ASCII (`plf`) or Unicode (`plF`) RzIL statements for an entire function (`agI` prints the RzIL graph of the current instruction; `e asm.cmt.il=true` shows RzIL inline in `pd`/`pdf`).
- `aoi [<N>]` / `aoip [<N>]` — Instruction analysis subcommands that print single-line (`aoi`) or pretty-printed (`aoip`) RzIL s-expressions for the next `N` instructions (`aoj <N>` includes `"rzil"` in the instruction analysis JSON).
- `aezi` — Initialize the RzIL Virtual Machine at the current seek offset (`s <start_va>; aezi`).
- `aezs [<N>]` — Step `N` instructions in the RzIL VM.
- `aezse [<N>]` / `aezsej [<N>]` — Step `N` instructions and emit all VM register/memory events (`pc_write`, `var_write`, `mem_write`, `var_read`, `mem_read`). Controlled by `e rzil.step.events.write=true` (default) and `e rzil.step.events.read=true`.
- `aezsu <end_va>` / `aezsue <end_va>` — Step until `PC == <end_va>` (with event logging in `aezsue`). Stepping automatically syncs RzIL VM registers into `RzReg` and updates register flags, so `@ <reg>` (e.g., `pf x4 @ R0`) immediately resolves to the register's post-emulation value.
- `aezv [<reg_or_var> [<val>]]` / `aezvj [<reg_or_var>]` — Inspect or set RzIL VM registers/variables (as JSON with `aezvj`).

### 2. Python RzIL Stack-String / Buffer Decryption Example

```python
import rzpipe

rz = rzpipe.open("sample.bin")
rz.cmd("aa; e io.cache=true")                             # Enable io.cache so RzIL stores can be read via p8/pxj
start_va, end_va, stack_base = 0x401200, 0x401285, 0x100000
rz.cmd(f"s 0x{start_va:x}; aezi")                         # Seek to decryptor start & init RzIL VM
rz.cmd(f"aezv rbp 0x{stack_base:x}; aezv rsp 0x{stack_base:x}")
rz.cmd(f"aezsu 0x{end_va:x}")                             # Step until end_va (or `aezsej N` for write events)
regs = rz.cmdj("aezvj")
rbp = int(regs["rbp"], 16)
decrypted = bytes.fromhex(rz.cmd(f"p8 64 @ 0x{rbp - 0x40:x}").strip())
rz.quit()
```

- **Inspecting RzIL write events directly (`aezsej`):** You can also capture every register and memory write event emitted during RzIL execution as JSON via `events = rz.cmdj("aezsej 32")`, where memory writes have `{"type": "mem_write", "address": "0x...", "old": "0x...", "new": "0x..."}`.

### 3. Probing Lookup / Decryptor Functions with RzIL Macros (`(tbl_val ...)` & `.(...)` / `..(...)`)

Combine Rizin macros (`(` / `.(` / `..(`), RzIL stepping (`aezi`, `aezv`, `aezsu`), and `pf` (`pf x4 @ <ret_reg>`) to probe lookup or helper functions directly from a call site without writing an external script:

1. **Emulate a call site until stop address `s` and dereference the returned pointer (`R0`):**
   ```text
   :> (tbl_val s; aezi; aezsu ${s}; pf x4 @ R0)
   :> pd 3
               0xfe109e08      ┌   call boot_cfg_lookup
               0xfe109e0c      │   R0 = ##0xdb
               0xfe109e10      └   allocframe(SP,#0x0):raw
   :> .(tbl_val 0xfe109e14)
   0xfe104de8 = 0x55000000 [LE]
   ```
2. **Override the input argument register (`aezv R0 ${v}`) before stepping to sweep lookup keys:**
   When the call site does not immediately overwrite the argument register (e.g., `R0` is already set before the `call`), parameterize both the input register value `v` and stop address `s` to test arbitrary lookup keys individually (`.(...)`) or in bulk (`..(...)`):
   ```text
   :> (tbl_val v s; aezi; aezv R0 ${v}; aezsu ${s}; pf x4 @ R0)
   :> pd 2
               0xfe109e08      ┌   call boot_cfg_lookup
               0xfe109e0c      └   allocframe(SP,#0x0):raw
   :> .(tbl_val 0xff 0xfe109e10)
   0xfe104de8 = 0x55000000 [LE]
   :> .(tbl_val 0x99 0xfe109e10)
   0xfe104de8 = 0xcc000000 [LE]
   :> .(tbl_val 0xaa 0xfe109e10)
   0xfe104de8 = 0x01020304 [LE]
   :> ..(tbl_val 0xff 0xfe109e10 0x99 0xfe109e10 0xaa 0xfe109e10)
   ```

## 13. Companion CLI Tools (`rz-bin`, `rz-find`, `rz-diff`, `rz-ax`, `rz-hash`, `rz-asm`, `rz-sign`, `rz-ar`)

For fast pre-triage without opening a full Rizin session:

```bash
# 1. Fast JSON triage of headers, sections, segments, imports, exports, symbols, libraries & strings (rz-bin)
rz-bin -Ij sample.bin    # Binary info (arch, bits, baddr, compiler, security flags)
rz-bin -Sj sample.bin    # Sections (-SSj for segments)
rz-bin -ij sample.bin    # Imports (-Ej for exports, -sj for symbols, -lj for linked libraries)
rz-bin -zj sample.bin    # Strings in data sections (-zzj for raw strings across whole binary)

# 2. Byte-pattern, string, wide-string & regex hunting across files (rz-find, -j for JSON)
rz-find -j -x "8b0485" sample.bin
rz-find -j -s "VirtualAlloc" -w "VirtualAlloc" sample.bin
rz-find -j -e "https?://[a-zA-Z0-9./_-]+" sample.bin

# 3. Binary & function diffing between two binary variants or unpacked stages (rz-diff)
rz-diff -j -d myers sample_v1.bin sample_v2.bin          # Edit-distance similarity (myers, leven, lcs-roll, ssdeep)
rz-diff -j -t functions sample_v1.bin sample_v2.bin      # Diff by type (-t functions|imports|strings|sections|symbols|classes; -B runs 'aaa')
rz-diff -t graphs -0 sym.main sample_v1.bin sample_v2.bin # CFG Graphviz DOT diff of a function (-1 <other_fcn> optional)

# 4. Base conversion, timestamps & encodings (rz-ax)
rz-ax -s "48656c6c6f"                                    # Hex string to raw ASCII (-S for raw stdin to hex)
rz-ax "0x401263 + 0xf8"                                  # Hex arithmetic (-d for base 10, -t <ts> Unix time, -W Win32 FILETIME, -I IPv4)
rz-ax -D "cml6aW4="                                      # Base64 decode (-E to base64 encode)

# 5. Hashing, statistical metrics & block/buffer crypto/encoding (rz-hash)
rz-hash -j -a sha256,md5,entropy,minentropy,chisquare,serialcorr sample.bin # Hashes & stats as JSON (-qq -a sha256 for bare hex digest, -L to list all)
rz-hash -D rc4 -K "s:secretkey" -x "deadbeef"            # Decrypt/encode hex (-x) or string (-s) with -D/-E <algo> and -K <key> (-I <iv>)

# 6. Disassemble, assemble & lift instructions to RzIL (rz-asm)
rz-asm -a x86 -b 64 -d "488d0d00100000"                  # Disassemble hexpairs (-D to include offset + hexpairs)
rz-asm -a x86 -b 64 -I "4831c0"                          # Lift hexpairs to validated RzIL expressions
rz-asm -a x86 -b 64 "xor rax, rax"                       # Assemble instruction to hexpairs

# 7. FLIRT signature generation/conversion & static archive extraction (rz-sign, rz-ar)
rz-sign -o libc.sig libc.so.6                            # Analyze binary/object (-a for 'aaa') and generate FLIRT .sig (takes ELF/PE/Mach-O/.o, NOT .a)
rz-sign -d libc.sig                                      # Dump FLIRT .sig contents (-c output.pat input.sig to convert between .sig and .pat)
rz-ar -l library.a                                       # List object members inside a static .a/.lib archive (-o outdir library.a to extract .o files)
```

## 14. Common Reverse Engineering Recipes

### Recipe 1: Find High-Fan-In Utility / Decryption Functions

String decryptors, API hash resolvers, and config accessors are called from many locations. Use `aflj` and filter `codexrefs` to `type == "CALL"` using `x["from"]`:

```python
for f in rz.cmdj("aflj") or []:
    callers = [x["from"] for x in f.get("codexrefs", []) if x.get("type") == "CALL"]
    if len(callers) >= 5:
        print(f"0x{f['offset']:x}: {f['name']} (size={f['size']}, callers={len(callers)})")
```

### Recipe 2: Extract Immediate Operands & RIP-Relative Pointers (`pdj`)

Rizin's `pdj <N> @ <addr>` automatically resolves RIP-relative addresses into `op["ptr"]` and immediate values into `op["val"]`, eliminating manual displacement math:

```python
for op in rz.cmdj(f"pdj 8 @ 0x{func_addr:x}") or []:
    print(f"0x{op['offset']:x}: {op.get('opcode', ''):30s} | bytes={op.get('bytes')} ptr={op.get('ptr')} val={op.get('val')}")
```

- **x64 RIP-relative `lea rcx, [rip + disp32]`**: `op["bytes"]` starts with `"488d0d"`, and `op["ptr"]` holds the exact target virtual address (`rcx`).
- **x86 indexed `mov eax, dword [rax*4 + 0x10001518]`**: `op["bytes"]` starts with `"8b0485"`, and the 32-bit table VA is at `int.from_bytes(bytes.fromhex(op["bytes"][6:14]), "little")`.

### Recipe 3: Trace Cross-References to Strings or Imports (`izxj` & `axtj`)

Use `izxj` (or table query `izx:string/str/http:json`) to get strings paired with their referencing addresses directly, or use `axtj @ <addr>` (`[{"from": <int>, "to": <int>, "type": "..."}]`) and query `pdj 1 @ <from>` / `afd @ <from>` for instruction and function context:

```python
# Option A: Directly query strings with xrefs via `izx` table query
for h in rz.cmdj("izx:string/str/http:json") or []:
    xref_addr = h["xref-from"]
    vaddr_str = f"0x{h['vaddr']:x}" if isinstance(h.get("vaddr"), int) else str(h.get("vaddr"))
    print(f"String {vaddr_str} ({h['string']!r}) <- {xref_addr} ({rz.cmd(f'afd @ {xref_addr}').strip()})")

# Option B: Trace all xrefs to an import or global address via `axtj`
for x in rz.cmdj(f"axtj @ 0x{target_vaddr:x}") or []:
    from_va = x["from"]
    ins = (rz.cmdj(f"pdj 1 @ 0x{from_va:x}") or [{}])[0]
    print(f"  <- 0x{from_va:x} [{x['type']}] in {rz.cmd(f'afd @ 0x{from_va:x}').strip()}: {ins.get('disasm', '')}")
```

### Recipe 4: Virtual Address (`vaddr`) to File Offset (`paddr`) Translation

When carving encrypted blobs or patching a raw binary buffer in Python while using Rizin virtual addresses:
- Inside Rizin: use `%p <vaddr>` (converts virtual address to physical file offset; `%P <paddr>` converts physical to virtual) or read bytes directly at the virtual address via `p8 <len> @ <vaddr>`.
- From `iSj` (sections): for a section where `sec["vaddr"] <= vaddr < sec["vaddr"] + sec["vsize"]`, `file_offset = vaddr - sec["vaddr"] + sec["paddr"]`.
- For raw shellcode or memory-mapped dumps where `vaddr == paddr`: pass `-b 32` or `-b 64` and `-m <base_addr>` if needed.

### Recipe 5: Handling Obfuscated / Non-Contiguous Functions

- **`pdfj` fails with `"Linear size differs too much from the bbsum"` or misses chunked blocks**: Use `pdrj @ <addr>` (recursive disassembly across basic blocks; returns a flat list `[...]` of instruction dicts) or `pdj <N> @ <addr>` (linear instruction count, independent of function boundaries).
- **Self-modifying / encrypted function bodies**: If a stub decrypts a function body in-place (e.g., per-function XOR stubs), decrypt the bytes in Python (or via RzIL with `e io.cache=true` or `wx <hex> @ <addr>`) and re-run `af @ <func_va>` so Rizin builds the CFG over the decrypted instructions.
- **Forcing code definition at undefined bytes**: Run `Cd- @ <addr>; af @ <addr>` to clear data metadata and analyze the function.

## 15. Golang (`go`) Binary Analysis (`aalg`, `ABIInternal` & Runtime Types)

Rizin includes native Golang support (`librz/core/golang.c`) that runs automatically during `aaa` (when `bin.lang` is `go`) or on demand via **`aalg`**:

### 1. `.gopclntab` Symbol & Package Recovery (`aalg`)
- Parses Go 1.2–1.15 (`0xfffffffb`), Go 1.16–1.17 (`0xfffffffa`), Go 1.18–1.19 (`0xfffffff0`), and Go 1.20+ (`0xfffffff1`) `.gopclntab` / `__gopclntab` tables across ELF, Mach-O, and PE (where `gopclntab` resides inside `.rdata`).
- Recovers stripped function symbols as `sym.go.<pkg>.<func>` (and aliases `sym.go.main.main` as `main`).
- Automatically skips compiler wrapper boilerplate (`.abi0`, `.abiinternal`, `..inittask`, `type:`, `go:`) during function CFG construction so analysis time is spent on real code, and populates Go package names into `ilj`.

```bash
aalg                             # Run Go symbol + string recovery explicitly (if opened with `aa`)
ilj                              # List recovered Go packages (libraries)
aflt:name/str/sym.go.main.:json  # List only application functions in `main.*` (skip 20,000 runtime.* funcs)
```

### 2. Go Calling Conventions (`golang` / `ABIInternal` vs. `golang_abi0` / `ABI0`)
- During `aalg`, Rizin samples up to 512 non-wrapper functions and votes on the prologue to detect the active Go ABI:
  - **`golang` (`ABIInternal`, Go 1.17+)**: Prologue matches `CMPQ SP|R12, 16(R14)` (`49 3b 66 10` / `4d 3b 66 10` on x86_64). Register allocation:
    - **x86_64**: `arg0..arg8` = `rax, rbx, rcx, rdi, rsi, r8, r9, r10, r11`, `ret` = `rax`, goroutine context `self` (`g`) = `r14`.
    - **arm64**: `arg0..arg7` = `x0..x7`, `ret` = `x0`, goroutine context `self` (`g`) = `x28`.
  - **`golang_abi0` (`ABI0`, Go < 1.17)**: Prologue loads `g` from TLS (`MOVQ FS|GS:[disp32], reg`); all arguments and return values are passed on the stack.
- Check or override a function's calling convention with `afc @ sym.go.main.main` or `afc golang @ sym.go.main.main` (`afc golang_abi0` for stack ABI0).

### 3. Preloaded Go Runtime Types (`types-golang-32.sdb` / `types-golang-64.sdb`)
`aalg` automatically loads Go's core runtime data structures into `RzTypeDB`. Use `tp`, `pfj '?(<type>) <name>'`, or `afvt` to inspect Go values instead of manual pointer arithmetic:
- **`string` / `stringStruct` / `runtime.stringStruct`**: `{ char *str; size_t len; }`
- **`slice` / `runtime.slice`**: `{ void *array; size_t len; size_t cap; }`
- **`eface` / `runtime.eface`** (empty `interface{}` / `any`): `{ void *_type; void *data; }`
- **`iface` / `runtime.iface`** (non-empty interface): `{ void *tab; void *data; }`
- **`hmap` / `runtime.hmap`** (Go `map` header): `{ int64_t count; uint8_t flags; uint8_t B; uint16_t noverflow; uint32_t hash0; void *buckets; void *oldbuckets; uintptr_t nevacuate; void *extra; }`

```bash
tp slice @ 0x560010; tp hmap @ 0x560030                                  # Print Go runtime structs at <addr>
pfj '?(slice) s' @ 0x560010; pfj '?(hmap) m' @ 0x560030                  # Dump Go runtime structs as JSON
afvt s_arg stringStruct @ sym.go.main.decrypt                            # Type a Go function variable
```

### 4. Non-Null-Terminated Go String Recovery
Go concatenates string literals into a single read-only blob without null terminators, so standard `strings` dumps mega-strings until the next accidental `\x00`. `aalg` recovers exact string boundaries and cross-references via two passes:
1. **Data Pointer Table Pass**: Scans data sections for `(string_addr, string_size)` pairs and registers `STRING` xrefs from the struct header to the slice of characters.
2. **Instruction Pattern Pass**: Scans basic blocks across `x86` (32/64), `arm` (32/64), `mips` (32/64), `ppc64`, and `riscv64` for `lea` + immediate-length or pointer-table loads, splits the string blob into individual `str.*` entries in `izj`, and adds `RZ_ANALYSIS_XREF_TYPE_STRING` xrefs (`axtj @ <str_vaddr>`) directly to the referencing instruction.

## 16. Troubleshooting & Self-Help Introspection

- **Command fails or returns empty output**:
  1. Read `stderr` (`rz.cmd(cmd, ret_stderr=True)` in `rzpipe`) — Rizin automatically prints `ERROR:` diagnostics and the parent command's help table to `stderr`.
  2. Query built-in help directly (never run interactive `?**` / `?***` / `?**e` in headless mode):
     - `<cmd>?` for short summary/subcommands (e.g., `afv?`, `/z?`, `aflt?`) and **`<cmd>??`** for full extended help (`description`, `details`, `Encodings`, `Regex Flags`, `Examples`, e.g., `/z??`, `La??`). To inspect table column names, run `<cmd>t~:0` (e.g., `aflt~:0` or `iz~:0`).
     - `?*~+<keyword>` or `?* <prefix>~+<keyword>` to search command names, args, and 1-line summaries case-insensitively.
     - `el~+<keyword>` (or `elj`) to search configuration variables and their descriptions.
     - `?+ | jq ...` (or `rz.cmdj("?+")` in Python) to search the **entire** command catalog tree (`summary`, `description`, `args`, `choices`, and `details`/`Examples` across all group and leaf nodes).
  3. Ensure `aa` / `aaa` (or `-p <hash>.rzdb`) has run; `pdfj` and `pdgj` require a function to be defined at `<addr>` (run `af @ <addr>` first, or use `pdj <N> @ <addr>` for raw instruction disassembly).
- **Decompiler (`pdg` / `pdgj`) unavailable**:
  `pdg` requires the `rz-ghidra` core plugin (`libcore_ghidra.so`). Check loaded core plugins with `Lcq~^ghidra$`, `Lct:name/eq/ghidra:json`, `Lcj`, or `pdg?`. When `rz-ghidra` is present, always prefer `pdg` / `pdgj` for decompilation; if unavailable, fall back to raw disassembly (`pdfj` / `pdrj` / `pdj` / `pi`) or RzIL (`plf` / `aez*`).
