---
name: rizin-analysis
description: >-
  Static binary analysis, reverse engineering, and decompilation using Rizin
  (rizin CLI, rzpipe, rz-ghidra, and rz-* companion tools) in headless mode.
license: LGPL-3.0-only
---

# Rizin Headless Binary Analysis

Focus on Rizin-specific agent ergonomics, output bounding, and syntax differences where models trained on legacy `radare2` corpora commonly produce invalid commands. For general command reference, query Rizin's built-in help directly.

## 1. Self-Serve Help & Live Command Discovery

1. **Query Built-In Help Before Guessing Syntax:**
   - `<cmd>?` — Short command summary and subcommand table (e.g., `afv?`, `/z?`, `t?`).
   - `<cmd>??` — Full extended help including `description`, `details`, argument `choices`, `Encodings`, `Regex Flags`, and `Examples` (e.g., `%??`, `pf??`, `/z??`, `e??`).
   - `?*~+<keyword>` or `?* <prefix>~+<keyword>` — Case-insensitively search command names, argument signatures, and 1-line summaries across the command tree (e.g., `?*~+noreturn`, `?* a~+xref`).
   - `el~+<keyword>` (or `elj`) — Search `e` configuration variable names and descriptions (e.g., `el~+search`, `el~+ghidra`).
   - `?+` (or `?+j`) — Dump the complete live runtime command tree (including dynamically loaded plugins such as `rz-ghidra`) as a single JSON object. Pipe to `jq` or inspect via `rz.cmdj("?+")` in Python rather than grepping the single-line JSON output with `~`.
2. **Never Run Interactive HUD Help in Headless Mode:**
   - Do **not** run `?**`, `?***`, or `?**e`. They invoke the interactive TTY HUD (`rz_cons_hud()`) and hang or fail when `scr.interactive=false`.
3. **Preserve `stderr` (Do Not Blindly Pass `-2`):**
   - Rizin writes command syntax errors (`ERROR: Command '...' does not exist`) and automatic fallback help tables to `stderr`.
   - In `rzpipe` (`rz-pipe` >= 0.5), open without `-2` (`rz = rzpipe.open(path)`): `rz.cmdj("<cmd>")` reads `stdout` cleanly, while `rz.cmd("<cmd>", ret_stderr=True)` captures `stderr` diagnostics when a command fails or returns empty output.
   - Analysis and loader passes (such as `aaa` ESIL analysis or DWARF type import) can emit non-fatal `ERROR:` diagnostics to `stderr` (e.g., `Cannot peek memory without specifying an address`) even when the command succeeds; distinguish these from command-parser failures (`Command '...' does not exist`, `Wrong number of arguments`) when checking `stderr` programmatically.

## 2. Output Bounding, JSON Parsing & Session Ergonomics

1. **Use JSON Output (`*j`) for Programmatic Parsing:**
   - Append `j` to commands (`iIj`, `iSj`, `iij`, `izj`, `izxj`, `aflj`, `afij`, `pdfj`, `pdrj`, `pdj`, `pdgj`, `axtj`, `axfj`, `afxj`, `afvlj`, `flj`, `aclj`) and parse via `rz.cmdj("<cmd>")` or `jq` (`agf j` / `agf J` take format as an argument).
2. **Filter Large Tables Inside Rizin (`<cmd>t:...:json`) to Avoid Context Blowups:**
   - On large C++, Go, or Rust binaries, raw `aflj` or `izzj` can emit megabytes of JSON. Use Rizin's table query syntax (`<cmd>[:<col>/<op>/<val>...][:<fmt>]`) to filter, sort, and slice before serializing:
   - Append `t` to commands whose default output is not a table (`aflt`, `afvlt`, `flt`, `omlt`, `/zt`, `/xt`, `/Rt`, `/Ct`, `/Jt`, `phlt`). For `i*` commands (`iz`, `izz`, `izx`, `ii`, `iE`, `iS`), table mode is already the default (`iz:...` and `izt:...` both work).
   - Use `<cmd>t:?` (prints to `stderr`) for table query operator help (e.g., `aflt:?`, `iz:?`) and `<cmd>t:simple~:0` to inspect exact column names (`:simple` avoids `:fancy` box borders on tables like `omlt`). Table column names can differ from `*j` JSON field names (e.g., `iit` uses `lib` rather than `iij`'s `libname`).
   - Operators: `eq`, `ne`, `gt`, `ge`, `lt`, `le`, `str` (substring), `minlen`, `maxlen`, `<col>/sort` (ascending), `<col>/sort/rev` (descending — **not** `dec`), `<col>/uniq`, `*/head/<N>`, `*/tail/<N>`, `<col1>/cols/<col2>`, and output modifiers `:json`, `:csv`, `:quiet`.
   - When a table command takes arguments (`/zt`, `/xt`, `/Rt`), attach `:query:json` to the command token before the arguments:
     ```bash
     aflt:size/gt/500:size/sort/rev:*/head/20:json  # Top 20 largest functions > 500 bytes as JSON
     izx:string/str/http:json                       # Strings with xrefs containing "http" as JSON
     /zt:*/head/20:json "http" li utf8              # First 20 UTF-8 search hits as JSON
     ```
   - **Never line-grep (`~`) single-line JSON commands (`aflj~...`, `izj~...`):** JSON commands emit the entire array on one line, so `~` matches and returns the full multi-megabyte blob. Use table queries (`aflt:...:json`, `izt:...:json`) or text grep (`afl~...`).
3. **Use Temporary Modifiers (`@`, `~`, `|`) Instead of Mutating Global State:**
   - `@ <addr_or_expr>` (temporary seek), `@! <size>` (temporary block size `$b`), `@e:<k>=<v>[,<k2>=<v2>]` (temporary config override for one command), `@s:<str>` / `@x:<hex>` / `@f:<file>` (temporary buffer), `@a:<arch>:<bits>`.
   - `~` (internal grep/slicer): `cmd~+<word>` (case-insensitive), `cmd~!<word>` (invert), `cmd~[col]`, `cmd~:0..10` (line range), `cmd~?` (line count), `cmd~{}` (pretty JSON; escape `\|` in jq-like filters like `aflj~{.[] \| {name,offset}}`). Trailing `|` strips ANSI colors.
4. **Choose Stateless CLI vs. Persistent Sessions Appropriately:**
   - **Stateless one-off queries:** Use companion tools (`rz-bin -Ij/-Sj/-ij/-zj`, `rz-find -j`, `rz-hash -j`, `rz-ax`, `rz-asm`, `rz-diff -j`) or `RZ_COLOR=0 rizin -N -qc "<cmd>" <binary>` (`-N` skips user `~/.rizinrc` for deterministic output; Rizin uses `RZ_COLOR=0` rather than `NO_COLOR=1`, or `-e scr.color=0`, to disable ANSI escape codes in non-TTY pipes).
   - **Stateful multi-step analysis:** When running auto-analysis (`aa` for fast symbols/entrypoints, `aaa` for full standard analysis; **never** `aaaa`), applying renames/types/comments, or stepping the RzIL VM across multiple turns, use a persistent `rzpipe` / MCP session or explicitly save/load a project with `e prj.compress=true; Ps <file.rzdb>` and `-N -p <file.rzdb>` (`Po <file.rzdb>`). `-q` quits immediately without auto-saving `.rzdb`. Note that `Po`/`-p` preserves session/logging/screen/compression settings (`scr.*`, `log.*`, `prj.compress`, `cfg.exit.errorcode`, `cfg.json.status`) while restoring saved `asm.*` and `hex.*` variables from `.rzdb`, so re-apply any custom compact disassembly/hexdump presets (`asm.lines=false`, `asm.emu=false`, `hex.compact=true`) after loading an external project.

## 3. Radare2 Pretraining Traps & Rizin Syntax Differences

Do **not** use legacy `radare2` syntax from model pretraining where Rizin has replaced or standardized the grammar:

| Area | Legacy `r2` Trap (Invalid/Deprecated) | Rizin Syntax | Key Rules & Gotchas |
| :--- | :--- | :--- | :--- |
| **Decompilation** | `pdd`, `pddj`, `pdda` (`r2dec`) | `pdg`, `pdgj`, `pdga` (`rz-ghidra`) | `pdd` requires the optional `rz-jsdec` plugin (not built-in by default); check loaded decompiler plugins with `Lcq` (`rz-ghidra` exposes `pdg` / `pdgj`). |
| **Function CFG JSON** | `agfj @ <addr>`, `agfJ @ <addr>` | `agf j @ <addr>`, `agf J @ <addr>` | `agf` takes format as an argument (`ascii`, `cmd`/`*`, `dot`/`d`, `gml`/`g`, `json`/`j`, `json_disasm`/`J`); `agfj` does not exist. |
| **Project Script Export** | `Ps*`, `P*`, `f*`, `CC*`, `afn*` | `Ps <file.rzdb>` or `*j` JSON (`flj`, `CClj`, `aflj`) | `*` script-dump commands (`Ps*`, `f*`, `CC*`, `afn*`) do not exist in Rizin; use `Ps` for `.rzdb` persistence or `*j` for JSON export. |
| **Positional `<addr>` (`@`)** | `afn <name> <addr>`, `axt <addr>`, `pdf <addr>`, `pdg <addr>`, `af <addr>` | `afn <name> @ <addr>`, `axt @ <addr>`, `pdf @ <addr>`, `pdg @ <addr>`, `af @ <addr>` | Rizin's `rz_cmd` grammar rejects trailing positional `<addr>` arguments (and `af <addr>` is worse: `af [<name>]` silently renames the function at `$$` to `<addr>`); always use `@ <addr>`. |
| **Comments** | `CCa <addr> <text>` / `CCj` | `CC <text> @ <addr>` or `CCu <text> @ <addr>` / `CClj` | `CCa` was removed/standardized; Rizin requires `@ <addr>` temporary seek modifier and `CClj` for JSON list. For comments with parser metacharacters (`~`, `()`, `&`, `@@`, `^`, `*`), pass `CCu base64:<b64> @ <addr>`. |
| **Type Binding & Cast** | `t <type> @ <addr>`, `tl <type> @ <addr>` | `td "<C_decl>"` (or `to file.h`) then `avga <var> <type> @ <addr>` / `tp <type> @ <addr>` / `Ct <text> @ <addr>` | `tl [<type>]` is verbose type listing (`t` long mode), **not** type linking; bare `t` lists types. Use `avga` for typed globals, `tp` to cast at seek, or `Ct` for type comments. |
| **Function Xrefs** | `axf @ <func>` (when expecting whole-function xrefs), `axff[j]`, `axj` | `afx[j] @ <func>` (whole function), `axf[j] @ <addr>` (single instruction/data address), `axtj @ <addr>` (xrefs TO), `axlj` | `axf` / `axfj` only inspects the single instruction at seek and `axff[j]` does not exist; use `afx` / `afxj` for all references from a function. |
| **Static Micro-Emulation** | `aei; aeim; aes; aesu <addr>` (ESIL), `aezr` | `aezi; aezs; aezsu <addr>; aezse[j]; aezv` (RzIL) | Rizin replaced ESIL with RzIL (`aez*`). Legacy `aei`/`aes` fails or uses incomplete ESIL stubs, and `aezr` does not exist. Set `e rzil.step.max=<N>` before `aezsu`/`aezsue` to bound loops. |
| **Config & Startup RC** | `e bin.relocs.apply=true`, `RZ_CONFIG_FILE=/path/to/rc`, `NO_COLOR=1` | `e bin.relocs=true`, `RZ_RCFILE=/path/to/rc`, `RZ_COLOR=0`, `-N` | `bin.relocs.apply`, `RZ_CONFIG_FILE`, and `NO_COLOR` are not used by Rizin; use `RZ_COLOR=0` (or `-e scr.color=0`) to disable ANSI escapes across `rizin`, `rz-bin`, `rz-diff`, and `rz-find`, and `-N` to skip user `~/.rizinrc`. |
| **Companion Binaries** | `rabin2`, `rafind2`, `radiff2`, `rahash2`, `rasm2`, `rax2` | `rz-bin`, `rz-find`, `rz-diff`, `rz-hash`, `rz-asm`, `rz-ax`, `rz-sign`, `rz-ar` | `ra*2` binaries do not exist in Rizin installations. |
| **Zero-Terminated String Print** | `psz @ <addr>`, `pszj @ <addr>`, `ps @ <addr>:utf16le` | `ps @ <addr>`, `psj @ <addr>` (`psu` UTF-8, `psw`/`pswj` UTF-16LE, `psW` UTF-32LE) | `psz` was removed and `:<enc>` on `@ <addr>` is invalid (silently truncates UTF-16LE as ASCII); use `psw` / `pswj` for wide strings. |
| **Math & Expressions** | `?v <expr>`, `? <expr>`, `[4:0x403000]` | `% <expr>`, `%j <expr>`, `%v <expr>`, `%vx <expr>`, `0x403000:le32` | All math/evaluation lives under `%` (`%??`). Also `%p <vaddr>` (to paddr), `%P <paddr>` (to vaddr), `%$` (state vars), `%b64[-]`. |
| **Memory Deref in `%`** | `[4:addr]`, `($$+8):be64`, `addr:u32` | `<literal_addr>:[le\|be]?(s?(8\|16\|32\|64\|128)\|f(16\|32\|64\|128))` | `f` supports `16\|32\|64\|128` (e.g., `% 0x403000:le32`, `% 0x403000:lef32`, `% 0x403000:s16`); `:<spec>` attaches **only** to numeric literals (never `:u32`). |
| **Binary Formats (`pf`)** | Single-letter `b`, `w`, `d`, `q`, `x`, `X`, `i`, `f`, `F`, `Z`, `t`; `<` / `>` endian prefix | `u1/u2/u4/u8`, `d1/d2/d4/d8`, `x1/x2/x4/x8`, `f2/f4/f8`, `z(utf16le)`, `t(unix32)`, `G(le)` | Lowercase = LE, uppercase = BE (`U4`, `X4`, `F4`, `T(unix32)`, `G(be)`), `n1..n8` = context-endian. `[N]<T>` fixed array, `[@field]<T>` dynamic array, `*<spec>` pointer deref, `?(type) name` struct. |
| **Named `pf` Formats** | `pf.name <fmt>`, `.pf*`, `pfw.name` | `pfn <name> "<fmt>"`, `pf.[j] <name>`, `pf- <name>`, `pfw <name>.<f> <v>`, `tdf` | `pfn` defines/lists named formats; `pf.` prints them; `tdf` promotes a `pf` format into `RzTypeDB`. |
| **Explicit `l` to List** | `f`, `afv`, `om`, `ph`, `ax`, `ah`, `ac`, `acj` | `fl[jt]`, `afvl[jt]`, `oml[jt]`, `phl[jt]`, `axl[j]`, `ahl[j]`, `acl[jl]`, `aci[jl] <cls>` | Listing items requires the explicit `l` subcommand (`f` errors if a flag such as `str.*` already exists at the address — use `f+ <name> <size> @ <addr>` to append without collision; `ac <name>` adds a class rather than listing). |
| **Function Info Keys** | Grepping `afi` text for `nbbs:` | `afij @ <addr>` (or `num-bbs:` in `afi` text) | Rizin `afi` text prints `num-bbs:` (not `r2`'s `nbbs:`); prefer parsing `afij` JSON (`size`, `nbbs`, `edges`, `cc`). |
| **Rename Variable** | `afvn <old_name> <new_name>` | `afvn <new_name> <old_name> [@ <addr>]` | `<new_name>` is **first**, `<old_name>` is **second** (whereas type rename is `tr <old> <new>`). |
| **String Search (`/z`)** | Expecting `/z` hits in `iz`/`izz`, or omitting encoding | `/z[jqt] "<pat>" [<flags>=l] [<enc>] [@e:search.prefix=<pfx>]` | `/z` writes `<search.prefix>.string.<enc>.<N>` flags and returns hits in `/zj`; it **never** populates `iz`/`izz`. Pass `<enc>` explicitly (`utf8`, `utf16le`) to avoid slow `str.encoding=guess` warnings (`flags`: `l` literal, `r` regex, `i` case-insensitive). |
| **Scripting Macros** | `(name arg; cmd $0)` | `(<name> <arg>; <cmd> ${<arg>})`, `.(<name> <val>)`, `..(<name> ...)` | Macro arguments use named `${arg}` substitution (not positional `$0`). `(-<name>` deletes a macro. |
| **Type Cast to JSON** | Expecting `tpj` to exist | `tp <type> @ <addr>` (text) or `pfj '?(<type>) <name>' @ <addr>` (JSON) | Use `td "<C_decl>"` to define types, `tsj <type>` to inspect struct fields, `tx <type>` for type xrefs, and `tn <func>` for `noreturn`. |

### Additional High-Frequency Gotchas

- **Case-sensitive `rz_cmd` command names:** Rizin's `rz_cmd` parser is strictly case-sensitive; use lowercase `afl` / `aflj` (never uppercase `AFL`).
- **`%` expressions containing `;` or `>` must be quoted:** Quote multi-statement or comparison expressions so the CLI parser does not split on `;` or redirect `>` to a file (e.g., `% "k = 0x403000:le32; k ^ 0xdeadbeef"`, `% "entropy($$, $FS) > 7.2"`). Built-in `%` IO functions (`entropy(addr, n)`, `temperature(addr, n)`, `sha256(addr, n)`, `crc32(addr, n)`) cap `n` at `64 KiB`; for larger buffers use `ph <algo> @! <size> @ <addr>` (`entropy`, `minentropy`, `chisquare`, `serialcorr`).
- **Decompilation (`pdg` / `pdgj`) and non-contiguous functions:** Both `pdgj` and `pdfj` require a defined function at `<addr>` (run `af @ <addr>` first). Never `;`-chain multiple `pdg` calls into a single command (causes cumulative timeouts); check `afij @ <addr>` (`size`, `nbbs`, `edges`) before running `pdg` on large or control-flow-flattened functions and bound each `pdg` call with a timeout so stalled decompilations fall back cleanly. If `pdfj` fails with `"Linear size differs too much from the bbsum"` on chunked/obfuscated functions (or `pdg` times out), use `pdrj @ <addr>` (recursive BB disassembly) or `pdj <N> @ <addr>`. For raw shellcode invoked via CLI, pass `-a x86 -b 32` (never `-e asm.arch=x86`).
- **Golang binaries (`aalg`):** `aaa` runs `aalg` automatically on Go binaries to recover `.gopclntab` symbols (`sym.go.<pkg>.<func>` on stripped binaries; unstripped binaries retain `sym.main.*`), split non-null-terminated string blobs with xrefs, detect `golang` (`ABIInternal`) vs. `golang_abi0` calling conventions, and preload `string`, `slice`, `eface`, `iface`, and `hmap` types into `RzTypeDB`. Filter user functions via `aflt:name/str/main.:json` (or `fl~+main.main`) and pass the exact recovered flag name to `@` seeks and xrefs (e.g., `axt @ sym.go.main.main` on stripped binaries — `@ sym.main.main` fails with an invalid-address error when only `sym.go.*` flags exist).
- **Static RzIL micro-emulation (`aez*`):** When stepping instructions in the RzIL VM (`s <start_va>; aezi; aezv <reg> <val>; aezsu <end_va>` or `aezsej <N>`), enable `e io.cache=true` first so emulated memory writes are visible to subsequent `p8`, `pxj`, or `pf` reads, and set `e rzil.step.max=<N>` (e.g., `100000`) before `aezsu`/`aezsue` so unreachable stop addresses or spin loops halt with an error instead of hanging. Use macros to probe table/lookup functions iteratively (register name depends on target arch, e.g., `rax` on x86_64, `r0` on ARM, or `R0` on Hexagon; read analysis/RzIL registers in `@` with `$r{<reg>}`): `(tbl_val v s; s <start_va>; aezi; aezv R0 ${v}; aezsu ${s}; pf x4 @ $r{R0}); .(tbl_val 0xff 0xfe109e10); (-tbl_val`.
