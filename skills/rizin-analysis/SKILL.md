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

## 2. Output Bounding, JSON Parsing & Session Ergonomics

1. **Use JSON Output (`*j`) for Programmatic Parsing:**
   - Append `j` to commands (`iIj`, `iSj`, `iij`, `izj`, `izxj`, `aflj`, `pdfj`, `pdrj`, `pdj`, `pdgj`, `axtj`, `axfj`, `afvlj`, `flj`) and parse via `rz.cmdj("<cmd>")` or `jq`.
2. **Filter Large Tables Inside Rizin (`<cmd>t:...:json`) to Avoid Context Blowups:**
   - On large C++, Go, or Rust binaries, raw `aflj` or `izzj` can emit megabytes of JSON. Use Rizin's table query syntax (`<cmd>[:<col>/<op>/<val>...][:<fmt>]`) to filter, sort, and slice before serializing:
   - Append `t` to commands whose default output is not a table (`aflt`, `afvlt`, `flt`, `omlt`, `/zt`, `/xt`, `/Rt`, `/Ct`, `/Jt`, `phlt`). For `i*` commands (`iz`, `izz`, `izx`, `ii`, `iE`, `iS`), table mode is already the default (`iz:...` and `izt:...` both work).
   - Inspect exact column names for any table command with `<cmd>t~:0` (e.g., `aflt~:0` or `iz~:0`; `<cmd>t:?` is invalid).
   - Operators: `eq`, `ne`, `gt`, `ge`, `lt`, `le`, `str` (substring), `minlen`, `maxlen`, `<col>/sort` (ascending), `<col>/sort/rev` (descending — **not** `dec`), `<col>/uniq`, `*/head/<N>`, `*/tail/<N>`, `<col1>/cols/<col2>`, and output modifiers `:json`, `:csv`, `:quiet`.
   - When a table command takes arguments (`/zt`, `/xt`, `/Rt`), attach `:query:json` to the command token before the arguments:
     ```bash
     aflt:size/gt/500:size/sort/rev:*/head/20:json  # Top 20 largest functions > 500 bytes as JSON
     izx:string/str/http:json                       # Strings with xrefs containing "http" as JSON
     /zt:*/head/20:json "http" li utf8              # First 20 UTF-8 search hits as JSON
     ```
3. **Use Temporary Modifiers (`@`, `~`, `|`) Instead of Mutating Global State:**
   - `@ <addr_or_expr>` (temporary seek), `@! <size>` (temporary block size `$b`), `@e:<k>=<v>[,<k2>=<v2>]` (temporary config override for one command), `@s:<str>` / `@x:<hex>` / `@f:<file>` (temporary buffer), `@a:<arch>:<bits>`.
   - `~` (internal grep/slicer): `cmd~+<word>` (case-insensitive), `cmd~!<word>` (invert), `cmd~[col]`, `cmd~:0..10` (line range), `cmd~?` (line count), `cmd~{}` (pretty JSON). Trailing `|` strips ANSI colors.
4. **Choose Stateless CLI vs. Persistent Sessions Appropriately:**
   - **Stateless one-off queries:** Use companion tools (`rz-bin -Ij/-Sj/-ij/-zj`, `rz-find -j`, `rz-hash -j`, `rz-ax`, `rz-asm`, `rz-diff -j`) or `rizin -qc "<cmd>" <binary>`.
   - **Stateful multi-step analysis:** When running auto-analysis (`aa` for fast symbols/entrypoints, `aaa` for full standard analysis; **never** `aaaa`), applying renames/types/comments, or stepping the RzIL VM across multiple turns, use a persistent `rzpipe` / MCP session or explicitly save/load a project with `Ps <file.rzdb>` and `-p <file.rzdb>` (`Po <file.rzdb>`). `-q` quits immediately without auto-saving `.rzdb`.

## 3. Radare2 Pretraining Traps & Rizin Syntax Differences

Do **not** use legacy `radare2` syntax from model pretraining where Rizin has replaced or standardized the grammar:

| Area | Legacy `r2` Trap (Invalid/Deprecated) | Rizin Syntax | Key Rules & Gotchas |
| :--- | :--- | :--- | :--- |
| **Math & Expressions** | `?v <expr>`, `? <expr>`, `[4:0x403000]` | `% <expr>`, `%j <expr>`, `%v <expr>`, `%vx <expr>`, `0x403000:le32` | All math/evaluation lives under `%` (`%??`). Also `%p <vaddr>` (to paddr), `%P <paddr>` (to vaddr), `%$` (state vars), `%b64[-]`. |
| **Memory Deref in `%`** | `[4:addr]`, `($$+8):be64`, `addr:u32` | `<literal_addr>:[le\|be]?[s]?(8\|16\|32\|64\|128)` or `f(16\|32\|64\|128)` | `:<spec>` attaches **only** to numeric address literals (e.g., `% 0x403000:le32 + 0x10`, `% 0x403000:s16`). Do **not** write `:u32`. |
| **Binary Formats (`pf`)** | Single-letter `b`, `w`, `d`, `q`, `x`, `X`, `i`, `f`, `F`, `Z`, `t`; `<` / `>` endian prefix | `u1/u2/u4/u8`, `d1/d2/d4/d8`, `x1/x2/x4/x8`, `f2/f4/f8`, `z(utf16le)`, `t(unix32)`, `G(le)` | Lowercase = LE, uppercase = BE (`U4`, `X4`, `F4`, `T(unix32)`, `G(be)`), `n1..n8` = context-endian. `[N]<T>` fixed array, `[@field]<T>` dynamic array, `*<spec>` pointer deref, `?(type) name` struct. |
| **Named `pf` Formats** | `pf.name <fmt>`, `.pf*`, `pfw.name` | `pfn <name> "<fmt>"`, `pf.[j] <name>`, `pf- <name>`, `pfw <name>.<f> <v>`, `tdf` | `pfn` defines/lists named formats; `pf.` prints them; `tdf` promotes a `pf` format into `RzTypeDB`. |
| **Explicit `l` to List** | `f`, `afv`, `om`, `ph`, `ax`, `ah` | `fl[jt]`, `afvl[jt]`, `oml[jt]`, `phl[jt]`, `axl[j]`, `ahl[j]` | Listing items requires the explicit `l` subcommand. |
| **Rename Variable** | `afvn <old_name> <new_name>` | `afvn <new_name> <old_name> [@ <addr>]` | `<new_name>` is **first**, `<old_name>` is **second** (whereas type rename is `tr <old> <new>`). |
| **String Search (`/z`)** | Expecting `/z` hits in `iz`/`izz`, or omitting encoding | `/z[jqt] "<pat>" [<flags>=l] [<enc>] [@e:search.prefix=<pfx>]` | `/z` writes `<search.prefix>.string.<enc>.<N>` flags and returns hits in `/zj`; it **never** populates `iz`/`izz`. Pass `<enc>` explicitly (`utf8`, `utf16le`) to avoid slow `str.encoding=guess` warnings (`flags`: `l` literal, `r` regex, `i` case-insensitive). |
| **Scripting Macros** | `(name arg; cmd $0)` | `(<name> <arg>; <cmd> ${<arg>})`, `.(<name> <val>)`, `..(<name> ...)` | Macro arguments use named `${arg}` substitution (not positional `$0`). `(-<name>` deletes a macro. |
| **Type Cast to JSON** | Expecting `tpj` to exist | `tp <type> @ <addr>` (text) or `pfj '?(<type>) <name>' @ <addr>` (JSON) | Use `td "<C_decl>"` to define types, `tsj <type>` to inspect struct fields, `tx <type>` for type xrefs, and `tn <func>` for `noreturn`. |

### Additional High-Frequency Gotchas

- **`%` expressions containing `;` or `>` must be quoted:** Quote multi-statement or comparison expressions so the CLI parser does not split on `;` or redirect `>` to a file (e.g., `% "k = 0x403000:le32; k ^ 0xdeadbeef"`, `% "entropy($$, $FS) > 7.2"`). Built-in `%` IO functions (`entropy(addr, n)`, `temperature(addr, n)`, `sha256(addr, n)`, `crc32(addr, n)`) cap `n` at `64 KiB`; for larger buffers use `ph <algo> @! <size> @ <addr>` (`entropy`, `minentropy`, `chisquare`, `serialcorr`).
- **Decompilation (`pdg` / `pdgj`) and non-contiguous functions:** Check if `rz-ghidra` is loaded with `Lcq~^ghidra$` and prefer `pdg` / `pdgj` (`RzAnnotatedCode` JSON with `code` and `annotations[]`). Both `pdgj` and `pdfj` require a defined function at `<addr>` (run `af @ <addr>` first). If `pdfj` fails with `"Linear size differs too much from the bbsum"` on chunked/obfuscated functions, use `pdrj @ <addr>` (recursive BB disassembly) or `pdj <N> @ <addr>`.
- **Golang binaries (`aalg`):** `aaa` runs `aalg` automatically on Go binaries to recover `.gopclntab` symbols (`sym.go.<pkg>.<func>`), split non-null-terminated string blobs with xrefs, detect `golang` (`ABIInternal`) vs. `golang_abi0` calling conventions, and preload `string`, `slice`, `eface`, `iface`, and `hmap` types into `RzTypeDB`. Filter out runtime functions via `aflt:name/str/sym.go.main.:json`.
- **Static RzIL micro-emulation (`aez*`):** When stepping instructions in the RzIL VM (`s <start_va>; aezi; aezv <reg> <val>; aezsu <end_va>` or `aezsej <N>`), enable `e io.cache=true` first so emulated memory writes are visible to subsequent `p8`, `pxj`, or `pf` reads.
