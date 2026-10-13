---
name: rizin-analysis
description: Analyze binaries using Rizin (rizin CLI, rzpipe Python API, rz-ghidra decompiler, and rz-bin/rz-find/rz-diff/rz-sign/rz-ax/rz-hash/rz-asm tools) in headless mode with persistent .rzdb project caching. Use when disassembling, decompiling with rz-ghidra (pdg/pdgj), mapping cross-references, recovering C structs/types/vtables/Go symbols, running RzIL micro-emulation (aez*), or writing automated binary analysis and configuration extraction scripts with Rizin.
license: LGPL-3.0-only
---

# Rizin Headless Binary Analysis (`rizin`, `rzpipe` & `rz-ghidra`)

Use this skill to perform static binary analysis, reverse engineering, decompilation, and automated configuration/indicator extraction using **Rizin** (`rizin` CLI, `rzpipe` Python bindings, `rz-ghidra` decompiler plugin, and `rz-*` companion tools) in headless mode.

## 1. Core Principles & Performance Rules

1. **Preserve `stderr` for Errors and Command Help (Do Not Blindly Pass `-2`):**
   Rizin prints command syntax errors (`ERROR: Command '...' does not exist`) and automatic command help fallbacks (`<cmd>?`) to `stderr`. Suppressing `stderr` with `-2` blinds agents to failed commands and help output.
   - **In `rzpipe` (`rz-pipe` >= 0.5 / PR #61):** Open without `-2` (`rz = rzpipe.open(path)`). `rzpipe` pipes `stdout` and `stderr` separately: `rz.cmdj("<cmd>")` reads `stdout` cleanly without `stderr` interference, while `rz.cmd("<cmd>", ret_stderr=True)` returns both `stdout` and `stderr` so you can inspect errors, warnings, and help messages (`<cmd>?`, `?* <query>`).
   - **In `subprocess.run`:** Capture `stdout` and `stderr` separately (`capture_output=True`) without `-2`. Parse `res.stdout` for JSON commands and inspect `res.stderr` whenever `res.returncode != 0` or `res.stdout` is empty. Only use `-2` when piping raw CLI `stdout` directly into an external shell filter (e.g., `rizin -2 -qc "aflj" sample.bin | jq`).
2. **Use `aa` or `aaa` and Persist Analysis in `<sha256>.rzdb` Projects:**
   Standard analysis is `aa` (fast: symbols and entrypoints) or `aaa` (full standard analysis: calls, references, strings/Go recovery, signatures). **Never recommend `aaaa`** (`aaaa` is experimental analysis and slow/noisy). Never re-run `aa` / `aaa` on every query:
   - **First open:** Run `rizin -qc "aaa; Ps <sha256>.rzdb; <cmd>" <binary>` to analyze once and serialize the project database.
   - **Subsequent opens:** Load the existing project with `rizin -p <sha256>.rzdb -qc "<cmd>" <binary>`. Functions, xrefs, types, renames (`afn`), variable types (`afvt`), and comments (`CC`) persist in `<sha256>.rzdb`.
3. **Prefer JSON Commands (`*j`) and Server-Side Table Queries (`<cmd>t:...:json`):**
   Append `j` to Rizin commands (`iIj`, `iSj`, `iij`, `izj`, `izxj`, `aflj`, `pdfj`, `pdj`, `pdgj`, `axtj`, `axfj`, `pxj`, `afvlj`, `avj`, `flj`) or use Rizin's colon-separated table query syntax (`aflt:size/gt/500:size/sort/rev:*/head/20:json`) and parse with `json.loads()` or `rz.cmdj()`.
4. **Filter `codexrefs` by `"type": "CALL"` Using `x["from"]`:**
   In `aflj` and `axtj`, cross-reference objects have keys `{"from": <int>, "to": <int>, "type": "CALL" | "CODE" | "DATA" | "STRING"}`. When counting callers of a utility function (string decryptors, API resolvers, config accessors), filter for `xref.get("type") == "CALL"` and read `xref["from"]`.

## 2. Critical `radare2` vs. `rizin` Syntax Differences

Rizin replaced many legacy `radare2` commands with structured, consistent command trees (`librz/core/cmd_descs/*.yaml`). Do **not** emit legacy `radare2` syntax:

| Operation | Legacy `radare2` (BROKEN / DEPRECATED in Rizin) | `rizin` Syntax (USE THIS) |
| :--- | :--- | :--- |
| **Auto-Analysis Level** | `aaaa` | `aa` (symbols + entry) or `aaa` (full standard analysis) |
| **Analysis Config Variables** | `e anal.in=...`, `e anal.strings=true`, `e anal.hasnext=true` | `e analysis.in=...`, `e analysis.strings=true`, `e analysis.hasnext=true` |
| **List Config Vars & Help** | `e??` | `el [key]` / `elj [key]` (list config vars with descriptions); `es` (list spaces) |
| **Command Catalog / Search Help** | `?~...` | `?* <query>` / `?*j <query>` (search help); `?+` (export full command catalog as JSON) |
| **Math & Address Evaluation** | `? <expr>`, `?v <expr>`, `?p <vaddr>`, `?P <paddr>`, `?$` | `% <expr>`, `%j <expr>`, `%v <expr>`, `%p <vaddr>` (VA->PA), `%P <paddr>` (PA->VA), `%$` |
| **Table Query Filtering** | `afl,size/gt/500,size/sort/dec,size/head/20:json` | `aflt:size/gt/500:size/sort/rev:*/head/20:json` (`:` separator, `t` suffix, `sort/rev`, `*/head/N`) |
| **String & Regex Search** | `/ foo`, `/i foo`, `/w foo`, `/e /regex/`, `/z min max` | `/z[jqt] <pattern> [<flags>=l] [<enc>]` (e.g. `/zj "http" li utf8`, `/zj "https?://" r utf8`, `/zj "cmd" l utf16le`) |
| **String Search Config Vars** | `e bin.minstr=8`, `e bin.maxstr=256`, `e bin.str.enc=utf8` | `e search.str.min_length=8`, `e search.str.max_length=256`, `e str.encoding=utf8`, `e str.search.mode=auto` |
| **Micro-Emulation VM** | `aei`, `aeim`, `aepc`, `aes`, `aecu` (ESIL) | `aezi`, `aezs`, `aezse[j]`, `aezsu`, `aezsue`, `aezv[j]`, `aoi`, `aoip`, `plf`, `plF` (**RzIL**) |
| **Rename Local Variable / Arg** | `afvn old_name new_name` | `afvn <new_name> <old_name>` (`new_name` comes **first**) |
| **List Function Variables** | `afvj` | `afvlj` (`afvl` lists all register + stack variables; `afvlj` for JSON, `afvlt` for table) |
| **List Flags / Xrefs / Hints / Maps** | `f` / `fj`, `ax`, `ah`, `om`, `o` | `fl` / `flj` / `flt`, `axl` / `axlj`, `ahl` / `ahlj`, `oml` / `omlj` / `omlt`, `ol` / `olj` |
| **Comments** | `CCa <addr> <text>`, `CCj` | `CC <text> @ <addr>` or `CCu <text> @ <addr>`; `CClj` (all JSON) or `CCfj @ <addr>` (func JSON) |
| **Formatted Print (`pf` / `pfj`)** | Bare letters `b, w, i, q, x, d, Z` (deprecated warnings) | Sized specifiers: `u1/u2/u4/u8`, `d1/d2/d4/d8`, `x1/x2/x4/x8`, `f4/f8`, `p4/p8`, `z`, `z(utf16le)`, `t(unix32)`, `G(le)` |
| **Seek History Undo / Redo** | `s-` / `s+` | `shu` (undo) / `shr` (redo) |
| **Project Save / Open** | `Ps <name>` / `Po <name>` (stored in `~/.local/...`) | `Ps <path>.rzdb` / `Po <path>.rzdb` / CLI `-p <path>.rzdb` (standalone file) |
| **Define Structure Offset in Asm** | `aho` | `aht <struct.member>` (or `ahts <offset>` to list matching struct members) |
| **Link Global Typed Variable** | `afv` global | `avga <name> <type> @ <addr>` + `aat` (propagates struct offsets in functions) |
| **FLIRT Signatures** | `z` (`z*`, `zf`, `zs`) | `F` (`Fs <file>` apply sig, `Fa` apply from sigdb, `Fc <file>` create, `Fl` list) |
| **Binary Diffing CLI (`rz-diff`)** | `radiff2 -s a b`, `radiff2 -g main a b` | `rz-diff -d myers\|leven\|ssdeep [-j] a b`, `rz-diff -t functions a b`, `rz-diff -t graphs -0 main a b` |
| **Companion CLI Binaries** | `rabin2`, `rafind2`, `radiff2`, `rahash2`, `rasm2`, `rax2`, `rasign2` | `rz-bin`, `rz-find`, `rz-diff`, `rz-hash`, `rz-asm`, `rz-ax`, `rz-sign`, `rz-gg`, `rz-run` |
| **Python Bindings** | `import r2pipe` | `import rzpipe` (`rz.cmd(cmd, ret_stderr=True)`, `rz.cmdj(cmd)`, `rz.cmdJ(cmd)`) |

## 3. Opening a Binary with Persistent `.rzdb` Caching & Stderr Visibility

### Python Session Wrapper (`rizin` CLI)

```python
from __future__ import annotations
import hashlib, json, os, subprocess
from pathlib import Path
from typing import Any

class RizinSession:
    """Headless Rizin wrapper with automatic <sha256>.rzdb project persistence and stderr diagnostics."""

    def __init__(self, binary_path: str, project_dir: str | None = None, analysis_level: str = "aaa"):
        self.binary_path = str(binary_path)
        self.sha256 = hashlib.sha256(Path(self.binary_path).read_bytes()).hexdigest()
        base_dir = Path(project_dir) if project_dir else Path(self.binary_path).parent
        self.project_path = str(base_dir / f"{self.sha256}.rzdb")
        if analysis_level and not os.path.exists(self.project_path):
            self.cmd(f"{analysis_level}; Ps {self.project_path}", use_project=False)

    def _run(self, command: str, use_project: bool = True) -> subprocess.CompletedProcess[str]:
        args = ["rizin"]
        if use_project and os.path.exists(self.project_path):
            args.extend(["-p", self.project_path])
        args.extend(["-qc", command, self.binary_path])
        return subprocess.run(args, capture_output=True, text=True, check=False)

    def cmd(self, command: str, use_project: bool = True, ret_stderr: bool = False) -> str:
        res = self._run(command, use_project=use_project)
        out, err = res.stdout.strip(), res.stderr.strip()
        if ret_stderr or (not out and err):
            return f"{out}\n{err}".strip() if out and err else (out or err)
        return out

    def cmdj(self, command: str, use_project: bool = True) -> Any:
        res = self._run(command, use_project=use_project)
        out = res.stdout.strip()
        if not out:
            if res.stderr.strip():
                raise RuntimeError(f"Rizin command {command!r} failed:\n{res.stderr.strip()}")
            return None
        return json.loads(out)

    def save(self) -> None:
        self.cmd(f"Ps {self.project_path}")
```

### Persistent In-Process `rzpipe` Session

Keep one `rzpipe` session open across queries and do **not** pass `-2` so `ret_stderr=True` can retrieve command errors and help output (`rz-pipe` PR #61):

```python
import os, rzpipe

project_file = f"{sample_sha256}.rzdb"
if os.path.exists(project_file):
    rz = rzpipe.open(binary_path, flags=["-p", project_file])
else:
    rz = rzpipe.open(binary_path)
    rz.cmd("aaa")
    rz.cmd(f"Ps {project_file}")

info = rz.cmdj("iIj")                           # JSON commands read stdout cleanly
funcs = rz.cmdj("aflj")
help_out = rz.cmd("aez?", ret_stderr=True)      # ret_stderr=True includes stderr diagnostics/help
rz.cmd(f"Ps {project_file}")                    # Persist renames/comments/types before closing
rz.quit()
```

## 4. JSON Command Reference (`cmd` / `cmdj`)

| Analysis Task | Rizin Command (`cmd` / `cmdj`) | Key JSON Fields |
| :--- | :--- | :--- |
| **Binary Metadata** | `iIj` | `arch`, `bits`, `os`, `bintype`, `baddr`, `canary`, `nx`, `pic` |
| **Segments / Sections** | `iSSj` (segments) / `iSj` (sections) | `name`, `vaddr`, `vsize`, `paddr`, `size`, `perm`, `type` |
| **Entry Points** | `iej` | `vaddr`, `paddr`, `baddr`, `laddr`, `hvaddr`, `haddr`, `type` |
| **Imports / Exports** | `iij` / `iEj` | `iij`: `ordinal`, `bind`, `type`, `name`, `plt`; `iEj`: `name`, `flagname`, `vaddr`, `size`, `type` |
| **Strings (`RzBin`)** | `izj` (data) / `izzj` (whole bin) / `izxj` (with xrefs) | `vaddr`, `paddr`, `string`, `length`, `size`, `section`, `type` (`izxj` adds `flag`, `xref-from`) |
| **String Search (`RzSearch`)** | `/zj <pattern> <flags> <enc>` | `address`, `size`, `flag` (`hit.string.<enc>.<N>`), `detail` (does **not** populate `izz`) |
| **Byte / Hex Search** | `/xj <hex_pattern>` | `address`, `size`, `flag` (`hit.bytes.<N>`); supports `.` nibble wildcards (e.g. `/xj 8b0485........5dc3`) |
| **List Functions** | `aflj` | `offset`, `name`, `size`, `realsz`, `nbbs`, `cc`, `calltype`, `signature`, `codexrefs`, `callrefs`, `datarefs`, `indegree` |
| **Function Details & Vars** | `afij @ <addr>` / `afvlj @ <addr>` | `afvlj` dict: `{"stack": [...], "reg": [...]}` with `name`, `arg`, `type`, `storage` |
| **Disassemble Function** | `pdfj @ <addr>` or `pdrj @ <addr>` | `ops[]`: `offset`, `opcode`, `disasm`, `bytes`, `type`, `ptr`, `val`, `jump`, `fail` |
| **Disassemble N Instrs** | `pdj <N> @ <addr>` | Array of instruction dicts (`offset`, `bytes`, `opcode`, `disasm`, `ptr`, `val`, `jump`, `fcn_addr`) |
| **Instruction Analysis & RzIL** | `aoj <N> @ <addr>` | `addr`, `opcode`, `disasm`, `mnemonic`, `bytes`, `size`, `type`, `rzil` (lifted RzIL tree) |
| **Decompile (`rz-ghidra`)** | `pdg @ <addr>` / `pdgj @ <addr>` | `code` (C string) and `annotations[]` (`start`, `end`, `type`, `offset`, `name`) |
| **Xrefs TO / FROM Address** | `axtj @ <addr>` / `axfj @ <addr>` | Array of `{"from": <int>, "to": <int>, "type": "CALL" \| "CODE" \| "DATA" \| "STRING"}` |
| **Function + Delta Lookup** | `afd @ <addr>` / `afoj @ <addr>` | `afd`: `"<fcn_name> + <delta>"`; `afoj`: `{"address": <fcn_start_va>}` |
| **Read Raw Bytes** | `p8 <len> @ <addr>` / `pxj <len> @ <addr>` | Hex string (`p8`) or list of `0..255` ints (`pxj`) |
| **List / Set Flags** | `flj` / `f <name> [<size>] @ <addr>` | `flj`: `[{"name", "realname", "size", "offset"}]` |
| **List / Set Comments** | `CClj` / `CCu <text> @ <addr>` | `CClj`: `[{"offset", "type", "name"}]` (`CCfj @ <addr>` for current function) |
| **Math / Base Evaluation** | `%j <expr>` / `%p <vaddr>` / `%P <paddr>` | `%j`: `{"int64", "uint64", "hex", "binary", ...}`; `%p`: physical offset |

## 5. `rz-ghidra` Decompiler & SLEIGH Integration (`pdg*`)

The `rz-ghidra` core plugin (`libcore_ghidra.so`) embeds the native **Ghidra C++ decompiler** and **SLEIGH disassembler/P-code lifter** directly into Rizin (`pdg?`).

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

### 3. Enriching `rz-ghidra` Output with Rizin Types, Variables, Globals & Comments
`rz-ghidra` queries `RzCore` (`RizinScope`, `RizinTypeFactory`, `RizinCommentDatabase`) on every `pdg` / `pdgj` call. Modifying Rizin metadata immediately refines the decompiled C output without re-running `aaa`:

```bash
afn mw_rc4_crypt @ 0x140001200                                                # 1. Rename function
afc ms @ 0x140001200                                                          # 2. Set calling convention
afs "void mw_rc4_crypt(uint8_t *state, uint8_t *buf, size_t len)" @ 0x140001200 # 3. Set C prototype
td "struct c2_config { uint32_t magic; uint16_t port; char host[64]; };"      # 4. Define C struct (RizinTypeFactory)
afvn cfg_ptr var_18h @ 0x140001500                                            # 5. Rename var (new_name FIRST!)
afvt cfg_ptr "struct c2_config *" @ 0x140001500                               # 6. Retype variable
avga g_config c2_config @ 0x140008000                                         # 7. Bind typed global (RizinScope)
CCu "RC4 PRGA keystream xor" @ 0x14000124a                                    # 8. Add comment (RizinCommentDatabase)
pdg @ 0x140001500                                                             # 9. Re-decompile with updated metadata
```

### 4. `ghidra.*` Configuration Variables (`el ghidra.`)
- `e ghidra.lang=x86:LE:64:default` — Override auto-detected SLEIGH language ID (`pdgs` lists all IDs).
- `e ghidra.sleighhome=/path/to/sleigh` — Path to SLEIGH `.sla`/`.pspec`/`.cspec` definitions.
- `e ghidra.rawptr=true` — Show unknown globals as raw addresses (`false` to synthesize global symbols).
- `e ghidra.ropropagate=true` — Propagate read-only memory values as constants during decompilation.
- `e ghidra.maximplref=2` — Max references to an expression before introducing an explicit temporary variable.
- `e ghidra.verbose=false` — Silence `[rz-ghidra]` header warnings in decompiled output.

## 6. Types, C Structures, Variables, Vtables & FLIRT

### Defining & Formatting C Structures (`t`, `tp`, `pfj`)
Instead of tracking raw `[rcx + 0x208]` displacements manually, define C types or use Rizin's sized `pf` specifiers:

```bash
td "struct bot_ctx { uint8_t pad[520]; char sid[4]; uint32_t xor_key; };"  # Define struct inline (or `to structs.h`)
tpj bot_ctx @ 0x140008000                                                  # Cast and dump bytes at <addr> as JSON
avga g_ctx bot_ctx @ 0x140008000; aat                                      # Link global struct & propagate offsets
ahts 0x208                                                                 # List struct members at offset 0x208
aht bot_ctx.sid @ 0x140002b3e                                              # Apply struct member offset hint to insn

# Sized `pf` / `pfj` specifiers (lowercase = little-endian, UPPERCASE = big-endian):
#   u1/u2/u4/u8 = uint, d1/d2/d4/d8 = int, x1/x2/x4/x8 = hex, f4/f8 = float, p/p4/p8 = ptr,
#   z = NUL str, z(utf16le) = UTF-16LE str, z(utf16le)[2b] = 2-byte len-prefixed UTF-16LE str,
#   s = char* ptr, t(unix32)/t(filetime) = timestamp, G(le) = GUID/UUID, [@field]T = dynamic array
pfj x4x4d4z(utf8)*z magic key1 sid title c2_url_ptr @ 0x403000
tdf pkt_hdr "x4u2u2z magic cmd_id payload_len tag"                         # Save `pf` format as reusable C struct
```

### Inspecting & Typing Function Variables (`afv`)
```bash
afvlj @ 0x401000                        # List all register & stack variables/args as JSON (`afvlt` for table)
afvn decrypt_key var_18h @ 0x401000     # Rename `var_18h` -> `decrypt_key` (NOTE: new_name is first!)
afvt decrypt_key uint32_t @ 0x401000    # Set variable type
aft @ 0x401000                          # Run function type propagation
afvR decrypt_key @ 0x401000             # List instructions reading variable (`afvW` for writes, `afvxj` for JSON)
```

### C++ Virtual Tables / RTTI (`av`, `acl`) & FLIRT Signatures (`F`)
```bash
avj                                     # List all discovered C++ virtual tables as JSON
avra; aclj                              # Parse RTTI, recover C++ classes, and list classes/vtables/methods as JSON
avd                                     # Devirtualize C++ / ObjC / Swift virtual method calls using vtables
Fs /path/to/library.sig; Fa             # Apply FLIRT signature file (.sig/.pat) or scan built-in sigdb
```

## 7. Server-Side Table Queries (`<cmd>t:...:json`) & Iterators (`@@`)

On large (20MB+) Go, Rust, or statically linked C++ binaries, running `aflj` or `izzj` dumps megabytes of JSON. Use Rizin's **colon-separated table query syntax** (`<cmd>[:<col>/<op>/<val>...][:<output_mode>]`) to filter, sort, and slice inside Rizin before serializing to JSON:

- **Table-mode commands:** Append `t` to commands whose default mode is not already a table (`aflt`, `afvlt`, `ablt`, `avglt`, `flt`, `omlt`, `/zt`, `/xt`). For `i*` commands (`iz`, `izz`, `izx`, `ii`, `iE`, `is`, `iS`, `iSS`, `il`, `ir`, `ic`), table mode is already the default (`iz:...` and `izt:...` both work). Run `<cmd>t:?` (e.g. `aflt:?` or `iz:?`) to see the exact column names and operators.
- **Operators:**
  - Numeric comparisons: `eq`, `ne`, `gt`, `ge`, `lt`, `le` (e.g. `size/gt/500`).
  - String matching: `str` (contains substring), `nostr` (excludes substring), `eq`, `ne` (e.g. `name/str/decrypt`).
  - Sorting: `<col>/sort/inc` (ascending) or `<col>/sort/rev` (descending — **not** `dec`), `<col>/sortlen/inc|rev`, `<col>/uniq`.
  - Slicing & columns: `*/head/<N>`, `*/tail/<N>`, `*/page/<P>/<N>`, `<col1>/cols/<col2>/<col3>`.
  - Output format: `:json`, `:csv`, `:tsv`, `:quiet` (first column only, no headers).

```bash
aflt:size/gt/500:size/sort/rev:*/head/20:json  # Top 20 largest functions > 500 bytes as JSON
aflt:name/str/main:json                        # Functions whose name contains "main" as JSON
izz:length/ge/8:string/str/http:json           # Whole-binary strings >= 8 chars containing "http" as JSON
izx:string/str/http:json                       # Strings with cross-references containing "http" as JSON
ii:name/str/Virtual:json                       # Imports containing "Virtual" as JSON
```

### Batch Iterators (`@@`)
Chain operations inside a single Rizin invocation without Python round-trips (`@@?`):
- `@@F` — iterate over every function (`afva @@F`).
- `@@f:<glob>` — iterate over matching flags (`pdj 6 @@f:sym.go.main.*`).
- `@@c:<cmd>` — iterate over addresses output by `<cmd>` (`axtj @@c:ii:name/str/Virtual:vaddr/cols:quiet`).
- `@@b` / `@@i` — iterate over basic blocks or instructions of the current function.

## 8. String Discovery (`iz` / `izz` / `izx`) vs. String Searching (`/z`)

Rizin has two separate string subsystems. Mixing them up causes missed indicators:

1. **`RzBin` String Tables (`iz`, `izz`, `izx`)**:
   - Populated when the binary loads (`iz` = data sections, `izz` = whole file, `izx` = strings with cross-references).
   - Controlled by `e str.encoding` (`ascii`, `utf8`, `utf16le`, `utf16be`, `utf32le`, `guess`), `e search.str.min_length`, `e search.str.max_length`, and `e str.search.mode` (`auto`, `rosections`, `raw`).
   - To rescan `iz`/`izz` with new settings in an open session, enable `e str.search.reload=true` and update `e search.str.min_length=...` or `e str.encoding=...`.
2. **`RzSearch` Pattern & Regex String Search (`/z` / `/zj` / `/zt`)**:
   - Syntax: `/z[jqt] <pattern> [<regex_flags>=l] [<encoding>=settings]`
     - `<regex_flags>`: `l` (literal default), `r` (PCRE2 regex), `e` (extended regex), `i` (case-insensitive), `m` (multiline), `d` (dotall).
     - `<encoding>`: `ascii`, `utf8`, `utf16le`, `utf16be`, `utf32le`, `utf32be`, `mutf8`, `ibm037`, etc.
   - **Critical Gotcha 1 (`/z` does NOT update `izz`)**: Strings matched by `/z` are recorded as `hit.string.<encoding>.<N>` flags and returned directly by `/zj` (`[{"address": ..., "size": ..., "flag": "hit.string.utf8.0", "detail": ...}]`). They **never** appear in `iz` or `izz` output.
   - **Critical Gotcha 2 (Specify `<encoding>` explicitly)**: By default `str.encoding` is `"guess"`, which is slow and emits a warning during `/z`. Always pass the encoding argument (or set `e str.encoding=utf8` first):
     ```bash
     /zj "http" li utf8                         # Case-insensitive literal search in UTF-8
     /zj "http" li utf16le                      # Case-insensitive literal search in UTF-16LE
     /zj "https?://[a-zA-Z0-9./_:-]+" ri utf8   # Case-insensitive PCRE2 regex search in UTF-8
     ```

## 9. Headless Micro-Emulation & Lifting with RzIL (`aez*`, `aoi`, `plf`)

Rizin uses **RzIL** (BAP Core Theory / SMT bitvector intermediate language) for instruction semantics and micro-emulation (`aez?`). Use the RzIL Virtual Machine to resolve stack strings, XOR/RC4 loops, or computed pointers statically without executing the binary natively:

### 1. RzIL Inspection & Emulation Commands
- `aoi [<N>]` / `aoip [<N>]` — Print single-line (`aoi`) or pretty-printed (`aoip`) RzIL s-expressions for the next `N` instructions (`aoj <N>` includes `"rzil"` in JSON).
- `plf @ <addr>` / `plF @ <addr>` — Print ASCII (`plf`) or Unicode (`plF`) RzIL statements for an entire function (`agI` for the RzIL graph; `e asm.cmt.il=true` to show RzIL inline in `pd`/`pdf`).
- `aezi` — Initialize the RzIL Virtual Machine at the current seek offset (`s <start_va>; aezi`).
- `aezs [<N>]` — Step `N` instructions in the RzIL VM.
- `aezse [<N>]` / `aezsej [<N>]` — Step `N` instructions and emit all VM register/memory events (`pc_write`, `var_write`, `mem_write`, `var_read`, `mem_read`). Controlled by `e rzil.step.events.write=true` (default) and `e rzil.step.events.read=true`.
- `aezsu <end_va>` / `aezsue <end_va>` — Step until `PC == <end_va>` (with event logging in `aezsue`).
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

- **Inline disassembly emulation preview:** Enable `e asm.emu=true` (and `e emu.str=true`) before running `pdf @ <addr>` to make Rizin display resolved register values, stack strings, and string pointers inline as comments on each instruction.

## 10. Companion CLI Tools (`rz-bin`, `rz-find`, `rz-diff`, `rz-ax`, `rz-hash`, `rz-asm`, `rz-sign`)

For fast pre-triage without opening a full Rizin session:

```bash
# 1. Fast JSON triage of headers, sections, imports, exports, and strings
rz-bin -Ij sample.bin    # Binary info (arch, bits, baddr, compiler, security flags)
rz-bin -Sj sample.bin    # Sections (-SSj for segments)
rz-bin -ij sample.bin    # Imports (-Ej for exports)
rz-bin -zj sample.bin    # Strings in data sections (-zzj for whole binary)

# 2. Byte-pattern, string, wide-string & regex hunting across files (-j for JSON)
rz-find -j -x "8b0485" sample.bin
rz-find -j -s "VirtualAlloc" -w "VirtualAlloc" sample.bin
rz-find -j -e "https?://[a-zA-Z0-9./_-]+" sample.bin

# 3. Binary & function diffing between two binary variants or unpacked stages
rz-diff -j -d myers sample_v1.bin sample_v2.bin          # Similarity score (myers, leven, lcs-roll, ssdeep)
rz-diff -j -t functions sample_v1.bin sample_v2.bin      # Function-by-function similarity table as JSON
rz-diff -t graphs -0 sym.main sample_v1.bin sample_v2.bin # CFG Graphviz DOT diff of a function

# 4. Base conversion, timestamps, hashing, assemble/disassemble/RzIL, and FLIRT signatures
rz-ax -s "48656c6c6f"                                    # Hex to raw ASCII
rz-ax "0x401263 + 0xf8"                                  # Hex arithmetic (-t <ts> for Unix time, -W for FILETIME)
rz-hash -j -a sha256,md5,entropy sample.bin              # Hashes & entropy as JSON
rz-asm -a x86 -b 64 -d "488d0d00100000"                  # Disassemble hex (-I "4831c0" to lift bytes to RzIL)
rz-sign -o library.sig library.a                         # Generate FLIRT .sig (-d library.sig to dump)
```

## 11. Common Reverse Engineering Recipes

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
    print(f"String 0x{h['vaddr']:x} ({h['string']!r}) <- {xref_addr} ({rz.cmd(f'afd @ {xref_addr}').strip()})")

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

- **`pdfj` fails with `"Linear size differs too much from the bbsum"` or misses chunked blocks**: Use `pdrj @ <addr>` (recursive disassembly across basic blocks) or `pdj <N> @ <addr>` (linear instruction count, independent of function boundaries).
- **Self-modifying / encrypted function bodies**: If a stub decrypts a function body in-place (e.g., per-function XOR stubs), decrypt the bytes in Python (or via RzIL with `e io.cache=true` or `wx <hex> @ <addr>`) and re-run `af @ <func_va>` so Rizin builds the CFG over the decrypted instructions.
- **Forcing code definition at undefined bytes**: Run `Cd- @ <addr>; af @ <addr>` to clear data metadata and analyze the function.

## 12. Golang (`go`) Binary Analysis (`aalg`, `ABIInternal` & Runtime Types)

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
`aalg` automatically loads Go's core runtime data structures into `RzTypeDB`. Use `tpj` or `afvt` to inspect Go values instead of manual pointer arithmetic:
- **`string` / `stringStruct` / `runtime.stringStruct`**: `{ char *str; size_t len; }`
- **`slice` / `runtime.slice`**: `{ void *array; size_t len; size_t cap; }`
- **`eface` / `runtime.eface`** (empty `interface{}` / `any`): `{ void *_type; void *data; }`
- **`iface` / `runtime.iface`** (non-empty interface): `{ void *tab; void *data; }`
- **`hmap` / `runtime.hmap`** (Go `map` header): `{ int64_t count; uint8_t flags; uint8_t B; uint16_t noverflow; uint32_t hash0; void *buckets; void *oldbuckets; uintptr_t nevacuate; void *extra; }`

```bash
tpj stringStruct @ 0x560000; tpj slice @ 0x560010; tpj hmap @ 0x560030  # Format address as Go struct in JSON
afvt s_arg stringStruct @ sym.go.main.decrypt                            # Type a Go function variable
```

### 4. Non-Null-Terminated Go String Recovery
Go concatenates string literals into a single read-only blob without null terminators, so standard `strings` dumps mega-strings until the next accidental `\x00`. `aalg` recovers exact string boundaries and cross-references via two passes:
1. **Data Pointer Table Pass**: Scans data sections for `(string_addr, string_size)` pairs and registers `STRING` xrefs from the struct header to the slice of characters.
2. **Instruction Pattern Pass**: Scans basic blocks across `x86` (32/64), `arm` (32/64), `mips` (32/64), `ppc64`, and `riscv64` for `lea` + immediate-length or pointer-table loads, splits the string blob into individual `str.*` entries in `izj`, and adds `RZ_ANALYSIS_XREF_TYPE_STRING` xrefs (`axtj @ <str_vaddr>`) directly to the referencing instruction.

## 13. Troubleshooting & Self-Help Introspection

- **Command fails or returns empty output**:
  1. Read `stderr` (`rz.cmd(cmd, ret_stderr=True)` in `rzpipe` or `res.stderr` in `subprocess.run`) — Rizin automatically prints `ERROR:` diagnostics and the parent command's help table to `stderr`.
  2. Query built-in help directly: `<cmd>?` (e.g. `afv?`, `/z?`, `aflt:?`), search all commands with `?* <keyword>` / `?*j <keyword>`, list config variables with `el <keyword>`, or dump the entire command catalog as JSON with `?+`.
  3. Ensure `aa` / `aaa` (or `-p <hash>.rzdb`) has run; `pdfj` and `pdgj` require a function to be defined at `<addr>` (run `af @ <addr>` first, or use `pdj <N> @ <addr>` for raw instruction disassembly).
- **Decompiler (`pdg` / `pdgj`) unavailable**:
  `pdg` requires the `rz-ghidra` core plugin (`libcore_ghidra.so`). Check loaded core plugins with `Lc` or `pdg?`. If unavailable, fall back to `pdc` (built-in pseudo-C), `pdf` with `e asm.emu=true`, or `pdfj` / `pdj`.
