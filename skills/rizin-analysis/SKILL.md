---
name: rizin-analysis
description: Analyze binaries using Rizin (rizin CLI, rzpipe Python API, and rz-bin/rz-find/rz-diff/rz-sign/rz-ax tools) in headless mode with persistent .rzdb project caching. Use when disassembling, decompiling (rz-ghidra), mapping cross-references, recovering C structs/types/vtables/Go symbols, running ESIL/RzIL micro-emulation, or writing automated binary analysis and configuration extraction scripts with Rizin.
license: LGPL-3.0-only
---

# Rizin Headless Binary Analysis (`rizin` & `rzpipe`)

Use this skill to perform static binary analysis, reverse engineering, and automated configuration/indicator extraction using **Rizin** (`rizin` CLI, `rzpipe` Python bindings, and `rz-*` companion tools) in headless mode.

---

## 1. Core Principles & Performance Rules

1. **Always Suppress Stderr (`-2`) in Headless / JSON Mode:**
   Rizin prints warnings and analysis progress to stderr, which can corrupt stdout pipes in subprocess/IPC wrappers. Always pass `-2` (`rizin -2 -qc ...` or `rzpipe.open(path, flags=["-2"])`).
2. **Persist Analysis in `<sha256>.rzdb` Projects:**
   Full analysis (`aaaa` or `aaa`) is expensive. Never re-run `aaaa` on every query.
   - **First open:** Run `rizin -2 -qc "aaaa; Ps <sha256>.rzdb; <cmd>" <binary>` to analyze once and serialize the project database.
   - **Subsequent opens:** Load the existing project with `rizin -2 -p <sha256>.rzdb -qc "<cmd>" <binary>`. Functions, xrefs, types, renames (`afn`), and comments (`CCa`) persist in `<sha256>.rzdb`.
3. **Prefer JSON Commands (`*j`) and Table Queries (`*,...:json`) over Text Parsing:**
   Append `j` to Rizin commands (`iIj`, `iSj`, `iij`, `izj`, `aflj`, `pdfj`, `pdj`, `axtj`, `axfj`, `pxj`, `afvlj`, `avj`) and parse with `json.loads()` or `rz.cmdj()`. Never regex-parse human-formatted ASCII tables when a `j` or `:json` table suffix exists.
4. **Filter `codexrefs` by `"type": "CALL"` When Counting Callers:**
   In `aflj` and `axtj`, cross-reference arrays include both `"CALL"` (function call) and `"CODE"` (jump/branch) entries. When identifying high-fan-in utility functions (string decryptors, API resolvers, config table accessors), filter for `xref.get("type") == "CALL"`.

---

## 2. Critical `radare2` vs. `rizin` Syntax Differences

Do **not** emit legacy `radare2` syntax when driving Rizin:

| Operation | Legacy `radare2` (BROKEN in Rizin) | `rizin` Syntax (USE THIS) |
| :--- | :--- | :--- |
| **Analysis Config Variables** | `e anal.in=...`, `e anal.strings=true`, `e anal.hasnext=true` | `e analysis.in=...`, `e analysis.strings=true`, `e analysis.hasnext=true` |
| **Rename Local Variable / Arg** | `afvn old_name new_name` | `afvn new_name old_name` (`new_name` comes **first**) |
| **List Function Variables** | `afvj` | `afvlj` (`afvl` lists all register + stack variables; `afvlj` for JSON) |
| **Seek History Undo / Redo** | `s-` / `s+` | `shu` (undo) / `shr` (redo) |
| **Project Save / Open** | `Ps <name>` / `Po <name>` (stored in `~/.local/...`) | `Ps <path>.rzdb` / `Po <path>.rzdb` / CLI `-p <path>.rzdb` (standalone file) |
| **Define Structure Offset in Asm** | `aho` / `aht` legacy | `aht <struct.member>` (or `ahts <offset>` to list matching struct members) |
| **Link Global Typed Variable** | `afv` global | `avga <name> <type> @ <addr>` + `aat` (propagates struct offsets in functions) |
| **FLIRT Signatures** | `z` (`z*`, `zf`, `zs`) | `F` (`Fs <file>` apply sig, `Fa` apply from sigdb, `Fc <file>` create, `Fl` list) |
| **Companion CLI Binaries** | `rabin2`, `rafind2`, `radiff2`, `rahash2`, `rasm2`, `rax2`, `rasign2` | `rz-bin`, `rz-find`, `rz-diff`, `rz-hash`, `rz-asm`, `rz-ax`, `rz-sign`, `rz-gg`, `rz-run` |
| **Python Bindings** | `import r2pipe` | `import rzpipe` (`rzpipe.open(path, flags=["-2"])`) |

---

## 3. Opening a Binary with Persistent `.rzdb` Caching

### Python Session Wrapper (`rizin` CLI)

```python
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any


class RizinSession:
    """Headless Rizin wrapper with automatic <sha256>.rzdb project persistence."""

    def __init__(self, binary_path: str, project_dir: str | None = None, analyze: bool = True):
        self.binary_path = str(binary_path)
        data = Path(self.binary_path).read_bytes()
        self.sha256 = hashlib.sha256(data).hexdigest()
        base_dir = Path(project_dir) if project_dir else Path(self.binary_path).parent
        self.project_path = str(base_dir / f"{self.sha256}.rzdb")
        if analyze and not os.path.exists(self.project_path):
            self.cmd(f"aaaa; Ps {self.project_path}", use_project=False)

    def cmd(self, command: str, use_project: bool = True) -> str:
        args = ["rizin", "-2"]
        if use_project and os.path.exists(self.project_path):
            args.extend(["-p", self.project_path])
        args.extend(["-qc", command, self.binary_path])
        res = subprocess.run(args, capture_output=True, text=True, check=False)
        return res.stdout.strip()

    def cmdj(self, command: str, use_project: bool = True) -> Any:
        out = self.cmd(command, use_project=use_project)
        return json.loads(out) if out else None

    def save(self) -> None:
        self.cmd(f"Ps {self.project_path}")
```

### Persistent In-Process `rzpipe` Session

When running many sequential queries in a single Python script, keep one `rzpipe` process open and save the `.rzdb` on exit:

```python
import os
import rzpipe

project_file = f"{sample_sha256}.rzdb"
if os.path.exists(project_file):
    rz = rzpipe.open(binary_path, flags=["-2", "-p", project_file])
else:
    rz = rzpipe.open(binary_path, flags=["-2"])
    rz.cmd("aaaa")
    rz.cmd(f"Ps {project_file}")

# Run multiple fast queries against the warm session
info = rz.cmdj("iIj")
funcs = rz.cmdj("aflj")

# Persist any renames/comments/types before closing
rz.cmd(f"Ps {project_file}")
rz.quit()
```

---

## 4. JSON Command Reference (`cmd` / `cmdj`)

| Analysis Task | Rizin Command (`cmd` / `cmdj`) | Key JSON Fields |
| :--- | :--- | :--- |
| **Binary Metadata** | `iIj` | `arch`, `bits`, `os`, `bintype`, `baddr`, `canary`, `nx`, `pic` |
| **Segments / Sections** | `iSj` | `name`, `vaddr`, `vsize`, `paddr`, `size`, `perm` |
| **Entry Points** | `iej` | `vaddr`, `paddr`, `baddr`, `laddr`, `type` |
| **Imports / Exports** | `iij` / `iEj` | `name`, `libname`, `plt` (`vaddr`), `ordinal`, `type` |
| **Strings (Data / All)** | `izj` (data) / `izzj` (whole bin) | `vaddr`, `paddr`, `string`, `length`, `section`, `type` |
| **List Functions** | `aflj` | `offset`, `name`, `size`, `nbbs`, `cc`, `codexrefs`, `callrefs` |
| **Function Details & Vars** | `afij @ <addr>` / `afvlj @ <addr>` | `size`, `stackframe`, `calltype`, `reg` + `sp` args/locals |
| **Disassemble Function** | `pdfj @ <addr>` or `pdrj @ <addr>` | `ops[]`: `offset`, `opcode`, `disasm`, `bytes`, `type`, `ptr`, `val`, `jump`, `fail` |
| **Disassemble N Instrs** | `pdj <N> @ <addr>` | Array of instruction dicts (`offset`, `bytes`, `opcode`, `ptr`, `val`, `jump`) |
| **Decompile Function** | `pdg @ <addr>` / `pdgj @ <addr>` (`rz-ghidra`) or `pdc @ <addr>` | `code` (C pseudocode string) and `annotations` |
| **Xrefs TO Address** | `axtj @ <addr>` | `from`, `type` (`"CALL"`, `"CODE"`, `"DATA"`, `"STRING"`), `opcode`, `fcn_addr`, `fcn_name` |
| **Xrefs FROM Address** | `axfj @ <addr>` | `from`, `to`, `type`, `opcode` |
| **Read Raw Bytes** | `p8 <len> @ <addr>` (hex) / `pxj <len> @ <addr>` (int array) | Hex string (`p8`) or list of `0..255` ints (`pxj`) |
| **Rename Function** | `afn <new_name> @ <addr>` | Updates function symbol in session; call `Ps <hash>.rzdb` to persist |
| **Set Comment** | `CCa <addr> <comment>` | Attaches comment at `<addr>`; call `Ps <hash>.rzdb` to persist |
| **Byte / Hex Search** | `/xj <hex_pattern>` | `offset`, `data` (supports byte/nibble wildcards with `.`, e.g. `/xj 8b0485........5dc3`) |

---

## 5. Types, C Structures, Variables, Vtables & FLIRT

### Defining & Applying C Structures (`t`, `tp`, `pfj`)
Instead of tracking raw `[rcx + 0x208]` offsets manually, define C structs and apply them to functions or memory:

```bash
# 1. Define a struct inline (or load a header file with `to structs.h`)
td "struct bot_ctx { uint8_t pad[520]; char sid[4]; uint32_t xor_key; };"

# 2. Print bytes at <addr> formatted as `struct bot_ctx` (JSON output via tpj)
tpj bot_ctx @ 0x140008000

# 3. Link a global address to a struct type and propagate member offsets in disassembly
avga g_ctx bot_ctx @ 0x140008000
aat

# 4. Explicitly annotate an instruction operand [reg + 0x208] with a struct member
aht bot_ctx.sid @ 0x140002b3e

# 5. Unpack arbitrary binary structures without defining a C type (`pf` / `pfj`)
# Format specifiers: b=byte, w=uint16, i=int32, x=uint32_hex, q=uint64, z=null-str, *x=ptr
pfj xxiiz flags key1 key2 sid c2_url @ 0x403000
```

### Inspecting & Typing Function Variables (`afv`)
```bash
# List all register and stack variables/arguments as JSON
afvlj @ 0x401000

# Rename variable `var_18h` to `decrypt_key` (NOTE: new_name is first in Rizin!)
afvn decrypt_key var_18h @ 0x401000

# Set variable type
afvt decrypt_key uint32_t @ 0x401000

# Find all instructions that read or write a local variable
afvR decrypt_key @ 0x401000
afvW decrypt_key @ 0x401000
```

### C++ Virtual Tables / RTTI (`av`) & FLIRT Signatures (`F`)
```bash
# List all discovered C++ virtual tables as JSON
avj

# Parse RTTI and recover C++ class hierarchy across the binary
avra
avrr

# Apply a FLIRT signature file (.sig or .pat) or scan built-in sigdb
Fs /path/to/library.sig
Fa
```

---

## 6. Server-Side Table Queries (`cmd,`) & Iterators (`@@`)

On large (20MB+) Go, Rust, or statically linked C++ binaries, running `aflj` or `izzj` dumps megabytes of JSON. Use Rizin's **table query syntax** (`<cmd>,<filter>:json`) to filter, sort, and slice inside Rizin before returning JSON:

```bash
# Filter functions: size > 500 bytes, sorted descending by size, top 20, as JSON
afl,size/gt/500,size/sort/dec,size/head/20:json

# Filter functions by name substring ("main" or "decrypt") as JSON
afl,name/str/main:json

# Filter all strings in binary (`izz,`): length >= 8, containing "http", as JSON
izz,length/ge/8,string/str/http:json

# Filter imports (`ii,`): only networking/memory APIs, as JSON
ii,name/str/Virtual:json
```

### Batch Iterators (`@@`)
Chain operations inside a single Rizin invocation without Python round-trips:
- `@@F` — iterate over every function (`afva @@F`).
- `@@f:<glob>` — iterate over matching flags (`pdj 6 @@f:sym.go.main.*`).
- `@@c:<cmd>` — iterate over addresses output by `<cmd>` (`axtj @@c:ii,name/str/Virtual:quiet`).
- `@@b` / `@@i` — iterate over basic blocks or instructions of the current function.

---

## 7. Headless Micro-Emulation with ESIL / RzIL (`ae`)

Rizin embeds an ESIL and RzIL virtual machine (`ae` / `rzil`) capable of executing instructions statically without running the binary natively. Use this to resolve stack strings, XOR loops, or computed jump targets inside a throwaway Rizin session:

```python
import rzpipe

rz = rzpipe.open("sample.bin", flags=["-2"])
rz.cmd("aa")

# 1. Initialize ESIL VM state and allocate a temporary stack (aeim)
rz.cmd("aei; aeim")

# 2. Allow ESIL execution to write decrypted bytes to virtual memory
rz.cmd("e io.cache=true")
rz.cmd("e emu.write=true")

# 3. Set instruction pointer to the start of the stack-string / decryptor block
start_va = 0x401200
end_va = 0x401285
rz.cmd(f"aepc 0x{start_va:x}")

# 4. Step until `end_va` (or step N instructions with `aes 50`)
rz.cmd(f"aecu 0x{end_va:x}")

# 5. Read registers (`drj` / `arj`) or dump decrypted stack/heap buffer
regs = rz.cmdj("arj")
ebp = regs.get("ebp") or regs.get("rbp")
decrypted_bytes = bytes.fromhex(rz.cmd(f"p8 64 @ 0x{ebp - 0x40:x}").strip())
print("Decrypted buffer:", decrypted_bytes)
rz.quit()
```

- **Inline disassembly emulation preview:** Enable `e asm.emu=true` (and `e emu.str=true`) before running `pdf @ <addr>` to make Rizin compute and display resolved register values, stack strings, and string pointers inline as comments on every instruction.

---

## 8. Companion CLI Tools (`rz-bin`, `rz-find`, `rz-diff`, `rz-ax`)

For fast pre-triage without initializing a full Rizin analysis engine:

```bash
# 1. Fast JSON triage of headers, sections, imports, exports, and strings
rz-bin -Ij sample.bin    # Binary info (arch, bits, baddr, compiler, hashes)
rz-bin -Sj sample.bin    # Sections (vaddr, paddr, size, entropy/perms)
rz-bin -ij sample.bin    # Imports
rz-bin -zj sample.bin    # Strings in data sections (-zzj for raw binary)

# 2. Byte-pattern & regex hunting across files (returns JSON offsets with -j)
rz-find -j -x "8b0485" sample.bin
rz-find -j -e "https?://[a-zA-Z0-9./_-]+" sample.bin

# 3. Binary / function diffing between two binary variants or patched stages
rz-diff -s sample_v1.bin sample_v2.bin          # Levenshtein similarity score
rz-diff -g sym.main sample_v1.bin sample_v2.bin # CFG graph diff of a function

# 4. Base conversion & hex expression evaluator (avoid mental hex math)
rz-ax -s "48656c6c6f"   # Hex to ASCII
rz-ax "0x401263 + 0xf8" # Hex arithmetic
```

---

## 9. Common Reverse Engineering Recipes

### Recipe 1: Find High-Fan-In Utility / Decryption Functions

String decryptors, API hash resolvers, and config table accessors are called from many locations. Use `aflj` and filter `codexrefs` to `type == "CALL"`:

```python
funcs = rz.cmdj("aflj") or []
for f in funcs:
    callers = [
        x["addr"] for x in f.get("codexrefs", [])
        if x.get("type") == "CALL"
    ]
    if len(callers) >= 5:
        print(f"0x{f['offset']:x}: {f['name']} (size={f['size']}, callers={len(callers)})")
```

### Recipe 2: Extract Immediate Operands & RIP-Relative Pointers (`pdj`)

Rizin's `pdj <N> @ <addr>` automatically resolves RIP-relative addresses into `op["ptr"]` and immediate values into `op["val"]`, eliminating manual displacement math:

```python
# Inspect 8 instructions of a function to extract a pointer table or key
ops = rz.cmdj(f"pdj 8 @ 0x{func_addr:x}") or []
for op in ops:
    opcode = op.get("opcode", "")
    raw_bytes = op.get("bytes", "")
    ptr = op.get("ptr")  # Resolved target VA for RIP-relative LEA/MOV
    val = op.get("val")  # Immediate constant
    print(f"0x{op['offset']:x}: {opcode:30s} | bytes={raw_bytes} ptr={ptr} val={val}")
```

- **x64 RIP-relative `lea rcx, [rip + disp32]`**: `op["bytes"]` starts with `"488d0d"`, and `op["ptr"]` holds the exact target virtual address (`rcx`).
- **x86 indexed `mov eax, dword [rax*4 + 0x10001518]`**: `op["bytes"]` starts with `"8b0485"`, and the 32-bit table VA is at `int.from_bytes(bytes.fromhex(op["bytes"][6:14]), "little")`.

### Recipe 3: Trace Cross-References to Strings or Imports

```python
for s in rz.cmdj("izj") or []:
    text = s.get("string", "")
    if "http" in text.lower() or "VirtualAlloc" in text:
        vaddr = s["vaddr"]
        xrefs = rz.cmdj(f"axtj @ 0x{vaddr:x}") or []
        print(f"String 0x{vaddr:x} ({text!r}):")
        for x in xrefs:
            print(f"  <- 0x{x['from']:x} in {x.get('fcn_name', 'unknown')} ({x['opcode']})")
```

### Recipe 4: Virtual Address (`vaddr`) to File Offset (`paddr`) Translation

When carving encrypted blobs or patching a raw binary buffer in Python while using Rizin virtual addresses:
- Inside Rizin: use `?p <vaddr>` (prints physical file offset) or read bytes directly at the virtual address via `p8 <len> @ <vaddr>`.
- From `iSj` (sections): for a section where `sec["vaddr"] <= vaddr < sec["vaddr"] + sec["vsize"]`, `file_offset = vaddr - sec["vaddr"] + sec["paddr"]`.
- For raw shellcode or memory-mapped dumps where `vaddr == paddr`: pass `-b 32` or `-b 64` and `-m <base_addr>` if needed.

### Recipe 5: Handling Obfuscated / Non-Contiguous Functions

- **`pdfj` fails with `"Linear size differs too much from the bbsum"` or misses chunked blocks**: Use `pdrj @ <addr>` (recursive disassembly across basic blocks) or `pdj <N> @ <addr>` (linear instruction count, independent of function boundaries).
- **Self-modifying / encrypted function bodies**: If a stub decrypts a function body in-place (e.g., per-function XOR stubs), decrypt the bytes in Python, write the patched binary, and re-run `af @ <func_va>` so Rizin builds the CFG over the decrypted instructions.
- **Forcing code definition at undefined bytes**: Run `Cd- @ <addr>; c @ <addr>; af @ <addr>` to clear data flags, mark code, and analyze the function.

---

## 10. Golang (`go`) Binary Analysis (`aalg`, `ABIInternal` & Runtime Types)

Rizin includes native Golang support (`librz/core/golang.c`) that runs automatically during `aaa` / `aaaa` (when `bin.lang` is `go`) or on demand via **`aalg`**:

### 1. `.gopclntab` Symbol & Package Recovery (`aalg`)
- Parses Go 1.2–1.15 (`0xfffffffb`), Go 1.16–1.17 (`0xfffffffa`), Go 1.18–1.19 (`0xfffffff0`), and Go 1.20+ (`0xfffffff1`) `.gopclntab` / `__gopclntab` tables across ELF, Mach-O, and PE (where `gopclntab` resides inside `.rdata`).
- Recovers stripped function symbols as `sym.go.<pkg>.<func>` (and aliases `sym.go.main.main` as `main`).
- Automatically skips compiler wrapper boilerplate (`.abi0`, `.abiinternal`, `.deferwrap`, `..inittask`, `type:`, `go:`) during function CFG construction so analysis time is spent on real code.
- Populates third-party/standard Go package names into the binary's library list (`ilj`).

```bash
# Run Go symbol + string recovery explicitly (if opening with `aa` instead of `aaa`)
aalg

# List recovered Go packages (libraries)
ilj

# List only application functions in `main.*` (avoid dumping 20,000 runtime.* functions)
afl,name/str/sym.go.main.:json
```

### 2. Go Calling Conventions (`golang` / `ABIInternal` vs. `golang_abi0` / `ABI0`)
- During `aalg`, Rizin samples up to 512 non-wrapper functions and votes on the prologue to detect the active Go ABI:
  - **`golang` (`ABIInternal`, Go 1.17+)**: Prologue matches `CMPQ SP|R12, 16(R14)` (`49 3b 66 10` / `4d 3b 66 10` on x86_64). Register allocation:
    - **x86_64**: `arg0..arg8` = `rax, rbx, rcx, rdi, rsi, r8, r9, r10, r11`, `ret` = `rax`, goroutine context `self` (`g`) = `r14`.
    - **arm64**: `arg0..arg7` = `x0..x7`, `ret` = `x0`, goroutine context `self` (`g`) = `x28`.
  - **`golang_abi0` (`ABI0`, Go < 1.17)**: Prologue loads `g` from TLS (`MOVQ FS|GS:[disp32], reg`); all arguments and return values are passed on the stack.
- Check or override a function's calling convention with `afc`:
  ```bash
  afc @ sym.go.main.main           # Inspect active calling convention
  afc golang @ sym.go.main.main    # Force ABIInternal register calling convention
  afc golang_abi0 @ sym.go.main.main
  ```

### 3. Preloaded Go Runtime Types (`types-golang-32.sdb` / `types-golang-64.sdb`)
`aalg` automatically loads Go's core runtime data structures into `RzTypeDB`. Use `tpj` or `afvt` to inspect Go values instead of manual pointer arithmetic:
- **`string` / `stringStruct` / `runtime.stringStruct`**: `{ char *str; size_t len; }`
- **`slice` / `runtime.slice`**: `{ void *array; size_t len; size_t cap; }`
- **`eface` / `runtime.eface`** (empty `interface{}` / `any`): `{ void *_type; void *data; }`
- **`iface` / `runtime.iface`** (non-empty interface): `{ void *tab; void *data; }`
- **`hmap` / `runtime.hmap`** (Go `map` header): `{ int64_t count; uint8_t flags; uint8_t B; uint16_t noverflow; uint32_t hash0; void *buckets; void *oldbuckets; uintptr_t nevacuate; void *extra; }`

```bash
# Format a memory address as a Go stringStruct, slice, or hmap in JSON
tpj stringStruct @ 0x560000
tpj slice @ 0x560010
tpj hmap @ 0x560030

# Type a stack/register variable inside a Go function
afvt s_arg stringStruct @ sym.go.main.decrypt
```

### 4. Non-Null-Terminated Go String Recovery
Go concatenates string literals into a single read-only blob without null terminators, so standard `strings` dumps mega-strings until the next accidental `\x00`. `aalg` recovers exact string boundaries and cross-references via two passes:
1. **Data Pointer Table Pass**: Scans data sections for `(string_addr, string_size)` pairs and registers `STRING` xrefs from the struct header to the slice of characters.
2. **Instruction Pattern Pass**: Scans basic blocks across `x86` (32/64), `arm` (32/64), `mips` (32/64), `ppc64`, and `riscv64` for `lea` + immediate-length or pointer-table loads, splits the string blob into individual `str.*` entries in `izj`, and adds `RZ_ANALYSIS_XREF_TYPE_STRING` xrefs (`axtj @ <str_vaddr>`) directly to the referencing instruction.

---

## 11. Troubleshooting

- **`JSONDecodeError` when calling `cmdj`**:
  1. Ensure `-2` is passed to silence stderr warnings.
  2. Verify the command supports the `j` suffix (`<cmd>?` in Rizin CLI) or `:json` table query (`<cmd>,?`).
  3. Ensure `aa` / `aaa` / `aaaa` (or `-p <hash>.rzdb`) has run; `pdfj` returns empty output if no function is defined at `<addr>` (use `af @ <addr>` first or fall back to `pdj <N> @ <addr>`).
- **Decompiler (`pdg` / `pdgj`) unavailable**:
  `pdg` requires the `rz-ghidra` plugin. Check availability with `Lc` or `pdg?`. If unavailable, fall back to `pdc` (built-in pseudo-C), `pdf` with `e asm.emu=true`, or `pdfj` / `pdj`.
