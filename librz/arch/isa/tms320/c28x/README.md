# TMS320C28x (`asm.cpu=c28x`)

Native decode / format / analysis / RzIL engine for the TMS320C28x
fixed-point DSP core: the C2000 real-time control line (C280x, C281x,
C2833x, F2806x, F2837x, F2838x), plus the C27x object mode those parts
boot in.

## Sources

Everything here comes from TI's public documentation and from black-box
observation of TI's own tools. No TI source or decompilation was consulted.

| document  | what it settles                                              |
|-----------|--------------------------------------------------------------|
| SPRU430F  | instruction encodings (ch. 6), `loc16`/`loc32` map (Table 5-1) |
| SPRUEO2   | `RPTB`, which SPRU430 does not document (it is C28x+FPU)      |
| SPRU514AA | calling convention (Table 7-2, section 7.3.1)                 |
| SPRAC71C  | ELF relocation types (Table 11-5) and layouts (Table 11-6)    |

## Encoding

One 16-bit opcode word, optionally followed by a second word carrying an
immediate, a branch displacement or a secondary operand field. Most opcodes
spend their low byte on `loc16`/`loc32`, the 8-bit addressing-mode selector
shared by nearly the whole instruction set; the `0x56` and `0x3e` prefixes open
a second opcode plane for what did not fit the primary map.

A single mask/match table over the packed `word0 << 16 | word1` therefore covers
both planes, and each row's operand descriptors drive extraction. The decoder
runs once and fills a `C28xInsn`; `c28x_format()` and `c28x_fill_analysis()`
only read the result and never re-parse. Same shape as the c6x engine.

`AMODE` (ST1 bit 8) reinterprets part of the `loc16` map: `AMODE = 0` is the
C28x-native set the C/C++ compiler emits, `AMODE = 1` restores the full
C2xLP-compatible set.

## Two things the manual does not say

Both were settled against compiled objects rather than assumed, and both would
have been wrong if guessed:

- **The `A` bit selects `AL` when 0 and `AH` when 1** — the opposite of what the
  operand wording ("accumulator high (AH) or accumulator low (AL)") suggests.
- **Branch displacements are relative to the branching instruction's own
  address**, not the following one. `SB 19,LOS` at word 0x43 targets 0x56.

## Addressing

Program and data addresses in the instruction stream count 16-bit words. Rizin
addresses bytes, and the COFF and ELF loaders scale C2000 objects by two, so the
decoder resolves every embedded address to `2 x word`. This is required, not
cosmetic: `LCR 0x000040` has to land on `_uart_write_text` at vaddr 0x80, and a
`SB` at byte 0x86 has to resolve to the label at 0xac.

TI's `dis2000` prints the raw word address instead, so its output and rizin's
differ numerically here by design.

## RzIL

The move, stack, ALU, shift, compare, bit-test, branch and `SETC`/`CLRC` core is
lifted. Anything else returns NULL and leaves `op->il_op` unset.

- Word addresses are scaled by `C28X_WORD_BYTES` into the byte-addressed IL VM,
  the convention the C2x and C5x lifters use.
- Pointer-modifying addressing modes are not pure expressions. The
  pre-modification runs first and latches the effective address into a local,
  the access reads that local, and the post-modification follows.
- `AH`/`AL`, `PH`/`PL`, `T`/`TL` and `AR0`-`AR7` are halves of `ACC`, `P`, `XT`
  and `XAR0`-`XAR7`. The IL VM binds halves and parents as separate variables,
  so writing one would leave the other stale; the parent is the single source of
  truth and the halves are read and written through it, the way the C2x lifter
  keeps `ACC` authoritative. `MOV ARn,loc16` leaving `ARnH` untouched while
  `MOVZ ARn,loc16` clears it depends on this.

Accumulator arithmetic follows SPRU430F's "Flags and Modes": `V` is sticky,
`OVC` counts overflows while `OVM` is clear, `OVM` instead saturates, and `SXM`
selects sign or zero extension of a `loc16` source.

### Why the memory-destination ALU forms are not lifted

`ADDL loc32,ACC`, `SUBL loc32,ACC` and the `<op> loc16,AX` group write their
result to memory rather than to a register. Their data flow is unambiguous --
`[loc32] = [loc32] + ACC` -- but SPRU430F does not say which operand the flags
are taken from, and contradicts itself where it tries.

`SUBL loc32, ACC` states, in the same "Flags and Modes" table:

- **N** -- set if bit 31 of the **`[loc32]`** is 1
- **Z** -- set if the **`ACC`** value is zero

Those cannot both describe the result. `ADDL loc32,ACC` names `ACC` for both,
which is the wording of the `ADDL ACC,loc32` entry and looks copied. The
carry/borrow line is consistent throughout and is the only part of the group
that can be read off the document with confidence.

TI's own compiler declines to rely on those flags. At `-O2`,
`*p -= x; if (*p < 0)` compiles to:

    SUBL *+XAR4[0], ACC     ; memory-destination op
    MOVL ACC, *+XAR4[0]     ; reload -- MOVL sets N and Z itself
    SB   3, GEQ             ; branch on the reload's flags

Branching directly would save an instruction and a memory access, so the reload
says the compiler does not treat the flags as describing the stored result. The
same shape appears for `ADDL`, and for the 16-bit case the compiler avoids the
memory-destination form altogether, using `XOR AL,loc16` plus a store.

That is evidence, not a specification: it is consistent with the flags following
`ACC` (which these instructions leave unchanged, so they would be useless for
testing the result) but it does not establish it. Lifting either reading would
be a guess, and a wrong one silently mis-drives every conditional that follows,
so these forms return NULL until the behaviour can be checked against silicon or
a simulator.

The documentation search is exhausted rather than merely unfinished: SPRU430F is
the latest revision (SPRU430G and H do not exist), and SPRUHS1, the other C28x
instruction manual, covers only the co-processor units -- FPU, FPU64, VCU,
VCU-II, FINTDIV and TMU -- so it does not re-document the base set.

TI's hand-written runtime avoids the forms altogether: across the 91 `.asm`
files the C2000 CGT ships as runtime source, `ADDL` and `SUBL` appear only as
`ADDL ACC,<src>`, and the only memory-destination writes are `MOVL`, `MOV32`
and `MOV`. So nothing in TI's own toolchain -- compiler or runtime -- depends on
these flags, which is consistent with the manual being unreliable about them.

Vendor firmware agrees. Across four PIP inverter DSP images (rizinorg/ideas#27),
scanned from `ADDB SP,#imm` prologue anchors so the disassembly stays aligned,
**5616 memory-destination ALU instructions occur and not one of them has its
flags consumed** by a conditional branch before something else sets them.

So three independent bodies of C28x code -- TI's compiler, TI's hand-written
runtime, and shipping third-party firmware -- all decline to use these flags.
That still does not say what the flags contain, but nothing observable depends
on it. The practical cost of leaving these forms unlifted is correspondingly
low: what is lost is the store's data flow, not a branch condition.

## Verification

`test/db/asm/tms320_c28x_32` holds the vectors; 26 of them also assert lifted
RzIL. Every vector was cross-checked against TI `dis2000` (c2000 v25.11.1.LTS) before
being written down, and the lifted semantics were checked by stepping the IL VM
against hand-computed values.

The decoder as a whole was measured by sweeping all 65536 opcode words through
`dis2000` and diffing, ignoring the renderings where rizin deliberately differs:
hex immediates, `@` on register-direct operands, resolved branch targets, and
the word-to-byte scaling of program and data addresses, which is the same x2 the
loader applies to `sh_addr` and `st_value`.

**99.6%** agree. Of the 877 that do not, 782 are the VCU co-processor set, which
is a separate instruction set rather than a gap in this one; excluding it the
figure is **99.9%**, leaving 95 words. Those are mostly spellings dis2000
prefers -- it writes `MOVL *SP++,ACC` where this engine writes `PUSH ACC`, and
`SETC INTM` where it writes `DINT` -- plus the `0xad` loc32 encoding, which has
no 32-bit register meaning and which dis2000 also declines to name.

## Not covered

- FPU32 (SPRUEO2) decodes in TI's tools but is out of scope here; it belongs
  behind its own cpu variant.
- Pseudo syntax covers the two-operand accumulator and memory forms; the
  multiply, repeat and co-processor groups still render as `asm("...")`.
- IL for the memory-destination ALU forms; see above.
- In `emulateme_nostd.ccsv7.c28x.eabi.*`, `.stack` (NOBITS, vaddr 0, memsz
  0x800) covers `.text` (vaddr 0x80), so mapped reads there return zeros until
  the zero-fill map is dropped (`om- <id>`).

  This was previously described here as the Harvard-architecture problem. That
  was wrong: SPRU430F lists a **unified memory map** among the C28x
  enhancements, and its blocks are "mapped to both program and data space",
  so there is no separate program space to model. The overlap is this test
  binary's link -- it places code at word 0x40 and the stack across all of M0
  RAM at 0x0-0x3ff -- not an architectural property. A firmware image with a
  realistic map (code in flash at 0x3d8000, stack in RAM) does not overlap.

  What remains is a general rizin question rather than a C28x one: a zero-fill
  NOBITS map is given priority over the file-backed map covering the same
  addresses. Whichever way that is resolved belongs in the loader, not here.

## Word and byte units in C2000 ELF

TI's C2000 ELF mixes units, and rizin currently reads all of them as bytes.
Measured against objects from ti-cgt-c2000 25.11.1.LTS, linked at a known
address:

| field | unit | evidence |
|---|---|---|
| `sh_addr` | **word** address | `.text` linked at the `0x3F0000` PROG origin |
| `st_value` | **word** address | `start` = `0x3F0000`, matching `sh_addr` |
| `r_offset` | **word** index | `.text` is 13 words; offsets run 0x01-0x0c |
| `sh_size` | **byte** count | `0x1a` = 26 bytes for those 13 words |

So addresses and relocation offsets need scaling by two on load while sizes do
not -- exactly what `rz_coff_addr_scale()` already does for the COFF path, where
it is applied at the eight sites that consume an address.

The loader scales those four fields on read, so symbols, sections and
relocations all resolve correctly and relocation patching works.

Scaling does **not** fix the map shadowing noted above: the C28x has distinct
program and data spaces while rizin has one flat one, so a data section at
address 0 still covers program text whatever the scale. That is a separate
problem.
- A data-space section mapped at address 0 shadows the program text in rizin's
  single flat address space, so mapped disassembly reads zeros until the
  offending map is dropped (`om- <id>`). This is the Harvard-architecture
  problem and is not specific to C28x.

### VCU verification

The dis2000 sweep holds the parameter word at a constant, so any operand field
living there is unexercised by it -- which is how several rows came to be fitted
from too little data. The assembler closes that: `asm2000 -v28
--vcu_support=vcu2` was given every `VMOVZI`/`VMOVXI`/`VMOVIX` over eight
registers and six immediates including 0x0000, 0x8000 and 0xffff, and the
encodings read back and compared. **168 of 168 agree.**

That pins the split immediate with real values rather than the sweep's filler:
`VMOVZI VR3, #0x1234` assembles to `e7f1 2343`, so the top nibble sits in the
opcode word and the low twelve plus the register in the parameter word.

Two limits the assembler shows and the sweep does not. `VCFLIP VR8`, `VCCON VR8`
and `VBITFLIP VR8` are rejected -- the assembler accepts VR0-VR7 -- while
dis2000 disassembles `a108` as `VCFLIP VR8`. Register 8 is therefore decodable
but not assemblable, and this engine follows dis2000 because disassembly is what
it does. `VITDLADDSUB` also rejects operands other than its fixed VR4, VR3, VR2
triple.

`VGFMAC4` was added the same way: the assembler puts its three registers in the
parameter word at bits 6, 3 and 0, three bits each, with a fixed opcode word --
fitted from the full 8x8 matrix and agreeing 64 of 64. The sweep contains a
*different* one-word encoding of that mnemonic, which is still undecoded, so the
two oracles are not interchangeable: the sweep covers opcode-word forms the
assembler was not asked for, and the assembler reaches parameter-word fields the
sweep holds constant. Both are worth running.

The assembler caught one mistake the sweep could not. `VGFMAC4` and `VGFMPY4`
share an opcode word and differ only in bit 9 of the *parameter* word, so a row
masking the opcode word alone claims both, and `VGFMPY4` disassembled as
`VGFMAC4`. The sweep holds that word constant and can never show it. The mask
now reaches bits 9 to 15 of the parameter word and the two are separate rows.

`VGFACC` came from the same probe and shows why the round-trip has to be run
rather than trusted: its first two registers sit at bits 3 and 0 with the third
fixed at VR7, and a first attempt placed them at 6, 3 and 0 by analogy with
`VGFMAC4`. That agreed with nothing -- 0 of 64 -- and the correct placement
agrees with all 64.

`VDEC` names the low half of a register, spelled `VR7L`, which needed an operand
kind of its own -- the assembler rejects the `H` spelling, so only the low half
exists.

`VCADD`, `VCMAC` and `VCCMAC` take no operand combination other than the one
they are written with -- the assembler rejects every substitution -- so they are
single encodings with fixed registers rather than rows with fields. Assembling
them consecutively also fails with a pipeline write-read conflict, which is why
the probe separates them with NOPs.

`VITBM2` was the last row still reading a register as a field. The assembler
rejects any first operand but VR0, so it is fixed; read as a field, its low
nibble looked like a reserved register number and the operand vanished from the
output. `VITBM3` is fixed the same way.

Five round-trip scripts are kept beside this engine and all agree completely:
168/168 (immediates), 64/64 (`VGFMAC4`), 72/72 (`VGFACC` and `VDEC`), 9/9 (the
fixed-operand three) and 11/11 (canonical forms) -- 324 encodings in total. Any
VCU row added later should extend one of them, because the sweep this table is
generated from cannot see the parameter word.
