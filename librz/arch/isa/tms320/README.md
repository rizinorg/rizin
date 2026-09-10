# TMS320 architectures

Rizin's `tms320` arch plugin covers four Texas Instruments DSP
families, selected by `analysis.cpu` / `asm.cpu`:

| cpu                                     | family      | word | endian | typical parts                                   |
|-----------------------------------------|-------------|------|--------|-------------------------------------------------|
| `c55x`                                  | TMS320C55x  | 16   | LE     | C5501, C5502, C5503, C5507, C5509, C5510        |
| `c55x+`                                 | TMS320C55x+ | 16   | LE     | C5504, C5505, C5514, C5515, C5517, C5535, C5545 |
| `c62x`, `c64x`, `c67x`, `c674x`, `c66x` | TMS320C6000 | 32   | LE/BE  | C6201..C6748, C6655, KeyStone-II                |
| `c28x`                                  | TMS320C28x  | 16   | LE     | C280x, C281x, C2833x, F2806x, F2837x, F2838x    |

## c6x

VLIW, with a fixed 32-bit instruction word. Instructions issue in execute
packets: bit 0 of each word, the p-bit, chains it to the next instruction in the
same cycle, and eight words form a fetch packet. From C64x+ on, a fetch packet
may also hold compact 16-bit instructions. Its eighth word is then a header,
whose layout field says which words hold two of them. Documented per generation
in TI **SPRU733** (C67x/C67x+), **SPRU732** (C64x/C64x+), **SPRUFE8** (C674x,
the superset of C64x+ and C67x+) and **SPRUGH7** (C66x).

Native engine under `c6x/`. One decoder serves every cpu, driven by a single
instruction table and a per-generation feature gate, as the C55 engine serves
C54x, C55x and C55x+. Analysis reconstructs execute packets, and the scalar
move, ALU, shift, multiply, load and store core is lifted to RzIL.

A whole execute packet is lifted on its first instruction. Every slot reads the
register file as it stood when the packet issued, through snapshot variables,
and all the writes land together. A parallel swap such as `mv a0,a1 || mv a1,a0`
is therefore exact. A branch is lifted together with the packets in its delay
slots. A load or multiply result read before it lands is written only once the
packets in between have run. `test/db/rzil/tms320` covers each case.

## c28x

Fixed-point control core of the C2000 line. An instruction is one 16-bit word,
optionally followed by a second holding an immediate, a branch displacement or
another operand field. Most opcodes spend their low byte on `loc16`/`loc32`, the
8-bit addressing-mode selector shared by nearly the whole instruction set.
Documented in TI **SPRU430** (*TMS320C28x CPU and Instruction Set Reference
Guide*), with `RPTB` in **SPRUEO2**, the calling convention in
**SPRU514** and the ELF relocations in **SPRAC71**.

Two encodings come from TI's tools, not the manual. The `A` bit selects `AL`
when clear and `AH` when set, the reverse of what the operand wording suggests.
A branch displacement counts from the branch itself, not from the next
instruction.

Program and data addresses count 16-bit words, while Rizin addresses bytes. The
COFF and ELF loaders therefore scale C2000 addresses by two, and the decoder
resolves embedded addresses the same way. TI's `dis2000` prints word addresses,
so its numbers differ from Rizin's by design. In C2000 ELF, `sh_addr`,
`st_value` and `r_offset` count words while `sh_size` counts bytes.

Native engine under `c28x/`, decoding from a mask/match table generated against
TI's `dis2000`: of the 62518 opcode words `dis2000` decodes as instructions, it
agrees on 61641 (98.6%). 782 of the rest are the VCU co-processor set; most of
the others are spellings `dis2000` prefers, such as `MOVL *SP++,ACC` where this
engine writes `PUSH ACC`.

## c55x

Variable-length (1-7 byte) instructions, little-endian, 16-bit word.
Documented in TI **SPRU374** (*TMS320C55x DSP Mnemonic Instruction
Set Reference Guide*). Bit 0 of the leading opcode byte is
the parallel-execution marker: `02 04 05` is `RETCC T0 == 0`, the
sibling encoding `03 04 05` is `|| RETCC T0 == 0`. Same instruction,
same operands, executed in parallel with the previous one.

## c55x+

Two distinct things share this name:

1. **TI's `c55x+` core (publicly documented)** -- the "C55x DSP
   Core+", a forward-compatible extension shipped in the Low-Power
   C55x family (C5504, C5505, C5514, C5515, C5517, C5535, C5545).
   Every baseline c55x instruction still decodes the same way; c55x+
   adds new instructions in previously-unused opcode slots.

2. **The pre-release c55x+ used in TI silicon ca. 2005-2010** --
   documented in *SWPU086* (CPU Reference Guide, May 2005)
   and *SWPU104* (Algebraic Instruction Set, Dec 2006). Original name
   internally was "Ryujin"; appears in production silicon including
   a TMS320C55x+ DSP baseband (as used in some Motorola basebands)
   (firmware partition CG45.img, validated against version
   MSG39UPEU_A1.19_1.80 dated 2010-02-05).
   Several opcode slots differ from baseline c55x -- most notably
   `0x21 = RET` (vs `|| nop` in baseline). The instruction stream is
   not byte-compatible with the modern c55x+ in slot 2, but a
   sizeable subset agrees.

Rizin's `c55x+` plugin handles both: the byte-driven analyzer
classifies the opcodes that overlap between the two, and the
disassembler covers SWPU086/104 encodings used by such
silicon. SWPU086/104 are not redistributed in this tree.

## Selecting a cpu

```
rizin -a tms320 -e analysis.cpu=c55x   FILE.coff   # baseline C55x
rizin -a tms320 -e analysis.cpu=c55x+  FILE.coff   # c55x+ (Ryujin / SWPU104)
rizin -a tms320 -e analysis.cpu=c64x   FILE.elf    # C6000; cpus in the table
rizin -a tms320 -e analysis.cpu=c28x   FILE.out    # C28x (C2000)
```

The COFF loader autodetects `c55x` (TI COFF v2 target_id 0x009c)
and `c55x+` (target_id 0x00a1) from the file header. C2000 objects load
as `c28x`, from COFF and from ELF with `e_machine` set to `EM_TI_C2000`.

## References

- TI [SPRU374G][spru374g] -- TMS320C55x DSP Mnemonic Instruction Set Reference
  Guide
- TI [SPRU732J][spru732j] -- TMS320C64x/C64x+ DSP CPU and Instruction Set
  Reference Guide
- TI [SPRU733A][spru733a] -- TMS320C67x/C67x+ DSP CPU and Instruction Set
  Reference Guide
- TI [SPRUFE8B][sprufe8b] -- TMS320C674x DSP CPU and Instruction Set Reference
  Guide
- TI [SPRUGH7][sprugh7] -- TMS320C66x DSP CPU and Instruction Set Reference
  Guide
- TI [SPRU430F][spru430f] -- TMS320C28x CPU and Instruction Set Reference
  Guide
- TI [SPRUEO2B][sprueo2b] -- TMS320C28x Floating Point Unit and Instruction Set
  Reference Guide (`RPTB`)
- TI [SPRU514AA][spru514aa] -- TMS320C28x Optimizing C/C++ Compiler User's
  Guide (calling convention)
- TI [SPRAC71C][sprac71c] -- C28x Embedded Application Binary Interface (DWARF
  register numbers and ELF relocations)
- TI SWPU086 -- TMS320C55x 'C55x+' CPU Reference Guide, Preliminary,
  May 2005
- TI SWPU104 -- TMS320C55x+ DSP Algebraic Instruction Set Reference
  Guide, December 2006

[spru374g]: https://web.archive.org/web/20250824113133/https://www.ti.com/lit/ug/spru374g/spru374g.pdf
[spru732j]: https://web.archive.org/web/20260908034433/https://www.ti.com/lit/ug/spru732j/spru732j.pdf
[spru733a]: https://web.archive.org/web/20260427195239/https://www.ti.com/lit/ug/spru733a/spru733a.pdf
[sprufe8b]: https://web.archive.org/web/20250910061354/https://www.ti.com/lit/ug/sprufe8b/sprufe8b.pdf
[sprugh7]: https://web.archive.org/web/20260209140719/https://www.ti.com/lit/ug/sprugh7/sprugh7.pdf
[spru430f]: https://web.archive.org/web/20251017052437/https://www.ti.com/lit/ug/spru430f/spru430f.pdf
[sprueo2b]: https://web.archive.org/web/20240513043003/https://www.ti.com/lit/ug/sprueo2b/sprueo2b.pdf
[spru514aa]: https://web.archive.org/web/20261006050208/https://www.ti.com/lit/ug/spru514aa/spru514aa.pdf
[sprac71c]: https://web.archive.org/web/20261006050055/https://www.ti.com/lit/an/sprac71c/sprac71c.pdf
