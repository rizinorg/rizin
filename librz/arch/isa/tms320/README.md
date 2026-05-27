# TMS320 architectures

Rizin's `tms320` arch plugin covers three Texas Instruments DSP
families, selected by `analysis.cpu` / `asm.cpu`:

| cpu     | family             | word | endian | typical parts                                 |
|---------|--------------------|------|--------|-----------------------------------------------|
| `c55x`  | TMS320C55x         |  16  | LE     | C5501, C5502, C5503, C5507, C5509, C5510       |
| `c55x+` | TMS320C55x+        |  16  | LE     | C5504, C5505, C5514, C5515, C5517, C5535, C5545|
| `c64x`  | TMS320C6000 / C64x |  32  | LE     | C6201..C6748, C6655, KeyStone-II               |

## c64x

VLIW 32-bit DSP. Independent disassembler under `c64x/` based on the
Capstone backend. Fixed 32-bit instruction width packed into execute
packets.

## c55x

Variable-length (1-7 byte) instructions, little-endian, 16-bit word.
Documented in TI **SPRU374** (*TMS320C55x DSP Mnemonic Instruction
Set Reference Guide*, public). Bit 0 of the leading opcode byte is
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
   the Wrigley3G DSP baseband used in the Motorola Droid A855
   (firmware partition CG45.img, validated against version
   MSG39UPEU_A1.19_1.80 dated 2010-02-05).
   Several opcode slots differ from baseline c55x -- most notably
   `0x21 = RET` (vs `|| nop` in baseline). The instruction stream is
   not byte-compatible with the modern c55x+ in slot 2, but a
   sizeable subset agrees.

Rizin's `c55x+` plugin handles both: the byte-driven analyzer
classifies the opcodes that overlap between the two, and the
disassembler covers SWPU086/104 encodings used by the Wrigley3G
silicon. SWPU086/104 are not redistributed in this tree.

## Selecting a cpu

```
rizin -a tms320 -e analysis.cpu=c55x   FILE.coff   # baseline C55x
rizin -a tms320 -e analysis.cpu=c55x+  FILE.coff   # c55x+ (Ryujin / SWPU104)
rizin -a tms320 -e analysis.cpu=c64x   FILE.elf    # VLIW C64x
```

The COFF loader autodetects `c55x` (TI COFF v2 target_id 0x009c)
and `c55x+` (target_id 0x00a1) from the file header.

## References

- TI SPRU374 -- TMS320C55x DSP Mnemonic Instruction Set Reference
  Guide (public)
- TI SPRU430 -- TMS320C6000 CPU and Instruction Set Reference Guide
  (public; covers c64x)
- TI SWPU086 -- TMS320C55x 'C55x+' CPU Reference Guide, Preliminary,
  May 2005
- TI SWPU104 -- TMS320C55x+ DSP Algebraic Instruction Set Reference
  Guide, December 2006
