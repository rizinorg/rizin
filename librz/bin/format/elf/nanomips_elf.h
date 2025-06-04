// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef ELF_NANOMIPS_RELOCS_H
#define ELF_NANOMIPS_RELOCS_H

// https://github.com/MIPS/toolchain_docs/blob/master/topics/c_abi_reloc_type.md

#define R_NANOMIPS_NONE              (0)
#define R_NANOMIPS_32                (1) /// S + A
#define R_NANOMIPS_64                (2) /// S + A
#define R_NANOMIPS_NEG               (3) /// -S + A
#define R_NANOMIPS_ASHIFTR_1         (4) /// sign_extend ((S + A) >> 1)
#define R_NANOMIPS_UNSIGNED_8        (5) /// S + A
#define R_NANOMIPS_SIGNED_8          (6) /// S + A
#define R_NANOMIPS_UNSIGNED_16       (7) /// S + A
#define R_NANOMIPS_SIGNED_16         (8) /// S + A
#define R_NANOMIPS_RELATIVE          (9) /// S + A
#define R_NANOMIPS_GLOBAL            (10) /// S + A
#define R_NANOMIPS_JUMP_SLOT         (11) /// lazy_stub (S)
#define R_NANOMIPS_IRELATIVE         (12) /// ifunc_resolver (S)
#define R_NANOMIPS_PC25_S1           (13) /// offset = (S + A - (P + 4)) is_signed_value (offset, nbits = 26) is_aligned(offset, 2)
#define R_NANOMIPS_PC21_S1           (14) /// offset = (S + A - (P + 4)) is_signed_value (offset, nbits = 22)  is_aligned(offset, 2)
#define R_NANOMIPS_PC14_S1           (15) /// offset = (S + A - (P + 4)) is_signed_value (offset, nbits = 15) is_aligned(offset, 2)
#define R_NANOMIPS_PC11_S1           (16) /// offset = (S + A - (P + 4)) is_signed_value (offset, nbits = 12) is_aligned(offset, 2)
#define R_NANOMIPS_PC10_S1           (17) /// offset = (S + A - (P + 2)) is_signed_value (offset, nbits = 11) is_aligned(offset, 2)
#define R_NANOMIPS_PC7_S1            (18) /// offset = (S + A - (P + 2)) is_signed_value (offset, nbits = 8) is_aligned(offset, 2)
#define R_NANOMIPS_PC4_S1            (19) /// offset = (S + A - (P + 2)) is_unsigned_value (offset, nbits = 5) is_aligned(offset, 2)
#define R_NANOMIPS_GPREL19_S2        (20) /// offset = (S + A - G) is_unsigned_value (offset, nbits = 21) is_aligned(offset, 4)
#define R_NANOMIPS_GPREL18_S3        (21) /// offset = (S + A - G)  is_unsigned_value (offset, nbits = 22) is_aligned(offset, 8)
#define R_NANOMIPS_GPREL18           (22) /// offset = (S + A - G) is_unsigned_value (offset, nbits = 18)
#define R_NANOMIPS_GPREL17_S1        (23) /// offset = (S + A - G) is_unsigned_value (offset, nbits = 18) is_aligned(offset, 2)
#define R_NANOMIPS_GPREL16_S2        (24) /// offset = (S + A - G) is_unsigned_value (offset, nbits = 18) is_aligned(offset, 4)
#define R_NANOMIPS_GPREL7_S2         (25) /// offset = (S + A - G) is_unsigned_value (offset, nbits = 9) is_aligned(offset, 4)
#define R_NANOMIPS_GPREL_HI20        (26) /// offset = (S + A - G)
#define R_NANOMIPS_PC_HI20           (27) /// offset = (S + A) - ((P + 4) & ~0xfff)
#define R_NANOMIPS_HI20              (28) /// offset = S + A
#define R_NANOMIPS_LO12              (29) /// offset = S + A
#define R_NANOMIPS_GPREL_I32         (30) /// offset = (S + A - G)
#define R_NANOMIPS_PC_I32            (31) /// offset = (S + A) - (P + 4) is_signed_value (offset, nbits = 32)
#define R_NANOMIPS_I32               (32) /// address = S + A, is_signed_value (address, nbits = 32)
#define R_NANOMIPS_GOT_DISP          (33) /// offset = (GOT(S + A) - G) is_unsigned_value (offset, nbits = 21) is_aligned(offset, 4)
#define R_NANOMIPS_GOTPC_I32         (34) /// offset = (GOT(S + A) - (P + 4)) is_signed_value (offset, nbits = 32)
#define R_NANOMIPS_GOTPC_HI20        (35) /// offset = GOT(S + A) - ((P + 4) & ~0xfff)
#define R_NANOMIPS_GOT_LO12          (36) /// offset = GOT(S + A)
#define R_NANOMIPS_GOT_CALL          (37) /// offset = (GOT(S + A) - G) is_unsigned_value (offset, nbits = 21) is_aligned(offset, 4)
#define R_NANOMIPS_GOT_PAGE          (38) /// expand to got slot for S + A
#define R_NANOMIPS_GOT_OFST          (39) /// expand to got slot for S + A
#define R_NANOMIPS_LO4_S2            (40) /// offset = (S + A)
#define R_NANOMIPS_HI32              (41) /// offset = (S + A)
#define R_NANOMIPS_GPREL_LO12        (42) /// offset = (S + A - G)
#define R_NANOMIPS_COPY              (44) /// copy_data (S)
#define R_NANOMIPS_ALIGN             (64) /// alignment
#define R_NANOMIPS_FILL              (65) /// fill-value
#define R_NANOMIPS_MAX               (66) /// max-fill
#define R_NANOMIPS_INSN32            (67) /// none
#define R_NANOMIPS_FIXED             (68) /// none
#define R_NANOMIPS_NORELAX           (69) /// none
#define R_NANOMIPS_RELAX             (70) /// none
#define R_NANOMIPS_SAVERESTORE       (71) /// function symbol
#define R_NANOMIPS_INSN16            (72) /// none
#define R_NANOMIPS_JALR32            (73) /// none
#define R_NANOMIPS_JALR16            (74) /// none
#define R_NANOMIPS_JUMPTABLE_LOAD    (75) /// jump-table symbol
#define R_NANOMIPS_TLS_DTPMOD        (80) /// tls_module_number (S)
#define R_NANOMIPS_TLS_DTPREL        (81) /// tls_module_offset (S)
#define R_NANOMIPS_TLS_TPREL         (82) /// tls_static_offset (S)
#define R_NANOMIPS_TLS_GD            (83) /// offset = (GOT_TLS(S + A) - G) is_unsigned_value (offset, nbits = 21) is_aligned(offset, 4)
#define R_NANOMIPS_TLS_GD_I32        (84) /// offset = (GOT_TLS(S + A) - G) is_signed_value (offset, nbits = 32)
#define R_NANOMIPS_TLS_LD            (85) /// offset = (GOT_TLS_MODULE(S) - G) is_unsigned_value (offset, nbits = 21) is_aligned(offset, 4)
#define R_NANOMIPS_TLS_LD_I32        (86) /// offset = (GOT_TLS_MODULE(S) - G) is_signed_value (offset, nbits = 32)
#define R_NANOMIPS_TLS_DTPREL12      (87) /// offset = (S - DTP) is_unsigned_value(offset, nbits = 12)
#define R_NANOMIPS_TLS_DTPREL16      (88) /// offset = (S - DTP) is_unsigned_value(offset, nbits = 16)
#define R_NANOMIPS_TLS_DTPREL_I32    (89) /// offset = (S - DTP) is_signed_value(offset, nbits = 32)
#define R_NANOMIPS_TLS_GOTTPREL      (90) /// offset = (GOT_TLS(S + A) - G) is_unsigned_value (offset, nbits = 21) is_aligned(offset, 4)
#define R_NANOMIPS_TLS_GOTTPREL_PC32 (91) /// offset = (GOT_TLS(S + A) - (P + 4)) is_signed_value(offset, nbits = 32)
#define R_NANOMIPS_TLS_TPREL12       (92) /// offset = (S - TP) is_unsigned_value(offset, nbits = 12)
#define R_NANOMIPS_TLS_TPREL16       (93) /// offset = (S - TP) is_unsigned_value(offset, nbits = 16)
#define R_NANOMIPS_TLS_TPREL_I32     (94) /// offset = (S - TP) is_signed_value(offset, nbits = 32)

#endif /* ELF_NANOMIPS_RELOCS_H */
