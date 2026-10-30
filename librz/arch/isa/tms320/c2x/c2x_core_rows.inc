// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

// clang-format off
	// TMS320C2x core instruction rows (shared with the C5x superset)
	// top-nibble arithmetic with 4-bit shift: ADD / SUB / LAC
	{ OP(0xf080, 0x0000), .id = C2X_INS_ADD, .len = 2, .ops = { MEM(0), SHF(8, 4) } },
	{ OP(0xf080, 0x0080), .id = C2X_INS_ADD, .len = 2, .ops = { MEM(0), SHF(8, 4), NARP(0) } },
	{ OP(0xf080, 0x1000), .id = C2X_INS_SUB, .len = 2, .ops = { MEM(0), SHF(8, 4) } },
	{ OP(0xf080, 0x1080), .id = C2X_INS_SUB, .len = 2, .ops = { MEM(0), SHF(8, 4), NARP(0) } },
	{ OP(0xf080, 0x2000), .id = C2X_INS_LAC, .len = 2, .ops = { MEM(0), SHF(8, 4) } },
	{ OP(0xf080, 0x2080), .id = C2X_INS_LAC, .len = 2, .ops = { MEM(0), SHF(8, 4), NARP(0) } },

	// LAR / SAR: 5-bit opcode (00110rrr / 01110rrr) + R
	{ OP(0xf880, 0x3000), .id = C2X_INS_LAR, .len = 2, .ops = { AR(8), MEM(0) } },
	{ OP(0xf880, 0x3080), .id = C2X_INS_LAR, .len = 2, .ops = { AR(8), MEM(0), NARP(0) } },
	{ OP(0xf880, 0x7000), .id = C2X_INS_SAR, .len = 2, .ops = { AR(8), MEM(0) } },
	{ OP(0xf880, 0x7080), .id = C2X_INS_SAR, .len = 2, .ops = { AR(8), MEM(0), NARP(0) } },

	// single-byte-opcode memory block 0x38..0x5B: multiply / T-P / logical / move
	MEMOP_D(0x38, C2X_INS_MPY), MEMOP_I(0x38, C2X_INS_MPY),
	MEMOP_D(0x39, C2X_INS_SQRA), MEMOP_I(0x39, C2X_INS_SQRA),
	MEMOP_D(0x3a, C2X_INS_MPYA), MEMOP_I(0x3a, C2X_INS_MPYA),
	MEMOP_D(0x3b, C2X_INS_MPYS), MEMOP_I(0x3b, C2X_INS_MPYS),
	MEMOP_D(0x3c, C2X_INS_LT), MEMOP_I(0x3c, C2X_INS_LT),
	MEMOP_D(0x3d, C2X_INS_LTA), MEMOP_I(0x3d, C2X_INS_LTA),
	MEMOP_D(0x3e, C2X_INS_LTP), MEMOP_I(0x3e, C2X_INS_LTP),
	MEMOP_D(0x3f, C2X_INS_LTD), MEMOP_I(0x3f, C2X_INS_LTD),
	MEMOP_D(0x40, C2X_INS_ZALH), MEMOP_I(0x40, C2X_INS_ZALH),
	MEMOP_D(0x41, C2X_INS_ZALS), MEMOP_I(0x41, C2X_INS_ZALS),
	MEMOP_D(0x42, C2X_INS_LACT), MEMOP_I(0x42, C2X_INS_LACT),
	MEMOP_D(0x43, C2X_INS_ADDC), MEMOP_I(0x43, C2X_INS_ADDC),
	MEMOP_D(0x44, C2X_INS_SUBH), MEMOP_I(0x44, C2X_INS_SUBH),
	MEMOP_D(0x45, C2X_INS_SUBS), MEMOP_I(0x45, C2X_INS_SUBS),
	MEMOP_D(0x46, C2X_INS_SUBT), MEMOP_I(0x46, C2X_INS_SUBT),
	MEMOP_D(0x47, C2X_INS_SUBC), MEMOP_I(0x47, C2X_INS_SUBC),
	MEMOP_D(0x48, C2X_INS_ADDH), MEMOP_I(0x48, C2X_INS_ADDH),
	MEMOP_D(0x49, C2X_INS_ADDS), MEMOP_I(0x49, C2X_INS_ADDS),
	MEMOP_D(0x4a, C2X_INS_ADDT), MEMOP_I(0x4a, C2X_INS_ADDT),
	MEMOP_D(0x4b, C2X_INS_RPT), MEMOP_I(0x4b, C2X_INS_RPT),
	MEMOP_D(0x4c, C2X_INS_XOR), MEMOP_I(0x4c, C2X_INS_XOR),
	MEMOP_D(0x4d, C2X_INS_OR), MEMOP_I(0x4d, C2X_INS_OR),
	MEMOP_D(0x4e, C2X_INS_AND), MEMOP_I(0x4e, C2X_INS_AND),
	MEMOP_D(0x4f, C2X_INS_SUBB), MEMOP_I(0x4f, C2X_INS_SUBB),
	MEMOP_D(0x50, C2X_INS_LST), MEMOP_I(0x50, C2X_INS_LST),
	MEMOP_D(0x51, C2X_INS_LST1), MEMOP_I(0x51, C2X_INS_LST1),
	MEMOP_D(0x52, C2X_INS_LDP), MEMOP_I(0x52, C2X_INS_LDP),
	MEMOP_D(0x53, C2X_INS_LPH), MEMOP_I(0x53, C2X_INS_LPH),
	MEMOP_D(0x54, C2X_INS_PSHD), MEMOP_I(0x54, C2X_INS_PSHD),
	MEMOP_D(0x56, C2X_INS_DMOV), MEMOP_I(0x56, C2X_INS_DMOV),
	MEMOP_D(0x57, C2X_INS_BITT), MEMOP_I(0x57, C2X_INS_BITT),
	MEMOP_D(0x58, C2X_INS_TBLR), MEMOP_I(0x58, C2X_INS_TBLR),
	MEMOP_D(0x59, C2X_INS_TBLW), MEMOP_I(0x59, C2X_INS_TBLW),
	MEMOP_D(0x5a, C2X_INS_SQRS), MEMOP_I(0x5a, C2X_INS_SQRS),
	MEMOP_D(0x5b, C2X_INS_LTS), MEMOP_I(0x5b, C2X_INS_LTS),

	// 0x5C/0x5D: multiply-accumulate with program memory (2-word, %B = pma)
	PMAOP_D(0x5c, C2X_INS_MACD), PMAOP_I(0x5c, C2X_INS_MACD),
	PMAOP_D(0x5d, C2X_INS_MAC), PMAOP_I(0x5d, C2X_INS_MAC),

	// store accumulator low/high with 3-bit shift (%S)
	{ OP(0xf880, 0x6000), .id = C2X_INS_SACL, .len = 2, .ops = { MEM(0), SHF(8, 3) } },
	{ OP(0xf880, 0x6080), .id = C2X_INS_SACL, .len = 2, .ops = { MEM(0), SHF(8, 3), NARP(0) } },
	{ OP(0xf880, 0x6800), .id = C2X_INS_SACH, .len = 2, .ops = { MEM(0), SHF(8, 3) } },
	{ OP(0xf880, 0x6880), .id = C2X_INS_SACH, .len = 2, .ops = { MEM(0), SHF(8, 3), NARP(0) } },

	// 0x78..0x7D single-byte-opcode block: store status / stack
	MEMOP_D(0x78, C2X_INS_SST), MEMOP_I(0x78, C2X_INS_SST),
	MEMOP_D(0x79, C2X_INS_SST1), MEMOP_I(0x79, C2X_INS_SST1),
	MEMOP_D(0x7a, C2X_INS_POPD), MEMOP_I(0x7a, C2X_INS_POPD),
	MEMOP_D(0x7b, C2X_INS_ZALR), MEMOP_I(0x7b, C2X_INS_ZALR),
	MEMOP_D(0x7c, C2X_INS_SPL), MEMOP_I(0x7c, C2X_INS_SPL),
	MEMOP_D(0x7d, C2X_INS_SPH), MEMOP_I(0x7d, C2X_INS_SPH),

	// ADRK / SBRK: add/subtract short immediate (full low byte) to/from AR(ARP)
	{ OP(0xff00, 0x7e00), .id = C2X_INS_ADRK, .len = 2, .ops = { IMM(0, 8, 0) } },
	{ OP(0xff00, 0x7f00), .id = C2X_INS_SBRK, .len = 2, .ops = { IMM(0, 8, 0) } },

	// IN / OUT: 4-bit port (%P) in bits 11-8
	{ OP(0xf080, 0x8000), .id = C2X_INS_IN, .len = 2, .ops = { MEM(0), IMM(8, 4, 0) } },
	{ OP(0xf080, 0x8080), .id = C2X_INS_IN, .len = 2, .ops = { MEM(0), IMM(8, 4, 0), NARP(0) } },
	{ OP(0xf080, 0xe000), .id = C2X_INS_OUT, .len = 2, .ops = { MEM(0), IMM(8, 4, 0) } },
	{ OP(0xf080, 0xe080), .id = C2X_INS_OUT, .len = 2, .ops = { MEM(0), IMM(8, 4, 0), NARP(0) } },

	// BIT: 4-bit bit-code (%T) in bits 11-8
	{ OP(0xf080, 0x9000), .id = C2X_INS_BIT, .len = 2, .ops = { MEM(0), SHF(8, 4) } },
	{ OP(0xf080, 0x9080), .id = C2X_INS_BIT, .len = 2, .ops = { MEM(0), SHF(8, 4), NARP(0) } },

	// immediate-operand instructions
	{ OP(0xe000, 0xa000), .id = C2X_INS_MPYK, .len = 2, .ops = { IMM(0, 13, 1) } },
	{ OP(0xf800, 0xc000), .id = C2X_INS_LARK, .len = 2, .ops = { AR(8), IMM(0, 8, 0) } },
	{ OP(0xfe00, 0xc800), .id = C2X_INS_LDPK, .len = 2, .ops = { IMM(0, 9, 0) } },
	{ FIX(0xca00, C2X_INS_ZAC) }, // LACK #0 == ZAC (specific row before the range)
	{ OP(0xff00, 0xca00), .id = C2X_INS_LACK, .len = 2, .ops = { IMM(0, 8, 0) } },
	{ OP(0xff00, 0xcb00), .id = C2X_INS_RPTK, .len = 2, .ops = { IMM(0, 8, 0) } },
	// NORM is CEx2 with the indirect AR-modify field in bits 6:4 (always indirect).
	{ OP(0xff8f, 0xce82), .id = C2X_INS_NORM, .len = 2, .ops = { MEM(0) } },
	{ OP(0xff00, 0xcc00), .id = C2X_INS_ADDK, .len = 2, .ops = { IMM(0, 8, 0) } },
	{ OP(0xff00, 0xcd00), .id = C2X_INS_SUBK, .len = 2, .ops = { IMM(0, 8, 0) } },

	// 0xCF is MPYU (multiply unsigned). The MAME *disassembler* table mislabels
	// it as a second "mpys", but the MAME execution table (and the TI ISA) run
	// MPYU here; we follow the architecturally-correct mnemonic.
	MEMOP_D(0xcf, C2X_INS_MPYU), MEMOP_I(0xcf, C2X_INS_MPYU),

	// CE block: no-operand status / mode / control
	{ FIX(0xce00, C2X_INS_EINT) }, { FIX(0xce01, C2X_INS_DINT) },
	{ FIX(0xce02, C2X_INS_ROVM) }, { FIX(0xce03, C2X_INS_SOVM) },
	{ FIX(0xce04, C2X_INS_CNFD) }, { FIX(0xce05, C2X_INS_CNFP) },
	{ FIX(0xce06, C2X_INS_RSXM) }, { FIX(0xce07, C2X_INS_SSXM) },
	{ OP(0xfffc, 0xce08), .id = C2X_INS_SPM, .len = 2, .ops = { IMM(0, 2, 0) } },
	{ FIX(0xce0c, C2X_INS_RXF) }, { FIX(0xce0d, C2X_INS_SXF) },
	{ FIX(0xce14, C2X_INS_PAC) }, { FIX(0xce15, C2X_INS_APAC) }, { FIX(0xce16, C2X_INS_SPAC) },
	{ FIX(0xce18, C2X_INS_SFL) }, { FIX(0xce19, C2X_INS_SFR) },
	{ FIX(0xce1b, C2X_INS_ABS) }, { FIX(0xce1c, C2X_INS_PUSH) }, { FIX(0xce1d, C2X_INS_POP) },
	{ FIX(0xce1e, C2X_INS_TRAP) }, { FIX(0xce1f, C2X_INS_IDLE) },
	{ FIX(0xce20, C2X_INS_RTXM) }, { FIX(0xce21, C2X_INS_STXM) },
	{ FIX(0xce23, C2X_INS_NEG) }, { FIX(0xce24, C2X_INS_CALA) }, { FIX(0xce25, C2X_INS_BACC) },
	{ FIX(0xce26, C2X_INS_RET) }, { FIX(0xce27, C2X_INS_CMPL) },
	{ FIX(0xce30, C2X_INS_RC) }, { FIX(0xce31, C2X_INS_SC) },
	{ FIX(0xce32, C2X_INS_RTC) }, { FIX(0xce33, C2X_INS_STC) },
	{ FIX(0xce34, C2X_INS_ROL) }, { FIX(0xce35, C2X_INS_ROR) },
	{ FIX(0xce36, C2X_INS_RFSM) }, { FIX(0xce37, C2X_INS_SFSM) },
	{ FIX(0xce38, C2X_INS_RHM) }, { FIX(0xce39, C2X_INS_SHM) },
	// CONF K (TMS320C26): two low bits select the RAM block configuration (ST1.CNF)
	{ OP(0xfffc, 0xce3c), .id = C2X_INS_CONF, .len = 2, .ops = { IMM(0, 2, 0) } },
	{ OP(0xfffc, 0xce50), .id = C2X_INS_CMPR, .len = 2, .ops = { IMM(0, 2, 0) } },

	// D block: long-immediate (opcode word + 16-bit data word)
	{ OP(0xf8ff, 0xd000), .id = C2X_INS_LRLK, .len = 4, .ops = { AR(24), IMM(0, 16, 0) } },
	{ OP(0xf0ff, 0xd001), .id = C2X_INS_LALK, .len = 4, .ops = { IMM(0, 16, 0), SHF(24, 4) } },
	{ OP(0xf0ff, 0xd002), .id = C2X_INS_ADLK, .len = 4, .ops = { IMM(0, 16, 0), SHF(24, 4) } },
	{ OP(0xf0ff, 0xd003), .id = C2X_INS_SBLK, .len = 4, .ops = { IMM(0, 16, 0), SHF(24, 4) } },
	{ OP(0xf0ff, 0xd004), .id = C2X_INS_ANDK, .len = 4, .ops = { IMM(0, 16, 0), SHF(24, 4) } },
	{ OP(0xf0ff, 0xd005), .id = C2X_INS_ORK, .len = 4, .ops = { IMM(0, 16, 0), SHF(24, 4) } },
	{ OP(0xf0ff, 0xd006), .id = C2X_INS_XORK, .len = 4, .ops = { IMM(0, 16, 0), SHF(24, 4) } },

	// control transfer (opcode word + 16-bit target word). BC/BNC confirmed at
	// 0x5E/0x5F; the F-block follows the same opcode-byte + bit7 pattern.
	BROP(0x5e, C2X_INS_BC), BROP(0x5f, C2X_INS_BNC),
	BROP(0xf0, C2X_INS_BV), BROP(0xf1, C2X_INS_BGZ), BROP(0xf2, C2X_INS_BLEZ),
	BROP(0xf3, C2X_INS_BLZ), BROP(0xf4, C2X_INS_BGEZ), BROP(0xf5, C2X_INS_BNZ),
	BROP(0xf6, C2X_INS_BZ), BROP(0xf7, C2X_INS_BNV), BROP(0xf8, C2X_INS_BBZ),
	BROP(0xf9, C2X_INS_BBNZ), BROP(0xfa, C2X_INS_BIOZ), BANZOP(0xfb, C2X_INS_BANZ),
	// 0xFC/0xFD: block move from program/data memory (2-word, %B = source addr)
	PMAOP_D(0xfc, C2X_INS_BLKP), PMAOP_I(0xfc, C2X_INS_BLKP),
	PMAOP_D(0xfd, C2X_INS_BLKD), PMAOP_I(0xfd, C2X_INS_BLKD),
	BROP(0xfe, C2X_INS_CALL), BROP(0xff, C2X_INS_B),

	// AR-pointer / nop (specific rows before the general MAR indirect row)
	{ FIX(0x5500, C2X_INS_NOP) },
	{ OP(0xfff8, 0x5588), .id = C2X_INS_LARP, .len = 2, .ops = { IMM(0, 3, 0) } },
	{ OP(0xff80, 0x5580), .id = C2X_INS_MAR, .len = 2, .ops = { MEM(0), NARP(0) } },
	// clang-format on
