// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TMS320_DWARF_REGNUM_TABLE_H
#define RZ_TMS320_DWARF_REGNUM_TABLE_H

/* DWARF register numbering for TMS320 cores, as emitted by TI
 * Code Composer Studio (CCS) v5+ tools.
 *
 * The numbering below covers TMS320C55x and TMS320C55x+ (extended
 * .L/.H/.G sub-register views) as used by the cl55 compiler. The
 * baseline mapping comes from TI's published cgt55 ABI tables; the
 * .H / .G aliases sit at the same DWARF number as the .L view since
 * the compiler always emits the .L name for scalar accesses.
 *
 * The mapping is intentionally conservative -- entries beyond the
 * range CCSv5 actually emits return NULL so the caller surfaces a
 * "dummy" register name rather than confidently picking the wrong
 * one. */

static const char *const map_dwarf_reg_to_tms320_c55x[] = {
	[0] = "ac0",
	[1] = "ac1",
	[2] = "ac2",
	[3] = "ac3",
	[4] = "t0",
	[5] = "t1",
	[6] = "t2",
	[7] = "t3",
	[8] = "ar0",
	[9] = "ar1",
	[10] = "ar2",
	[11] = "ar3",
	[12] = "ar4",
	[13] = "ar5",
	[14] = "ar6",
	[15] = "ar7",
	[16] = "sp",
	[17] = "ssp",
	[18] = "cdp",
	[19] = "bk03",
	[20] = "bk47",
	[21] = "bkc",
	[22] = "dp",
	[23] = "pdp",
	[24] = "csr",
	[25] = "brc0",
	[26] = "brc1",
	[27] = "trn0",
	[28] = "trn1",
	[29] = "rptc",
	[30] = "ier0",
	[31] = "ier1",
	[32] = "ifr0",
	[33] = "ifr1",
	[34] = "dbier0",
	[35] = "dbier1",
	[36] = "ivpd",
	[37] = "ivph",
	[38] = "st0_55",
	[39] = "st1_55",
	[40] = "st2_55",
	[41] = "st3_55",
};

#define TMS320_C55X_REG_MAX (sizeof(map_dwarf_reg_to_tms320_c55x) / sizeof(map_dwarf_reg_to_tms320_c55x[0]))

static inline const char *tms320_c55x_register_name(ut32 reg_num) {
	if (reg_num < TMS320_C55X_REG_MAX) {
		return map_dwarf_reg_to_tms320_c55x[reg_num];
	}
	return NULL;
}

/* DWARF register numbering for TMS320C28x, from SPRAC71C Table 10-1
 * ("C28x Embedded Application Binary Interface", revised March 2026).
 *
 * The 16-bit halves and their 32-bit parents each get their own number, so
 * AR0 and XAR0 are distinct entries rather than aliases. Numbers TI marks
 * reserved for internal use are left NULL so the caller surfaces a dummy name
 * instead of confidently picking the wrong register. */

static const char *const map_dwarf_reg_to_tms320_c28x[] = {
	[0] = "al",
	[1] = "ah",
	[2] = "pl",
	[3] = "ph",
	[4] = "ar0",
	[5] = "xar0",
	[6] = "ar1",
	[7] = "xar1",
	[8] = "ar2",
	[9] = "xar2",
	[10] = "ar3",
	[11] = "xar3",
	[12] = "ar4",
	[13] = "xar4",
	[14] = "ar5",
	[15] = "xar5",
	[16] = "ar6",
	[17] = "xar6",
	[18] = "ar7",
	[19] = "xar7",
	[20] = "sp",
	[21] = "tl",
	[22] = "t",
	[23] = "st0",
	[24] = "st1",
	[25] = "pc",
	[26] = "rpc",
	// 27 reserved for internal use
	[28] = "xar2", // TI lists this as FP, which on C28x is XAR2
	[29] = "dp",
	[30] = "sxm",
	[31] = "pm",
	[32] = "ovm",
	// 33-35 reserved for internal use
	[36] = "ifr",
	[37] = "ier",
	// 38 is EALLOW, reserved for internal use
};

#define TMS320_C28X_REG_MAX (sizeof(map_dwarf_reg_to_tms320_c28x) / sizeof(map_dwarf_reg_to_tms320_c28x[0]))

static inline const char *tms320_c28x_register_name(ut32 reg_num) {
	if (reg_num < TMS320_C28X_REG_MAX) {
		return map_dwarf_reg_to_tms320_c28x[reg_num];
	}
	return NULL;
}

/* DWARF register numbering for TMS320C6000, from SPRAB89B Table 12-1
 * ("C6000 Embedded Application Binary Interface", revised August 2025).
 *
 * Numbers TI marks reserved, and the control registers the C6000 register
 * profile does not model (IN, OUT, ACR, ADR, the floating-point configuration
 * registers, ARP, and the block of undocumented control registers from 100 up)
 * are left NULL so the caller surfaces a dummy name rather than confidently
 * picking the wrong register.
 *
 * SPRAB89B spells number 70 "CST"; the register is the Control Status Register
 * and the profile, like the rest of the C6000 documentation, calls it CSR. */

static const char *const map_dwarf_reg_to_tms320_c6000[] = {
	[0] = "a0",
	[1] = "a1",
	[2] = "a2",
	[3] = "a3",
	[4] = "a4",
	[5] = "a5",
	[6] = "a6",
	[7] = "a7",
	[8] = "a8",
	[9] = "a9",
	[10] = "a10",
	[11] = "a11",
	[12] = "a12",
	[13] = "a13",
	[14] = "a14",
	[15] = "a15",
	[16] = "b0",
	[17] = "b1",
	[18] = "b2",
	[19] = "b3",
	[20] = "b4",
	[21] = "b5",
	[22] = "b6",
	[23] = "b7",
	[24] = "b8",
	[25] = "b9",
	[26] = "b10",
	[27] = "b11",
	[28] = "b12",
	[29] = "b13",
	[30] = "b14",
	[31] = "b15",
	[33] = "pce1",
	[34] = "irp",
	[35] = "ifr",
	[36] = "nrp",
	[37] = "a16",
	[38] = "a17",
	[39] = "a18",
	[40] = "a19",
	[41] = "a20",
	[42] = "a21",
	[43] = "a22",
	[44] = "a23",
	[45] = "a24",
	[46] = "a25",
	[47] = "a26",
	[48] = "a27",
	[49] = "a28",
	[50] = "a29",
	[51] = "a30",
	[52] = "a31",
	[53] = "b16",
	[54] = "b17",
	[55] = "b18",
	[56] = "b19",
	[57] = "b20",
	[58] = "b21",
	[59] = "b22",
	[60] = "b23",
	[61] = "b24",
	[62] = "b25",
	[63] = "b26",
	[64] = "b27",
	[65] = "b28",
	[66] = "b29",
	[67] = "b30",
	[68] = "b31",
	[69] = "amr",
	[70] = "csr",
	[71] = "isr",
	[72] = "icr",
	[73] = "ier",
	[74] = "istp",
	[82] = "gfpgfr",
	[83] = "dier",
	[84] = "rep",
	[85] = "tscl",
	[86] = "tsch",
	[88] = "ilc",
	[89] = "rilc",
	[90] = "dnum",
	[91] = "ssr",
	[92] = "gplya",
	[93] = "gplyb",
	[94] = "tsr",
	[95] = "itsr",
	[96] = "ntsr",
	[97] = "efr",
	[98] = "ecr",
	[99] = "ierr",
};

#define TMS320_C6000_REG_MAX (sizeof(map_dwarf_reg_to_tms320_c6000) / sizeof(map_dwarf_reg_to_tms320_c6000[0]))

static inline const char *tms320_c6000_register_name(ut32 reg_num) {
	if (reg_num < TMS320_C6000_REG_MAX) {
		return map_dwarf_reg_to_tms320_c6000[reg_num];
	}
	return NULL;
}

#endif /* RZ_TMS320_DWARF_REGNUM_TABLE_H */
