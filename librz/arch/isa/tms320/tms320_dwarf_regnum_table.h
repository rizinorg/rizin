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

/**
 * \brief DWARF register numbers for the TMS320C28x, from SPRAC71C Table 10-1.
 *
 * TI's numbering, not derived from anything in the register profile, so the
 * values are named here rather than left as bare indices below. Numbers TI
 * reserves are absent and those slots stay NULL.
 */
typedef enum {
	DW_TMS320_C28X_AL = 0,
	DW_TMS320_C28X_AH = 1,
	DW_TMS320_C28X_PL = 2,
	DW_TMS320_C28X_PH = 3,
	DW_TMS320_C28X_AR0 = 4,
	DW_TMS320_C28X_XAR0 = 5,
	DW_TMS320_C28X_AR1 = 6,
	DW_TMS320_C28X_XAR1 = 7,
	DW_TMS320_C28X_AR2 = 8,
	DW_TMS320_C28X_XAR2 = 9,
	DW_TMS320_C28X_AR3 = 10,
	DW_TMS320_C28X_XAR3 = 11,
	DW_TMS320_C28X_AR4 = 12,
	DW_TMS320_C28X_XAR4 = 13,
	DW_TMS320_C28X_AR5 = 14,
	DW_TMS320_C28X_XAR5 = 15,
	DW_TMS320_C28X_AR6 = 16,
	DW_TMS320_C28X_XAR6 = 17,
	DW_TMS320_C28X_AR7 = 18,
	DW_TMS320_C28X_XAR7 = 19,
	DW_TMS320_C28X_SP = 20,
	DW_TMS320_C28X_TL = 21,
	DW_TMS320_C28X_T = 22,
	DW_TMS320_C28X_ST0 = 23,
	DW_TMS320_C28X_ST1 = 24,
	DW_TMS320_C28X_PC = 25,
	DW_TMS320_C28X_RPC = 26,
	DW_TMS320_C28X_XAR2_AT28 = 28,
	DW_TMS320_C28X_DP = 29,
	DW_TMS320_C28X_SXM = 30,
	DW_TMS320_C28X_PM = 31,
	DW_TMS320_C28X_OVM = 32,
	DW_TMS320_C28X_IFR = 36,
	DW_TMS320_C28X_IER = 37,
} DwTms320C28XReg;

static const char *const map_dwarf_reg_to_tms320_c28x[] = {
	[DW_TMS320_C28X_AL] = "al",
	[DW_TMS320_C28X_AH] = "ah",
	[DW_TMS320_C28X_PL] = "pl",
	[DW_TMS320_C28X_PH] = "ph",
	[DW_TMS320_C28X_AR0] = "ar0",
	[DW_TMS320_C28X_XAR0] = "xar0",
	[DW_TMS320_C28X_AR1] = "ar1",
	[DW_TMS320_C28X_XAR1] = "xar1",
	[DW_TMS320_C28X_AR2] = "ar2",
	[DW_TMS320_C28X_XAR2] = "xar2",
	[DW_TMS320_C28X_AR3] = "ar3",
	[DW_TMS320_C28X_XAR3] = "xar3",
	[DW_TMS320_C28X_AR4] = "ar4",
	[DW_TMS320_C28X_XAR4] = "xar4",
	[DW_TMS320_C28X_AR5] = "ar5",
	[DW_TMS320_C28X_XAR5] = "xar5",
	[DW_TMS320_C28X_AR6] = "ar6",
	[DW_TMS320_C28X_XAR6] = "xar6",
	[DW_TMS320_C28X_AR7] = "ar7",
	[DW_TMS320_C28X_XAR7] = "xar7",
	[DW_TMS320_C28X_SP] = "sp",
	[DW_TMS320_C28X_TL] = "tl",
	[DW_TMS320_C28X_T] = "t",
	[DW_TMS320_C28X_ST0] = "st0",
	[DW_TMS320_C28X_ST1] = "st1",
	[DW_TMS320_C28X_PC] = "pc",
	[DW_TMS320_C28X_RPC] = "rpc",
	[DW_TMS320_C28X_XAR2_AT28] = "xar2",
	[DW_TMS320_C28X_DP] = "dp",
	[DW_TMS320_C28X_SXM] = "sxm",
	[DW_TMS320_C28X_PM] = "pm",
	[DW_TMS320_C28X_OVM] = "ovm",
	[DW_TMS320_C28X_IFR] = "ifr",
	[DW_TMS320_C28X_IER] = "ier",
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

/**
 * \brief DWARF register numbers for the TMS320C6000, from SPRAB89B Table 12-1.
 *
 * As above, TI's numbering. Note CSR at 70, which SPRAB89B spells "CST".
 */
typedef enum {
	DW_TMS320_C6000_A0 = 0,
	DW_TMS320_C6000_A1 = 1,
	DW_TMS320_C6000_A2 = 2,
	DW_TMS320_C6000_A3 = 3,
	DW_TMS320_C6000_A4 = 4,
	DW_TMS320_C6000_A5 = 5,
	DW_TMS320_C6000_A6 = 6,
	DW_TMS320_C6000_A7 = 7,
	DW_TMS320_C6000_A8 = 8,
	DW_TMS320_C6000_A9 = 9,
	DW_TMS320_C6000_A10 = 10,
	DW_TMS320_C6000_A11 = 11,
	DW_TMS320_C6000_A12 = 12,
	DW_TMS320_C6000_A13 = 13,
	DW_TMS320_C6000_A14 = 14,
	DW_TMS320_C6000_A15 = 15,
	DW_TMS320_C6000_B0 = 16,
	DW_TMS320_C6000_B1 = 17,
	DW_TMS320_C6000_B2 = 18,
	DW_TMS320_C6000_B3 = 19,
	DW_TMS320_C6000_B4 = 20,
	DW_TMS320_C6000_B5 = 21,
	DW_TMS320_C6000_B6 = 22,
	DW_TMS320_C6000_B7 = 23,
	DW_TMS320_C6000_B8 = 24,
	DW_TMS320_C6000_B9 = 25,
	DW_TMS320_C6000_B10 = 26,
	DW_TMS320_C6000_B11 = 27,
	DW_TMS320_C6000_B12 = 28,
	DW_TMS320_C6000_B13 = 29,
	DW_TMS320_C6000_B14 = 30,
	DW_TMS320_C6000_B15 = 31,
	DW_TMS320_C6000_PCE1 = 33,
	DW_TMS320_C6000_IRP = 34,
	DW_TMS320_C6000_IFR = 35,
	DW_TMS320_C6000_NRP = 36,
	DW_TMS320_C6000_A16 = 37,
	DW_TMS320_C6000_A17 = 38,
	DW_TMS320_C6000_A18 = 39,
	DW_TMS320_C6000_A19 = 40,
	DW_TMS320_C6000_A20 = 41,
	DW_TMS320_C6000_A21 = 42,
	DW_TMS320_C6000_A22 = 43,
	DW_TMS320_C6000_A23 = 44,
	DW_TMS320_C6000_A24 = 45,
	DW_TMS320_C6000_A25 = 46,
	DW_TMS320_C6000_A26 = 47,
	DW_TMS320_C6000_A27 = 48,
	DW_TMS320_C6000_A28 = 49,
	DW_TMS320_C6000_A29 = 50,
	DW_TMS320_C6000_A30 = 51,
	DW_TMS320_C6000_A31 = 52,
	DW_TMS320_C6000_B16 = 53,
	DW_TMS320_C6000_B17 = 54,
	DW_TMS320_C6000_B18 = 55,
	DW_TMS320_C6000_B19 = 56,
	DW_TMS320_C6000_B20 = 57,
	DW_TMS320_C6000_B21 = 58,
	DW_TMS320_C6000_B22 = 59,
	DW_TMS320_C6000_B23 = 60,
	DW_TMS320_C6000_B24 = 61,
	DW_TMS320_C6000_B25 = 62,
	DW_TMS320_C6000_B26 = 63,
	DW_TMS320_C6000_B27 = 64,
	DW_TMS320_C6000_B28 = 65,
	DW_TMS320_C6000_B29 = 66,
	DW_TMS320_C6000_B30 = 67,
	DW_TMS320_C6000_B31 = 68,
	DW_TMS320_C6000_AMR = 69,
	DW_TMS320_C6000_CSR = 70,
	DW_TMS320_C6000_ISR = 71,
	DW_TMS320_C6000_ICR = 72,
	DW_TMS320_C6000_IER = 73,
	DW_TMS320_C6000_ISTP = 74,
	DW_TMS320_C6000_GFPGFR = 82,
	DW_TMS320_C6000_DIER = 83,
	DW_TMS320_C6000_REP = 84,
	DW_TMS320_C6000_TSCL = 85,
	DW_TMS320_C6000_TSCH = 86,
	DW_TMS320_C6000_ILC = 88,
	DW_TMS320_C6000_RILC = 89,
	DW_TMS320_C6000_DNUM = 90,
	DW_TMS320_C6000_SSR = 91,
	DW_TMS320_C6000_GPLYA = 92,
	DW_TMS320_C6000_GPLYB = 93,
	DW_TMS320_C6000_TSR = 94,
	DW_TMS320_C6000_ITSR = 95,
	DW_TMS320_C6000_NTSR = 96,
	DW_TMS320_C6000_EFR = 97,
	DW_TMS320_C6000_ECR = 98,
	DW_TMS320_C6000_IERR = 99,
} DwTms320C6000Reg;

static const char *const map_dwarf_reg_to_tms320_c6000[] = {
	[DW_TMS320_C6000_A0] = "a0",
	[DW_TMS320_C6000_A1] = "a1",
	[DW_TMS320_C6000_A2] = "a2",
	[DW_TMS320_C6000_A3] = "a3",
	[DW_TMS320_C6000_A4] = "a4",
	[DW_TMS320_C6000_A5] = "a5",
	[DW_TMS320_C6000_A6] = "a6",
	[DW_TMS320_C6000_A7] = "a7",
	[DW_TMS320_C6000_A8] = "a8",
	[DW_TMS320_C6000_A9] = "a9",
	[DW_TMS320_C6000_A10] = "a10",
	[DW_TMS320_C6000_A11] = "a11",
	[DW_TMS320_C6000_A12] = "a12",
	[DW_TMS320_C6000_A13] = "a13",
	[DW_TMS320_C6000_A14] = "a14",
	[DW_TMS320_C6000_A15] = "a15",
	[DW_TMS320_C6000_B0] = "b0",
	[DW_TMS320_C6000_B1] = "b1",
	[DW_TMS320_C6000_B2] = "b2",
	[DW_TMS320_C6000_B3] = "b3",
	[DW_TMS320_C6000_B4] = "b4",
	[DW_TMS320_C6000_B5] = "b5",
	[DW_TMS320_C6000_B6] = "b6",
	[DW_TMS320_C6000_B7] = "b7",
	[DW_TMS320_C6000_B8] = "b8",
	[DW_TMS320_C6000_B9] = "b9",
	[DW_TMS320_C6000_B10] = "b10",
	[DW_TMS320_C6000_B11] = "b11",
	[DW_TMS320_C6000_B12] = "b12",
	[DW_TMS320_C6000_B13] = "b13",
	[DW_TMS320_C6000_B14] = "b14",
	[DW_TMS320_C6000_B15] = "b15",
	[DW_TMS320_C6000_PCE1] = "pce1",
	[DW_TMS320_C6000_IRP] = "irp",
	[DW_TMS320_C6000_IFR] = "ifr",
	[DW_TMS320_C6000_NRP] = "nrp",
	[DW_TMS320_C6000_A16] = "a16",
	[DW_TMS320_C6000_A17] = "a17",
	[DW_TMS320_C6000_A18] = "a18",
	[DW_TMS320_C6000_A19] = "a19",
	[DW_TMS320_C6000_A20] = "a20",
	[DW_TMS320_C6000_A21] = "a21",
	[DW_TMS320_C6000_A22] = "a22",
	[DW_TMS320_C6000_A23] = "a23",
	[DW_TMS320_C6000_A24] = "a24",
	[DW_TMS320_C6000_A25] = "a25",
	[DW_TMS320_C6000_A26] = "a26",
	[DW_TMS320_C6000_A27] = "a27",
	[DW_TMS320_C6000_A28] = "a28",
	[DW_TMS320_C6000_A29] = "a29",
	[DW_TMS320_C6000_A30] = "a30",
	[DW_TMS320_C6000_A31] = "a31",
	[DW_TMS320_C6000_B16] = "b16",
	[DW_TMS320_C6000_B17] = "b17",
	[DW_TMS320_C6000_B18] = "b18",
	[DW_TMS320_C6000_B19] = "b19",
	[DW_TMS320_C6000_B20] = "b20",
	[DW_TMS320_C6000_B21] = "b21",
	[DW_TMS320_C6000_B22] = "b22",
	[DW_TMS320_C6000_B23] = "b23",
	[DW_TMS320_C6000_B24] = "b24",
	[DW_TMS320_C6000_B25] = "b25",
	[DW_TMS320_C6000_B26] = "b26",
	[DW_TMS320_C6000_B27] = "b27",
	[DW_TMS320_C6000_B28] = "b28",
	[DW_TMS320_C6000_B29] = "b29",
	[DW_TMS320_C6000_B30] = "b30",
	[DW_TMS320_C6000_B31] = "b31",
	[DW_TMS320_C6000_AMR] = "amr",
	[DW_TMS320_C6000_CSR] = "csr",
	[DW_TMS320_C6000_ISR] = "isr",
	[DW_TMS320_C6000_ICR] = "icr",
	[DW_TMS320_C6000_IER] = "ier",
	[DW_TMS320_C6000_ISTP] = "istp",
	[DW_TMS320_C6000_GFPGFR] = "gfpgfr",
	[DW_TMS320_C6000_DIER] = "dier",
	[DW_TMS320_C6000_REP] = "rep",
	[DW_TMS320_C6000_TSCL] = "tscl",
	[DW_TMS320_C6000_TSCH] = "tsch",
	[DW_TMS320_C6000_ILC] = "ilc",
	[DW_TMS320_C6000_RILC] = "rilc",
	[DW_TMS320_C6000_DNUM] = "dnum",
	[DW_TMS320_C6000_SSR] = "ssr",
	[DW_TMS320_C6000_GPLYA] = "gplya",
	[DW_TMS320_C6000_GPLYB] = "gplyb",
	[DW_TMS320_C6000_TSR] = "tsr",
	[DW_TMS320_C6000_ITSR] = "itsr",
	[DW_TMS320_C6000_NTSR] = "ntsr",
	[DW_TMS320_C6000_EFR] = "efr",
	[DW_TMS320_C6000_ECR] = "ecr",
	[DW_TMS320_C6000_IERR] = "ierr",
};

#define TMS320_C6000_REG_MAX (sizeof(map_dwarf_reg_to_tms320_c6000) / sizeof(map_dwarf_reg_to_tms320_c6000[0]))

static inline const char *tms320_c6000_register_name(ut32 reg_num) {
	if (reg_num < TMS320_C6000_REG_MAX) {
		return map_dwarf_reg_to_tms320_c6000[reg_num];
	}
	return NULL;
}

#endif /* RZ_TMS320_DWARF_REGNUM_TABLE_H */
