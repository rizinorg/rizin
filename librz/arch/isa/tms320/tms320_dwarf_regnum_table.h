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

#endif /* RZ_TMS320_DWARF_REGNUM_TABLE_H */
