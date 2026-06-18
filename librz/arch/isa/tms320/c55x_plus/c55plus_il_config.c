// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

#include "c55plus_analysis.h"

// IL-VM register bindings for the TMS320C55x and C55x+ cores. The lifter emits
// SET/VAR ops that name these registers; the binding list tells the RzIL VM
// which variables to materialise. C55x+ extends the C55x file with the high
// accumulators (ac8-31) and the high address registers (ar8-15 / xar8-15).
static const char *c55x_il_regs[] = {
	"ac0", "ac1", "ac2", "ac3", "ac4", "ac5", "ac6", "ac7",
	"ar0", "ar1", "ar2", "ar3", "ar4", "ar5", "ar6", "ar7",
	"xar0", "xar1", "xar2", "xar3", "xar4", "xar5", "xar6", "xar7",
	"t0", "t1", "t2", "t3",
	"sp", "ssp", "dp", "dph", "sph", "pdp", "pc",
	"cdp", "cdph", "xcdp", "csr", "rptc",
	"brc0", "brc1", "brs1", "trn0", "trn1",
	"bk03", "bk47", "bkc",
	"bsa01", "bsa23", "bsa45", "bsa67", "bsac",
	"st0_55", "st1_55", "st2_55", "st3_55",
	NULL
};
static const char *c55x_plus_il_regs[] = {
	"ac0", "ac1", "ac2", "ac3", "ac4", "ac5", "ac6", "ac7",
	"ac8", "ac9", "ac10", "ac11", "ac12", "ac13", "ac14", "ac15",
	"ac16", "ac17", "ac18", "ac19", "ac20", "ac21", "ac22", "ac23",
	"ac24", "ac25", "ac26", "ac27", "ac28", "ac29", "ac30", "ac31",
	"ar0", "ar1", "ar2", "ar3", "ar4", "ar5", "ar6", "ar7",
	"ar8", "ar9", "ar10", "ar11", "ar12", "ar13", "ar14", "ar15",
	"xar0", "xar1", "xar2", "xar3", "xar4", "xar5", "xar6", "xar7",
	"xar8", "xar9", "xar10", "xar11", "xar12", "xar13", "xar14", "xar15",
	"t0", "t1", "t2", "t3",
	"sp", "ssp", "dp", "dph", "sph", "pdp", "pc",
	"cdp", "cdph", "xcdp", "csr", "rptc",
	"brc0", "brc1", "brs1", "trn0", "trn1",
	"bk03", "bk47", "bkc",
	"bsa01", "bsa23", "bsa45", "bsa67", "bsac",
	"st0_55", "st1_55", "st2_55", "st3_55",
	NULL
};

RZ_IPI RzAnalysisILConfig *tms320_c55x_plus_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(24, false, 24);
	if (!cfg) {
		return NULL;
	}
	const char *cpu = rz_analysis_get_cpu(analysis);
	bool plus = cpu && rz_str_casecmp(cpu, "c55x+") == 0;
	cfg->reg_bindings = plus ? c55x_plus_il_regs : c55x_il_regs;
	return cfg;
}
