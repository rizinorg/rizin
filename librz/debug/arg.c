// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

RZ_API ut64 rz_debug_arg_get (RzDebug *dbg, int cctype, int num) {
	r_return_val_if_fail (dbg, UT64_MAX);
	ut32 n32;
	ut64 n64, sp;
	char reg[32];
	if (dbg->analysis) {
		const char *cc = rz_analysis_syscc_default (dbg->analysis);
		if (!RZ_STR_ISEMPTY (cc)) {
			if (!strcmp (cc, "stdcall") || !strcmp (cc, "pascal")) {
				sp = rz_debug_reg_get (dbg, "SP");
				if (dbg->bits == 64) {
					sp += 8; // skip return address, assume we are inside the call
					sp += 8 * num;
					// FIXME: honor endianness of platform
					dbg->iob.read_at (dbg->iob.io, sp, (ut8*)&n64, sizeof(ut64));
					return (ut64)n64;
				} else {
					sp += 4; // skip return address, assume we are inside the call
					sp += 4 * num;
					// FIXME: honor endianness of platform
					dbg->iob.read_at (dbg->iob.io, sp, (ut8*)&n32, sizeof(ut32));
					return (ut64)n32;
				}
			}
			const char *rn = rz_analysis_cc_arg (dbg->anal, cc, num);
			if (rn) {
				return rz_debug_reg_get (dbg, rn);
			}
		}
	}
	snprintf (reg, sizeof (reg) - 1, "A%d", num);
	return rz_debug_reg_get (dbg, reg);
}

RZ_API bool rz_debug_arg_set (RzDebug *dbg, int cctype, int num, ut64 val) {
	rz_return_val_if_fail (dbg, false);
	const char *cc = rz_analysis_syscc_default (dbg->analysis);
	if (!RZ_STR_ISEMPTY (cc)) {
		cc = "reg";
	}
	const char *rn = rz_analysis_cc_arg (dbg->analysis, cc, num);
	if (rn) {
		rz_debug_reg_set (dbg, rn, val);
		return true;
	}
	char reg[32];
	snprintf (reg, sizeof (reg) - 1, "A%d", num);
	rz_debug_reg_set (dbg, reg, val);
	return true;
}
