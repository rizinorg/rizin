// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

RZ_API ut64 rz_debug_arg_get (RzDebug *dbg, int cctype, int num) {
	ut32 n32;
	ut64 n64, sp;
	char reg[32];
	//TODO replace the hardcoded implementation with the sdb
	switch (cctype) {
	case RZ_ANAL_CC_TYPE_SYSV:
	case RZ_ANAL_CC_TYPE_FASTCALL:
		snprintf (reg, sizeof (reg)-1, "A%d", num);
		return rz_debug_reg_get (dbg, reg);
	case RZ_ANAL_CC_TYPE_STDCALL:
	case RZ_ANAL_CC_TYPE_PASCAL:
		sp = rz_debug_reg_get (dbg, "SP");
		if (dbg->bits == 64) {
			sp += 8; // skip return address, assume we are inside the call
			sp += 8 * num;
			dbg->iob.read_at (dbg->iob.io, sp, (ut8*)&n64, sizeof(ut64));
			// TODO: honor endianness of platform
			return (ut64)n64;
		} else {
			sp += 4; // skip return address, assume we are inside the call
			sp += 4 * num;
			dbg->iob.read_at (dbg->iob.io, sp, (ut8*)&n32, sizeof(ut32));
			// TODO: honor endianness of platform
			return (ut64)n32;
		}
	}
	snprintf (reg, sizeof (reg)-1, "A%d", num);
	return rz_debug_reg_get (dbg, reg);
}

RZ_API bool rz_debug_arg_set (RzDebug *dbg, int cctype, int num, ut64 val) {
	// TODO replace the hardcoded implementation with the sdb
	char reg[32];
	switch (cctype) {
	case RZ_ANAL_CC_TYPE_SYSV:
	case RZ_ANAL_CC_TYPE_FASTCALL:
		snprintf (reg, 30, "A%d", num);
		return rz_debug_reg_set (dbg, reg, val);
	case RZ_ANAL_CC_TYPE_STDCALL:
	case RZ_ANAL_CC_TYPE_PASCAL:
		/* TODO: get from stack */
		break;
	}
	return false;
}
