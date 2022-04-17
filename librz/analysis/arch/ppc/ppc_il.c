// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ppc_il.h"
#include <rz_util/rz_assert.h>
#include <rz_analysis.h>
#include <rz_il.h>
#include <rz_types.h>

RZ_IPI RzAnalysisILConfig *rz_ppc_cs_64_il_config(bool big_endian) {
	RzAnalysisILConfig *r = rz_analysis_il_config_new(64, big_endian, 64);
	return r;
}

RZ_IPI RzAnalysisILConfig *rz_ppc_cs_32_il_config(bool big_endian) {
	RzAnalysisILConfig *r = rz_analysis_il_config_new(32, big_endian, 32);
	return r;
}

bool ppc_is_x_form(ut32 insn_id) {
	switch (insn_id) {
	default:
		return false;
	case PPC_INS_LBZCIX:
	case PPC_INS_LBZUX:
	case PPC_INS_LBZX:
	case PPC_INS_LDARX:
	case PPC_INS_LDBRX:
	case PPC_INS_LDCIX:
	case PPC_INS_LDUX:
	case PPC_INS_LDX:
	case PPC_INS_LHAUX:
	case PPC_INS_LHAX:
	case PPC_INS_LHBRX:
	case PPC_INS_LHZCIX:
	case PPC_INS_LHZUX:
	case PPC_INS_LHZX:
	case PPC_INS_LWARX:
	case PPC_INS_LWAUX:
	case PPC_INS_LWAX:
	case PPC_INS_LWBRX:
	case PPC_INS_LWZCIX:
	case PPC_INS_LWZUX:
	case PPC_INS_LWZX:
		return true;
	}
}

ut32 ppc_get_mem_acc_size(ut32 insn_id) {
	switch (insn_id) {
	default:
		rz_warn_if_reached();
		RZ_LOG_WARN("Memory access size for instruction %d requested. But it is not in the switch case.\n", insn_id);
		return 0;
	case PPC_INS_LI:
	case PPC_INS_LIS:
		return 0; // Don't read from mem.
	case PPC_INS_LBZ:
	case PPC_INS_LBZCIX:
	case PPC_INS_LBZU:
	case PPC_INS_LBZUX:
	case PPC_INS_LBZX:
		return PPC_BYTE;
	case PPC_INS_LHA:
	case PPC_INS_LHAU:
	case PPC_INS_LHAUX:
	case PPC_INS_LHAX:
	case PPC_INS_LHBRX:
	case PPC_INS_LHZ:
	case PPC_INS_LHZCIX:
	case PPC_INS_LHZU:
	case PPC_INS_LHZUX:
	case PPC_INS_LHZX:
		return PPC_HWORD;
	case PPC_INS_LWA:
	case PPC_INS_LWARX:
	case PPC_INS_LWAUX:
	case PPC_INS_LWAX:
	case PPC_INS_LWBRX:
	case PPC_INS_LWZ:
	case PPC_INS_LWZCIX:
	case PPC_INS_LWZU:
	case PPC_INS_LWZUX:
	case PPC_INS_LWZX:
		return PPC_WORD;
	case PPC_INS_LD:
	case PPC_INS_LDARX:
	case PPC_INS_LDBRX:
	case PPC_INS_LDCIX:
	case PPC_INS_LDU:
	case PPC_INS_LDUX:
	case PPC_INS_LDX:
		return PPC_DWORD;
	}
}

bool ppc_updates_ra_with_ea(ut32 insn_id) {
	switch (insn_id) {
	default:
		return false;
	case PPC_INS_LBZU:
	case PPC_INS_LBZUX:
	case PPC_INS_LDU:
	case PPC_INS_LDUX:
	case PPC_INS_LHAU:
	case PPC_INS_LHAUX:
	case PPC_INS_LHZU:
	case PPC_INS_LHZUX:
	case PPC_INS_LWAUX:
	case PPC_INS_LWZU:
	case PPC_INS_LWZUX:
		return true;
	}
}

bool ppc_is_algebraic(ut32 insn_id) {
	switch (insn_id) {
	default:
		return false;
	case PPC_INS_LA:
	case PPC_INS_LDARX:
	case PPC_INS_LHA:
	case PPC_INS_LHAU:
	case PPC_INS_LHAUX:
	case PPC_INS_LHAX:
	case PPC_INS_LWA:
	case PPC_INS_LWAX:
	case PPC_INS_LWARX:
	case PPC_INS_LWAUX:
		return true;
	}
}