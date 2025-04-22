// SPDX-FileCopyrightText: 2014 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

static int hook_flag_read(RzAnalysisEsil *esil, const char *flag, ut64 *num) {
	sdb_array_add(esil->stats, "flg.read", flag);
	return 0;
}

static int hook_command(RzAnalysisEsil *esil, const char *op) {
	sdb_array_add(esil->stats, "ops.list", op);
	return 0;
}

static int hook_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	sdb_array_add_num(esil->stats, "mem.read", addr);
	return 0;
}

static int hook_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	sdb_array_add_num(esil->stats, "mem.write", addr);
	return 0;
}

static int hook_reg_read(RzAnalysisEsil *esil, const char *name, ut64 *res, int *size) {
	const char *key = (*name >= '0' && *name <= '9') ? "num.load" : "reg.read";
	sdb_array_add(esil->stats, key, name);
	return 0;
}

static int hook_reg_write(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	sdb_array_add(esil->stats, "reg.write", name);
	return 0;
}

static int hook_NOP_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	RZ_LOG_DEBUG("esil: NOP write at 0x%08" PFMT64x "\n", addr);
	return 1; // override
}

RZ_API void rz_analysis_esil_mem_ro(RzAnalysisEsil *esil, int mem_readonly) {
	if (mem_readonly) {
		esil->cb.hook_mem_write = hook_NOP_mem_write;
	} else {
		esil->cb.hook_mem_write = NULL;
	}
}

RZ_API void rz_analysis_esil_stats(RzAnalysisEsil *esil, int enable) {
	if (enable) {
		if (esil->stats) {
			sdb_reset(esil->stats);
		} else {
			esil->stats = sdb_new0();
		}
		// reset sdb->stats
		esil->cb.hook_reg_read = hook_reg_read;
		esil->cb.hook_mem_read = hook_mem_read;
		esil->cb.hook_mem_write = hook_mem_write;
		esil->cb.hook_reg_write = hook_reg_write;
		esil->cb.hook_flag_read = hook_flag_read;
		esil->cb.hook_command = hook_command;
	} else {
		esil->cb.hook_mem_write = NULL;
		esil->cb.hook_flag_read = NULL;
		esil->cb.hook_command = NULL;
		sdb_free(esil->stats);
		esil->stats = NULL;
	}
}
