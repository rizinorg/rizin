// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_core.h>

/**
 * \file bench_core_analysis.c
 * \brief Benchmark for rz_core_analysis_bytes(), the iterator behind `ao`.
 *
 * One iteration drains the iterator over a run of identical instructions. The
 * same run is measured at doubling lengths: work that is linear in the number
 * of instructions doubles in time from one row to the next, while quadratic
 * work quadruples.
 */

typedef struct {
	const char *arch;
	const char *cpu;
	int bits;
	const char *insn; ///< one instruction, as hex, repeated to fill the buffer
} BenchTarget;

/*
 * Each instruction carries a branch target, so masking has something to hide:
 * the default mask for x86, and the ARM plugin's own analysis_mask for ARM.
 */
static const BenchTarget targets[] = {
	{ "x86", NULL, 64, "e800000000" }, // call rel32
	{ "arm", NULL, 32, "000000eb" }, // bl
	{ "tms320", "c55x", 32, "20" }, // nop
};

static void bench_analysis_bytes(RzTable *t_out, const BenchTarget *target, ut64 n_ops, ut64 iterations) {
	RzCore *core = rz_core_new();
	if (!core) {
		return;
	}
	rz_config_set(core->config, "asm.arch", target->arch);
	rz_config_set_i(core->config, "asm.bits", target->bits);
	if (target->cpu) {
		rz_config_set(core->config, "asm.cpu", target->cpu);
	}
	ut8 insn[16];
	int insn_len = rz_hex_str2bin(target->insn, insn);
	ut64 len = (ut64)insn_len * n_ops;
	ut8 *buf = insn_len > 0 ? malloc(len) : NULL;
	if (!buf) {
		rz_core_free(core);
		return;
	}
	for (ut64 i = 0; i < n_ops; i++) {
		memcpy(buf + i * insn_len, insn, insn_len);
	}

	char title[96];
	rz_strf(title, "rz_core_analysis_bytes: %s%s%s, %" PFMT64u " ops", target->arch,
		target->cpu ? "/" : "", target->cpu ? target->cpu : "", n_ops);
	RZ_BENCH_RUN(title, t_out, iterations, {
		RzIterator *it = rz_core_analysis_bytes(core, 0, buf, len, n_ops);
		RzCoreDecodedBytes *db;
		rz_iterator_foreach(it, db) {
		}
		rz_iterator_free(it);
	});

	free(buf);
	rz_core_free(core);
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	for (size_t i = 0; i < RZ_ARRAY_SIZE(targets); i++) {
		for (ut64 n_ops = 250; n_ops <= 2000; n_ops *= 2) {
			bench_analysis_bytes(t, &targets[i], n_ops, 5);
		}
	}

	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
