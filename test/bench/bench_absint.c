// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_analysis.h>
#include <rz_io.h>
#include <rz_inquiry/rz_absint.h>
#include <rz_inquiry/rz_il_cache.h>

/**
 * \file bench_absint.c
 * \brief Benchmark for the RzAbsInt interpreter
 *
 * Interprets a synthetic function with a repeated arithmetic body and compares
 * the run time with and without the may_skip_rhs_eval short-circuit hook of the
 * value domain. This measures whether the cost of consulting the plugin for
 * every binary operation is compensated by the avoided operand evaluations.
 */

typedef struct bench_interp_t {
	RzAnalysis *analysis;
	RzIO *io;
	RzILCache *il_cache;
	RzAbsIntInstance *inst;
} BenchInterp;

static RzAbsIntIOReadResult bench_io_read(RzAbsIntIOReadRequest *req, void *user) {
	return RZ_ABSINT_IO_READ_RESULT_TOP; // memory contents are unknown
}

static RzAbsIntLiftBlockResult bench_lift_block(ut64 addr, const RzILCacheBlock **block_out, void *user) {
	BenchInterp *interp = user;
	const RzILCacheBlock *block = rz_il_cache_lift_il_block(interp->il_cache, addr);
	if (block) {
		*block_out = block;
		return RZ_ABSINT_LIFT_BLOCK_RESULT_OK;
	}
	return RZ_ABSINT_LIFT_BLOCK_RESULT_FAILED;
}

static BenchInterp *bench_interp_new(const char *arch, int bits, ut64 baddr, const char *url, const RzAbsIntValueDomain *val_domain) {
	BenchInterp *interp = RZ_NEW(BenchInterp);
	interp->analysis = rz_analysis_new(NULL);
	rz_analysis_use(interp->analysis, arch);
	rz_analysis_set_bits(interp->analysis, bits);
	interp->io = rz_io_new();
	interp->io->va = 1;
	interp->il_cache = rz_il_cache_new(interp->analysis, interp->io, RZ_IL_CACHE_CONFIG_NOP_UNLIFTED);
	RzAbsIntConfig config = {
		.val_domain = val_domain,
		.cb_user = interp,
		.io_read = bench_io_read,
		.lift_block = bench_lift_block
	};
	interp->inst = rz_absint_instance_new(interp->analysis, &config);
	RzIODesc *desc = rz_io_open_at(interp->io, url, RZ_PERM_RX, 0644, baddr, NULL);
	if (!desc) {
		eprintf("Failed to load code\n");
		free(interp);
		return NULL;
	}
	return interp;
}

static void bench_interp_free(BenchInterp *interp) {
	if (!interp) {
		return;
	}
	rz_absint_instance_free(interp->inst);
	rz_il_cache_free(interp->il_cache);
	rz_io_free(interp->io);
	rz_analysis_free(interp->analysis);
	free(interp);
}

// one body iteration: alternation of operations with top and constant first operand
#define BODY_HEX \
	"0200138b" /* add x2, x0, x19   ; x0 is top            -> short-circuit */ \
	"6302148b" /* add x3, x19, x20  ; const operands       -> no short-circuit */ \
	"4400148b" /* add x4, x2, x20   ; x2 is top            -> short-circuit */ \
	"6500048b" /* add x5, x3, x4    ; x3 is const          -> no short-circuit */ \
	"a600008b" /* add x6, x5, x0    ; x5 is const          -> no short-circuit */ \
	"c700018b" /* add x7, x6, x1    ; x6 is top            -> short-circuit */

#define BODY_REPS 64

static char *bench_code_url(void) {
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	rz_strbuf_append(&sb, "hex://");
	rz_strbuf_append(&sb, "332282d2"); // mov x19, 0x1111
	rz_strbuf_append(&sb, "544484d2"); // mov x20, 0x2222
	rz_strbuf_append(&sb, "756686d2"); // mov x21, 0x3333
	for (int i = 0; i < BODY_REPS; i++) {
		rz_strbuf_append(&sb, BODY_HEX);
	}
	rz_strbuf_append(&sb, "c0035fd6"); // ret
	char *r = rz_strbuf_drain_nofree(&sb);
	rz_strbuf_fini(&sb);
	return r;
}

static void bench_absint_run(const char *title, RzTable *t, ut32 iterations, const RzAbsIntValueDomain *domain) {
	char *url = bench_code_url();
	BenchInterp *interp = bench_interp_new("arm", 64, 0x10000, url, domain);
	free(url);
	if (!interp) {
		return;
	}
	// warmup, so that lifting is not part of the measurement
	RzAbsIntResult *res = NULL;
	rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);
	rz_absint_result_free(interp->inst, res);

	RZ_BENCH_RUN(title, t, iterations, {
		res = NULL;
		rz_absint_run(interp->inst, 0x10000, RZ_ABSINT_RESULT_DIMEN_BASE, &res);
		rz_absint_result_free(interp->inst, res);
	});

	bench_interp_free(interp);
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	RzAbsIntValueDomain domain_without_hook = *rz_absint_builtin_value_domain(RZ_ABSINT_VALUE_DOMAIN_CONST);
	domain_without_hook.may_skip_rhs_eval = NULL;
	const RzAbsIntValueDomain *domains[] = {
		rz_absint_builtin_value_domain(RZ_ABSINT_VALUE_DOMAIN_CONST),
		&domain_without_hook,
	};

	const ut32 iterations = 2000;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(domains); i++) {
		char title[128];
		snprintf(title, sizeof(title), "rz_absint_run (may_skip_rhs_eval = %s)",
			domains[i]->may_skip_rhs_eval ? "on" : "off");
		bench_absint_run(title, t, iterations, domains[i]);
	}

	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
