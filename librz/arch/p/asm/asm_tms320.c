// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include "asm_private.h"
#include <tms320/c55x_plus/c55plus_arch.h>
#include <tms320/c55x/c55x_analysis.h>
#include <tms320/c54x/c54x.h>
#include <tms320/c2x/c2x.h>
#include <tms320/c5x/c5x.h>
#include <tms320/c64x/c64x.h>
#include <tms320/c6x/c6x.h>

typedef struct tms_cs_context_t {
	void *c64x;
	ut64 c6x_prev_end; ///< address just past the last c6x instruction disassembled
	bool c6x_prev_par; ///< parallel bit of that instruction (for "||" continuation)
} TmsContext;

static int tms320_disassemble(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	TmsContext *ctx = (TmsContext *)a->plugin_data;
	// The native shared engine handles the whole TMS320C6000 VLIW family
	// (c62x/c64x/c67x/c674x/c66x); it supersedes the optional capstone c64x path.
	const C6xArchDesc *c6x = c6x_desc_from_cpu(a->cpu);
	if (c6x) {
		C6xInsn insn;
		if (c6x_decode(c6x, buf, len, a->pc, a->big_endian, &insn)) {
			c6x_mark_parallel(&insn, a->pc, &ctx->c6x_prev_end, &ctx->c6x_prev_par);
			char *s = c6x_format(c6x, &insn, a->pc);
			if (s) {
				rz_asm_op_set_asm(op, s);
				free(s);
				return op->size = insn.size;
			}
		}
		rz_asm_op_set_asm(op, "invalid");
		// an unrecognised word still occupies a full instruction slot
		return op->size = C6X_WORD_SIZE;
	}
	if (a->cpu && !rz_str_casecmp(a->cpu, "c64x-capstone")) {
		return tms320_c64x_disassemble(a, op, buf, len, ctx->c64x);
	}
	// C55x / C55x+ / C54x are decoded by the shared decode-IR engine; any other
	// cpu is unknown.
	const C55ArchDesc *desc = NULL;
	if (a->cpu && !rz_str_casecmp(a->cpu, "c55x+")) {
		desc = &c55plus_arch_desc;
	} else if (a->cpu && !rz_str_casecmp(a->cpu, "c55x")) {
		desc = &c55x_arch_desc;
	} else if (a->cpu && !rz_str_casecmp(a->cpu, "c54x")) {
		desc = &c54x_arch_desc;
	} else if (a->cpu && !rz_str_casecmp(a->cpu, "c2x")) {
		desc = &c2x_arch_desc;
	} else if (a->cpu && !rz_str_casecmp(a->cpu, "c5x")) {
		desc = &c5x_arch_desc;
	} else {
		rz_asm_op_set_asm(op, "unknown asm.cpu");
		return op->size = -1;
	}
	if (desc) {
		C55Insn insn;
		bool ok;
		if (desc == &c5x_arch_desc) {
			// The C5x has its own decode front-end (real C5x encoding).
			ok = c5x_decode(buf, len, &insn) > 0;
		} else {
			ok = c55_decode(desc, buf, len, &insn);
		}
		if (ok) {
			char *s = c55_format(desc, &insn);
			if (s) {
				rz_asm_op_set_asm(op, s);
				free(s);
				return op->size = insn.size;
			}
		}
	}
	rz_asm_op_set_asm(op, "invalid");
	return op->size = 1;
}

static bool tms320_init(void **user) {
	TmsContext *ctx = RZ_NEW0(TmsContext);
	if (!ctx) {
		return false;
	}
	ctx->c64x = tms320_c64x_new();
	*user = ctx;
	return true;
}

static bool tms320_fini(void *user) {
	rz_return_val_if_fail(user, false);
	TmsContext *ctx = (TmsContext *)user;
	tms320_c64x_free(ctx->c64x);
	free(ctx);
	return true;
}

static char *tms320_mnemonics(const RzAsm *a, int id, bool json) {
	TmsContext *ctx = (TmsContext *)a->plugin_data;
	if (!a->cpu || rz_str_casecmp(a->cpu, "c64x-capstone")) {
		return NULL;
	}
	return tms320_c64x_mnemonics(a, id, json, ctx->c64x);
}

static char **tms320_cpu_descriptions() {
	static char *cpu_desc[] = {
		"c54x", "Texas Instruments TMS320C54x DSP family",
		"c2x", "Texas Instruments TMS320C2x legacy fixed-point DSP family",
		"c5x", "Texas Instruments TMS320C5x fixed-point DSP family (C2x-compatible superset)",
		"c55x", "Texas Instruments TMS320C55x DSP family",
		"c55x+", "Texas Instruments TMS320C55x+ DSP family",
		"c62x", "Texas Instruments TMS320C62x fixed-point VLIW DSP family",
		"c64x", "Texas Instruments TMS320C64x/C64x+ fixed-point VLIW DSP family",
		"c67x", "Texas Instruments TMS320C67x/C67x+ floating-point VLIW DSP family",
		"c674x", "Texas Instruments TMS320C674x unified fixed/floating-point DSP family",
		"c66x", "Texas Instruments TMS320C66x VLIW DSP family",
		NULL
	};
	return cpu_desc;
}

RzAsmPlugin rz_asm_plugin_tms320 = {
	.name = "tms320",
	.arch = "tms320",
	.cpus = "c54x,c55x,c55x+,c2x,c5x,c62x,c64x,c67x,c674x,c66x",
	.desc = "Texas Instruments TMS320 DSP family (c54x,c55x,c55x+,c2x,c5x,c6x) disassembler",
	.license = "LGPL3",
	.bits = 16 | 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = tms320_init,
	.fini = tms320_fini,
	.disassemble = &tms320_disassemble,
	.mnemonics = tms320_mnemonics,
	.get_cpu_desc = tms320_cpu_descriptions,
};
