// SPDX-FileCopyrightText: 2016-2020 FXTi <zjxiang1998@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>

#include "pyc/pyc_dis.h"

#define JMP_OFFSET(ops, v) ((ops)->jump_use_instruction_offset ? (v) * 2 : (v))

static int archinfo(RzAnalysis *analysis, RzAnalysisInfoType query) {
	if (!strcmp(analysis->cpu, "x86")) {
		return -1;
	}

	bool is_16_bits = analysis && analysis->bits == 16;

	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return is_16_bits ? 1 : 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return is_16_bits ? 3 : 2;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return false;
	default:
		return -1;
	}
}

static char *get_reg_profile(RzAnalysis *analysis) {
	return rz_str_dup(
		"=PC    pc\n"
		"=BP    bp\n"
		"=SP    sp\n"
		"=A0    sp\n"
		"gpr    sp  .32 0   0\n" // stack pointer
		"gpr    pc  .32 4   0\n" // program counter
		"gpr    bp  .32 8   0\n" // base pointer // unused
	);
}

static RzList /*<RzList<void *> *>*/ *get_pyc_code_obj(RzAnalysis *analysis) {
	RzBin *b = analysis->binb.bin;
	RzBinPlugin *plugin = b->cur && b->cur->o ? b->cur->o->plugin : NULL;
	bool is_pyc = (plugin && strcmp(plugin->name, "pyc") == 0);
	if (!is_pyc) {
		return NULL;
	}
	return ((RzBinPycObj *)b->cur->o->bin_obj)->shared;
}

static int pyc_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	pyc_context_t *ctx = (pyc_context_t *)a->plugin_data;
	RzList *cobjs = rz_list_get_n(get_pyc_code_obj(a), 0);
	RzListIter *iter = NULL;
	pyc_code_object *func = NULL, *t = NULL;
	rz_list_foreach (cobjs, iter, t) {
		if (RZ_BETWEEN(t->start_offset, addr, t->end_offset - 1)) { // addr in [start_offset, end_offset)
			func = t;
			break;
		}
	}
	if (!func) {
		return -1;
	}

	ut64 func_base = func->start_offset;
	ut32 extended_arg = 0, oparg = 0;
	ut8 op_code = data[0];
	op->addr = addr;
	op->sign = true;
	op->type = RZ_ANALYSIS_OP_TYPE_ILL;
	op->id = op_code;

	if (!ctx->cache || RZ_STR_NE(ctx->version, a->cpu)) {
		if (!pyc_context_set_opcode_by_version(a->cpu, ctx)) {
			RZ_LOG_ERROR("analysis: pyc: unsupported pyc opcode cpu/version (analysis.cpu=%s).\n", a->cpu);
			return -1;
		}
		ctx->cache->bits = a->bits;
	}

	bool is_python36 = a->bits == 8;
	pyc_opcode_object *op_obj = &ctx->cache->opcodes[op_code];
	if (!op_obj->op_name) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->size = 1;
		goto analysis_end;
	}

	op->size = is_python36 ? 2 : ((op_code >= ctx->cache->have_argument) ? 3 : 1);

	if (op_code >= ctx->cache->have_argument) {
		if (!is_python36) {
			oparg = data[1] + data[2] * 256 + extended_arg;
		} else {
			oparg = data[1] + extended_arg;
		}
	}

	if (op_obj->type & HASJABS) {
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = func_base + JMP_OFFSET(ctx->cache, oparg);

		if (op_obj->type & HASCONDITION) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = addr + ((is_python36) ? 2 : 3);
		}
		goto analysis_end;
	}
	if (op_obj->type & HASJREL) {
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + ((is_python36) ? 2 : 3) + JMP_OFFSET(ctx->cache, oparg);
		op->fail = addr + ((is_python36) ? 2 : 3);

		if (op_obj->type & HASCONDITION) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			// op->fail = addr + ((is_python36)? 2: 3);
		}
		// goto analysis_end;
	}

	if (op_obj->type & HASCOMPARE) {
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		goto analysis_end;
	}

	analysis_pyc_op(op, op_obj, oparg);

analysis_end:
	return op->size;
}

static bool pyc_analysis_fini(void *user) {
	pyc_context_free((pyc_context_t *)user);
	return true;
}

static bool pyc_analysis_init(void **user) {
	pyc_context_t *context = RZ_NEW0(pyc_context_t);
	if (!context) {
		return false;
	}

	*user = context;
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_pyc = {
	.name = "pyc",
	.desc = "Python bytecode analysis plugin",
	.license = "LGPL3",
	.arch = "pyc",
	.bits = 16 | 8, // Partially agree with this
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
	.op = &pyc_op,
	.esil = false,
	.init = &pyc_analysis_init,
	.fini = &pyc_analysis_fini,
};
