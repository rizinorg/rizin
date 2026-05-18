// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-FileCopyrightText: 2026 Arya-1-HR

#include <rz_types.h>
#include <analysis_private.h>
#include <rz_analysis.h>

#include <luac/lua_arch.h>

int rz_luajit_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	LuaJITInstructions instr = rz_read_ble32(data, analysis->big_endian);
	return luajit_analysis_op(analysis, op, addr, data, len, instr);
}

int rz_lua_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	const char *cpu = rz_analysis_get_cpu(analysis);
	if (!cpu) {
		RZ_LOG_ERROR("Cannot get lua version\n");
		return 0;
	}

	if (!op || len < 4) {
		return 0;
	}

	if (rz_str_startswith(cpu, "luajit")) {
		return rz_luajit_analysis_op(analysis, op, addr, data, len, mask);
	}

	if (!rz_type_db_format_get(analysis->typedb, "LuaConstant")) {
		RZ_LOG_ERROR("LuaConstant format not found.\n");
		return 0;
	}
	if (!rz_type_db_format_get(analysis->typedb, "LuaUpvalue")) {
		RZ_LOG_ERROR("LuaUpvalue format not found.\n");
		return 0;
	}
	if (!rz_type_db_format_get(analysis->typedb, "LuaLocalVar")) {
		RZ_LOG_ERROR("LuaLocalVar format not found.\n");
		return 0;
	}

	memset(op, 0, sizeof(RzAnalysisOp));

	op->size = 4;
	op->addr = addr;
	const LuaInstruction instruction = lua_build_instruction(data);

	AnalysisLuacContext *ctx = (AnalysisLuacContext *)analysis->plugin_data;
	ctx->mask = mask;
	ctx->addr = addr;
	ctx->instruction = instruction;
	ctx->next_inst = len >= 32 ? *(ut32 *)(data + 4) : 0;

	int ret = 0;

	if (rz_analysis_is_cpu(analysis, "5.0")) {
		ret = lua50_analysis_op(analysis, op, ctx, data, len);
	} else if (rz_analysis_is_cpu(analysis, "5.1") || rz_analysis_is_cpu(analysis, "openwrt-5.1") || rz_analysis_is_cpu(analysis, "tp-link-5.1")) {
		ret = lua51_analysis_op(analysis, op, ctx, data, len);
	} else if (rz_analysis_is_cpu(analysis, "5.2")) {
		ret = lua52_analysis_op(analysis, op, ctx, data, len);
	} else if (rz_analysis_is_cpu(analysis, "5.3")) {
		ret = lua53_analysis_op(analysis, op, ctx, data, len);
	} else if (rz_analysis_is_cpu(analysis, "5.4")) {
		ret = lua54_analysis_op(analysis, op, ctx, data, len);
	} else if (rz_analysis_is_cpu(analysis, "5.5")) {
		ret = lua55_analysis_op(analysis, op, ctx, data, len);
	} else {
		RZ_LOG_ERROR("Cannot find a suitable lua version to handle lua analysis.\n");
		return 0;
	}

	ctx->prev_inst = instruction;
	return ret;
}

#define R_REG_COUNT 256
#define REG_OFFSET  0x20000

static char *get_reg_profile(RzAnalysis *analysis) {
	RzStrBuf *sb = rz_strbuf_new("");

	rz_strbuf_appendf(sb, "gpr pc .32 %d 0\n", REG_OFFSET + (0 * 4));
	rz_strbuf_appendf(sb, "gpr sp .32 %d 0\n", REG_OFFSET + (1 * 4));

	///< Stack slots (Registers R0-R255)
	///< Use offset +8 (after pc and sp)
	for (int i = 0; i < R_REG_COUNT; i++) {
		rz_strbuf_appendf(sb, "gpr r%d .32 %d 0\n", i, REG_OFFSET + 8 + (i * 4));
	}

	rz_strbuf_append(sb, "=PC pc\n"); ///< Program Counter
	rz_strbuf_append(sb, "=SP sp\n"); ///< Stack Pointer
	rz_strbuf_append(sb, "=A0 r0\n");
	rz_strbuf_append(sb, "=A1 r1\n");
	rz_strbuf_append(sb, "=A2 r2\n");
	rz_strbuf_append(sb, "=A3 r3");
	return rz_strbuf_drain(sb);
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return -1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return false;
	default:
		return -1;
	}
}

static bool init(void **user) {
	AnalysisLuacContext *ctx = RZ_NEW0(AnalysisLuacContext);
	if (!ctx) {
		return false;
	}
	*user = ctx;
	return true;
}

static bool fini(void *user) {
	rz_return_val_if_fail(user, false);
	AnalysisLuacContext *ctx = (AnalysisLuacContext *)user;
	free(ctx);
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_luac = {
	.name = "luac",
	.desc = "Lua bytecode analysis plugin",
	.license = "LGPL3",
	.arch = "luac",
	.bits = 32,
	.get_reg_profile = &get_reg_profile,
	.op = &rz_lua_analysis_op,
	.archinfo = archinfo,
	.init = &init,
	.fini = &fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_luac,
	.version = RZ_VERSION
};
#endif
