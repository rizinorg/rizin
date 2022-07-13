// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "analysis_tms320c64x.c"
#include "../../asm/arch/tms320/tms320_dasm.h"

typedef int (*TMS_ANALYSIS_OP_FN)(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len);

int tms320_c54x_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len);
int tms320_c55x_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len);
int tms320_c55x_plus_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len);

static bool match(const char *str, const char *token) {
	return !strncasecmp(str, token, strlen(token));
}

int tms320_c54x_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len) {
	// TODO: add the implementation
	return 0;
}

int tms320_c55x_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len) {
	tms320_dasm_t *engine = (tms320_dasm_t *)analysis->plugin_data;
	const char *str = engine->syntax;

	op->delay = 0;
	op->size = tms320_dasm(engine, buf, len);
	op->type = RZ_ANALYSIS_OP_TYPE_NULL;

	str = strstr(str, "||") ? str + 3 : str;

	if (match(str, "B ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		if (match(str, "B AC")) {
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		}
	} else if (match(str, "BCC ") || match(str, "BCCU ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	} else if (match(str, "CALL ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		if (match(str, "CALL AC")) {
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		}
	} else if (match(str, "CALLCC ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
	} else if (match(str, "RET")) {
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		if (match(str, "RETCC")) {
			op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		}
	} else if (match(str, "MOV ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
	} else if (match(str, "PSHBOTH ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_UPUSH;
	} else if (match(str, "PSH ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
	} else if (match(str, "POPBOTH ") || match(str, "POP ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
	} else if (match(str, "CMP ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
	} else if (match(str, "CMPAND ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_ACMP;
	} else if (match(str, "NOP")) {
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
	} else if (match(str, "INTR ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
	} else if (match(str, "TRAP ")) {
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
	} else if (match(str, "INVALID")) {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	}

	return op->size;
}

int tms320_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	TMS_ANALYSIS_OP_FN aop = tms320_c55x_op;

	if (analysis->cpu && rz_str_casecmp(analysis->cpu, "c64x") == 0) {
#ifdef CAPSTONE_TMS320C64X_H
		return tms320c64x_analop(analysis, op, addr, buf, len, mask);
#else
		return -1;
#endif
	}
	if (analysis->cpu && rz_str_casecmp(analysis->cpu, "c54x") == 0) {
		aop = tms320_c54x_op;
	} else if (analysis->cpu && rz_str_casecmp(analysis->cpu, "c55x") == 0) {
		aop = tms320_c55x_op;
	} else if (analysis->cpu && rz_str_casecmp(analysis->cpu, "c55x+") == 0) {
		aop = tms320_c55x_plus_op;
	}
	return aop(analysis, op, addr, buf, len);
}

static bool tms320_init(void **user) {
	tms320_dasm_t *engine = RZ_NEW0(tms320_dasm_t);
	if (!engine) {
		return false;
	}
	tms320_dasm_init(engine);
	*user = engine;
	return true;
}

static bool tms320_fini(void *user) {
	rz_return_val_if_fail(user, false);
	tms320_dasm_t *engine = (tms320_dasm_t *)user;
	tms320_dasm_fini(engine);
	free(engine);
	return true;
}

static char *get_reg_profile(RZ_BORROW RzAnalysis *a) {
	const char *p =
		"=PC	pc\n"
		"gpr	A0	.32	0 		0\n"
		"gpr	A1	.32	4 		0\n"
		"gpr	A2	.32	8 		0\n"
		"gpr	A3	.32	12 		0\n"
		"gpr	A4	.32	16 		0\n"
		"gpr	A5	.32	20 		0\n"
		"gpr	A6	.32	24 		0\n"
		"gpr	A7	.32	28 		0\n"
		"gpr	A8	.32	32 		0\n"
		"gpr	A9	.32	36 		0\n"
		"gpr	A10	.32	40 		0\n"
		"gpr	A11	.32	44 		0\n"
		"gpr	A12	.32	48 		0\n"
		"gpr	A13	.32	52 		0\n"
		"gpr	A14	.32	56 		0\n"
		"gpr	A15	.32	60 		0\n"
		"gpr	A16	.32	64 		0\n"
		"gpr	A17	.32	68 		0\n"
		"gpr	A18	.32	72 		0\n"
		"gpr	A19	.32	76 		0\n"
		"gpr	A20	.32	80 		0\n"
		"gpr	A21	.32	84 		0\n"
		"gpr	A22	.32	88 		0\n"
		"gpr	A23	.32	92 		0\n"
		"gpr	A24	.32	96 		0\n"
		"gpr	A25	.32	100 	0\n"
		"gpr	A26	.32	104 	0\n"
		"gpr	A27	.32	108 	0\n"
		"gpr	A28	.32	112 	0\n"
		"gpr	A29	.32	116 	0\n"
		"gpr	A30	.32	120 	0\n"
		"gpr	A31	.32	124 	0\n"
		"gpr	B0	.32	128 	0\n"
		"gpr	B1	.32	132 	0\n"
		"gpr	B2	.32	136 	0\n"
		"gpr	B3	.32	140 	0\n"
		"gpr	B4	.32	144 	0\n"
		"gpr	B5	.32	148 	0\n"
		"gpr	B6	.32	152 	0\n"
		"gpr	B7	.32	156 	0\n"
		"gpr	B8	.32	160 	0\n"
		"gpr	B9	.32	164 	0\n"
		"gpr	B10	.32	168 	0\n"
		"gpr	B11	.32	172 	0\n"
		"gpr	B12	.32	176 	0\n"
		"gpr	B13	.32	180 	0\n"
		"gpr	B14	.32	184 	0\n"
		"gpr	B15	.32	188 	0\n"
		"gpr	B16	.32	192 	0\n"
		"gpr	B17	.32	196 	0\n"
		"gpr	B18	.32	200 	0\n"
		"gpr	B19	.32	204 	0\n"
		"gpr	B20	.32	208 	0\n"
		"gpr	B21	.32	212 	0\n"
		"gpr	B22	.32	216 	0\n"
		"gpr	B23	.32	220 	0\n"
		"gpr	B24	.32	224 	0\n"
		"gpr	B25	.32	228 	0\n"
		"gpr	B26	.32	232 	0\n"
		"gpr	B27	.32	236 	0\n"
		"gpr	B28	.32	240 	0\n"
		"gpr	B29	.32	244 	0\n"
		"gpr	B30	.32	248 	0\n"
		"gpr	B31	.32	252 	0\n"
		"ctr AMR     .32 256 0  # Addressing mode register\n"
		"ctr CSR     .32 260 0  # Control status register\n"
		"ctr GFPGFR  .32 264 0  # Galois field multiply control register\n"
		"ctr ICR     .32 268 0  # Interrupt clear register\n"
		"ctr IER     .32 272 0  # Interrupt enable register\n"
		"ctr IFR     .32 276 0  # Interrupt flag register\n"
		"ctr IRP     .32 280 0  # Interrupt return pointer register\n"
		"ctr ISR     .32 284 0  # Interrupt set register\n"
		"ctr ISTP    .32 288 0  # Interrupt service table pointer register\n"
		"ctr NRP     .32 292 0  # Nonmaskable interrupt return pointer register\n"
		"ctr PCE1    .32 296 0  # Program counter, E1 phase\n"
#ifdef CAPSTONE_TMS320C64X_H
		// Control Register File Extensions (C64x+ DSP)
		"ctr DIER    .32 300 0  # (C64x+ only) Debug interrupt enable register\n"
		"ctr DNUM    .32 304 0  # (C64x+ only) DSP core number register\n"
		"ctr ECR     .32 308 0  # (C64x+ only) Exception clear register\n"
		"ctr EFR     .32 312 0  # (C64x+ only) Exception flag register\n"
		"ctr GPLYA   .32 316 0  # (C64x+ only) GMPY A-side polynomial register\n"
		"ctr GPLYB   .32 320 0  # (C64x+ only) GMPY B-side polynomial register\n"
		"ctr IERR    .32 324 0  # (C64x+ only) Internal exception report register\n"
		"ctr ILC     .32 328 0  # (C64x+ only) Inner loop count register\n"
		"ctr ITSR    .32 332 0  # (C64x+ only) Interrupt task state register\n"
		"ctr NTSR    .32 336 0  # (C64x+ only) NMI/Exception task state register\n"
		"ctr REP     .32 340 0  # (C64x+ only) Restricted entry point address register\n"
		"ctr RILC    .32 344 0  # (C64x+ only) Reload inner loop count register\n"
		"ctr SSR     .32 348 0  # (C64x+ only) Saturation status register\n"
		"ctr TSCH    .32 352 0  # (C64x+ only) Time-stamp counter (high 32) register\n"
		"ctr TSCL    .32 356 0  # (C64x+ only) Time-stamp counter (low 32) register\n"
		"ctr TSR     .32 360 0  # (C64x+ only) Task state register\n"
#endif
		;

	return strdup(p);
}

RzAnalysisPlugin rz_analysis_plugin_tms320 = {
	.name = "tms320",
	.arch = "tms320",
	.bits = 32,
	.desc = "TMS320 DSP family code analysis plugin",
	.init = tms320_init,
	.fini = tms320_fini,
	.license = "LGPLv3",
	.op = &tms320_op,
	.get_reg_profile = get_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_tms320,
	.version = RZ_VERSION
};
#endif
