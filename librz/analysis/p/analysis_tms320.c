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

static bool is_c5000(const char *cpu) {
	rz_return_val_if_fail(cpu, false);
	return (rz_str_casecmp(cpu, "c55x+") == 0) || (rz_str_casecmp(cpu, "c55x") == 0);
}

static char *get_reg_profile(RZ_BORROW RzAnalysis *a) {
	const char *p;
	if (is_c5000(a->cpu)) {
		p =
			"=PC	PC\n"
			"=A0	AR0\n"
			"=A1	AR1\n"
			"=A2	AR2\n"
			"=A3	AR3\n"
			"=A4	AR4\n"
			"=R0	AR0\n"
			"ctr AC0    .40 496 0 # Accumulator 0\n"
			"ctr AC1    .40 498 0 # Accumulator 1\n"
			"ctr AC2    .40 500 0 # Accumulator 2\n"
			"ctr AC3    .40 502 0 # Accumulator 3\n"
			"gpr AR0    .16 504 0 # Auxiliary registers 0\n"
			"gpr AR1    .16 505 0 # Auxiliary registers 1\n"
			"gpr AR2    .16 506 0 # Auxiliary registers 2\n"
			"gpr AR3    .16 507 0 # Auxiliary registers 3\n"
			"gpr AR4    .16 508 0 # Auxiliary registers 4\n"
			"gpr AR5    .16 509 0 # Auxiliary registers 5\n"
			"gpr AR6    .16 510 0 # Auxiliary registers 6\n"
			"gpr AR7    .16 511 0 # Auxiliary registers 7\n"
			"gpr XAR0   .23 512 0 # Extended auxiliary registers 0\n"
			"gpr XAR1   .23 513 0 # Extended auxiliary registers 1\n"
			"gpr XAR2   .23 514 0 # Extended auxiliary registers 2\n"
			"gpr XAR3   .23 515 0 # Extended auxiliary registers 3\n"
			"gpr XAR4   .23 516 0 # Extended auxiliary registers 4\n"
			"gpr XAR5   .23 517 0 # Extended auxiliary registers 5\n"
			"gpr XAR6   .23 518 0 # Extended auxiliary registers 6\n"
			"gpr XAR7   .23 519 0 # Extended auxiliary registers 7\n"
			"ctr BK03   .16 520 0 # Circular buffer size registers\n"
			"ctr BK47   .16 521 0 # Circular buffer size registers\n"
			"ctr BKC    .16 522 0 # Circular buffer size registers\n"
			"ctr BRC0   .16 523 0 # Block-repeat counters 0\n"
			"ctr BRC1   .16 524 0 # Block-repeat counters 1\n"
			"ctr BRS1   .16 525 0 # BRC1 save register\n"
			"ctr BSA01  .16 526 0 # Circular buffer start address registers\n"
			"ctr BSA23  .16 527 0 # Circular buffer start address registers\n"
			"ctr BSA45  .16 528 0 # Circular buffer start address registers\n"
			"ctr BSA67  .16 529 0 # Circular buffer start address registers\n"
			"ctr BSAC   .16 530 0 # Circular buffer start address registers\n"
			"ctr CDP    .16 531 0 # Coefficient data pointer (low part of XCDP)\n"
			"ctr CDPH   .7  532 0 # High part of XCDP\n"
			"ctr CFCT   .8  533 0 # Control-flow context register\n"
			"ctr CSR    .16 534 0 # Computed single-repeat register\n"
			"ctr DBIER0 .16 535 0 # Debug interrupt enable registers 0\n"
			"ctr DBIER1 .16 536 0 # Debug interrupt enable registers 1\n"
			"ctr DP     .16 537 0 # Data page register (low part of XDP)\n"
			"ctr DPH    .7  538 0 # High part of XDP\n"
			"ctr IER0   .16 539 0 # Interrupt enable registers 0\n"
			"ctr IER1   .16 540 0 # Interrupt enable registers 1\n"
			"ctr IFR0   .16 541 0 # Interrupt flag registers 0\n"
			"ctr IFR1   .16 542 0 # Interrupt flag registers 1\n"
			"ctr IVPD   .16 543 0 # Interrupt vector pointers\n"
			"ctr IVPH   .16 544 0 # Interrupt vector pointers\n"
			"ctr PC     .24 545 0 # Program counter\n"
			"ctr PDP    .9  546 0 # Peripheral data page register\n"
			"ctr REA0   .24 547 0 # Block-repeat end address registers 0\n"
			"ctr REA1   .24 548 0 # Block-repeat end address registers 1\n"
			"ctr RETA   .24 549 0 # Return address register\n"
			"ctr RPTC   .16 550 0 # Single-repeat counter\n"
			"ctr RSA0   .24 551 0 # Block-repeat start address registers 0\n"
			"ctr RSA1   .24 552 0 # Block-repeat start address registers 1\n"
			"ctr SP     .16 553 0 # Data stack pointer (low part of XSP)\n"
			"ctr SPH    .7  554 0 # High part of XSP and XSSP\n"
			"ctr SSP    .16 555 0 # System stack pointer (low part of XSSP)\n"
			"ctr ST0_55 .16 556 0 # Status registers 0\n"
			"ctr ST1_55 .16 557 0 # Status registers 1\n"
			"ctr ST2_55 .16 558 0 # Status registers 2\n"
			"ctr ST3_55 .16 559 0 # Status registers 3\n"
			"ctr T0     .16 560 0 # Temporary register 0\n"
			"ctr T1     .16 561 0 # Temporary register 1\n"
			"ctr T2     .16 562 0 # Temporary register 2\n"
			"ctr T3     .16 563 0 # Temporary register 3\n"
			"ctr TRN0   .16 564 0 # Transition registers 1\n"
			"ctr TRN1   .16 565 0 # Transition registers 1\n"
			"ctr XCDP   .23 566 0 # Extended coefficient data pointer\n"
			"ctr XDP    .23 567 0 # Extended data page register\n"
			"ctr XSP    .23 568 0 # Extended data stack pointer\n"
			"ctr XSSP   .23 569 0 # Extended system stack pointer\n";
	} else {
		p =
			"=PC	pc\n"
			"=A0	A4\n"
			"=A1	B4\n"
			"=A2	A6\n"
			"=A3	A6\n"
			"=A4	A8\n"
			"=A5	B8\n"
			"=A6	A10\n"
			"=A7	B10\n"
			"=A8	A12\n"
			"=A9	B12\n"
			"=R0	A4\n"
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
#ifdef CAPSTONE_TMS320C64X_H
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
#endif
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
#ifdef CAPSTONE_TMS320C64X_H
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
#endif
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
			"gpr	A0:A1 	.64	364	0\n"
			"gpr	A2:A3 	.64	368	0\n"
			"gpr	A4:A5 	.64	372	0\n"
			"gpr	A6:A7 	.64	376	0\n"
			"gpr	A8:A9 	.64	380	0\n"
			"gpr	A10:A11	.64	384	0\n"
			"gpr	A12:A13	.64	388	0\n"
			"gpr	A14:A15	.64	392	0\n"
#ifdef CAPSTONE_TMS320C64X_H
			"gpr	A16:A17	.64	396	0\n"
			"gpr	A18:A19	.64	400	0\n"
			"gpr	A20:A21	.64	404	0\n"
			"gpr	A22:A23	.64	408	0\n"
			"gpr	A24:A25	.64	412	0\n"
			"gpr	A26:A27	.64	416	0\n"
			"gpr	A28:A29	.64	420	0\n"
			"gpr	A30:A31	.64	424	0\n"
#endif
			"gpr	B0:B1 	.64	428	0\n"
			"gpr	B2:B3 	.64	432	0\n"
			"gpr	B4:B5 	.64	436	0\n"
			"gpr	B6:B7 	.64	440	0\n"
			"gpr	B8:B9 	.64	444	0\n"
			"gpr	B10:B11	.64	448	0\n"
			"gpr	B12:B13	.64	452	0\n"
			"gpr	B14:B15	.64	456	0\n"
#ifdef CAPSTONE_TMS320C64X_H
			"gpr	B16:B17	.64	460	0\n"
			"gpr	B18:B19	.64	464	0\n"
			"gpr	B20:B21	.64	468	0\n"
			"gpr	B22:B23	.64	472	0\n"
			"gpr	B24:B25	.64	476	0\n"
			"gpr	B26:B27	.64	480	0\n"
			"gpr	B28:B29	.64	484	0\n"
			"gpr	B30:B31	.64	488	0\n"
#endif
			;
	}

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
