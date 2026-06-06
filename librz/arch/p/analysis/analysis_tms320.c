// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_search.h>
#include <tms320/tms320_dasm.h>

#include <tms320/c55x/c55x_analysis.h>
#include <tms320/c55x_plus/c55plus_analysis.h>
#include <tms320/c64x/c64x.h>

typedef struct tms320_ctx_t {
	void *c64x;
} Tms320Context;

int tms320_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	Tms320Context *context = (Tms320Context *)analysis->plugin_data;

	const char *cpu = rz_analysis_get_cpu(analysis);
	if (cpu && rz_str_casecmp(cpu, "c55x+") == 0) {
		return tms320_c55x_plus_op(analysis, op, addr, buf, len, mask);
	} else if (cpu && rz_str_casecmp(cpu, "c64x") == 0) {
		return tms320_c64x_op(analysis, op, addr, buf, len, mask, context->c64x);
	}
	return tms320_c55x_op_byte(analysis, op, addr, buf, len, mask);
}

static bool tms320_analysis_init(void **user) {
	Tms320Context *context = RZ_NEW0(Tms320Context);
	if (!context) {
		return false;
	}

	context->c64x = tms320_c64x_new();
	*user = context;
	return true;
}

static bool tms320_analysis_fini(void *user) {
	rz_return_val_if_fail(user, false);
	Tms320Context *context = (Tms320Context *)user;

	tms320_c64x_free(context->c64x);
	free(context);
	return true;
}

static bool is_c5000(const char *cpu) {
	if (!cpu) {
		return false;
	}
	return (rz_str_casecmp(cpu, "c55x+") == 0) || (rz_str_casecmp(cpu, "c55x") == 0);
}

static char *get_reg_profile(RZ_BORROW RzAnalysis *a) {
	const char *p;
	if (is_c5000(rz_analysis_get_cpu(a))) {
		p =
			"=PC	pc\n"
			"=A0	ar0\n"
			"=A1	ar1\n"
			"=A2	ar2\n"
			"=A3	ar3\n"
			"=A4	ar4\n"
			"=R0	ar0\n"
			"ctr ac0    .40 496 0 # Accumulator 0\n"
			"ctr ac1    .40 501 0 # Accumulator 1\n"
			"ctr ac2    .40 506 0 # Accumulator 2\n"
			"ctr ac3    .40 511 0 # Accumulator 3\n"
			"gpr ar0    .16 516 0 # Auxiliary registers 0\n"
			"gpr ar1    .16 518 0 # Auxiliary registers 1\n"
			"gpr ar2    .16 520 0 # Auxiliary registers 2\n"
			"gpr ar3    .16 522 0 # Auxiliary registers 3\n"
			"gpr ar4    .16 524 0 # Auxiliary registers 4\n"
			"gpr ar5    .16 526 0 # Auxiliary registers 5\n"
			"gpr ar6    .16 528 0 # Auxiliary registers 6\n"
			"gpr ar7    .16 530 0 # Auxiliary registers 7\n"
			"gpr xar0   .23 532 0 # Extended auxiliary registers 0\n"
			"gpr xar1   .23 535 0 # Extended auxiliary registers 1\n"
			"gpr xar2   .23 538 0 # Extended auxiliary registers 2\n"
			"gpr xar3   .23 541 0 # Extended auxiliary registers 3\n"
			"gpr xar4   .23 544 0 # Extended auxiliary registers 4\n"
			"gpr xar5   .23 547 0 # Extended auxiliary registers 5\n"
			"gpr xar6   .23 550 0 # Extended auxiliary registers 6\n"
			"gpr xar7   .23 553 0 # Extended auxiliary registers 7\n"
			"ctr bk03   .16 556 0 # Circular buffer size registers\n"
			"ctr bk47   .16 558 0 # Circular buffer size registers\n"
			"ctr bkc    .16 560 0 # Circular buffer size registers\n"
			"ctr brc0   .16 562 0 # Block-repeat counters 0\n"
			"ctr brc1   .16 564 0 # Block-repeat counters 1\n"
			"ctr brs1   .16 566 0 # BRC1 save register\n"
			"ctr bsa01  .16 568 0 # Circular buffer start address registers\n"
			"ctr bsa23  .16 570 0 # Circular buffer start address registers\n"
			"ctr bsa45  .16 572 0 # Circular buffer start address registers\n"
			"ctr bsa67  .16 574 0 # Circular buffer start address registers\n"
			"ctr bsac   .16 576 0 # Circular buffer start address registers\n"
			"ctr cdp    .16 578 0 # Coefficient data pointer (low part of XCDP)\n"
			"ctr cdph   .7  580 0 # High part of XCDP\n"
			"ctr cfct   .8  581 0 # Control-flow context register\n"
			"ctr csr    .16 582 0 # Computed single-repeat register\n"
			"ctr dbier0 .16 584 0 # Debug interrupt enable registers 0\n"
			"ctr dbier1 .16 586 0 # Debug interrupt enable registers 1\n"
			"ctr dp     .16 588 0 # Data page register (low part of XDP)\n"
			"ctr dph    .7  590 0 # High part of XDP\n"
			"ctr ier0   .16 591 0 # Interrupt enable registers 0\n"
			"ctr ier1   .16 593 0 # Interrupt enable registers 1\n"
			"ctr ifr0   .16 595 0 # Interrupt flag registers 0\n"
			"ctr ifr1   .16 597 0 # Interrupt flag registers 1\n"
			"ctr ivpd   .16 599 0 # Interrupt vector pointers\n"
			"ctr ivph   .16 601 0 # Interrupt vector pointers\n"
			"ctr pc     .24 603 0 # Program counter\n"
			"ctr pdp    .9  606 0 # Peripheral data page register\n"
			"ctr rea0   .24 608 0 # Block-repeat end address registers 0\n"
			"ctr rea1   .24 611 0 # Block-repeat end address registers 1\n"
			"ctr reta   .24 614 0 # Return address register\n"
			"ctr rptc   .16 617 0 # Single-repeat counter\n"
			"ctr rsa0   .24 619 0 # Block-repeat start address registers 0\n"
			"ctr rsa1   .24 622 0 # Block-repeat start address registers 1\n"
			"ctr sp     .16 625 0 # Data stack pointer (low part of XSP)\n"
			"ctr sph    .7  627 0 # High part of XSP and XSSP\n"
			"ctr ssp    .16 628 0 # System stack pointer (low part of XSSP)\n"
			"ctr st0_55 .16 630 0 # Status registers 0\n"
			"ctr st1_55 .16 632 0 # Status registers 1\n"
			"ctr st2_55 .16 634 0 # Status registers 2\n"
			"ctr st3_55 .16 636 0 # Status registers 3\n"
			"ctr t0     .16 638 0 # Temporary register 0\n"
			"ctr t1     .16 640 0 # Temporary register 1\n"
			"ctr t2     .16 642 0 # Temporary register 2\n"
			"ctr t3     .16 644 0 # Temporary register 3\n"
			"ctr trn0   .16 646 0 # Transition registers 1\n"
			"ctr trn1   .16 648 0 # Transition registers 1\n"
			"ctr xcdp   .23 650 0 # Extended coefficient data pointer\n"
			"ctr xdp    .23 653 0 # Extended data page register\n"
			"ctr xsp    .23 656 0 # Extended data stack pointer\n"
			"ctr xssp   .23 659 0 # Extended system stack pointer\n"
			"ctr ac4    .40 664 0 # Accumulator 4\n"
			"ctr ac5    .40 669 0 # Accumulator 5\n"
			"ctr ac6    .40 674 0 # Accumulator 6\n"
			"ctr ac7    .40 679 0 # Accumulator 7\n";
	} else {
		p =
			"=PC	pce1\n"
			"=A0	a4\n"
			"=A1	b4\n"
			"=A2	a6\n"
			"=A3	a6\n"
			"=A4	a8\n"
			"=A5	b8\n"
			"=A6	a10\n"
			"=A7	b10\n"
			"=A8	a12\n"
			"=A9	b12\n"
			"=R0	a4\n"
			"gpr	a0	.32	0 		0\n"
			"gpr	a1	.32	4 		0\n"
			"gpr	a2	.32	8 		0\n"
			"gpr	a3	.32	12 		0\n"
			"gpr	a4	.32	16 		0\n"
			"gpr	a5	.32	20 		0\n"
			"gpr	a6	.32	24 		0\n"
			"gpr	a7	.32	28 		0\n"
			"gpr	a8	.32	32 		0\n"
			"gpr	a9	.32	36 		0\n"
			"gpr	a10	.32	40 		0\n"
			"gpr	a11	.32	44 		0\n"
			"gpr	a12	.32	48 		0\n"
			"gpr	a13	.32	52 		0\n"
			"gpr	a14	.32	56 		0\n"
			"gpr	a15	.32	60 		0\n"
#ifdef CAPSTONE_TMS320C64X_H
			"gpr	a16	.32	64 		0\n"
			"gpr	a17	.32	68 		0\n"
			"gpr	a18	.32	72 		0\n"
			"gpr	a19	.32	76 		0\n"
			"gpr	a20	.32	80 		0\n"
			"gpr	a21	.32	84 		0\n"
			"gpr	a22	.32	88 		0\n"
			"gpr	a23	.32	92 		0\n"
			"gpr	a24	.32	96 		0\n"
			"gpr	a25	.32	100 	0\n"
			"gpr	a26	.32	104 	0\n"
			"gpr	a27	.32	108 	0\n"
			"gpr	a28	.32	112 	0\n"
			"gpr	a29	.32	116 	0\n"
			"gpr	a30	.32	120 	0\n"
			"gpr	a31	.32	124 	0\n"
#endif
			"gpr	b0	.32	128 	0\n"
			"gpr	b1	.32	132 	0\n"
			"gpr	b2	.32	136 	0\n"
			"gpr	b3	.32	140 	0\n"
			"gpr	b4	.32	144 	0\n"
			"gpr	b5	.32	148 	0\n"
			"gpr	b6	.32	152 	0\n"
			"gpr	b7	.32	156 	0\n"
			"gpr	b8	.32	160 	0\n"
			"gpr	b9	.32	164 	0\n"
			"gpr	b10	.32	168 	0\n"
			"gpr	b11	.32	172 	0\n"
			"gpr	b12	.32	176 	0\n"
			"gpr	b13	.32	180 	0\n"
			"gpr	b14	.32	184 	0\n"
			"gpr	b15	.32	188 	0\n"
#ifdef CAPSTONE_TMS320C64X_H
			"gpr	b16	.32	192 	0\n"
			"gpr	b17	.32	196 	0\n"
			"gpr	b18	.32	200 	0\n"
			"gpr	b19	.32	204 	0\n"
			"gpr	b20	.32	208 	0\n"
			"gpr	b21	.32	212 	0\n"
			"gpr	b22	.32	216 	0\n"
			"gpr	b23	.32	220 	0\n"
			"gpr	b24	.32	224 	0\n"
			"gpr	b25	.32	228 	0\n"
			"gpr	b26	.32	232 	0\n"
			"gpr	b27	.32	236 	0\n"
			"gpr	b28	.32	240 	0\n"
			"gpr	b29	.32	244 	0\n"
			"gpr	b30	.32	248 	0\n"
			"gpr	b31	.32	252 	0\n"
#endif
			"ctr amr     .32 256 0  # Addressing mode register\n"
			"ctr csr     .32 260 0  # Control status register\n"
			"ctr gfpgfr  .32 264 0  # Galois field multiply control register\n"
			"ctr icr     .32 268 0  # Interrupt clear register\n"
			"ctr ier     .32 272 0  # Interrupt enable register\n"
			"ctr ifr     .32 276 0  # Interrupt flag register\n"
			"ctr irp     .32 280 0  # Interrupt return pointer register\n"
			"ctr isr     .32 284 0  # Interrupt set register\n"
			"ctr istp    .32 288 0  # Interrupt service table pointer register\n"
			"ctr nrp     .32 292 0  # Nonmaskable interrupt return pointer register\n"
			"ctr pce1    .32 296 0  # Program counter, E1 phase\n"
#ifdef CAPSTONE_TMS320C64X_H
			// Control Register File Extensions (C64x+ DSP)
			"ctr dier    .32 300 0  # (C64x+ only) Debug interrupt enable register\n"
			"ctr dnum    .32 304 0  # (C64x+ only) DSP core number register\n"
			"ctr ecr     .32 308 0  # (C64x+ only) Exception clear register\n"
			"ctr efr     .32 312 0  # (C64x+ only) Exception flag register\n"
			"ctr gplya   .32 316 0  # (C64x+ only) GMPY A-side polynomial register\n"
			"ctr gplyb   .32 320 0  # (C64x+ only) GMPY B-side polynomial register\n"
			"ctr ierr    .32 324 0  # (C64x+ only) Internal exception report register\n"
			"ctr ilc     .32 328 0  # (C64x+ only) Inner loop count register\n"
			"ctr itsr    .32 332 0  # (C64x+ only) Interrupt task state register\n"
			"ctr ntsr    .32 336 0  # (C64x+ only) NMI/Exception task state register\n"
			"ctr rep     .32 340 0  # (C64x+ only) Restricted entry point address register\n"
			"ctr rilc    .32 344 0  # (C64x+ only) Reload inner loop count register\n"
			"ctr ssr     .32 348 0  # (C64x+ only) Saturation status register\n"
			"ctr tsch    .32 352 0  # (C64x+ only) Time-stamp counter (high 32) register\n"
			"ctr tscl    .32 356 0  # (C64x+ only) Time-stamp counter (low 32) register\n"
			"ctr tsr     .32 360 0  # (C64x+ only) Task state register\n"
#endif
			"gpr	a0:a1 	.64	364	0\n"
			"gpr	a2:a3 	.64	368	0\n"
			"gpr	a4:a5 	.64	372	0\n"
			"gpr	a6:a7 	.64	376	0\n"
			"gpr	a8:a9 	.64	380	0\n"
			"gpr	a10:a11	.64	384	0\n"
			"gpr	a12:a13	.64	388	0\n"
			"gpr	a14:a15	.64	392	0\n"
#ifdef CAPSTONE_TMS320C64X_H
			"gpr	a16:a17	.64	396	0\n"
			"gpr	a18:a19	.64	400	0\n"
			"gpr	a20:a21	.64	404	0\n"
			"gpr	a22:a23	.64	408	0\n"
			"gpr	a24:a25	.64	412	0\n"
			"gpr	a26:a27	.64	416	0\n"
			"gpr	a28:a29	.64	420	0\n"
			"gpr	a30:a31	.64	424	0\n"
#endif
			"gpr	b0:b1 	.64	428	0\n"
			"gpr	b2:b3 	.64	432	0\n"
			"gpr	b4:b5 	.64	436	0\n"
			"gpr	b6:b7 	.64	440	0\n"
			"gpr	b8:b9 	.64	444	0\n"
			"gpr	b10:b11	.64	448	0\n"
			"gpr	b12:b13	.64	452	0\n"
			"gpr	b14:b15	.64	456	0\n"
#ifdef CAPSTONE_TMS320C64X_H
			"gpr	b16:b17	.64	460	0\n"
			"gpr	b18:b19	.64	464	0\n"
			"gpr	b20:b21	.64	468	0\n"
			"gpr	b22:b23	.64	472	0\n"
			"gpr	b24:b25	.64	476	0\n"
			"gpr	b26:b27	.64	480	0\n"
			"gpr	b28:b29	.64	484	0\n"
			"gpr	b30:b31	.64	488	0\n"
#endif
			;
	}

	return rz_str_dup(p);
}

/* Function-start preludes.
 *
 * TMS320 C55x / C55x+ functions do not have a single fixed-byte prologue the
 * way x86 (55 89 e5) does: a prologue is a *run* of register pushes whose
 * encodings vary with the register saved. The reliable signal is therefore
 * "several consecutive PSH instructions". We key on the push opcodes:
 *   - C55x+ : PSH is the 2-byte form `0e <reg>`, so a prologue looks like
 *             `0e ?? 0e ?? (0e ??)`. Three consecutive pushes is very unlikely
 *             to occur mid-stream by chance; two is a weaker seed.
 *   - C55x  : PSH single is 0x38; PSH Smem / dbl(Smem) / dbl(Lmem) are
 *             0xb5 / 0xb7 / 0xe4. Two consecutive single pushes (`38 38`) is a
 *             conservative prologue signal.
 * These seed `aap` so the analyzer can discover functions that the call-graph
 * sweep alone misses (e.g. leaf or indirectly-reached routines). Prelude hits
 * are still validated by the normal function analysis, which discards ones
 * that do not decode into a sane body. */
static RzList /*<RzSearchKeyword *>*/ *tms320_analysis_preludes(RzAnalysis *analysis) {
	RzList *l = rz_list_newf((RzListFree)rz_search_keyword_free);
	if (!l) {
		return NULL;
	}
#define KW(d, ds, m, ms) rz_list_append(l, rz_search_keyword_new((const ut8 *)(d), (ds), (const ut8 *)(m), (ms), NULL))
	const char *cpu = rz_analysis_get_cpu(analysis);
	if (cpu && rz_str_casecmp(cpu, "c55x+") == 0) {
		/* three consecutive C55x+ pushes: 0e ?? 0e ?? 0e ?? */
		KW("\x0e\x00\x0e\x00\x0e\x00", 6, "\xff\x00\xff\x00\xff\x00", 6);
		/* two consecutive C55x+ pushes: 0e ?? 0e ?? */
		KW("\x0e\x00\x0e\x00", 4, "\xff\x00\xff\x00", 4);
	} else if (cpu && rz_str_casecmp(cpu, "c64x") == 0) {
		/* C64x VLIW: no reliable fixed prologue; leave to call-graph. */
	} else {
		/* plain C55x: two consecutive single pushes (0x38 0x38) */
		KW("\x38\x38", 2, "\xff\xff", 2);
	}
#undef KW
	return l;
}

static RzAnalysisILConfig *tms320_il_config(RzAnalysis *analysis) {
	// IL is provided for the C55x/C55x+ integer core; other CPUs (c64x, plain
	// byte-mode) have no IL yet, so return NULL to leave the VM unconfigured.
	const char *cpu = rz_analysis_get_cpu(analysis);
	if (cpu && (rz_str_casecmp(cpu, "c55x+") == 0 || rz_str_casecmp(cpu, "c55x") == 0)) {
		return tms320_c55x_plus_il_config(analysis);
	}
	return NULL;
}

RzAnalysisPlugin rz_analysis_plugin_tms320 = {
	.name = "tms320",
	.arch = "tms320",
	.bits = 32,
	.desc = "TMS320 DSP family code analysis plugin",
	.init = tms320_analysis_init,
	.fini = tms320_analysis_fini,
	.license = "LGPLv3",
	.op = &tms320_analysis_op,
	.preludes = tms320_analysis_preludes,
	.il_config = tms320_il_config,
	.get_reg_profile = get_reg_profile,
};
