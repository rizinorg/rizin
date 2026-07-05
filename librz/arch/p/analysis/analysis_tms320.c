// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_search.h>

#include <tms320/c55x/c55x_analysis.h>
#include <tms320/c55x_plus/c55plus_analysis.h>
#include <tms320/c54x/c54x.h>
#include <tms320/c2x/c2x.h>
#include <tms320/c5x/c5x.h>
#include <tms320/c6x/c6x.h>

typedef struct tms320_ctx_t {
	ut64 c6x_prev_end; ///< address just past the last c6x instruction analyzed
	bool c6x_prev_par; ///< parallel bit of that instruction (for "||" continuation)
} Tms320Context;

int tms320_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	Tms320Context *context = (Tms320Context *)analysis->plugin_data;

	const char *cpu = rz_analysis_get_cpu(analysis);
	const C6xArchDesc *c6x = c6x_desc_from_cpu(cpu);
	if (c6x) {
		C6xInsn insn;
		if (!c6x_decode(c6x, buf, len, addr, analysis->big_endian, &insn)) {
			return -1;
		}
		c6x_fill_analysis(c6x, &insn, addr, op);
		c6x_mark_parallel(&insn, addr, &context->c6x_prev_end, &context->c6x_prev_par);
		if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
			op->opex = c6x_opex(&insn);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = c6x_lift(&insn, addr);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = c6x_format(c6x, &insn, addr);
		}
		return op->size;
	}
	if (cpu && rz_str_casecmp(cpu, "c55x+") == 0) {
		return tms320_c55x_plus_op(analysis, op, addr, buf, len, mask);
	} else if (cpu && rz_str_casecmp(cpu, "c54x") == 0) {
		return tms320_c54x_op(analysis, op, addr, buf, len, mask);
	} else if (cpu && rz_str_casecmp(cpu, "c2x") == 0) {
		return tms320_c2x_op(analysis, op, addr, buf, len, mask);
	} else if (cpu && rz_str_casecmp(cpu, "c5x") == 0) {
		return tms320_c5x_op(analysis, op, addr, buf, len, mask);
	}
	return tms320_c55x_op_byte(analysis, op, addr, buf, len, mask);
}

static bool tms320_analysis_init(void **user) {
	Tms320Context *context = RZ_NEW0(Tms320Context);
	if (!context) {
		return false;
	}

	*user = context;
	return true;
}

static bool tms320_analysis_fini(void *user) {
	rz_return_val_if_fail(user, false);
	Tms320Context *context = (Tms320Context *)user;

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
	const char *cpu0 = rz_analysis_get_cpu(a);
	if (cpu0 && rz_str_casecmp(cpu0, "c54x") == 0) {
		// TMS320C54x: two 40-bit accumulators A/B (with the L/H 16-bit and G
		// 8-bit guard slices overlapping their parent), eight 16-bit auxiliary
		// registers AR0-AR7, the T/TRN temporaries, SP, the DP data page, the
		// BK circular-buffer size, the ST0/ST1/PMST status words, the BRC/RSA/
		// REA repeat registers, IMR/IFR and the 16-bit XPC program-page. PC is
		// 24-bit. These names match c54x_reg_info()'s il_var bindings so the
		// lifter's SET/VAR ops resolve in the IL VM.
		return rz_str_dup(
			"=PC	pc\n"
			"=SP	sp\n"
			"=BP	sp\n"
			"=A0	ar0\n"
			"=A1	ar1\n"
			"=A2	ar2\n"
			"=A3	ar3\n"
			"=A4	ar4\n"
			"=R0	a\n"
			"ctr a    .40 0  0 # Accumulator A\n"
			"gpr al   .16 0  0 # A low word\n"
			"gpr ah   .16 2  0 # A high word\n"
			"gpr ag   .8  4  0 # A guard bits\n"
			"ctr b    .40 5  0 # Accumulator B\n"
			"gpr bl   .16 5  0 # B low word\n"
			"gpr bh   .16 7  0 # B high word\n"
			"gpr bg   .8  9  0 # B guard bits\n"
			"gpr ar0  .16 10 0 # Auxiliary register 0\n"
			"gpr ar1  .16 12 0 # Auxiliary register 1\n"
			"gpr ar2  .16 14 0 # Auxiliary register 2\n"
			"gpr ar3  .16 16 0 # Auxiliary register 3\n"
			"gpr ar4  .16 18 0 # Auxiliary register 4\n"
			"gpr ar5  .16 20 0 # Auxiliary register 5\n"
			"gpr ar6  .16 22 0 # Auxiliary register 6\n"
			"gpr ar7  .16 24 0 # Auxiliary register 7\n"
			"ctr t    .16 26 0 # Temporary register\n"
			"ctr trn  .16 28 0 # Transition register\n"
			"ctr sp   .16 30 0 # Stack pointer\n"
			"ctr dp   .16 32 0 # Data page pointer\n"
			"ctr bk   .16 34 0 # Circular buffer size\n"
			"ctr st0  .16 36 0 # Status register 0\n"
			"ctr st1  .16 38 0 # Status register 1\n"
			"ctr pmst .16 40 0 # Processor mode status\n"
			"ctr brc  .16 42 0 # Block-repeat counter\n"
			"ctr rsa  .16 44 0 # Block-repeat start address\n"
			"ctr rea  .16 46 0 # Block-repeat end address\n"
			"ctr imr  .16 48 0 # Interrupt mask register\n"
			"ctr ifr  .16 50 0 # Interrupt flag register\n"
			"ctr xpc  .16 52 0 # Extended program counter\n"
			"ctr pc   .24 54 0 # Program counter\n");
	}
	if (cpu0 && rz_str_casecmp(cpu0, "c2x") == 0) {
		// TMS320C2x: a single 32-bit accumulator ACC (with ACCL/ACCH 16-bit
		// halves overlapping it), the 16-bit temporary T, the 32-bit product
		// register P (PL/PH halves), eight 16-bit auxiliary registers AR0-AR7,
		// the 3-bit ARP pointer (held in a 16-bit slot), the 9-bit DP data page,
		// the ST0/ST1 status words and a 16-bit PC. SP is a synthetic stack
		// pointer (the hardware stack is not memory-mapped). These names match
		// c2x_reg_info()'s il_var bindings so the lifter resolves in the IL VM.
		return rz_str_dup(
			"=PC\tpc\n"
			"=SP\tsp\n"
			"=BP\tsp\n"
			"=A0\tar0\n"
			"=A1\tar1\n"
			"=A2\tar2\n"
			"=A3\tar3\n"
			"=R0\tacc\n"
			"ctr acc  .32 0  0\n" // Accumulator
			"gpr accl .16 0  0\n" // Accumulator low word
			"gpr acch .16 2  0\n" // Accumulator high word
			"ctr t    .16 4  0\n" // Temporary register
			"ctr p    .32 6  0\n" // Product register
			"gpr pl   .16 6  0\n" // Product low word
			"gpr ph   .16 8  0\n" // Product high word
			"gpr ar0  .16 10 0\n" // Auxiliary register 0
			"gpr ar1  .16 12 0\n" // Auxiliary register 1
			"gpr ar2  .16 14 0\n" // Auxiliary register 2
			"gpr ar3  .16 16 0\n" // Auxiliary register 3
			"gpr ar4  .16 18 0\n" // Auxiliary register 4
			"gpr ar5  .16 20 0\n" // Auxiliary register 5
			"gpr ar6  .16 22 0\n" // Auxiliary register 6
			"gpr ar7  .16 24 0\n" // Auxiliary register 7
			"ctr arp  .16 26 0\n" // Auxiliary register pointer
			"ctr dp   .16 28 0\n" // Data page pointer
			"ctr st0  .16 30 0\n" // Status register 0
			"ctr st1  .16 32 0\n" // Status register 1
			"ctr sp   .16 34 0\n" // Stack pointer (synthetic)
			"ctr pc   .16 36 0\n" // Program counter
			// status/mode bits modelled individually for the IL lifter (they
			// also live inside ST0/ST1 on real silicon; ST0/ST1 are composed
			// from / decomposed to these by SST/SST1/LST/LST1)
			"flg c    .1 38.0 0\n" // Carry
			"flg ov   .1 39.0 0\n" // Overflow (sticky until tested)
			"flg tc   .1 40.0 0\n" // Test/control bit
			"gpr ovm  .1 41.0 0\n" // Overflow saturation mode
			"gpr sxm  .1 42.0 0\n" // Sign-extension mode
			"gpr pm   .2 43.0 0\n" // Product shift mode
			"gpr arb  .16 44 0\n" // Auxiliary register pointer backup
			"gpr rptc .16 46 0\n"); // Repeat counter
	}
	if (cpu0 && rz_str_casecmp(cpu0, "c5x") == 0) {
		// TMS320C5x: the C2x register file plus the C5x additions — the 32-bit
		// accumulator buffer ACCB, the TREG1/TREG2 multiplier/shift registers,
		// the processor-mode status PMST, the index register INDX, the
		// auxiliary-compare register ARCR, the circular-buffer start/end
		// pointers CBSR1/CBER1/CBSR2/CBER2, the block-repeat registers
		// BRCR/PASR/PAER, the block-move address BMAR, the dynamic bit-mask
		// DBMR and the global-memory register GREG. The core names match the
		// C2x lifter's il_var bindings (the C5x lifter reuses it).
		return rz_str_dup(
			"=PC\tpc\n"
			"=SP\tsp\n"
			"=BP\tsp\n"
			"=A0\tar0\n"
			"=A1\tar1\n"
			"=A2\tar2\n"
			"=A3\tar3\n"
			"=R0\tacc\n"
			"ctr acc   .32 0  0\n" // Accumulator
			"gpr accl  .16 0  0\n" // Accumulator low word
			"gpr acch  .16 2  0\n" // Accumulator high word
			"ctr accb  .32 4  0\n" // Accumulator buffer
			"ctr t     .16 8  0\n" // Temporary/multiplicand register (TREG0)
			"ctr treg1 .16 10 0\n" // TREG1 (dynamic shift count)
			"ctr treg2 .16 12 0\n" // TREG2 (dynamic bit position)
			"ctr p     .32 14 0\n" // Product register
			"gpr pl    .16 14 0\n" // Product low word
			"gpr ph    .16 16 0\n" // Product high word
			"gpr ar0   .16 18 0\n" // Auxiliary register 0
			"gpr ar1   .16 20 0\n" // Auxiliary register 1
			"gpr ar2   .16 22 0\n" // Auxiliary register 2
			"gpr ar3   .16 24 0\n" // Auxiliary register 3
			"gpr ar4   .16 26 0\n" // Auxiliary register 4
			"gpr ar5   .16 28 0\n" // Auxiliary register 5
			"gpr ar6   .16 30 0\n" // Auxiliary register 6
			"gpr ar7   .16 32 0\n" // Auxiliary register 7
			"ctr arp   .16 34 0\n" // Auxiliary register pointer
			"ctr dp    .16 36 0\n" // Data page pointer
			"ctr st0   .16 38 0\n" // Status register 0
			"ctr st1   .16 40 0\n" // Status register 1
			"ctr pmst  .16 42 0\n" // Processor mode status register
			"ctr indx  .16 44 0\n" // Index register
			"ctr arcr  .16 46 0\n" // Auxiliary register compare register
			"ctr cbsr1 .16 48 0\n" // Circular buffer 1 start address
			"ctr cber1 .16 50 0\n" // Circular buffer 1 end address
			"ctr cbsr2 .16 52 0\n" // Circular buffer 2 start address
			"ctr cber2 .16 54 0\n" // Circular buffer 2 end address
			"ctr brcr  .16 56 0\n" // Block repeat counter register
			"ctr pasr  .16 58 0\n" // Block repeat program address start
			"ctr paer  .16 60 0\n" // Block repeat program address end
			"ctr bmar  .16 62 0\n" // Block move address register
			"ctr dbmr  .16 64 0\n" // Dynamic bit manipulation register
			"ctr greg  .16 66 0\n" // Global memory allocation register
			"ctr sp    .16 68 0\n" // Stack pointer (synthetic)
			"ctr pc    .16 70 0\n" // Program counter
			// status/mode bits modelled individually for the shared C2x-core
			// lifter (they also live inside ST0/ST1 on silicon)
			"flg c     .1 72.0 0\n" // Carry
			"flg ov    .1 73.0 0\n" // Overflow (sticky until tested)
			"flg tc    .1 74.0 0\n" // Test/control bit
			"gpr ovm   .1 75.0 0\n" // Overflow saturation mode
			"gpr sxm   .1 76.0 0\n" // Sign-extension mode
			"gpr pm    .2 77.0 0\n" // Product shift mode
			"gpr arb   .16 78 0\n" // Auxiliary register pointer backup
			"gpr rptc  .16 80 0\n"); // Repeat counter
	}
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
		// C6000: C62x/C67x expose 16 general registers per side (A0-A15,
		// B0-B15); C64x and later widen this to 32 and add the C64x+ control-
		// register file. Emit the extended half only for the variants that own
		// it, so `arp` on a C62x/C67x reads back the true 16-register machine.
		bool wide = !(cpu0 && (rz_str_casecmp(cpu0, "c62x") == 0 || rz_str_casecmp(cpu0, "c67x") == 0));
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		rz_strbuf_append(&sb,
			"=PC	pce1\n"
			"=SP	b15\n"
			"=BP	a15\n"
			"=SR	csr\n"
			"=A0	a4\n"
			"=A1	b4\n"
			"=A2	a6\n"
			"=A3	b6\n"
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
			"gpr	a15	.32	60 		0\n");
		if (wide) {
			rz_strbuf_append(&sb,
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
				"gpr	a31	.32	124 	0\n");
		}
		rz_strbuf_append(&sb,
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
			"gpr	b15	.32	188 	0\n");
		if (wide) {
			rz_strbuf_append(&sb,
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
				"gpr	b31	.32	252 	0\n");
		}
		rz_strbuf_append(&sb,
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
			"ctr pce1    .32 296 0  # Program counter, E1 phase\n");
		if (wide) {
			// Control register file extensions; these exist only on C64x+ and later.
			rz_strbuf_append(&sb,
				"ctr dier    .32 300 0  # Debug interrupt enable register\n"
				"ctr dnum    .32 304 0  # DSP core number register\n"
				"ctr ecr     .32 308 0  # Exception clear register\n"
				"ctr efr     .32 312 0  # Exception flag register\n"
				"ctr gplya   .32 316 0  # GMPY A-side polynomial register\n"
				"ctr gplyb   .32 320 0  # GMPY B-side polynomial register\n"
				"ctr ierr    .32 324 0  # Internal exception report register\n"
				"ctr ilc     .32 328 0  # Inner loop count register\n"
				"ctr itsr    .32 332 0  # Interrupt task state register\n"
				"ctr ntsr    .32 336 0  # NMI/Exception task state register\n"
				"ctr rep     .32 340 0  # Restricted entry point address register\n"
				"ctr rilc    .32 344 0  # Reload inner loop count register\n"
				"ctr ssr     .32 348 0  # Saturation status register\n"
				"ctr tsch    .32 352 0  # Time-stamp counter (high 32) register\n"
				"ctr tscl    .32 356 0  # Time-stamp counter (low 32) register\n"
				"ctr tsr     .32 360 0  # Task state register\n");
		}
		rz_strbuf_append(&sb,
			"gpr	a0:a1  	.64	0	0\n"
			"gpr	a2:a3  	.64	8	0\n"
			"gpr	a4:a5  	.64	16	0\n"
			"gpr	a6:a7  	.64	24	0\n"
			"gpr	a8:a9  	.64	32	0\n"
			"gpr	a10:a11	.64	40	0\n"
			"gpr	a12:a13	.64	48	0\n"
			"gpr	a14:a15	.64	56	0\n");
		if (wide) {
			rz_strbuf_append(&sb,
				"gpr	a16:a17	.64	64	0\n"
				"gpr	a18:a19	.64	72	0\n"
				"gpr	a20:a21	.64	80	0\n"
				"gpr	a22:a23	.64	88	0\n"
				"gpr	a24:a25	.64	96	0\n"
				"gpr	a26:a27	.64	104	0\n"
				"gpr	a28:a29	.64	112	0\n"
				"gpr	a30:a31	.64	120	0\n");
		}
		rz_strbuf_append(&sb,
			"gpr	b0:b1  	.64	128	0\n"
			"gpr	b2:b3  	.64	136	0\n"
			"gpr	b4:b5  	.64	144	0\n"
			"gpr	b6:b7  	.64	152	0\n"
			"gpr	b8:b9  	.64	160	0\n"
			"gpr	b10:b11	.64	168	0\n"
			"gpr	b12:b13	.64	176	0\n"
			"gpr	b14:b15	.64	184	0\n");
		if (wide) {
			rz_strbuf_append(&sb,
				"gpr	b16:b17	.64	192	0\n"
				"gpr	b18:b19	.64	200	0\n"
				"gpr	b20:b21	.64	208	0\n"
				"gpr	b22:b23	.64	216	0\n"
				"gpr	b24:b25	.64	224	0\n"
				"gpr	b26:b27	.64	232	0\n"
				"gpr	b28:b29	.64	240	0\n"
				"gpr	b30:b31	.64	248	0\n");
		}
		return rz_strbuf_drain_nofree(&sb);
	}

	// C55x+ (Ryujin) has 32 accumulators and 16 (extended) auxiliary registers,
	// vs the 8/8 of the base C55x profile above. Append the extra ac8-31,
	// ar8-15 and xar8-15 so the shared lifter's IL variables for them resolve
	// (the byte offsets continue past ac7 at 684; C55x never references these).
	const char *cpu = rz_analysis_get_cpu(a);
	if (cpu && rz_str_casecmp(cpu, "c55x+") == 0) {
		static const char *ext =
			"ctr ac8    .40 684 0 # Accumulator 8\n"
			"ctr ac9    .40 689 0 # Accumulator 9\n"
			"ctr ac10   .40 694 0 # Accumulator 10\n"
			"ctr ac11   .40 699 0 # Accumulator 11\n"
			"ctr ac12   .40 704 0 # Accumulator 12\n"
			"ctr ac13   .40 709 0 # Accumulator 13\n"
			"ctr ac14   .40 714 0 # Accumulator 14\n"
			"ctr ac15   .40 719 0 # Accumulator 15\n"
			"ctr ac16   .40 724 0 # Accumulator 16\n"
			"ctr ac17   .40 729 0 # Accumulator 17\n"
			"ctr ac18   .40 734 0 # Accumulator 18\n"
			"ctr ac19   .40 739 0 # Accumulator 19\n"
			"ctr ac20   .40 744 0 # Accumulator 20\n"
			"ctr ac21   .40 749 0 # Accumulator 21\n"
			"ctr ac22   .40 754 0 # Accumulator 22\n"
			"ctr ac23   .40 759 0 # Accumulator 23\n"
			"ctr ac24   .40 764 0 # Accumulator 24\n"
			"ctr ac25   .40 769 0 # Accumulator 25\n"
			"ctr ac26   .40 774 0 # Accumulator 26\n"
			"ctr ac27   .40 779 0 # Accumulator 27\n"
			"ctr ac28   .40 784 0 # Accumulator 28\n"
			"ctr ac29   .40 789 0 # Accumulator 29\n"
			"ctr ac30   .40 794 0 # Accumulator 30\n"
			"ctr ac31   .40 799 0 # Accumulator 31\n"
			"gpr ar8    .16 804 0 # Auxiliary register 8\n"
			"gpr ar9    .16 806 0 # Auxiliary register 9\n"
			"gpr ar10   .16 808 0 # Auxiliary register 10\n"
			"gpr ar11   .16 810 0 # Auxiliary register 11\n"
			"gpr ar12   .16 812 0 # Auxiliary register 12\n"
			"gpr ar13   .16 814 0 # Auxiliary register 13\n"
			"gpr ar14   .16 816 0 # Auxiliary register 14\n"
			"gpr ar15   .16 818 0 # Auxiliary register 15\n"
			"gpr xar8   .23 820 0 # Extended auxiliary register 8\n"
			"gpr xar9   .23 823 0 # Extended auxiliary register 9\n"
			"gpr xar10  .23 826 0 # Extended auxiliary register 10\n"
			"gpr xar11  .23 829 0 # Extended auxiliary register 11\n"
			"gpr xar12  .23 832 0 # Extended auxiliary register 12\n"
			"gpr xar13  .23 835 0 # Extended auxiliary register 13\n"
			"gpr xar14  .23 838 0 # Extended auxiliary register 14\n"
			"gpr xar15  .23 841 0 # Extended auxiliary register 15\n";
		char *prof = rz_str_newf("%s%s", p, ext);
		// On C55x+ the extended auxiliary and stack/data pointer registers
		// (XARn, XSP, XSSP, XDP, XCDP) are 24-bit rather than the 23-bit of
		// classic C55x; widen them so a 24-bit address immediate (amov #k,xarN)
		// and pointer values fit. Every .23 width field in this profile is one
		// of those registers, so a single substitution covers them.
		return prof ? rz_str_replace(prof, ".23", ".24", 1) : NULL;
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
	} else if (c6x_desc_from_cpu(cpu)) {
		/* C6000 VLIW: no reliable fixed prologue; leave to the call graph. */
	} else {
		/* plain C55x: two consecutive single pushes (0x38 0x38) */
		KW("\x38\x38", 2, "\xff\xff", 2);
	}
#undef KW
	return l;
}

static RzAnalysisILConfig *tms320_il_config(RzAnalysis *analysis) {
	// IL is provided for the C6000 (c6x) scalar core, the C55x/C55x+ integer
	// core and the C54x core; other CPUs (plain byte-mode) have no IL yet, so
	// return NULL to leave the VM unconfigured.
	const char *cpu = rz_analysis_get_cpu(analysis);
	if (c6x_desc_from_cpu(cpu)) {
		return tms320_c6x_il_config(analysis);
	}
	if (cpu && (rz_str_casecmp(cpu, "c55x+") == 0 || rz_str_casecmp(cpu, "c55x") == 0)) {
		return tms320_c55x_plus_il_config(analysis);
	}
	if (cpu && rz_str_casecmp(cpu, "c54x") == 0) {
		return tms320_c54x_il_config(analysis);
	}
	if (cpu && rz_str_casecmp(cpu, "c2x") == 0) {
		return tms320_c2x_il_config(analysis);
	}
	if (cpu && rz_str_casecmp(cpu, "c5x") == 0) {
		return tms320_c5x_il_config(analysis);
	}
	return NULL;
}

RzAnalysisPlugin rz_analysis_plugin_tms320 = {
	.name = "tms320",
	.arch = "tms320",
	.bits = 16 | 32,
	.desc = "TMS320 DSP family code analysis plugin",
	.init = tms320_analysis_init,
	.fini = tms320_analysis_fini,
	.license = "LGPLv3",
	.op = &tms320_analysis_op,
	.preludes = tms320_analysis_preludes,
	.il_config = tms320_il_config,
	.get_reg_profile = get_reg_profile,
};
