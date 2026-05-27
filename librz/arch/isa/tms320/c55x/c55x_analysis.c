// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-FileCopyrightText: 2014 montekki <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_endian.h>
#include <rz_analysis.h>

#include "c55x_analysis.h"

/**
 * \file c55x_analysis.c
 *
 * TMS320C55x (base) analysis: classify opcodes, resolve branch
 * targets, set basic-block fallthrough, fill in stack effects.
 *
 * Pure byte-level dispatch -- no mnemonic-string matching. Each
 * recognised opcode is dispatched on its leading byte (with second-
 * byte refinement where the prefix family is shared by multiple
 * instructions).
 *
 * The encoding map below was extracted from TI SPRU374 (TMS320C55x
 * DSP Mnemonic Instruction Set Reference Guide, public) and cross-
 * referenced against the rizin c55x decoder's internal opcode table
 * (librz/arch/isa/tms320/c55x/table.h, originally by th0rpe 2013).
 *
 * Key differences from the C55x+ ('+'-suffixed Ryujin / Low-Power
 * C55x) instruction set:
 *
 *   - 0x21 is the parallel-instruction marker (`|| nop`), NOT RET.
 *     RET in baseline C55x is encoded as the 2-byte form 0x48 0x88;
 *     RETI as 0x48 0xA8.
 *   - 0x00 is RPTCC (3-byte conditional repeat), NOT NOP_16.
 *     NOP is the 1-byte 0x20 (same as C55x+).
 *   - 0x02 is RETCC (conditional return), NOT B/CALL indirect.
 *   - 0x04 / 0x06 / 0x08 / 0x4A are the short B/BCC/CALL forms;
 *     0x6A / 0x6B / 0x6C / 0x6E are the 24-bit absolute forms.
 *   - INTR / TRAP are 2-byte 0x95 ?? (bit 7 of byte 2 selects).
 *   - Many control-flow opcodes use a second-byte high bit to flip
 *     between B / CALL or related variants.
 *
 * Encoding cross-validated against rz-asm output for the testbins
 * c55x emulateme binary (tms320/emulateme_nostd.ccsv5.c55x.ticoff2.*)
 * and against TI SPRU374 sec.4 (Instruction Set Reference).
 *
 * Byte-order note: C55x branch displacements and absolute targets
 * are stored MSB-first within the instruction stream -- see SPRU374
 * sec.3. Extracted with rz_read_at_be16() / rz_read_at_be24() to avoid
 * any unaligned-int dereference.
 */

/* Sign-extend an n-bit value to st32. */
static inline st32 sign_extend(ut32 v, ut32 bits) {
	const ut32 mask = (1u << bits) - 1;
	v &= mask;
	if (v & (1u << (bits - 1))) {
		return (st32)(v | ~mask);
	}
	return (st32)v;
}

/* Set conditional-jump fields: type=cjmp, jump=target, fail=fallthrough. */
static inline void set_cjmp(RzAnalysisOp *op, ut64 target) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	op->jump = target;
	op->fail = op->addr + op->size;
	op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
}

/* Set conditional-call fields: type=ccall, jump=target, fail=fallthrough. */
static inline void set_ccall(RzAnalysisOp *op, ut64 target) {
	op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
	op->jump = target;
	op->fail = op->addr + op->size;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = 2;
	op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
}

/* Set unconditional-call fields: type=call, jump=target. */
static inline void set_call(RzAnalysisOp *op, ut64 target) {
	op->type = RZ_ANALYSIS_OP_TYPE_CALL;
	op->jump = target;
	op->fail = op->addr + op->size;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = 2;
	op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
}

/* Set unconditional-jump fields. */
static inline void set_jmp(RzAnalysisOp *op, ut64 target) {
	op->type = RZ_ANALYSIS_OP_TYPE_JMP;
	op->jump = target;
	op->eob = true;
	op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
}

/* Mark an instruction as a return, with stack accounting. */
static inline void set_ret(RzAnalysisOp *op) {
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	op->eob = true;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = -2;
}

/* Record a memory access width (in bytes: 1, 2, or 4) for loads and
 * stores whose effective address is computed at runtime (e.g. via
 * an address register or SP+disp). */
static inline void set_mem_width(RzAnalysisOp *op, int width) {
	op->refptr = width;
	op->ptrsize = width;
}

/* Record an immediate value (for "mov #k, dst" / "add #k, dst" etc.). */
static inline void set_imm(RzAnalysisOp *op, st64 val) {
	op->val = (ut64)val;
}

/* Stack push: write+decrement. Track the byte delta. */
static inline void set_push(RzAnalysisOp *op, int delta) {
	op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = delta;
}

/* Stack pop: read+increment. Track the byte delta. */
static inline void set_pop(RzAnalysisOp *op, int delta) {
	op->type = RZ_ANALYSIS_OP_TYPE_POP;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = delta;
}

/* Conditional return -- like RET but doesn't end the basic block
 * (fallthrough is possible if the condition is false). */
static inline void set_cret(RzAnalysisOp *op) {
	op->type = RZ_ANALYSIS_OP_TYPE_CRET;
	op->fail = op->addr + op->size;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = -2;
}

/* Set op->reg (destination register name) for instructions whose
 * destination register is encoded statically in the leading byte(s).
 * The string is borrowed and must point to static storage. */
static inline void set_dst_reg(RzAnalysisOp *op, const char *name) {
	op->reg = name;
}

/* Set op->ireg (register used for indirect memory computation) for
 * register-indirect loads, stores, branches and calls (e.g. B ACx,
 * CALL ACx). The string is borrowed and must point to static storage. */
static inline void set_ireg(RzAnalysisOp *op, const char *name) {
	op->ireg = name;
}

/* Set op->direction so higher-level analysis knows whether the op
 * reads from memory (LOAD-style), writes to memory (STORE-style),
 * jumps (EXEC), or just references an address (REF). */
static inline void set_dir(RzAnalysisOp *op, RzAnalysisOpDirection dir) {
	op->direction = dir;
}

/* Set op->disp (displacement) for memory references that compute
 * their effective address as `base_register + disp`. */
static inline void set_disp(RzAnalysisOp *op, st64 disp) {
	op->disp = (ut64)disp;
}

/* ACx selector tables -- index 0..3 corresponds to AC0..AC3. */
static const char *const c55x_acc_names[4] = { "ac0", "ac1", "ac2", "ac3" };

/* General-purpose register table indexed by the 4-bit field used in
 * 0x14 (AADD register form) and a number of other instructions:
 *   0..3 -> AC0..AC3 (accumulators)
 *   4..7 -> T0..T3   (temporary registers)
 *   8..f -> AR0..AR7 (auxiliary / address registers)
 * Confirmed against rz-asm output on the c55x decoder. */
static const char *const c55x_gpr_names[16] = {
	"ac0", "ac1", "ac2", "ac3",
	"t0", "t1", "t2", "t3",
	"ar0", "ar1", "ar2", "ar3", "ar4", "ar5", "ar6", "ar7"
};

/* Per-leading-byte instruction size, extracted from the c55x
 * decoder's opcode table (librz/arch/isa/tms320/c55x/table.h --
 * originally by th0rpe 2013, sourced from TI SPRU374). Bytes not
 * documented in the table default to size=1 so the analyzer
 * advances and re-syncs on the next byte rather than getting stuck.
 *
 * Note that some c55x instructions are even longer (up to 7 bytes
 * total) due to immediate-operand suffixes; the table value is the
 * size of the *leading* fixed-form, not necessarily the size of the
 * decoded instruction. This works for analysis purposes (we don't
 * need exact instruction boundaries; we need enough bytes to read
 * branch displacements and at least classify the type).
 *
 * For boundary-critical analyses (basic-block formation), the
 * disassembler is still authoritative; the analyzer's size estimate
 * just needs to be non-zero and not lie about a branch's
 * displacement bytes being there. */
static const ut8 c55x_op_sizes[256] = {
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 3, 3, 3, 3, /* 0x00 */
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0x10 */
	1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0x20 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0x30 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0x40 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0x50 */
	2, 1, 1, 1, 1, 1, 1, 1, 5, 5, 4, 4, 4, 4, 4, 4, /* 0x60 */
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, /* 0x70 */
	3, 3, 4, 4, 4, 4, 4, 4, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x80 */
	2, 2, 2, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 2, /* 0x90 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0xa0 */
	2, 1, 1, 1, 2, 2, 2, 2, 2, 1, 1, 2, 2, 1, 1, 1, /* 0xb0 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0xc0 */
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0xd0 */
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0xe0 */
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 1, 1, /* 0xf0 */
};

static int c55x_op_size(const ut8 *buf, int len) {
	if (len < 1) {
		return 0;
	}
	const ut8 sz = c55x_op_sizes[buf[0]];
	return ((int)sz <= len) ? (int)sz : 0;
}

int tms320_c55x_op_byte(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len) {
	if (!op || !buf || len < 1) {
		return 0;
	}

	const int sz = c55x_op_size(buf, len);
	if (sz == 0) {
		return 0;
	}

	op->addr = addr;
	op->size = sz;
	op->type = RZ_ANALYSIS_OP_TYPE_NULL;

	/* C55x parallel-instruction marker: bit 0 of the leading
	 * opcode byte, when the byte is in the parallel-capable range
	 * 0x01..0x5F, is the 'execute in parallel with the previous
	 * instruction' flag -- not a separate prefix byte. So 0x03 is
	 * RETCC-with-parallel-bit-set (same encoding/operands as 0x02
	 * but executed in parallel), 0x05 is BCC-with-parallel, 0x07
	 * is B-with-parallel, etc. Per SPRU374 sec.5 ('Parallel Execution
	 * of Instructions') and cross-checked against the disassembler:
	 *
	 *   $ rz-asm -a tms320 -c c55x -d 020405 -> retcc t0 == 0
	 *   $ rz-asm -a tms320 -c c55x -d 030405 -> || retcc t0 == 0
	 *
	 * Above the 0x60 boundary, odd-byte opcodes are unrelated
	 * (0x69 CALLCC, 0x6B B abs, etc.); we only mask the bit in the
	 * parallel-capable range so we don't merge unrelated opcodes.
	 *
	 * The instruction size from the table is the same for the even
	 * and odd siblings (since they encode the same instruction). */
	ut8 op_byte = buf[0];
	if ((op_byte & 0x01) && op_byte < 0x60) {
		op_byte &= ~0x01;
	}

	switch (op_byte) {
	/* ---- 0x00: RPTCC k8, cond (3-byte conditional repeat) -------- */
	case 0x00:
		op->type = RZ_ANALYSIS_OP_TYPE_REP;
		op->fail = addr + sz;
		break;

	/* ---- 0x02: RETCC cond (conditional return) ------------------- */
	case 0x02:
		set_cret(op);
		break;

	/* ---- 0x04: BCC k8, cond (8-bit signed relative cond branch) -- */
	case 0x04:
		if (sz >= 2) {
			set_cjmp(op, addr + sz + sign_extend(buf[1], 8));
		}
		break;

	/* ---- 0x06: B L16 (16-bit relative unconditional) ------------- */
	case 0x06:
		if (sz >= 3) {
			const ut32 disp = rz_read_at_be16(buf, 1);
			set_jmp(op, addr + sz + sign_extend(disp, 16));
		}
		break;

	/* ---- 0x08: CALL L16 (16-bit relative call) ------------------- */
	case 0x08:
		if (sz >= 3) {
			const ut32 disp = rz_read_at_be16(buf, 1);
			set_call(op, addr + sz + sign_extend(disp, 16));
		}
		break;

	/* ---- 0x0C: RPT k16 ------------------------------------------- */
	case 0x0c:
		op->type = RZ_ANALYSIS_OP_TYPE_REP;
		break;

	/* ---- 0x0E: RPTB pmad (block-repeat) -------------------------- */
	case 0x0e:
		op->type = RZ_ANALYSIS_OP_TYPE_REP;
		break;

	/* ---- 0x20: NOP (1 byte) -------------------------------------- */
	case 0x20:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;

	/* ---- 0x21: || nop (parallel marker -- NOT a return) ---------- */
	case 0x21:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;

	/* ---- 0x38: PSH (single-word push) ---------------------------- */
	case 0x38:
		set_push(op, 1);
		break;

	/* ---- 0x3A: POP ----------------------------------------------- */
	case 0x3a:
		set_pop(op, -1);
		break;

	/* ---- 0x48: 2-byte multi-form: RPT CSR / RPTADD / RPTSUB / RET / RETI
	 *     differentiated by bits 0-2 of buf[1] (per the table.h
	 *     INSN_MASK(8,3,value) where bit 8 of the 16-bit BE
	 *     instruction is bit 0 of byte 1). The mapping:
	 *       buf[1] & 0x07 == 0 -> RPT CSR
	 *       buf[1] & 0x07 == 1 -> RPTADD CSR, TAx
	 *       buf[1] & 0x07 == 2 -> RPTADD CSR, K4
	 *       buf[1] & 0x07 == 3 -> RPTSUB CSR, K4
	 *       buf[1] & 0x07 == 4 -> RET
	 *       buf[1] & 0x07 == 5 -> RETI
	 */
	case 0x48:
		if (sz >= 2) {
			switch (buf[1] & 0x07) {
			case 4: /* RET */
			case 5: /* RETI */
				set_ret(op);
				break;
			case 0: /* RPT CSR */
			case 1: /* RPTADD CSR, TAx */
			case 2: /* RPTADD CSR, K4 */
			case 3: /* RPTSUB CSR, K4 */
				op->type = RZ_ANALYSIS_OP_TYPE_REP;
				break;
			default:
				op->type = RZ_ANALYSIS_OP_TYPE_NOP;
				break;
			}
		}
		break;

	/* ---- 0x49-0x4F miscellaneous 2-byte forms (most aren't control
	 *     flow). 0x4A is the 2-byte short B; everything else stays
	 *     NULL or is handled below. */
	case 0x4a: /* B k8 (8-bit signed relative B) -- 2 bytes */
		if (sz >= 2) {
			set_jmp(op, addr + sz + sign_extend(buf[1], 8));
		}
		break;
	case 0x4c: /* RPT k8 (3-byte) */
		op->type = RZ_ANALYSIS_OP_TYPE_REP;
		break;
	case 0x4e:
		/* AADD K8, SP -- address arithmetic (frame setup).
		 *
		 * Semantic: SP = SP + K8 (signed).
		 *
		 * rizin's stack-effect convention is that op->stackptr is
		 * the amount by which SP *decreases* (i.e. the amount the
		 * stack frame grows). On c55x the stack grows downward, so
		 *   K8 < 0  ->  SP decreases  ->  frame grows  ->  stackptr = -K8
		 *   K8 > 0  ->  SP increases  ->  frame shrinks ->  stackptr = -K8
		 * which is just stackptr = -K8 in both cases. See
		 * rz_analysis_op_apply_sp_effect() in librz/arch/op.c. */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (sz >= 2) {
			const st8 k8 = (st8)buf[1];
			set_imm(op, k8);
			set_dst_reg(op, "sp");
			set_disp(op, k8);
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -k8;
		}
		break;

	/* ---- 0x60-0x66: BCC variants (8-bit signed relative cond branch).
	 *     Multiple variants encode different condition register
	 *     interpretations but all are conditional jumps with
	 *     8-bit signed displacement at byte 1. */
	case 0x60:
	case 0x61:
	case 0x62:
	case 0x63:
	case 0x64:
	case 0x65:
	case 0x66:
		if (sz >= 2) {
			set_cjmp(op, addr + sz + sign_extend(buf[1], 8));
		}
		break;

	/* ---- 0x6A / 0x6B: B P24 (24-bit absolute unconditional) ------ */
	case 0x6a:
	case 0x6b:
		if (sz >= 4) {
			set_jmp(op, rz_read_at_be24(buf, 1));
		}
		break;

	/* ---- 0x6C: CALL P24 (24-bit absolute call) ------------------- */
	case 0x6c:
		if (sz >= 4) {
			set_call(op, rz_read_at_be24(buf, 1));
		}
		break;

	/* ---- 0x6E: CALLCC P24, cond (conditional 24-bit call) -------- */
	case 0x6e:
		if (sz >= 4) {
			/* Format: 6E hh ll cond -- disp is BE16 at offset 1. */
			const ut32 disp = rz_read_at_be16(buf, 1);
			set_ccall(op, addr + sz + sign_extend(disp, 16));
		}
		break;

	/* ---- 0x6F: BCC P24, cond -- alternate cond branch ------------- */
	case 0x6f:
		if (sz >= 4) {
			const ut32 disp = rz_read_at_be16(buf, 1);
			set_cjmp(op, addr + sz + sign_extend(disp, 16));
		}
		break;

	/* ---- 0x91: B ACx (indirect register branch) ------------------ */
	case 0x91:
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		op->eob = true;
		op->fail = addr + sz;
		if (sz >= 2) {
			set_ireg(op, c55x_acc_names[buf[1] & 0x03]);
		}
		break;

	/* ---- 0x92 / 0x93: CALL ACx (indirect register call) ---------- */
	case 0x92:
	case 0x93:
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		op->fail = addr + sz;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 2;
		if (sz >= 2) {
			set_ireg(op, c55x_acc_names[buf[1] & 0x03]);
		}
		break;

	/* ---- 0x94: RESET --------------------------------------------- */
	case 0x94:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;

	/* ---- 0x95: INTR #k5 or TRAP #k5 (bit 7 of buf[1] selects) ---- */
	case 0x95:
		if (sz >= 2) {
			const ut8 k5 = buf[1] & 0x1f;
			if (buf[1] & 0x80) {
				op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
			} else {
				op->type = RZ_ANALYSIS_OP_TYPE_SWI;
			}
			set_imm(op, k5);
			op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		}
		break;

	/* ---- 0x96 / 0x97 / 0x9E / 0x9F: XCC (predicated execute) ----- */
	case 0x96:
	case 0x97:
	case 0x9e:
	case 0x9f:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;

	/* ---- PSH/POP variants ---------------------------------------- */
	case 0xb5:
	case 0xb7:
	case 0xe4:
		/* PSH variants: 0xb5 PSH Smem, 0xb7 PSH dbl(Smem),
		 * 0xe4 PSH dbl(Lmem). All decrement SP. */
		set_push(op, (op_byte == 0xb7 || op_byte == 0xe4) ? 2 : 1);
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
		break;
	case 0xb8:
	case 0xb9:
	case 0xbb:
		/* POP variants: 0xb8 / 0xb9 POP dbl(Smem),
		 * 0xbb POP Smem. All increment SP. */
		set_pop(op, (op_byte == 0xbb) ? -1 : -2);
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_READ);
		break;

	/* ---- Common arithmetic/logical/move bytes ------------------- */
	case 0x10:
	case 0x18:
	case 0x28:
	case 0x72:
	case 0x7d:
	case 0xd9:
	case 0xf4:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case 0x1a:
	case 0x2a:
	case 0x73:
	case 0x7e:
	case 0xda:
	case 0xf5:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case 0x1c:
	case 0x2c:
	case 0x74:
	case 0x7f:
	case 0xdb:
	case 0xf6:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case 0x12:
	case 0xf0:
	case 0xf1:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case 0x14:
		/* AADD k16, AC/AR -- address-arithmetic add.
		 * Encoding: 14 <src_high_nib>0 <dst_high_nib>0.
		 * Both register fields are 4 bits in the high nibble of
		 * buf[1] / buf[2]; see c55x_gpr_names[] for the map. */
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		if (sz >= 3) {
			const ut8 src_idx = (buf[1] >> 4) & 0x0f;
			const ut8 dst_idx = (buf[2] >> 4) & 0x0f;
			set_dst_reg(op, c55x_gpr_names[dst_idx]);
			set_ireg(op, c55x_gpr_names[src_idx]);
		}
		break;
	case 0x16:
	case 0x22:
	case 0x3c:
	case 0x3e:
	case 0x44:
	case 0x52:
	case 0x75:
	case 0x78:
		/* MOV-family bytes that don't have a uniform low-nibble
		 * register encoding -- type only. */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case 0xa0:
	case 0xa1:
	case 0xa2:
	case 0xa3:
	case 0xa4:
	case 0xa5:
	case 0xa6:
	case 0xa7:
	case 0xa8:
	case 0xa9:
	case 0xaa:
	case 0xab:
	case 0xac:
	case 0xad:
	case 0xae:
	case 0xaf:
		/* MOV Smem, REG -- LOAD-family. Low nibble of the leading
		 * byte selects the destination register; for the SP-relative
		 * common case (bit 0 of buf[1] clear), the source memory
		 * operand is `*sp(#disp)` where disp = buf[1]>>1. */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		set_dst_reg(op, c55x_gpr_names[op_byte & 0x0f]);
		set_dir(op, RZ_ANALYSIS_OP_DIR_READ);
		set_mem_width(op, 2);
		if (sz >= 2 && !(buf[1] & 0x01)) {
			set_ireg(op, "sp");
			set_disp(op, buf[1] >> 1);
		}
		break;
	case 0xc0:
	case 0xc1:
	case 0xc2:
	case 0xc3:
	case 0xc4:
	case 0xc5:
	case 0xc6:
	case 0xc7:
	case 0xc8:
	case 0xc9:
	case 0xca:
	case 0xcb:
	case 0xcc:
	case 0xcd:
	case 0xce:
	case 0xcf:
		/* MOV REG, Smem -- STORE-family. Low nibble of the leading
		 * byte selects the source register; for the SP-relative
		 * common case, the destination memory operand is
		 * `*sp(#disp)` where disp = buf[1]>>1. */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		set_dst_reg(op, c55x_gpr_names[op_byte & 0x0f]);
		set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
		set_mem_width(op, 2);
		if (sz >= 2 && !(buf[1] & 0x01)) {
			set_ireg(op, "sp");
			set_disp(op, buf[1] >> 1);
		}
		break;
	case 0x24:
	case 0x40:
	case 0x5a:
	case 0x70:
	case 0x7a:
	case 0x7b:
	case 0x81:
	case 0xd6:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case 0x26:
	case 0x42:
	case 0x71:
	case 0x7c:
	case 0xd7:
	case 0xd8:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case 0x2e: /* MAX */
	case 0x30: /* MIN */
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case 0x32: /* ABS -- see comment in c55x_plus analyzer */
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		break;
	case 0x34: /* NEG */
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case 0x36: /* NOT */
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case 0x46: /* BCLR */
	case 0xec: /* BSET */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case 0x50:
	case 0x5c: /* SFTL */
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case 0x54: /* ADDV */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case 0x56:
	case 0x83: /* MAC */
	case 0x58:
	case 0x82:
	case 0xfd: /* MPY */
	case 0x1e:
	case 0x79: /* MPYK */
	case 0x84: /* MAS */
	case 0x86:
	case 0x87:
	case 0xd1:
	case 0xd3: /* MPYM */
	case 0xd0: /* MACMZ */
	case 0xd2:
	case 0xd4: /* MACM */
	case 0xd5: /* MASM */
	case 0xf8: /* MPYMK */
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case 0x5e: /* SWAP */
		op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		break;
	case 0x76: /* BFXTR */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case 0x77: /* AMOV */
	case 0x85:
	case 0xb4: /* AMAR */
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		break;
	case 0xb6: /* DELAY */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case 0xdc:
	case 0xe0: /* BTST */
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case 0xe3: /* BTSTSET */
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case 0xde: /* ADDSUBCC */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case 0xf2:
	case 0xf3: /* BAND */
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;

	default:
		/* Unknown leading byte. Mark as NULL so the analyzer can
		 * keep walking but won't merge it into a basic block. The
		 * size=1 default in c55x_op_size() means we advance one
		 * byte and try the next one -- useful for parallel-prefixed
		 * instructions where the leading 0x01/0x03/0x05/... bytes
		 * are themselves the parallel marker. */
		break;
	}

	return op->size;
}
