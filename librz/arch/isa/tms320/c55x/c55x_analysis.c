// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-FileCopyrightText: 2014 montekki <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_endian.h>
#include <rz_analysis.h>

#include "c55x_analysis.h"
#include "../tms320c55x_insn.h"
#include "../tms320_dasm.h"

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

	/* Resolve the named instruction ID from the disassembler (single
	 * source of truth) and dispatch on it, rather than on the raw opcode
	 * byte. The disassembler runs the operand mask lists, so multi-form
	 * leading bytes resolve to the exact mnemonic decoded. Second-byte
	 * refinements and register-field extraction still read buf[]/op_byte
	 * directly where the mnemonic alone is insufficient (e.g. picking the
	 * displacement width for the several B / CALL encodings). */
	const ut16 id = tms320c55x_insn_id_decode(buf, len);
	op->id = id;

	switch (id) {
	/* ---- RPTCC k8, cond (3-byte conditional repeat) -------------- */
	case TMS320C55_INS_RPTCC:
		op->type = RZ_ANALYSIS_OP_TYPE_REP;
		op->fail = addr + sz;
		break;

	/* ---- RETCC cond (conditional return) ------------------------- */
	case TMS320C55_INS_RETCC:
		set_cret(op);
		break;

	/* ---- BCC: 8-bit or 16-bit signed relative conditional branch.
	 *     0x04 / 0x60-0x66 carry an 8-bit displacement at byte 1;
	 *     0x6F carries a 16-bit BE displacement. ------------------- */
	case TMS320C55_INS_BCC:
		if (op_byte == 0x6f) {
			if (sz >= 4) {
				const ut32 disp = rz_read_at_be16(buf, 1);
				set_cjmp(op, addr + sz + sign_extend(disp, 16));
			}
		} else if (sz >= 2) {
			set_cjmp(op, addr + sz + sign_extend(buf[1], 8));
		}
		break;

	/* ---- B: unconditional branch. Encodings:
	 *     0x06 16-bit relative, 0x4A 8-bit relative,
	 *     0x6A 24-bit absolute, 0x91 indirect via ACx. ------------- */
	case TMS320C55_INS_B:
		if (op_byte == 0x91) {
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			op->eob = true;
			op->fail = addr + sz;
			if (sz >= 2) {
				set_ireg(op, c55x_acc_names[buf[1] & 0x03]);
			}
		} else if (op_byte == 0x6a || op_byte == 0x6b) {
			if (sz >= 4) {
				set_jmp(op, rz_read_at_be24(buf, 1));
			}
		} else if (op_byte == 0x4a) {
			if (sz >= 2) {
				set_jmp(op, addr + sz + sign_extend(buf[1], 8));
			}
		} else { /* 0x06 */
			if (sz >= 3) {
				const ut32 disp = rz_read_at_be16(buf, 1);
				set_jmp(op, addr + sz + sign_extend(disp, 16));
			}
		}
		break;

	/* ---- CALL: 0x08 16-bit relative, 0x6C 24-bit absolute,
	 *     0x92 indirect via ACx. ----------------------------------- */
	case TMS320C55_INS_CALL:
		if (op_byte == 0x92 || op_byte == 0x93) {
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
			op->fail = addr + sz;
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = 2;
			if (sz >= 2) {
				set_ireg(op, c55x_acc_names[buf[1] & 0x03]);
			}
		} else if (op_byte == 0x6c) {
			if (sz >= 4) {
				set_call(op, rz_read_at_be24(buf, 1));
			}
		} else { /* 0x08 */
			if (sz >= 3) {
				const ut32 disp = rz_read_at_be16(buf, 1);
				set_call(op, addr + sz + sign_extend(disp, 16));
			}
		}
		break;

	/* ---- CALLCC P24, cond (conditional 24-bit call) -------------- */
	case TMS320C55_INS_CALLCC:
		if (sz >= 4) {
			/* Format: 6E hh ll cond -- disp is BE16 at offset 1. */
			const ut32 disp = rz_read_at_be16(buf, 1);
			set_ccall(op, addr + sz + sign_extend(disp, 16));
		}
		break;

	/* ---- RPT / RPTB / RPTADD / RPTSUB (block/single repeat) ------ */
	case TMS320C55_INS_RPT:
	case TMS320C55_INS_RPTB:
	case TMS320C55_INS_RPTADD:
	case TMS320C55_INS_RPTSUB:
	case TMS320C55_INS_RPTBLOCAL:
		op->type = RZ_ANALYSIS_OP_TYPE_REP;
		break;

	/* ---- RET / RETI: both are returns with -2 stack effect. The
	 *     disassembler resolves the 0x48 family (and any other return
	 *     encodings) to the exact mnemonic, so no second-byte logic is
	 *     needed here. ------------------------------------------------ */
	case TMS320C55_INS_RET:
	case TMS320C55_INS_RETI:
		set_ret(op);
		break;

	/* ---- NOP ----------------------------------------------------- */
	case TMS320C55_INS_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;

	/* ---- PSH variants: 0x38 single push; 0xB5 PSH Smem,
	 *     0xB7 PSH dbl(Smem), 0xE4 PSH dbl(Lmem). ------------------ */
	case TMS320C55_INS_PSH:
		if (op_byte == 0x38) {
			set_push(op, 1);
		} else {
			set_push(op, (op_byte == 0xb7 || op_byte == 0xe4) ? 2 : 1);
			set_dst_reg(op, "sp");
			set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
		}
		break;

	/* ---- POP variants: 0x3A single pop; 0xB8/0xB9 POP dbl(Smem),
	 *     0xBB POP Smem. ------------------------------------------- */
	case TMS320C55_INS_POP:
		if (op_byte == 0x3a) {
			set_pop(op, -1);
		} else {
			set_pop(op, (op_byte == 0xbb) ? -1 : -2);
			set_dst_reg(op, "sp");
			set_dir(op, RZ_ANALYSIS_OP_DIR_READ);
		}
		break;

	/* ---- PSHBOTH / POPBOTH (dual register stack ops) ------------- */
	case TMS320C55_INS_PSHBOTH:
		set_push(op, 2);
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
		break;
	case TMS320C55_INS_POPBOTH:
		set_pop(op, -2);
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_READ);
		break;

	/* ---- AADD: address-arithmetic add. 0x4E is `AADD K8, SP`
	 *     (frame setup); 0x14 is `AADD k16, AC/AR`. --------------- */
	case TMS320C55_INS_AADD:
		if (op_byte == 0x4e) {
			/* SP = SP + K8 (signed). rizin's convention: op->stackptr is
			 * the amount SP *decreases* (frame growth). On C55x the stack
			 * grows down, so stackptr = -K8 regardless of sign. See
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
		} else { /* 0x14: AADD k16, AC/AR */
			op->type = RZ_ANALYSIS_OP_TYPE_LEA;
			if (sz >= 3) {
				const ut8 src_idx = (buf[1] >> 4) & 0x0f;
				const ut8 dst_idx = (buf[2] >> 4) & 0x0f;
				set_dst_reg(op, c55x_gpr_names[dst_idx]);
				set_ireg(op, c55x_gpr_names[src_idx]);
			}
		}
		break;

	/* ---- RESET --------------------------------------------------- */
	case TMS320C55_INS_RESET:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;

	/* ---- INTR #k5 / TRAP #k5: the disassembler distinguishes the two
	 *     (bit 7 of buf[1]); use the resolved ID for the type and read
	 *     the 5-bit immediate from buf[1]. ------------------------- */
	case TMS320C55_INS_INTR:
	case TMS320C55_INS_TRAP:
		op->type = (id == TMS320C55_INS_TRAP) ? RZ_ANALYSIS_OP_TYPE_TRAP : RZ_ANALYSIS_OP_TYPE_SWI;
		if (sz >= 2) {
			set_imm(op, buf[1] & 0x1f);
		}
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;

	/* ---- XCC / XCCPART (predicated execute) ---------------------- */
	case TMS320C55_INS_XCC:
	case TMS320C55_INS_XCCPART:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;

	/* ---- Logical AND family -------------------------------------- */
	case TMS320C55_INS_AND:
	case TMS320C55_INS_BAND:
	case TMS320C55_INS_BTST:
	case TMS320C55_INS_BTSTSET:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;

	/* ---- Logical OR ---------------------------------------------- */
	case TMS320C55_INS_OR:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;

	/* ---- Logical XOR --------------------------------------------- */
	case TMS320C55_INS_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;

	/* ---- Compare family ------------------------------------------ */
	case TMS320C55_INS_CMP:
	case TMS320C55_INS_CMPAND:
	case TMS320C55_INS_CMPOR:
	case TMS320C55_INS_MAX:
	case TMS320C55_INS_MIN:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;

	/* ---- MOV family ---------------------------------------------- */
	case TMS320C55_INS_MOV:
		/* 0xA0-0xAF: MOV Smem, REG (LOAD); 0xC0-0xCF: MOV REG, Smem
		 * (STORE). Both extract the register from the low nibble and,
		 * for the SP-relative form (bit 0 of buf[1] clear), set a
		 * *sp(#disp) operand. Other MOV-encoding bytes set only type. */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		if (op_byte >= 0xa0 && op_byte <= 0xaf) {
			set_dst_reg(op, c55x_gpr_names[op_byte & 0x0f]);
			set_dir(op, RZ_ANALYSIS_OP_DIR_READ);
			set_mem_width(op, 2);
			if (sz >= 2 && !(buf[1] & 0x01)) {
				set_ireg(op, "sp");
				set_disp(op, buf[1] >> 1);
			}
		} else if (op_byte >= 0xc0 && op_byte <= 0xcf) {
			set_dst_reg(op, c55x_gpr_names[op_byte & 0x0f]);
			set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
			set_mem_width(op, 2);
			if (sz >= 2 && !(buf[1] & 0x01)) {
				set_ireg(op, "sp");
				set_disp(op, buf[1] >> 1);
			}
		}
		break;

	/* ---- Bit set/clear (treated as MOV-like field writes) -------- */
	case TMS320C55_INS_BCLR:
	case TMS320C55_INS_BSET:
	case TMS320C55_INS_BFXTR:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	/* ---- DELAY: memory-delay move. Per TI SWPU104 sec.6.7.1 (Memory
	 *     Delay, grouped under "Move Operations"), delay(Smem) copies the
	 *     content of Smem to the next-higher address Smem+1 -- a one-word
	 *     memory-to-memory data shift used to implement delay lines in
	 *     filters. It is a data MOV (one data read + one data write), not
	 *     a CPU/system-control instruction, so it gets the default
	 *     family rather than FAMILY_CPU. ----------------------------- */
	case TMS320C55_INS_DELAY:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		set_mem_width(op, 2);
		set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
		break;

	/* ---- Add family ---------------------------------------------- */
	case TMS320C55_INS_ADD:
	case TMS320C55_INS_ADDSUBCC:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;

	/* ---- Subtract / negate --------------------------------------- */
	case TMS320C55_INS_SUB:
	case TMS320C55_INS_NEG:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;

	/* ---- Bitwise NOT --------------------------------------------- */
	case TMS320C55_INS_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;

	/* ---- Shifts -------------------------------------------------- */
	case TMS320C55_INS_SFTL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;

	/* ---- Multiply / MAC family ----------------------------------- */
	case TMS320C55_INS_MAC:
	case TMS320C55_INS_MACM:
	case TMS320C55_INS_MASM:
	case TMS320C55_INS_MAS:
	case TMS320C55_INS_MPY:
	case TMS320C55_INS_MPYK:
	case TMS320C55_INS_MPYM:
	case TMS320C55_INS_MPYMK:
	case TMS320C55_INS_SQDST:
	case TMS320C55_INS_LMSF:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;

	/* ---- SWAP (register exchange) -------------------------------- */
	case TMS320C55_INS_SWAP:
		op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		break;

	/* ---- Address-register moves (LEA-like) ----------------------- */
	case TMS320C55_INS_AMOV:
	case TMS320C55_INS_AMAR:
	case TMS320C55_INS_FIRSADD:
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		break;

	/* ---- ABS: leave NULL (no precise rizin type; see C55x+ note) - */
	case TMS320C55_INS_ABS:
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		break;

	default:
		/* Unknown / untyped instruction. Mark as NULL so the analyzer
		 * keeps walking but won't merge it into a basic block. The
		 * size=1 default in c55x_op_size() means we advance one byte
		 * and re-sync -- useful for parallel-prefixed instructions
		 * whose leading 0x01/0x03/0x05/... bytes are the parallel
		 * marker. */
		break;
	}

	return op->size;
}
