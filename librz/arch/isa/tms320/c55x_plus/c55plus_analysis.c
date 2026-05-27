// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-FileCopyrightText: 2014 montekki <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_endian.h>
#include <rz_analysis.h>

#include "c55plus_analysis.h"
#include "ins.h"

/**
 * \file c55plus_analysis.c
 *
 * TMS320C55x+ analysis: classify opcodes, resolve branch targets, set
 * basic-block fallthrough, fill in src/dst/val and stack effects.
 *
 * Pure byte-level dispatch -- no mnemonic-string matching. Each
 * recognised opcode is dispatched on its leading byte (or leading byte
 * + a small subset of the second byte where the prefix family is
 * shared by multiple instructions).
 *
 * The encoding map below was extracted from SWPU104 chapter 6 (Dec
 * 2006 'Algebraic Instruction Set' reference) and SWPU086 chapter 4
 * (May 2005 'CPU Reference Guide', Preliminary), then cross-validated
 * against TI dis55.exe v4.3.6 (CCSv5 c55x_plus SDK, Feb 2010) on the
 * testbins#289 c55xp corpus.
 *
 * Branch and control-flow encodings:
 *
 *   0x00 ..       NOP / IDLE / RETI / to_word    sec.6.5.11, sec.6.5.20, sec.6.5.16
 *   0x02 b1       B/CALL ACx (indirect register) sec.6.5.2, sec.6.5.6
 *   0x03 b1       INTR #k4 / TRAP #k4            sec.6.5.13, sec.6.5.19
 *   0x04 / 0x06   XCC predicated execute         sec.6.5.9
 *   0x05 / 0x07   XCCPART                        sec.6.5.9
 *   0x08          RETCC                          sec.6.5.17
 *   0x20          NOP   (1 byte)                 sec.6.5.11
 *   0x21          RET   (1 byte)                 sec.6.5.16
 *   0x68 hh ll    B    short-relative            sec.6.5.2
 *   0x69 hh ll    CALL short-relative            sec.6.5.6
 *   0x6A ss dst   BCC  short-relative (8-bit)    sec.6.5.1
 *   0x6C / 0x6D   RPT / RPTCC                    sec.6.5.14
 *   0x6E / 0x6F   RPTBLOCAL / RPTB               sec.6.5.14
 *   0x9A hh ll d  BCC  long-relative (16-bit)    sec.6.5.1
 *   0x9B hh ll d  CALLCC long-relative           sec.6.5.5
 *   0x9C hh ll d  B    long-absolute (24-bit)    sec.6.5.2
 *   0x9D hh ll d  CALL long-absolute             sec.6.5.6
 *   0x9E / 0x9F   B / CALL with far() prefix     sec.6.5.2, sec.6.5.6
 *   0xD8 ...      BCC  far-absolute (5-byte)     sec.6.5.1
 *   0xD9 ...      CALLCC far-absolute            sec.6.5.5
 *   0xDA / 0xDB   BCC / BCCU short-form          sec.6.5.1
 *   0xDC / 0xDD   BCC / BCCU                     sec.6.5.1
 *   0xDE / 0xDF   BCC / BCCU                     sec.6.5.1
 *
 * Stack-affecting:
 *
 *   0x0D          PSHBOTH ACx (2 words)          sec.6.7.6
 *   0x0E          PSH dbl(ACx) (2 words)         sec.6.7
 *   0x0F          POP dbl(ACx) (2 words)
 *   0x61          PSH dbl(mem) (2 words)
 *   0x70          PSH dual-register (2 words)
 *   0x71          POP dual-register
 *   0x94          PSH ACx, mem (2 words)
 *
 * Byte-order note: C55x+ branch displacements and absolute targets are
 * stored MSB-first within the instruction stream even though the
 * surrounding processor is little-endian -- see SWPU104 sec.3.5. We use
 * rz_read_at_be16() / rz_read_at_be24() from rz_endian.h to extract
 * them unambiguously without unaligned-int dereference.
 */

/* Helper: sign-extend an n-bit value (for short conditional branch
 * relative displacements, which are 8-bit signed in some encodings
 * and 16-bit signed in others). */
static inline st32 sign_extend(ut32 v, ut32 bits) {
	const ut32 mask = (1u << bits) - 1;
	v &= mask;
	if (v & (1u << (bits - 1))) {
		return (st32)(v | ~mask);
	}
	return (st32)v;
}

/* Set conditional-jump fields: type=cjmp, jump=target, fail=fallthrough. */
static inline void set_cjmp(RzAnalysisOp *op, ut64 addr, ut64 target) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	op->jump = target;
	op->fail = addr + op->size;
	op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
}

/* Set conditional-call fields: type=ccall, jump=target, fail=fallthrough. */
static inline void set_ccall(RzAnalysisOp *op, ut64 addr, ut64 target) {
	op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
	op->jump = target;
	op->fail = addr + op->size;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = 2;
	op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
}

/* Set unconditional-call fields: type=call, jump=target. */
static inline void set_call(RzAnalysisOp *op, ut64 target) {
	op->type = RZ_ANALYSIS_OP_TYPE_CALL;
	op->jump = target;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = 2;
	op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
}

/* Set unconditional-jump fields. */
static inline void set_jmp(RzAnalysisOp *op, ut64 target) {
	op->type = RZ_ANALYSIS_OP_TYPE_JMP;
	op->jump = target;
	op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
}

/* Mark an instruction as a return, with stack accounting. */
static inline void set_ret(RzAnalysisOp *op) {
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	op->eob = true;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = -2;
}

/* Conditional return -- like RET but doesn't end the basic block
 * (fallthrough is possible if the condition is false). */
static inline void set_cret(RzAnalysisOp *op) {
	op->type = RZ_ANALYSIS_OP_TYPE_CRET;
	op->fail = op->addr + op->size;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = -2;
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

/* Record an immediate value (for "mov #k, dst" / "add #k, dst" etc.). */
static inline void set_imm(RzAnalysisOp *op, st64 val) {
	op->val = (ut64)val;
}

/* Record a memory access width (in bytes: 1, 2, or 4) for loads and
 * stores whose effective address is computed at runtime. */
static inline void set_mem_width(RzAnalysisOp *op, int width) {
	op->refptr = width;
	op->ptrsize = width;
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
static const char *const c55xp_acc_names[4] = { "ac0", "ac1", "ac2", "ac3" };

int tms320_c55x_plus_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len) {
	if (!op || !buf || len < 1) {
		return 0;
	}

	const ut32 ins_len = get_ins_len(buf[0]);
	if (ins_len == 0 || (int)ins_len > len) {
		return 0;
	}

	op->addr = addr;
	op->size = ins_len;
	op->type = RZ_ANALYSIS_OP_TYPE_NULL;

	switch (buf[0]) {
	/* ---- 0x00 family: NOP_16 / IDLE / RETI / to_word --------------- */
	case 0x00:
		if (ins_len < 2) {
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		}
		switch (buf[1]) {
		case 0x20: /* IDLE */
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
			break;
		case 0xc0: /* RETI */
			set_ret(op);
			set_dst_reg(op, "sp");
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		}
		break;

	/* ---- 0x01 family: rptsub --------------------------------------- */
	case 0x01:
		op->type = RZ_ANALYSIS_OP_TYPE_REP;
		break;

	/* ---- 0x02 family: B/CALL ACx indirect; both eob -----------------*/
	case 0x02: {
		if (ins_len < 2) {
			break;
		}
		/* Bit 7 of the second byte selects CALL (=1) vs B (=0).
		 * The low 2 bits of buf[1] select ACx (0..3). */
		const bool is_call = (buf[1] & 0x80) != 0;
		const ut8 ac_idx = buf[1] & 0x03;
		if (is_call) {
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = 2;
			set_dir(op, RZ_ANALYSIS_OP_DIR_EXEC);
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			op->eob = true;
			set_dir(op, RZ_ANALYSIS_OP_DIR_EXEC);
		}
		set_ireg(op, c55xp_acc_names[ac_idx]);
		op->fail = addr + ins_len;
		break;
	}

	/* ---- 0x03 family: INTR / TRAP / SWAP / SIM_TRIG ---------------
	 * Differentiated by buf[1] high nibble:
	 *   0x0?,0x1?,0x2?,0x3?  -> intr #k5     (SWPU104 6.5.13)
	 *   0x4?,0x5?            -> trap #k5     (SWPU104 6.5.19)
	 *   0x8?,0x9?,0xa?,0xb?  -> swap regs    (SWPU104 6.7.x)
	 *   0xc?..0xf?           -> sim_trig     (Wrigley silicon)
	 */
	case 0x03:
		if (ins_len < 2) {
			break;
		}
		switch (buf[1] & 0xc0) {
		case 0x00: /* intr #k5 */
			op->type = RZ_ANALYSIS_OP_TYPE_SWI;
			set_imm(op, buf[1] & 0x1f);
			op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
			break;
		case 0x40: /* trap #k5 */
			op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
			set_imm(op, buf[1] & 0x1f);
			op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
			break;
		case 0x80: /* swap */
			op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
			break;
		case 0xc0: /* sim_trig - Wrigley simulator trigger */
			op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
			op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
			break;
		}
		break;

	/* ---- 0x04 / 0x06: XCC (predicated execute) --------------------- */
	case 0x04:
	case 0x06:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;

	/* ---- 0x05 / 0x07: XCCPART -------------------------------------- */
	case 0x05:
	case 0x07:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;

	/* ---- 0x08: RETCC (conditional ret) ----------------------------- */
	case 0x08:
		set_cret(op);
		set_dst_reg(op, "sp");
		break;

	/* ---- 0x0A: BCLR/BSET status-register-bit ---------------------- */
	case 0x0a:
		/* Modifies a status-reg bit -- surface as MOV (the closest fit
		 * in the rizin optype set; the immediate-side bit pattern is
		 * not extracted here). */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	/* ---- 0x0C: AADD addr-add ------------------------------------- */
	case 0x0c:
		/* AADD K8, SP -- prologue/epilogue frame adjustment.
		 *
		 * Semantic: SP = SP + K8 (signed). rizin's convention is
		 * that op->stackptr is the amount by which SP *decreases*,
		 * so for AADD that is -K8. See c55x_analysis.c 0x4e and
		 * rz_analysis_op_apply_sp_effect() in librz/arch/op.c. */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (ins_len >= 2) {
			const st8 k8 = (st8)buf[1];
			set_imm(op, k8);
			set_dst_reg(op, "sp");
			set_disp(op, k8);
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -k8;
		}
		break;

	/* ---- 0x0D: PSHBOTH ------------------------------------------- */
	case 0x0d:
		op->type = RZ_ANALYSIS_OP_TYPE_UPUSH;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 2;
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
		break;

	/* ---- 0x0E / 0x0F: PSH/POP dbl -------------------------------- */
	case 0x0e:
		set_push(op, 2);
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
		break;
	case 0x0f:
		set_pop(op, -2);
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_READ);
		break;

	/* ---- 0x20: NOP ----------------------------------------------- */
	case 0x20:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;

	/* ---- 0x21: RET ----------------------------------------------- */
	case 0x21:
		set_ret(op);
		set_dst_reg(op, "sp");
		break;

	/* ---- 0x24-0x26: PSH variants --------------------------------- */
	case 0x24:
	case 0x25:
	case 0x26:
		set_push(op, 1);
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
		break;
	/* ---- 0x27: CIRC -- circular addressing helper ---------------- */
	case 0x27:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	/* ---- 0x60: DELAY --------------------------------------------- */
	case 0x60:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;

	/* ---- 0x61: PSH dbl(mem) -------------------------------------- */
	case 0x61:
		set_push(op, 2);
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
		break;

	/* ---- 0x68: B short-relative (16-bit) ------------------------- */
	case 0x68:
		if (ins_len >= 3) {
			const ut32 disp = rz_read_at_be16(buf, 1);
			set_jmp(op, addr + 3 + sign_extend(disp, 16));
			op->eob = true;
		}
		break;

	/* ---- 0x69: CALL short-relative ------------------------------- */
	case 0x69:
		if (ins_len >= 3) {
			const ut32 disp = rz_read_at_be16(buf, 1);
			set_call(op, addr + 3 + sign_extend(disp, 16));
			op->fail = addr + ins_len;
		}
		break;

	/* ---- 0x6A: BCC short-relative -------------------------------- */
	case 0x6a:
		if (ins_len >= 3) {
			/* 6A ss dst -- ss is 8-bit signed displacement. */
			set_cjmp(op, addr, addr + 3 + sign_extend(buf[1], 8));
		}
		break;

	/* ---- 0x6C: RPT ----------------------------------------------- */
	case 0x6c:
		op->type = RZ_ANALYSIS_OP_TYPE_REP;
		break;
	/* ---- 0x6D: RPTCC --------------------------------------------- */
	case 0x6d:
		op->type = RZ_ANALYSIS_OP_TYPE_REP;
		op->fail = addr + ins_len;
		break;
	/* ---- 0x6E/0x6F: RPTBLOCAL / RPTB ----------------------------- */
	case 0x6e:
	case 0x6f:
		op->type = RZ_ANALYSIS_OP_TYPE_REP;
		break;

	/* ---- 0x70/0x71: PSH/POP dual-register ------------------------ */
	case 0x70:
		set_push(op, 2);
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
		break;
	case 0x71:
		set_pop(op, -2);
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_READ);
		break;

	/* ---- 0x72: ASUB addr-sub ------------------------------------- */
	case 0x72:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;

	/* ---- 0x74-0x76: ADD/AND/{ABS/NEG/MAX/MIN} -------------------- */
	case 0x74:
		/* ADD smem,ACx -- but bit 7 of buf[2] flips ADD <-> SUB
		 * for one of the addressing-mode subforms. */
		if (ins_len >= 3 && (buf[2] & 0x80)) {
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		}
		break;
	case 0x75: op->type = RZ_ANALYSIS_OP_TYPE_AND; break;
	case 0x76:
		/* 0x76 family -- unary arithmetic on accumulators. The two
		 * MSB-of-byte bits select the subfamily:
		 *
		 *   buf[1] & 0x80 == 0:  ABS (buf[2]&0x80==0) or NEG (==1)
		 *   buf[1] & 0x80 == 1:  MAX (buf[2]&0x80==0) or MIN (==1)
		 *
		 * ABS has no clean rizin optype (the RZ_ANALYSIS_OP_TYPE_ABS
		 * code 44 is missing from the optypes table -- renders as
		 * 'undefined') so we leave it at NULL. */
		if (ins_len >= 3) {
			const ut8 b1_top = buf[1] & 0x80;
			const ut8 b2_top = buf[2] & 0x80;
			if (b1_top) {
				op->type = RZ_ANALYSIS_OP_TYPE_CMP; /* MAX/MIN */
				(void)b2_top;
			} else if (b2_top) {
				op->type = RZ_ANALYSIS_OP_TYPE_SUB; /* NEG */
			} else {
				/* ABS -- see comment above */
				op->type = RZ_ANALYSIS_OP_TYPE_NULL;
			}
		}
		break;

	/* ---- 0x77: MOV ----------------------------------------------- */
	case 0x77:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	/* ---- 0x79: ROUND --------------------------------------------- */
	case 0x79:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	/* ---- 0x7B: ADD #k7, ACx (b1 0x00-0x0F) or MOV #k8, Tx (0xB0-0xBF) */
	case 0x7b:
		if (ins_len >= 3) {
			set_imm(op, buf[2]);
			if ((buf[1] & 0xf0) == 0xb0) {
				op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			} else {
				op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			}
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		}
		break;

	/* ---- 0x80/0x81/0x82: ADD/SUB long-imm ------------------------ */
	case 0x80: op->type = RZ_ANALYSIS_OP_TYPE_ADD; break;
	case 0x81:
	case 0x82: op->type = RZ_ANALYSIS_OP_TYPE_SUB; break;

	/* ---- 0x84/0x85/0x86: AND/OR/XOR ------------------------------ */
	case 0x84: op->type = RZ_ANALYSIS_OP_TYPE_AND; break;
	case 0x85: op->type = RZ_ANALYSIS_OP_TYPE_OR; break;
	case 0x86: op->type = RZ_ANALYSIS_OP_TYPE_XOR; break;

	/* ---- 0x89: BCLR --------------------------------------------- */
	case 0x89:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	/* ---- 0x8D / 0x8E: ADD smem,ACx ------------------------------ */
	case 0x8d:
	case 0x8e:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;

	/* ---- 0x90/0x91/0x92/0x93/0x94: various ----------------------- */
	case 0x90: op->type = RZ_ANALYSIS_OP_TYPE_ADD; break;
	case 0x91: op->type = RZ_ANALYSIS_OP_TYPE_AND; break; /* btstclr */
	case 0x92:
	case 0x93: op->type = RZ_ANALYSIS_OP_TYPE_MUL; break; /* sqrm */
	case 0x94:
		set_push(op, 2);
		set_dst_reg(op, "sp");
		set_dir(op, RZ_ANALYSIS_OP_DIR_WRITE);
		break;

	/* ---- 0x9A: BCC long-relative (16-bit) ------------------------ */
	case 0x9a:
		if (ins_len >= 4) {
			const ut32 disp = rz_read_at_be16(buf, 1);
			set_cjmp(op, addr, addr + ins_len + sign_extend(disp, 16));
		}
		break;

	/* ---- 0x9B: CALLCC long-relative ------------------------------ */
	case 0x9b:
		if (ins_len >= 4) {
			const ut32 disp = rz_read_at_be16(buf, 1);
			set_ccall(op, addr, addr + ins_len + sign_extend(disp, 16));
		}
		break;

	/* ---- 0x9C: B long-absolute (24-bit) -------------------------- */
	case 0x9c:
		if (ins_len >= 4) {
			set_jmp(op, rz_read_at_be24(buf, 1));
			op->eob = true;
		}
		break;

	/* ---- 0x9D: CALL long-absolute -------------------------------- */
	case 0x9d:
		if (ins_len >= 4) {
			set_call(op, rz_read_at_be24(buf, 1));
			op->fail = addr + ins_len;
		}
		break;

	/* ---- 0x9E / 0x9F: B / CALL with far() prefix ----------------- */
	case 0x9e:
		if (ins_len >= 4) {
			set_jmp(op, rz_read_at_be24(buf, 1));
			op->eob = true;
		}
		break;
	case 0x9f:
		if (ins_len >= 4) {
			set_call(op, rz_read_at_be24(buf, 1));
			op->fail = addr + ins_len;
		}
		break;

	/* ---- 0xA1/0xA4/0xA6/0xA7/0xA8: arith & compare --------------- */
	case 0xa1: op->type = RZ_ANALYSIS_OP_TYPE_ADD; break;
	case 0xa4: op->type = RZ_ANALYSIS_OP_TYPE_CMP; break;
	case 0xa6:
	case 0xa7: op->type = RZ_ANALYSIS_OP_TYPE_SHL; break; /* SFTS/SFTL */
	case 0xa8: op->type = RZ_ANALYSIS_OP_TYPE_ROL; break;
	case 0xa9: op->type = RZ_ANALYSIS_OP_TYPE_MOV; break; /* EXP */
	case 0xaa:
	case 0xab: op->type = RZ_ANALYSIS_OP_TYPE_MUL; break;
	case 0xae:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;

	/* ---- 0xB0: BCC short-form (3-byte conditional jump) ---------- */
	case 0xb0:
		if (ins_len >= 4) {
			const ut32 disp = rz_read_at_be16(buf, 2);
			set_cjmp(op, addr, addr + ins_len + sign_extend(disp, 16));
		}
		break;
	case 0xb1:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case 0xb2:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case 0xb3:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;

	/* ---- 0xB8/0xB9/0xBA/0xBB: MAC/MPY families ------------------- */
	case 0xb8:
	case 0xb9:
	case 0xba:
	case 0xbb: op->type = RZ_ANALYSIS_OP_TYPE_MUL; break;
	case 0xbc:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break; /* BFXTR */

	/* ---- 0xC1/0xC3/0xC5: AND/OR/XOR long-imm ---------------------
	 * For 0xC5 specifically, bit 7 of buf[1] selects XOR (=1);
	 * if not XOR, bit 7 of buf[2] picks OR (=1) over AND (=0). The
	 * 0xC1 and 0xC3 slots are AND / OR variants for different
	 * addressing forms (mem vs ACx) -- they have only one operation. */
	case 0xc1: op->type = RZ_ANALYSIS_OP_TYPE_AND; break;
	case 0xc3: op->type = RZ_ANALYSIS_OP_TYPE_OR; break;
	case 0xc5:
		if (ins_len >= 3 && (buf[1] & 0x80)) {
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		} else if (ins_len >= 3 && (buf[2] & 0x80)) {
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
		}
		break;
	case 0xc6: op->type = RZ_ANALYSIS_OP_TYPE_MOV; break; /* BFXTR / BFXPA - bit-field extract / pack */
	case 0xc7: op->type = RZ_ANALYSIS_OP_TYPE_MUL; break; /* MPYK */
	case 0xc8:
	case 0xc9:
	case 0xca:
	case 0xcb: op->type = RZ_ANALYSIS_OP_TYPE_MUL; break;
	case 0xce: op->type = RZ_ANALYSIS_OP_TYPE_MUL; break; /* SQDST */

	case 0xd1: op->type = RZ_ANALYSIS_OP_TYPE_MOV; break; /* COPY */
	case 0xd2: op->type = RZ_ANALYSIS_OP_TYPE_SUB; break;
	case 0xd4:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break; /* MAXDIFF */

	/* ---- 0xD8: BCC far-absolute (5-byte) ------------------------- */
	case 0xd8:
		if (ins_len >= 5) {
			set_cjmp(op, addr, rz_read_at_be24(buf, 1));
		}
		break;

	/* ---- 0xD9: CALLCC far-absolute (5-byte) ---------------------- */
	case 0xd9:
		if (ins_len >= 5) {
			set_ccall(op, addr, rz_read_at_be24(buf, 1));
		}
		break;

	/* ---- 0xDA-0xDF: BCC/BCCU register-compare conditional ------- */
	case 0xda:
	case 0xdb:
	case 0xdc:
	case 0xdd:
	case 0xde:
	case 0xdf:
		/* 5-byte form: DA/DB ARx cmp RRx ll hh dd (16-bit signed disp).
		 * The target is encoded as a relative 16-bit displacement
		 * at bytes 3..4 in BE byte order. */
		if (ins_len >= 5) {
			const ut32 disp = rz_read_at_be16(buf, 3);
			set_cjmp(op, addr, addr + ins_len + sign_extend(disp, 16));
		}
		break;

	/* ---- 0xE0/0xE1/0xE2/0xE3/0xE8/0xE9/0xEC/0xED: MAC/MPY parallel  */
	case 0xe0:
	case 0xe1:
	case 0xe2:
	case 0xe3:
	case 0xe8:
	case 0xe9:
	case 0xec:
	case 0xed: op->type = RZ_ANALYSIS_OP_TYPE_MUL; break;
	case 0xea:
	case 0xeb: op->type = RZ_ANALYSIS_OP_TYPE_LEA; break; /* AMAR parallel */
	case 0xee: op->type = RZ_ANALYSIS_OP_TYPE_MUL; break; /* MPYK */

	default:
		/* MOV-family bytes 0x48-0x4F (mov #imm, mem) - common in
		 * real firmware, classified as MOV here. */
		if (buf[0] >= 0x48 && buf[0] <= 0x4f) {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		}
		/* Memory<->register MOV cluster, byte 0x50-0x5F. Per the
		 * SWPU104 encoding map: 0x50 (mem <- ARx high), 0x51-0x53
		 * (mem <- ACx parts), 0x54-0x57 (COPY), 0x58 (mem -> ACx),
		 * 0x59 (mem<<16 -> ACx), 0x5A/0x5B (mem -> ACx halves),
		 * 0x5C (40-bit dbl mov), 0x5D (ACx >> 1 -> dbl mem). All
		 * MOV-family for analysis purposes; the 0x5C / 0x5D dbl
		 * forms access 4 bytes, the rest 2. */
		if (buf[0] >= 0x50 && buf[0] <= 0x5f) {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			set_mem_width(op, (buf[0] == 0x5c || buf[0] == 0x5d) ? 4 : 2);
			break;
		}
		/* AMAR family - address-modifying instructions (LEA-like). */
		if (buf[0] == 0x62 || buf[0] == 0x63) {
			op->type = RZ_ANALYSIS_OP_TYPE_LEA;
			break;
		}
		/* MOV-family bytes 0x88, 0x8A: ACx <-> mem variants. */
		if (buf[0] == 0x88 || buf[0] == 0x8a) {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		}
		/* 0x8C: ADD with carry, mem -> ACx. */
		if (buf[0] == 0x8c) {
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		}
		/* 0x97: dual-mem MOV. */
		if (buf[0] == 0x97) {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		}
		/* 0xA0, 0xAC, 0xAD: MOV with parallel dual addressing or
		 * MOV #imm,ACx (long form). */
		if (buf[0] == 0xa0 || buf[0] == 0xac || buf[0] == 0xad) {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		}
		/* 0xB4, 0xB5: MOV with rounding / shift. */
		if (buf[0] == 0xb4 || buf[0] == 0xb5) {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		}
		/* 0xB6, 0xB7: ADD with shift (T-register or immediate). */
		if (buf[0] == 0xb6 || buf[0] == 0xb7) {
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		}
		/* 0xC0, 0xC2, 0xC4: ADD #k16 with optional shift. */
		if (buf[0] == 0xc0 || buf[0] == 0xc2 || buf[0] == 0xc4) {
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		}
		/* 0xCC: dual-instruction packed encoding (ADD :: MOV). The
		 * primary operation that affects control flow / data flow
		 * is the ADD, so classify as ADD. */
		if (buf[0] == 0xcc) {
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		}
		/* 0xD0: MOV ACx, dbl(*(#abs24)) -- 4-byte (dbl) memory move. */
		if (buf[0] == 0xd0) {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			set_mem_width(op, 4);
			break;
		}
		/* 0x2E, 0x2F: XCCPART predicated execute. */
		if (buf[0] == 0x2e || buf[0] == 0x2f) {
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
			break;
		}
		/* 0x0B (ecopr__), 0x23 (estop_byte): pseudo opcodes
		 * specific to the Wrigley silicon. Used as emulation /
		 * coprocessor traps; classify as TRAP. */
		if (buf[0] == 0x0b || buf[0] == 0x23) {
			op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
			op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
			break;
		}
		/* Anything we have not catalogued: leave op->type at its
		 * default (NULL).  We intentionally do NOT mark unknown
		 * leading bytes as ILL: many bytes in the 0x10..0x1f and
		 * 0x30..0x3f ranges are valid parallel-instruction prefixes
		 * (0x39 = MACK, etc.) that decode to multi-instruction
		 * forms only when paired with the right following bytes.
		 * Flagging them as ILL would mislead the basic-block
		 * walker and the colorizer, which treats ILL as
		 * "definitely-invalid" and renders the opcode in bold
		 * red. Leaving as NULL lets the disassembler's own
		 * "invalid" rendering speak for itself per-instruction. */
		break;
	}

	return op->size;
}
