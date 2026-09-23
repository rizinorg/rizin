// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "c6x.h"

// Base-register write-back and offset direction; the offset itself is reported
// separately as "index" or "disp".
static const char *opex_mode_name(C6xAddrMode mode) {
	switch (mode) {
	case C6X_AM_NEG_CST:
	case C6X_AM_NEG_REG:
		return "neg-offset";
	case C6X_AM_PREDEC_CST:
	case C6X_AM_PREDEC_REG:
		return "pre-dec";
	case C6X_AM_PREINC_CST:
	case C6X_AM_PREINC_REG:
		return "pre-inc";
	case C6X_AM_POSTDEC_CST:
	case C6X_AM_POSTDEC_REG:
		return "post-dec";
	case C6X_AM_POSTINC_CST:
	case C6X_AM_POSTINC_REG:
		return "post-inc";
	default:
		return "pos-offset";
	}
}

// Functional unit and datapath side as the disassembly spells them, e.g. "l1".
static void opex_unit_str(const C6xInsn *insn, char out[3]) {
	char u;
	switch (insn->unit) {
	case C6X_UNIT_L: u = 'l'; break;
	case C6X_UNIT_S: u = 's'; break;
	case C6X_UNIT_M: u = 'm'; break;
	default: u = 'd'; break;
	}
	out[0] = u;
	out[1] = insn->unit_side == C6X_SIDE_A ? '1' : '2';
	out[2] = '\0';
}

// One entry of the opex operands array.
static void opex_add_operand(RzStructuredData *operands, const C6xOperand *o) {
	RzStructuredData *ent = rz_structured_data_array_add_map(operands);
	if (!ent) {
		return;
	}
	switch (o->kind) {
	case C6X_OP_REG:
	case C6X_OP_REGPAIR:
	case C6X_OP_REGQUAD: {
		char *name = c6x_reg_operand_str(o);
		if (!name) {
			return;
		}
		rz_structured_data_map_add_string(ent, "type",
			o->kind == C6X_OP_REG ? "reg" : o->kind == C6X_OP_REGPAIR ? "regpair"
										  : "regquad");
		rz_structured_data_map_add_string(ent, "value", name);
		free(name);
		break;
	}
	case C6X_OP_UNITMASK: {
		// The SPMASK unit list reads as the assembler spells it, so opex and the
		// mnemonic agree.
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		for (ut8 u = 0; u < 8; u++) {
			if (o->v.units & (1u << u)) {
				rz_strbuf_appendf(&sb, "%s%s", rz_strbuf_length(&sb) ? "," : "", c6x_unit_name(u));
			}
		}
		rz_structured_data_map_add_string(ent, "type", "units");
		rz_structured_data_map_add_string(ent, "value", rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);
		break;
	}
	case C6X_OP_CTRLREG:
		rz_structured_data_map_add_string(ent, "type", "ctrl");
		rz_structured_data_map_add_string(ent, "value", o->v.ctrl ? o->v.ctrl : "?");
		break;
	case C6X_OP_IMM:
	case C6X_OP_PCREL:
		// A PC-relative target is already resolved to an absolute address by the
		// decoder, so it is reported like any other immediate.
		rz_structured_data_map_add_string(ent, "type", "imm");
		rz_structured_data_map_add_signed(ent, "value", o->v.imm.value);
		break;
	case C6X_OP_MEM: {
		rz_structured_data_map_add_string(ent, "type", "mem");
		char *base = rz_str_newf("%c%u", o->v.mem.base_side ? 'b' : 'a', o->v.mem.base);
		if (base) {
			rz_structured_data_map_add_string(ent, "base", base);
			free(base);
		}
		bool reg_off = o->v.mem.mode == C6X_AM_NEG_REG || o->v.mem.mode == C6X_AM_POS_REG ||
			o->v.mem.mode == C6X_AM_PREDEC_REG || o->v.mem.mode == C6X_AM_PREINC_REG ||
			o->v.mem.mode == C6X_AM_POSTDEC_REG || o->v.mem.mode == C6X_AM_POSTINC_REG;
		if (reg_off) {
			char *idx = rz_str_newf("%c%u", o->v.mem.base_side ? 'b' : 'a', o->v.mem.off_reg);
			if (idx) {
				rz_structured_data_map_add_string(ent, "index", idx);
				free(idx);
			}
		} else {
			// The constant is reported as encoded; "scaled" says whether the
			// hardware multiplies it by the access size (bracket syntax).
			rz_structured_data_map_add_signed(ent, "disp", (st64)o->v.mem.off_cst);
		}
		rz_structured_data_map_add_boolean(ent, "scaled", o->v.mem.scaled);
		rz_structured_data_map_add_string(ent, "mode", opex_mode_name(o->v.mem.mode));
		break;
	}
	default:
		rz_warn_if_reached();
		rz_structured_data_map_add_string(ent, "type", "invalid");
		break;
	}
}

/**
 * Build the RzAnalysisOp::opex operand detail of a decoded instruction: the
 * operand list plus the C6000 issue properties that RzAnalysisOp itself cannot
 * express -- the functional unit and side, the cross-path bit, and the
 * predicate register with its test sense. Execute-packet continuation is
 * deliberately left out: it depends on the previously decoded word rather than
 * on this instruction, and the disassembly already carries it as "||".
 */
RZ_IPI RZ_OWN RzStructuredData *c6x_opex(const C6xInsn *insn) {
	rz_return_val_if_fail(insn, NULL);
	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}
	RzStructuredData *opex = rz_structured_data_map_add_map(root, "opex");
	if (!opex) {
		rz_structured_data_free(root);
		return NULL;
	}
	if (insn->unit != C6X_UNIT_NONE) {
		char unit[3];
		opex_unit_str(insn, unit);
		rz_structured_data_map_add_string(opex, "unit", unit);
	}
	if (insn->cross) {
		rz_structured_data_map_add_boolean(opex, "cross", true);
	}
	// creg == 0 with z == 1 is an opcode bit, not a predicate, so the guard is
	// reported only when a predicate register is actually named.
	const char *pred = insn->creg ? c6x_pred_reg_name(insn->creg) : NULL;
	if (pred) {
		rz_structured_data_map_add_string(opex, "cond_reg", pred);
		rz_structured_data_map_add_boolean(opex, "cond_zero", insn->z != 0);
	}
	RzStructuredData *operands = rz_structured_data_map_add_array(opex, "operands");
	if (!operands) {
		rz_structured_data_free(root);
		return NULL;
	}
	for (ut8 i = 0; i < insn->nops; i++) {
		opex_add_operand(operands, &OP(i));
	}
	return root;
}

/**
 * Fill an RzAnalysisOp from a decoded instruction: the type, size and
 * control-flow targets that come from the instruction alone. A predicated
 * instruction (creg != 0) is conditional, which turns a branch into a CJMP.
 */
RZ_IPI void c6x_fill_analysis(const C6xArchDesc *desc, const C6xInsn *insn, ut64 addr, RZ_OUT RzAnalysisOp *op) {
	op->id = insn->id;
	rz_return_if_fail(desc && insn && op);
	op->size = insn->size; // 4 for a normal word, 2 for a compact instruction
	op->type = insn->op_type;
	op->family = insn->is_fp ? RZ_ANALYSIS_OP_FAMILY_FPU : RZ_ANALYSIS_OP_FAMILY_CPU;
	// An instruction is predicated only when it names a predicate register
	// (creg != 0). z is the test sense and is meaningful only alongside creg;
	// creg == 0 with z == 1 is an opcode bit (CALLP, the C66x complex ops),
	// not a predicate.
	bool conditional = insn->creg != 0;

	// Expose a constant operand as the op value, and treat an ADD/SUB that
	// writes the stack pointer (B15 in the C6000 EABI) as a frame adjustment.
	for (ut8 i = 0; i < insn->nops; i++) {
		if (OP(i).kind == C6X_OP_IMM) {
			op->val = OP(i).v.imm.value;
			break;
		}
	}
	if ((insn->op_type == RZ_ANALYSIS_OP_TYPE_ADD || insn->op_type == RZ_ANALYSIS_OP_TYPE_SUB) && insn->nops >= 2) {
		const C6xOperand *dst = &OP(insn->nops - 1);
		bool sp_dst = dst->kind == C6X_OP_REG && dst->v.reg.side == 1 && dst->v.reg.num == 15;
		bool sp_src = insn->nops == 2; // 2-op ADDK/SUBK operate on dst in place
		st64 k = 0;
		bool has_imm = false;
		for (ut8 i = 0; i + 1 < insn->nops; i++) {
			if (OP(i).kind == C6X_OP_IMM) {
				k = OP(i).v.imm.value;
				has_imm = true;
			} else if (OP(i).kind == C6X_OP_REG && OP(i).v.reg.side == 1 && OP(i).v.reg.num == 15) {
				sp_src = true;
			}
		}
		if (sp_dst && sp_src && has_imm) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = insn->op_type == RZ_ANALYSIS_OP_TYPE_SUB ? -k : k;
		}
	}

	switch (insn->op_type) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
		// B displacement is relative to the fetch-packet base (PCE1), i.e. the
		// address masked to the 32-byte packet, not to the branch instruction.
		if (insn->nops > 0 && OP(0).kind == C6X_OP_PCREL) {
			op->jump = c6x_packet_base(addr) + OP(0).v.imm.value;
		}
		if (conditional) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = addr + insn->size;
		}
		// A branch has five delay slots; the transfer is not immediate, but the
		// jump target is what matters for the CFG.
		op->delay = 5;
		break;
	case RZ_ANALYSIS_OP_TYPE_CALL:
		// CALLP takes its target the same way B does, from the fetch-packet base
		// (SPRUFE8B: cst21 = (label - PCE1) >> 2). Its five delay slots are
		// filled by hardware -- the CPU inserts an implied NOP 5 over E2-E6 --
		// so unlike B the transfer needs no delay for the CFG, and the callee
		// returns to the execute packet after this one.
		if (insn->nops > 0 && OP(0).kind == C6X_OP_PCREL) {
			op->jump = c6x_packet_base(addr) + OP(0).v.imm.value;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_RJMP:
		// B to a register (e.g. B B3 return); target is data-dependent. B3 is the
		// return-address register in the C6x ABI, so an unconditional B .S2 B3 is
		// a function return.
		if (insn->nops > 0 && OP(0).kind == C6X_OP_REG &&
			OP(0).v.reg.side == 1 && OP(0).v.reg.num == 3) {
			op->type = conditional ? RZ_ANALYSIS_OP_TYPE_CRET : RZ_ANALYSIS_OP_TYPE_RET;
		} else if (conditional) {
			op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
			op->fail = addr + insn->size;
		}
		op->delay = 5;
		break;
	case RZ_ANALYSIS_OP_TYPE_CJMP:
		// BDEC/BPOS resolve a PC-relative target (PCE1 + scst10*4) like B, but
		// the branch is taken on a register test, so it is always two-way -- the
		// fall-through is the next execute packet.
		if (insn->nops > 0 && OP(0).kind == C6X_OP_PCREL) {
			op->jump = c6x_packet_base(addr) + OP(0).v.imm.value;
			op->fail = addr + insn->size;
		}
		op->delay = 5;
		break;
	default:
		if (conditional && insn->op_type != RZ_ANALYSIS_OP_TYPE_NOP) {
			op->cond = RZ_TYPE_COND_AL; // predicated, but not a branch
		}
		break;
	}
}
