// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util.h>
#include "c28x.h"

static bool c28x_is_branch(const C28xInsn *insn) {
	switch (insn->op_type) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
		return true;
	default:
		return false;
	}
}

/**
 * \brief Fill \p op from a decoded instruction.
 * \param insn decoded instruction
 * \param addr byte address of the instruction
 * \param op receives type, size, jump/fail targets and stack effects
 *
 * Branch targets are taken from the decoded operand, which already carries an
 * absolute byte address. Conditional forms also get \p fail set to the next
 * instruction so the analyzer can follow both edges.
 */
RZ_IPI void c28x_fill_analysis(const C28xInsn *insn, ut64 addr, RZ_OUT RzAnalysisOp *op) {
	rz_return_if_fail(insn && op);
	op->size = insn->size;
	op->type = insn->op_type;
	op->addr = addr;
	op->cond = RZ_TYPE_COND_AL;

	if (c28x_is_branch(insn)) {
		for (ut8 i = 0; i < insn->nops; i++) {
			const C28xOperand *o = &insn->ops[i];
			if (o->kind == C28X_OP_PCREL || o->kind == C28X_OP_PMA) {
				op->jump = (ut64)o->imm;
				break;
			}
		}
		if (op->type == RZ_ANALYSIS_OP_TYPE_CJMP) {
			op->fail = addr + insn->size;
		}
	}

	// An unconditional XB/XCALL is encoded as the COND = UNC case of the
	// conditional form; report it as a plain jump/call so the analyzer does not
	// grow a false fall-through edge.
	if (insn->cond == C28X_COND_UNC) {
		if (op->type == RZ_ANALYSIS_OP_TYPE_CJMP && op->jump) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->fail = UT64_MAX;
		} else if (op->type == RZ_ANALYSIS_OP_TYPE_CRET) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
		}
	}

	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_PUSH:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = C28X_WORD_BYTES;
		break;
	case RZ_ANALYSIS_OP_TYPE_POP:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -C28X_WORD_BYTES;
		break;
	default:
		break;
	}

	// ADDB/SUBB SP,#7bit is how the compiler opens and closes a frame; report
	// the adjustment in bytes so variable analysis can track locals.
	if (insn->nops == 2 && insn->ops[0].kind == C28X_OP_REG &&
		insn->ops[0].reg == C28X_REG_SP && insn->ops[1].kind == C28X_OP_IMM) {
		const st64 words = insn->ops[1].imm;
		if (op->type == RZ_ANALYSIS_OP_TYPE_ADD) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = words * C28X_WORD_BYTES;
		} else if (op->type == RZ_ANALYSIS_OP_TYPE_SUB) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -words * C28X_WORD_BYTES;
		}
	}
}

static const char *c28x_opkind_name(C28xOpKind kind) {
	switch (kind) {
	case C28X_OP_REG: return "reg";
	case C28X_OP_MEM: return "mem";
	case C28X_OP_IMM: return "imm";
	case C28X_OP_SHIFT: return "shift";
	case C28X_OP_COND: return "cond";
	case C28X_OP_PCREL: return "pcrel";
	case C28X_OP_PMA: return "pma";
	case C28X_OP_DMA: return "dma";
	case C28X_OP_PORT: return "port";
	case C28X_OP_MODE: return "mode";
	default: return "invalid";
	}
}

static const char *c28x_addrmode_name(C28xAddrMode mode) {
	switch (mode) {
	case C28X_AM_DP: return "dp";
	case C28X_AM_SP: return "sp";
	case C28X_AM_SP_POSTINC: return "sp_postinc";
	case C28X_AM_SP_PREDEC: return "sp_predec";
	case C28X_AM_XAR_NONE: return "xar";
	case C28X_AM_XAR_POSTINC: return "xar_postinc";
	case C28X_AM_XAR_POSTDEC: return "xar_postdec";
	case C28X_AM_XAR_PREDEC: return "xar_predec";
	case C28X_AM_XAR_AR0: return "xar_ar0";
	case C28X_AM_XAR_AR1: return "xar_ar1";
	case C28X_AM_XAR_IMM: return "xar_imm";
	case C28X_AM_ARP: return "arp";
	case C28X_AM_ARP_POSTINC: return "arp_postinc";
	case C28X_AM_ARP_POSTDEC: return "arp_postdec";
	case C28X_AM_ARP_IDX_INC: return "arp_idx_inc";
	case C28X_AM_ARP_IDX_DEC: return "arp_idx_dec";
	case C28X_AM_ARP_BR_INC: return "arp_br_inc";
	case C28X_AM_ARP_BR_DEC: return "arp_br_dec";
	case C28X_AM_ARP_SET: return "arp_set";
	case C28X_AM_CIRC: return "circular";
	case C28X_AM_REG: return "reg";
	default: return "none";
	}
}

/**
 * \brief Structured dump of \p insn's operands for RZ_ANALYSIS_OP_MASK_OPEX.
 * \return an owned RzStructuredData, or NULL on allocation failure
 */
RZ_IPI RZ_OWN RzStructuredData *c28x_opex(const C28xInsn *insn) {
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
	rz_structured_data_map_add_string(opex, "mnemonic", insn->mnemonic);
	if (insn->cond != C28X_COND_UNC) {
		rz_structured_data_map_add_string(opex, "cond", c28x_cond_name(insn->cond));
	}
	if (insn->repeatable) {
		rz_structured_data_map_add_boolean(opex, "repeatable", true);
	}
	RzStructuredData *operands = rz_structured_data_map_add_array(opex, "operands");
	if (!operands) {
		rz_structured_data_free(root);
		return NULL;
	}
	for (ut8 i = 0; i < insn->nops; i++) {
		const C28xOperand *o = &insn->ops[i];
		RzStructuredData *ent = rz_structured_data_array_add_map(operands);
		if (!ent) {
			break;
		}
		rz_structured_data_map_add_string(ent, "type", c28x_opkind_name(o->kind));
		switch (o->kind) {
		case C28X_OP_REG:
			rz_structured_data_map_add_string(ent, "value", c28x_reg_name(o->reg));
			if (o->byte_sel) {
				rz_structured_data_map_add_string(ent, "part", o->byte_sel == 1 ? "lsb" : "msb");
			}
			break;
		case C28X_OP_MEM:
			rz_structured_data_map_add_string(ent, "mode", c28x_addrmode_name(o->mode));
			rz_structured_data_map_add_boolean(ent, "wide", o->wide);
			if (o->mode == C28X_AM_REG) {
				rz_structured_data_map_add_string(ent, "reg", c28x_reg_name(o->reg));
			} else {
				rz_structured_data_map_add_unsigned(ent, "arn", o->arn, false);
				rz_structured_data_map_add_unsigned(ent, "disp", o->off, false);
			}
			break;
		case C28X_OP_COND:
			rz_structured_data_map_add_string(ent, "value", c28x_cond_name((ut8)o->imm));
			break;
		case C28X_OP_PCREL:
		case C28X_OP_PMA:
		case C28X_OP_DMA:
		case C28X_OP_PORT:
			rz_structured_data_map_add_unsigned(ent, "value", (ut64)o->imm, true);
			break;
		default:
			rz_structured_data_map_add_signed(ent, "value", o->imm);
			break;
		}
	}
	return root;
}
