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
RZ_IPI void c28x_fill_analysis(RZ_NONNULL const C28xInsn *insn, ut64 addr,
	RZ_OUT RzAnalysisOp *op) {
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
		} else if (op->type == RZ_ANALYSIS_OP_TYPE_CCALL) {
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
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

static const char *const c28x_opkind_names[] = {
	[C28X_OP_REG] = "reg",
	[C28X_OP_MEM] = "mem",
	[C28X_OP_IMM] = "imm",
	[C28X_OP_SHIFT] = "shift",
	[C28X_OP_COND] = "cond",
	[C28X_OP_PCREL] = "pcrel",
	[C28X_OP_PMA] = "pma",
	[C28X_OP_PMA_IND] = "pma_ind",
	[C28X_OP_PMA_DP] = "pma_dp",
	[C28X_OP_DMA] = "dma",
	[C28X_OP_PORT] = "port",
	[C28X_OP_MODE] = "mode",
	[C28X_OP_INTR] = "intr",
};

static const char *const c28x_addrmode_names[] = {
	[C28X_AM_DP] = "dp",
	[C28X_AM_SP] = "sp",
	[C28X_AM_SP_POSTINC] = "sp_postinc",
	[C28X_AM_SP_PREDEC] = "sp_predec",
	[C28X_AM_XAR_NONE] = "xar",
	[C28X_AM_XAR_POSTINC] = "xar_postinc",
	[C28X_AM_XAR_POSTDEC] = "xar_postdec",
	[C28X_AM_XAR_MOD_INC] = "xar_mod_inc",
	[C28X_AM_XAR_MOD_DEC] = "xar_mod_dec",
	[C28X_AM_XAR_PREDEC] = "xar_predec",
	[C28X_AM_XAR_AR0] = "xar_ar0",
	[C28X_AM_XAR_AR1] = "xar_ar1",
	[C28X_AM_XAR_IMM] = "xar_imm",
	[C28X_AM_ARP] = "arp",
	[C28X_AM_ARP_POSTINC] = "arp_postinc",
	[C28X_AM_ARP_POSTDEC] = "arp_postdec",
	[C28X_AM_ARP_IDX_INC] = "arp_idx_inc",
	[C28X_AM_ARP_IDX_DEC] = "arp_idx_dec",
	[C28X_AM_ARP_BR_INC] = "arp_br_inc",
	[C28X_AM_ARP_BR_DEC] = "arp_br_dec",
	[C28X_AM_ARP_SET] = "arp_set",
	[C28X_AM_CIRC] = "circular",
	[C28X_AM_REG] = "reg",
};

static const char *c28x_opkind_name(C28xOpKind kind) {
	if ((size_t)kind >= RZ_ARRAY_SIZE(c28x_opkind_names) || !c28x_opkind_names[kind]) {
		return "invalid";
	}
	return c28x_opkind_names[kind];
}

static const char *c28x_addrmode_name(C28xAddrMode mode) {
	if ((size_t)mode >= RZ_ARRAY_SIZE(c28x_addrmode_names) || !c28x_addrmode_names[mode]) {
		return "none";
	}
	return c28x_addrmode_names[mode];
}

/**
 * \brief Structured dump of \p insn's operands for RZ_ANALYSIS_OP_MASK_OPEX.
 * \return an owned RzStructuredData, or NULL on allocation failure
 */
RZ_IPI RZ_OWN RzStructuredData *c28x_opex(RZ_NONNULL const C28xInsn *insn) {
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
				rz_structured_data_map_add_string(ent, "part",
					o->byte_sel == 1 ? "lsb" : "msb");
			}
			break;
		case C28X_OP_MEM:
			rz_structured_data_map_add_string(ent, "mode", c28x_addrmode_name(o->mode));
			rz_structured_data_map_add_boolean(ent, "wide", o->wide);
			if (o->mode == C28X_AM_REG) {
				rz_structured_data_map_add_string(ent, "reg",
					c28x_reg_name(o->reg));
			} else {
				rz_structured_data_map_add_unsigned(ent, "arn", o->arn, false);
				rz_structured_data_map_add_unsigned(ent, "disp", o->off, false);
			}
			break;
		case C28X_OP_COND:
			rz_structured_data_map_add_string(ent, "value",
				c28x_cond_name((ut8)o->imm));
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
