// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "c28x.h"

static const char *const c28x_reg_names[] = {
	[C28X_REG_NONE] = "",
	[C28X_REG_ACC] = "acc",
	[C28X_REG_AH] = "ah",
	[C28X_REG_AL] = "al",
	[C28X_REG_P] = "p",
	[C28X_REG_PH] = "ph",
	[C28X_REG_PL] = "pl",
	[C28X_REG_XT] = "xt",
	[C28X_REG_T] = "t",
	[C28X_REG_TL] = "tl",
	[C28X_REG_XAR0] = "xar0",
	[C28X_REG_XAR1] = "xar1",
	[C28X_REG_XAR2] = "xar2",
	[C28X_REG_XAR3] = "xar3",
	[C28X_REG_XAR4] = "xar4",
	[C28X_REG_XAR5] = "xar5",
	[C28X_REG_XAR6] = "xar6",
	[C28X_REG_XAR7] = "xar7",
	[C28X_REG_AR0] = "ar0",
	[C28X_REG_AR1] = "ar1",
	[C28X_REG_AR2] = "ar2",
	[C28X_REG_AR3] = "ar3",
	[C28X_REG_AR4] = "ar4",
	[C28X_REG_AR5] = "ar5",
	[C28X_REG_AR6] = "ar6",
	[C28X_REG_AR7] = "ar7",
	[C28X_REG_SP] = "sp",
	[C28X_REG_DP] = "dp",
	[C28X_REG_PC] = "pc",
	[C28X_REG_RPC] = "rpc",
	[C28X_REG_ST0] = "st0",
	[C28X_REG_ST1] = "st1",
	[C28X_REG_IER] = "ier",
	[C28X_REG_IFR] = "ifr",
	[C28X_REG_DBGIER] = "dbgier",
	[C28X_REG_OVC] = "ovc",
	[C28X_REG_PM] = "pm",
	[C28X_REG_ARP] = "arp",
	[C28X_REG_P_PM] = "p << pm",
	[C28X_REG_ACC_P] = "acc:p",
	[C28X_REG_AR1_AR0] = "ar1:ar0",
	[C28X_REG_AR3_AR2] = "ar3:ar2",
	[C28X_REG_AR5_AR4] = "ar5:ar4",
	[C28X_REG_AR1H_AR0H] = "ar1h:ar0h",
	[C28X_REG_DP_ST1] = "dp:st1",
	[C28X_REG_T_ST0] = "t:st0",
	[C28X_REG_AMODE] = "amode",
	[C28X_REG_OBJMODE] = "objmode",
	[C28X_REG_M0M1MAP] = "m0m1map",
	[C28X_REG_XF] = "xf",
	[C28X_REG_NMI] = "nmi",
	[C28X_REG_EMUINT] = "emuint",
};

static const char *const c28x_cond_names[16] = {
	"neq", "eq", "gt", "geq", "lt", "leq", "hi", "his",
	"lo", "los", "nov", "ov", "ntc", "tc", "nbio", "unc"
};

/// ST0/ST1 bits addressable by name in the SETC/CLRC mode mask, LSB first.
// INTR's 4-bit field selects a maskable interrupt or one of two special vectors
static const char *const c28x_intr_names[16] = {
	"int1", "int2", "int3", "int4", "int5", "int6", "int7", "int8",
	"int9", "int10", "int11", "int12", "int13", "int14", "dlogint", "rtosint"
};

static const char *const c28x_mode_bits[8] = {
	"sxm", "ovm", "tc", "c", "intm", "dbgm", "page0", "vmap"
};

/**
 * \brief Printable name of \p reg.
 * \return the lowercase mnemonic spelling, or "?" for an unknown value
 */
RZ_IPI const char *c28x_reg_name(C28xReg reg) {
	if (reg >= RZ_ARRAY_SIZE(c28x_reg_names) || !c28x_reg_names[reg]) {
		return "?";
	}
	return c28x_reg_names[reg];
}

/**
 * \brief Printable name of condition code \p cond.
 */
RZ_IPI const char *c28x_cond_name(ut8 cond) {
	return c28x_cond_names[cond & 0xf];
}

static void c28x_format_mem(RzStrBuf *sb, const C28xOperand *op) {
	switch (op->mode) {
	case C28X_AM_DP:
		rz_strbuf_appendf(sb, "@0x%02x", op->off);
		break;
	case C28X_AM_SP:
		rz_strbuf_appendf(sb, "*-sp[%d]", op->off);
		break;
	case C28X_AM_SP_POSTINC:
		rz_strbuf_append(sb, "*sp++");
		break;
	case C28X_AM_SP_PREDEC:
		rz_strbuf_append(sb, "*--sp");
		break;
	case C28X_AM_XAR_NONE:
		rz_strbuf_appendf(sb, "*xar%d", op->arn);
		break;
	case C28X_AM_XAR_POSTINC:
		rz_strbuf_appendf(sb, "*xar%d++", op->arn);
		break;
	case C28X_AM_XAR_MOD_INC:
		rz_strbuf_appendf(sb, "xar%d++", op->arn);
		break;
	case C28X_AM_XAR_MOD_DEC:
		rz_strbuf_appendf(sb, "xar%d--", op->arn);
		break;
	case C28X_AM_XAR_POSTDEC:
		rz_strbuf_appendf(sb, "*xar%d--", op->arn);
		break;
	case C28X_AM_XAR_PREDEC:
		rz_strbuf_appendf(sb, "*--xar%d", op->arn);
		break;
	case C28X_AM_XAR_AR0:
		rz_strbuf_appendf(sb, "*+xar%d[ar0]", op->arn);
		break;
	case C28X_AM_XAR_AR1:
		rz_strbuf_appendf(sb, "*+xar%d[ar1]", op->arn);
		break;
	case C28X_AM_XAR_IMM:
		rz_strbuf_appendf(sb, "*+xar%d[%d]", op->arn, op->off);
		break;
	case C28X_AM_ARP:
		rz_strbuf_append(sb, "*");
		break;
	case C28X_AM_ARP_POSTINC:
		rz_strbuf_append(sb, "*++");
		break;
	case C28X_AM_ARP_POSTDEC:
		rz_strbuf_append(sb, "*--");
		break;
	case C28X_AM_ARP_IDX_INC:
		rz_strbuf_append(sb, "*0++");
		break;
	case C28X_AM_ARP_IDX_DEC:
		rz_strbuf_append(sb, "*0--");
		break;
	case C28X_AM_ARP_BR_INC:
		rz_strbuf_append(sb, "*br0++");
		break;
	case C28X_AM_ARP_BR_DEC:
		rz_strbuf_append(sb, "*br0--");
		break;
	case C28X_AM_ARP_SET:
		rz_strbuf_appendf(sb, "*arp%d", op->arn);
		break;
	case C28X_AM_CIRC:
		rz_strbuf_append(sb, "*ar6%++");
		break;
	case C28X_AM_REG:
		rz_strbuf_appendf(sb, "@%s", c28x_reg_name(op->reg));
		break;
	default:
		rz_strbuf_append(sb, "?");
		break;
	}
}

static void c28x_format_mode(RzStrBuf *sb, ut32 mask) {
	if (!mask) {
		// an empty mask changes nothing, but the assembler still accepts it
		rz_strbuf_append(sb, "#0");
		return;
	}
	bool first = true;
	for (ut8 i = 0; i < 8; i++) {
		if (!(mask & (1u << i))) {
			continue;
		}
		rz_strbuf_appendf(sb, "%s%s", first ? "" : "|", c28x_mode_bits[i]);
		first = false;
	}
}

static void c28x_format_operand(RzStrBuf *sb, const C28xInsn *insn, const C28xOperand *op) {
	switch (op->kind) {
	case C28X_OP_REG:
		if (op->reg == C28X_REG_ARP) {
			rz_strbuf_appendf(sb, "arp%d", (int)op->imm);
			break;
		}
		rz_strbuf_append(sb, c28x_reg_name(op->reg));
		if (op->byte_sel == 1) {
			rz_strbuf_append(sb, ".lsb");
		} else if (op->byte_sel == 2) {
			rz_strbuf_append(sb, ".msb");
		}
		break;
	case C28X_OP_MEM:
		c28x_format_mem(sb, op);
		break;
	case C28X_OP_IMM:
		if (op->is_signed && op->imm < 0) {
			rz_strbuf_appendf(sb, "#-0x%" PFMT64x, (ut64)-op->imm);
		} else {
			rz_strbuf_appendf(sb, "#0x%" PFMT64x, (ut64)op->imm);
		}
		break;
	case C28X_OP_SHIFT:
		rz_strbuf_appendf(sb, "<< #%d", (int)op->imm);
		break;
	case C28X_OP_INTR:
		rz_strbuf_append(sb, c28x_intr_names[op->imm & 0xf]);
		break;
	case C28X_OP_COND:
		rz_strbuf_append(sb, c28x_cond_name((ut8)op->imm));
		break;
	case C28X_OP_PCREL:
	case C28X_OP_PMA:
		rz_strbuf_appendf(sb, "0x%" PFMT64x, (ut64)op->imm);
		break;
	// A program address used as a branch target prints bare; one read as data
	// is wrapped, or qualified with the page for MAC. dis2000 draws the same
	// three-way distinction.
	case C28X_OP_PMA_IND:
		rz_strbuf_appendf(sb, "*(0x%" PFMT64x ")", (ut64)op->imm);
		break;
	case C28X_OP_PMA_DP:
		rz_strbuf_appendf(sb, "0:0x%" PFMT64x, (ut64)op->imm);
		break;
	case C28X_OP_DMA:
		rz_strbuf_appendf(sb, "*(0:0x%" PFMT64x ")", (ut64)op->imm);
		break;
	case C28X_OP_PORT:
		rz_strbuf_appendf(sb, "*(0x%" PFMT64x ")", (ut64)op->imm);
		break;
	case C28X_OP_MODE:
		c28x_format_mode(sb, (ut32)op->imm);
		break;
	default:
		rz_strbuf_append(sb, "?");
		break;
	}
	(void)insn;
}

/**
 * \brief Render an instruction as an assembly string.
 * \param insn decoded instruction to render
 * \param pc byte address of the instruction (already applied to branch targets)
 * \return an owned string, or NULL on allocation failure
 *
 * A shift operand carries its own "<< " prefix rather than a separating comma,
 * matching the TI syntax `ADD ACC,loc16 << #16`.
 */
RZ_IPI RZ_OWN char *c28x_format(const C28xInsn *insn, ut64 pc) {
	rz_return_val_if_fail(insn, NULL);
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	rz_strbuf_append(&sb, insn->mnemonic);

	// NOP carries an addressing byte that usually selects "no modification";
	// TI writes that case as a bare NOP.
	const bool bare_nop = !strcmp(insn->mnemonic, "nop") && insn->nops == 1 &&
		insn->ops[0].kind == C28X_OP_MEM && insn->ops[0].mode == C28X_AM_DP &&
		insn->ops[0].off == 0;
	if (bare_nop) {
		return rz_strbuf_drain_nofree(&sb);
	}

	for (ut8 i = 0; i < insn->nops; i++) {
		const C28xOperand *op = &insn->ops[i];
		const bool suffix_shift = i > 1;
		if (op->kind == C28X_OP_SHIFT) {
			if (!suffix_shift) {
				// LSL ACC,#1..16 and friends take the count as an operand
				rz_strbuf_appendf(&sb, ", %d", (int)op->imm);
				continue;
			}
			if (!op->imm) {
				continue; // a zero shift is not written
			}
			rz_strbuf_append(&sb, " ");
		} else if (op->kind == C28X_OP_REG && op->reg == C28X_REG_T && i == 2 &&
			insn->ops[1].kind == C28X_OP_MEM && insn->ops[0].kind == C28X_OP_REG &&
			insn->ops[0].reg == C28X_REG_ACC) {
			// "ACC, loc16 << T" shifts by T; MOV loc16,T is a plain move
			rz_strbuf_append(&sb, " << ");
			rz_strbuf_append(&sb, c28x_reg_name(op->reg));
			continue;
		} else {
			rz_strbuf_append(&sb, i ? ", " : " ");
		}
		c28x_format_operand(&sb, insn, op);
	}
	(void)pc;
	return rz_strbuf_drain_nofree(&sb);
}
