// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2019 condret
// SPDX-FileCopyrightText: 2012 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// this file was based on analysis_i8080.c

#include <string.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_reg.h>
#include <gb/gbdis.c>
#include <gb/gb_makros.h>
#include <gb/meta_gb_cmt.c>
#include <gb/gb_il.inc>
#include <gb/gb.h>

// lookup tables for disassembly
static const char *regs_1[] = { "Z", "N", "H", "C" };
static gb_reg regs_8[] = {
	GB_REG_B,
	GB_REG_C,
	GB_REG_D,
	GB_REG_E,
	GB_REG_H,
	GB_REG_L,
	GB_REG_HL,
	GB_REG_A
};
static gb_reg regs_16[] = {
	GB_REG_BC,
	GB_REG_DE,
	GB_REG_HL,
	GB_REG_SP
};
static gb_reg regs_16_alt[] = {
	GB_REG_BC,
	GB_REG_DE,
	GB_REG_HL,
	GB_REG_AF
};

static ut8 gb_op_calljump(RzAnalysis *a, RzAnalysisOp *op, const ut8 *data, ut64 addr) {
	if (GB_IS_RAM_DST(data[1], data[2])) {
		op->jump = GB_SOFTCAST(data[1], data[2]);
		rz_meta_set_string(a, RZ_META_TYPE_COMMENT, addr, "--> unpredictable");
		return false;
	}
	if (!GB_IS_VBANK_DST(data[1], data[2])) {
		op->jump = GB_SOFTCAST(data[1], data[2]);
	} else {
		op->jump = GB_IB_DST(data[1], data[2], addr);
	}
	return true;
}

static void gb_analysis_esil_call(RzAnalysisOp *op) {
	rz_strbuf_setf(&op->esil, "2,sp,-=,pc,sp,=[2],%" PFMT64d ",pc,:=", (op->jump & 0xffff));
}

static void gb_analysis_call(RzAnalysisOpMask mask, RzAnalysisOp *op) {
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		gb_analysis_esil_call(op);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_call(op->jump, op->addr, op->size);
	}
}

static inline void gb_analysis_esil_ccall(RzAnalysisOp *op, const ut8 data) {
	char cond;
	switch (data) {
	case 0xc4:
	case 0xcc:
		cond = 'Z';
		break;
	default:
		cond = 'C';
	}
	if (op->cond == RZ_TYPE_COND_EQ) {
		rz_strbuf_setf(&op->esil, "%c,?{,2,sp,-=,pc,sp,=[2],%" PFMT64d ",pc,:=,}", cond, (op->jump & 0xffff));
	} else {
		rz_strbuf_setf(&op->esil, "%c,!,?{,2,sp,-=,pc,sp,=[2],%" PFMT64d ",pc,:=,}", cond, (op->jump & 0xffff));
	}
}

static void gb_analysis_ccall(RzAnalysisOpMask mask, RzAnalysisOp *op, const ut8 data) {
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		gb_analysis_esil_ccall(op, data);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		gb_flag flag;
		bool neg = false;
		switch (data) {
		case 0xc4:
			neg = true;
			// fallthrough
		case 0xcc:
			flag = GB_FLAG_Z;
			break;
		case 0xd4:
			neg = true;
			// fallthrough
		case 0xdc:
			flag = GB_FLAG_C;
			break;
		default:
			rz_warn_if_reached();
			return;
		}
		op->il_op = gb_il_ccall(op->jump, op->addr, op->size, flag, neg);
	}
}

static inline void gb_analysis_esil_ret(RzAnalysisOp *op) {
	rz_strbuf_append(&op->esil, "sp,[2],pc,:=,2,sp,+=");
}

static inline void gb_analysis_esil_cret(RzAnalysisOpMask mask, RzAnalysisOp *op, const ut8 data) {
	char cond;
	gb_flag cond_flag;
	if ((data & 0xd0) == 0xd0) {
		cond = 'C';
		cond_flag = GB_FLAG_C;
	} else {
		cond = 'Z';
		cond_flag = GB_FLAG_Z;
	}
	bool neg = op->cond != RZ_TYPE_COND_EQ;
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if (!neg) {
			rz_strbuf_setf(&op->esil, "%c,?{,sp,[2],pc,:=,2,sp,+=,}", cond);
		} else {
			rz_strbuf_setf(&op->esil, "%c,!,?{,sp,[2],pc,:=,2,sp,+=,}", cond);
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_cret(cond_flag, neg, op->addr);
	}
}

static inline void gb_analysis_esil_cjmp(RzAnalysisOp *op, const ut8 data) {
	char cond;
	switch (data) {
	case 0x20:
	case 0x28:
	case 0xc2:
	case 0xca:
		cond = 'Z';
		break;
	default:
		cond = 'C';
	}
	if (op->cond == RZ_TYPE_COND_EQ) {
		rz_strbuf_setf(&op->esil, "%c,?{,0x%" PFMT64x ",pc,:=,}", cond, (op->jump & 0xffff));
	} else {
		rz_strbuf_setf(&op->esil, "%c,!,?{,0x%" PFMT64x ",pc,:=,}", cond, (op->jump & 0xffff));
	}
}

static inline void gb_analysis_cjmp(RzAnalysisOpMask mask, RzAnalysisOp *op, const ut8 data) {
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		gb_analysis_esil_cjmp(op, data);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		gb_flag flag;
		bool neg = false;
		switch (data) {
		case 0x20:
		case 0xc2:
			neg = true;
			// fallthrough
		case 0x28:
		case 0xca:
			flag = GB_FLAG_Z;
			break;
		case 0x30:
		case 0xd2:
			neg = true;
			// fallthrough
		case 0x38:
		case 0xda:
			flag = GB_FLAG_C;
			break;
		default:
			rz_warn_if_reached();
			return;
		}
		op->il_op = gb_il_cjmp(op->jump, flag, neg);
	}
}

static inline void gb_analysis_esil_jmp(RzAnalysisOp *op) {
	rz_strbuf_setf(&op->esil, "0x%" PFMT64x ",pc,:=", (op->jump & 0xffff));
}

static inline void gb_analysis_jmp_hl(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, "pc", RZ_REG_TYPE_GPR);
	op->src[0]->reg = rz_reg_get(reg, "hl", RZ_REG_TYPE_GPR);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_set(&op->esil, "hl,pc,:=");
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_jmp_hl(op->addr);
	}
}

static inline void gb_analysis_id(RzAnalysisOpMask mask, RzAnalysis *analysis, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[0]->imm = 1;
	op->src[0]->absolute = true;
	if (data == 0x34 || data == 0x35) {
		op->dst->memref = 1;
		op->dst->reg = rz_reg_get(analysis->reg, "hl", RZ_REG_TYPE_GPR);
		bool is_add = data == 0x34;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			if (is_add) {
				rz_strbuf_set(&op->esil, "1,hl,[1],+,hl,=[1],3,$c,H,:=,$z,Z,:=,0,N,:=");
			} else {
				rz_strbuf_set(&op->esil, "1,hl,[1],-,hl,=[1],4,$b,H,:=,$z,Z,:=,1,N,:=");
			}
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_inc_hl_mem(!is_add, op->addr);
		}
	} else {
		gb_reg regid;
		if (!(data & (1 << 2))) {
			regid = regs_16[data >> 4];
			const char *reg_name = gb_reg_name(regid);
			op->dst->reg = rz_reg_get(analysis->reg, reg_name, RZ_REG_TYPE_GPR);
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				if (op->type == RZ_ANALYSIS_OP_TYPE_ADD) {
					rz_strbuf_setf(&op->esil, "1,%s,+=", reg_name);
				} else {
					rz_strbuf_setf(&op->esil, "1,%s,-=", reg_name);
				}
			}
		} else {
			regid = regs_8[data >> 3];
			const char *reg_name = gb_reg_name(regid);
			op->dst->reg = rz_reg_get(analysis->reg, reg_name, RZ_REG_TYPE_GPR);
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				if (op->type == RZ_ANALYSIS_OP_TYPE_ADD) {
					rz_strbuf_setf(&op->esil, "1,%s,+=,3,$c,H,:=,$z,Z,:=,0,N,:=", reg_name);
				} else {
					rz_strbuf_setf(&op->esil, "1,%s,-=,4,$b,H,:=,$z,Z,:=,1,N,:=", reg_name);
				}
			}
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_inc(regid, op->type != RZ_ANALYSIS_OP_TYPE_ADD);
		}
	}
}

static inline void gb_analysis_add_hl(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, "hl", RZ_REG_TYPE_GPR);
	gb_reg regid = regs_16[(data & 0xf0) >> 4];
	const char *reg_name = gb_reg_name(regid);
	op->src[0]->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_setf(&op->esil, "%s,hl,+=,0,N,:=", reg_name); // hl+=<reg>,N=0
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_add_hl(regid);
	}
}

static inline void gb_analysis_add_sp(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, "sp", RZ_REG_TYPE_GPR);
	op->src[0]->imm = (st8)data;
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if (data < 128) {
			rz_strbuf_setf(&op->esil, "0x%02x,sp,+=", data);
		} else {
			rz_strbuf_setf(&op->esil, "0x%02x,sp,-=", 0 - (st8)data);
		}
		rz_strbuf_append(&op->esil, ",0,Z,=,0,N,:=");
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_add_sp(data);
	}
}

static void gb_analysis_mov_imm(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 *data) {
	gb_reg regid;
	ut16 imm;
	if (data[0] & 1) {
		// 16-bit dst reg
		regid = regs_16[data[0] >> 4];
		imm = GB_SOFTCAST(data[1], data[2]);
	} else {
		// 8-bit dst reg
		regid = regs_8[data[0] >> 3];
		imm = data[1];
	}
	const char *reg_name = gb_reg_name(regid);
	op->dst = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	op->src[0] = rz_analysis_value_new();
	op->src[0]->imm = imm;
	op->src[0]->absolute = true;
	op->val = op->src[0]->imm;
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_setf(&op->esil,
			gb_reg_bits(regid) == 16 ? "0x%04" PFMT64x ",%s,=" : "0x%02" PFMT64x ",%s,=",
			(ut64)imm, reg_name);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_mov_imm(regid, imm);
	}
}

static inline void gb_analysis_mov_sp_hl(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, "sp", RZ_REG_TYPE_GPR);
	op->src[0]->reg = rz_reg_get(reg, "hl", RZ_REG_TYPE_GPR);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_set(&op->esil, "hl,sp,=");
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_mov_sp_hl();
	}
}

static inline void gb_analysis_mov_hl_sp(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[1] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, gb_reg_name(GB_REG_HL), RZ_REG_TYPE_GPR);
	op->src[0]->reg = rz_reg_get(reg, gb_reg_name(GB_REG_SP), RZ_REG_TYPE_GPR);
	op->src[1]->imm = (st8)data;
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if (data < 128) {
			rz_strbuf_setf(&op->esil, "0x%02x,sp,+,hl,=", data);
		} else {
			rz_strbuf_setf(&op->esil, "0x%02x,sp,-,hl,=", 0 - (st8)data);
		}
		rz_strbuf_append(&op->esil, ",0,Z,=,0,N,:=");
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_mov_hl_sp(data);
	}
}

static void gb_analysis_mov_reg(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	gb_reg dst_regid = regs_8[(data / 8) - 8];
	const char *dst_reg = gb_reg_name(dst_regid);
	gb_reg src_regid = regs_8[data & 7];
	const char *src_reg = gb_reg_name(src_regid);
	op->dst->reg = rz_reg_get(reg, dst_reg, RZ_REG_TYPE_GPR);
	op->src[0]->reg = rz_reg_get(reg, src_reg, RZ_REG_TYPE_GPR);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_setf(&op->esil, "%s,%s,=", src_reg, dst_reg);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_mov_mov(dst_regid, src_regid);
	}
}

static inline void gb_analysis_mov_ime(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, "ime", RZ_REG_TYPE_GPR);
	op->src[0]->absolute = true;
	bool val = data != 0xf3;
	op->src[0]->imm = val;
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_setf(&op->esil, "%d,ime,=", (int)op->src[0]->imm);
		if (data == 0xd9) {
			rz_strbuf_append(&op->esil, ",");
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = data == 0xd9 ? gb_il_reti(op->addr) : gb_il_mov_ime(val);
	}
}

static inline void gb_analysis_mov_scf(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, regs_1[3], RZ_REG_TYPE_GPR);
	op->src[0]->imm = 1;
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_set(&op->esil, "1,C,:=");
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_scf();
	}
}

static inline void gb_analysis_daa(RzAnalysisOpMask mask, RzAnalysisOp *op) {
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_set(&op->esil, "a,daa,a,=,$z,Z,:=,3,$c,H,:=,7,$c,C,:=");
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_daa();
	}
}

static inline void gb_analysis_xor_cpl(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, gb_reg_name(GB_REG_A), RZ_REG_TYPE_GPR);
	op->src[0]->imm = 0xff;
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_set(&op->esil, "0xff,a,^=,1,N,:=,1,H,:=");
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_cpl();
	}
}

static inline void gb_analysis_xor_ccf(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, regs_1[3], RZ_REG_TYPE_GPR);
	op->src[0]->imm = 1;
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_set(&op->esil, "C,!=");
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_ccf();
	}
}

static inline void gb_analysis_cond(RzReg *reg, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[0]->imm = 1;
	if (data & 0x8) {
		op->cond = RZ_TYPE_COND_EQ;
	} else {
		op->cond = RZ_TYPE_COND_NE;
	}
	switch (data) {
	case 0x20:
	case 0x28:
	case 0xc0:
	case 0xc2:
	case 0xc4:
	case 0xc8:
	case 0xca:
	case 0xcc:
		op->dst->reg = rz_reg_get(reg, regs_1[0], RZ_REG_TYPE_GPR);
		break;
	default:
		op->dst->reg = rz_reg_get(reg, regs_1[3], RZ_REG_TYPE_GPR);
	}
}

static inline void gb_analysis_pp(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) // push , pop
{
	RzAnalysisValue *val = rz_analysis_value_new();
	gb_reg regid = regs_16_alt[(data >> 4) - 12];
	const char *reg_name = gb_reg_name(regid);
	val->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	if ((data & 0xf) == 1) {
		// pop
		op->dst = val;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "sp,[2],%s,=,2,sp,+=", reg_name);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_pop(regid, op->addr);
		}
	} else {
		// push
		op->src[0] = val;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "2,sp,-=,%s,sp,=[2]", reg_name);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_push(regid, op->addr);
		}
	}
}

static inline void gb_analysis_and_res(RzAnalysisOpMask mask, RzAnalysis *analysis, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	ut8 bit = ~(0x1 << ((data >> 3) & 7));
	op->src[0]->imm = bit;
	op->dst->memref = ((data & 7) == 6);
	gb_reg regid = regs_8[data & 7];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(analysis->reg, reg_name, RZ_REG_TYPE_GPR);
	if (op->dst->memref) {
		rz_strbuf_setf(&op->esil, "0x%02" PFMT64x ",%s,[1],&,%s,=[1]", op->src[0]->imm, reg_name, reg_name);
	} else {
		rz_strbuf_setf(&op->esil, "0x%02" PFMT64x ",%s,&=", op->src[0]->imm, reg_name);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_res(regid, bit, op->addr);
	}
}

static inline void gb_analysis_and_bit(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	ut8 bit = 1 << ((data >> 3) & 7);
	op->src[0]->imm = bit;
	op->dst->memref = ((data & 7) == 6);
	gb_reg regid = regs_8[data & 7];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if (op->dst->memref) {
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,[1],&,0,==,$z,Z,:=,0,N,:=,1,H,:=", op->src[0]->imm, reg_name);
		} else {
			rz_strbuf_setf(&op->esil, "%" PFMT64d ",%s,&,0,==,$z,Z,:=,0,N,:=,1,H,:=", op->src[0]->imm, reg_name);
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_bit(regid, bit, op->addr);
	}
}

static inline void gb_analysis_or_set(RzAnalysisOpMask mask, RzAnalysis *analysis, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	ut8 bit = 1 << ((data >> 3) & 7);
	op->src[0]->imm = bit;
	op->dst->memref = ((data & 7) == 6);
	gb_reg regid = regs_8[data & 7];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(analysis->reg, reg_name, RZ_REG_TYPE_GPR);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if (op->dst->memref) {
			rz_strbuf_setf(&op->esil, "0x%02" PFMT64x ",%s,[1],|,%s,=[1]", op->src[0]->imm, reg_name, reg_name);
		} else {
			rz_strbuf_setf(&op->esil, "0x%02" PFMT64x ",%s,|=", op->src[0]->imm, reg_name);
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_set(regid, bit, op->addr);
	}
}

static void gb_analysis_xoaasc(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 *data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, "a", RZ_REG_TYPE_GPR);
	gb_reg src_regid = regs_8[data[0] & 7];
	const char *reg_name = gb_reg_name(src_regid);
	op->src[0]->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	op->src[0]->memref = ((data[0] & 7) == 6);
	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_XOR:
		if (op->src[0]->memref) {
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,[1],a,^=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg_memref(GB_IL_BINOP_XOR, GB_REG_A, src_regid, op->addr);
			}
		} else {
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,a,^=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg(GB_IL_BINOP_XOR, GB_REG_A, src_regid);
			}
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_OR:
		if (op->src[0]->memref) {
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,[1],a,|=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg_memref(GB_IL_BINOP_OR, GB_REG_A, src_regid, op->addr);
			}
		} else {
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,a,|=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg(GB_IL_BINOP_OR, GB_REG_A, src_regid);
			}
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_AND:
		if (op->src[0]->memref) {
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,[1],a,&=,$z,Z,:=,0,N,:=,1,H,:=,0,C,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg_memref(GB_IL_BINOP_AND, GB_REG_A, src_regid, op->addr);
			}
		} else {
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,a,&=,$z,Z,:=,0,N,:=,1,H,:=,0,C,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg(GB_IL_BINOP_AND, GB_REG_A, src_regid);
			}
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_ADD: {
		bool with_carry = data[0] > 0x87;
		bool memref = op->src[0]->memref;
		if (memref) {
			if (with_carry) {
				op->src[1] = rz_analysis_value_new();
				op->src[1]->reg = rz_reg_get(reg, "C", RZ_REG_TYPE_GPR);
				if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
					rz_strbuf_setf(&op->esil, "C,%s,[1],+,a,+=,$z,Z,:=,3,$c,H,:=,7,$c,C,:=,0,N,:=", reg_name);
				}
			} else if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,[1],a,+=,$z,Z,:=,3,$c,H,:=,7,$c,C,:=,0,N,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg_memref(with_carry ? GB_IL_BINOP_ADC : GB_IL_BINOP_ADD, GB_REG_A, src_regid, op->addr);
			}
		} else {
			if (with_carry) {
				op->src[1] = rz_analysis_value_new();
				op->src[1]->reg = rz_reg_get(reg, "C", RZ_REG_TYPE_GPR);
				if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
					rz_strbuf_setf(&op->esil, "C,%s,+,a,+=,$z,Z,:=,3,$c,H,:=,7,$c,C,:=,0,N,:=", reg_name);
				}
			} else if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,a,+=,$z,Z,:=,3,$c,H,:=,7,$c,C,:=,0,N,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg(with_carry ? GB_IL_BINOP_ADC : GB_IL_BINOP_ADD, GB_REG_A, src_regid);
			}
		}
		break;
	}
	case RZ_ANALYSIS_OP_TYPE_SUB:
		if (op->src[0]->memref) {
			bool with_carry = data[0] > 0x97;
			if (with_carry) {
				op->src[1] = rz_analysis_value_new();
				op->src[1]->reg = rz_reg_get(reg, "C", RZ_REG_TYPE_GPR);
				if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
					rz_strbuf_setf(&op->esil, "C,%s,[1],+,a,-=,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", reg_name);
				}
			} else if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,[1],a,-=,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg_memref(with_carry ? GB_IL_BINOP_SBC : GB_IL_BINOP_SUB, GB_REG_A, src_regid, op->addr);
			}
		} else {
			bool with_carry = data[0] > 0x97;
			if (with_carry) {
				op->src[1] = rz_analysis_value_new();
				op->src[1]->reg = rz_reg_get(reg, "C", RZ_REG_TYPE_GPR);
				if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
					rz_strbuf_setf(&op->esil, "C,%s,+,a,-=,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", reg_name);
				}
			} else if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,a,-=,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg(with_carry ? GB_IL_BINOP_SBC : GB_IL_BINOP_SUB, GB_REG_A, src_regid);
			}
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_CMP:
		if (op->src[0]->memref) {
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,[1],a,==,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg_memref(GB_IL_BINOP_CMP, GB_REG_A, src_regid, op->addr);
			}
		} else {
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_setf(&op->esil, "%s,a,==,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", reg_name);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				op->il_op = gb_il_binop_reg(GB_IL_BINOP_CMP, GB_REG_A, src_regid);
			}
		}
		break;
	default:
		// not handled yet
		break;
	}
}

static void gb_analysis_xoaasc_imm(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 *data) // xor , or, and, add, adc, sub, sbc, cp
{
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, "a", RZ_REG_TYPE_GPR);
	op->src[0]->absolute = true;
	op->src[0]->imm = data[1];
	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_XOR:
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "0x%02x,a,^=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", data[1]);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_binop_imm(GB_IL_BINOP_XOR, GB_REG_A, data[1]);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_OR:
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "0x%02x,a,|=,$z,Z,:=,0,N,:=,0,H,:=,0,C,:=", data[1]);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_binop_imm(GB_IL_BINOP_OR, GB_REG_A, data[1]);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_AND:
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "0x%02x,a,&=,$z,Z,:=,0,N,:=,1,H,:=,0,C,:=", data[1]);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_binop_imm(GB_IL_BINOP_AND, GB_REG_A, data[1]);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_ADD: {
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "0x%02x,", data[1]);
		}
		bool with_carry = data[0] == 0xce; // adc
		if (with_carry) {
			op->src[1] = rz_analysis_value_new();
			op->src[1]->reg = rz_reg_get(reg, "C", RZ_REG_TYPE_GPR);
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_append(&op->esil, "a,+=,C,NUM,7,$c,C,:=,3,$c,H,:=,a,+=,7,$c,C,|,C,:=,3,$c,H,|=,a,a,=,$z,Z,:=,0,N,:=");
			}
		} else if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_append(&op->esil, "a,+=,3,$c,H,:=,7,$c,C,:=,0,N,:=,a,a,=,$z,Z,:=");
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_binop_imm(with_carry ? GB_IL_BINOP_ADC : GB_IL_BINOP_ADD, GB_REG_A, data[1]);
		}
		break;
	}
	case RZ_ANALYSIS_OP_TYPE_SUB:
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "0x%02x,", data[1]);
		}
		bool with_carry = data[0] == 0xde;
		if (with_carry) { // sbc
			op->src[1] = rz_analysis_value_new();
			op->src[1]->reg = rz_reg_get(reg, "C", RZ_REG_TYPE_GPR);
			if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
				rz_strbuf_append(&op->esil, "a,-=,C,NUM,8,$b,C,:=,4,$b,H,:=,a,-=,8,$b,C,|,C,=,4,$b,H,|,H,=,a,a,=,$z,Z,:=,1,N,:=");
			}
		} else if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_append(&op->esil, "a,-=,4,$b,H,:=,8,$b,C,:=,1,N,:=,a,a,=,$z,Z,:=");
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_binop_imm(with_carry ? GB_IL_BINOP_SBC : GB_IL_BINOP_SUB, GB_REG_A, data[1]);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_CMP:
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "%d,a,==,$z,Z,:=,4,$b,H,:=,8,$b,C,:=,1,N,:=", data[1]);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_binop_imm(GB_IL_BINOP_CMP, GB_REG_A, data[1]);
		}
		break;
	}
}

static inline void gb_analysis_load_hl(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) // load with [hl] as memref
{
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[0]->reg = rz_reg_get(reg, "hl", RZ_REG_TYPE_GPR);
	op->src[0]->memref = 1;
	op->src[0]->absolute = true;
	bool inc = data == 0x2a;
	bool dec = data == 0x3a;
	gb_reg regid = inc || dec ? GB_REG_A : regs_8[((data & 0x38) >> 3)];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_setf(&op->esil, "hl,[1],%s,=", reg_name);
		if (dec) {
			rz_strbuf_append(&op->esil, ",1,hl,-=");
		} else if (inc) {
			rz_strbuf_set(&op->esil, "hl,[1],a,=,1,hl,+="); // hack in concept
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_load_reg_reg(regid, GB_REG_HL, inc, dec, op->addr);
	}
}

static inline void gb_analysis_load(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 *data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, "a", RZ_REG_TYPE_GPR);
	op->src[0]->memref = 1;
	switch (data[0]) {
	case 0xf0: {
		ut16 addr = 0xff00 + data[1];
		op->src[0]->base = addr;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "0x%04" PFMT64x ",[1],a,=", (ut64)addr);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_load_a_imm(addr, op->addr);
		}
		break;
	}
	case 0xf2:
		op->src[0]->base = 0xff00;
		op->src[0]->regdelta = rz_reg_get(reg, "c", RZ_REG_TYPE_GPR);
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_set(&op->esil, "0xff00,c,+,[1],a,=");
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_load_reg_reg(GB_REG_A, GB_REG_C, false, false, op->addr);
		}
		break;
	case 0xfa: {
		ut16 addr = GB_SOFTCAST(data[1], data[2]);
		op->src[0]->base = addr;
		if (op->src[0]->base < 0x4000) {
			op->ptr = op->src[0]->base;
		} else {
			if (op->addr > 0x3fff && op->src[0]->base < 0x8000) { /* hack */
				op->ptr = op->src[0]->base + (op->addr & 0xffffffffffff0000LL);
			}
		}
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "0x%04" PFMT64x ",[1],a,=", (ut64)addr);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_load_a_imm(addr, op->addr);
		}
		break;
	}
	default: {
		gb_reg regid = regs_16[(data[0] & 0xf0) >> 4];
		const char *reg_name = gb_reg_name(regid);
		op->src[0]->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "%s,[1],a,=", reg_name);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_load_reg_reg(GB_REG_A, regid, false, false, op->addr);
		}
		break;
	}
	}
}

static inline void gb_analysis_store_hl(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 *data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->reg = rz_reg_get(reg, "hl", RZ_REG_TYPE_GPR);
	op->dst->memref = 1;
	op->src[0]->absolute = true;
	if (data[0] == 0x36) {
		op->src[0]->imm = data[1];
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "0x%02x,hl,=[1]", data[1]);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_store_reg_imm(GB_REG_HL, data[1], op->addr);
		}
		return;
	}
	bool inc = data[0] == 0x22;
	bool dec = data[0] == 0x32;
	gb_reg regid = inc || dec ? GB_REG_A : regs_8[data[0] & 0x07];
	const char *reg_name = gb_reg_name(regid);
	op->src[0]->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if (dec) {
			rz_strbuf_set(&op->esil, "a,hl,=[1],1,hl,-=");
		} else if (inc) {
			rz_strbuf_set(&op->esil, "a,hl,=[1],1,hl,+=");
		} else {
			rz_strbuf_setf(&op->esil, "%s,hl,=[1]", reg_name);
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_store_reg_reg(GB_REG_HL, inc, dec, regid, op->addr);
	}
}

static void gb_analysis_store(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 *data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->dst->memref = 1;
	op->src[0]->reg = rz_reg_get(reg, "a", RZ_REG_TYPE_GPR);
	switch (data[0]) {
	case 0x08: {
		ut16 dst_addr = GB_SOFTCAST(data[1], data[2]);
		op->dst->memref = 2;
		op->dst->base = dst_addr;
		op->src[0]->reg = rz_reg_get(reg, "sp", RZ_REG_TYPE_GPR);
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "sp,0x%04" PFMT64x ",=[2]", op->dst->base);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_store_imm_sp(dst_addr, op->addr);
		}
		break;
	}
	case 0xe0: {
		ut16 dst_addr = 0xff00 + data[1];
		op->dst->base = dst_addr;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "a,0x%04" PFMT64x ",=[1]", (ut64)dst_addr);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_store_imm_a(dst_addr, op->addr);
		}
		break;
	}
	case 0xe2:
		op->dst->base = 0xff00;
		op->dst->regdelta = rz_reg_get(reg, "c", RZ_REG_TYPE_GPR);
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_set(&op->esil, "a,0xff00,c,+,=[1]");
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_store_reg_reg(GB_REG_C, false, false, GB_REG_A, op->addr);
		}
		break;
	case 0xea: {
		ut16 dst_addr = GB_SOFTCAST(data[1], data[2]);
		op->dst->base = dst_addr;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "a,0x%04" PFMT64x ",=[1]", op->dst->base);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_store_imm_a(dst_addr, op->addr);
		}
		break;
	}
	default: {
		gb_reg regid = regs_16[(data[0] & 0xf0) >> 4];
		const char *reg_name = gb_reg_name(regid);
		op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "a,%s,=[1]", reg_name);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_store_reg_reg(regid, false, false, GB_REG_A, op->addr);
		}
	}
	}
}

static inline void gb_analysis_cb_swap(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[0]->imm = 4;
	gb_reg regid = regs_8[data & 7];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if ((data & 7) == 6) {
			op->dst->memref = 1;
			rz_strbuf_setf(&op->esil, "4,%s,[1],>>,4,%s,[1],<<,|,%s,=[1],$z,Z,:=", reg_name, reg_name, reg_name);
		} else {
			rz_strbuf_setf(&op->esil, "4,%s,>>,4,%s,<<,|,%s,=,$z,Z,:=", reg_name, reg_name, reg_name);
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_swap(regid, op->addr);
	}
}

static inline void gb_analysis_cb_rlc(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data, bool is_rlca) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[0]->imm = 1;
	gb_reg regid = regs_8[data & 7];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	if (regid == GB_REG_HL) {
		op->dst->memref = 1;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "7,%s,[1],>>,1,&,C,:=,1,%s,[1],<<,C,|,%s,=[1],$z,Z,:=,0,H,:=,0,N,:=", reg_name, reg_name, reg_name);
		}
	} else if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_setf(&op->esil, "1,%s,<<=,7,$c,C,:=,C,%s,|=,$z,Z,:=,0,H,:=,0,N,:=", reg_name, reg_name);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		if (is_rlca) {
			op->il_op = gb_il_rot_ca(false);
		} else {
			op->il_op = gb_il_rot_c(regid, false, op->addr);
		}
	}
}

static inline void gb_analysis_cb_rl(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data, bool is_rla) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[0]->imm = 1;
	gb_reg regid = regs_8[data & 7];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	if (regid == GB_REG_HL) {
		op->dst->memref = 1;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "1,%s,<<,C,|,%s,=[1],7,$c,C,:=,$z,Z,:=,0,H,:=,0,N,:=", reg_name, reg_name);
		}
	} else if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_setf(&op->esil, "1,%s,<<,C,|,%s,=,7,$c,C,:=,$z,Z,:=,0,H,:=,0,N,:=", reg_name, reg_name);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_rot(regid, false, !is_rla, op->addr);
	}
}

static inline void gb_analysis_cb_rrc(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data, bool is_rrca) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[0]->imm = 1;
	gb_reg regid = regs_8[data & 7];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	if ((data & 7) == 6) {
		op->dst->memref = 1;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "1,%s,[1],&,C,:=,1,%s,[1],>>,7,C,<<,|,%s,=[1],$z,Z,:=,0,H,:=,0,N,:=", reg_name, reg_name, reg_name);
		}
	} else if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		rz_strbuf_setf(&op->esil, "1,%s,&,C,:=,1,%s,>>,7,C,<<,|,%s,=,$z,Z,:=,0,H,:=,0,N,:=", reg_name, reg_name, reg_name);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		if (is_rrca) {
			op->il_op = gb_il_rot_ca(true);
		} else {
			op->il_op = gb_il_rot_c(regid, true, op->addr);
		}
	}
}

static inline void gb_analysis_cb_rr(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data, bool is_rra) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[0]->imm = 1;
	gb_reg regid = regs_8[data & 7];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	if ((data & 7) == 6) {
		op->dst->memref = 1;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_setf(&op->esil, "1,%s,[1],&,H,:=,1,%s,[1],>>,7,C,<<,|,%s,=[1],H,C,:=,0,H,:=,0,N,:=", reg_name, reg_name, reg_name);
		}
	} else {
		rz_strbuf_setf(&op->esil, "1,%s,&,H,:=,1,%s,>>,7,C,<<,|,%s,=,H,C,:=,0,H,:=,0,N,:=", reg_name, reg_name, reg_name); // HACK
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_rot(regid, true, !is_rra, op->addr);
	}
}

static inline void gb_analysis_cb_sla(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) // sra+sla+srl in one function, like xoaasc
{
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[0]->imm = 1;
	gb_reg regid = regs_8[data & 7];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	op->dst->memref = ((data & 7) == 6);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if (op->dst->memref) {
			rz_strbuf_setf(&op->esil, "1,%s,[1],<<,%s,=[1],7,$c,C,:=,%s,[1],%s,=[1],$z,Z,:=,0,H,:=,0,N,:=", reg_name, reg_name, reg_name, reg_name);
		} else {
			rz_strbuf_setf(&op->esil, "1,%s,<<=,7,$c,C,:=,%s,%s,=,$z,Z,:=,0,H,:=0,N,:=", reg_name, reg_name, reg_name); // %s,%s,= is a HACK for $z
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_shift(regid, false, false, op->addr);
	}
}

static inline void gb_analysis_cb_sra(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[0]->imm = 1;
	gb_reg regid = regs_8[data & 7];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	op->dst->memref = ((data & 7) == 6);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if (op->dst->memref) {
			rz_strbuf_setf(&op->esil, "1,%s,[1],&,C,:=,0x80,%s,[1],&,1,%s,[1],>>,|,%s,=[1],$z,Z,:=,0,N,:=,0,H,:=", reg_name, reg_name, reg_name, reg_name); // spaguesil
		} else {
			rz_strbuf_setf(&op->esil, "1,%s,&,C,:=,0x80,%s,&,1,%s,>>,|,%s,=,$z,Z,:=,0,N,:=,0,H,:=", reg_name, reg_name, reg_name, reg_name);
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_shift(regid, true, true, op->addr);
	}
}

static inline void gb_analysis_cb_srl(RzAnalysisOpMask mask, RzReg *reg, RzAnalysisOp *op, const ut8 data) {
	op->dst = rz_analysis_value_new();
	op->src[0] = rz_analysis_value_new();
	op->src[0]->imm = 1;
	gb_reg regid = regs_8[data & 7];
	const char *reg_name = gb_reg_name(regid);
	op->dst->reg = rz_reg_get(reg, reg_name, RZ_REG_TYPE_GPR);
	op->dst->memref = ((data & 7) == 6);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if (op->dst->memref) {
			rz_strbuf_setf(&op->esil, "1,%s,[1],&,C,:=,1,%s,[1],>>,%s,=[1],$z,Z,:=,0,N,:=,0,H,:=", reg_name, reg_name, reg_name);
		} else {
			rz_strbuf_setf(&op->esil, "1,%s,&,C,:=,1,%s,>>=,$z,Z,:=,0,N,:=,0,H,:=", reg_name, reg_name);
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = gb_il_shift(regid, true, false, op->addr);
	}
}

static bool gb_custom_daa(RzAnalysisEsil *esil) {
	if (!esil || !esil->analysis || !esil->analysis->reg) {
		return false;
	}
	char *v = rz_analysis_esil_pop(esil);
	ut64 n;
	if (!v || !rz_analysis_esil_get_parm(esil, v, &n)) {
		return false;
	}
	RZ_FREE(v);
	ut8 val = (ut8)n;
	rz_analysis_esil_reg_read(esil, "H", &n, NULL);
	const ut8 H = (ut8)n;
	rz_analysis_esil_reg_read(esil, "C", &n, NULL);
	const ut8 C = (ut8)n;
	rz_analysis_esil_reg_read(esil, "N", &n, NULL);
	if (n) {
		if (C) {
			val = (val - 0x60) & 0xff;
		}
		if (H) {
			val = (val - 0x06) & 0xff;
		}
	} else {
		if (C || (val > 0x99)) {
			val = (val + 0x60) & 0xff;
		}
		if (H || ((val & 0x0f) > 0x09)) {
			val += 0x06;
		};
	}
	return rz_analysis_esil_pushnum(esil, val);
}

static int gb_anop(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	int ilen = gbOpLength(gb_op[data[0]].type);
	if (ilen > len) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->size = 0;
		return 0;
	}
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		char mn[32];
		memset(mn, '\0', sizeof(mn));
		char reg[32];
		memset(reg, '\0', sizeof(reg));
		switch (gb_op[data[0]].type) {
		case GB_8BIT:
			sprintf(mn, "%s", gb_op[data[0]].name);
			break;
		case GB_16BIT:
			sprintf(mn, "%s %s", cb_ops[data[1] >> 3], cb_regs[data[1] & 7]);
			break;
		case GB_8BIT + ARG_8:
			sprintf(mn, gb_op[data[0]].name, data[1]);
			break;
		case GB_8BIT + ARG_16:
			sprintf(mn, gb_op[data[0]].name, data[1] | (data[2] << 8));
			break;
		case GB_8BIT + ARG_8 + GB_IO:
			gb_hardware_register_name(reg, data[1]);
			sprintf(mn, gb_op[data[0]].name, reg);
			break;
		}
		op->mnemonic = rz_str_dup(mn);
	}
	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->size = ilen;
	op->nopcode = 1;
	switch (data[0]) {
	case 0x00:
	case 0x40:
	case 0x49:
	case 0x52:
	case 0x5b:
	case 0x64:
	case 0x6d:
	case 0x7f:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = rz_il_op_new_nop();
		}
		break;
	case 0x01:
	case 0x11:
	case 0x21:
	case 0x31:
		gb_analysis_mov_imm(mask, analysis->reg, op, data);
		op->cycles = 12;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case 0xf8:
		gb_analysis_mov_hl_sp(mask, analysis->reg, op, data[1]);
		op->cycles = 12;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->type2 = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case 0x06:
	case 0x0e:
	case 0x16:
	case 0x1e:
	case 0x26:
	case 0x2e:
	case 0x3e:
		gb_analysis_mov_imm(mask, analysis->reg, op, data);
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case 0xf9:
		gb_analysis_mov_sp_hl(mask, analysis->reg, op);
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV; // LD
		break;
	case 0x03:
	case 0x13:
	case 0x23:
	case 0x33:
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		gb_analysis_id(mask, analysis, op, data[0]);
		break;
	case 0x04:
	case 0x0c:
	case 0x14:
	case 0x1c:
	case 0x24:
	case 0x2c:
	case 0x3c:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_ADD; // INC
		gb_analysis_id(mask, analysis, op, data[0]);
		break;
	case 0x34:
		op->cycles = 12;
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		gb_analysis_id(mask, analysis, op, data[0]);
		break;
	case 0xea:
	case 0x08:
		meta_gb_bankswitch_cmt(analysis, addr, GB_SOFTCAST(data[1], data[2]));
		gb_analysis_store(mask, analysis->reg, op, data);
		op->cycles = data[0] == 0xea ? 16 : 20;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case 0x02:
	case 0x12:
	case 0xe2:
		gb_analysis_store(mask, analysis->reg, op, data);
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case 0x36:
	case 0x22:
	case 0x32:
	case 0x70:
	case 0x71:
	case 0x72:
	case 0x73:
	case 0x74:
	case 0x75:
	case 0x77:
		gb_analysis_store_hl(mask, analysis->reg, op, data);
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE; // LD
		break;
	case 0xe0:
		gb_analysis_store(mask, analysis->reg, op, data);
		op->cycles = 12;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case 0x41:
	case 0x42:
	case 0x43:
	case 0x44:
	case 0x45:
	case 0x47:
	case 0x48:
	case 0x4a:
	case 0x4b:
	case 0x4c:
	case 0x4d:
	case 0x4f:
	case 0x50:
	case 0x51:
	case 0x53:
	case 0x54:
	case 0x55:
	case 0x57:
	case 0x58:
	case 0x59:
	case 0x5a:
	case 0x5c:
	case 0x5d:
	case 0x5f:
	case 0x60:
	case 0x61:
	case 0x62:
	case 0x63:
	case 0x65:
	case 0x67:
	case 0x68:
	case 0x69:
	case 0x6a:
	case 0x6b:
	case 0x6c:
	case 0x6f:
	case 0x78:
	case 0x79:
	case 0x7a:
	case 0x7b:
	case 0x7c:
	case 0x7d:
		gb_analysis_mov_reg(mask, analysis->reg, op, data[0]);
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV; // LD
		break;
	case 0x0a:
	case 0x1a:
	case 0xf2:
		gb_analysis_load(mask, analysis->reg, op, data);
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case 0x2a:
	case 0x3a:
	case 0x46:
	case 0x4e:
	case 0x56:
	case 0x5e:
	case 0x66:
	case 0x6e:
	case 0x7e:
		gb_analysis_load_hl(mask, analysis->reg, op, data[0]);
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case 0xf0:
		gb_analysis_load(mask, analysis->reg, op, data);
		op->cycles = 12;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case 0xfa:
		gb_analysis_load(mask, analysis->reg, op, data);
		op->cycles = 16;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case 0x80:
	case 0x81:
	case 0x82:
	case 0x83:
	case 0x84:
	case 0x85:
	case 0x87:
	case 0x88:
	case 0x89:
	case 0x8a:
	case 0x8b:
	case 0x8c:
	case 0x8d:
	case 0x8f:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		break;
	case 0x09:
	case 0x19:
	case 0x29:
	case 0x39:
		gb_analysis_add_hl(mask, analysis->reg, op, data[0]);
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case 0x86:
	case 0x8e:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		op->cycles = 8;
		break;
	case 0xc6:
	case 0xce:
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		gb_analysis_xoaasc_imm(mask, analysis->reg, op, data);
		break;
	case 0xe8:
		gb_analysis_add_sp(mask, analysis->reg, op, data[1]);
		op->cycles = 16;
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case 0x90:
	case 0x91:
	case 0x92:
	case 0x93:
	case 0x94:
	case 0x95:
	case 0x97:
	case 0x98:
	case 0x99:
	case 0x9a:
	case 0x9b:
	case 0x9c:
	case 0x9d:
	case 0x9f:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		break;
	case 0x96:
	case 0x9e:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		op->cycles = 8;
		break;
	case 0xd6:
	case 0xde:
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		gb_analysis_xoaasc_imm(mask, analysis->reg, op, data);
		break;
	case 0xa0:
	case 0xa1:
	case 0xa2:
	case 0xa3:
	case 0xa4:
	case 0xa5:
	case 0xa7:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		break;
	case 0xe6:
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		gb_analysis_xoaasc_imm(mask, analysis->reg, op, data);
		break;
	case 0xa6:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		op->cycles = 8;
		break;
	case 0x07: // rlca
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		gb_analysis_cb_rlc(mask, analysis->reg, op, 7, true);
		break;
	case 0x17: // rla
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		gb_analysis_cb_rl(mask, analysis->reg, op, 7, true);
		break;
	case 0x0f: // rrca
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		gb_analysis_cb_rrc(mask, analysis->reg, op, 7, true);
		break;
	case 0x1f: // rra
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		gb_analysis_cb_rr(mask, analysis->reg, op, 7, true);
		break;
	case 0x2f:
		gb_analysis_xor_cpl(mask, analysis->reg, op); // cpl
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case 0x3f: // ccf
		gb_analysis_xor_ccf(mask, analysis->reg, op);
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case 0xa8:
	case 0xa9:
	case 0xaa:
	case 0xab:
	case 0xac:
	case 0xad:
	case 0xaf:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		break;
	case 0xee:
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		gb_analysis_xoaasc_imm(mask, analysis->reg, op, data);
		break;
	case 0xae:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		op->cycles = 8;
		break;
	case 0xb0:
	case 0xb1:
	case 0xb2:
	case 0xb3:
	case 0xb4:
	case 0xb5:
	case 0xb7:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		break;
	case 0xf6:
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		gb_analysis_xoaasc_imm(mask, analysis->reg, op, data);
		break;
	case 0xb6:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		op->cycles = 8;
		break;
	case 0xb8:
	case 0xb9:
	case 0xba:
	case 0xbb:
	case 0xbc:
	case 0xbd:
	case 0xbf:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		break;
	case 0xfe:
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		gb_analysis_xoaasc_imm(mask, analysis->reg, op, data);
		break;
	case 0xbe:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		gb_analysis_xoaasc(mask, analysis->reg, op, data);
		op->cycles = 8;
		break;
	case 0xc0:
	case 0xc8:
	case 0xd0:
	case 0xd8:
		gb_analysis_cond(analysis->reg, op, data[0]);
		gb_analysis_esil_cret(mask, op, data[0]);
		op->eob = true;
		op->cycles = 20;
		op->failcycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		break;
	case 0xd9:
		gb_analysis_mov_ime(mask, analysis->reg, op, data[0]);
		op->type2 = RZ_ANALYSIS_OP_TYPE_MOV;
		// fallthrough
	case 0xc9:
		op->eob = true;
		op->cycles = 16;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			gb_analysis_esil_ret(op);
		}
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -2;
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		if (mask & RZ_ANALYSIS_OP_MASK_IL && data[0] == 0xc9) {
			op->il_op = gb_il_ret(op->addr);
		}
		break;
	case 0x0b:
	case 0x1b:
	case 0x2b:
	case 0x3b:
		op->cycles = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		gb_analysis_id(mask, analysis, op, data[0]);
		break;
	case 0x05:
	case 0x0d:
	case 0x15:
	case 0x1d:
	case 0x25:
	case 0x2d:
	case 0x3d:
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_SUB; // DEC
		gb_analysis_id(mask, analysis, op, data[0]);
		break;
	case 0x35:
		op->cycles = 12;
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		gb_analysis_id(mask, analysis, op, data[0]);
		break;
	case 0xc5:
	case 0xd5:
	case 0xe5:
	case 0xf5:
		gb_analysis_pp(mask, analysis->reg, op, data[0]);
		op->cycles = 16;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 2;
		op->type = RZ_ANALYSIS_OP_TYPE_RPUSH;
		break;
	case 0xc1:
	case 0xd1:
	case 0xe1:
	case 0xf1:
		gb_analysis_pp(mask, analysis->reg, op, data[0]);
		op->cycles = 12;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -2;
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;
	case 0xc3:
		if (gb_op_calljump(analysis, op, data, addr)) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			gb_analysis_esil_jmp(op);
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		}
		op->il_op = gb_il_jmp(op->jump);
		op->eob = true;
		op->cycles = 16;
		op->fail = addr + ilen;
		break;
	case 0x18: // JR
		op->jump = addr + ilen + (st8)data[1];
		op->fail = addr + ilen;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			gb_analysis_esil_jmp(op);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_jmp(op->jump);
		}
		op->cycles = 12;
		op->eob = true;
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		break;
	case 0x20:
	case 0x28:
	case 0x30:
	case 0x38: // JR cond
		gb_analysis_cond(analysis->reg, op, data[0]);
		op->jump = addr + ilen + (st8)data[1];
		op->fail = addr + ilen;
		gb_analysis_cjmp(mask, op, data[0]);
		op->cycles = 12;
		op->failcycles = 8;
		op->eob = true;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case 0xc2:
	case 0xca:
	case 0xd2:
	case 0xda:
		if (gb_op_calljump(analysis, op, data, addr)) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UCJMP;
		}
		op->eob = true;
		gb_analysis_cond(analysis->reg, op, data[0]);
		gb_analysis_cjmp(mask, op, data[0]);
		op->cycles = 16;
		op->failcycles = 12;
		op->fail = addr + ilen;
		break;
	case 0xe9:
		op->cycles = 4;
		op->eob = true;
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		gb_analysis_jmp_hl(mask, analysis->reg, op);
		break;
	case 0x76:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->eob = true; // halt might wait for interrupts
		op->fail = addr + ilen;
		if (len > 1) {
			op->jump = addr + gbOpLength(gb_op[data[1]].type) + ilen;
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_halt();
		}
		break;
	case 0xcd:
		if (gb_op_calljump(analysis, op, data, addr)) {
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		}
		op->fail = addr + ilen;
		op->eob = true;
		gb_analysis_call(mask, op);
		op->cycles = 24;
		break;
	case 0xc4:
	case 0xcc:
	case 0xd4:
	case 0xdc:
		gb_analysis_cond(analysis->reg, op, data[0]);
		if (gb_op_calljump(analysis, op, data, addr)) {
			op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UCCALL;
		}
		op->fail = addr + ilen;
		op->eob = true;
		gb_analysis_ccall(mask, op, data[0]);
		op->cycles = 24;
		op->failcycles = 12;
		break;
	case 0xc7: // rst 0
		op->jump = 0x00;
		op->fail = addr + ilen;
		op->eob = true;
		gb_analysis_call(mask, op);
		op->cycles = 16;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case 0xcf: // rst 8
		op->jump = 0x08;
		op->fail = addr + ilen;
		op->eob = true;
		gb_analysis_call(mask, op);
		op->cycles = 16;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case 0xd7: // rst 16
		op->jump = 0x10;
		op->fail = addr + ilen;
		op->eob = true;
		gb_analysis_call(mask, op);
		op->cycles = 16;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case 0xdf: // rst 24
		op->jump = 0x18;
		op->fail = addr + ilen;
		op->eob = true;
		gb_analysis_call(mask, op);
		op->cycles = 16;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case 0xe7: // rst 32
		op->jump = 0x20;
		op->fail = addr + ilen;
		op->eob = true;
		gb_analysis_call(mask, op);
		op->cycles = 16;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case 0xef: // rst 40
		op->jump = 0x28;
		op->fail = addr + ilen;
		op->eob = true;
		gb_analysis_call(mask, op);
		op->cycles = 16;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case 0xf7: // rst 48
		op->jump = 0x30;
		op->fail = addr + ilen;
		op->eob = true;
		gb_analysis_call(mask, op);
		op->cycles = 16;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case 0xff: // rst 56
		op->jump = 0x38;
		op->fail = addr + ilen;
		op->eob = true;
		gb_analysis_call(mask, op);
		op->cycles = 16;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case 0xf3: // di
	case 0xfb: // ei
		gb_analysis_mov_ime(mask, analysis->reg, op, data[0]);
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case 0x37:
		gb_analysis_mov_scf(mask, analysis->reg, op);
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case 0x27: // daa
		op->cycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		gb_analysis_daa(mask, op);
		break;
	case 0x10: // stop
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			rz_strbuf_set(&op->esil, "TODO,stop");
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = gb_il_stop();
		}
		break;
	case 0xcb:
		op->nopcode = 2;
		switch (data[1] >> 3) {
		case 0:
			if ((data[1] & 7) == 6) {
				op->cycles = 16;
			} else {
				op->cycles = 8;
			}
			op->type = RZ_ANALYSIS_OP_TYPE_ROL;
			gb_analysis_cb_rlc(mask, analysis->reg, op, data[1], false);
			break;
		case 1:
			if ((data[1] & 7) == 6) {
				op->cycles = 16;
			} else {
				op->cycles = 8;
			}
			op->type = RZ_ANALYSIS_OP_TYPE_ROR;
			gb_analysis_cb_rrc(mask, analysis->reg, op, data[1], false);
			break;
		case 2:
			if ((data[1] & 7) == 6) {
				op->cycles = 16;
			} else {
				op->cycles = 8;
			}
			op->type = RZ_ANALYSIS_OP_TYPE_ROL;
			gb_analysis_cb_rl(mask, analysis->reg, op, data[1], false);
			break;
		case 3:
			if ((data[1] & 7) == 6) {
				op->cycles = 16;
			} else {
				op->cycles = 8;
			}
			op->type = RZ_ANALYSIS_OP_TYPE_ROR;
			gb_analysis_cb_rr(mask, analysis->reg, op, data[1], false);
			break;
		case 4:
			if ((data[1] & 7) == 6) {
				op->cycles = 16;
			} else {
				op->cycles = 8;
			}
			op->type = RZ_ANALYSIS_OP_TYPE_SAL;
			gb_analysis_cb_sla(mask, analysis->reg, op, data[1]);
			break;
		case 6:
			if ((data[1] & 7) == 6) {
				op->cycles = 16;
			} else {
				op->cycles = 8;
			}
			op->type = RZ_ANALYSIS_OP_TYPE_ROL;
			gb_analysis_cb_swap(mask, analysis->reg, op, data[1]);
			break;
		case 5:
			if ((data[1] & 7) == 6) {
				op->cycles = 16;
			} else {
				op->cycles = 8;
			}
			op->type = RZ_ANALYSIS_OP_TYPE_SAR;
			gb_analysis_cb_sra(mask, analysis->reg, op, data[1]);
			break;
		case 7:
			if ((data[1] & 7) == 6) {
				op->cycles = 16;
			} else {
				op->cycles = 8;
			}
			op->type = RZ_ANALYSIS_OP_TYPE_SHR;
			gb_analysis_cb_srl(mask, analysis->reg, op, data[1]);
			break;
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
		case 15:
			if ((data[1] & 7) == 6) {
				op->cycles = 12;
			} else {
				op->cycles = 8;
			}
			op->type = RZ_ANALYSIS_OP_TYPE_ACMP;
			gb_analysis_and_bit(mask, analysis->reg, op, data[1]);
			break; // bit
		case 16:
		case 17:
		case 18:
		case 19:
		case 20:
		case 21:
		case 22:
		case 23:
			if ((data[1] & 7) == 6) {
				op->cycles = 16;
			} else {
				op->cycles = 8;
			}
			gb_analysis_and_res(mask, analysis, op, data[1]);
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			break; // res
		case 24:
		case 25:
		case 26:
		case 27:
		case 28:
		case 29:
		case 30:
		case 31:
			if ((data[1] & 7) == 6) {
				op->cycles = 16;
			} else {
				op->cycles = 8;
			}
			gb_analysis_or_set(mask, analysis, op, data[1]);
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			break; // set
		}
	}
	if (op->type == RZ_ANALYSIS_OP_TYPE_CALL) {
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 2;
	}
	return op->size;
}

/*
	The reg-profile below does not represent the real gameboy registers.
		->There is no such thing like m, mpc or mbc. there is only pc.
	m and mbc should make it easier to inspect the current mbc-state, because
	the mbc can be seen as a register but it isn't. For the Gameboy the mbc is invisble.
*/

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	mpc\n"
		"=SP	sp\n"
		"=A0	af\n"
		"=A1	bc\n"
		"=A2	de\n"
		"=A3	hl\n"

		"gpr	mpc	.32	0	0\n"
		"gpr	pc	.16	0	0\n"
		"gpr	m	.16	2	0\n"

		"gpr	sp	.16	4	0\n"

		"gpr	af	.16	6	0\n"
		"gpr	f	.8	6	0\n"
		"gpr	a	.8	7	0\n"
		"gpr	Z	.1	.55	0\n"
		"gpr	N	.1	.54	0\n"
		"gpr	H	.1	.53	0\n"
		"gpr	C	.1	.52	0\n"

		"gpr	bc	.16	8	0\n"
		"gpr	c	.8	8	0\n"
		"gpr	b	.8	9	0\n"

		"gpr	de	.16	10	0\n"
		"gpr	e	.8	10	0\n"
		"gpr	d	.8	11	0\n"

		"gpr	hl	.16	12	0\n"
		"gpr	l	.8	12	0\n"
		"gpr	h	.8	13	0\n"

		"gpr	mbcrom	.16	14	0\n"
		"gpr	mbcram	.16	16	0\n"

		"gpr	ime	.1	18	0\n";
	return rz_str_dup(p);
}

static int esil_gb_init(RzAnalysisEsil *esil) {
	GBUser *user = RZ_NEW0(GBUser);
	rz_analysis_esil_set_op(esil, "daa", gb_custom_daa, 1, 1, RZ_ANALYSIS_ESIL_OP_TYPE_MATH | RZ_ANALYSIS_ESIL_OP_TYPE_CUSTOM);
	if (user) {
		if (esil->analysis) {
			esil->analysis->iob.read_at(esil->analysis->iob.io, 0x147, &user->mbc_id, 1);
			esil->analysis->iob.read_at(esil->analysis->iob.io, 0x148, &user->romsz_id, 1);
			esil->analysis->iob.read_at(esil->analysis->iob.io, 0x149, &user->ramsz_id, 1);
			if (esil->analysis->reg) { // initial values
				rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "mpc", -1), 0x100);
				rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "sp", -1), 0xfffe);
				rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "af", -1), 0x01b0);
				rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "bc", -1), 0x0013);
				rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "de", -1), 0x00d8);
				rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "hl", -1), 0x014d);
				rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "ime", -1), true);
			}
		}
		esil->cb.user = user;
	}
	return true;
}

static int esil_gb_fini(RzAnalysisEsil *esil) {
	RZ_FREE(esil->cb.user);
	return true;
}

static const char *gb_regs_bound[] = {
	"a", "b", "c", "d", "e", "h", "l", "sp", "Z", "N", "H", "C", "ime", NULL
};

static RzAnalysisILConfig *il_config(RzAnalysis *analysis) {
	RzAnalysisILConfig *r = rz_analysis_il_config_new(32, false, 16);
	r->reg_bindings = gb_regs_bound;
	return r;
}

RzAnalysisPlugin rz_analysis_plugin_gb = {
	.name = "gb",
	.desc = "Gameboy CPU code analysis plugin",
	.license = "LGPL3",
	.arch = "z80",
	.esil = true,
	.bits = 16,
	.op = &gb_anop,
	.get_reg_profile = &get_reg_profile,
	.esil_init = esil_gb_init,
	.esil_fini = esil_gb_fini,
	.il_config = il_config
};
