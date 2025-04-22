// SPDX-FileCopyrightText: 2024 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rx_inst.h"

#define AssignOpVar(vid, field, expr) \
	{ \
		switch (vid) { \
		case 0: inst->v0.field = (expr); break; \
		case 1: inst->v1.field = (expr); break; \
		default: inst->v2.field = (expr); break; \
		} \
	}

RxOperandFlag rx_cb_map[16] = {
	RX_FLAG_C,
	RX_FLAG_Z,
	RX_FLAG_S,
	RX_FLAG_O,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_I,
	RX_FLAG_U,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
};

RxReg rx_cr_map[32] = {
	RX_REG_PSW,
	RX_REG_PC,
	RX_REG_USP,
	RX_REG_FPSW,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_BPSW,
	RX_REG_BPC,
	RX_REG_ISP,
	RX_REG_FINTV,
	RX_REG_INTB,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,

	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
};

static inline ut64 getbits(ut64 bytes, ut8 s, ut8 l) {
	return (bytes >> (64 - s - l)) & ((1ULL << l) - 1);
}

bool match_code(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.inst.tk_len;
	ut64 bits = getbits(bytes, s, l);
	if (bits == token->tk.inst.detail) {
		*bits_read += l;
		return true;
	}

	return false;
}

RxOpExtMark bits2mark(ut64 bits) {
	// 00 - B, 01 - W, 10 - L, 11 - UW
	return RX_EXT_B + bits;
}

bool match_mi(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.mi.tk_len;
	RxOpCode op = inst->op;
	ut64 bits = getbits(bytes, s, l);
	if (op == RX_OP_ADC) {
		if (bits != 2) {
			// only 10 - L allowed
			return false;
		}
	}

	inst->v0.v.reg.memex = bits2mark(bits);
	*bits_read += l;
	return true;
}

bool match_ld(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.ld.tk_len;
	ut64 ld_bits = getbits(bytes, s, l);
	ut8 dsp_len;

	// 11 - Rs
	switch (ld_bits) {
	case 3:
		*bits_read += l;
		return true;
	case 0:
		dsp_len = 0;
		break;
	case 1:
		dsp_len = 8;
		break;
	case 2:
		dsp_len = 16;
		break;
	default:
		rz_warn_if_reached();
		return 0;
	}

	AssignOpVar(token->tk.ld.vid, v.reg.as_indirect, true);
	AssignOpVar(token->tk.ld.vid, v.reg.dsp_width, dsp_len);

	*bits_read += l;
	return true;
}

bool match_ld_part(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.ld_part.tk_len;
	ut8 ldr = getbits(bytes, s, l);
	ut8 dsp_width;
	// 00 - None, 01 - dsp:8, 10 - dsp:16, 11 - invalid
	switch (ldr) {
	case 3:
		// invalid 11
		return false;
	case 0:
		dsp_width = 0;
		break;
	case 1:
		dsp_width = 8;
		break;
	case 2:
		dsp_width = 16;
		break;
	default:
		rz_warn_if_reached();
		return false;
	}

	AssignOpVar(token->tk.ld_part.vid, v.reg.dsp_width, dsp_width);
	AssignOpVar(token->tk.ld_part.vid, v.reg.as_indirect, true);
	*bits_read += l;
	return true;
}

ut8 bits2immlen(ut64 bits) {
	// 01 - SIMM: 8, 10 - SIMM: 16
	// 11 - SIMM: 24, 00 - IMM: 32
	switch (bits) {
	case 0:
		return 32;
	case 1:
		return 8;
	case 2:
		return 16;
	case 3:
		return 24;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

bool match_li(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.li.tk_len;
	AssignOpVar(token->tk.li.vid, v.imm.imm_width, bits2immlen(getbits(bytes, s, l)));
	*bits_read += l;
	return true;
}

bool match_reg(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.reg.tk_len;
	ut8 operand_id = token->tk.reg.vid;
	AssignOpVar(operand_id, v.reg.reg, RX_REG_R0 + getbits(bytes, s, l));
	AssignOpVar(operand_id, kind, RX_OPERAND_REG);
	*bits_read += l;
	return true;
}

bool match_reg_patched(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.reg.tk_len;
	ut8 operand_id = token->tk.reg.vid;
	ut64 reg_bits = getbits(bytes, s, l);
	RxOpCode op = inst->op;
	RxReg reg = RX_REG_R0 + reg_bits;

	if (op == RX_OP_PUSHM || op == RX_OP_POPM) {
		if (operand_id == 0) {
			// for opr0, R1 -> R14
			if (reg < RX_REG_R1 || reg > RX_REG_R14) {
				return false;
			}
		}
		if (operand_id == 1) {
			// for opr1
			if (reg < RX_REG_R2 || reg > RX_REG_R15) {
				return false;
			}
		}
	}

	if (op == RX_OP_EMUL || op == RX_OP_EMULU) {
		if (operand_id == 1) {
			// dest reg limit: R0 -> R14
			if (reg > RX_REG_R14) {
				return false;
			}
		}
	}

	if (op == RX_OP_RTSD) {
		if (reg < RX_REG_R1 || reg > RX_REG_R15) {
			return false;
		}
	}

	AssignOpVar(operand_id, v.reg.reg, RX_REG_R0 + reg_bits);
	AssignOpVar(operand_id, kind, RX_OPERAND_REG);
	*bits_read += l;
	return true;
}

bool match_ri(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.reg.tk_len;
	ut8 operand_id = token->tk.reg.vid;
	ut64 reg_bits = getbits(bytes, s, l);
	AssignOpVar(operand_id, v.reg.as_indirect, true);
	AssignOpVar(operand_id, v.reg.as_base, true);
	AssignOpVar(operand_id, v.reg.ri, RX_REG_R0 + reg_bits);
	*bits_read += l;
	return true;
}

bool match_cr(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.cr.tk_len;
	ut8 operand_id = token->tk.cr.vid;
	AssignOpVar(operand_id, v.reg.reg, rx_cr_map[(getbits(bytes, s, l))]);
	AssignOpVar(operand_id, kind, RX_OPERAND_REG);
	*bits_read += l;
	return true;
}

bool match_imm(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.imm.tk_len;
	ut8 operand_id = token->tk.imm.vid;
	AssignOpVar(operand_id, v.imm.imm, getbits(bytes, s, l));
	AssignOpVar(operand_id, v.imm.imm_width, l);
	AssignOpVar(operand_id, kind, RX_OPERAND_IMM);
	*bits_read += l;
	return true;
}

bool match_cond(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.cond.tk_len;
	ut8 operand_id = token->tk.cond.vid;
	ut64 cond_bits = getbits(bytes, s, l);
	RxOpCondMark cond_mark;
	if (inst->op == RX_OP_BMCND) {
		if (cond_bits >= 0xe) {
			// reserved val for cond
			return false;
		}
		cond_mark = RX_COND_EQ + cond_bits;
	} else {
		cond_mark = RX_COND_EQ + cond_bits;
	}
	AssignOpVar(operand_id, v.cond.cond, cond_mark);
	AssignOpVar(operand_id, kind, RX_OPERAND_COND);
	*bits_read += l;
	return true;
}

bool match_jump(RZ_OUT RxInst *inst, RxToken *token) {
	// judge as a unconditional jump
	inst->v0.kind = RX_OPERAND_COND;
	inst->v0.v.cond.cond = RX_COND_JUMP;
	return true;
}

bool match_cb(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.cb.tk_len;
	ut8 control_bits = getbits(bytes, s, l);

	inst->v0.v.flag = rx_cb_map[control_bits];
	inst->v0.kind = RX_OPERAND_FLAG;

	if (inst->v0.v.flag == RX_FLAG_RESERVED) {
		// TODO: should we use strict policy ?
		return false;
	}

	*bits_read += l;
	return true;
}

bool match_dsp(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	// DSP mark should follow a jump
	ut8 s = *bits_read;
	ut8 l = token->tk.dsp.tk_len;
	ut8 dsp_bits = getbits(bytes, s, l);

	// for condition dsp
	if (dsp_bits > 10 || dsp_bits < 3) {
		return false;
	}

	inst->v0.v.cond.pc_dsp_len = 3;
	inst->v0.v.cond.pc_dsp_val = dsp_bits;
	*bits_read += l;
	return true;
}

bool match_dsp_split(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.dsp_sp.tk_len;
	ut8 interval = token->tk.dsp_sp.interval;
	ut8 ll = token->tk.dsp_sp.tk_len_more;

	// | dsp_A | interval_bits | dsp_B |
	// dsp_bits = concat(dsp_A, dsp_B)
	ut8 dsp_bits = (getbits(bytes, s, l) << ll) | getbits(bytes, s + l + interval, ll);
	ut8 operand_id = token->tk.dsp_sp.vid;
	AssignOpVar(operand_id, v.reg.dsp_val, dsp_bits);
	AssignOpVar(operand_id, v.reg.dsp_width, l + ll);
	AssignOpVar(operand_id, v.reg.as_indirect, true);

	*bits_read += l;
	return true;
}

bool match_ignore(RxToken *token, RZ_OUT ut8 *bits_read) {
	ut8 l = token->tk.reserved.tk_len;
	*bits_read += l;
	return true;
}

bool match_sz(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.sz.tk_len;
	ut8 sz = getbits(bytes, s, l);
	if (sz == 3) {
		// invalid 11
		return false;
	}
	inst->sz_mark = RX_EXT_B + sz;
	*bits_read += l;
	return true;
}

bool match_ad(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 l = token->tk.ad.tk_len;
	ut8 addr_bits = getbits(bytes, s, l);

	if (inst->op == RX_OP_MOVU) {
		// 10 [Rs+] and 11 [-Rs] is allowed
		if (addr_bits < 2) {
			return false;
		}
	}

	// 00 Rs, [Rd+], 01: Rs, [-Rd], inc/dec on Rd
	// 10 [Rs+], Rd, 11: [-Rs], Rd, inc/dec on Rs
	switch (addr_bits) {
	case 0:
		inst->v1.v.reg.as_indirect = true;
		inst->v1.v.reg.fix_mode = RX_FIXOP_POST_INC;
		break;
	case 1:
		inst->v1.v.reg.as_indirect = true;
		inst->v1.v.reg.fix_mode = RX_FIXOP_PRE_DEC;
		break;
	case 2:
		inst->v0.v.reg.as_indirect = true;
		inst->v0.v.reg.fix_mode = RX_FIXOP_POST_INC;
		break;
	case 3:
		inst->v0.v.reg.as_indirect = true;
		inst->v0.v.reg.fix_mode = RX_FIXOP_PRE_DEC;
		break;
	default:
		rz_warn_if_reached();
		return false;
	}

	*bits_read += l;
	return true;
}

static ut32 pack_big(ut32 raw_data, ut8 len_in_bytes) {
	ut32 result = 0;
	for (int i = 0; i < len_in_bytes; i++) {
		ut32 byte = (raw_data >> (8 * i)) & 0xFF;
		result = (result << 8) | byte;
	}
	return result;
}

bool pack_data(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	ut8 s = *bits_read;
	ut8 vid = token->tk.data.vid;
	ut8 l;
	ut32 follow_data;

	RxOperand *opr = vid == 0 ? &(inst->v0) : vid == 1 ? &(inst->v1)
							   : &(inst->v2);

	ut8 data_type = token->tk.data.data_type;
	if (data_type == 2) {
		// pack dsp
		l = opr->v.reg.dsp_width;
		follow_data = getbits(bytes, s, l);
		opr->v.reg.dsp_val = pack_big(follow_data, l / 8);
		*bits_read += l;
		return true;
	}

	if (data_type == 1) {
		// pack imm
		if (token->tk.data.fixed_len) {
			l = token->tk.data.fixed_len;
			opr->v.imm.imm_width = l;
		} else {
			l = opr->v.imm.imm_width;
		}
		opr->kind = RX_OPERAND_IMM;
		follow_data = getbits(bytes, s, l);
		opr->v.imm.imm = pack_big(follow_data, l / 8);
		*bits_read += l;
		return true;
	}

	if (data_type == 3) {
		// pack pcdsp
		if (token->tk.data.fixed_len) {
			l = token->tk.data.fixed_len;
			opr->v.cond.pc_dsp_len = l;
		} else {
			l = opr->v.cond.pc_dsp_len;
		}
		follow_data = getbits(bytes, s, l);
		opr->v.cond.pc_dsp_val = pack_big(follow_data, l / 8);
		*bits_read += l;
		return true;
	}

	rz_warn_if_reached();
	return false;
}

bool check_some(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
	// a token hook for parser loop
	if (inst->op == RX_OP_MOV) {
		// check order of src and dest
		// for ad[1:0], if 00 or 01, mov dst, src
		// for ad[0:1], if 10 or 11, mov src, dst
		if (inst->v1.kind == RX_OPERAND_REG) {
			// parse RegBist[3:0] as dest(V1)
			if (inst->v0.v.reg.fix_mode != RX_FIXOP_NON) {
				// but set src fixed, parse failed
				return false;
			}
		}
		if (inst->v0.kind == RX_OPERAND_REG) {
			if (inst->v1.v.reg.fix_mode != RX_FIXOP_NON) {
				return false;
			}
		}
	}
	return true;
}

/**
 * \brief Parse bytes according to the given RX instruction description to see if it matches
 * \param inst an empty RxInst to be filled
 * \param desc an RxDesc to be matched
 * \param bytes_read bytes read
 * \param bytes prefetched bytes
 * \return true if parse success, false otherwise
 */
bool rx_try_match_and_parse(RZ_OUT RxInst *inst, RxDesc *desc, st32 RZ_OUT *bytes_read, ut64 bytes) {
	ut8 read_bits = 0;
	bool is_valid = true;
	inst->op = desc->op;
	for (int tki = 0; tki < MAX_TOKEN; ++tki) {
		if (!is_valid) {
			return false;
		}
		RxTokenType tk_type = desc->tks[tki].type;
		RxToken *token = &(desc->tks[tki]);

		if (tk_type == RX_TOKEN_NON) {
			// break the loop
			break;
		}

		switch (tk_type) {
		case RX_TOKEN_INST:
			is_valid = match_code(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_LD:
			is_valid = match_ld(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_LD_PART:
			is_valid = match_ld_part(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_LI:
			is_valid = match_li(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_MI:
			is_valid = match_mi(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_DSP:
			is_valid = match_dsp(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_DSP_SPLIT:
			is_valid = match_dsp_split(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_SZ:
			is_valid = match_sz(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_AD:
			is_valid = match_ad(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_REG:
			is_valid = match_reg(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_CR:
			is_valid = match_cr(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_CB:
			is_valid = match_cb(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_IMM:
			is_valid = match_imm(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_COND:
			is_valid = match_cond(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_IGNORE:
			match_ignore(token, &read_bits);
			break;
		case RX_TOKEN_JMP:
			is_valid = match_jump(inst, token);
			break;
		case RX_TOKEN_REG_LIMIT:
			is_valid = match_reg_patched(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_HOOK:
			is_valid = check_some(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_RI:
			is_valid = match_ri(inst, token, &read_bits, bytes);
			break;
		case RX_TOKEN_DATA:
			pack_data(inst, token, &read_bits, bytes);
			break;
		default:
			rz_warn_if_reached();
			return false;
		}
	}

	// assume bits / 8 = bytes should be integer
	if ((read_bits & 7)) {
		// instruction are defined as bytes
		rz_warn_if_reached();
		return false;
	}

	*bytes_read = (st32)read_bits / 8;
	return true;
}
