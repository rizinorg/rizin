// SPDX-FileCopyrightText: 2012-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

static void update_flags(RzStrBuf *out, int flags) {
	if (flags & V850_FLAG_CY) {
		rz_strbuf_append(out, "31,$c,cy,:=");
	}
	if (flags & V850_FLAG_OV) {
		rz_strbuf_append(out, ",31,$o,ov,:=");
	}
	if (flags & V850_FLAG_S) {
		rz_strbuf_append(out, ",31,$s,s,:=");
	}
	if (flags & V850_FLAG_Z) {
		rz_strbuf_append(out, ",$z,z,:=");
	}
}

static void clear_flags(RzStrBuf *out, int flags) {
	if (flags & V850_FLAG_CY) {
		rz_strbuf_append(out, ",0,cy,=");
	}
	if (flags & V850_FLAG_OV) {
		rz_strbuf_append(out, ",0,ov,=");
	}
	if (flags & V850_FLAG_S) {
		rz_strbuf_append(out, ",0,s,=");
	}
	if (flags & V850_FLAG_Z) {
		rz_strbuf_append(out, ",0,z,=");
	}
}

#define R1 GR_get(get_reg1(x))
#define R2 GR_get(get_reg2(x))

static void v850_esil(RzStrBuf *out, V850_Inst *x) {
	ut32 bitmask = 0;
	switch (x->id) {
	case V850_MOV:
		// 2 formats
		if (x->format == I_reg_reg) { // Format I
			rz_strbuf_appendf(out, "%s,%s,=", R1, R2);
		} else if (x->format == II_imm_reg) { // Format II
			rz_strbuf_appendf(out, "%" PFMT64d ",%s,=", (st64)(x->imm), R2);
		}
		break;
	case V850_MOVEA:
		// FIXME: to decide about reading 16/32 bit and use only macros to access
		rz_strbuf_appendf(out, "%s,0xffff,&,%u,+,%s,=", R1, get_imm16(x), R2);
		break;
	case V850_SLDB:
	case V850_SLDH:
	case V850_SLDW:
	case V850_SSTB:
	case V850_SSTH:
	case V850_SSTW:
		break;
	case V850_STB:
	case V850_STH:
	case V850_STW:
	case V850_STDW:
		rz_strbuf_appendf(out, "%s,0x%x,%s,+,=[4],",
			R2, x->disp, R1);
		break;

	case V850_NOT:
		rz_strbuf_appendf(out, "%s,0xffffffff,^,%s,=", R1, R2);
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_DIVH:
		rz_strbuf_appendf(out, "%s,%s,0xffff,&,/,%s,=",
			R1, R2, R2);
		update_flags(out, V850_FLAG_OV | V850_FLAG_S | V850_FLAG_Z);
		break;
	case V850_JMP:
		rz_strbuf_appendf(out, "%s,pc,=", R1);
		break;
	case V850_JARL:
		rz_strbuf_appendf(out, "pc,%s,=,pc,%u,+=", R2, x->disp);
		break;
	case V850_OR:
		rz_strbuf_appendf(out, "%s,%s,|=", R1, R2);
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_ORI:
		rz_strbuf_appendf(out, "%hu,%s,|,%s,=",
			get_imm16(x), R1, R2);
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_MULH:
		break;
	case V850_XOR:
		rz_strbuf_appendf(out, "%s,%s,^=", R1, R2);
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_XORI:
		rz_strbuf_appendf(out, "%hu,%s,^,%s,=", get_imm16(x), R1, R2);
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_AND:
		rz_strbuf_appendf(out, "%s,%s,&=", R1, R2);
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_ANDI:
		rz_strbuf_appendf(out, "%hu,%s,&,%s,=", get_imm16(x), R1, R2);
		update_flags(out, V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV | V850_FLAG_S);
		break;
	case V850_CMP:
		if (x->format == I_reg_reg) {
			rz_strbuf_appendf(out, "%s,%s,==", R1, R2);
		} else if (x->format == II_imm_reg) {
			rz_strbuf_appendf(out, "%d,%s,==", x->imm, R2);
		}
		update_flags(out, -1);
		break;
	case V850_TST:
		rz_strbuf_appendf(out, "%s,%s,&", R1, R2);
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_SUB:
		rz_strbuf_appendf(out, "%s,%s,-=", R1, R2);
		update_flags(out, -1);
		break;
	case V850_SUBR:
		rz_strbuf_appendf(out, "%s,%s,-,%s=", R2, R1, R2);
		update_flags(out, -1);
		break;
	case V850_ADD:
		if (x->format == I_reg_reg) {
			rz_strbuf_appendf(out, "%s,%s,+=", R1, R2);
		} else if (x->format == II_imm_reg) {
			rz_strbuf_appendf(out, "%d,%s,+=", (st8)x->imm, R2);
		}
		update_flags(out, -1);
		break;
	case V850_ADDI:
		rz_strbuf_appendf(out, "%d,%s,+,%s,=", (st32)get_imm16(x), R1, R2);
		update_flags(out, -1);
		break;
	case V850_BCOND:
		switch (get_cond(x)) {
		case V850_COND_BV:
			rz_strbuf_appendf(out, "ov");
			break;
		case V850_COND_BL:
			rz_strbuf_appendf(out, "cy");
			break;
		case V850_COND_BE:
			rz_strbuf_appendf(out, "z");
			break;
		case V850_COND_BNH:
			rz_strbuf_appendf(out, "cy,z,|");
			break;
		case V850_COND_BN:
			rz_strbuf_appendf(out, "s");
			break;
		case V850_COND_BR: // Always
			rz_strbuf_appendf(out, "1");
			break;
		case V850_COND_BLT:
			rz_strbuf_appendf(out, "s,ov,^");
			break;
		case V850_COND_BLE:
			rz_strbuf_appendf(out, "s,ov,^,z,|");
			break;
		case V850_COND_BNV:
			rz_strbuf_appendf(out, "ov,!");
			break;
		case V850_COND_BNL:
			rz_strbuf_appendf(out, "cy,!");
			break;
		case V850_COND_BNE:
			rz_strbuf_appendf(out, "z,!");
			break;
		case V850_COND_BH:
			rz_strbuf_appendf(out, "cy,z,|,!");
			break;
		case V850_COND_BP:
			rz_strbuf_appendf(out, "s,!");
			break;
		case V850_COND_BGE:
			rz_strbuf_appendf(out, "s,ov,^,!");
			break;
		case V850_COND_BGT:
			rz_strbuf_appendf(out, "s,ov,^,z,|,!");
			break;
		}
		rz_strbuf_appendf(out, ",?{,$$,%llu,+,pc,=,}", x->addr + x->disp);
		break;
	case V850_CLR1:
		bitmask = (1 << viii_bit(x));
		rz_strbuf_appendf(out, "%hu,%s,+,[1],%u,&,%hu,%s,+,=[1]", get_imm16(x), R1, bitmask, get_imm16(x), R1);
		// TODO: Read the value of the memory byte and set zero flag accordingly!
		break;
	case V850_NOT1:
		bitmask = (1 << viii_bit(x));
		rz_strbuf_appendf(out, "%hu,%s,+,[1],%u,^,%hu,%s,+,=[1]", get_imm16(x), R1, bitmask, get_imm16(x), R1);
		// TODO: Read the value of the memory byte and set zero flag accordingly!
		break;
	case V850_SHL:
		if (x->format == I_reg_reg) {
			rz_strbuf_appendf(out, "%s,%s,<<=", R1, R2);
		} else if (x->format == II_imm_reg) {
			rz_strbuf_appendf(out, "%d,%s,<<=", (st8)x->imm, R2);
		}
		update_flags(out, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_SHR:
		if (x->format == I_reg_reg) {
			rz_strbuf_appendf(out, "%s,%s,>>=", R1, R2);
		} else if (x->format == II_imm_reg) {
			rz_strbuf_appendf(out, "%d,%s,>>=", (st8)x->imm, R2);
		}
		update_flags(out, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_SAR: {
		ut16 imm5 = x->imm;
		const char *reg1 = R1;
		const char *reg2 = R2;
		if (x->format == I_reg_reg) {
			rz_strbuf_appendf(out, "31,%s,>>,?{,%s,32,-,%s,1,<<,--,<<,}{,0,},%s,%s,>>,|,%s,=", reg2, reg1, reg1, reg1, reg2, reg2);
		} else if (x->format == II_imm_reg) {
			rz_strbuf_appendf(out, "31,%s,>>,?{,%u,32,-,%u,1,<<,--,<<,}{,0,},%u,%s,>>,|,%s,=", reg2, (ut8)imm5, (ut8)imm5, (ut8)imm5, reg2, reg2);
		}
		update_flags(out, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	}
	default: break;
	}
}