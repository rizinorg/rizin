// SPDX-FileCopyrightText: 2015-2019 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2025 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <string.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "mcs96/mcs96.h"
#include "rz_analysis.h"
#include "rz_util/rz_pj.h"

typedef struct {
	RzPVector /*<RzAsmTokenPattern *>*/ *token_patterns;
} Mcs96Context;

#define TOKEN(_type, _pat) \
	do { \
		RzAsmTokenPattern *pat = RZ_NEW0(RzAsmTokenPattern); \
		pat->type = RZ_ASM_TOKEN_##_type; \
		pat->pattern = strdup(_pat); \
		rz_pvector_push(pvec, pat); \
	} while (0)

static RZ_OWN RzPVector /*<RzAsmTokenPattern *>*/ *get_token_patterns() {
	RzPVector *pvec = rz_pvector_new(rz_asm_token_pattern_free);
	if (!pvec) {
		return NULL;
	}

	TOKEN(META, "(\\[|\\])");
	TOKEN(OPERATOR, "(\\+)");
	TOKEN(NUMBER, "(0x[[:digit:]abcdef]+)");
	TOKEN(MNEMONIC, "([[:alpha:]]+)");
	TOKEN(SEPARATOR, "([[:blank:]]+)");

	return pvec;
}

static void decode_operands(RzAsmOp *op, const char *mnemonic, const ut8 *buf, int size, ut32 isa_bit) {
	if (size < 1) {
		return;
	}

	// Skip operand decoding for invalid instructions
	if (strcmp(mnemonic, "invalid") == 0) {
		rz_asm_op_set_asm(op, "invalid");
		return;
	}

	ut8 opcode = buf[0];
	ut32 instr_fmt = mcs96_op[opcode].type;

	if (instr_fmt & MCS96_FMT_OPC_BYTEOPR && size == 2) {
		ut8 operand = buf[1];
		rz_asm_op_setf_asm(op, "%s 0x%02x", mnemonic, operand);
	} else if (instr_fmt & MCS96_FMT_2_BYTE_NOP && size == 2) {
		rz_asm_op_set_asm(op, mnemonic);
	} else if (instr_fmt & MCS96_FMT_OPC_IMM11 && size == 2) {
		st16 imm11 = extract_disp11(opcode, buf[1]);
		rz_asm_op_setf_asm(op, "%s 0x%04x", mnemonic, (ut16)imm11);
	} else if (instr_fmt & MCS96_FMT_OPC_BYTEOPR_X2 && size == 3) {
		ut8 opr0 = buf[2];
		ut8 opr1 = buf[1];
		rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x", mnemonic, opr0, opr1);
	} else if (instr_fmt & MCS96_FMT_OPC_IMM16 && size == 3) {
		st16 imm = (st16)rz_read_le16(buf + 1);
		rz_asm_op_setf_asm(op, "%s 0x%04x", mnemonic, (ut16)imm);
	} else if (instr_fmt & MCS96_FMT_TIJMP && size == 4) {
		ut8 index = buf[1];
		ut8 mask = buf[2];
		ut8 tbase = buf[3];
		rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x[0x%02x]", mnemonic, tbase, index, mask);
	} else if (instr_fmt & MCS96_FMT_OPC_IMM11_BYTEOPR && size == 3) {
		st16 imm11 = extract_disp11(opcode, buf[2]);
		ut8 reg = buf[1];
		rz_asm_op_setf_asm(op, "%s 0x%02x 0x%04x", mnemonic, reg, (ut16)imm11);
	} else if (instr_fmt & MCS96_FMT_OPC_IMM24 && size == 4) {
		ut32 imm = (ut32)rz_read_le24(buf + 1);
		rz_asm_op_setf_asm(op, "%s 0x%06x", mnemonic, (ut32)imm);
	} else if (instr_fmt & MCS96_FMT_OPC_INDEX && size >= 1) {
		ut8 reg = buf[1] & 0xFE; // erase lsb
		if (size == 3) {
			ut8 offset = buf[2];
			rz_asm_op_setf_asm(op, "%s 0x%02x[0x%02x]", mnemonic, offset, reg);
		} else if (size == 4) {
			ut16 offset = rz_read_le16(buf + 2);
			rz_asm_op_setf_asm(op, "%s 0x%04x[0x%02x]", mnemonic, offset, reg);
		}
	} else if (instr_fmt & MCS96_FMT_EXTENDED_INDEXED && size == 6) {
		ut8 dst = buf[5];
		ut8 base = buf[1];
		st32 offset = (st32)rz_read_le24(buf + 2);
		rz_asm_op_setf_asm(op, "%s 0x%02x 0x%06x[0x%02x]", mnemonic, dst, (ut32)offset, base);
	} else if (instr_fmt & MCS96_FMT_2OP) {
		ut8 address_mode = opcode & 0x3;
		if (address_mode == MCS96_ADDRESSING_REG_DIRECT && size == 3) {
			ut8 dst = buf[2];
			ut8 src_reg = buf[1];
			rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x", mnemonic, dst, src_reg);
		} else if (address_mode == MCS96_ADDRESSING_IMMEDIATE) {
			if (size == 3) {
				ut8 dst = buf[2];
				ut8 src_imm8 = buf[1];
				rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x", mnemonic, dst, src_imm8);
			} else if (size == 4) {
				ut8 dst = buf[3];
				ut16 src_imm16 = rz_read_le16(buf + 1);
				rz_asm_op_setf_asm(op, "%s 0x%02x 0x%04x", mnemonic, dst, src_imm16);
			}
		} else if (address_mode == MCS96_ADDRESSING_INDIRECT && size == 3) {
			ut8 dst = buf[2];
			boolt autoincrement = buf[1] & 0x1;
			ut8 src_reg = buf[1] & 0xFE;
			if (autoincrement) {
				rz_asm_op_setf_asm(op, "%s 0x%02x [0x%02x]+", mnemonic, dst, src_reg);
			} else {
				rz_asm_op_setf_asm(op, "%s 0x%02x [0x%02x]", mnemonic, dst, src_reg);
			}
		} else if (address_mode == MCS96_ADDRESSING_INDEXED) {
			if (size == 4) {
				ut8 dst = buf[3];
				ut8 offset = buf[2];
				ut8 base = buf[1] & 0xFE; // erase lsb
				rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x[0x%02x]", mnemonic, dst, offset, base);
			} else if (size == 5) {
				ut8 dst = buf[4];
				ut16 offset = rz_read_le16(buf + 2);
				ut8 base = buf[1] & 0xFE; // erase lsb
				rz_asm_op_setf_asm(op, "%s 0x%02x 0x%04x[0x%02x]", mnemonic, dst, offset, base);
			}
		}
	} else if (instr_fmt & MCS96_FMT_3OP) {
		ut8 address_mode = opcode & 0x3;
		if (address_mode == MCS96_ADDRESSING_REG_DIRECT && size == 4) {
			ut8 dst = buf[3];
			ut8 src0_reg = buf[2];
			ut8 src1_reg = buf[1];
			rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x 0x%02x", mnemonic, dst, src0_reg, src1_reg);
		} else if (address_mode == MCS96_ADDRESSING_IMMEDIATE) {
			if (size == 4) {
				ut8 dst = buf[3];
				ut8 src0_reg = buf[2];
				ut8 src_imm8 = buf[1];
				rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x 0x%02x", mnemonic, dst, src0_reg, src_imm8);
			} else if (size == 5) {
				ut8 dst = buf[4];
				ut8 src0_reg = buf[3];
				ut16 src_imm16 = rz_read_le16(buf + 1);
				rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x 0x%04x", mnemonic, dst, src0_reg, src_imm16);
			}
		} else if (address_mode == MCS96_ADDRESSING_INDIRECT && size == 4) {
			ut8 dst = buf[3];
			ut8 src0_reg = buf[2];
			ut8 src1_reg = buf[1] & 0xFE;
			boolt autoincrement = buf[1] & 0x1;
			if (autoincrement) {
				rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x [0x%02x]+", mnemonic, dst, src0_reg, src1_reg);
			} else {
				rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x [0x%02x]", mnemonic, dst, src0_reg, src1_reg);
			}
		} else if (address_mode == MCS96_ADDRESSING_INDEXED) {
			if (size == 5) {
				ut8 dst = buf[4];
				ut8 src1_reg = buf[3];
				ut8 offset = buf[2];
				ut8 base = buf[1] & 0xFE; // erase lsb
				rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x 0x%02x[0x%02x]", mnemonic, dst, src1_reg, offset, base);
			} else if (size == 6) {
				ut8 dst = buf[5];
				ut8 src1_reg = buf[4];
				ut16 offset = rz_read_le16(buf + 2);
				ut8 base = buf[1] & 0xFE; // erase lsb
				rz_asm_op_setf_asm(op, "%s 0x%02x 0x%02x 0x%04x[0x%02x]", mnemonic, dst, src1_reg, offset, base);
			}
		}
	} else {
		rz_asm_op_set_asm(op, mnemonic);
	}
}

static const char *decode_mnemonic(const ut8 *buf, int size, ut32 isa_bit) {
	if (size < 1) {
		return "invalid";
	}

	if (buf[0] == 0x0d && isa_bit == MCS96_80296 && size == 3) { // SHLL/MVAC/MSAC
		ut8 lreg_bits = buf[2] & 0x3;
		// lreg.1 lreg.0 Execute
		// 0      0      SHLL
		// 0      1      MVAC
		// 1      0      Reserved
		// 1      1      MSAC
		switch (lreg_bits) {
		case 0x0:
			return "shll";
		case 0x1:
			return "mvac";
		case 0x3:
			return "msac";
		default:
			return "invalid";
		}
	} else if (buf[0] == 0x40 && isa_bit == MCS96_80296 && size == 4 && buf[size - 1] == 0x04) { // AND/RPT/RPTxxx/RPTI/RPTIxxx
		// RPT waop
		// (010000aa) (waop) (00) (04)
		// RPTxxx
		// (010000aa) (waop) (10 - 1F) (04)
		// RPTI
		// (010000aa) (waop) (20) (04)
		// RPTIxxx
		// (010000aa) (waop) (30 - 3F) (04)
		switch (buf[size - 2]) {
		case 0x00:
			return "rpt";
		case 0x10:
			return "rptnst";
		case 0x11:
			return "rptnh";
		case 0x12:
			return "rptgt";
		case 0x13:
			return "rptnc";
		case 0x14:
			return "rptnvt";
		case 0x15:
			return "rptnv";
		case 0x16:
			return "rptge";
		case 0x17:
			return "rptne";
		case 0x18:
			return "rptst";
		case 0x19:
			return "rpth";
		case 0x1a:
			return "rptle";
		case 0x1b:
			return "rptc";
		case 0x1c:
			return "rptvt";
		case 0x1d:
			return "rptv";
		case 0x1e:
			return "rptlt";
		case 0x1f:
			return "rpte";
		case 0x20:
			return "rpti";
		case 0x30:
			return "rptinst";
		case 0x31:
			return "rptinh";
		case 0x32:
			return "rptigt";
		case 0x33:
			return "rptinc";
		case 0x34:
			return "rptinvt";
		case 0x35:
			return "rptinv";
		case 0x36:
			return "rptige";
		case 0x37:
			return "rptine";
		case 0x38:
			return "rptist";
		case 0x39:
			return "rptih";
		case 0x3a:
			return "rptile";
		case 0x3b:
			return "rptic";
		case 0x3c:
			return "rptivt";
		case 0x3d:
			return "rptiv";
		case 0x3e:
			return "rptilt";
		case 0x3f:
			return "rptie";
		default:
			return "and";
		}
	} else if (size > 2 && mcs96_op[buf[1]].type & MCS96_FE) {
		const ut32 fe_idx = ((buf[1] & 0x70) >> 4) ^ 0x4;
		return mcs96_fe_op[fe_idx];
	} else {
		return mcs96_op[buf[0]].ins;
	}
}

static bool mcs96_init(void **u) {
	Mcs96Context *ctx = RZ_NEW0(Mcs96Context);
	if (!ctx) {
		return false;
	}
	ctx->token_patterns = get_token_patterns();
	rz_asm_compile_token_patterns(ctx->token_patterns);
	*u = ctx;
	return true;
}

static bool mcs96_fini(void *u) {
	if (!u) {
		return true;
	}
	Mcs96Context *ctx = u;
	rz_pvector_free(ctx->token_patterns);
	free(u);
	return true;
}

static int mcs96_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (len > 1 && !memcmp(buf, "\xff\xff", 2)) {
		return -1;
	}

	if (!a->plugin_data) {
		return -1;
	}
	Mcs96Context *ctx = a->plugin_data;

	ut32 isa_bit = MCS96_8096; // default
	if (a->cpu && *a->cpu) {
		if (strstr(a->cpu, "80296")) {
			isa_bit = MCS96_80296;
		} else if (strstr(a->cpu, "80196")) {
			isa_bit = MCS96_80196;
		}
	}

	op->size = mcs96_len(isa_bit, buf, len);
	const char *mnemonic = decode_mnemonic(buf, op->size, isa_bit);
	decode_operands(op, mnemonic, buf, op->size, isa_bit);

	op->asm_toks = rz_asm_tokenize_asm_regex(&op->buf_asm, ctx->token_patterns);
	return op->size;
}

RzAsmPlugin rz_asm_plugin_mcs96 = {
	.name = "mcs96",
	.desc = "Intel MCS-96 disassembler",
	.cpus = "8096,80196,80296",
	.arch = "mcs96",
	.license = "LGPL3",
	.author = "condret",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.init = &mcs96_init,
	.fini = &mcs96_fini,
	.disassemble = &mcs96_disassemble
};
