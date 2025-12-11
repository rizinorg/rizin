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

typedef enum {
	MCS96_ADDRESSING_REG_DIRECT = 0, // 2 reg
	MCS96_ADDRESSING_IMMEDIATE = 1, // 1 reg + 1 imm
	MCS96_ADDRESSING_INDIRECT = 2, //
	MCS96_ADDRESSING_INDEXED = 3,
} MCS96_ADDRESSING_MODE;

/**
 * @brief computes the length of an instruction.
 * @return int the length of the instruction. returns -1 when invalid.
 */
static int mcs96_len(ut32 isa_bit, const ut8 *buf, int len, RzStrBuf *asm_buf) {
	if (len < 1) {
		return 0;
	}

	if (!(mcs96_op[buf[0]].isa & isa_bit)) { // unsupported instruction
		rz_strbuf_set(asm_buf, "invalid");
		return -1;
	}

	int ret = 1;
	if (buf[0] == 0xfe) {
		if (isa_bit == MCS96_80296) {
			rz_strbuf_set(asm_buf, "invalid");
			return -1;
		}

		if (len < 2) {
			return 0;
		}
		if (mcs96_op[buf[1]].type & MCS96_FE) {
			if (mcs96_op[buf[1]].type & MCS96_5B_OR_6B) {
				if (len < 3) {
					return 0;
				}
				ret = 6 + (buf[2] & 0x1);
			}
			if (mcs96_op[buf[1]].type & MCS96_4B_OR_5B) {
				if (len < 3) {
					return 0;
				}
				ret = 5 + (buf[2] & 0x1);
			}
			if (mcs96_op[buf[1]].type & MCS96_3B_OR_4B) {
				if (len < 3) {
					return 0;
				}
				ret = 4 + (buf[1] & 0x1);
			}
			if (mcs96_op[buf[1]].type & MCS96_5B) {
				ret = 6;
			}
			if (mcs96_op[buf[1]].type & MCS96_4B) {
				ret = 5;
			}
			if (mcs96_op[buf[1]].type & MCS96_3B) {
				ret = 4;
			}
			if (mcs96_op[buf[1]].type & MCS96_2B) {
				ret = 3;
			}
			if (ret > len) {
				ret = 0;
			}
			return ret;
		}
	}
	if (mcs96_op[buf[0]].type & MCS96_5B_OR_6B) {
		if (len < 2) {
			return 0;
		}
		ret = 5 + (buf[1] & 0x1);
	}
	if (mcs96_op[buf[0]].type & MCS96_4B_OR_5B) {
		if (len < 2) {
			return 0;
		}
		ret = 4 + (buf[1] & 0x1);
	}
	if (mcs96_op[buf[0]].type & MCS96_3B_OR_4B) {
		if (len < 2) {
			return 0;
		}
		ret = 3 + (buf[1] & 0x1);
	}
	if (mcs96_op[buf[0]].type & MCS96_6B) {
		ret = 6;
	}
	if (mcs96_op[buf[0]].type & MCS96_5B) {
		ret = 5;
	}
	if (mcs96_op[buf[0]].type & MCS96_4B) {
		ret = 4;
	}
	if (mcs96_op[buf[0]].type & MCS96_3B) {
		ret = 3;
	}
	if (mcs96_op[buf[0]].type & MCS96_2B) {
		ret = 2;
	}
	if (ret > len) {
		ret = 0;
	}
	return ret;
}

static void decode_mnemonic(RzStrBuf *asm_buf, const ut8 *buf, int size, ut32 isa_bit) {
	if (size <= 0) {
		return;
	}

	if (buf[0] == 0x0d && isa_bit == MCS96_80296 && size == 3) { // SHLL/MVAC/MSAC
		ut8 lreg_bits = buf[2] & 0x3;
		// lreg.1 lreg.0 Execute
		// 0      0      SHLL
		// 0      1      MVAC
		// 1      0      Reserved
		// 1      1      MSAC
		const char *mnemonic;
		switch (lreg_bits) {
		case 0x0:
			mnemonic = "shll";
			break;
		case 0x1:
			mnemonic = "mvac";
			break;
		case 0x3:
			mnemonic = "msac";
			break;
		default:
			mnemonic = "invalid";
			break;
		}
		rz_strbuf_set(asm_buf, mnemonic);
	} else if (buf[0] == 0x40 && isa_bit == MCS96_80296 && buf[size - 1] == 0x04 && size == 4) { // AND/RPT/RPTxxx/RPTI/RPTIxxx
		// RPT waop
		// (010000aa) (waop) (00) (04)
		// RPTxxx
		// (010000aa) (waop) (10 - 1F) (04)
		// RPTI
		// (010000aa) (waop) (20) (04)
		// RPTIxxx
		// (010000aa) (waop) (30 - 3F) (04)
		const char *mnemonic;
		switch (buf[size - 2]) {
		case 0x00:
			mnemonic = "rpt";
			break;
		case 0x10:
			mnemonic = "rptnst";
			break;
		case 0x11:
			mnemonic = "rptnh";
			break;
		case 0x12:
			mnemonic = "rptgt";
			break;
		case 0x13:
			mnemonic = "rptnc";
			break;
		case 0x14:
			mnemonic = "rptnvt";
			break;
		case 0x15:
			mnemonic = "rptnv";
			break;
		case 0x16:
			mnemonic = "rptge";
			break;
		case 0x17:
			mnemonic = "rptne";
			break;
		case 0x18:
			mnemonic = "rptst";
			break;
		case 0x19:
			mnemonic = "rpth";
			break;
		case 0x1a:
			mnemonic = "rptle";
			break;
		case 0x1b:
			mnemonic = "rptc";
			break;
		case 0x1c:
			mnemonic = "rptvt";
			break;
		case 0x1d:
			mnemonic = "rptv";
			break;
		case 0x1e:
			mnemonic = "rptlt";
			break;
		case 0x1f:
			mnemonic = "rpte";
			break;
		case 0x20:
			mnemonic = "rpti";
			break;
		case 0x30:
			mnemonic = "rptinst";
			break;
		case 0x31:
			mnemonic = "rptinh";
			break;
		case 0x32:
			mnemonic = "rptigt";
			break;
		case 0x33:
			mnemonic = "rptinc";
			break;
		case 0x34:
			mnemonic = "rptinvt";
			break;
		case 0x35:
			mnemonic = "rptinv";
			break;
		case 0x36:
			mnemonic = "rptige";
			break;
		case 0x37:
			mnemonic = "rptine";
			break;
		case 0x38:
			mnemonic = "rptist";
			break;
		case 0x39:
			mnemonic = "rptih";
			break;
		case 0x3a:
			mnemonic = "rptile";
			break;
		case 0x3b:
			mnemonic = "rptic";
			break;
		case 0x3c:
			mnemonic = "rptivt";
			break;
		case 0x3d:
			mnemonic = "rptiv";
			break;
		case 0x3e:
			mnemonic = "rptilt";
			break;
		case 0x3f:
			mnemonic = "rptie";
			break;
		default:
			mnemonic = "and";
			break;
		}
		rz_strbuf_set(asm_buf, mnemonic);
	} else if (mcs96_op[buf[1]].type & MCS96_FE && size > 2) {
		const ut32 fe_idx = ((buf[1] & 0x70) >> 4) ^ 0x4;
		rz_strbuf_set(asm_buf, mcs96_fe_op[fe_idx]);
	} else {
		rz_strbuf_set(asm_buf, mcs96_op[buf[0]].ins);
	}
}

/**
 * Extract 11-bit signed displacement from sjmp/scall instruction.
 * Format: (instr|xxx)(disp-low)
 *
 * \param opcode First byte of the instruction, containing upper 3 bits of the displacement
 * \param disp_low Second byte of the instruction, containing lower 8 bits of the displacement
 * \return Sign-extended 16-bit displacement (-1024 to +1023)
 */
static st16 extract_disp11(ut8 opcode, ut8 disp_low) {
	st16 upper3bits = (st16)(opcode & 0x07); // 0b00000111
	st16 disp = (upper3bits << 8) | disp_low;

	// Sign-extend from 11 bits to 16 bits
	if (disp & 0x400) { // Check if bit 10 (sign bit) is set
		disp |= 0xF800; // Set bits 15-11 to extend the sign
	}

	return disp;
}

static void decode_operands(RzStrBuf *asm_buf, const ut8 *buf, int size, ut32 isa_bit) {

	if (size < 1) {
		return;
	}

	// Skip operand decoding for invalid instructions
	const char *str = rz_strbuf_get(asm_buf);
	if (str && strcmp(str, "invalid") == 0) {
		return;
	}

	ut8 opcode = buf[0];
	ut32 instr_fmt = mcs96_op[opcode].type;

	if (instr_fmt & MCS96_FMT_OPC_BYTEOPR && size == 2) {
		ut8 operand = buf[1];
		rz_strbuf_appendf(asm_buf, " 0x%02x", operand);
	} else if (instr_fmt & MCS96_FMT_2_BYTE_NOP && size == 2) {
		return; // do nothing
	} else if (instr_fmt & MCS96_FMT_OPC_IMM11 && size == 2) {
		st16 imm11 = extract_disp11(opcode, buf[1]);
		rz_strbuf_appendf(asm_buf, " 0x%04x", (ut16)imm11);
	} else if (instr_fmt & MCS96_FMT_OPC_BYTEOPR_X2 && size == 3) {
		ut8 opr0 = buf[2];
		ut8 opr1 = buf[1];
		rz_strbuf_appendf(asm_buf, " 0x%02x 0x%02x", opr0, opr1);
	} else if (instr_fmt & MCS96_FMT_OPC_IMM16 && size == 3) {
		st16 imm = (st16)rz_read_le16(buf + 1);
		rz_strbuf_appendf(asm_buf, " 0x%04x", (ut16)imm);
	} else if (instr_fmt & MCS96_FMT_TIJMP && size == 4) {
		ut8 index = buf[1];
		ut8 mask = buf[2];
		ut8 tbase = buf[3];
		rz_strbuf_appendf(asm_buf, " 0x%02x 0x%02x[0x%02x]", tbase, index, mask);
	} else if (instr_fmt & MCS96_FMT_OPC_IMM11_BYTEOPR && size == 3) {
		st16 imm11 = extract_disp11(opcode, buf[2]);
		ut8 reg = buf[1];
		rz_strbuf_appendf(asm_buf, " 0x%02x 0x%04x", reg, (ut16)imm11);
	} else if (instr_fmt & MCS96_FMT_OPC_IMM24 && size == 4) {
		ut32 imm = (ut32)rz_read_le24(buf + 1);
		rz_strbuf_appendf(asm_buf, " 0x%06x", (ut32)imm);
	} else if (instr_fmt & MCS96_FMT_OPC_INDEX && size >= 1) {
		ut8 reg = buf[1] & 0xFE; // erase lsb
		if (size == 3) {
			ut8 offset = buf[2];
			rz_strbuf_appendf(asm_buf, " 0x%02x[0x%02x]", offset, reg);
		} else if (size == 4) {
			ut16 offset = rz_read_le16(buf + 2);
			rz_strbuf_appendf(asm_buf, " 0x%04x[0x%02x]", offset, reg);
		}
	} else if (instr_fmt & MCS96_FMT_EXTENDED_INDEXED && size == 6) {
		ut8 dst = buf[5];
		ut8 base = buf[1];
		st32 offset = (st32)rz_read_le24(buf + 2);
		rz_strbuf_appendf(asm_buf, " 0x%02x 0x%06x[0x%02x]", dst, (ut32)offset, base);
	} else if (instr_fmt & MCS96_FMT_2OP) {
		ut8 address_mode = opcode & 0x3;
		if (address_mode == MCS96_ADDRESSING_REG_DIRECT && size == 3) {
			ut8 dst = buf[2];
			ut8 src_reg = buf[1];
			rz_strbuf_appendf(asm_buf, " 0x%02x 0x%02x", dst, src_reg);
		} else if (address_mode == MCS96_ADDRESSING_IMMEDIATE) {
			if (size == 3) {
				ut8 dst = buf[2];
				ut8 src_imm8 = buf[1];
				rz_strbuf_appendf(asm_buf, " 0x%02x 0x%02x", dst, src_imm8);
			} else if (size == 4) {
				ut8 dst = buf[3];
				ut16 src_imm16 = rz_read_le16(buf + 1);
				rz_strbuf_appendf(asm_buf, " 0x%02x 0x%04x", dst, src_imm16);
			}
		} else if (address_mode == MCS96_ADDRESSING_INDIRECT && size == 3) {
			ut8 dst = buf[2];
			boolt autoincrement = buf[1] & 0x1;
			ut8 src_reg = buf[1] & 0xFE;
			rz_strbuf_appendf(asm_buf, " 0x%02x [0x%02x]", dst, src_reg);
			if (autoincrement) {
				rz_strbuf_appendf(asm_buf, "+");
			}
		} else if (address_mode == MCS96_ADDRESSING_INDEXED) {
			if (size == 4) {
				ut8 dst = buf[3];
				ut8 offset = buf[2];
				ut8 base = buf[1] & 0xFE; // erase lsb
				rz_strbuf_appendf(asm_buf, " 0x%02x 0x%02x[0x%02x]", dst, offset, base);
			} else if (size == 5) {
				ut8 dst = buf[4];
				ut16 offset = rz_read_le16(buf + 2);
				ut8 base = buf[1] & 0xFE; // erase lsb
				rz_strbuf_appendf(asm_buf, " 0x%02x 0x%04x[0x%02x]", dst, offset, base);
			}
		}
	} else if (instr_fmt & MCS96_FMT_3OP) {
		ut8 address_mode = opcode & 0x3;
		if (address_mode == MCS96_ADDRESSING_REG_DIRECT && size == 4) {
			ut8 dst = buf[3];
			ut8 src0_reg = buf[2];
			ut8 src1_reg = buf[1];
			rz_strbuf_appendf(asm_buf, " 0x%02x 0x%02x 0x%02x", dst, src0_reg, src1_reg);
		} else if (address_mode == MCS96_ADDRESSING_IMMEDIATE) {
			if (size == 4) {
				ut8 dst = buf[3];
				ut8 src0_reg = buf[2];
				ut8 src_imm8 = buf[1];
				rz_strbuf_appendf(asm_buf, " 0x%02x 0x%02x 0x%02x", dst, src0_reg, src_imm8);
			} else if (size == 5) {
				ut8 dst = buf[4];
				ut8 src0_reg = buf[3];
				ut16 src_imm16 = rz_read_le16(buf + 1);
				rz_strbuf_appendf(asm_buf, " 0x%02x 0x%02x 0x%04x", dst, src0_reg, src_imm16);
			}
		} else if (address_mode == MCS96_ADDRESSING_INDIRECT && size == 4) {
			ut8 dst = buf[3];
			ut8 src0_reg = buf[2];
			ut8 src1_reg = buf[1] & 0xFE;
			boolt autoincrement = buf[1] & 0x1;
			rz_strbuf_appendf(asm_buf, " 0x%02x 0x%02x [0x%02x]", dst, src0_reg, src1_reg);
			if (autoincrement) {
				rz_strbuf_appendf(asm_buf, "+");
			}
		} else if (address_mode == MCS96_ADDRESSING_INDEXED) {
			if (size == 5) {
				ut8 dst = buf[4];
				ut8 src1_reg = buf[3];
				ut8 offset = buf[2];
				ut8 base = buf[1] & 0xFE; // erase lsb
				rz_strbuf_appendf(asm_buf, " 0x%02x 0x%02x 0x%02x[0x%02x]", dst, src1_reg, offset, base);
			} else if (size == 6) {
				ut8 dst = buf[5];
				ut8 src1_reg = buf[4];
				ut16 offset = rz_read_le16(buf + 2);
				ut8 base = buf[1] & 0xFE; // erase lsb
				rz_strbuf_appendf(asm_buf, " 0x%02x 0x%02x 0x%04x[0x%02x]", dst, src1_reg, offset, base);
			}
		}
	}
}

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (len > 1 && !memcmp(buf, "\xff\xff", 2)) {
		return -1;
	}

	RzStrBuf *asm_buf = &op->buf_asm;

	ut32 isa_bit = MCS96_8096; // default
	if (a->cpu && *a->cpu) {
		if (strstr(a->cpu, "80296")) {
			isa_bit = MCS96_80296;
		} else if (strstr(a->cpu, "80196")) {
			isa_bit = MCS96_80196;
		}
	}

	op->size = mcs96_len(isa_bit, buf, len, asm_buf);
	decode_mnemonic(asm_buf, buf, op->size, isa_bit);
	decode_operands(asm_buf, buf, op->size, isa_bit);
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
	.endian = RZ_SYS_ENDIAN_NONE,
	.disassemble = &disassemble
};
