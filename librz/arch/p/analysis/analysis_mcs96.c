// SPDX-FileCopyrightText: 2025 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util/rz_pj.h>
#include "mcs96/mcs96.h"

static int mcs96_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 6;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 2; // WORDs must be aligned at even byte boundaries in the address space.
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

static char *mcs96_get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC   pc\n"
		"=SP   sp\n"
		"=SR   psw\n"
		"=A0   garbage\n"
		"=A1   garbage\n"
		"=A2   garbage\n"
		"gpr   pc       .16  0   0\n" // Program counter
		"gpr   sp       .16  2   0\n" // Stack pointer
		"gpr   psw      .16  4   0\n" // Processor status word
		"gpr   garbage  .16  6   0\n"
		"gpr   garbage  .16  8   0\n"
		"gpr   garbage  .16  10  0\n";
	return rz_str_dup(p);
}

/**
 * Extract shift count from the second byte of shift instructions, and update
 * the analysis op accordingly.
 * The count may be specified either as an immediate value in the range of 0 to
 * 15 (0FH), inclusive, or as the content of any register (10H – 0FFH) with a
 * value in the range of 0 to 31 (1FH), inclusive.
 */
static inline void analyze_shift_count(RzAnalysisOp *op, ut8 byte) {
	if (byte <= 0x0F) { // immediate value
		op->val = byte;
	} else { // register value
		op->ptr = byte;
	}
}

static void opex_add_reg(RzStructuredData *operands, ut64 reg) {
	RzStructuredData *operand = rz_structured_data_array_add_map(operands);
	rz_structured_data_map_add_string(operand, "type", "reg");
	rz_structured_data_map_add_unsigned(operand, "value", reg, false);
}

static void opex_add_imm(RzStructuredData *operands, st64 imm) {
	RzStructuredData *operand = rz_structured_data_array_add_map(operands);
	rz_structured_data_map_add_string(operand, "type", "imm");
	rz_structured_data_map_add_signed(operand, "value", imm);
}

static void opex_add_mem(RzStructuredData *operands, ut64 base, st64 disp, bool autoincrement) {
	RzStructuredData *operand = rz_structured_data_array_add_map(operands);
	rz_structured_data_map_add_string(operand, "type", "mem");
	rz_structured_data_map_add_unsigned(operand, "value", base, false);
	if (disp) {
		rz_structured_data_map_add_signed(operand, "disp", disp);
	}
	if (autoincrement) {
		rz_structured_data_map_add_boolean(operand, "autoincrement", true);
	}
}

static RzStructuredData *mcs96_opex(const ut8 *buf, const int size, ut32 isa_bit) {
	if (size < 1) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	RzStructuredData *opex = rz_structured_data_map_add_map(root, "opex");
	if (!opex) {
		rz_structured_data_free(root);
		return NULL;
	}

	RzStructuredData *operands = rz_structured_data_map_add_array(opex, "operands");

	ut8 opcode = buf[0];
	ut32 instr_fmt = mcs96_op[opcode].type;
	Mcs96AddressingMode addr_mode = extract_addressing_mode(opcode);

	if (instr_fmt & MCS96_FMT_OPC_BYTEOPR && size == 2) {
		ut8 operand = buf[1];
		opex_add_reg(operands, operand);
	} else if (instr_fmt & MCS96_FMT_2_BYTE_NOP && size == 2) {
		// No operands
	} else if (instr_fmt & MCS96_FMT_OPC_IMM11 && size == 2) {
		st16 imm11 = extract_disp11(opcode, buf[1]);
		opex_add_imm(operands, imm11);
	} else if (instr_fmt & MCS96_FMT_OPC_BYTEOPR_X2 && size == 3) {
		ut8 opr0 = buf[2];
		ut8 opr1 = buf[1];
		opex_add_reg(operands, opr0);
		opex_add_reg(operands, opr1);
	} else if (instr_fmt & MCS96_FMT_OPC_IMM16 && size == 3) {
		st16 imm = (st16)rz_read_le16(buf + 1);
		opex_add_imm(operands, imm);
	} else if (instr_fmt & MCS96_FMT_TIJMP && size == 4) {
		ut8 index = buf[1];
		ut8 mask = buf[2];
		ut8 tbase = buf[3];
		opex_add_reg(operands, tbase);
		opex_add_reg(operands, index);
		opex_add_imm(operands, mask);
	} else if (instr_fmt & MCS96_FMT_OPC_IMM11_BYTEOPR && size == 3) {
		st16 imm11 = extract_disp11(opcode, buf[2]);
		ut8 reg = buf[1];
		opex_add_reg(operands, reg);
		opex_add_imm(operands, imm11);
	} else if (instr_fmt & MCS96_FMT_OPC_IMM24 && size == 4) {
		ut32 imm = (ut32)rz_read_le24(buf + 1);
		opex_add_imm(operands, imm);
	} else if (instr_fmt & MCS96_FMT_OPC_INDEX && size >= 1) {
		ut8 reg = buf[1] & 0xFE; // erase lsb
		if (size == 3) {
			ut8 offset = buf[2];
			opex_add_mem(operands, reg, offset, false);
		} else if (size == 4) {
			ut16 offset = rz_read_le16(buf + 2);
			opex_add_mem(operands, reg, offset, false);
		}
	} else if (instr_fmt & MCS96_FMT_EXTENDED_INDEXED && size == 6) {
		ut8 dst = buf[5];
		ut8 base = buf[1];
		st32 offset = (st32)rz_read_le24(buf + 2);
		opex_add_reg(operands, dst);
		opex_add_mem(operands, base, offset, false);
	} else if (instr_fmt & MCS96_FMT_2OP) {
		if (addr_mode == MCS96_ADDRESSING_REG_DIRECT && size == 3) {
			ut8 dst = buf[2];
			ut8 src_reg = buf[1];
			opex_add_reg(operands, dst);
			opex_add_reg(operands, src_reg);
		} else if (addr_mode == MCS96_ADDRESSING_IMMEDIATE) {
			if (size == 3) {
				ut8 dst = buf[2];
				ut8 src_imm8 = buf[1];
				opex_add_reg(operands, dst);
				opex_add_imm(operands, src_imm8);
			} else if (size == 4) {
				ut8 dst = buf[3];
				ut16 src_imm16 = rz_read_le16(buf + 1);
				opex_add_reg(operands, dst);
				opex_add_imm(operands, src_imm16);
			}
		} else if (addr_mode == MCS96_ADDRESSING_INDIRECT && size == 3) {
			ut8 dst = buf[2];
			bool autoincrement = buf[1] & 0x1;
			ut8 src_reg = buf[1] & 0xFE;
			opex_add_reg(operands, dst);
			opex_add_mem(operands, src_reg, 0, autoincrement);
		} else if (addr_mode == MCS96_ADDRESSING_INDEXED) {
			if (size == 4) {
				ut8 dst = buf[3];
				ut8 offset = buf[2];
				ut8 base = buf[1] & 0xFE; // erase lsb
				opex_add_reg(operands, dst);
				opex_add_mem(operands, base, offset, false);
			} else if (size == 5) {
				ut8 dst = buf[4];
				ut16 offset = rz_read_le16(buf + 2);
				ut8 base = buf[1] & 0xFE; // erase lsb
				opex_add_reg(operands, dst);
				opex_add_mem(operands, base, offset, false);
			}
		}
	} else if (instr_fmt & MCS96_FMT_3OP) {
		if (addr_mode == MCS96_ADDRESSING_REG_DIRECT && size == 4) {
			ut8 dst = buf[3];
			ut8 src0_reg = buf[2];
			ut8 src1_reg = buf[1];
			opex_add_reg(operands, dst);
			opex_add_reg(operands, src0_reg);
			opex_add_reg(operands, src1_reg);
		} else if (addr_mode == MCS96_ADDRESSING_IMMEDIATE) {
			if (size == 4) {
				ut8 dst = buf[3];
				ut8 src0_reg = buf[2];
				ut8 src_imm8 = buf[1];
				opex_add_reg(operands, dst);
				opex_add_reg(operands, src0_reg);
				opex_add_imm(operands, src_imm8);
			} else if (size == 5) {
				ut8 dst = buf[4];
				ut8 src0_reg = buf[3];
				ut16 src_imm16 = rz_read_le16(buf + 1);
				opex_add_reg(operands, dst);
				opex_add_reg(operands, src0_reg);
				opex_add_imm(operands, src_imm16);
			}
		} else if (addr_mode == MCS96_ADDRESSING_INDIRECT && size == 4) {
			ut8 dst = buf[3];
			ut8 src0_reg = buf[2];
			ut8 src1_reg = buf[1] & 0xFE;
			bool autoincrement = buf[1] & 0x1;
			opex_add_reg(operands, dst);
			opex_add_reg(operands, src0_reg);
			opex_add_mem(operands, src1_reg, 0, autoincrement);
		} else if (addr_mode == MCS96_ADDRESSING_INDEXED) {
			if (size == 5) {
				ut8 dst = buf[4];
				ut8 src1_reg = buf[3];
				ut8 offset = buf[2];
				ut8 base = buf[1] & 0xFE; // erase lsb
				opex_add_reg(operands, dst);
				opex_add_reg(operands, src1_reg);
				opex_add_mem(operands, base, offset, false);
			} else if (size == 6) {
				ut8 dst = buf[5];
				ut8 src1_reg = buf[4];
				ut16 offset = rz_read_le16(buf + 2);
				ut8 base = buf[1] & 0xFE; // erase lsb
				opex_add_reg(operands, dst);
				opex_add_reg(operands, src1_reg);
				opex_add_mem(operands, base, offset, false);
			}
		}
	}

	return root;
}

static int mcs96_analyze_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	// Determine CPU variant from analysis->cpu
	ut32 isa_bit = MCS96_8096; // default
	if (analysis->cpu && *analysis->cpu) {
		if (strstr(analysis->cpu, "80296")) {
			isa_bit = MCS96_80296;
		} else if (strstr(analysis->cpu, "80196")) {
			isa_bit = MCS96_80196;
		}
	}

	int size = mcs96_len(isa_bit, buf, len);

	// for valid instructions, a positive integer returned from mcs96_len guarantees:
	// 1. size > 0
	// 2. size >= len
	// there should be no need to check for size > len after this point.
	if (size <= 0) {
		return -1;
	}

	ut8 opcode = buf[0];
	op->size = size;
	op->addr = addr;
	op->nopcode = 1;
	op->id = opcode;
	op->family = RZ_ANALYSIS_OP_FAMILY_CPU;

	Mcs96AddressingMode addr_mode = extract_addressing_mode(opcode);

	switch (opcode) {
	case MCS96_SKIP_00:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case MCS96_CLR_01:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case MCS96_NOT_02:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case MCS96_NEG_03:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MCS96_XCH_04:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		}
		break;
	case MCS96_DEC_05:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MCS96_EXT_06:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case MCS96_INC_07:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case MCS96_SHR_08:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		op->sign = false;
		analyze_shift_count(op, buf[1]);
		break;
	case MCS96_SHL_09:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		op->sign = false;
		analyze_shift_count(op, buf[1]);
		break;
	case MCS96_SHRA_0A:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		op->sign = true;
		analyze_shift_count(op, buf[1]);
		break;
	case MCS96_XCH_0B:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	case MCS96_SHRL_0C:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		op->sign = false;
		analyze_shift_count(op, buf[1]);
		break;
	case MCS96_SHLL_0D: {
		bool is_shll = false;
		if (isa_bit == MCS96_80296) { // shll, mvac, reserved, masc
			ut8 lreg_bits = buf[2] & 0x3;
			if (lreg_bits == 0x0) {
				is_shll = true;
			} else if (lreg_bits == 0x1 || lreg_bits == 0x3) {
				op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			} else if (lreg_bits == 0x2) {
				op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			}
		} else {
			is_shll = true;
		}
		if (is_shll) {
			op->type = RZ_ANALYSIS_OP_TYPE_SHL;
			op->sign = false;
			analyze_shift_count(op, buf[1]);
		}
		break;
	}
	case MCS96_SHRAL_0E:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		op->sign = true;
		analyze_shift_count(op, buf[1]);
		break;
	case MCS96_NORML_0F:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case MCS96_INVALID_10:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	case MCS96_CLRB_11:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case MCS96_NOTB_12:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case MCS96_NEGB_13:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MCS96_XCHB_14:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		}
		break;
	case MCS96_DECB_15:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MCS96_EXTB_16:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case MCS96_INCB_17:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case MCS96_SHRB_18:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		op->sign = false;
		analyze_shift_count(op, buf[1]);
		break;
	case MCS96_SHLB_19:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		op->sign = false;
		analyze_shift_count(op, buf[1]);
		break;
	case MCS96_SHRAB_1A:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		op->sign = true;
		analyze_shift_count(op, buf[1]);
		break;
	case MCS96_XCHB_1B:
		op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		break;
	case MCS96_EST_1C:
	case MCS96_EST_1D:
	case MCS96_ESTB_1E:
	case MCS96_ESTB_1F:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		}
		break;
	case MCS96_SJMP_20:
	case MCS96_SJMP_21:
	case MCS96_SJMP_22:
	case MCS96_SJMP_23:
	case MCS96_SJMP_24:
	case MCS96_SJMP_25:
	case MCS96_SJMP_26:
	case MCS96_SJMP_27:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->id = opcode & 0xF8; // chop off lower 3 bits
		st16 imm = extract_disp11(opcode, buf[1]);
		op->val = imm;
		op->jump = addr + op->size + imm;
		op->eob = true;
		break;
	case MCS96_SCALL_28:
	case MCS96_SCALL_29:
	case MCS96_SCALL_2A:
	case MCS96_SCALL_2B:
	case MCS96_SCALL_2C:
	case MCS96_SCALL_2D:
	case MCS96_SCALL_2E:
	case MCS96_SCALL_2F:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->id = opcode & 0xF8; // chop off lower 3 bits
		imm = extract_disp11(opcode, buf[1]);
		op->val = imm;
		op->jump = addr + op->size + imm;
		op->eob = true;
		op->stackptr = -2;
		break;
	case MCS96_JBC_30:
	case MCS96_JBC_31:
	case MCS96_JBC_32:
	case MCS96_JBC_33:
	case MCS96_JBC_34:
	case MCS96_JBC_35:
	case MCS96_JBC_36:
	case MCS96_JBC_37:
	case MCS96_JBS_38:
	case MCS96_JBS_39:
	case MCS96_JBS_3A:
	case MCS96_JBS_3B:
	case MCS96_JBS_3C:
	case MCS96_JBS_3D:
	case MCS96_JBS_3E:
	case MCS96_JBS_3F:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		imm = (st8)buf[2]; // 8-bit displacement
		op->val = imm;
		op->jump = addr + op->size + imm;
		op->fail = addr + op->size;
		op->eob = true;
		break;
	case MCS96_AND_40:
		if (size == 4 && buf[size - 1] == 0x04) { // RPT/RPTxxx/RPTI/RPTIxxx
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
		}
		break;
	case MCS96_AND_41:
	case MCS96_AND_42:
	case MCS96_AND_43:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case MCS96_ADD_44:
	case MCS96_ADD_45:
	case MCS96_ADD_46:
	case MCS96_ADD_47:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case MCS96_SUB_48:
	case MCS96_SUB_49:
	case MCS96_SUB_4A:
	case MCS96_SUB_4B:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MCS96_MULU_4C:
	case MCS96_MULU_4D:
	case MCS96_MULU_4E:
	case MCS96_MULU_4F:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case MCS96_ANDB_50:
	case MCS96_ANDB_51:
	case MCS96_ANDB_52:
	case MCS96_ANDB_53:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case MCS96_ADDB_54:
	case MCS96_ADDB_55:
	case MCS96_ADDB_56:
	case MCS96_ADDB_57:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case MCS96_SUBB_58:
	case MCS96_SUBB_59:
	case MCS96_SUBB_5A:
	case MCS96_SUBB_5B:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MCS96_MULUB_5C:
	case MCS96_MULUB_5D:
	case MCS96_MULUB_5E:
	case MCS96_MULUB_5F:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case MCS96_AND_60:
	case MCS96_AND_61:
	case MCS96_AND_62:
	case MCS96_AND_63:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case MCS96_ADD_64:
	case MCS96_ADD_65:
	case MCS96_ADD_66:
	case MCS96_ADD_67:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case MCS96_SUB_68:
	case MCS96_SUB_69:
	case MCS96_SUB_6A:
	case MCS96_SUB_6B:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MCS96_MULU_6C:
	case MCS96_MULU_6D:
	case MCS96_MULU_6E:
	case MCS96_MULU_6F:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case MCS96_ANDB_70:
	case MCS96_ANDB_71:
	case MCS96_ANDB_72:
	case MCS96_ANDB_73:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case MCS96_ADDB_74:
	case MCS96_ADDB_75:
	case MCS96_ADDB_76:
	case MCS96_ADDB_77:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case MCS96_SUBB_78:
	case MCS96_SUBB_79:
	case MCS96_SUBB_7A:
	case MCS96_SUBB_7B:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MCS96_MULUB_7C:
	case MCS96_MULUB_7D:
	case MCS96_MULUB_7E:
	case MCS96_MULUB_7F:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case MCS96_OR_80:
	case MCS96_OR_81:
	case MCS96_OR_82:
	case MCS96_OR_83:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case MCS96_XOR_84:
	case MCS96_XOR_85:
	case MCS96_XOR_86:
	case MCS96_XOR_87:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case MCS96_CMP_88:
	case MCS96_CMP_89:
	case MCS96_CMP_8A:
	case MCS96_CMP_8B:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case MCS96_DIVU_8C:
	case MCS96_DIVU_8D:
	case MCS96_DIVU_8E:
	case MCS96_DIVU_8F:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case MCS96_ORB_90:
	case MCS96_ORB_91:
	case MCS96_ORB_92:
	case MCS96_ORB_93:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case MCS96_XORB_94:
	case MCS96_XORB_95:
	case MCS96_XORB_96:
	case MCS96_XORB_97:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case MCS96_CMPB_98:
	case MCS96_CMPB_99:
	case MCS96_CMPB_9A:
	case MCS96_CMPB_9B:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case MCS96_DIVUB_9C:
	case MCS96_DIVUB_9D:
	case MCS96_DIVUB_9E:
	case MCS96_DIVUB_9F:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case MCS96_LD_A0:
	case MCS96_LD_A1:
	case MCS96_LD_A2:
	case MCS96_LD_A3:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case MCS96_ADDC_A4:
	case MCS96_ADDC_A5:
	case MCS96_ADDC_A6:
	case MCS96_ADDC_A7:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case MCS96_SUBC_A8:
	case MCS96_SUBC_A9:
	case MCS96_SUBC_AA:
	case MCS96_SUBC_AB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MCS96_LDBZE_AC:
	case MCS96_LDBZE_AD:
	case MCS96_LDBZE_AE:
	case MCS96_LDBZE_AF:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case MCS96_LDB_B0:
	case MCS96_LDB_B1:
	case MCS96_LDB_B2:
	case MCS96_LDB_B3:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case MCS96_ADDCB_B4:
	case MCS96_ADDCB_B5:
	case MCS96_ADDCB_B6:
	case MCS96_ADDCB_B7:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case MCS96_SUBCB_B8:
	case MCS96_SUBCB_B9:
	case MCS96_SUBCB_BA:
	case MCS96_SUBCB_BB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MCS96_LDBSE_BC:
	case MCS96_LDBSE_BD:
	case MCS96_LDBSE_BE:
	case MCS96_LDBSE_BF:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case MCS96_ST_C0:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->ptr = buf[1];
		break;
	case MCS96_BMOV_C1:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		}
		break;
	case MCS96_ST_C2:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case MCS96_ST_C3:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case MCS96_STB_C4:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case MCS96_CMPL_C5:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		}
		break;
	case MCS96_STB_C6:
	case MCS96_STB_C7:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case MCS96_PUSH_C8:
	case MCS96_PUSH_C9:
	case MCS96_PUSH_CA:
	case MCS96_PUSH_CB:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		op->stackptr = -2;
		break;
	case MCS96_POP_CC:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		op->stackptr = 2;
		break;
	case MCS96_BMOVI_CD:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		}
		break;
	case MCS96_POP_CE:
	case MCS96_POP_CF:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		op->stackptr = 2;
		break;
	case MCS96_JNST_D0:
	case MCS96_JNH_D1:
	case MCS96_JGT_D2:
	case MCS96_JNC_D3:
	case MCS96_JNVT_D4:
	case MCS96_JNV_D5:
	case MCS96_JGE_D6:
	case MCS96_JNE_D7:
	case MCS96_JST_D8:
	case MCS96_JH_D9:
	case MCS96_JLE_DA:
	case MCS96_JC_DB:
	case MCS96_JVT_DC:
	case MCS96_JV_DD:
	case MCS96_JLT_DE:
	case MCS96_JE_DF:
		imm = (st8)buf[1];
		op->jump = addr + op->size + imm;
		op->fail = addr + op->size;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->eob = true;
		break;
	case MCS96_DJNZ_E0:
		imm = (st8)buf[2];
		op->jump = addr + op->size + imm;
		op->fail = addr + op->size;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->eob = true;
		break;
	case MCS96_DJNZW_E1:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			break;
		} else {
			imm = (st8)buf[2];
			op->jump = addr + op->size + imm;
			op->fail = addr + op->size;
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->eob = true;
		}
		break;
	case MCS96_TIJMP_E2:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			break;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->eob = true;
		}
		break;
	case MCS96_BR_E3:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->eob = true;
		break;
	case MCS96_EBMOVI_E4:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		}
		break;
	case MCS96_RETI_E5:
		if (isa_bit == MCS96_8096 || isa_bit == MCS96_80196) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			break;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			op->eob = true;
			op->stackptr = 2;
		}
		break;
	case MCS96_EJMP_E6:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			break;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->eob = true;
		}
		break;
	case MCS96_LJMP_E7:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		imm = (st16)rz_read_le16(buf + 1);
		op->val = imm;
		op->jump = addr + op->size + imm;
		op->eob = true;
		break;
	case MCS96_ELD_E8:
	case MCS96_ELD_E9:
	case MCS96_ELDB_EA:
	case MCS96_ELDB_EB:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		}
		break;
	case MCS96_DPTS_EC:
	case MCS96_EPTS_ED:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		}
		break;
	case MCS96_INVALID_EE:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	case MCS96_LCALL_EF:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		imm = (st16)rz_read_le16(buf + 1);
		op->val = imm;
		op->jump = addr + op->size + imm;
		op->stackptr = -2;
		op->eob = true;
		break;
	case MCS96_RET_F0:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		op->stackptr = 2;
		break;
	case MCS96_ECALL_F1:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->eob = true;
			op->stackptr = -2;
		}
		break;
	case MCS96_PUSHF_F2:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		op->stackptr = -2;
		break;
	case MCS96_POPF_F3:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		op->stackptr = 2;
		break;
	case MCS96_PUSHA_F4:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			op->stackptr = -4;
		}
		break;
	case MCS96_POPA_F5:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_POP;
			op->stackptr = 4;
		}
		break;
	case MCS96_IDLPD_F6:
		if (isa_bit == MCS96_8096) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		}
		break;
	case MCS96_TRAP_F7:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case MCS96_CLRC_F8:
	case MCS96_SETC_F9:
	case MCS96_DI_FA:
	case MCS96_EI_FB:
	case MCS96_CLRVT_FC:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case MCS96_NOP_FD:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case MCS96_MUL_DIV_FE: {
		const ut32 fe_idx = compute_fe_index(buf[1]);
		switch (fe_idx) {
		case 0:
		case 1:
		case 2:
		case 3:
			op->type = RZ_ANALYSIS_OP_TYPE_MUL;
			break;
		case 4:
		case 5:
			op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		default:
			break;
		}
		break;
	}
	case MCS96_RST_FF:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	default:
		return -1;
	}

	switch (opcode) {
	case MCS96_AND_40:
	case MCS96_AND_41:
	case MCS96_AND_42:
	case MCS96_AND_43:
	case MCS96_ADD_44:
	case MCS96_ADD_45:
	case MCS96_ADD_46:
	case MCS96_ADD_47:
	case MCS96_SUB_48:
	case MCS96_SUB_49:
	case MCS96_SUB_4A:
	case MCS96_SUB_4B:
	case MCS96_MULU_4C:
	case MCS96_MULU_4D:
	case MCS96_MULU_4E:
	case MCS96_MULU_4F:
	case MCS96_AND_60:
	case MCS96_AND_61:
	case MCS96_AND_62:
	case MCS96_AND_63:
	case MCS96_ADD_64:
	case MCS96_ADD_65:
	case MCS96_ADD_66:
	case MCS96_ADD_67:
	case MCS96_SUB_68:
	case MCS96_SUB_69:
	case MCS96_SUB_6A:
	case MCS96_SUB_6B:
	case MCS96_MULU_6C:
	case MCS96_MULU_6D:
	case MCS96_MULU_6E:
	case MCS96_MULU_6F:
	case MCS96_OR_80:
	case MCS96_OR_81:
	case MCS96_OR_82:
	case MCS96_OR_83:
	case MCS96_XOR_84:
	case MCS96_XOR_85:
	case MCS96_XOR_86:
	case MCS96_XOR_87:
	case MCS96_CMP_88:
	case MCS96_CMP_89:
	case MCS96_CMP_8A:
	case MCS96_CMP_8B:
	case MCS96_DIVU_8C:
	case MCS96_DIVU_8D:
	case MCS96_DIVU_8E:
	case MCS96_DIVU_8F:
	case MCS96_LD_A0:
	case MCS96_LD_A1:
	case MCS96_LD_A2:
	case MCS96_LD_A3:
	case MCS96_ADDC_A4:
	case MCS96_ADDC_A5:
	case MCS96_ADDC_A6:
	case MCS96_ADDC_A7:
	case MCS96_SUBC_A8:
	case MCS96_SUBC_A9:
	case MCS96_SUBC_AA:
	case MCS96_SUBC_AB:
	case MCS96_PUSH_C8:
	case MCS96_PUSH_C9:
	case MCS96_PUSH_CA:
	case MCS96_PUSH_CB:
		switch (addr_mode) {
		case MCS96_ADDRESSING_REG_DIRECT:
			op->ptr = rz_read_le16(buf + 1);
			op->refptr = 2;
			break;
		case MCS96_ADDRESSING_IMMEDIATE:
			op->val = rz_read_le16(buf + 1);
			break;
		default:
			break;
		}
		break;
	case MCS96_ANDB_50:
	case MCS96_ANDB_51:
	case MCS96_ANDB_52:
	case MCS96_ANDB_53:
	case MCS96_ADDB_54:
	case MCS96_ADDB_55:
	case MCS96_ADDB_56:
	case MCS96_ADDB_57:
	case MCS96_SUBB_58:
	case MCS96_SUBB_59:
	case MCS96_SUBB_5A:
	case MCS96_SUBB_5B:
	case MCS96_MULUB_5C:
	case MCS96_MULUB_5D:
	case MCS96_MULUB_5E:
	case MCS96_MULUB_5F:
	case MCS96_ANDB_70:
	case MCS96_ANDB_71:
	case MCS96_ANDB_72:
	case MCS96_ANDB_73:
	case MCS96_ADDB_74:
	case MCS96_ADDB_75:
	case MCS96_ADDB_76:
	case MCS96_ADDB_77:
	case MCS96_SUBB_78:
	case MCS96_SUBB_79:
	case MCS96_SUBB_7A:
	case MCS96_SUBB_7B:
	case MCS96_MULUB_7C:
	case MCS96_MULUB_7D:
	case MCS96_MULUB_7E:
	case MCS96_MULUB_7F:
	case MCS96_ORB_90:
	case MCS96_ORB_91:
	case MCS96_ORB_92:
	case MCS96_ORB_93:
	case MCS96_XORB_94:
	case MCS96_XORB_95:
	case MCS96_XORB_96:
	case MCS96_XORB_97:
	case MCS96_CMPB_98:
	case MCS96_CMPB_99:
	case MCS96_CMPB_9A:
	case MCS96_CMPB_9B:
	case MCS96_DIVUB_9C:
	case MCS96_DIVUB_9D:
	case MCS96_DIVUB_9E:
	case MCS96_DIVUB_9F:
	case MCS96_LDBZE_AC:
	case MCS96_LDBZE_AD:
	case MCS96_LDBZE_AE:
	case MCS96_LDBZE_AF:
	case MCS96_LDB_B0:
	case MCS96_LDB_B1:
	case MCS96_LDB_B2:
	case MCS96_LDB_B3:
	case MCS96_ADDCB_B4:
	case MCS96_ADDCB_B5:
	case MCS96_ADDCB_B6:
	case MCS96_ADDCB_B7:
	case MCS96_SUBCB_B8:
	case MCS96_SUBCB_B9:
	case MCS96_SUBCB_BA:
	case MCS96_SUBCB_BB:
	case MCS96_LDBSE_BC:
	case MCS96_LDBSE_BD:
	case MCS96_LDBSE_BE:
	case MCS96_LDBSE_BF:
		switch (addr_mode) {
		case MCS96_ADDRESSING_REG_DIRECT:
			op->ptr = buf[1];
			op->refptr = 1;
			break;
		case MCS96_ADDRESSING_IMMEDIATE:
			op->val = buf[1];
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		const char *mnemonic = decode_mnemonic(buf, op->size, isa_bit);
		op->mnemonic = rz_str_dup(mnemonic);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = mcs96_opex(buf, size, isa_bit);
	}

	return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_mcs96 = {
	.name = "mcs96",
	.desc = "Intel MCS-96 analyzer",
	.license = "LGPL3",
	.arch = "mcs96",
	.author = "bubblepipe",
	.bits = 16,
	.archinfo = mcs96_archinfo,
	.get_reg_profile = mcs96_get_reg_profile,
	.op = mcs96_analyze_op,
};