// SPDX-FileCopyrightText: 2025 well-mannered-goat <takshformal@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"
#include <rz_util/ht_uu.h>

static ut32 arm_rotr32(ut32 val, ut32 n) {
	n &= 31; // n mod 32
	return n ? (val >> n) | (val << (32 - n)) : val;
}

/**
 * \brief Reads a 32-bit Thumb instruction, its first halfword in the high bits as AAELF32 numbers them.
 */
static ut32 arm_read_thumb32(const ut8 *b, bool big_endian) {
	return ((ut32)rz_read_ble16(b, big_endian) << 16) | rz_read_ble16(b + 2, big_endian);
}

static st64 arm_apply_sign(ut32 imm, bool positive) {
	return positive ? (st64)imm : -(st64)imm;
}

/**
 * \brief Reads the implicit addend of an Arm relocation, as AAELF32 forms it.
 *
 * MOVW and MOVT both hold a signed 16-bit addend, not the half they compute.
 */
static bool get_reloc_addend_arm(RzBuffer *buf, RzBinElfReloc *reloc, ut64 patch_addr, bool big_endian) {
	ut32 size = 4;
	switch (reloc->type) {
	case R_ARM_NONE:
	case R_ARM_V4BX:
	case R_ARM_COPY:
	case R_ARM_GLOB_DAT:
	case R_ARM_JUMP_SLOT:
	case R_ARM_TLS_DTPMOD32:
		reloc->addend = 0;
		return true;
	case R_ARM_ABS8:
		size = 1;
		break;
	case R_ARM_ABS16:
	case R_ARM_THM_ABS5:
	case R_ARM_THM_PC8:
	case R_ARM_THM_JUMP6:
	case R_ARM_THM_JUMP8:
	case R_ARM_THM_JUMP11:
	case R_ARM_THM_ALU_ABS_G0_NC:
	case R_ARM_THM_ALU_ABS_G1_NC:
	case R_ARM_THM_ALU_ABS_G2_NC:
	case R_ARM_THM_ALU_ABS_G3:
		size = 2;
		break;
	default:
		break;
	}
	ut8 b[4];
	if (rz_buf_read_at(buf, patch_addr, b, size) != size) {
		return false;
	}
	ut32 insn = rz_read_ble(b, big_endian, size * 8);
	ut32 thumb = size == 4 ? arm_read_thumb32(b, big_endian) : 0;
	ut32 s, i1, i2, imm;
	switch (reloc->type) {
	case R_ARM_ABS8:
	case R_ARM_ABS16:
	case R_ARM_ABS32:
	case R_ARM_REL32:
	case R_ARM_SBREL32:
	case R_ARM_TLS_DTPOFF32:
	case R_ARM_TLS_TPOFF32:
	case R_ARM_RELATIVE:
	case R_ARM_GOTOFF32:
	case R_ARM_BASE_PREL:
	case R_ARM_GOT_BREL:
	case R_ARM_BASE_ABS:
	case R_ARM_TARGET1:
	case R_ARM_TARGET2:
	case R_ARM_ABS32_NOI:
	case R_ARM_REL32_NOI:
	case R_ARM_TLS_GOTDESC:
	case R_ARM_PLT32_ABS:
	case R_ARM_GOT_ABS:
	case R_ARM_GOT_PREL:
	case R_ARM_TLS_GD32:
	case R_ARM_TLS_LDM32:
	case R_ARM_TLS_LDO32:
	case R_ARM_TLS_IE32:
	case R_ARM_TLS_LE32:
		reloc->addend = rz_bits_sign_ext64(insn, size * 8);
		break;
	case R_ARM_PREL31:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 31), 31);
		break;
	case R_ARM_PC24:
	case R_ARM_PLT32:
	case R_ARM_CALL:
	case R_ARM_JUMP24:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 24) << 2, 26);
		break;
	case R_ARM_MOVW_ABS_NC:
	case R_ARM_MOVT_ABS:
	case R_ARM_MOVW_PREL_NC:
	case R_ARM_MOVT_PREL:
	case R_ARM_MOVW_BREL_NC:
	case R_ARM_MOVT_BREL:
	case R_ARM_MOVW_BREL:
		// imm4:imm12
		imm = rz_bits_extract(insn, 16, 4) << 12 | rz_bits_extract(insn, 0, 12);
		reloc->addend = rz_bits_sign_ext64(imm, 16);
		break;
	case R_ARM_THM_MOVW_ABS_NC:
	case R_ARM_THM_MOVT_ABS:
	case R_ARM_THM_MOVW_PREL_NC:
	case R_ARM_THM_MOVT_PREL:
	case R_ARM_THM_MOVW_BREL_NC:
	case R_ARM_THM_MOVT_BREL:
	case R_ARM_THM_MOVW_BREL:
		// imm4:i:imm3:imm8
		imm = rz_bits_extract(thumb, 16, 4) << 12 | rz_bits_extract(thumb, 26, 1) << 11 |
			rz_bits_extract(thumb, 12, 3) << 8 | rz_bits_extract(thumb, 0, 8);
		reloc->addend = rz_bits_sign_ext64(imm, 16);
		break;
	case R_ARM_ALU_PC_G0_NC:
	case R_ARM_ALU_PC_G0:
	case R_ARM_ALU_PC_G1_NC:
	case R_ARM_ALU_PC_G1:
	case R_ARM_ALU_PC_G2:
	case R_ARM_ALU_SB_G0_NC:
	case R_ARM_ALU_SB_G0:
	case R_ARM_ALU_SB_G1_NC:
	case R_ARM_ALU_SB_G1:
	case R_ARM_ALU_SB_G2:
		// imm8 rotated right by twice rot, subtracted by a SUB
		imm = arm_rotr32(rz_bits_extract(insn, 0, 8), rz_bits_extract(insn, 8, 4) * 2);
		reloc->addend = arm_apply_sign(imm, rz_bits_extract(insn, 21, 4) != 0x2);
		break;
	case R_ARM_LDR_PC_G0:
	case R_ARM_LDR_PC_G1:
	case R_ARM_LDR_PC_G2:
	case R_ARM_LDR_SB_G0:
	case R_ARM_LDR_SB_G1:
	case R_ARM_LDR_SB_G2:
	case R_ARM_ABS12:
	case R_ARM_LDR_SBREL_11_0_NC:
	case R_ARM_GOT_BREL12:
	case R_ARM_GOTOFF12:
	case R_ARM_TLS_LDO12:
	case R_ARM_TLS_LE12:
	case R_ARM_TLS_IE12GP:
		reloc->addend = arm_apply_sign(rz_bits_extract(insn, 0, 12), rz_bits_extract(insn, 23, 1));
		break;
	case R_ARM_LDRS_PC_G0:
	case R_ARM_LDRS_PC_G1:
	case R_ARM_LDRS_PC_G2:
	case R_ARM_LDRS_SB_G0:
	case R_ARM_LDRS_SB_G1:
	case R_ARM_LDRS_SB_G2:
		// imm4H:imm4L
		imm = rz_bits_extract(insn, 8, 4) << 4 | rz_bits_extract(insn, 0, 4);
		reloc->addend = arm_apply_sign(imm, rz_bits_extract(insn, 23, 1));
		break;
	case R_ARM_LDC_PC_G0:
	case R_ARM_LDC_PC_G1:
	case R_ARM_LDC_PC_G2:
	case R_ARM_LDC_SB_G0:
	case R_ARM_LDC_SB_G1:
	case R_ARM_LDC_SB_G2:
		reloc->addend = arm_apply_sign(rz_bits_extract(insn, 0, 8) << 2, rz_bits_extract(insn, 23, 1));
		break;
	case R_ARM_THM_CALL:
	case R_ARM_THM_JUMP24:
		// S:I1:I2:imm10:imm11:'0', where In = NOT(Jn XOR S)
		s = rz_bits_extract(thumb, 26, 1);
		i1 = !(rz_bits_extract(thumb, 13, 1) ^ s);
		i2 = !(rz_bits_extract(thumb, 11, 1) ^ s);
		imm = s << 24 | i1 << 23 | i2 << 22 | rz_bits_extract(thumb, 16, 10) << 12 | rz_bits_extract(thumb, 0, 11) << 1;
		reloc->addend = rz_bits_sign_ext64(imm, 25);
		break;
	case R_ARM_THM_JUMP19:
		// S:J2:J1:imm6:imm11:'0'
		imm = rz_bits_extract(thumb, 26, 1) << 20 | rz_bits_extract(thumb, 11, 1) << 19 | rz_bits_extract(thumb, 13, 1) << 18 |
			rz_bits_extract(thumb, 16, 6) << 12 | rz_bits_extract(thumb, 0, 11) << 1;
		reloc->addend = rz_bits_sign_ext64(imm, 21);
		break;
	case R_ARM_THM_ALU_PREL_11_0:
		// i:imm3:imm8, of a SUBW from the PC when bit 23 is set and of an ADDW otherwise
		imm = rz_bits_extract(thumb, 26, 1) << 11 | rz_bits_extract(thumb, 12, 3) << 8 | rz_bits_extract(thumb, 0, 8);
		reloc->addend = arm_apply_sign(imm, !rz_bits_extract(thumb, 23, 1));
		break;
	case R_ARM_THM_PC12:
		reloc->addend = arm_apply_sign(rz_bits_extract(thumb, 0, 12), rz_bits_extract(thumb, 23, 1));
		break;
	case R_ARM_THM_GOT_BREL12:
		reloc->addend = rz_bits_extract(thumb, 0, 12);
		break;
	case R_ARM_THM_ALU_ABS_G0_NC:
	case R_ARM_THM_ALU_ABS_G1_NC:
	case R_ARM_THM_ALU_ABS_G2_NC:
	case R_ARM_THM_ALU_ABS_G3:
		reloc->addend = rz_bits_extract(insn, 0, 8);
		break;
	case R_ARM_THM_ABS5:
		reloc->addend = rz_bits_extract(insn, 6, 5) << 2;
		break;
	case R_ARM_THM_PC8:
		// The field is unsigned, so it holds the usual -4 modulo 1024.
		reloc->addend = (st64)(((rz_bits_extract(insn, 0, 8) << 2) + 4) & 0x3ff) - 4;
		break;
	case R_ARM_THM_JUMP6:
		// i:imm5:'0', unsigned like the field of R_ARM_THM_PC8
		imm = rz_bits_extract(insn, 9, 1) << 6 | rz_bits_extract(insn, 3, 5) << 1;
		reloc->addend = (st64)((imm + 4) & 0x7f) - 4;
		break;
	case R_ARM_THM_JUMP8:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 8) << 1, 9);
		break;
	case R_ARM_THM_JUMP11:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 11) << 1, 12);
		break;
	default:
		return false;
	}
	return true;
}

/**
 * \brief Reads the implicit addend of an i386 relocation from its field.
 *
 * R_386_JMP_SLOT holds the lazy binding address and R_386_TLS_DESC_CALL marks
 * an instruction, so neither has an addend.
 */
static bool get_reloc_addend_x86_32(RzBuffer *buf, RzBinElfReloc *reloc, ut64 patch_addr) {
	ut32 width;
	switch (reloc->type) {
	case R_386_NONE:
	case R_386_COPY:
	case R_386_GLOB_DAT:
	case R_386_JMP_SLOT:
	case R_386_TLS_DTPMOD32:
	case R_386_TLS_DESC_CALL:
		reloc->addend = 0;
		return true;
	case R_386_8:
	case R_386_PC8:
		width = 1;
		break;
	case R_386_16:
	case R_386_PC16:
		width = 2;
		break;
	case R_386_32:
	case R_386_PC32:
	case R_386_GOT32:
	case R_386_PLT32:
	case R_386_RELATIVE:
	case R_386_GOTOFF:
	case R_386_GOTPC:
	case R_386_TLS_TPOFF:
	case R_386_TLS_IE:
	case R_386_TLS_GOTIE:
	case R_386_TLS_LE:
	case R_386_TLS_GD:
	case R_386_TLS_LDM:
	case R_386_TLS_LDO_32:
	case R_386_TLS_IE_32:
	case R_386_TLS_LE_32:
	case R_386_TLS_DTPOFF32:
	case R_386_TLS_TPOFF32:
	case R_386_SIZE32:
	case R_386_TLS_GOTDESC:
	case R_386_IRELATIVE:
	case R_386_GOT32X:
		width = 4;
		break;
	default:
		return false;
	}
	ut8 b[4];
	if (rz_buf_read_at(buf, patch_addr, b, width) != width) {
		return false;
	}
	reloc->addend = rz_bits_sign_ext64(rz_read_ble(b, false, width * 8), width * 8);
	return true;
}

static bool mips_is_local(ELFOBJ *bin, ut64 sym) {
	RzBinElfSymbol *symbol = Elf_(rz_bin_elf_get_symbol)(bin, sym);
	return symbol && RZ_STR_EQ(symbol->bind, RZ_BIN_BIND_LOCAL_STR);
}

/**
 * \brief The type of low half that \p reloc pairs with as the high half of an AHL addend, or 0.
 *
 * A GOT16 against a local symbol loads the GOT page and leaves the offset
 * within it to a LO16.
 */
static ut32 mips_ahl_low_type(ELFOBJ *bin, const RzBinElfReloc *reloc) {
	switch (reloc->type) {
	case R_MIPS_HI16:
		return R_MIPS_LO16;
	case R_MIPS_PCHI16:
		return R_MIPS_PCLO16;
	case R_MICROMIPS_HI16:
		return R_MICROMIPS_LO16;
	case R_MIPS16_HI16:
		return R_MIPS16_LO16;
	case R_MIPS_GOT16:
		return mips_is_local(bin, reloc->sym) ? R_MIPS_LO16 : 0;
	case R_MICROMIPS_GOT16:
		return mips_is_local(bin, reloc->sym) ? R_MICROMIPS_LO16 : 0;
	case R_MIPS16_GOT16:
		return mips_is_local(bin, reloc->sym) ? R_MIPS16_LO16 : 0;
	default:
		return 0;
	}
}

static bool mips_is_ahl_low(ut32 type) {
	return type == R_MIPS_LO16 || type == R_MIPS_PCLO16 || type == R_MICROMIPS_LO16 || type == R_MIPS16_LO16;
}

/**
 * \brief Whether \p type relocates a microMIPS or MIPS16 instruction, whose halfwords are in order.
 */
static bool mips_is_compressed(ut32 type) {
	return (type >= R_MIPS16_26 && type <= R_MIPS16_PC16_S1) || (type >= R_MICROMIPS_26_S1 && type <= R_MICROMIPS_PC23_S2);
}

/**
 * \brief The 16-bit immediate of an extended MIPS16 instruction, whose EXTEND holds bits 10:5 above bits 15:11.
 */
static ut32 mips16_extended_imm(ut32 insn) {
	return rz_bits_extract(insn, 16, 5) << 11 | rz_bits_extract(insn, 21, 6) << 5 | rz_bits_extract(insn, 0, 5);
}

/**
 * \brief The 26-bit target of a MIPS16 JAL, which holds bits 20:16 above bits 25:21.
 */
static ut32 mips16_jal_target(ut32 insn) {
	return rz_bits_extract(insn, 16, 5) << 21 | rz_bits_extract(insn, 21, 5) << 16 | rz_bits_extract(insn, 0, 16);
}

/**
 * \brief Reads the implicit addend of a MIPS relocation.
 *
 * A jump against a local symbol is not sign-extended, as it is an offset
 * within the 256MB region of the jump. Each half of an AHL addend only gets
 * its own part here, see mips_pair_ahl().
 */
static bool get_reloc_addend_mips(ELFOBJ *bin, RzBuffer *buf, RzBinElfReloc *reloc, ut64 patch_addr) {
	bool big_endian = bin->big_endian;
	ut32 size = 4;
	switch (reloc->type) {
	case R_MIPS_NONE:
	case R_MIPS_JALR:
	case R_MICROMIPS_JALR:
	case R_MIPS_COPY:
	case R_MIPS_JUMP_SLOT:
	case R_MIPS_TLS_DTPMOD32:
	case R_MIPS_TLS_DTPMOD64:
		reloc->addend = 0;
		return true;
	case R_MIPS_16: // a halfword at the place, not the low half of a word
	case R_MICROMIPS_PC7_S1:
	case R_MICROMIPS_PC10_S1:
	case R_MICROMIPS_GPREL7_S2:
		size = 2;
		break;
	case R_MIPS_64:
	case R_MIPS_TLS_DTPREL64:
	case R_MIPS_TLS_TPREL64:
	case R_MIPS_REL32 | (R_MIPS_64 << 8): // the dynamic relocation of MIPS64
		size = 8;
		break;
	default:
		break;
	}
	ut8 b[8];
	if (rz_buf_read_at(buf, patch_addr, b, size) != size) {
		return false;
	}
	ut64 field = rz_read_ble(b, big_endian, size * 8);
	ut32 insn = (ut32)field;
	if (size == 4 && mips_is_compressed(reloc->type)) {
		insn = ((ut32)rz_read_ble16(b, big_endian) << 16) | rz_read_ble16(b + 2, big_endian);
	}
	if (mips_ahl_low_type(bin, reloc)) {
		ut32 high = reloc->type == R_MIPS16_HI16 || reloc->type == R_MIPS16_GOT16 ? mips16_extended_imm(insn) : rz_bits_extract(insn, 0, 16);
		reloc->addend = rz_bits_sign_ext64((ut64)high << 16, 32);
		return true;
	}
	ut64 addend;
	switch (reloc->type) {
	case R_MIPS_16:
		reloc->addend = rz_bits_sign_ext64(field, 16);
		break;
	case R_MIPS_32:
	case R_MIPS_REL32:
	case R_MIPS_GPREL32:
	case R_MIPS_PC32:
	case R_MIPS_TLS_DTPREL32:
	case R_MIPS_TLS_TPREL32:
		reloc->addend = rz_bits_sign_ext64(field, 32);
		break;
	case R_MIPS_64:
	case R_MIPS_TLS_DTPREL64:
	case R_MIPS_TLS_TPREL64:
	case R_MIPS_REL32 | (R_MIPS_64 << 8):
		reloc->addend = (st64)field;
		break;
	case R_MIPS_26:
		addend = rz_bits_extract(insn, 0, 26) << 2;
		reloc->addend = mips_is_local(bin, reloc->sym) ? (st64)addend : rz_bits_sign_ext64(addend, 28);
		break;
	case R_MICROMIPS_26_S1:
		addend = rz_bits_extract(insn, 0, 26) << 1;
		reloc->addend = mips_is_local(bin, reloc->sym) ? (st64)addend : rz_bits_sign_ext64(addend, 27);
		break;
	case R_MIPS16_26:
		addend = (ut64)mips16_jal_target(insn) << 2;
		reloc->addend = mips_is_local(bin, reloc->sym) ? (st64)addend : rz_bits_sign_ext64(addend, 28);
		break;
	case R_MIPS_PC16:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 16) << 2, 18);
		break;
	case R_MIPS_PC21_S2:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 21) << 2, 23);
		break;
	case R_MIPS_PC26_S2:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 26) << 2, 28);
		break;
	case R_MIPS_PC18_S3:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 18) << 3, 21);
		break;
	case R_MIPS_PC19_S2:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 19) << 2, 21);
		break;
	case R_MICROMIPS_PC7_S1:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 7) << 1, 8);
		break;
	case R_MICROMIPS_PC10_S1:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 10) << 1, 11);
		break;
	case R_MICROMIPS_PC16_S1:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 16) << 1, 17);
		break;
	case R_MICROMIPS_PC23_S2:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 23) << 2, 25);
		break;
	case R_MICROMIPS_GPREL7_S2:
		reloc->addend = rz_bits_extract(insn, 0, 7) << 2;
		break;
	case R_MIPS16_PC16_S1:
		reloc->addend = rz_bits_sign_ext64((ut64)mips16_extended_imm(insn) << 1, 17);
		break;
	case R_MIPS16_LO16:
	case R_MIPS16_GPREL:
	case R_MIPS16_GOT16:
	case R_MIPS16_CALL16:
	case R_MIPS16_TLS_GD:
	case R_MIPS16_TLS_LDM:
	case R_MIPS16_TLS_DTPREL_HI16:
	case R_MIPS16_TLS_DTPREL_LO16:
	case R_MIPS16_TLS_GOTTPREL:
	case R_MIPS16_TLS_TPREL_HI16:
	case R_MIPS16_TLS_TPREL_LO16:
		reloc->addend = rz_bits_sign_ext64(mips16_extended_imm(insn), 16);
		break;
	case R_MIPS_LO16:
	case R_MIPS_PCLO16:
	case R_MIPS_GPREL16:
	case R_MIPS_LITERAL:
	case R_MIPS_GOT16:
	case R_MIPS_CALL16:
	case R_MIPS_GOT_DISP:
	case R_MIPS_GOT_PAGE:
	case R_MIPS_GOT_OFST:
	case R_MIPS_GOT_HI16:
	case R_MIPS_GOT_LO16:
	case R_MIPS_CALL_HI16:
	case R_MIPS_CALL_LO16:
	case R_MIPS_TLS_GD:
	case R_MIPS_TLS_LDM:
	case R_MIPS_TLS_DTPREL_HI16:
	case R_MIPS_TLS_DTPREL_LO16:
	case R_MIPS_TLS_GOTTPREL:
	case R_MIPS_TLS_TPREL_HI16:
	case R_MIPS_TLS_TPREL_LO16:
	case R_MICROMIPS_LO16:
	case R_MICROMIPS_GPREL16:
	case R_MICROMIPS_LITERAL:
	case R_MICROMIPS_GOT16:
	case R_MICROMIPS_CALL16:
	case R_MICROMIPS_GOT_DISP:
	case R_MICROMIPS_GOT_PAGE:
	case R_MICROMIPS_GOT_OFST:
	case R_MICROMIPS_GOT_HI16:
	case R_MICROMIPS_GOT_LO16:
	case R_MICROMIPS_CALL_HI16:
	case R_MICROMIPS_CALL_LO16:
	case R_MICROMIPS_HI0_LO16:
	case R_MICROMIPS_TLS_GD:
	case R_MICROMIPS_TLS_LDM:
	case R_MICROMIPS_TLS_DTPREL_HI16:
	case R_MICROMIPS_TLS_DTPREL_LO16:
	case R_MICROMIPS_TLS_GOTTPREL:
	case R_MICROMIPS_TLS_TPREL_HI16:
	case R_MICROMIPS_TLS_TPREL_LO16:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(insn, 0, 16), 16);
		break;
	default:
		return false;
	}
	return true;
}

/**
 * \brief Keys a half of an AHL addend by its kind of low half, section and symbol.
 */
static ut64 mips_ahl_key(const RzBinElfReloc *reloc, ut32 low_type) {
	ut64 kind;
	switch (low_type) {
	case R_MIPS_LO16:
		kind = 0;
		break;
	case R_MIPS_PCLO16:
		kind = 1;
		break;
	case R_MICROMIPS_LO16:
		kind = 2;
		break;
	default:
		kind = 3;
		break;
	}
	return (kind << 48) | ((ut64)reloc->section << 32) | (ut32)reloc->sym;
}

/**
 * \brief Joins the part of an AHL addend held by a high half with the low 16 bits of \p low.
 */
static st64 mips_ahl(st64 high, st64 low) {
	// AHL is a 32-bit sum, so a carry out of the high half wraps.
	return rz_bits_sign_ext64((ut32)(high + rz_bits_sign_ext64(rz_bits_extract(low, 0, 16), 16)), 32);
}

/**
 * \brief Joins the halves of MIPS AHL addends, as R_MIPS_HI16 with R_MIPS_LO16.
 *
 * A high half takes the next low half of its kind against the same symbol in
 * the same section, and a low half the previous high half, as either may be
 * shared. A half without a pair keeps its own part.
 */
static void mips_pair_ahl(ELFOBJ *bin) {
	HtUU *high = ht_uu_new();
	HtUU *low = ht_uu_new();
	if (!high || !low) {
		goto beach;
	}
	RzBinElfReloc *reloc;
	rz_bin_elf_foreach_relocs(bin, reloc) {
		if (reloc->mode != DT_REL) {
			continue;
		}
		ut32 low_type = mips_ahl_low_type(bin, reloc);
		bool found = false;
		if (low_type) {
			ht_uu_update(high, mips_ahl_key(reloc, low_type), reloc->addend);
		} else if (mips_is_ahl_low(reloc->type)) {
			ut64 part = ht_uu_find(high, mips_ahl_key(reloc, reloc->type), &found);
			if (found) {
				reloc->addend = mips_ahl(part, reloc->addend);
			}
		}
	}
	// Backwards, as a high half takes the low half after it. The low 16 bits
	// of a low half addend are its own part, joined or not.
	for (size_t i = rz_vector_len(bin->relocs); i-- > 0;) {
		reloc = rz_vector_index_ptr(bin->relocs, i);
		if (reloc->mode != DT_REL) {
			continue;
		}
		ut32 low_type = mips_ahl_low_type(bin, reloc);
		bool found = false;
		if (mips_is_ahl_low(reloc->type)) {
			ht_uu_update(low, mips_ahl_key(reloc, reloc->type), reloc->addend);
		} else if (low_type) {
			ut64 part = ht_uu_find(low, mips_ahl_key(reloc, low_type), &found);
			if (found) {
				reloc->addend = mips_ahl(reloc->addend, part);
			}
		}
	}
beach:
	ht_uu_free(high);
	ht_uu_free(low);
}

static bool get_reloc_addend(ELFOBJ *bin, RzBinElfReloc *reloc) {
	ut64 patch_addr = reloc->paddr != UT64_MAX ? reloc->paddr : Elf_(rz_bin_elf_v2p)(bin, reloc->vaddr);
	bool big_endian = bin->big_endian;

	switch (bin->ehdr.e_machine) {
	case EM_ARM:
		return get_reloc_addend_arm(bin->b, reloc, patch_addr, big_endian);
	case EM_386:
		return get_reloc_addend_x86_32(bin->b, reloc, patch_addr);
	case EM_MIPS_X:
	case EM_MIPS_RS3_LE:
	case EM_MIPS:
		return get_reloc_addend_mips(bin, bin->b, reloc, patch_addr);
	default:
		return false;
	}
}

/**
 * \brief Sets the addends of the REL relocations of \p bin from the fields they relocate.
 *
 * The fields are read from the unrelocated image, so that the addends do not
 * depend on the relocations patched so far.
 */
void Elf_(rz_bin_elf_relocs_read_addends)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_if_fail(bin);
	RzBinElfReloc *reloc;
	rz_bin_elf_foreach_relocs(bin, reloc) {
		if (reloc->mode == DT_REL && !get_reloc_addend(bin, reloc)) {
			RZ_LOG_INFO("Immediate value extraction not implemented for %x\n", reloc->type);
		}
	}
	switch (bin->ehdr.e_machine) {
	case EM_MIPS_X:
	case EM_MIPS_RS3_LE:
	case EM_MIPS:
		mips_pair_ahl(bin);
		break;
	default:
		break;
	}
}
