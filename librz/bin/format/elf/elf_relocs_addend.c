// SPDX-FileCopyrightText: 2025 well-mannered-goat <takshformal@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static ut32 arm_rotr32(ut32 val, ut32 n) {
	return (val >> n) | (val << (32 - n));
}

static bool get_reloc_addend_arm(RzBuffer *buf, RzBinElfReloc *reloc, ut64 patch_addr, bool big_endian) {
	ut8 b[4] = { 0 };
	ut32 opcode;
	ut32 unsigned_imm = 0;
	ut32 rot = 0;
	ut32 decoded = 0;
	st32 signed_imm = 0;
	ut16 w1 = 0;
	ut16 w2 = 0;
	ut32 i, imm3, imm4, imm6, imm8, imm10, imm11, imm12;
	ut32 s, j1, j2, i1, i2;

	switch (reloc->type) {
	case R_ARM_ALU_PC_G0:
	/* fall-thru */
	case R_ARM_ALU_PC_G0_NC:
		/* fall-thru */
	case R_ARM_ALU_PC_G1:
		/* fall-thru */
	case R_ARM_ALU_PC_G1_NC:
		/* fall-thru */
	case R_ARM_ALU_PC_G2:
		rz_buf_read_at(buf, patch_addr, b, 4);
		opcode = rz_read_ble32(b, big_endian);
		unsigned_imm = opcode & 0xFFF;
		rot = (unsigned_imm >> 8) & 0xF;
		unsigned_imm = unsigned_imm & 0xFF;
		decoded = arm_rotr32(unsigned_imm, rot * 2);
		bool is_sub = (((opcode >> 21) & 0xF) == 0x2);
		reloc->addend = is_sub ? -(st64)decoded : (st64)decoded;
		break;

	case R_ARM_LDR_PC_G0:
		/* fall-thru */
	case R_ARM_LDR_PC_G1:
		/* fall-thru */
	case R_ARM_LDR_PC_G2:
		rz_buf_read_at(buf, patch_addr, b, 4);
		opcode = rz_read_ble32(b, big_endian);
		unsigned_imm = opcode & 0xFFF;
		bool u_bit = (opcode >> 23) & 1;
		reloc->addend = u_bit ? (st64)unsigned_imm : -(st64)unsigned_imm;
		break;

	case R_ARM_LDRS_PC_G0:
		/* fall-thru */
	case R_ARM_LDRS_PC_G1:
		/* fall-thru */
	case R_ARM_LDRS_PC_G2:
		rz_buf_read_at(buf, patch_addr, b, 4);
		opcode = rz_read_ble32(b, big_endian);
		unsigned_imm = ((opcode & 0xF00) >> 4) | (opcode & 0xF);
		u_bit = (opcode >> 23) & 1;
		reloc->addend = u_bit ? (st64)unsigned_imm : -(st64)unsigned_imm;
		break;

	case R_ARM_LDC_PC_G0:
		/* fall-thru */
	case R_ARM_LDC_PC_G1:
		/* fall-thru */
	case R_ARM_LDC_PC_G2:
		rz_buf_read_at(buf, patch_addr, b, 4);
		opcode = rz_read_ble32(b, big_endian);
		unsigned_imm = (opcode & 0xFF) << 2;
		u_bit = (opcode >> 23) & 1;
		reloc->addend = u_bit ? (st64)unsigned_imm : -(st64)unsigned_imm;
		break;

	case R_ARM_PC24:
		/* fall-thru */
	case R_ARM_CALL:
		/* fall-thru */
	case R_ARM_JUMP24:
		rz_buf_read_at(buf, patch_addr, b, 4);
		opcode = rz_read_ble32(b, big_endian);
		unsigned_imm = opcode & 0X00FFFFFF;
		signed_imm = (st32)(unsigned_imm << 8) >> 8;
		reloc->addend = signed_imm << 2;
		break;

	case R_ARM_MOVW_ABS_NC:
		/* fall-thru */
	case R_ARM_MOVW_PREL_NC:
		/* fall-thru */
	case R_ARM_MOVW_BREL_NC:
		/* fall-thru */
	case R_ARM_MOVT_ABS:
		/* fall-thru */
	case R_ARM_MOVT_PREL:
		/* fall-thru */
	case R_ARM_MOVT_BREL:
		rz_buf_read_at(buf, patch_addr, b, 4);
		opcode = rz_read_ble32(b, big_endian);

		imm4 = (opcode >> 16) & 0xF;
		imm12 = opcode & 0xFFF;
		unsigned_imm = (imm4 << 12) | imm12;

		if (reloc->type == R_ARM_MOVW_ABS_NC ||
			reloc->type == R_ARM_MOVW_PREL_NC ||
			reloc->type == R_ARM_MOVW_BREL_NC) {
			reloc->addend = (st32)(st16)unsigned_imm;
		} else {
			reloc->addend = (st32)unsigned_imm;
		}
		break;

	case R_ARM_THM_MOVW_ABS_NC:
		/* fall-thru */
	case R_ARM_THM_MOVW_PREL_NC:
		/* fall-thru */
	case R_ARM_THM_MOVW_BREL_NC:
		rz_buf_read_at(buf, patch_addr, b, 4);
		w1 = rz_read_ble16(b, big_endian);
		w2 = rz_read_ble16(b + 2, big_endian);

		i = (w1 >> 10) & 0x1;
		imm3 = (w1 & 0xF);
		imm4 = (w2 >> 12) & 0xF;
		imm8 = (w2 & 0xFF);

		unsigned_imm = (i << 12) | (imm4 << 11) | (imm3 << 8) | imm8;

		reloc->addend = (st64)unsigned_imm;
		break;

	case R_ARM_THM_MOVT_ABS:
		/* fall-thru */
	case R_ARM_THM_MOVT_PREL:
		/* fall-thru */
	case R_ARM_THM_MOVT_BREL:
		rz_buf_read_at(buf, patch_addr, b, 4);
		w1 = rz_read_ble16(b, big_endian);
		w2 = rz_read_ble16(b + 2, big_endian);

		imm4 = (w1 & 0x000F);
		i = (w1 >> 10) & 0x1;
		imm3 = (w2 >> 12) & 0x7;
		imm8 = (w2 & 0x00FF);

		unsigned_imm = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8;

		reloc->addend = (st64)(st32)(unsigned_imm << 16);
		break;

	case R_ARM_THM_JUMP19:
		rz_buf_read_at(buf, patch_addr, b, 4);
		w1 = rz_read_ble16(b, big_endian);
		w2 = rz_read_ble16(b + 2, big_endian);

		s = (w1 >> 10) & 1;
		j2 = (w2 >> 11) & 1;
		j1 = (w2 >> 13) & 1;
		imm6 = (w1 & 0x3F);
		imm11 = (w2 & 0x7FF);

		unsigned_imm = (s << 19) | (j1 << 18) | (j2 << 17) | (imm6 << 11) | (imm11 << 0);
		unsigned_imm <<= 1;

		if (unsigned_imm & 0x100000) {
			reloc->addend = (st32)(unsigned_imm | 0xFFE00000);
		} else {
			reloc->addend = (st32)unsigned_imm;
		}
		break;

	case R_ARM_THM_ALU_PREL_11_0:
		rz_buf_read_at(buf, patch_addr, b, 4);
		w1 = rz_read_ble16(b, big_endian);
		w2 = rz_read_ble16(b + 2, big_endian);
		// Although the instruction manual gives different encoding for ADR instruction, it is essentially a pseudo instruction
		//  Check out: https://stackoverflow.com/questions/3583606/understanding-the-adr-instruction-in-arm-and-adding-an-offset-to-that
		unsigned_imm = (w2 & 0xFF);

		ut32 op2 = (w1 >> 5) & 0x1F;

		if (op2 == 0x15) { // Subtract
			reloc->addend = -(st32)unsigned_imm;
		} else { // Add
			reloc->addend = (st32)unsigned_imm;
		}
		break;

	case R_ARM_THM_JUMP24:
		/* fall-thru */
	case R_ARM_THM_CALL:
		rz_buf_read_at(buf, patch_addr, b, 4);
		w1 = rz_read_ble16(b, big_endian);
		w2 = rz_read_ble16(b + 2, big_endian);

		s = (w1 >> 10) & 1;
		imm10 = (w1 & 0x03FF);
		j1 = (w2 >> 13) & 1;
		j2 = (w2 >> 11) & 1;
		imm11 = (w2 & 0x07FF);

		i1 = (j1 == s);
		i2 = (j2 == s);

		unsigned_imm = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
		signed_imm = (st32)(unsigned_imm << 7) >> 7;
		reloc->addend = (st64)signed_imm;
		break;

	case R_ARM_THM_PC12:
		rz_buf_read_at(buf, patch_addr, b, 4);

		w1 = rz_read_ble16(b, big_endian);
		w2 = rz_read_ble16(b + 2, big_endian);

		imm12 = w2 & 0x0FFF;

		u_bit = (w1 >> 7) & 1;

		signed_imm = (st32)imm12;
		if (u_bit == 0) {
			signed_imm = -signed_imm;
		}

		reloc->addend = signed_imm;
		break;

	case R_ARM_THM_ALU_ABS_G0_NC:
		/* fall-thru */
	case R_ARM_THM_ALU_ABS_G1_NC:
		/* fall-thru */
	case R_ARM_THM_ALU_ABS_G2_NC:
		/* fall-thru */
	case R_ARM_THM_ALU_ABS_G3:
		rz_buf_read_at(buf, patch_addr, b, 2);
		opcode = rz_read_ble16(b, big_endian);

		reloc->addend = (ut64)(opcode & 0xFF);
		break;

	default:
		return false;
	}
	return true;
}

RZ_BORROW bool Elf_(rz_bin_elf_reloc_get_addend)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RzBinElfReloc *reloc) {
	ut64 e_machine = bin->ehdr.e_machine;
	ut64 patch_addr = reloc->paddr != UT64_MAX ? reloc->paddr : Elf_(rz_bin_elf_v2p)(bin, reloc->vaddr);
	bool big_endian = bin->big_endian;

	switch (e_machine) {
	case EM_ARM:
		return get_reloc_addend_arm(bin->buf_patched, reloc, patch_addr, big_endian);
	default:
		return false;
	}
}