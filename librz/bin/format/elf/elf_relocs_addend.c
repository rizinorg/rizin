// SPDX-FileCopyrightText: 2025 well-mannered-goat <takshformal@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"
#include <rz_util/ht_uu.h>

static ut32 arm_rotr32(ut32 val, ut32 n) {
	n &= 31; // n mod 32
	return n ? (val >> n) | (val << (32 - n)) : val;
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
		reloc->addend = (st32)((ut32)signed_imm << 2);
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
 * \brief Whether \p reloc holds the high half of a MIPS AHL addend.
 *
 * A GOT16 against a local symbol loads the GOT page and leaves the offset
 * within it to a LO16.
 */
static bool mips_is_hi16(ELFOBJ *bin, const RzBinElfReloc *reloc) {
	return reloc->type == R_MIPS_HI16 || (reloc->type == R_MIPS_GOT16 && mips_is_local(bin, reloc->sym));
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
	ut8 b[4];
	switch (reloc->type) {
	case R_MIPS_NONE:
	case R_MIPS_JALR:
	case R_MIPS_COPY:
	case R_MIPS_JUMP_SLOT:
	case R_MIPS_TLS_DTPMOD32:
		reloc->addend = 0;
		return true;
	case R_MIPS_16:
		// The psABI field is a halfword at the place, not the low half of a word.
		if (rz_buf_read_at(buf, patch_addr, b, 2) != 2) {
			return false;
		}
		reloc->addend = rz_bits_sign_ext64(rz_read_ble16(b, big_endian), 16);
		return true;
	default:
		break;
	}
	if (rz_buf_read_at(buf, patch_addr, b, 4) != 4) {
		return false;
	}
	ut32 word = rz_read_ble32(b, big_endian);
	if (mips_is_hi16(bin, reloc)) {
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(word, 0, 16) << 16, 32);
		return true;
	}
	switch (reloc->type) {
	case R_MIPS_32:
	case R_MIPS_REL32:
	case R_MIPS_GPREL32:
	case R_MIPS_PC32:
	case R_MIPS_TLS_DTPREL32:
	case R_MIPS_TLS_TPREL32:
		reloc->addend = rz_bits_sign_ext64(word, 32);
		break;
	case R_MIPS_26: {
		ut64 addend = rz_bits_extract(word, 0, 26) << 2;
		reloc->addend = mips_is_local(bin, reloc->sym) ? (st64)addend : rz_bits_sign_ext64(addend, 28);
		break;
	}
	case R_MIPS_PC16:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(word, 0, 16) << 2, 18);
		break;
	case R_MIPS_LO16:
	case R_MIPS_GPREL16:
	case R_MIPS_LITERAL:
	case R_MIPS_GOT16:
	case R_MIPS_CALL16:
	case R_MIPS_GOT_DISP:
	case R_MIPS_TLS_GD:
	case R_MIPS_TLS_LDM:
	case R_MIPS_TLS_DTPREL_HI16:
	case R_MIPS_TLS_DTPREL_LO16:
	case R_MIPS_TLS_GOTTPREL:
	case R_MIPS_TLS_TPREL_HI16:
	case R_MIPS_TLS_TPREL_LO16:
		reloc->addend = rz_bits_sign_ext64(rz_bits_extract(word, 0, 16), 16);
		break;
	default:
		return false;
	}
	return true;
}

static ut64 mips_ahl_key(const RzBinElfReloc *reloc) {
	return ((ut64)reloc->section << 32) | (ut32)reloc->sym;
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
 * A high half takes the next LO16 against the same symbol in the same
 * section, and a LO16 the previous high half, as either may be shared. A half
 * without a pair keeps its own part.
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
		ut64 key = mips_ahl_key(reloc);
		bool found = false;
		if (mips_is_hi16(bin, reloc)) {
			ht_uu_update(high, key, reloc->addend);
		} else if (reloc->type == R_MIPS_LO16) {
			ut64 part = ht_uu_find(high, key, &found);
			if (found) {
				reloc->addend = mips_ahl(part, reloc->addend);
			}
		}
	}
	// Backwards, as a high half takes the LO16 after it. The low 16 bits of a
	// LO16 addend are its own part, joined or not.
	for (size_t i = rz_vector_len(bin->relocs); i-- > 0;) {
		reloc = rz_vector_index_ptr(bin->relocs, i);
		if (reloc->mode != DT_REL) {
			continue;
		}
		ut64 key = mips_ahl_key(reloc);
		bool found = false;
		if (reloc->type == R_MIPS_LO16) {
			ht_uu_update(low, key, reloc->addend);
		} else if (mips_is_hi16(bin, reloc)) {
			ut64 part = ht_uu_find(low, key, &found);
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
