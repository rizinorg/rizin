// SPDX-FileCopyrightText: 2024-2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"
#include "elf/glibc_elf.h"
#include "rz_types.h"
#include "rz_types_base.h"
#include "rz_util/rz_buf.h"
#include "rz_util/rz_log.h"

typedef struct reloc_formular_symbols_t {
	ut64 A; // Appendend
	ut64 B; // Base address
	ut64 G; // Offset into GOT for symbol entry.
	ut64 GOT; // Address of entry zero in GOT.
	ut64 L; // Offset into POT for symbol entry.
	ut64 P; // Place address of the field being relocated. The address of the bytes to patch.
	ut64 S; // Value of symbol.
	ut64 Z; // Size of symbol.
	ut64 TLS; // Thread-pointer-relative offset to a thread-local symbol.
	ut64 T; // Base address of the static thread-local tmeplate that contains a thread-local symbol.
	ut64 MB; // Base address of all strings consumed by compiler message base optimization (Hexagon specific).
	ut64 GP; // Value of GP register (Hexagon specific).
	ut64 AHL; // Special value used by MIPS to handle R_MIPS_HI16 & R_MIPS_LO16 relocs
	/**
	 * \brief Sparc64: Secondary addend, extracted from the r_info field by
	 * applying the ELF_SPARC64_R_TYPE_DATA macro (alias for ELF64_R_TYPE_DATA).
	 */
	ut64 O;
} RelocFormularSymbols;

typedef struct {
	ut32 cmpMask; // Opcode bits of instruction.
	ut32 relocMask; // Relocation bitmask for patching.
} HexagonRelocMask;

/**
 * \brief Maps instructions of the R_HEX_6_X relocation typ
 * to its bitmask patched during relocation.
 */
static const HexagonRelocMask hex_rel6_x_masks[] = {
	{ 0x38000000, 0x0000201f }, { 0x39000000, 0x0000201f },
	{ 0x3e000000, 0x00001f80 }, { 0x3f000000, 0x00001f80 },
	{ 0x40000000, 0x000020f8 }, { 0x41000000, 0x000007e0 },
	{ 0x42000000, 0x000020f8 }, { 0x43000000, 0x000007e0 },
	{ 0x44000000, 0x000020f8 }, { 0x45000000, 0x000007e0 },
	{ 0x46000000, 0x000020f8 }, { 0x47000000, 0x000007e0 },
	{ 0x6a000000, 0x00001f80 }, { 0x7c000000, 0x001f2000 },
	{ 0x9a000000, 0x00000f60 }, { 0x9b000000, 0x00000f60 },
	{ 0x9c000000, 0x00000f60 }, { 0x9d000000, 0x00000f60 },
	{ 0x9f000000, 0x001f0100 }, { 0xab000000, 0x0000003f },
	{ 0xad000000, 0x0000003f }, { 0xaf000000, 0x00030078 },
	{ 0xd7000000, 0x006020e0 }, { 0xd8000000, 0x006020e0 },
	{ 0xdb000000, 0x006020e0 }, { 0xdf000000, 0x006020e0 }
};

/**
 * \brief Returns the bitmask for reloc patching of a Hexagon instruction
 * of type R_HEX_6_X.
 *
 * \param insn The instruction bits.
 * \return ut32 The bitmask for patching.
 */
static ut32 hexagon_get_bitmask_r6(ut32 insn) {
	if ((insn & 0xc000) == 0) { // Duplex instruction
		return 0x03f00000;
	}

	for (int i = 0; i < sizeof(hex_rel6_x_masks) / sizeof(HexagonRelocMask); ++i) {
		if ((0xff000000 & insn) == hex_rel6_x_masks[i].cmpMask) {
			return hex_rel6_x_masks[i].relocMask;
		}
	}
	RZ_LOG_ERROR("Unrecognized instruction for 6_X relocation: 0x%x\n", insn);
	return 0;
}

/**
 * \brief Returns the bitmask for reloc patching of a Hexagon instruction
 * of type R_HEX_8_X.
 *
 * \param insn The instruction bits.
 * \return ut32 The bitmask for patching.
 */
static ut32 hexagon_get_bitmask_r8(ut32 insn) {
	if ((0xff000000 & insn) == 0xde000000) {
		return 0x00e020e8;
	}
	if ((0xff000000 & insn) == 0x3c000000) {
		return 0x0000207f;
	}
	return 0x00001fe0;
}

/**
 * \brief Returns the bitmask for reloc patching of a Hexagon instruction
 * of type R_HEX_11_X.
 *
 * \param insn The instruction bits.
 * \return ut32 The bitmask for patching.
 */
static ut32 hexagon_get_bitmask_r11(ut32 insn) {
	if ((0xff000000 & insn) == 0xa1000000) {
		return 0x060020ff;
	}
	return 0x06003fe0;
}

/**
 * \brief Returns the bitmask for reloc patching of a Hexagon instruction
 * of type R_HEX_16_X.
 *
 * \param insn The instruction bits.
 * \return ut32 The bitmask for patching.
 */
static ut32 hexagon_get_bitmask_r16(ut32 insn) {
	if ((0xff000000 & insn) == 0x48000000) {
		return 0x061f20ff;
	}
	if ((0xff000000 & insn) == 0x49000000) {
		return 0x061f3fe0;
	}
	if ((0xff000000 & insn) == 0x78000000) {
		return 0x00df3fe0;
	}
	if ((0xff000000 & insn) == 0xb0000000) {
		return 0x0fe03fe0;
	}
	if ((insn & 0xc000) == 0) { // Duplex instruction
		return 0x03f00000;
	}

	for (int i = 0; i < sizeof(hex_rel6_x_masks) / sizeof(HexagonRelocMask); ++i) {
		if ((0xff000000 & insn) == hex_rel6_x_masks[i].cmpMask) {
			return hex_rel6_x_masks[i].relocMask;
		}
	}

	RZ_LOG_ERROR("Unrecognized instruction for 16_X relocation: 0x%x\n", insn);
	return 0;
}

/**
 * \brief Patches a given value into an opcode at \p addr in \p buf_patched.
 * The bits from \p val are spread into the resulting value according to \p mask.
 *
 * Often immediated bits in opcodes are not sequential.
 * If a relocation value is patched into the opcode,
 * its bits must be aligned with bit locations in the opcode.
 * The parameter \p mask indicates where the immediate bits are located.
 *
 * \param buf_patched Pointer to buffer.
 * \param big_endian If set reads and writes the buffer in big endian.
 * \param addr Address the opcode is located.
 * \param mask The bitmask (patchable bits) of the opcode bits to set.
 * \param val The value patched into the opcode.
 */
static void patch_val_over_mask_32(RZ_INOUT RzBuffer *buf_patched, bool big_endian, const ut32 addr, const ut32 mask, const ut32 val) {
	rz_return_if_fail(buf_patched);
	ut8 buf[4] = { 0 };

	rz_buf_read_at(buf_patched, addr, buf, 4);
	ut32 opcode = rz_read_ble32(buf, big_endian) | rz_bits_spread(mask, val);

	rz_write_ble32(buf, opcode, big_endian);
	rz_buf_write_at(buf_patched, addr, buf, 4);
}

/**
 * \brief Does the same as patch_val_over_mask_32 but for 64bit values.
 */
static void patch_val_over_mask_64(RZ_INOUT RzBuffer *buf_patched, bool big_endian, const ut64 addr, const ut64 mask, const ut64 val) {
	rz_return_if_fail(buf_patched);
	ut8 buf[8] = { 0 };

	rz_buf_read_at(buf_patched, addr, buf, 8);
	ut64 opcode = rz_read_ble64(buf, big_endian) | rz_bits_spread(mask, val);

	rz_write_ble64(buf, opcode, big_endian);
	rz_buf_write_at(buf_patched, addr, buf, 8);
}

/**
 * \brief Does the same as patch_val_over_mask_32 but for 16bit values.
 */
static void patch_val_over_mask_16(RZ_INOUT RzBuffer *buf_patched, bool big_endian, const ut64 addr, const ut16 mask, const ut16 val) {
	rz_return_if_fail(buf_patched);
	ut8 buf[2] = { 0 };

	rz_buf_read_at(buf_patched, addr, buf, 2);
	ut16 opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(mask, val);

	rz_write_ble16(buf, opcode, big_endian);
	rz_buf_write_at(buf_patched, addr, buf, 2);
}

#define UNHANDL(NAME) \
	RZ_LOG_WARN("Unhandled " NAME " reloc\n"); \
	return

#define UNHANDL_DEF(NAME, NUM) \
	RZ_LOG_WARN(NAME ": Unhandled patching case for relocation %d.\n", NUM)

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols (e.g. TLS, G) are not yet implemented and are set to 0.
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_hexagon(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, const RelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[8] = { 0 };
	ut64 val = 0;
	ut64 bitmask = R_HEX_BITMASK_WORD32; // Mask of value and opcode bits.

	switch (rel_type) {
	default:
		// For more implementetations check out the LLVM src:
		// https://github.com/llvm/llvm-project/blob/abc17a67519747be36f1fd03e227c5103da4c677/lld/ELF/Arch/Hexagon.cpp
		UNHANDL_DEF("Hexagon", rel_type);
		return;
	case R_HEX_NONE:
		return;
	case R_HEX_GLOB_DAT:
	case R_HEX_JMP_SLOT:
		val = (fs->S + fs->A);
		break;
	case R_HEX_RELATIVE:
		val = (fs->B + fs->A);
		break;
	case R_HEX_B22_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B22;
		val = (fs->S + fs->A - fs->P) >> 2;
		break;
	case R_HEX_B15_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B15;
		val = (fs->S + fs->A - fs->P) >> 2;
		break;
	case R_HEX_B7_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B7;
		val = (fs->S + fs->A - fs->P) >> 2;
		break;
	case R_HEX_LO16:
		bitmask = R_HEX_BITMASK_WORD32_LO;
		val = (fs->S + fs->A);
		break;
	case R_HEX_HI16:
		bitmask = R_HEX_BITMASK_WORD32_HL;
		val = (fs->S + fs->A) >> 16;
		break;
	case R_HEX_32:
		val = (fs->S + fs->A);
		break;
	case R_HEX_16:
		bitmask = R_HEX_BITMASK_WORD16;
		val = (fs->S + fs->A);
		break;
	case R_HEX_8:
		bitmask = R_HEX_BITMASK_WORD8;
		val = (fs->S + fs->A);
		break;
	case R_HEX_HL16:
		bitmask = R_HEX_BITMASK_WORD32_HL;
		val = (fs->S + fs->A);
		break;
	case R_HEX_B13_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B13;
		val = (fs->S + fs->A - fs->P) >> 2;
		break;
	case R_HEX_B9_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B9;
		val = (fs->S + fs->A - fs->P) >> 2;
		break;
	case R_HEX_B32_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_X26;
		val = (fs->S + fs->A - fs->P) >> 6;
		break;
	case R_HEX_32_6_X:
		bitmask = R_HEX_BITMASK_WORD32_X26;
		val = (fs->S + fs->A) >> 6;
		break;
	case R_HEX_B22_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B22;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_B15_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B15;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_B13_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B13;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_B9_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B9;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_B7_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B7;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_12_X:
		bitmask = R_HEX_BITMASK_WORD32_R6;
		val = (fs->S + fs->A);
		break;
	case R_HEX_32_PCREL:
		val = (fs->S + fs->A - fs->P);
		break;
	case R_HEX_GOTREL_LO16:
		bitmask = R_HEX_BITMASK_WORD32_LO;
		val = (fs->S + fs->A - fs->GOT);
		break;
	case R_HEX_GOTREL_HI16:
		bitmask = R_HEX_BITMASK_WORD32_HL;
		val = (fs->S + fs->A - fs->GOT) >> 16;
		break;
	case R_HEX_GOTREL_32:
		val = (fs->S + fs->A - fs->GOT);
		break;
	case R_HEX_GOTREL_32_6_X:
		bitmask = R_HEX_BITMASK_WORD32_X26;
		val = (fs->S + fs->A - fs->GOT) >> 6;
		break;
	case R_HEX_PLT_B22_PCREL:
	case R_HEX_LD_PLT_B22_PCREL:
	case R_HEX_GD_PLT_B22_PCREL:
		bitmask = R_HEX_BITMASK_WORD32_B22;
		val = (fs->L + fs->A - fs->P) >> 2;
		break;
	case R_HEX_GD_PLT_B22_PCREL_X:
	case R_HEX_LD_PLT_B22_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_B22;
		val = (fs->S + fs->A - fs->P) & 0x3f;
		break;
	case R_HEX_GD_PLT_B32_PCREL_X:
	case R_HEX_LD_PLT_B32_PCREL_X:
		bitmask = R_HEX_BITMASK_WORD32_X26;
		val = (fs->S + fs->A - fs->P) >> 6;
		break;
	case R_HEX_16_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r16(rz_read_le32(buf));
		val = (fs->S + fs->A) & 0x3f;
		break;
	case R_HEX_11_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r11(rz_read_le32(buf));
		val = (fs->S + fs->A) & 0x3f;
		break;
	case R_HEX_10_X:
		bitmask = 0x00203fe0;
		val = (fs->S + fs->A) & 0x3f;
		break;
	case R_HEX_9_X:
		bitmask = 0x00003fe0;
		val = (fs->S + fs->A) & 0x3f;
		break;
	case R_HEX_8_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r8(rz_read_le32(buf));
		val = (fs->S + fs->A);
		break;
	case R_HEX_6_PCREL_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r6(rz_read_le32(buf));
		val = (fs->S + fs->A - fs->P);
		break;
	case R_HEX_6_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r6(rz_read_le32(buf));
		val = (fs->S + fs->A);
		break;
	case R_HEX_GOTREL_16_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r16(rz_read_le32(buf));
		val = (fs->S + fs->A - fs->GOT);
		break;
	case R_HEX_GOTREL_11_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r11(rz_read_le32(buf));
		val = (fs->S + fs->A - fs->GOT);
		break;
	case R_HEX_DTPREL_32_6_X:
		bitmask = R_HEX_BITMASK_WORD32_X26;
		val = (fs->S + fs->A - fs->T) >> 6;
		break;
	case R_HEX_DTPREL_16_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r16(rz_read_le32(buf));
		val = (fs->S + fs->A - fs->T);
		break;
	case R_HEX_DTPREL_11_X:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		bitmask = hexagon_get_bitmask_r11(rz_read_le32(buf));
		val = (fs->S + fs->A - fs->T);
		break;
	}
	// Patch two opcodes at once.
	if (rel_type == R_HEX_HL16) {
		patch_val_over_mask_32(buf_patched, false, patch_addr, bitmask, val & 0xffffffff);
		patch_val_over_mask_32(buf_patched, false, patch_addr + 4, bitmask, val >> 32);
	} else {
		patch_val_over_mask_32(buf_patched, false, patch_addr, bitmask, val);
	}
}

static void patch_reloc_sparc(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, const RelocFormularSymbols *fs) {
	ut64 val = 0;
	ut64 bitmask = 0;

	switch (rel_type) {
	default:
		UNHANDL_DEF("Sparc", rel_type);
		return;
	case R_SPARC_GOTDATA_OP:
		// bitmask = R_SPARC_BITMASK_WORD32;
		// I can't find details how this one is patched.
		// The docs all refer to "the explanation following this table."
		// But there is no explanation in all the docs I could find.
		// There is a related LLVM issue about those though:
		// https://github.com/llvm/llvm-project/issues/100320
		//
		// But in https://docs.oracle.com/cd/E53394_01/html/E54833/gpvxz.html
		// it looks like this relocation simply signals the
		// linker to check for an optimization.
		// So return her silently.
		return;
	case R_SPARC_JMP_SLOT:
		// PLT entry patched by the runtime linker are of these reloc types.
		// The values written there depend on %g1.
		// %g1 seems to be used to store the relative offset from the PC
		// to a section base address is made in.
		// So for JMP_SLOT it would hold the offset to the PLT at patch time.
		// At least this is how it is done for the GOT patching in here
		// https://docs.oracle.com/cd/E53394_01/html/E54833/gpvxz.html
	case R_SPARC_COPY:
		// Copies data from a shared library to the
		// dynamic executable's pre-allocated space for this data.
		UNHANDL_DEF("Sparc", rel_type);
	case R_SPARC_NONE:
		return;
	case R_SPARC_8:
		bitmask = R_SPARC_BITMASK_BYTE8;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_16:
		bitmask = R_SPARC_BITMASK_HALF16;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_32:
		bitmask = R_SPARC_BITMASK_WORD32;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_DISP8:
		bitmask = R_SPARC_BITMASK_BYTE8;
		val = (fs->S + fs->A - fs->P);
		break;
	case R_SPARC_DISP16:
		bitmask = R_SPARC_BITMASK_HALF16;
		val = (fs->S + fs->A - fs->P);
		break;
	case R_SPARC_DISP32:
		bitmask = R_SPARC_BITMASK_DISP32;
		val = (fs->S + fs->A - fs->P);
		break;
	case R_SPARC_WDISP30:
		bitmask = R_SPARC_BITMASK_DISP30;
		val = ((fs->S + fs->A - fs->P) >> 2);
		break;
	case R_SPARC_WDISP22:
		bitmask = R_SPARC_BITMASK_DISP22;
		val = ((fs->S + fs->A - fs->P) >> 2);
		break;
	case R_SPARC_HI22:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = ((fs->S + fs->A) >> 10);
		break;
	case R_SPARC_22:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_13:
		bitmask = R_SPARC_BITMASK_SIMM13;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_LO10:
		bitmask = R_SPARC_BITMASK_SIMM13;
		val = ((fs->S + fs->A) & 0x3ff);
		break;
	case R_SPARC_GOT10:
		bitmask = R_SPARC_BITMASK_SIMM13;
		val = (fs->G & 0x3ff);
		break;
	case R_SPARC_GOT13:
		bitmask = R_SPARC_BITMASK_SIMM13;
		val = (fs->G);
		break;
	case R_SPARC_GOT22:
		bitmask = R_SPARC_BITMASK_SIMM22;
		val = (fs->G >> 10);
		break;
	case R_SPARC_PC10:
		bitmask = R_SPARC_BITMASK_SIMM13;
		val = ((fs->S + fs->A - fs->P) & 0x3ff);
		break;
	case R_SPARC_PC22:
		bitmask = R_SPARC_BITMASK_DISP22;
		val = ((fs->S + fs->A - fs->P) >> 10);
		break;
	case R_SPARC_WPLT30:
		bitmask = R_SPARC_BITMASK_DISP30;
		val = ((fs->L + fs->A - fs->P) >> 2);
		break;
	case R_SPARC_GLOB_DAT:
		bitmask = R_SPARC_BITMASK_WORD32;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_RELATIVE:
		bitmask = R_SPARC_BITMASK_WORD32;
		val = (fs->B + fs->A);
		break;
	case R_SPARC_UA32:
		bitmask = R_SPARC_BITMASK_WORD32;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_PLT32:
		bitmask = R_SPARC_BITMASK_WORD32;
		val = (fs->L + fs->A);
		break;
	case R_SPARC_HIPLT22:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = ((fs->L + fs->A) >> 10);
		break;
	case R_SPARC_LOPLT10:
		bitmask = R_SPARC_BITMASK_SIMM13;
		val = ((fs->L + fs->A) & 0x3ff);
		break;
	case R_SPARC_PCPLT32:
		bitmask = R_SPARC_BITMASK_WORD32;
		val = (fs->L + fs->A - fs->P);
		break;
	case R_SPARC_PCPLT22:
		bitmask = R_SPARC_BITMASK_DISP22;
		val = ((fs->L + fs->A - fs->P) >> 10);
		break;
	case R_SPARC_PCPLT10:
		bitmask = R_SPARC_BITMASK_SIMM13;
		val = ((fs->L + fs->A - fs->P) & 0x3ff);
		break;
	case R_SPARC_10:
		bitmask = R_SPARC_BITMASK_SIMM10;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_11:
		bitmask = R_SPARC_BITMASK_SIMM11;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_64:
		bitmask = R_SPARC_BITMASK_XWORD64;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_OLO10:
		bitmask = R_SPARC_BITMASK_SIMM13;
		val = (((fs->S + fs->A) & 0x3ff) + fs->O);
		break;
	case R_SPARC_HH22:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = ((fs->S + fs->A) >> 42);
		break;
	case R_SPARC_HM10:
		bitmask = R_SPARC_BITMASK_SIMM13;
		val = (((fs->S + fs->A) >> 32) & 0x3ff);
		break;
	case R_SPARC_LM22:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = ((fs->S + fs->A) >> 10);
		break;
	case R_SPARC_PC_HH22:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = ((fs->S + fs->A - fs->P) >> 42);
		break;
	case R_SPARC_PC_HM10:
		bitmask = R_SPARC_BITMASK_SIMM13;
		val = (((fs->S + fs->A - fs->P) >> 32) & 0x3ff);
		break;
	case R_SPARC_PC_LM22:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = ((fs->S + fs->A - fs->P) >> 10);
		break;
	case R_SPARC_WDISP16:
		bitmask = R_SPARC_BITMASK_D2_DISP14;
		val = ((fs->S + fs->A - fs->P) >> 2);
		break;
	case R_SPARC_WDISP19:
		bitmask = R_SPARC_BITMASK_DISP19;
		val = ((fs->S + fs->A - fs->P) >> 2);
		break;
	case R_SPARC_7:
		bitmask = R_SPARC_BITMASK_IMM7;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_5:
		bitmask = R_SPARC_BITMASK_IMM5;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_6:
		bitmask = R_SPARC_BITMASK_IMM6;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_DISP64:
		bitmask = R_SPARC_BITMASK_XWORD64;
		val = (fs->S + fs->A - fs->P);
		break;
	case R_SPARC_PLT64:
		bitmask = R_SPARC_BITMASK_XWORD64;
		val = (fs->L + fs->A);
		break;
	case R_SPARC_HIX22:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = (((fs->S + fs->A) ^ 0xffffffffffffffff) >> 10);
		break;
	case R_SPARC_LOX10:
		bitmask = R_SPARC_BITMASK_SIMM13;
		val = (((fs->S + fs->A) & 0x3ff) | 0x1c00);
		break;
	case R_SPARC_H44:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = ((fs->S + fs->A) >> 22);
		break;
	case R_SPARC_M44:
		bitmask = R_SPARC_BITMASK_IMM10;
		val = (((fs->S + fs->A) >> 12) & 0x3ff);
		break;
	case R_SPARC_L44:
		bitmask = R_SPARC_BITMASK_IMM13;
		val = ((fs->S + fs->A) & 0xfff);
		break;
	case R_SPARC_REGISTER:
		bitmask = R_SPARC_BITMASK_WORD32;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_UA64:
		bitmask = R_SPARC_BITMASK_XWORD64;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_UA16:
		bitmask = R_SPARC_BITMASK_HALF16;
		val = (fs->S + fs->A);
		break;
	case R_SPARC_H34:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = ((fs->S + fs->A) >> 12);
		break;
	case R_SPARC_SIZE64:
		bitmask = R_SPARC_BITMASK_XWORD64;
		val = (fs->Z + fs->A);
		break;
	case R_SPARC_GOTDATA_HIX22:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = (((fs->S + fs->A - fs->GOT) >> 10) ^ ((fs->S + fs->A - fs->GOT) >> 31));
		break;
	case R_SPARC_GOTDATA_LOX10:
		bitmask = R_SPARC_BITMASK_IMM13;
		val = (((fs->S + fs->A - fs->GOT) & 0x3ff) | (((fs->S + fs->A - fs->GOT) >> 31) & 0x1c00));
		break;
	case R_SPARC_GOTDATA_OP_HIX22:
		bitmask = R_SPARC_BITMASK_IMM22;
		val = ((fs->G >> 10) ^ (fs->G >> 31));
		break;
	case R_SPARC_GOTDATA_OP_LOX10:
		bitmask = R_SPARC_BITMASK_IMM13;
		val = ((fs->G & 0x3ff) | ((fs->G >> 31) & 0x1c00));
		break;
	case R_SPARC_SIZE32:
		bitmask = R_SPARC_BITMASK_WORD32;
		val = (fs->Z + fs->A);
		break;
	case R_SPARC_WDISP10:
		bitmask = R_SPARC_BITMASK_D2_DISP8;
		val = ((fs->S + fs->A - fs->P) >> 2);
		break;
	}
	if (bitmask == R_SPARC_BITMASK_XWORD64) {
		patch_val_over_mask_64(buf_patched, big_endian, patch_addr, bitmask, val);
	} else {
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, bitmask, val);
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param big_endian The endianness - true if BE, false if LE
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_mips(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, RelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[4] = { 0 };
	ut64 val = 0;

	switch (rel_type) {
	default:
		UNHANDL_DEF("MIPS", rel_type);
		return;
	case R_MIPS_NONE:
		return;
	case R_MIPS_16: // S + sign–extend(A)
		rz_buf_read_at(buf_patched, patch_addr, buf, 2);
		val = rz_read_ble16(buf, big_endian);
		val += fs->S + fs->A;
		rz_write_ble16(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 2);
		return;
	case R_MIPS_32: // S + A
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = rz_read_ble32(buf, big_endian);
		val += fs->S + fs->A;
		rz_write_ble32(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		return;
	case R_MIPS_REL32: // A – EA + S
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = rz_read_ble32(buf, big_endian);
		val += fs->S + fs->A - fs->P;
		rz_write_ble32(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		return;
	case R_MIPS_26: // (((A << 2) | (P & 0xf0000000) + S) >> 2
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = rz_read_ble32(buf, big_endian);
		val += ((fs->A << 2) | (fs->P & 0xf0000000));
		val += fs->S;
		val >>= 2;
		rz_write_ble32(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		return;
	case R_MIPS_HI16:
		rz_buf_read_at(buf_patched, patch_addr, buf, 2);
		fs->AHL = rz_read_ble16(buf, big_endian) << 16;
		return;
	case R_MIPS_LO16:
		rz_buf_read_at(buf_patched, patch_addr, buf, 2);
		val = rz_read_ble16(buf, big_endian);
		val += fs->AHL;
		val += fs->S;
		rz_write_ble32(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		return;
	case R_MIPS_GPREL16: UNHANDL("R_MIPS_GPREL16");
	case R_MIPS_LITERAL: UNHANDL("R_MIPS_LITERAL");
	case R_MIPS_GOT16: UNHANDL("R_MIPS_GOT16");
	case R_MIPS_PC16: UNHANDL("R_MIPS_PC16");
	case R_MIPS_CALL16: UNHANDL("R_MIPS_CALL16");
	case R_MIPS_GPREL32: UNHANDL("R_MIPS_GPREL32");
	case R_MIPS_SHIFT5: UNHANDL("R_MIPS_SHIFT5");
	case R_MIPS_SHIFT6: UNHANDL("R_MIPS_SHIFT6");
	case R_MIPS_64: UNHANDL("R_MIPS_64");
	case R_MIPS_GOT_DISP: UNHANDL("R_MIPS_GOT_DISP");
	case R_MIPS_GOT_PAGE: UNHANDL("R_MIPS_GOT_PAGE");
	case R_MIPS_GOT_OFST: UNHANDL("R_MIPS_GOT_OFST");
	case R_MIPS_GOT_HI16: UNHANDL("R_MIPS_GOT_HI16");
	case R_MIPS_GOT_LO16: UNHANDL("R_MIPS_GOT_LO16");
	case R_MIPS_SUB: UNHANDL("R_MIPS_SUB");
	case R_MIPS_INSERT_A: UNHANDL("R_MIPS_INSERT_A");
	case R_MIPS_INSERT_B: UNHANDL("R_MIPS_INSERT_B");
	case R_MIPS_DELETE: UNHANDL("R_MIPS_DELETE");
	case R_MIPS_HIGHER: UNHANDL("R_MIPS_HIGHER");
	case R_MIPS_HIGHEST: UNHANDL("R_MIPS_HIGHEST");
	case R_MIPS_CALL_HI16: UNHANDL("R_MIPS_CALL_HI16");
	case R_MIPS_CALL_LO16: UNHANDL("R_MIPS_CALL_LO16");
	case R_MIPS_SCN_DISP: UNHANDL("R_MIPS_SCN_DISP");
	case R_MIPS_REL16: UNHANDL("R_MIPS_REL16");
	case R_MIPS_ADD_IMMEDIATE: UNHANDL("R_MIPS_ADD_IMMEDIATE");
	case R_MIPS_PJUMP: UNHANDL("R_MIPS_PJUMP");
	case R_MIPS_RELGOT: UNHANDL("R_MIPS_RELGOT");
	case R_MIPS_JALR: UNHANDL("R_MIPS_JALR");
	case R_MIPS_TLS_DTPMOD32: UNHANDL("R_MIPS_TLS_DTPMOD32");
	case R_MIPS_TLS_DTPREL32: UNHANDL("R_MIPS_TLS_DTPREL32");
	case R_MIPS_TLS_DTPMOD64: UNHANDL("R_MIPS_TLS_DTPMOD64");
	case R_MIPS_TLS_DTPREL64: UNHANDL("R_MIPS_TLS_DTPREL64");
	case R_MIPS_TLS_GD: UNHANDL("R_MIPS_TLS_GD");
	case R_MIPS_TLS_LDM: UNHANDL("R_MIPS_TLS_LDM");
	case R_MIPS_TLS_DTPREL_HI16: UNHANDL("R_MIPS_TLS_DTPREL_HI16");
	case R_MIPS_TLS_DTPREL_LO16: UNHANDL("R_MIPS_TLS_DTPREL_LO16");
	case R_MIPS_TLS_GOTTPREL: UNHANDL("R_MIPS_TLS_GOTTPREL");
	case R_MIPS_TLS_TPREL32: UNHANDL("R_MIPS_TLS_TPREL32");
	case R_MIPS_TLS_TPREL64: UNHANDL("R_MIPS_TLS_TPREL64");
	case R_MIPS_TLS_TPREL_HI16: UNHANDL("R_MIPS_TLS_TPREL_HI16");
	case R_MIPS_TLS_TPREL_LO16: UNHANDL("R_MIPS_TLS_TPREL_LO16");
	case R_MIPS_GLOB_DAT: UNHANDL("R_MIPS_GLOB_DAT");
	case R_MIPS_COPY: UNHANDL("R_MIPS_COPY");
	case R_MIPS_JUMP_SLOT: UNHANDL("R_MIPS_JUMP_SLOT");
	case R_MICROMIPS_26_S1: UNHANDL("R_MICROMIPS_26_S1");
	case R_MICROMIPS_HI16: UNHANDL("R_MICROMIPS_HI16");
	case R_MICROMIPS_LO16: UNHANDL("R_MICROMIPS_LO16");
	case R_MICROMIPS_GPREL16: UNHANDL("R_MICROMIPS_GPREL16");
	case R_MICROMIPS_LITERAL: UNHANDL("R_MICROMIPS_LITERAL");
	case R_MICROMIPS_GOT16: UNHANDL("R_MICROMIPS_GOT16");
	case R_MICROMIPS_PC7_S1: UNHANDL("R_MICROMIPS_PC7_S1");
	case R_MICROMIPS_PC10_S1: UNHANDL("R_MICROMIPS_PC10_S1");
	case R_MICROMIPS_PC16_S1: UNHANDL("R_MICROMIPS_PC16_S1");
	case R_MICROMIPS_CALL16: UNHANDL("R_MICROMIPS_CALL16");
	case R_MICROMIPS_GOT_DISP: UNHANDL("R_MICROMIPS_GOT_DISP");
	case R_MICROMIPS_GOT_PAGE: UNHANDL("R_MICROMIPS_GOT_PAGE");
	case R_MICROMIPS_GOT_OFST: UNHANDL("R_MICROMIPS_GOT_OFST");
	case R_MICROMIPS_GOT_HI16: UNHANDL("R_MICROMIPS_GOT_HI16");
	case R_MICROMIPS_GOT_LO16: UNHANDL("R_MICROMIPS_GOT_LO16");
	case R_MICROMIPS_SUB: UNHANDL("R_MICROMIPS_SUB");
	case R_MICROMIPS_HIGHER: UNHANDL("R_MICROMIPS_HIGHER");
	case R_MICROMIPS_HIGHEST: UNHANDL("R_MICROMIPS_HIGHEST");
	case R_MICROMIPS_CALL_HI16: UNHANDL("R_MICROMIPS_CALL_HI16");
	case R_MICROMIPS_CALL_LO16: UNHANDL("R_MICROMIPS_CALL_LO16");
	case R_MICROMIPS_SCN_DISP: UNHANDL("R_MICROMIPS_SCN_DISP");
	case R_MICROMIPS_JALR: UNHANDL("R_MICROMIPS_JALR");
	case R_MICROMIPS_HI0_LO16: UNHANDL("R_MICROMIPS_HI0_LO16");
	case R_MICROMIPS_TLS_GD: UNHANDL("R_MICROMIPS_TLS_GD");
	case R_MICROMIPS_TLS_LDM: UNHANDL("R_MICROMIPS_TLS_LDM");
	case R_MICROMIPS_TLS_DTPREL_HI16: UNHANDL("R_MICROMIPS_TLS_DTPREL_HI16");
	case R_MICROMIPS_TLS_DTPREL_LO16: UNHANDL("R_MICROMIPS_TLS_DTPREL_LO16");
	case R_MICROMIPS_TLS_GOTTPREL: UNHANDL("R_MICROMIPS_TLS_GOTTPREL");
	case R_MICROMIPS_TLS_TPREL_HI16: UNHANDL("R_MICROMIPS_TLS_TPREL_HI16");
	case R_MICROMIPS_TLS_TPREL_LO16: UNHANDL("R_MICROMIPS_TLS_TPREL_LO16");
	case R_MICROMIPS_GPREL7_S2: UNHANDL("R_MICROMIPS_GPREL7_S2");
	case R_MICROMIPS_PC23_S2: UNHANDL("R_MICROMIPS_PC23_S2");
	case R_MIPS_PC32: UNHANDL("R_MIPS_PC32");
	case R_MIPS_EH: UNHANDL("R_MIPS_EH");
	case R_MIPS_GNU_REL16_S2: UNHANDL("R_MIPS_GNU_REL16_S2");
	case R_MIPS_GNU_VTINHERIT: UNHANDL("R_MIPS_GNU_VTINHERIT");
	case R_MIPS_GNU_VTENTRY: UNHANDL("R_MIPS_GNU_VTENTRY");
	}
}

// For arm group relocations related to ALU instructions
static ut32 convert_alu_group_mask(ut32 X, int n) {
	ut32 residual = X;
	ut32 encoded_g_n = 0;

	for (int current_n = 0; current_n <= n; current_n++) {
		int msb;
		int shift;

		if (residual == 0) {
			shift = 0;
		} else {
			for (msb = 30; msb >= 0; msb -= 2) {
				if (residual & (0x3 << msb)) {
					break;
				}
			}
			shift = ((msb - 6) < 0) ? 0 : (msb - 6);
		}

		ut32 g_n = residual & (0xFF << shift);
		encoded_g_n = (g_n >> shift) | ((g_n <= 0xff ? 0 : (32 - shift) / 2) << 8);

		residual &= ~g_n;
	}

	return encoded_g_n;
}

// For arm group relocations not related to ALU instructions
static ut32 convert_group_mask(ut32 X, int n) {
	ut32 residual = X;

	for (int current_n = 0; current_n <= n; current_n++) {
		int msb;
		int shift;

		if (residual == 0) {
			shift = 0;
		} else {
			for (msb = 30; msb >= 0; msb -= 2) {
				if (residual & (0x3 << msb)) {
					break;
				}
			}
			shift = ((msb - 6) < 0) ? 0 : (msb - 6);
		}

		ut32 g_n = residual & (0xFF << shift);
		residual &= ~g_n;
	}

	return residual;
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel The relocation elf structure.
 * \param big_endian The endianness - true if BE, false if LE
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_arm(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const RzBinElfReloc *rel, bool big_endian, const RelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && rel && fs);
	ut16 keephw1 = 0, keephw2 = 0;
	ut32 nbytes = 4;
	ut8 buf[4] = { 0 };
	ut64 val = 0;
	ut16 offset = 0;

	switch (rel->type) {
	case R_ARM_NONE:
		return;
	case R_ARM_THM_JUMP24:
		/* fall-thru */
	case R_ARM_THM_CALL:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		// Encoding B  T4, BL T1, BLX T2: Val = S:I1:I2:imm10:imm11:0
		// I1 = NOT(J1 EOR S)
		// I2 = NOT(J2 EOR S)
		val = fs->S + fs->A;
		keephw1 = rz_read_ble16(&buf[0], big_endian);
		keephw2 = rz_read_ble16(&buf[2], big_endian);
		rz_write_ble16(&buf[0],
			(keephw1 & 0xF800U) | // opcode
				((val >> 14) & 0x0400U) | // sign
				((val >> 12) & 0x03FFU), // imm 10
			big_endian);
		rz_write_ble16(&buf[2],
			(keephw2 & 0xD000U) | // opcode
				(((~(val >> 10)) ^ (val >> 11)) & 0x2000) | // J1
				(((~(val >> 11)) ^ (val >> 13)) & 0x0800) | // J2
				((val >> 1) & 0x07ff), // imm11
			big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_ABS32:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A;
		rz_write_ble32(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_REL32:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A - fs->P;
		rz_write_ble32(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_PC24:
	/* fall through */
	case R_ARM_PLT32:
	/* fall through */
	case R_ARM_CALL:
	/* fall through */
	case R_ARM_JUMP24:
		val = fs->S + fs->A - fs->P;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0x03FFFFFE, (val >> 2));
		break;

	case R_ARM_MOVW_PREL_NC:
		val = fs->S + fs->A - fs->P;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0x000F0FFF, val);
		break;

	case R_ARM_THM_MOVW_PREL_NC:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		// val = imm4:i:imm3:imm8
		val = fs->S + fs->A - fs->P;
		keephw1 = rz_read_ble16(&buf[0], big_endian);
		keephw2 = rz_read_ble16(&buf[2], big_endian);
		keephw1 = (keephw1 & 0xFBF0) |
			((val & 0xF000) >> 12) | // imm4
			((val & 0x0800) >> 1); // i
		keephw2 = (keephw2 & 0x8F00) |
			((val & 0x0700) << 4) | // imm3
			((val & 0x00FF)); // imm8
		rz_write_ble16(&buf[0], keephw1, big_endian);
		rz_write_ble16(&buf[2], keephw2, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_THM_JUMP19:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		// val = S:J1:J2:imm6:imm11:0
		val = fs->S + fs->A - fs->P;
		keephw1 = rz_read_ble16(&buf[0], big_endian);
		keephw2 = rz_read_ble16(&buf[2], big_endian);
		keephw1 = (keephw1 & 0xFBC0) |
			((val >> 10) & 0x0400) | // S
			((val >> 12) & 0x003F); // imm6
		keephw2 = (keephw2 & 0xD000) |
			(((val >> 19) & 1) << 13) | // J1
			(((val >> 18) & 1) << 11) | // J2
			((val >> 1) & 0x07FF); // imm11

		rz_write_ble16(&buf[0], keephw1, big_endian);
		rz_write_ble16(&buf[2], keephw2, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_THM_ALU_PREL_11_0:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		// val = i:imm3:imm8
		val = fs->S + fs->A - (fs->P & 0xFFFFFFFC); // S+A-Pa
		keephw1 = rz_read_ble16(&buf[0], big_endian);
		keephw2 = rz_read_ble16(&buf[2], big_endian);

		keephw1 = (keephw1 & 0xFBFF) |
			((val >> 1) & 0x0400); // i
		keephw2 = (keephw2 & 0x8F00) |
			((val << 4) & 0x7000) | // imm3
			(val & 0x00FF); // imm8

		rz_write_ble16(&buf[0], keephw1, big_endian);
		rz_write_ble16(&buf[2], keephw2, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_ABS16:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A;
		rz_write_ble16(buf, (val & 0xFFFF), big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_ABS12:
		val = fs->S + fs->A;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, val);
		break;

	case R_ARM_THM_ABS5:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = ((fs->S + fs->A) & 0x7C) >> 2;
		keephw1 = rz_read_ble16(buf, big_endian);
		keephw1 = (keephw1 & 0xF83F) |
			(val << 6);
		rz_write_ble16(buf, keephw1, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_ABS8:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A;
		rz_write_ble8(buf, (val & 0xFF));
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_SBREL32:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A - fs->B;
		rz_write_ble32(buf, (val & 0xFFFFFFF), big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_THM_PC8:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A - (fs->P & 0xFFFFFFFC);
		val = (val & 0x3FC) >> 2;
		keephw1 = rz_read_ble16(buf, big_endian);
		keephw1 = (keephw1 & 0xFF00) | val;
		rz_write_ble16(buf, keephw1, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_GOTOFF32:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A - fs->GOT;
		rz_write_ble32(buf, (val & 0xFFFFFFFF), big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_BASE_PREL:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		if (fs->S == 0) { // NUll symbol
			val = fs->GOT + fs->A;
		} else {
			val = fs->B + fs->A;
		}
		rz_write_ble32(buf, (val & 0xFFFFFFFF), big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_GOT_BREL:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->G + fs->A;
		rz_write_ble32(buf, (val & 0xFFFFFFFF), big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_BASE_ABS:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		rz_write_ble32(buf, (fs->A & 0xFFFFFFFF), big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_PREL31:
		val = (fs->S + fs->A - fs->P) >> 1;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0x7FFFFFFF, val);
		break;

	case R_ARM_MOVW_ABS_NC:
		// val = imm4:imm12
		val = (fs->S + fs->A) & 0xFFFF;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0x000F0FFF, val);
		break;

	case R_ARM_MOVT_ABS:
		/* fall through */
	case R_ARM_MOVT_PREL:
		// val = imm4:imm12
		val = (fs->S + fs->A) >> 16;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0x000F0FFF, val);
		break;

	case R_ARM_THM_MOVW_ABS_NC:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		// val = imm4:i:imm3:imm8
		val = (fs->S + fs->A) & 0xFFFF;
		keephw1 = rz_read_ble16(&buf[0], big_endian);
		keephw2 = rz_read_ble16(&buf[2], big_endian);

		keephw1 = (keephw1 & 0xFBF0) |
			((val >> 1) & 0x0400) | // i
			((val >> 12) & 0x000F); // imm4

		keephw2 = (keephw2 & 0x8F00) |
			((val << 4) & 0x7000) | // imm3
			(val & 0x00FF); // imm8

		rz_write_ble16(&buf[0], keephw1, big_endian);
		rz_write_ble16(&buf[2], keephw2, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_THM_MOVT_ABS:
		/* fall through */
	case R_ARM_THM_MOVT_PREL:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		// val = imm4:i:imm3:imm8
		val = (fs->S + fs->A) >> 16;
		keephw1 = rz_read_ble16(&buf[0], big_endian);
		keephw2 = rz_read_ble16(&buf[2], big_endian);

		keephw1 = (keephw1 & 0xFBF0) |
			((val >> 1) & 0x0400) | // i
			((val >> 12) & 0x000F); // imm4

		keephw2 = (keephw2 & 0x8F00) |
			((val << 4) & 0x7000) | // imm3
			(val & 0x00FF); // imm8

		rz_write_ble16(&buf[0], keephw1, big_endian);
		rz_write_ble16(&buf[2], keephw2, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_THM_JUMP6:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		// val = i:imm5
		val = ((fs->S + fs->A) & 0x7E) >> 1;
		keephw1 = rz_read_ble16(buf, big_endian);
		keephw1 = (keephw1 & 0xFD07) |
			((val << 4) & 0x0200) | // i
			((val << 3) & 0x00F8); // imm5
		rz_write_ble16(buf, keephw1, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_THM_PC12:
		// val = imm12
		val = (fs->S + fs->A) & 0xFFF;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, val);
		break;

	case R_ARM_ABS32_NOI:
		/* fall through */
	case R_ARM_REL32_NOI:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A;
		rz_write_ble32(buf, (val & 0xFFFFFFFF), big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_MOVW_BREL:
		/* fall through */
	case R_ARM_MOVW_BREL_NC:
		// val = imm4:imm12
		val = (fs->S + fs->A - fs->B) & 0xFFFF;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0x000F0FFF, val);
		break;

	case R_ARM_MOVT_BREL:
		val = (fs->S + fs->A) >> 16;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0x000F0FFF, val);
		break;

	case R_ARM_THM_MOVW_BREL:
		/* fall through */
	case R_ARM_THM_MOVW_BREL_NC:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		// val = imm4:i:imm3:imm8
		val = (fs->S + fs->A - fs->B) & 0xFFFF;
		keephw1 = rz_read_ble16(&buf[0], big_endian);
		keephw2 = rz_read_ble16(&buf[2], big_endian);

		keephw1 = (keephw1 & 0xFBF0) |
			((val >> 1) & 0x0400) | // i
			((val >> 12) & 0x000F); // imm4

		keephw2 = (keephw2 & 0x8F00) |
			((val << 4) & 0x7000) | // imm3
			(val & 0x00FF); // imm8

		rz_write_ble16(&buf[0], keephw1, big_endian);
		rz_write_ble16(&buf[2], keephw2, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_THM_MOVT_BREL:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		// val = imm4:i:imm3:imm8
		val = (fs->S + fs->A) >> 16;
		keephw1 = rz_read_ble16(&buf[0], big_endian);
		keephw2 = rz_read_ble16(&buf[2], big_endian);

		keephw1 = (keephw1 & 0xFBF0) |
			((val >> 1) & 0x0400) | // i
			((val >> 12) & 0x000F); // imm4

		keephw2 = (keephw2 & 0x8F00) |
			((val << 4) & 0x7000) | // imm3
			(val & 0x00FF); // imm8

		rz_write_ble16(&buf[0], keephw1, big_endian);
		rz_write_ble16(&buf[2], keephw2, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_GOT_PREL:
		/* fall through */
	case R_ARM_GOT_ABS:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->G + fs->GOT + fs->A;
		rz_write_ble32(buf, (val & 0xFFFFFFFF), big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_THM_GOT_BREL12:
		/* fall through */
	case R_ARM_TLS_IE12GP:
		/* fall through */
	case R_ARM_GOT_BREL12:
		// val = imm12
		val = (fs->G + fs->A) & 0xFFF; // G(S) + A - GOT_ORG
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, val);
		break;

	case R_ARM_GOTOFF12:
		// val = imm12
		val = (fs->S + fs->A) & 0xFFF;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, val);
		break;

	case R_ARM_THM_JUMP11:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		// val = imm11
		val = ((fs->S + fs->A) & 0xFFE) >> 1;
		keephw1 = rz_read_ble16(buf, big_endian);
		keephw1 = (keephw1 & 0xF800) | val;
		rz_write_ble16(buf, keephw1, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_THM_JUMP8:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		// val - imm8
		val = ((fs->S + fs->A) & 0x1FE) >> 1;
		keephw1 = rz_read_ble16(buf, big_endian);
		keephw1 = (keephw1 & 0xFF00) | val;
		rz_write_ble16(buf, keephw1, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_TLS_GD32:
		/* fall through */
	case R_ARM_TLS_LDM32:
		/* fall through */
	case R_ARM_TLS_IE32:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->G + fs->GOT + fs->A;
		rz_write_ble32(buf, (val & 0xFFFFFFFF), big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;

	case R_ARM_ALU_PC_G0:
		/* fall through */
	case R_ARM_ALU_PC_G0_NC:
		val = fs->S + fs->A - fs->P;
		offset = convert_alu_group_mask(val, 0);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, offset);
		break;

	case R_ARM_ALU_PC_G1:
		/* fall through */
	case R_ARM_ALU_PC_G1_NC:
		val = fs->S + fs->A - fs->P;
		offset = convert_alu_group_mask(val, 1);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, offset);
		break;

	case R_ARM_ALU_PC_G2:
		val = fs->S + fs->A - fs->P;
		offset = convert_alu_group_mask(val, 2);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, offset);
		break;

	case R_ARM_LDR_SB_G0:
		/* fall through */
	case R_ARM_LDR_PC_G0:
		val = fs->S + fs->A;
		offset = convert_group_mask(val, 0);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, offset);
		break;

	case R_ARM_LDR_SB_G1:
		/* fall through */
	case R_ARM_LDR_PC_G1:
		val = fs->S + fs->A;
		offset = convert_group_mask(val, 1);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, offset);
		break;

	case R_ARM_LDR_SB_G2:
		/* fall through */
	case R_ARM_LDR_PC_G2:
		val = fs->S + fs->A;
		offset = convert_group_mask(val, 2);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, offset);
		break;

	case R_ARM_LDRS_SB_G0:
		/* fall through */
	case R_ARM_LDRS_PC_G0:
		val = fs->S + fs->A;
		offset = convert_group_mask(val, 0);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0x0F0F, offset);
		break;

	case R_ARM_LDRS_SB_G1:
		/* fall through */
	case R_ARM_LDRS_PC_G1:
		val = fs->S + fs->A;
		offset = convert_group_mask(val, 1);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0x0F0F, offset);
		break;

	case R_ARM_LDRS_SB_G2:
		/* fall through */
	case R_ARM_LDRS_PC_G2:
		val = fs->S + fs->A;
		offset = convert_group_mask(val, 2);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0x0F0F, offset);
		break;

	case R_ARM_LDC_SB_G0:
		/* fall through */
	case R_ARM_LDC_PC_G0:
		val = fs->S + fs->A;
		offset = convert_group_mask(val, 0);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFF, offset);
		break;

	case R_ARM_LDC_SB_G1:
		/* fall through */
	case R_ARM_LDC_PC_G1:
		val = fs->S + fs->A;
		offset = convert_group_mask(val, 1);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFF, offset);
		break;

	case R_ARM_LDC_SB_G2:
		/* fall through */
	case R_ARM_LDC_PC_G2:
		val = fs->S + fs->A;
		offset = convert_group_mask(val, 2);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFF, offset);
		break;

	case R_ARM_ALU_SB_G0:
		/* fall through */
	case R_ARM_ALU_SB_G0_NC:
		val = fs->S + fs->A - fs->B;
		offset = convert_alu_group_mask(val, 0);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, offset);
		break;

	case R_ARM_ALU_SB_G1:
		/* fall through */
	case R_ARM_ALU_SB_G1_NC:
		val = fs->S + fs->A - fs->B;
		offset = convert_alu_group_mask(val, 1);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, offset);
		break;

	case R_ARM_ALU_SB_G2:
		val = fs->S + fs->A - fs->B;
		offset = convert_alu_group_mask(val, 2);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, 0xFFF, offset);
		break;

	/*
		The following relocations are for Branch Future instructions in Armv8.1-M Mainline.
		Check the docs: https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#56114armv81-m-mainline-branch-future-relocations
	 */
	case R_ARM_THM_BF16:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = (fs->S + fs->A - fs->P) & 0x0001FFFE;
		keephw1 = rz_read_ble16(buf, big_endian);
		keephw2 = rz_read_ble16(buf + 2, big_endian);
		// insn[10:1] = (val >> 2) & 0x3FF
		// insn[11] = (val >> 1) & 0x1
		// insn[20:16] = val >> 12
		keephw1 = (keephw1 & 0xF800) | ((val >> 2) & 0x3FF) | (((val >> 1) & 0x1) << 11);
		keephw2 = (keephw2 & 0xFFE0) | ((val >> 12) & 0x1F);

		rz_write_ble16(buf, keephw1, big_endian);
		rz_write_ble16(buf + 2, keephw2, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;

	case R_ARM_THM_BF12:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A - fs->P;
		val = val & 0x00001FFE;
		keephw1 = rz_read_ble16(buf, big_endian);
		keephw2 = rz_read_ble16(buf + 2, big_endian);
		// insn[10:1] = (val >> 2) & 0x3FF
		// insn[11] = (val >> 1) & 0x1
		// insn[16] = val >> 12
		keephw1 = (keephw1 & 0xF800) | ((val >> 2) & 0x3FF) | (((val >> 1) & 0x1) << 11);
		keephw2 = (keephw2 & 0xFFFE) | ((val >> 12) & 0x1);

		rz_write_ble16(buf, keephw1, big_endian);
		rz_write_ble16(buf + 2, keephw2, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;

	case R_ARM_THM_BF18:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A - fs->P;
		val = val & 0x0007FFFE;
		keephw1 = rz_read_ble16(buf, big_endian);
		keephw2 = rz_read_ble16(buf + 2, big_endian);
		// insn[10:1] = (val >> 2) & 0x3FF
		// insn[11] = (val >> 1) & 0x1
		// insn[22:16] = val >> 12
		keephw1 = (keephw1 & 0xF800) | ((val >> 2) & 0x3FF) | (((val >> 1) & 0x1) << 11);
		keephw2 = (keephw2 & 0xFF80) | ((val >> 12) & 0x7F);

		rz_write_ble16(buf, keephw1, big_endian);
		rz_write_ble16(buf + 2, keephw2, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;

	default:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A;
		if (!rel->sym && rel->mode == DT_REL) {
			val += rz_read_ble32(buf, big_endian);
		}
		rz_write_ble32(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel The relocation elf structure.
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_arm64(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const RzBinElfReloc *rel, const RelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && rel && fs);
// AARCH64-specific defines
// Take the PAGE component of an address or offset.
#define PG(x)         ((x) & ~0xFFFULL)
#define PG_OFFSET(x)  ((x) & 0xFFFULL)
#define ADR_IMM_MASK1 (((1U << 2) - 1) << 29)
#define ADR_IMM_MASK2 (((1U << 19) - 1) << 5)
#define ADR_IMM_MASK3 (((1U << 19) - 1) << 2)

	ut32 keep = 0;
	ut32 nbytes = 4;
	ut8 buf[8] = { 0 };
	ut64 val = 0;
	rz_buf_read_at(buf_patched, patch_addr, buf, 8);
	switch (rel->type) {
	case R_AARCH64_NONE:
		return;
	case R_AARCH64_ABS16:
		val = fs->S + fs->A;
		rz_write_le16(buf, val);
		nbytes = 2;
		break;
	case R_AARCH64_ABS32:
		val = fs->S + fs->A;
		rz_write_le32(buf, val);
		break;
	case R_AARCH64_GLOB_DAT:
	/* fall-thru */
	case R_AARCH64_ABS64:
	/* fall-thru */
	case R_AARCH64_JUMP_SLOT:
		val = fs->S + fs->A;
		rz_write_le64(buf, val);
		nbytes = 8;
		break;
	case R_AARCH64_PREL16:
		val = fs->S + fs->A - fs->P;
		rz_write_le16(buf, val);
		nbytes = 2;
		break;
	case R_AARCH64_PREL32:
		val = fs->S + fs->A - fs->P;
		rz_write_le32(buf, val);
		break;
	case R_AARCH64_PREL64:
		val = fs->S + fs->A - fs->P;
		rz_write_le64(buf, val);
		nbytes = 8;
		break;
	case R_AARCH64_RELATIVE:
		val = fs->B + fs->A;
		rz_write_le64(buf, val);
		nbytes = 8;
		break;
	case R_AARCH64_ADR_PREL_PG_HI21:
	/* fall-thru */
	case R_AARCH64_ADR_PREL_PG_HI21_NC:
	/* fall-thru */
	case R_AARCH64_ADR_GOT_PAGE:
		// Reencode ADR imm
		keep = rz_read_le32(buf) & ~(ADR_IMM_MASK1 | ADR_IMM_MASK2);
		val = ((st64)(PG(fs->S + fs->A) - PG(fs->P))) >> 12;
		rz_write_le32(buf, keep | ((val & RZ_BIT_MASK32(2, 0)) << 29) | ((val & ADR_IMM_MASK3) << 3));
		break;
	case R_AARCH64_JUMP26:
	/* fall-thru */
	case R_AARCH64_CALL26:
		// Reencode 26 bits of the offset
		keep = rz_read_le32(buf) & ~RZ_BIT_MASK32(26, 0);
		val = ((st64)(fs->S + fs->A - fs->P)) >> 2;
		rz_write_le32(buf, keep | (val & RZ_BIT_MASK32(26, 0)));
		break;
	case R_AARCH64_LDST8_ABS_LO12_NC:
	/* fall-thru */
	case R_AARCH64_ADD_ABS_LO12_NC:
		keep = rz_read_le32(buf) & ~(RZ_BIT_MASK32(12, 0) << 10);
		val = PG_OFFSET(fs->S + fs->A);
		rz_write_le32(buf, keep | ((val & RZ_BIT_MASK32(12, 0)) << 10));
		break;
	case R_AARCH64_LD64_GOT_LO12_NC:
	/* fall-thru */
	case R_AARCH64_LDST64_ABS_LO12_NC:
		// Reencode LD/ST imm
		keep = rz_read_le32(buf) & ~(RZ_BIT_MASK32(12, 0) << 10);
		val = PG_OFFSET(fs->S + fs->A) >> 3;
		rz_write_le32(buf, keep | ((val & RZ_BIT_MASK32(12, 0)) << 10));
		break;
	case R_AARCH64_TLSDESC:
		// R_AARCH64_TLSDESC is a relocation type handled by the
		// dynamic linker. We intentionally do not handle do anything.
		break;
	default:
		UNHANDL_DEF("AArch64", rel->type);
		return;
	}
	rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);

#undef PG
#undef PG_OFFSET
#undef ADR_IMM_MASK1
#undef ADR_IMM_MASK2
#undef ADR_IMM_MASK3
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param big_endian The endianness - true if BE, false if LE
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_ppc64(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, const RelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[8] = { 0 };
	ut64 val = 0;
	ut32 low = 0, word = 0;
	switch (rel_type) {
	case R_PPC64_NONE:
		return;
	case R_PPC64_ADDR24:
		low = 24;
		val = (fs->S + fs->A) >> 2;
		break;
	case R_PPC64_ADDR16_HI:
		word = 2;
		val = (fs->S + fs->A) >> 16;
		break;
	case R_PPC64_ADDR16_HA:
		word = 2;
		val = (fs->S + fs->A + 0x8000) >> 16;
		break;
	case R_PPC64_REL16_HA:
		word = 2;
		val = (fs->S + fs->A - fs->P + 0x8000) >> 16;
		break;
	case R_PPC64_ADDR16_LO:
		word = 2;
		val = (fs->S + fs->A) & 0xffff;
		break;
	case R_PPC64_REL16_LO:
		word = 2;
		val = (fs->S + fs->A - fs->P) & 0xffff;
		break;
	case R_PPC64_REL14:
		low = 14;
		val = (st64)(fs->S + fs->A - fs->P) >> 2;
		break;
	case R_PPC64_REL24:
		low = 24;
		val = (st64)(fs->S + fs->A - fs->P) >> 2;
		break;
	case R_PPC64_REL32:
		word = 4;
		val = fs->S + fs->A - fs->P;
		break;
	default:
		UNHANDL_DEF("PowerPC 64", rel_type);
		return;
	}
	if (low) {
		switch (low) {
		case 14:
			val &= (1 << 14) - 1;
			rz_buf_read_at(buf_patched, patch_addr, buf, 2);
			rz_write_ble32(buf, (rz_read_ble32(buf, big_endian) & ~(RZ_BIT_MASK32(16, 2))) | val << 2, big_endian);
			rz_buf_write_at(buf_patched, patch_addr, buf, 2);
			break;
		case 24:
			val &= (1 << 24) - 1;
			rz_buf_read_at(buf_patched, patch_addr, buf, 4);
			rz_write_ble32(buf, (rz_read_ble32(buf, big_endian) & ~(RZ_BIT_MASK32(26, 2))) | val << 2, big_endian);
			rz_buf_write_at(buf_patched, patch_addr, buf, 4);
			break;
		default:
			RZ_LOG_WARN("PowerPC 64: Unhandled patching case for relocation %d with low %u bits.\n", rel_type, low);
			return;
		}
	} else if (word) {
		switch (word) {
		case 2:
			rz_write_ble16(buf, val, big_endian);
			rz_buf_write_at(buf_patched, patch_addr, buf, 2);
			break;
		case 4:
			rz_write_ble32(buf, val, big_endian);
			rz_buf_write_at(buf_patched, patch_addr, buf, 4);
			break;
		default:
			RZ_LOG_WARN("PowerPC 64: Unhandled patching case for relocation %d with word size %u.\n", rel_type, word);
			return;
		}
	} else {
		UNHANDL_DEF("PowerPC 64", rel_type);
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_x86_32(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, const RelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[4] = { 0 };
	ut64 val = 0;
	switch (rel_type) {
	case R_386_NONE:
		return;
	case R_386_32:
		/* fall-thru */
	case R_386_PC32:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = rz_read_le32(buf) + fs->S + fs->A;
		if (rel_type == R_386_PC32) {
			val -= fs->P;
		}
		rz_write_le32(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;
	case R_386_GOT32:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->G + fs->A - fs->GOT;
		rz_write_le32(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;
	case R_386_PLT32:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->L + fs->A - fs->P;
		rz_write_le32(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;
	case R_386_GLOB_DAT:
	/* fall through */
	case R_386_JMP_SLOT:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S;
		rz_write_le32(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;
	case R_386_RELATIVE:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->B + fs->A;
		rz_write_le32(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;
	case R_386_GOTOFF:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->S + fs->A - fs->GOT;
		rz_write_le32(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;
	case R_386_GOTPC:
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = fs->GOT + fs->A - fs->P;
		rz_write_le32(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;

	case R_386_16:
	/* fall through */
	case R_386_PC16:
		val = fs->S + fs->A;
		rz_buf_read_at(buf_patched, patch_addr, buf, 2);
		if (rel_type == R_386_PC16) {
			val -= fs->P;
		}
		rz_write_le16(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 2);
		break;
	case R_386_8:
	/* fall through */
	case R_386_PC8:
		val = fs->S + fs->A;
		rz_buf_read_at(buf_patched, patch_addr, buf, 1);
		if (rel_type == R_386_PC16) {
			val -= fs->P;
		}
		rz_write_le8(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 1);
		break;
	default:
		UNHANDL_DEF("x86_32", rel_type);
		return;
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_x86_64(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, const RelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[8] = { 0 };
	ut64 val = 0;
	int word = 0;
	switch (rel_type) {
	case R_X86_64_NONE:
		/* fall-thru */
	case R_X86_64_COPY:
		return;
	case R_X86_64_8:
		word = 1;
		val = fs->S + fs->A;
		break;
	case R_X86_64_16:
		word = 2;
		val = fs->S + fs->A;
		break;
	case R_X86_64_32:
		/* fall-thru */
	case R_X86_64_32S:
		word = 4;
		val = fs->S + fs->A;
		break;
	case R_X86_64_64:
		word = 8;
		val = fs->S + fs->A;
		break;
	case R_X86_64_GLOB_DAT:
		/* fall-thru */
	case R_X86_64_JUMP_SLOT:
		word = 4;
		val = fs->S;
		break;
	case R_X86_64_PC8:
		word = 1;
		val = fs->S + fs->A - fs->P;
		break;
	case R_X86_64_PC16:
		word = 2;
		val = fs->S + fs->A - fs->P;
		break;
	case R_X86_64_PC32:
		word = 4;
		val = fs->S + fs->A - fs->P;
		break;
	case R_X86_64_PC64:
		word = 8;
		val = fs->S + fs->A - fs->P;
		break;
	case R_X86_64_PLT32:
		word = 4;
		val = fs->L + fs->A - fs->P;
		break;
	case R_X86_64_RELATIVE64:
		/* fall-thru */
	case R_X86_64_RELATIVE:
		word = 8;
		val = fs->B + fs->A;
		break;
	case R_X86_64_GOT32:
		word = 4;
		val = fs->G + fs->A;
		break;
	case R_X86_64_GOTPCREL64:
		/* fall thru */
	case R_X86_64_GOTPCREL:
		/* fall thru */
	case R_X86_64_GOTPCRELX:
		/* fall thru */
	case R_X86_64_REX_GOTPCRELX:
		/* fall thru */
	case R_X86_64_CODE_4_GOTPCRELX:
		/* fall thru */
	case R_X86_64_CODE_5_GOTPCRELX:
		/* fall thru */
	case R_X86_64_CODE_6_GOTPCRELX:
		word = 4;
		val = fs->G + fs->GOT + fs->A - fs->P;
		break;
	case R_X86_64_GOTOFF64:
		word = 8;
		val = fs->S + fs->A - fs->GOT;
		break;
	case R_X86_64_GOTPC32:
		word = 4;
		val = fs->GOT + fs->A - fs->P;
		break;
	case R_X86_64_GOT64:
		word = 8;
		val = fs->G + fs->A;
		break;
	case R_X86_64_GOTPC64:
		word = 8;
		val = fs->GOT - fs->P + fs->A;
		break;
	case R_X86_64_PLTOFF64:
		word = 8;
		val = fs->L - fs->GOT + fs->A;
		break;
	default:
		UNHANDL_DEF("x86_64", rel_type);
		return;
	}
	switch (word) {
	default:
		break;
	case 1:
		buf[0] = val;
		rz_buf_write_at(buf_patched, patch_addr, buf, 1);
		break;
	case 2:
		rz_write_le16(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 2);
		break;
	case 4:
		rz_write_le32(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;
	case 8:
		rz_write_le64(buf, val);
		rz_buf_write_at(buf_patched, patch_addr, buf, 8);
		break;
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param big_endian The endianness - true if BE, false if LE
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_rx(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, const RelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[4] = { 0 };
	ut64 val = 0;
	// no dynamic for rx-elf program, handle rx elf object reloc type (emulate linkage map)
	// and no GOT/PLT for existed for rx-elf, leave no imports info for extern symbol
	switch (rel_type) {
	// simply use rizin default symbol resolution to map OBJECT variable symbol to vaddr
	case R_RX_NONE:
		return;
	case R_RX_DIR32:
		val = fs->S + fs->A;
		rz_buf_write_ble32_at(buf_patched, patch_addr, val, big_endian);
		break;
	case R_RX_DIR24S_PCREL:
		val = fs->S + fs->A - fs->P + 1;
		if (big_endian) {
			buf[2] = val;
			buf[1] = val >> 8;
			buf[0] = val >> 16;
		} else {
			buf[0] = val;
			buf[1] = val >> 8;
			buf[2] = val >> 16;
		}
		// write 3 Bytes
		rz_buf_write_at(buf_patched, patch_addr, buf, 3);
		break;
	default:
		UNHANDL_DEF("Renesas RX", rel_type);
		return;
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param big_endian The endianness - true if BE, false if LE
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_alpha(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, const RelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[4] = { 0 };
	ut64 val = 0;

	switch (rel_type) {
	case R_ALPHA_NONE:
		return;
	case R_ALPHA_REFLONG:
		val = fs->S + fs->A;
		rz_buf_write_ble32_at(buf_patched, patch_addr, val, big_endian);
		break;
	case R_ALPHA_REFQUAD:
		val = fs->S + fs->A;
		rz_buf_write_ble64_at(buf_patched, patch_addr, val, big_endian);
		break;
	case R_ALPHA_SREL16:
		val = fs->S + fs->A - fs->P + 1;
		if (big_endian) {
			buf[1] = val;
			buf[0] = val >> 8;
		} else {
			buf[0] = val;
			buf[1] = val >> 8;
		}
		rz_buf_write_at(buf_patched, patch_addr, buf, 2);
		break;
	case R_ALPHA_SREL32:
		val = fs->S + fs->A - fs->P + 1;
		if (big_endian) {
			buf[3] = val;
			buf[2] = val >> 8;
			buf[1] = val >> 16;
			buf[0] = val >> 24;
		} else {
			buf[0] = val;
			buf[1] = val >> 8;
			buf[2] = val >> 16;
			buf[3] = val >> 24;
		}
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		break;
	default:
		UNHANDL_DEF("Alpha", rel_type);
		return;
	}
}

/**
 * \brief Patches the opcode at a given address depending on the relocation type.
 *
 * NOTE: Some relocation symbols are not yet implemented
 *
 * \param buf_patched Buffer from which the opcode is read and the patched opcode is written to.
 * \param patch_addr The address of the opcode being patched.
 * \param rel_type The relocation type.
 * \param big_endian The endianness - true if BE, false if LE
 * \param fs Formular values to calculate the new relocation value.
 */
static void patch_reloc_parisc(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, RelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);
	ut8 buf[8] = { 0 };
	ut64 val = 0;

	switch (rel_type) {
	default:
		UNHANDL_DEF("PARISC", rel_type);
		return;
	case R_PARISC_COPY:
		/* fall-thru */
	case R_PARISC_NONE:
		return;
	case R_PARISC_DIR32: // S + A
		rz_buf_read_at(buf_patched, patch_addr, buf, 4);
		val = rz_read_ble32(buf, big_endian);
		val += fs->S + fs->A;
		rz_write_ble32(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 4);
		return;
	case R_PARISC_DIR64: // S + A
		rz_buf_read_at(buf_patched, patch_addr, buf, 8);
		val = rz_read_ble64(buf, big_endian);
		val += fs->S + fs->A;
		rz_write_ble64(buf, val, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, 8);
		return;
	}
}

static void patch_reloc_avr(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, const RelocFormularSymbols *fs) {
	rz_return_if_fail(buf_patched && fs);

	ut8 buf[2] = { 0 };
	st64 offset = 0;
	ut16 opcode = 0;
	ut32 nbytes = 2;

	ut64 val = fs->S + fs->A;

	switch (rel_type) {
	case R_AVR_NONE:
		return;
	case R_AVR_32:
		rz_buf_write_ble32_at(buf_patched, patch_addr, val, big_endian);
		break;
	case R_AVR_7_PCREL:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = (val - fs->P - 2) / 2;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0x3F8, offset);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_13_PCREL:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = (val - fs->P - 2) / 2;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xFFF, offset);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_16:
		rz_buf_write_ble16_at(buf_patched, patch_addr, val, big_endian);
		break;
	case R_AVR_16_PM:
		rz_buf_write_ble16_at(buf_patched, patch_addr, val / 2, big_endian);
		break;
	case R_AVR_LO8_LDI:
	/* fall through */
	case R_AVR_LDI:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = val & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_HI8_LDI:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = (val >> 8) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_HH8_LDI:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = (val >> 16) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_LO8_LDI_NEG:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = (-val) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_HI8_LDI_NEG:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = ((-val) >> 8) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_HH8_LDI_NEG:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = ((-val) >> 16) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_LO8_LDI_PM:
		/* fall through */
	case R_AVR_LO8_LDI_GS:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = val & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset / 2);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_HI8_LDI_PM:
		/* fall through */
	case R_AVR_HI8_LDI_GS:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = (val >> 8) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset / 2);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_HH8_LDI_PM:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = (val >> 16) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset / 2);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_LO8_LDI_PM_NEG:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = (-val) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset / 2);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_HI8_LDI_PM_NEG:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = ((-val) >> 8) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset / 2);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_HH8_LDI_PM_NEG:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = ((-val) >> 16) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset / 2);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_CALL:
		nbytes = 4;
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		val = val / 2;
		break;
	case R_AVR_6:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0x2C07, val);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_6_ADIW:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xCF, val);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_MS8_LDI:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = (val >> 24) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_MS8_LDI_NEG:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = ((-val) >> 24) & 0xFF;
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF0F, offset);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_8:
		/* fall through */
	case R_AVR_8_LO8:
		offset = val & 0xFF;
		rz_buf_write_ble32_at(buf_patched, patch_addr, offset, big_endian);
		break;
	case R_AVR_8_HI8:
		offset = (val >> 8) & 0xFF;
		rz_buf_write_ble32_at(buf_patched, patch_addr, offset, big_endian);
		break;
	case R_AVR_8_HLO8:
		offset = (val >> 16) & 0xFF;
		rz_buf_write_ble32_at(buf_patched, patch_addr, offset, big_endian);
		break;
	case R_AVR_DIFF8:
		/* fall through */
	case R_AVR_DIFF16:
		/* fall through */
	case R_AVR_DIFF32:
		/* Value already written by assembler */
		break;
	case R_AVR_LDS_STS_16:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		offset = (val - 0x40) & 0x7F;
		offset = (val & 0x0f) | ((val & 0x30) << 5) | ((val & 0x40) << 2);
		opcode = rz_read_ble16(buf, big_endian) | offset;
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_PORT6:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0x60F, val);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_PORT5:
		rz_buf_read_at(buf_patched, patch_addr, buf, nbytes);
		opcode = rz_read_ble16(buf, big_endian) | rz_bits_spread(0xF8, val);
		rz_write_ble16(buf, opcode, big_endian);
		rz_buf_write_at(buf_patched, patch_addr, buf, nbytes);
		break;
	case R_AVR_32_PCREL:
		rz_buf_write_ble32_at(buf_patched, patch_addr, val - fs->P, big_endian);
		break;
	default:
		UNHANDL_DEF("AVR", rel_type);
		break;
	}
}
// U-Type: 32-bit instructions that store a 20-bit immediate in their upper 20 bit
static const ut32 RISCV_U_TYPE_IMM_MASK = ((1ULL << 20) - 1) << 12;
// I-Type: 32-bit instructions that store a 12-bit immediate in their upper 12 bit
static const ut32 RISCV_I_TYPE_IMM_MASK = ((1ULL << 12) - 1) << 20;
// S-Type: 32-bit instructions that store a 12-bit immediate scattered over 2 places but still in relative order
static const ut32 RISCV_S_TYPE_IMM_MASK = ((0x7F << 25) | (0x1F << 7));
// B-TYPE: 32-bit instructions that store an 11-bit immediate scattered all over and out of order
static const ut32 RISCV_B_TYPE_IMM_MASKS[] = {
	1ULL << 31, // bit 31: imm[12]
	0x3fULL << 25, // bits 30-25: imm[10:5]
	0xfULL << 8, // bits 11-8: imm[4:1]
	1ULL << 7 // bit 7: imm[11]
};
// J-TYPE: 32-bit instructions (JAL) that store a 20-bit immediate scattered all over and out of order
static const ut32 RISCV_J_TYPE_IMM_MASKS[] = {
	1ULL << 31, // bit 31: imm[20]
	0x3ffULL << 21, // bits 30-21: imm[10:1]
	1ULL << 20, // bit 20: imm[11]
	0xffULL << 12 // bits 19-12: imm[19:12]
};
// CB-Type: 16-bit instructions that store an 8-bit immediate scattered all over and out of order
// the immediate is effectively 9 bit with bit 0 implied and always zero
static const ut16 RISCV_CB_TYPE_IMM_MASKS[] = {
	(1 << 12), // bit 12: imm[8]
	(3 << 10), // bits 11-10: imm[4:3]
	(3 << 5), // bits 6-5: imm[7:6]
	(3 << 3), // bits 4-3: imm[2:1]
	(1 << 2) // bit 2: imm[5]
};
// CJ-Type: 16-bit instructions that store an 11-bit immediate scattered all over and out of order
// the immediate is effectively 12 bit with bit 0 implied and always zero
static const ut16 RISCV_CJ_TYPE_IMM_MASKS[] = {
	(1 << 12), // bit 12: imm[11]
	(1 << 11), // bit 11: imm[4]
	(3 << 9), // bits 10:9: imm[9:8]
	(1 << 8), // bit 8: imm[10]
	(1 << 7), // bit 7: imm[6]
	(1 << 6), // bit 6: imm[7]
	(7 << 3), // bits 5:3: imm[3:1]
	(1 << 2) // bit 2: imm[5]
};
// CI-type: 16-bit instructions that store a 6-bit immediate with the 6th bit scattered from the rest but still in relative order
static const ut16 RISCV_CI_TYPE_IMM_MASK = (1 << 12) | (0x1f << 2);

#define RISCV_HI20(i) ((i) + 0x800) >> 12
#define RISCV_LO12(i) ((i) & 0xfff)
#define RISCV_CHECK_NARROWING_32(i, w) \
	if (w == 32) { \
		i = ((ut32)i); \
	}

static void patch_reloc_riscv(RZ_INOUT RzBuffer *buf_patched, const ut64 patch_addr, const int rel_type, bool big_endian, const RelocFormularSymbols *fs, const int bits) {
	rz_return_if_fail(buf_patched && fs);

	ut64 val = 0;
	// narrow address values for 32-bit binaries
	ut64 S = (bits == 32) ? ((ut32)fs->S) : fs->S;
	ut64 A = (bits == 32) ? ((ut32)fs->A) : fs->A;
	ut64 B = (bits == 32) ? ((ut32)fs->B) : fs->B;
	ut64 P = (bits == 32) ? ((ut32)fs->P) : fs->P;

	switch (rel_type) {
	case R_RISCV_NONE:
		return;

	case R_RISCV_32:
		val = S + A;
		rz_buf_write_ble32_at(buf_patched, patch_addr, val, big_endian);
		break;

	case R_RISCV_64:
		val = S + A;
		rz_buf_write_ble64_at(buf_patched, patch_addr, val, big_endian);
		break;

	case R_RISCV_RELATIVE:
		val = A + B;
		switch (bits) {
		case 32:
			rz_buf_write_ble32_at(buf_patched, patch_addr, val, big_endian);
			break;
		case 64:
			rz_buf_write_ble64_at(buf_patched, patch_addr, val, big_endian);
			break;
		default:
			RZ_LOG_WARN("Unsupported number of bits for R_RISCV_RELATIVE: %d, only 32 bits and 64 bits are supported", bits);
			return;
		}
		break;

	case R_RISCV_BRANCH: {
		val = S + A - P;
		ut64 imm12 = ((val >> 12) & 0x1); // inst[31] = imm[12]
		ut64 imm10_5 = ((val >> 5) & 0x3f); // inst[30:25] = imm[10:5]
		ut64 imm4_1 = ((val >> 1) & 0xf); // inst[11:8] = imm[4:1]
		ut64 imm11 = ((val >> 11) & 0x1); // inst[7] = imm[11]
		ut64 imms[4] = { imm12, imm10_5, imm4_1, imm11 };
		for (int i = 0; i < sizeof(RISCV_B_TYPE_IMM_MASKS) / sizeof(RISCV_B_TYPE_IMM_MASKS[0]); i++) {
			patch_val_over_mask_32(buf_patched, big_endian, patch_addr, RISCV_B_TYPE_IMM_MASKS[i], imms[i]);
		}
		break;
	}

	case R_RISCV_JAL: {
		val = S + A - P;
		RISCV_CHECK_NARROWING_32(val, bits);
		ut64 imm20 = ((val >> 20) & 0x1); // inst[31] = imm[20]
		ut64 imm10_1 = ((val >> 1) & 0x3ff); // inst[30:21] = imm[10:1]
		ut64 imm11 = ((val >> 11) & 0x1); // inst[20] = imm[11]
		ut64 imm19_12 = ((val >> 12) & 0xff); // inst[19:12] = imm[19:12]
		ut64 imms[4] = { imm20, imm10_1, imm11, imm19_12 };
		for (int i = 0; i < sizeof(RISCV_J_TYPE_IMM_MASKS) / sizeof(RISCV_J_TYPE_IMM_MASKS[0]); i++) {
			patch_val_over_mask_32(buf_patched, big_endian, patch_addr, RISCV_J_TYPE_IMM_MASKS[i], imms[i]);
		}
		break;
	}

	// both handled by the same formula
	// TODO: CALL_PLT is more complex if the symbol is outside the same object file
	case R_RISCV_CALL:
	case R_RISCV_CALL_PLT: {
		ut64 result = S + A - P;

		ut32 hi20 = RISCV_HI20(result);
		ut32 lo12 = RISCV_LO12(result);

		// the AUIPC part of the call sequence takes the upper 20 bits of the address
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, RISCV_U_TYPE_IMM_MASK, hi20);
		// the JALR part of the call sequence takes the lower 12 bits of the address;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr + 4, RISCV_I_TYPE_IMM_MASK, lo12);
		break;
	}

	case R_RISCV_JUMP_SLOT:
		switch (bits) {
		case 32:
			rz_buf_write_ble32_at(buf_patched, patch_addr, S, big_endian);
			break;
		case 64:
			rz_buf_write_ble64_at(buf_patched, patch_addr, S, big_endian);
			break;
		default:
			RZ_LOG_WARN("Unsupported number of bits for R_RISCV_JUMP_SLOT: %d, only 32 bits and 64 bits are supported", bits);
			break;
		}
		break;

	case R_RISCV_32_PCREL:
		val = S + A - P;
		rz_buf_write_ble32_at(buf_patched, patch_addr, val, big_endian);
		break;

	case R_RISCV_GOT_HI20: {
		val = fs->G + fs->GOT + A - P;
		ut32 hi20 = RISCV_HI20(val);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, RISCV_U_TYPE_IMM_MASK, hi20);
		break;
	}
	case R_RISCV_PCREL_HI20: {
		val = S + A - P;
		ut32 hi20 = RISCV_HI20(val);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, RISCV_U_TYPE_IMM_MASK, hi20);
		break;
	}

	case R_RISCV_PCREL_LO12_I:
	case R_RISCV_PCREL_LO12_S: {
		val = S + A - P;
		ut32 lo12 = RISCV_LO12(val);
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, (rel_type == R_RISCV_PCREL_LO12_I) ? RISCV_I_TYPE_IMM_MASK : RISCV_S_TYPE_IMM_MASK, lo12);
		break;
	}

	case R_RISCV_HI20: {
		val = S + A;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, RISCV_U_TYPE_IMM_MASK, RISCV_HI20(val));
		break;
	}

	case R_RISCV_LO12_I:
	case R_RISCV_LO12_S: {
		val = S + A;
		patch_val_over_mask_32(buf_patched, big_endian, patch_addr, (rel_type == R_RISCV_LO12_I) ? RISCV_I_TYPE_IMM_MASK : RISCV_S_TYPE_IMM_MASK, RISCV_LO12(val));
		break;
	}

	case R_RISCV_RVC_BRANCH: {
		val = S + A - P;
		uint16_t imms[] = {
			((val >> 8) & 0x1), // imm[8]
			((val >> 3) & 0x3), // imm[4:3]
			((val >> 6) & 0x3), // imm[7:6]
			((val >> 1) & 0x3), // imm[2:1]
			((val >> 5) & 0x1) // imm[5]
		};
		for (int i = 0; i < sizeof(RISCV_CB_TYPE_IMM_MASKS) / sizeof(RISCV_CB_TYPE_IMM_MASKS[0]); i++) {
			patch_val_over_mask_16(buf_patched, big_endian, patch_addr, RISCV_CB_TYPE_IMM_MASKS[i], imms[i]);
		}
		break;
	}

	case R_RISCV_RVC_JUMP: {
		val = S + A - P;
		uint16_t imms[] = {
			((val >> 11) & 0x1), // imm[11]
			((val >> 4) & 0x1), // imm[4]
			((val >> 8) & 0x3), // imm[9:8]
			((val >> 10) & 0x1), // imm[10]
			((val >> 6) & 0x1), // imm[6]
			((val >> 7) & 0x1), // imm[7]
			((val >> 1) & 0x7), // imm[3:1]
			((val >> 5) & 0x1), // imm[5]
		};
		for (int i = 0; i < sizeof(RISCV_CJ_TYPE_IMM_MASKS) / sizeof(RISCV_CJ_TYPE_IMM_MASKS[0]); i++) {
			patch_val_over_mask_16(buf_patched, big_endian, patch_addr, RISCV_CJ_TYPE_IMM_MASKS[i], imms[i]);
		}
		break;
	}

	case R_RISCV_RVC_LUI:
		val = S + A;
		patch_val_over_mask_16(buf_patched, big_endian, patch_addr, RISCV_CI_TYPE_IMM_MASK, val >> 12);
		break;

	case R_RISCV_ADD8: {
		ut8 old_val = 0;
		rz_buf_read_ble8_at(buf_patched, patch_addr, &old_val, big_endian);
		ut64 result = ((ut64)old_val) + S + A;
		unsigned long long addr = patch_addr;
		rz_buf_write_ble8_offset(buf_patched, &addr, (ut8)result, big_endian);
		break;
	}

	case R_RISCV_ADD16: {
		ut16 old_val = 0;
		rz_buf_read_ble16_at(buf_patched, patch_addr, &old_val, big_endian);
		ut64 result = ((ut64)old_val) + S + A;
		rz_buf_write_ble16_at(buf_patched, patch_addr, (ut16)result, big_endian);
		break;
	}

	case R_RISCV_ADD32: {
		ut32 old_val = 0;
		rz_buf_read_ble32_at(buf_patched, patch_addr, &old_val, big_endian);
		ut64 result = ((ut64)old_val) + S + A;
		rz_buf_write_ble32_at(buf_patched, patch_addr, (ut32)result, big_endian);
		break;
	}

	case R_RISCV_ADD64: {
		ut64 old_val = 0;
		rz_buf_read_ble64_at(buf_patched, patch_addr, &old_val, big_endian);
		ut64 result = old_val + S + A;
		rz_buf_write_ble64_at(buf_patched, patch_addr, result, big_endian);
		break;
	}

	case R_RISCV_SUB8: {
		ut8 old_val = 0;
		rz_buf_read_ble8_at(buf_patched, patch_addr, &old_val, big_endian);
		ut64 result = ((ut64)old_val) - S - A;
		unsigned long long addr = patch_addr;
		rz_buf_write_ble8_offset(buf_patched, &addr, (ut8)result, big_endian);
		break;
	}

	case R_RISCV_SUB16: {
		ut16 old_val = 0;
		rz_buf_read_ble16_at(buf_patched, patch_addr, &old_val, big_endian);
		ut64 result = ((ut64)old_val) - S - A;
		rz_buf_write_ble16_at(buf_patched, patch_addr, (ut16)result, big_endian);
		break;
	}

	case R_RISCV_SUB32: {
		ut32 old_val = 0;
		rz_buf_read_ble32_at(buf_patched, patch_addr, &old_val, big_endian);
		ut64 result = ((ut64)old_val) - S - A;
		rz_buf_write_ble32_at(buf_patched, patch_addr, (ut32)result, big_endian);
		break;
	}

	case R_RISCV_SUB64: {
		ut64 old_val = 0;
		rz_buf_read_ble64_at(buf_patched, patch_addr, &old_val, big_endian);
		ut64 result = ((ut64)old_val) - S - A;
		rz_buf_write_ble64_at(buf_patched, patch_addr, result, big_endian);
		break;
	}

	case R_RISCV_SET8: {
		val = S + A;
		unsigned long long addr = patch_addr;
		rz_buf_write_ble8_offset(buf_patched, &addr, (ut8)val, big_endian);
		break;
	}
	case R_RISCV_SET16: {
		val = S + A;
		rz_buf_write_ble16_at(buf_patched, patch_addr, (ut16)val, big_endian);
		break;
	}
	case R_RISCV_SET32: {
		val = S + A;
		rz_buf_write_ble32_at(buf_patched, patch_addr, (ut32)val, big_endian);
		break;
	}

	case R_RISCV_SET6:
	case R_RISCV_SUB6: {
		ut8 old_val = 0;
		rz_buf_read_ble8_at(buf_patched, patch_addr, &old_val, big_endian);
		val = S + A;
		ut8 result = (rel_type == R_RISCV_SET6) ? val : ((old_val & 0x3F) - val);
		rz_buf_write_ble8_at(buf_patched, patch_addr, (old_val & 0xC0) | (result & 0x3F), big_endian);
		break;
	}

	/*************************************************** UNIMPLEMENTED ***************************************************/
	case R_RISCV_TLS_DTPMOD32:
		UNHANDL_DEF("RISCV", rel_type);
		RZ_LOG_WARN("RISCV Relocations: TLS_DTPMOD32 UNIMPLEMENTED");
		break;

	case R_RISCV_TLS_DTPMOD64:
		UNHANDL_DEF("RISCV", rel_type);
		RZ_LOG_WARN("RISCV Relocations: TLS_DTPMOD64 UNIMPLEMENTED");
		break;

	case R_RISCV_TLS_TPREL32:
		UNHANDL_DEF("RISCV", rel_type);
		RZ_LOG_WARN("RISCV Relocations: TLS_TPREL32 UNIMPLEMENTED");
		break;

	case R_RISCV_TLS_TPREL64:
		UNHANDL_DEF("RISCV", rel_type);
		RZ_LOG_WARN("RISCV Relocations: TLS_TPREL64 UNIMPLEMENTED");
		break;

	case R_RISCV_TLS_GD_HI20:
		UNHANDL_DEF("RISCV", rel_type);
		RZ_LOG_WARN("RISCV Relocations: TLS_GD_HI20 UNIMPLEMENTED");
		break;

	case R_RISCV_TLS_GOT_HI20:
		UNHANDL_DEF("RISCV", rel_type);
		RZ_LOG_WARN("RISCV Relocations: TLS_GOT_HI20 UNIMPLEMENTED");
		break;

	case R_RISCV_TLS_DTPREL32:
		UNHANDL_DEF("RISCV", rel_type);
		RZ_LOG_WARN("RISCV Relocations: TLS_DTPREL32 UNIMPLEMENTED");
		break;

	case R_RISCV_TLS_DTPREL64:
		UNHANDL_DEF("RISCV", rel_type);
		RZ_LOG_WARN("RISCV Relocations: TLS_DTPREL64 UNIMPLEMENTED");
		break;

	default:
		UNHANDL_DEF("RISC-V", rel_type);
		return;
	}
}

#undef UNHANDL
#undef UNHANDL_DEF

#define ARCH_MISSING(NAME) \
	RZ_LOG_WARN("Relocation patching for " NAME " is not implemented.\n"); \
	return

void Elf_(rz_bin_elf_patch_relocation)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RzBinElfReloc *rel, ut64 S, ut64 Z, ut64 B, ut64 L, ut64 GOT, RZ_NONNULL ut64 *AHL) {
	rz_return_if_fail(bin && rel && AHL);
	ut16 e_machine = bin->ehdr.e_machine;
	RelocFormularSymbols formular_sym = {
		.A = rel->addend,
		.B = B,
		.GOT = GOT,
		.L = L,
		.S = S,
		.Z = Z,
		.P = rel->vaddr,
		.MB = 0,
		.G = Elf_(rz_bin_get_reloc_sym_offset_in_got)(bin, rel->sym),
		.GP = 0,
		.T = 0,
		.TLS = 0,
		.AHL = *AHL,
		.O = rel->sparc_secondary_addend,
	};
	ut64 patch_addr = rel->paddr != UT64_MAX ? rel->paddr : Elf_(rz_bin_elf_v2p)(bin, rel->vaddr);
	bool big_endian = bin->big_endian;
	switch (e_machine) {
	case EM_QDSP6:
		patch_reloc_hexagon(bin->buf_patched, patch_addr, rel->type, &formular_sym);
		break;
	case EM_ARM:
		patch_reloc_arm(bin->buf_patched, patch_addr, rel, big_endian, &formular_sym);
		break;
	case EM_AARCH64:
		patch_reloc_arm64(bin->buf_patched, patch_addr, rel, &formular_sym);
		break;
	case EM_PPC64:
		patch_reloc_ppc64(bin->buf_patched, patch_addr, rel->type, big_endian, &formular_sym);
		break;
	case EM_MIPS_X:
		/* fall-thru */
	case EM_MIPS_RS3_LE:
		/* fall-thru */
	case EM_MIPS:
		patch_reloc_mips(bin->buf_patched, patch_addr, rel->type, big_endian, &formular_sym);
		// This is a special value used only in mips
		// An R_MIPS_HI16 must be followed immediately by an R_MIPS_LO16 relocation record in a SHT_REL section.
		// The contents of the two fields to be relocated are combined to form a full 32-bit addend AHL.
		*AHL = formular_sym.AHL;
		break;
	case EM_386:
		patch_reloc_x86_32(bin->buf_patched, patch_addr, rel->type, &formular_sym);
		break;
	case EM_X86_64:
		patch_reloc_x86_64(bin->buf_patched, patch_addr, rel->type, &formular_sym);
		break;
	case EM_RX:
		patch_reloc_rx(bin->buf_patched, patch_addr, rel->type, big_endian, &formular_sym);
		break;
	case EM_ALPHA:
		patch_reloc_alpha(bin->buf_patched, patch_addr, rel->type, big_endian, &formular_sym);
		break;
	case EM_SPARC:
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
		patch_reloc_sparc(bin->buf_patched, patch_addr, rel->type, big_endian, &formular_sym);
		break;
	case EM_PARISC:
		patch_reloc_parisc(bin->buf_patched, patch_addr, rel->type, big_endian, &formular_sym);
		break;
	case EM_AVR:
		patch_reloc_avr(bin->buf_patched, patch_addr, rel->type, big_endian, &formular_sym);
		break;
	case EM_RISCV:
		patch_reloc_riscv(bin->buf_patched, patch_addr, rel->type, big_endian, &formular_sym, bin->bits);
		break;

	case EM_M32: ARCH_MISSING("EM_M32");
	case EM_68K: ARCH_MISSING("EM_68K");
	case EM_88K: ARCH_MISSING("EM_88K");
	case EM_IAMCU: ARCH_MISSING("EM_IAMCU");
	case EM_860: ARCH_MISSING("EM_860");
	case EM_S370: ARCH_MISSING("EM_S370");
	case EM_VPP500: ARCH_MISSING("EM_VPP500");
	case EM_960: ARCH_MISSING("EM_960");
	case EM_PPC: ARCH_MISSING("EM_PPC");
	case EM_S390: ARCH_MISSING("EM_S390");
	case EM_SPU: ARCH_MISSING("EM_SPU");
	case EM_V800: ARCH_MISSING("EM_V800");
	case EM_FR20: ARCH_MISSING("EM_FR20");
	case EM_RH32: ARCH_MISSING("EM_RH32");
	case EM_RCE: ARCH_MISSING("EM_RCE");
	case EM_FAKE_ALPHA: ARCH_MISSING("EM_FAKE_ALPHA");
	case EM_SH: ARCH_MISSING("EM_SH");
	case EM_TRICORE: ARCH_MISSING("EM_TRICORE");
	case EM_ARC: ARCH_MISSING("EM_ARC");
	case EM_H8_300: ARCH_MISSING("EM_H8_300");
	case EM_H8_300H: ARCH_MISSING("EM_H8_300H");
	case EM_H8S: ARCH_MISSING("EM_H8S");
	case EM_H8_500: ARCH_MISSING("EM_H8_500");
	case EM_IA_64: ARCH_MISSING("EM_IA_64");
	case EM_COLDFIRE: ARCH_MISSING("EM_COLDFIRE");
	case EM_68HC12: ARCH_MISSING("EM_68HC12");
	case EM_MMA: ARCH_MISSING("EM_MMA");
	case EM_PCP: ARCH_MISSING("EM_PCP");
	case EM_NCPU: ARCH_MISSING("EM_NCPU");
	case EM_NDR1: ARCH_MISSING("EM_NDR1");
	case EM_STARCORE: ARCH_MISSING("EM_STARCORE");
	case EM_ME16: ARCH_MISSING("EM_ME16");
	case EM_ST100: ARCH_MISSING("EM_ST100");
	case EM_TINYJ: ARCH_MISSING("EM_TINYJ");
	case EM_PDSP: ARCH_MISSING("EM_PDSP");
	case EM_PDP10: ARCH_MISSING("EM_PDP10");
	case EM_PDP11: ARCH_MISSING("EM_PDP11");
	case EM_FX66: ARCH_MISSING("EM_FX66");
	case EM_ST9PLUS: ARCH_MISSING("EM_ST9PLUS");
	case EM_ST7: ARCH_MISSING("EM_ST7");
	case EM_68HC16: ARCH_MISSING("EM_68HC16");
	case EM_68HC11: ARCH_MISSING("EM_68HC11");
	case EM_68HC08: ARCH_MISSING("EM_68HC08");
	case EM_68HC05: ARCH_MISSING("EM_68HC05");
	case EM_SVX: ARCH_MISSING("EM_SVX");
	case EM_ST19: ARCH_MISSING("EM_ST19");
	case EM_VAX: ARCH_MISSING("EM_VAX");
	case EM_CRIS: ARCH_MISSING("EM_CRIS");
	case EM_JAVELIN: ARCH_MISSING("EM_JAVELIN");
	case EM_FIREPATH: ARCH_MISSING("EM_FIREPATH");
	case EM_ZSP: ARCH_MISSING("EM_ZSP");
	case EM_MMIX: ARCH_MISSING("EM_MMIX");
	case EM_HUANY: ARCH_MISSING("EM_HUANY");
	case EM_PRISM: ARCH_MISSING("EM_PRISM");
	case EM_FR30: ARCH_MISSING("EM_FR30");
	case EM_D10V: ARCH_MISSING("EM_D10V");
	case EM_D30V: ARCH_MISSING("EM_D30V");
	case EM_V850: ARCH_MISSING("EM_V850");
	case EM_M32R: ARCH_MISSING("EM_M32R");
	case EM_MN10300: ARCH_MISSING("EM_MN10300");
	case EM_MN10200: ARCH_MISSING("EM_MN10200");
	case EM_PJ: ARCH_MISSING("EM_PJ");
	case EM_OR1K: ARCH_MISSING("EM_OR1K");
	case EM_ARC_COMPACT: ARCH_MISSING("EM_ARC_COMPACT");
	case EM_XTENSA: ARCH_MISSING("EM_XTENSA");
	case EM_VIDEOCORE: ARCH_MISSING("EM_VIDEOCORE");
	case EM_TMM_GPP: ARCH_MISSING("EM_TMM_GPP");
	case EM_NS32K: ARCH_MISSING("EM_NS32K");
	case EM_TPC: ARCH_MISSING("EM_TPC");
	case EM_SNP1K: ARCH_MISSING("EM_SNP1K");
	case EM_ST200: ARCH_MISSING("EM_ST200");
	case EM_IP2K: ARCH_MISSING("EM_IP2K");
	case EM_MAX: ARCH_MISSING("EM_MAX");
	case EM_CR: ARCH_MISSING("EM_CR");
	case EM_F2MC16: ARCH_MISSING("EM_F2MC16");
	case EM_MSP430: ARCH_MISSING("EM_MSP430");
	case EM_BLACKFIN: ARCH_MISSING("EM_BLACKFIN");
	case EM_SE_C33: ARCH_MISSING("EM_SE_C33");
	case EM_SEP: ARCH_MISSING("EM_SEP");
	case EM_ARCA: ARCH_MISSING("EM_ARCA");
	case EM_UNICORE: ARCH_MISSING("EM_UNICORE");
	case EM_EXCESS: ARCH_MISSING("EM_EXCESS");
	case EM_DXP: ARCH_MISSING("EM_DXP");
	case EM_ALTERA_NIOS2: ARCH_MISSING("EM_ALTERA_NIOS2");
	case EM_CRX: ARCH_MISSING("EM_CRX");
	case EM_XGATE: ARCH_MISSING("EM_XGATE");
	case EM_C166: ARCH_MISSING("EM_C166");
	case EM_M16C: ARCH_MISSING("EM_M16C");
	case EM_DSPIC30F: ARCH_MISSING("EM_DSPIC30F");
	case EM_CE: ARCH_MISSING("EM_CE");
	case EM_M32C: ARCH_MISSING("EM_M32C");
	case EM_TSK3000: ARCH_MISSING("EM_TSK3000");
	case EM_RS08: ARCH_MISSING("EM_RS08");
	case EM_SHARC: ARCH_MISSING("EM_SHARC");
	case EM_ECOG2: ARCH_MISSING("EM_ECOG2");
	case EM_SCORE7: ARCH_MISSING("EM_SCORE7");
	case EM_DSP24: ARCH_MISSING("EM_DSP24");
	case EM_VIDEOCORE3: ARCH_MISSING("EM_VIDEOCORE3");
	case EM_LATTICEMICO32: ARCH_MISSING("EM_LATTICEMICO32");
	case EM_SE_C17: ARCH_MISSING("EM_SE_C17");
	case EM_TI_C6000: ARCH_MISSING("EM_TI_C6000");
	case EM_TI_C2000: ARCH_MISSING("EM_TI_C2000");
	case EM_TI_C5500: ARCH_MISSING("EM_TI_C5500");
	case EM_TI_ARP32: ARCH_MISSING("EM_TI_ARP32");
	case EM_TI_PRU: ARCH_MISSING("EM_TI_PRU");
	case EM_MMDSP_PLUS: ARCH_MISSING("EM_MMDSP_PLUS");
	case EM_CYPRESS_M8C: ARCH_MISSING("EM_CYPRESS_M8C");
	case EM_R32C: ARCH_MISSING("EM_R32C");
	case EM_TRIMEDIA: ARCH_MISSING("EM_TRIMEDIA");
	case EM_8051: ARCH_MISSING("EM_8051");
	case EM_STXP7X: ARCH_MISSING("EM_STXP7X");
	case EM_NDS32: ARCH_MISSING("EM_NDS32");
	case EM_ECOG1X: ARCH_MISSING("EM_ECOG1X");
	case EM_MAXQ30: ARCH_MISSING("EM_MAXQ30");
	case EM_XIMO16: ARCH_MISSING("EM_XIMO16");
	case EM_MANIK: ARCH_MISSING("EM_MANIK");
	case EM_CRAYNV2: ARCH_MISSING("EM_CRAYNV2");
	case EM_METAG: ARCH_MISSING("EM_METAG");
	case EM_MCST_ELBRUS: ARCH_MISSING("EM_MCST_ELBRUS");
	case EM_ECOG16: ARCH_MISSING("EM_ECOG16");
	case EM_CR16: ARCH_MISSING("EM_CR16");
	case EM_ETPU: ARCH_MISSING("EM_ETPU");
	case EM_SLE9X: ARCH_MISSING("EM_SLE9X");
	case EM_L10M: ARCH_MISSING("EM_L10M");
	case EM_K10M: ARCH_MISSING("EM_K10M");
	case EM_AVR32: ARCH_MISSING("EM_AVR32");
	case EM_STM8: ARCH_MISSING("EM_STM8");
	case EM_TILE64: ARCH_MISSING("EM_TILE64");
	case EM_TILEPRO: ARCH_MISSING("EM_TILEPRO");
	case EM_MICROBLAZE: ARCH_MISSING("EM_MICROBLAZE");
	case EM_CUDA: ARCH_MISSING("EM_CUDA");
	case EM_TILEGX: ARCH_MISSING("EM_TILEGX");
	case EM_CLOUDSHIELD: ARCH_MISSING("EM_CLOUDSHIELD");
	case EM_COREA_1ST: ARCH_MISSING("EM_COREA_1ST");
	case EM_COREA_2ND: ARCH_MISSING("EM_COREA_2ND");
	case EM_ARCV2: ARCH_MISSING("EM_ARCV2");
	case EM_OPEN8: ARCH_MISSING("EM_OPEN8");
	case EM_RL78: ARCH_MISSING("EM_RL78");
	case EM_VIDEOCORE5: ARCH_MISSING("EM_VIDEOCORE5");
	case EM_78KOR: ARCH_MISSING("EM_78KOR");
	case EM_56800EX: ARCH_MISSING("EM_56800EX");
	case EM_BA1: ARCH_MISSING("EM_BA1");
	case EM_BA2: ARCH_MISSING("EM_BA2");
	case EM_XCORE: ARCH_MISSING("EM_XCORE");
	case EM_MCHP_PIC: ARCH_MISSING("EM_MCHP_PIC");
	case EM_KM32: ARCH_MISSING("EM_KM32");
	case EM_KMX32: ARCH_MISSING("EM_KMX32");
	case EM_EMX16: ARCH_MISSING("EM_EMX16");
	case EM_EMX8: ARCH_MISSING("EM_EMX8");
	case EM_KVARC: ARCH_MISSING("EM_KVARC");
	case EM_CDP: ARCH_MISSING("EM_CDP");
	case EM_COGE: ARCH_MISSING("EM_COGE");
	case EM_COOL: ARCH_MISSING("EM_COOL");
	case EM_NORC: ARCH_MISSING("EM_NORC");
	case EM_CSR_KALIMBA: ARCH_MISSING("EM_CSR_KALIMBA");
	case EM_Z80: ARCH_MISSING("EM_Z80");
	case EM_VISIUM: ARCH_MISSING("EM_VISIUM");
	case EM_FT32: ARCH_MISSING("EM_FT32");
	case EM_MOXIE: ARCH_MISSING("EM_MOXIE");
	case EM_AMDGPU: ARCH_MISSING("EM_AMDGPU");
	case EM_LANAI_OLD: ARCH_MISSING("EM_LANAI_OLD");
	case EM_CEVA: ARCH_MISSING("EM_CEVA");
	case EM_CEVA_X2: ARCH_MISSING("EM_CEVA_X2");
	case EM_BPF: ARCH_MISSING("EM_BPF");
	case EM_GRAPHCORE_IPU: ARCH_MISSING("EM_GRAPHCORE_IPU");
	case EM_IMG1: ARCH_MISSING("EM_IMG1");
	case EM_NFP: ARCH_MISSING("EM_NFP");
	case EM_VE: ARCH_MISSING("EM_VE");
	case EM_CSKY: ARCH_MISSING("EM_CSKY");
	case EM_ARC_COMPACT3_64: ARCH_MISSING("EM_ARC_COMPACT3_64");
	case EM_MCS6502: ARCH_MISSING("EM_MCS6502");
	case EM_ARC_COMPACT3: ARCH_MISSING("EM_ARC_COMPACT3");
	case EM_KVX: ARCH_MISSING("EM_KVX");
	case EM_65816: ARCH_MISSING("EM_65816");
	case EM_LOONGARCH: ARCH_MISSING("EM_LOONGARCH");
	case EM_KF32: ARCH_MISSING("EM_KF32");
	case EM_U16_U8CORE: ARCH_MISSING("EM_U16_U8CORE");
	case EM_TACHYUM: ARCH_MISSING("EM_TACHYUM");
	case EM_56800EF: ARCH_MISSING("EM_56800EF");
	case EM_AVR_OLD: ARCH_MISSING("EM_AVR_OLD");
	case EM_MSP430_OLD: ARCH_MISSING("EM_MSP430_OLD");
	case EM_MT: ARCH_MISSING("EM_MT");
	case EM_CYGNUS_FR30: ARCH_MISSING("EM_CYGNUS_FR30");
	case EM_WEBASSEMBLY: ARCH_MISSING("EM_WEBASSEMBLY");
	case EM_S12Z: ARCH_MISSING("EM_S12Z");
	case EM_DLX: ARCH_MISSING("EM_DLX");
	case EM_CYGNUS_FRV: ARCH_MISSING("EM_CYGNUS_FRV");
	case EM_XC16X: ARCH_MISSING("EM_XC16X");
	case EM_CYGNUS_D10V: ARCH_MISSING("EM_CYGNUS_D10V");
	case EM_CYGNUS_D30V: ARCH_MISSING("EM_CYGNUS_D30V");
	case EM_IP2K_OLD: ARCH_MISSING("EM_IP2K_OLD");
	case EM_CYGNUS_POWERPC: ARCH_MISSING("EM_CYGNUS_POWERPC");
	case EM_CYGNUS_M32R: ARCH_MISSING("EM_CYGNUS_M32R");
	case EM_CYGNUS_V850: ARCH_MISSING("EM_CYGNUS_V850");
	case EM_S390_OLD: ARCH_MISSING("EM_S390_OLD");
	case EM_XTENSA_OLD: ARCH_MISSING("EM_XTENSA_OLD");
	case EM_XSTORMY16: ARCH_MISSING("EM_XSTORMY16");
	case EM_CYGNUS_MN10300: ARCH_MISSING("EM_CYGNUS_MN10300");
	case EM_CYGNUS_MN10200: ARCH_MISSING("EM_CYGNUS_MN10200");
	case EM_M32C_OLD: ARCH_MISSING("EM_M32C_OLD");
	case EM_IQ2000: ARCH_MISSING("EM_IQ2000");
	case EM_NIOS32: ARCH_MISSING("EM_NIOS32");
	case EM_CYGNUS_MEP: ARCH_MISSING("EM_CYGNUS_MEP");
	case EM_MOXIE_OLD: ARCH_MISSING("EM_MOXIE_OLD");
	case EM_MICROBLAZE_OLD: ARCH_MISSING("EM_MICROBLAZE_OLD");
	case EM_ADAPTEVA_EPIPHANY: ARCH_MISSING("EM_ADAPTEVA_EPIPHANY");
	case EM_V810: ARCH_MISSING("EM_V810");
	default:
		RZ_LOG_INFO("Relocation patching for machine %d is not implemented.\n", (int)e_machine);
		return;
	}
}
#undef ARCH_MISSING
