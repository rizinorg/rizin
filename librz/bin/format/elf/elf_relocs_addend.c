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

	switch (reloc->type) {
	case R_ARM_ALU_PC_G0:
	case R_ARM_ALU_PC_G0_NC:
	case R_ARM_ALU_PC_G1:
	case R_ARM_ALU_PC_G1_NC:
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
	case R_ARM_LDR_PC_G1:
	case R_ARM_LDR_PC_G2:
		rz_buf_read_at(buf, patch_addr, b, 4);
		opcode = rz_read_ble32(b, big_endian);
		unsigned_imm = opcode & 0xFFF;
		bool u_bit = (opcode >> 23) & 1;
		reloc->addend = u_bit ? (st64)unsigned_imm : -(st64)unsigned_imm;
		break;
    case R_ARM_PC24:
    case R_ARM_CALL:
    case R_ARM_JUMP24:
        rz_buf_read_at(buf, patch_addr, b, 4);
        opcode = rz_read_ble32(b, big_endian);
        unsigned_imm = opcode & 0X00FFFFFF;
        signed_imm = (st32)(unsigned_imm << 8) >> 8;
        reloc->addend = signed_imm << 2;
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