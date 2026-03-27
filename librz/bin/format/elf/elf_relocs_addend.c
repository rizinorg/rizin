#include "elf.h"

static ut32 arm_rotr32(ut32 val, ut32 n) {
    return (val >> n) | (val << (32 - n));
}

static bool get_reloc_addend_arm(RzBuffer *buf, RzBinElfReloc *reloc, ut64 patch_addr, bool big_endian){
    ut8 b[4] = {0};
    ut32 opcode;

    switch(reloc->type){
        case R_ARM_ALU_PC_G0:
        case R_ARM_ALU_PC_G0_NC:
        case R_ARM_ALU_PC_G1:
        case R_ARM_ALU_PC_G1_NC:
        case R_ARM_ALU_PC_G2:   
        rz_buf_read_at(buf, patch_addr,b, 4);
        opcode = rz_read_ble32(b, big_endian);
        ut32 imm12 = opcode & 0xFFF;
        ut32 rot = (imm12 >> 8) & 0xF;
        ut32 imm8 = imm12 & 0xFF;
        ut32 decoded = arm_rotr32(imm8, rot * 2);
        bool is_sub = (((opcode >> 21) & 0xF) == 0x2);
        reloc->addend = is_sub ? -(st64)decoded : (st64)decoded;
        return true;
        default:
        return false;
    }
}

RZ_BORROW bool Elf_(rz_bin_elf_reloc_get_addend)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RzBinElfReloc *reloc){
    ut64 e_machine = bin->ehdr.e_machine;
	ut64 patch_addr = reloc->paddr != UT64_MAX ? reloc->paddr : Elf_(rz_bin_elf_v2p)(bin, reloc->vaddr);
	bool big_endian = bin->big_endian;

    switch(e_machine){
        case EM_ARM:
            return get_reloc_addend_arm(bin->buf_patched, reloc, patch_addr, big_endian);
        default:
        return false;
    }
}