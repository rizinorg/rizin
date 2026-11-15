// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "c166_raw.h"

#include "rz_bin.h"
#include "rz_util/rz_str.h"

static const BinC166IntTable c166_int_table[] = {
	{ 0x00, 0x000000, "RESET" }, ///< Reset Handler
	{ 0x01, 0x000004, "user_01" },
	{ 0x02, 0x000008, "NMI_trap" }, ///< Non-Maskable Interrupt
	{ 0x03, 0x00000C, "user_03" },
	{ 0x04, 0x000010, "STKOF_trap" }, ///< Stack Overflow
	{ 0x05, 0x000014, "user_05" },
	{ 0x06, 0x000018, "STKUF_trap" }, ///< Stack Underflow
	{ 0x07, 0x00001C, "user_07" },
	{ 0x08, 0x000020, "user_08" },
	{ 0x09, 0x000024, "user_09" },

	{ 0x0A, 0x000028, "Class_B_trap" }, ///< Timer1 Capture Handler

	{ 0x0B, 0x00002C, "reserved_0B" }, ///< Reserved
	{ 0x0C, 0x000030, "reserved_0C" }, ///< Reserved
	{ 0x0D, 0x000034, "reserved_0D" }, ///< Reserved
	{ 0x0E, 0x000038, "reserved_0E" }, ///< Reserved
	{ 0x0F, 0x00003C, "reserved_0F" }, ///< Reserved

	{ 0x10, 0x000040, "CC0INT" }, ///< CAPCOM Register 0
	{ 0x11, 0x000044, "CC1INT" }, ///< CAPCOM Register 1
	{ 0x12, 0x000048, "CC2INT" }, ///< CAPCOM Register 2
	{ 0x13, 0x00004c, "CC3INT" }, ///< CAPCOM Register 3
	{ 0x14, 0x000050, "CC4INT" }, ///< CAPCOM Register 4
	{ 0x15, 0x000054, "CC5INT" }, ///< CAPCOM Register 5
	{ 0x16, 0x000058, "CC6INT" }, ///< CAPCOM Register 6
	{ 0x17, 0x00005c, "CC7INT" }, ///< CAPCOM Register 7
	{ 0x18, 0x000060, "CC8INT" }, ///< CAPCOM Register 8
	{ 0x19, 0x000064, "CC9INT" }, ///< CAPCOM Register 9
	{ 0x1a, 0x000068, "CC10INT" }, ///< CAPCOM Register 10
	{ 0x1b, 0x00006c, "CC11INT" }, ///< CAPCOM Register 11
	{ 0x1c, 0x000070, "CC12INT" }, ///< CAPCOM Register 12
	{ 0x1d, 0x000074, "CC13INT" }, ///< CAPCOM Register 13
	{ 0x1e, 0x000078, "CC14INT" }, ///< CAPCOM Register 14
	{ 0x1f, 0x00007c, "CC15INT" }, ///< CAPCOM Register 15

	{ 0x20, 0x000080, "T0INT" }, ///< CAPCOM Timer 0
	{ 0x21, 0x000084, "T1INT" }, ///< CAPCOM Timer 1
	{ 0x22, 0x000088, "T2INT" }, ///< GPT1 Timer 2
	{ 0x23, 0x00008C, "T3INT" }, ///< GPT1 Timer 3
	{ 0x24, 0x000090, "T4INT" }, ///< GPT1 Timer 4
	{ 0x25, 0x000094, "T5INT" }, ///< GPT2 Timer 5
	{ 0x26, 0x000098, "T6INT" }, ///< GPT2 Timer 6

	{ 0x27, 0x00009C, "CRINT" }, ///< GPT2 CAPREL Register
	{ 0x28, 0x0000A0, "ADCINT" }, ///< A/D Conversion Complete
	{ 0x29, 0x0000A4, "ADEINT" }, ///< A/D Overrun Error
	{ 0x2A, 0x0000A8, "S0TINT" }, ///< ASC0 Transmit
	{ 0x2B, 0x0000AC, "S0RINT" }, ///< ASC0 Receive
	{ 0x2C, 0x0000B0, "S0EINT" }, ///< ASC0 Error
	{ 0x2D, 0x0000B4, "SCTINT" }, ///< SSC Transmit
	{ 0x2E, 0x0000B8, "SCRINT" }, ///< SSC Receive
	{ 0x2F, 0x0000BC, "SCEINT" }, ///< SSC Error

	{ 0x30, 0x0000c0, "CC16INT" }, ///< CAPCOM Register 16
	{ 0x31, 0x0000c4, "CC17INT" }, ///< CAPCOM Register 17
	{ 0x32, 0x0000c8, "CC18INT" }, ///< CAPCOM Register 18
	{ 0x33, 0x0000cc, "CC19INT" }, ///< CAPCOM Register 19
	{ 0x34, 0x0000d0, "CC20INT" }, ///< CAPCOM Register 20
	{ 0x35, 0x0000d4, "CC21INT" }, ///< CAPCOM Register 21
	{ 0x36, 0x0000d8, "CC22INT" }, ///< CAPCOM Register 22
	{ 0x37, 0x0000dc, "CC23INT" }, ///< CAPCOM Register 23
	{ 0x38, 0x0000e0, "CC24INT" }, ///< CAPCOM Register 24
	{ 0x39, 0x0000e4, "CC25INT" }, ///< CAPCOM Register 25
	{ 0x3a, 0x0000e8, "CC26INT" }, ///< CAPCOM Register 26
	{ 0x3b, 0x0000ec, "CC27INT" }, ///< CAPCOM Register 27
	{ 0x3c, 0x0000f0, "CC28INT" }, ///< CAPCOM Register 28
	{ 0x3d, 0x0000F4, "T7INT" }, ///< CAPCOM Timer 7
	{ 0x3e, 0x0000F8, "T8INT" }, ///< CAPCOM Timer 8

	{ 0x3F, 0x0000FC, "PWMINT" }, ///< PWM Channel 0...3

	{ 0x40, 0x000100, "XP0INT" }, ///< X-Peripheral interrupt
	{ 0x41, 0x000104, "XP1INT" }, ///< X-Peripheral interrupt
	{ 0x42, 0x000108, "XP2INT" }, ///< X-Peripheral interrupt
	{ 0x43, 0x00010C, "XP3INT" }, ///< X-Peripheral interrupt

	{ 0x44, 0x000110, "CC29INT" }, ///< CAPCOM Register 29
	{ 0x45, 0x000114, "CC30INT" }, ///< CAPCOM Register 30
	{ 0x46, 0x000118, "CC31INT" }, ///< CAPCOM Register 31

	{ 0x47, 0x00011C, "S0TBINT" }, ///< ASC0 Transmit Buffer

	// 112 - 126
	// 0x0001C0 – 0x0001F8  USER TRAPS
};
const ut8 c166_int_table_count = RZ_ARRAY_SIZE(c166_int_table);

bool create_isr_sym(RzPVector /*<RzBinSymbol *>*/ *isr_table, char *sym_name, const ut64 addr) {
	RzBinSymbol *ptr = RZ_NEW0(RzBinSymbol);
	if (!ptr) {
		free(sym_name);
		return false;
	}
	ptr->name = sym_name;
	ptr->paddr = addr;
	ptr->vaddr = addr;
	ptr->size = 4;
	ptr->ordinal = 0;
	ptr->bits = 16;
	ptr->bind = RZ_BIN_BIND_GLOBAL_STR;
	ptr->type = RZ_BIN_TYPE_FUNC_STR;
	rz_pvector_push(isr_table, ptr);
	return true;
}

bool populate_isr_table(RzVector /*<ut64>*/ *interrupts, RzPVector /*<RzBinSymbol *>*/ *isr_table, ut64 base_addr) {
	void **iter;
	rz_vector_foreach (interrupts, iter) {
		const ut64 isr_addr = (ut64)*iter;
		for (ut8 j = 0; j < (ut8)RZ_ARRAY_SIZE(c166_int_table); j++) {
			const BinC166IntTable intr = c166_int_table[j];
			const ut64 addr = base_addr | intr.address;
			if (isr_addr == addr) {
				char *sym_name = rz_str_newf("isr.%s", intr.name);
				create_isr_sym(isr_table, sym_name, addr);
			}
		}
		for (ut8 i = 80; i < 128; i++) {
			const ut64 loc_addr = i * 4;
			const ut64 addr = base_addr | loc_addr;
			if (isr_addr == addr) {
				char *sym_name = rz_str_newf("isr.user_%i", i);
				create_isr_sym(isr_table, sym_name, addr);
			}
		}
	}
	return true;
}

char *cpu_name(const C16xCpuType cpu) {
	switch (cpu) {
	case CPU_ST10:
		return rz_str_dup("st10");
	case CPU_C167:
		return rz_str_dup("c167");
	case CPU_C166:
	default:
		return rz_str_dup("c166-generic");
	}
}
