// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARCH_H
#define RZ_ARCH_H

#include <rz_types.h>
#include <rz_util.h>
#include <sdb.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_core_t RzCore;

typedef struct rz_arch_profile_t {
	Sdb *db;
	char *cpu;
	char *arch;
	ut64 ROM_SIZE;
	ut64 RAM_SIZE;
	ut64 EEPROM_SIZE;
	ut64 IO_SIZE;
	ut64 SRAM_START;
	ut64 SRAM_SIZE;
	ut64 PC;
	ut64 PAGE_SIZE;
	ut64 INTERRUPT_VECTOR_SIZE;
	HtUP /* <ut64 , char *> */ *registers_mmio;
	HtUP /* <ut64 , char *> */ *registers_extended;
} RzArchProfile;

RZ_API RZ_OWN RzArchProfile *rz_arch_profile_new();
RZ_API void rz_arch_profile_free(RzArchProfile *s);
RZ_API bool rz_arch_profiles_init(RzArchProfile *c, const char *cpu, const char *arch, const char *dir_prefix);
RZ_API void rz_arch_profile_add_flag_every_io(RzCore *core);

#ifdef __cplusplus
}
#endif

#endif
