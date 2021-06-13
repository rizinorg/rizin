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

struct rz_core_t;

typedef struct rz_arch_profile_t {
	ut64 rom_size;
	ut64 ram_size;
	ut64 eeprom_size;
	ut64 io_size;
	ut64 sram_start;
	ut64 sram_size;
	ut64 pc;
	ut64 page_size;
	ut64 interrupt_vector_size;
	HtUP /* <ut64 , char *> */ *registers_mmio;
	HtUP /* <ut64 , char *> */ *registers_extended;
} RzArchProfile;

typedef struct rz_arch_target_t {
	Sdb *db;
	char *cpu;
	char *arch;
	RzArchProfile *profile;
} RzArchTarget;

RZ_API RZ_OWN RzArchProfile *rz_arch_profile_new();
RZ_API RZ_OWN RzArchTarget *rz_arch_target_new();
RZ_API void rz_arch_profile_free(RzArchProfile *profile);
RZ_API void rz_arch_target_free(RzArchTarget *target);
RZ_API bool rz_arch_profiles_init(RzArchTarget *c, const char *cpu, const char *arch, const char *dir_prefix);
RZ_API void rz_arch_profile_add_flag_every_io(struct rz_core_t *core);

#ifdef __cplusplus
}
#endif

#endif
