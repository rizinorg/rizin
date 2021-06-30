// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARCH_H
#define RZ_ARCH_H

#include <rz_flag.h>
#include <sdb.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_arch_profile_t {
	ut64 rom_size;
	ut64 ram_size;
	ut64 rom_address;
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
	char *cpu;
	char *arch;
	RzArchProfile *profile;
} RzArchTarget;

typedef struct rz_platform_item_t {
	char *name;
	char *comment;
} RzArchPlatformItem;

typedef struct rz_platform_target_t {
	HtUP /* <ut64 , RzArchPlatformItem> */ *platforms;
} RzArchPlatformTarget;

RZ_API RZ_OWN RzArchProfile *rz_arch_profile_new();
RZ_API RZ_OWN RzArchTarget *rz_arch_target_new();
RZ_API void rz_arch_profile_free(RzArchProfile *profile);
RZ_API void rz_arch_target_free(RzArchTarget *target);
RZ_API bool rz_arch_profiles_init(RzArchTarget *c, const char *cpu, const char *arch, const char *dir_prefix);
RZ_API void rz_arch_profile_add_flag_every_io(RzArchProfile *profile, RzFlag *flags);
RZ_API bool rz_arch_load_profile_sdb(RzArchTarget *t, const char *path);

RZ_API RZ_OWN RzArchPlatformItem *rz_arch_platform_item_new(RZ_NULLABLE const char *name);
RZ_API RZ_OWN RzArchPlatformTarget *rz_arch_platform_target_new();
RZ_API void rz_arch_platform_target_free(RzArchPlatformTarget *target);
RZ_API void rz_arch_platform_item_free(RzArchPlatformItem *item);
RZ_API bool rz_arch_load_platform_sdb(RzArchPlatformTarget *t, RZ_NONNULL const char *path);
RZ_API bool rz_arch_platform_init(RzArchPlatformTarget *t, const char *arch, const char *cpu, const char *platform, const char *dir_prefix);

#ifdef __cplusplus
}
#endif

#endif
