// SPDX-FileCopyrightText: 2021-2022 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PLATFORM_H
#define RZ_PLATFORM_H

#include <rz_config.h>
#include <rz_flag.h>
#include <rz_il.h>
#include <sdb.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_platform_profile_t {
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
	HtUP /*<ut64 , char *>*/ *registers_mmio;
	HtUP /*<ut64 , char *>*/ *registers_extended;
} RzPlatformProfile;

typedef struct rz_platform_target_t {
	char *cpu;
	char *arch;
	RzPlatformProfile *profile;
} RzPlatformTarget;

typedef struct rz_platform_item_t {
	char *name;
	char *comment;
} RzPlatformItem;

typedef struct rz_platform_target_index_t {
	HtUP /*<ut64 , RzPlatformItem>*/ *platforms;
	char *path; ///< Path used to load the platforms, used to avoid reloading
} RzPlatformTargetIndex;

RZ_API RZ_OWN RzPlatformProfile *rz_platform_profile_new();
RZ_API RZ_OWN RzPlatformTarget *rz_platform_target_new();
RZ_API void rz_platform_profile_free(RzPlatformProfile *profile);
RZ_API void rz_platform_target_free(RzPlatformTarget *target);
RZ_API bool rz_platform_profiles_init(RzPlatformTarget *c, const char *cpu, const char *arch, const char *cpus_dir);
RZ_API void rz_platform_profile_add_flag_every_io(RzPlatformProfile *profile, RzFlag *flags);
RZ_API bool rz_platform_load_profile_sdb(RzPlatformTarget *t, const char *path);
RZ_API RZ_BORROW const char *rz_platform_profile_resolve_mmio(RZ_NONNULL RzPlatformProfile *profile, ut64 address);
RZ_API RZ_BORROW const char *rz_platform_profile_resolve_extended_register(RZ_NONNULL RzPlatformProfile *profile, ut64 address);

RZ_API RZ_OWN RzPlatformItem *rz_platform_item_new(RZ_NULLABLE const char *name);
RZ_API RZ_OWN RzPlatformTargetIndex *rz_platform_target_index_new();
RZ_API void rz_platform_target_index_free(RzPlatformTargetIndex *target);
RZ_API void rz_platform_item_free(RzPlatformItem *item);
RZ_API bool rz_platform_target_index_load_sdb(RZ_NONNULL RzPlatformTargetIndex *t, RZ_NONNULL const char *path);
RZ_API bool rz_platform_target_index_init(RzPlatformTargetIndex *t, RZ_NONNULL const char *arch, RZ_NONNULL const char *cpu,
	const char *platform, RZ_NONNULL const char *platforms_dir);

#ifdef __cplusplus
}
#endif

#endif /* RZ_PLATFORM_H */
