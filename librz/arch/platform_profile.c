// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_platform.h>
#include <string.h>

/**
 * \brief Frees an RzPlatformProfile type
 *
 * 	Frees the hashtables used for MMIO and extended
 * 	registers
 */
RZ_API void rz_platform_profile_free(RzPlatformProfile *p) {
	if (!p) {
		return;
	}
	ht_up_free(p->registers_mmio);
	ht_up_free(p->registers_extended);
	free(p);
}

/**
 * \brief Creates a new RzPlatformProfile type
 */
RZ_API RZ_OWN RzPlatformProfile *rz_platform_profile_new() {
	RzPlatformProfile *profile = RZ_NEW0(RzPlatformProfile);
	if (!profile) {
		return NULL;
	}
	profile->registers_mmio = ht_up_new((HtUPDupValue)strdup, free);
	if (!profile->registers_mmio) {
		free(profile);
		return NULL;
	}
	profile->registers_extended = ht_up_new((HtUPDupValue)strdup, free);
	if (!profile->registers_extended) {
		ht_up_free(profile->registers_mmio);
		free(profile);
		return NULL;
	}
	return profile;
}

/**
 * \brief Creates a new RzPlatformTarget type
 */
RZ_API RZ_OWN RzPlatformTarget *rz_platform_target_new() {
	RzPlatformTarget *profile = RZ_NEW0(RzPlatformTarget);
	if (!profile) {
		return NULL;
	}
	profile->profile = rz_platform_profile_new();
	if (!profile->profile) {
		free(profile);
		return NULL;
	}
	return profile;
}

/**
 * \brief Frees an RzPlatformTarget type
 *
 *	Frees the pointer to the SDB and the RzPlatformProfile
 */
RZ_API void rz_platform_target_free(RzPlatformTarget *t) {
	if (!t) {
		return;
	}
	rz_platform_profile_free(t->profile);
	free(t->cpu);
	free(t->arch);
	free(t);
}

/**
 * \brief Resolves an address and returns the linked mmio
 */
RZ_API RZ_BORROW const char *rz_platform_profile_resolve_mmio(RZ_NONNULL RzPlatformProfile *profile, ut64 address) {
	rz_return_val_if_fail(profile, NULL);

	return ht_up_find(profile->registers_mmio, (ut64)address, NULL);
}

/**
 * \brief Resolves an address and returns the linked extended register
 */
RZ_API RZ_BORROW const char *rz_platform_profile_resolve_extended_register(RZ_NONNULL RzPlatformProfile *profile, ut64 address) {
	rz_return_val_if_fail(profile, NULL);

	return ht_up_find(profile->registers_extended, (ut64)address, NULL);
}

static inline bool cpu_reload_needed(RzPlatformTarget *c, const char *cpu, const char *arch) {
	if (!c->arch || strcmp(c->arch, arch)) {
		return true;
	}
	return !c->cpu || strcmp(c->cpu, cpu);
}

static bool sdb_load_arch_profile(RzPlatformTarget *t, Sdb *sdb) {
	rz_return_val_if_fail(t && sdb, false);

	RzPlatformProfile *c = rz_platform_profile_new();
	if (!c) {
		return false;
	}
	void **iter;
	RzPVector *l = sdb_get_kv_list(sdb, false);
	rz_pvector_foreach (l, iter) {
		SdbKv *kv = *iter;
		if (!strcmp(sdbkv_key(kv), "PC")) {
			c->pc = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "EEPROM_SIZE")) {
			c->eeprom_size = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "IO_SIZE")) {
			c->io_size = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "SRAM_START")) {
			c->sram_start = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "SRAM_SIZE")) {
			c->sram_size = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "PAGE_SIZE")) {
			c->page_size = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "ROM_SIZE")) {
			c->rom_size = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "ROM_ADDRESS")) {
			c->rom_address = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "RAM_SIZE")) {
			c->ram_size = rz_num_math(NULL, sdbkv_value(kv));
		}
		if (!strcmp(sdbkv_value(kv), "io")) {
			char *io_name = sdbkv_key(kv);
			char *argument_key = rz_str_newf("%s.address", io_name);
			ut64 io_address = sdb_num_get(sdb, argument_key, NULL);
			free(argument_key);
			ht_up_insert(c->registers_mmio, io_address, io_name);
		}
		if (!strcmp(sdbkv_value(kv), "ext_io")) {
			char *ext_io_name = sdbkv_key(kv);
			char *argument_key = rz_str_newf("%s.address", ext_io_name);
			ut64 ext_io_address = sdb_num_get(sdb, argument_key, NULL);
			free(argument_key);
			ht_up_insert(c->registers_extended, ext_io_address, ext_io_name);
		}
	}
	rz_pvector_free(l);
	rz_platform_profile_free(t->profile);
	t->profile = c;
	return true;
}

static bool sdb_load_arch_profile_by_path(RZ_NONNULL RzPlatformTarget *t, const char *path) {
	Sdb *db = sdb_new(0, path, 0);
	bool result = sdb_load_arch_profile(t, db);
	sdb_close(db);
	sdb_free(db);
	return result;
}

/**
 * \brief Loads the contents of the CPU Profile to the RzPlatformProfile
 *
 * \param t reference to RzPlatformTarget
 * \param path reference to path of the SDB file
 */
RZ_API bool rz_platform_load_profile_sdb(RzPlatformTarget *t, const char *path) {
	if (!rz_file_exists(path)) {
		return false;
	}
	return sdb_load_arch_profile_by_path(t, path);
}

static bool is_cpu_valid(const char *cpu_dir, const char *cpu) {
	RzList *files = rz_sys_dir(cpu_dir);
	if (!files) {
		return false;
	}
	RzListIter *it;
	char *filename = NULL;
	char *arch_cpu = NULL;

	rz_list_foreach (files, it, filename) {
		char *cpu_name = NULL;
		if (!strcmp(filename, "..") || !strcmp(filename, "..")) {
			continue;
		}
		arch_cpu = rz_str_ndup(filename, strlen(filename) - 4);
		if (!arch_cpu) {
			continue;
		}
		cpu_name = strchr(arch_cpu, '-');
		if (!cpu_name) {
			free(arch_cpu);
			continue;
		}
		cpu_name[0] = '\0';
		if (!strcmp(cpu_name + 1, cpu)) {
			rz_list_free(files);
			free(arch_cpu);
			return true;
		}

		free(arch_cpu);
	}

	rz_list_free(files);
	return false;
}

/**
 * \brief Initializes RzPlatformProfile by loading the path to the SDB file
 * 		  of the CPU profile
 *
 * \param t reference to RzPlatformTarget
 * \param cpu reference to the selected CPU (value of `asm.cpu`)
 * \param arch reference to the selected architecture (value of `asm.arch`)
 * \param cpus_dir reference to the directory containing cpu files
 */
RZ_API bool rz_platform_profiles_init(RzPlatformTarget *t, const char *cpu, const char *arch, const char *cpus_dir) {
	if (!cpu_reload_needed(t, cpu, arch)) {
		return false;
	}
	if (!cpus_dir || !arch || !cpu) {
		return false;
	}
	char buf[50];
	char *path = rz_file_path_join(cpus_dir, rz_strf(buf, "%s-%s.sdb", arch, cpu));
	if (!path) {
		return false;
	}
	if (!is_cpu_valid(cpus_dir, cpu)) {
		if (!strcmp(arch, "avr")) {
			free(path);
			path = rz_file_path_join(cpus_dir, "avr-ATmega8.sdb");
		}
	}
	free(t->cpu);
	free(t->arch);
	t->cpu = strdup(cpu);
	t->arch = strdup(arch);
	rz_platform_load_profile_sdb(t, path);
	free(path);
	return true;
}
