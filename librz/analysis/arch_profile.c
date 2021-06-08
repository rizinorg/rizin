// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_arch.h>
#include <stdio.h>
#include <string.h>

/**
 * \brief Frees an RzArchProfile type
 *
 * 	Frees the hashtables used for MMIO and extended
 * 	registers
 */
RZ_API void rz_arch_profile_free(RzArchProfile *p) {
	if (!p) {
		return;
	}
	ht_up_free(p->registers_mmio);
	ht_up_free(p->registers_extended);
}

/**
 * \brief Creates a new RzArchProfile type
 */
RZ_API RZ_OWN RzArchProfile *rz_arch_profile_new() {
	RzArchProfile *profile = RZ_NEW0(RzArchProfile);
	profile->registers_mmio = ht_up_new0();
	profile->registers_extended = ht_up_new0();
	return profile;
}

/**
 * \brief Creates a new RzArchTarget type
 */
RZ_API RZ_OWN RzArchTarget *rz_arch_target_new() {
	RzArchTarget *profile = RZ_NEW0(RzArchTarget);
	profile->db = sdb_new0();
	profile->profile = rz_arch_profile_new();
	return profile;
}

/**
 * \brief Frees an RzArchTarget type
 *
 *	Frees the pointer to the SDB and the RzArchProfile
 */
RZ_API void rz_arch_target_free(RzArchTarget *t) {
	if (!t) {
		return;
	}
	sdb_free(t->db);
	rz_arch_profile_free(t->profile);
}

static inline bool cpu_reload_needed(RzArchTarget *c, const char *cpu, const char *arch) {
	if (!c->arch || strcmp(c->arch, arch)) {
		return true;
	}
	return !c->cpu || strcmp(c->cpu, cpu);
}

static bool sdb_load_arch_profile(RzArchTarget *t, Sdb *sdb) {
	rz_return_val_if_fail(t && sdb, NULL);
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(sdb, false);
	RzArchProfile *c = rz_arch_profile_new();
	ls_foreach (l, iter, kv) {
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
		} else if (!strcmp(sdbkv_key(kv), "RAM_SIZE")) {
			c->ram_size = rz_num_math(NULL, sdbkv_value(kv));
		}
		if (!strcmp(sdbkv_value(kv), "io")) {
			char *io_name = sdbkv_key(kv);
			char *argument_key = rz_str_newf("%s.address", io_name);
			ut64 io_address = sdb_num_get(sdb, argument_key, NULL);
			ht_up_insert(c->registers_mmio, io_address, io_name);
		}
		if (!strcmp(sdbkv_value(kv), "ext_io")) {
			char *ext_io_name = sdbkv_key(kv);
			char *argument_key = rz_str_newf("%s.address", ext_io_name);
			ut64 ext_io_address = sdb_num_get(sdb, argument_key, NULL);
			ht_up_insert(c->registers_extended, ext_io_address, ext_io_name);
		}
	}
	t->profile = c;
	return true;
}

static bool sdb_load_arch_profile_by_path(RZ_NONNULL RzArchTarget *t, const char *path) {
	Sdb *db = sdb_new(0, path, 0);
	bool result = sdb_load_arch_profile(t, db);
	sdb_close(db);
	sdb_free(db);
	return result;
}

/**
 * \brief Loads the contents of the CPU Profile to the RzArchProfile
 *
 * \param t reference to RzArchTarget
 * \param path reference to path of the SDB file
 */
RZ_API bool rz_type_db_load_arch_profile_sdb(RzArchTarget *t, const char *path) {
	if (!rz_file_exists(path)) {
		return false;
	}
	return sdb_load_arch_profile_by_path(t, path);
}

/**
 * \brief Initializes RzArchProfile by loading the path to the SDB file
 * 		  of the CPU profile
 *
 * \param t reference to RzArchTarget
 * \param cpu reference to the selected CPU (value of `asm.cpu`)
 * \param arch reference to the seletec architecture (value of `asm.arch`)
 * \param dir_prefix reference to the directory prefix or the value of dir.prefix
 */
RZ_API bool rz_arch_profiles_init(RzArchTarget *t, const char *cpu, const char *arch, const char *dir_prefix) {
	if (!cpu_reload_needed(t, cpu, arch)) {
		return false;
	}
	char *path = rz_str_newf(RZ_JOIN_4_PATHS("%s", RZ_SDB, "asm/cpus", "%s-%s.sdb"),
		dir_prefix, arch, cpu);
	if (!path) {
		return false;
	}
	if (!rz_type_db_load_arch_profile_sdb(t, path)) {
		sdb_free(t->db);
		t->db = NULL;
	}
	free(path);
	return true;
}