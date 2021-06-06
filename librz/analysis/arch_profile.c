// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_arch.h>
#include <stdio.h>
#include <string.h>

RZ_API void rz_arch_profile_free(RzArchProfile *p) {
	if (!p) {
		return;
	}
	free(p->arch);
	free(p->cpu);
	ht_up_free(p->io_registers);
	ht_up_free(p->extended_io_registers);
}

RZ_API RZ_OWN RzArchProfile *rz_arch_profile_new() {
	RzArchProfile *cpu = RZ_NEW0(RzArchProfile);
	if (!cpu) {
		return NULL;
	}
	cpu->db = sdb_new0();
	cpu->arch = NULL;
	cpu->cpu = NULL;

	cpu->io_registers = ht_up_new0();
	cpu->extended_io_registers = ht_up_new0();
	return cpu;
}

static inline bool cpu_reload_needed(RzArchProfile *c, const char *cpu, const char *arch) {
	if (!c->arch || strcmp(c->arch, arch)) {
		return true;
	}
	return !c->cpu || strcmp(c->cpu, cpu);
}

static bool sdb_load_arch_profile(RzArchProfile *c, Sdb *sdb) {
	rz_return_val_if_fail(c && sdb, NULL);
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(sdb, false);
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_key(kv), "PC")) {
			c->PC = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "EEPROM_SIZE")) {
			c->EEPROM_SIZE = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "IO_SIZE")) {
			c->IO_SIZE = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "SRAM_START")) {
			c->SRAM_START = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "SRAM_SIZE")) {
			c->SRAM_SIZE = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "PAGE_SIZE")) {
			c->PAGE_SIZE = rz_num_math(NULL, sdbkv_value(kv));
		} else if (!strcmp(sdbkv_key(kv), "ROM_SIZE")) {
			c->ROM_SIZE = rz_num_math(NULL, sdbkv_value(kv));
		} else 	if (!strcmp(sdbkv_key(kv), "RAM_SIZE")) {
			eprintf("ram size %s \n", sdbkv_value(kv));
			c->RAM_SIZE = rz_num_math(NULL, sdbkv_value(kv));
		}
		if (!strcmp(sdbkv_value(kv), "io")) {
			char *io_name = sdbkv_key(kv);
			char *argument_key = rz_str_newf("%s.address", io_name);
			ut64 io_address = sdb_num_get(sdb, argument_key, NULL);
			ht_up_insert(c->io_registers, io_address, io_name);
		}
		if (!strcmp(sdbkv_value(kv), "ext_io")) {
			char *ext_io_name = sdbkv_key(kv);
			char *argument_key = rz_str_newf("%s.address", ext_io_name);
			ut64 ext_io_address = sdb_num_get(sdb, argument_key, NULL);
			ht_up_insert(c->extended_io_registers, ext_io_address, ext_io_name);
		}
	}
	return true;
}

static bool sdb_load_arch_profile_by_path(RZ_NONNULL RzArchProfile *c, const char *path) {
	Sdb *db = sdb_new(0, path, 0);
	bool result = sdb_load_arch_profile(c, db);
	sdb_close(db);
	sdb_free(db);
	return result;
}

RZ_API bool rz_type_db_load_arch_profile_sdb(RzArchProfile *c, const char *path) {
	if (!rz_file_exists(path)) {
		return false;
	}
	return sdb_load_arch_profile_by_path(c, path);
}

RZ_API bool rz_arch_profiles_init(RzArchProfile *c, const char *cpu, const char *arch, const char *dir_prefix) {
	/* bool cpu_changed;

	if (!arch) {
		arch = RZ_SYS_ARCH;
	}
	if (!cpu) {
		cpu = arch;
	}

	cpu_changed = cpu_reload_needed(c, cpu, arch);

	free(c->cpu);
	c->cpu = strdup(cpu);

	free(c->arch);
	c->arch = strdup(arch);

	//cpu_changed = true; */

	// change path for DB

	// 	char *path = sdb_fmt(RZ_JOIN_4_PATHS("%s", RZ_SDB, "reg", "%s-%s-%d.sdb"), dir_prefix,
	//	arch, s->cpu, s->bits);
	//  bool cpu_changed = cpu_reload_needed(c, cpu, arch);
	//	bool cpu_changed = true;
	//if (cpu_changed) {
	char *path = rz_str_newf(RZ_JOIN_4_PATHS("%s", RZ_SDB, "asm/cpus", "%s-%s.sdb"),
		dir_prefix, arch, cpu);
	eprintf("%s \n", path);
	if (path) {
		if (!rz_type_db_load_arch_profile_sdb(c, path)) {
			sdb_free(c->db);
			c->db = NULL;
		}
		free(path);
	}
	//}
	return true;
}