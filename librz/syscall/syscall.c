// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_syscall.h>
#include <stdio.h>
#include <string.h>

RZ_LIB_VERSION(rz_syscall);

RZ_API RzSyscall *rz_syscall_ref(RzSyscall *sc) {
	sc->refs++;
	return sc;
}

/**
 * \brief Creates a new RzSysregItem type
 *
 * \param name Name of the SysregItem (sysregitem->name)
 */
RZ_API RZ_OWN RzSysregItem *rz_sysreg_item_new(RZ_NULLABLE const char *name) {
	RzSysregItem *sysregitem = RZ_NEW0(RzSysregItem);
	if (!sysregitem) {
		return NULL;
	}
	sysregitem->comment = NULL;
	sysregitem->type = NULL;
	sysregitem->name = rz_str_dup(name);
	return sysregitem;
}

/**
 * \brief Creates a new RzSysregDB type
 */
RZ_API RzSysregsDB *rz_sysregs_db_new() {
	RzSysregsDB *sysregdb = RZ_NEW0(RzSysregsDB);
	if (!sysregdb) {
		return NULL;
	}
	sysregdb->port = ht_up_new(NULL, (HtUPFreeValue)rz_sysreg_item_free);
	if (!sysregdb->port) {
		free(sysregdb);
		return NULL;
	}
	return sysregdb;
}

/**
 * \brief Frees a RzSysregDB type
 */
RZ_API void rz_sysregs_db_free(RzSysregsDB *sysregdb) {
	if (!sysregdb) {
		return;
	}
	ht_up_free(sysregdb->port);
	free(sysregdb);
}

/**
 * \brief Creates a new RzSyscall type
 */
RZ_API RzSyscall *rz_syscall_new(void) {
	RzSyscall *rs = RZ_NEW0(RzSyscall);
	if (rs) {
		rs->srdb = rz_sysregs_db_new(); // sysregs database
		rs->db = sdb_new0();
	}
	return rs;
}

/**
 * \brief Frees an RzSyscall type
 */
RZ_API void rz_syscall_free(RzSyscall *s) {
	if (s) {
		if (s->refs > 0) {
			s->refs--;
			return;
		}
		sdb_free(s->db);
		free(s->os);
		free(s->cpu);
		free(s->arch);
		rz_sysregs_db_free(s->srdb);
		free(s);
	}
}

/**
 * \brief Frees an RzSysregItem type
 */
RZ_API void rz_sysreg_item_free(RzSysregItem *s) {
	if (!s) {
		return;
	}
	free(s->comment);
	free(s->name);
	free(s->type);
	free(s);
}

static bool load_sdb(Sdb **db, const char *name) {
	rz_return_val_if_fail(db, false);
	char *sdb_path = rz_path_system(RZ_SDB);
	char *file_name = rz_str_newf("%s.sdb", name);
	char *file = rz_file_path_join(sdb_path, file_name);
	free(file_name);
	free(sdb_path);
	if (rz_file_exists(file)) {
		if (*db) {
			sdb_reset(*db);
			sdb_open(*db, file);
		} else {
			*db = sdb_new(0, file, 0);
		}
		free(file);
		return true;
	}
	free(file);
	return false;
}

static inline bool syscall_reload_needed(RzSyscall *s, const char *os, const char *arch, int bits) {
	if (!s->os || strcmp(s->os, os)) {
		return true;
	}
	if (!s->arch || strcmp(s->arch, arch)) {
		return true;
	}
	return s->bits != bits;
}

static inline bool sysregs_reload_needed(RzSyscall *s, const char *arch, int bits, const char *cpu) {
	if (!s->arch || strcmp(s->arch, arch)) {
		return true;
	}
	if (s->bits != bits) {
		return true;
	}
	return !s->cpu || strcmp(s->cpu, cpu);
}

static bool sdb_load_sysregs(RzSysregsDB *sysregdb, Sdb *sdb) {
	rz_return_val_if_fail(sysregdb && sdb, false);

	void **iter;
	RzPVector *items = sdb_get_items(sdb, false);
	rz_pvector_foreach (items, iter) {
		SdbKv *kv = *iter;
		if (!strcmp(sdbkv_value(kv), "mmio") || !strcmp(sdbkv_value(kv), "reg")) {
			const char *name = sdbkv_key(kv);
			RzSysregItem *sysregitem = rz_sysreg_item_new(name);
			char *argument_key = rz_str_newf("%s.address", name);
			if (!argument_key) {
				rz_sysreg_item_free(sysregitem);
				return false;
			}
			ut64 address = sdb_num_get(sdb, argument_key);
			free(argument_key);
			if (!address) {
				rz_sysreg_item_free(sysregitem);
				return false;
			}

			argument_key = rz_str_newf("%s.comment", name);
			char *comment = sdb_get(sdb, argument_key);
			free(argument_key);
			sysregitem->type = sdbkv_dup_value(kv);
			sysregitem->comment = comment;

			ht_up_insert(sysregdb->port, address, sysregitem);
		}
	}
	rz_pvector_free(items);
	return true;
}

static bool sdb_load_by_path(RZ_NONNULL RzSysregsDB *sysregdb, const char *path) {
	Sdb *db = sdb_new(0, path, 0);
	bool result = sdb_load_sysregs(sysregdb, db);
	sdb_close(db);
	sdb_free(db);
	return result;
}

/**
 * \brief Loads the RzSysregDB from the path to the hashtable
 *
 * \param s reference to RzSysregDB
 * \param path reference to path of the SDB file
 */
RZ_API bool rz_sysreg_load_sdb(RzSysregsDB *sysregdb, const char *path) {
	if (!rz_file_exists(path) || !sysregdb) {
		return false;
	}
	return sdb_load_by_path(sysregdb, path);
}

/**
 * \brief Sets the architecture for sysregs during analysis and
 * 		  loads up the sysregs SDB database
 *
 * \param s reference to RzSyscall
 * \param arch reference to value of asm.arch
 * \param regs_dir path where registers SDB files are located
 */
RZ_API bool rz_sysreg_set_arch(RzSyscall *s, RZ_NONNULL const char *arch, RZ_NONNULL const char *regs_dir) {
	rz_return_val_if_fail(s && regs_dir && arch, false);

	char buf[60];
	char *path = rz_file_path_join(regs_dir, rz_strf(buf, "%s-%s-%d.sdb", arch, s->cpu, s->bits));
	if (!path) {
		return true;
	}
	rz_sysregs_db_free(s->srdb);
	s->srdb = rz_sysregs_db_new();
	if (!rz_sysreg_load_sdb(s->srdb, path)) {
		free(path);
		rz_sysregs_db_free(s->srdb);
		s->srdb = rz_sysregs_db_new();
		return false;
	}
	free(path);
	return true;
}

// TODO: should be renamed to rz_syscall_use();
RZ_API bool rz_syscall_setup(RzSyscall *s, const char *arch, int bits, const char *cpu, const char *os) {
	bool syscall_changed, sysregs_changed;

	if (!os || !*os) {
		os = RZ_SYS_OS;
	}
	if (!arch) {
		arch = RZ_SYS_ARCH;
	}
	if (!cpu) {
		cpu = arch;
	}
	syscall_changed = syscall_reload_needed(s, os, arch, bits);
	sysregs_changed = sysregs_reload_needed(s, arch, bits, cpu);

	free(s->os);
	s->os = rz_str_dup(os);

	free(s->cpu);
	s->cpu = rz_str_dup(cpu);

	free(s->arch);
	s->arch = rz_str_dup(arch);

	s->bits = bits;

	if (!strcmp(os, "any")) { // ignored
		return true;
	} else if (!strcmp(os, "darwin") || !strcmp(os, "osx") || !strcmp(os, "macos")) {
		os = "darwin";
	}

	if (syscall_changed) {
		char *dbName = rz_str_newf(RZ_JOIN_2_PATHS("syscall", "%s-%s-%d"),
			os, arch, bits);
		if (dbName) {
			if (!load_sdb(&s->db, dbName)) {
				sdb_free(s->db);
				s->db = NULL;
			}
			free(dbName);
		}
	}

	if (sysregs_changed) {
		char *regs_dir = rz_path_system(RZ_SDB_REG);
		rz_sysreg_set_arch(s, arch, regs_dir);
		free(regs_dir);
	}
	if (s->fd) {
		fclose(s->fd);
		s->fd = NULL;
	}
	return true;
}

RZ_API RzSyscallItem *rz_syscall_item_new_from_string(const char *name, const char *s) {
	RzSyscallItem *si;
	char *o;
	if (!name || !s) {
		return NULL;
	}
	o = rz_str_dup(s);
	int cols = rz_str_split(o, ',');
	if (cols < 3) {
		free(o);
		return NULL;
	}

	si = RZ_NEW0(RzSyscallItem);
	if (!si) {
		free(o);
		return NULL;
	}
	si->name = rz_str_dup(name);
	si->swi = (int)rz_num_get(NULL, rz_str_word_get0(o, 0));
	si->num = (int)rz_num_get(NULL, rz_str_word_get0(o, 1));
	si->args = (int)rz_num_get(NULL, rz_str_word_get0(o, 2));
	si->sargs = calloc(si->args + 1, sizeof(char));
	if (!si->sargs) {
		free(si);
		free(o);
		return NULL;
	}
	if (cols > 3) {
		strncpy(si->sargs, rz_str_word_get0(o, 3), si->args);
	}
	free(o);
	return si;
}

RZ_API void rz_syscall_item_free(RzSyscallItem *si) {
	if (!si) {
		return;
	}
	free(si->name);
	free(si->sargs);
	free(si);
}

static int getswi(RzSyscall *s, int swi) {
	if (s && swi == -1) {
		return rz_syscall_get_swi(s);
	}
	return swi;
}

RZ_API int rz_syscall_get_swi(RzSyscall *s) {
	return (int)sdb_num_get(s->db, "_");
}

RZ_API RzSyscallItem *rz_syscall_get(RzSyscall *s, int num, int swi) {
	rz_return_val_if_fail(s, NULL);
	if (!s->db) {
		return NULL;
	}
	const char *ret, *ret2, *key;
	char tmpbuf[64] = { 0 };
	swi = getswi(s, swi);
	if (swi < 16) {
		key = rz_strf(tmpbuf, "%d.%d", swi, num);
	} else {
		key = rz_strf(tmpbuf, "0x%02x.%d", swi, num);
	}
	ret = sdb_const_get(s->db, key);
	if (!ret) {
		key = rz_strf(tmpbuf, "0x%02x.0x%02x", swi, num); // Workaround until Syscall SDB is fixed
		ret = sdb_const_get(s->db, key);
		if (!ret) {
			key = rz_strf(tmpbuf, "0x%02x.%d", num, swi); // Workaround until Syscall SDB is fixed
			ret = sdb_const_get(s->db, key);
			if (!ret) {
				return NULL;
			}
		}
	}
	ret2 = sdb_const_get(s->db, ret);
	if (!ret2) {
		return NULL;
	}
	return rz_syscall_item_new_from_string(ret, ret2);
}

RZ_API int rz_syscall_get_num(RzSyscall *s, const char *str) {
	rz_return_val_if_fail(s && str, -1);
	if (!s->db) {
		return -1;
	}
	int sn = (int)sdb_array_get_num(s->db, str, 1);
	if (sn == 0) {
		return (int)sdb_array_get_num(s->db, str, 0);
	}
	return sn;
}

RZ_API const char *rz_syscall_get_i(RzSyscall *s, int num, int swi) {
	rz_return_val_if_fail(s, NULL);
	if (!s->db) {
		return NULL;
	}
	char foo[32];
	swi = getswi(s, swi);
	snprintf(foo, sizeof(foo), "0x%x.%d", swi, num);
	return sdb_const_get(s->db, foo);
}

static bool callback_list(void *u, const SdbKv *kv) {
	RzList *list = (RzList *)u;
	if (!strchr(sdbkv_key(kv), '.')) {
		RzSyscallItem *si = rz_syscall_item_new_from_string(sdbkv_key(kv), sdbkv_value(kv));
		if (!si) {
			return true;
		}
		if (!strchr(si->name, '.')) {
			rz_list_append(list, si);
		} else {
			rz_syscall_item_free(si);
		}
	}
	return true; // continue loop
}

RZ_API RzList /*<RzSyscallItem *>*/ *rz_syscall_list(RzSyscall *s) {
	rz_return_val_if_fail(s, NULL);
	if (!s->db) {
		return NULL;
	}
	RzList *list = rz_list_newf((RzListFree)rz_syscall_item_free);
	sdb_foreach(s->db, callback_list, list);
	return list;
}

/**
 * \brief Searches the sysregs SDB database inside librz/reg/d for the type (mmio/reg) and
 * 		  returns its value as a string
 *
 * \param s reference to RzSyscall
 * \param type reference to the type of key: mmio/reg
 * \param port reference to the io port
 */
RZ_API const char *rz_sysreg_get(RzSyscall *s, const char *type, ut64 port) {
	rz_return_val_if_fail(s, NULL);
	if (!s->srdb) {
		return NULL;
	}
	RzSysregItem *item = ht_up_find(s->srdb->port, port, NULL);
	if (item && !strcmp(item->type, type)) {
		return item->comment;
	}
	return NULL;
}
