// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_syscall.h>
#include <stdio.h>
#include <string.h>

RZ_LIB_VERSION(rz_syscall);

// TODO: now we use sdb
extern RzSyscallPort sysport_x86[];
extern RzSyscallPort sysport_avr[];

RZ_API RzSyscall *rz_syscall_ref(RzSyscall *sc) {
	sc->refs++;
	return sc;
}

RZ_API RzSyscall *rz_syscall_new(void) {
	RzSyscall *rs = RZ_NEW0(RzSyscall);
	if (rs) {
		rs->sysport = sysport_x86;
		rs->srdb = sdb_new0(); // sysregs database
		rs->db = sdb_new0();
	}
	return rs;
}

RZ_API void rz_syscall_free(RzSyscall *s) {
	if (s) {
		if (s->refs > 0) {
			s->refs--;
			return;
		}
		sdb_free(s->srdb);
		sdb_free(s->db);
		free(s->os);
		free(s->cpu);
		free(s->arch);
		free(s);
	}
}

static bool load_sdb(Sdb **db, const char *name) {
	rz_return_val_if_fail(db, false);
	char *sdb_path = rz_str_rz_prefix(RZ_SDB);
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
	s->os = strdup(os);

	free(s->cpu);
	s->cpu = strdup(cpu);

	free(s->arch);
	s->arch = strdup(arch);

	s->bits = bits;

	if (!strcmp(os, "any")) { // ignored
		return true;
	}
	if (!strcmp(arch, "avr")) {
		s->sysport = sysport_avr;
	} else if (!strcmp(os, "darwin") || !strcmp(os, "osx") || !strcmp(os, "macos")) {
		os = "darwin";
	} else if (!strcmp(arch, "x86")) {
		s->sysport = sysport_x86;
	}

	if (syscall_changed) {
		char *dbName = rz_str_newf(RZ_JOIN_2_PATHS("syscall", "%s-%s-%d"),
			os, arch, bits);
		if (dbName) {
			if (!load_sdb(&s->db, dbName)) {
				sdb_free(s->db);
#if __FreeBSD__
				s->db = sdb_new0();
#else
				s->db = NULL;
#endif
			}
			free(dbName);
		}
	}

	if (sysregs_changed) {
		char *dbName = rz_str_newf(RZ_JOIN_2_PATHS("sysregs", "%s-%d-%s"),
			arch, bits, cpu);
		if (dbName) {
			if (!load_sdb(&s->srdb, dbName)) {
				sdb_free(s->srdb);
#if __FreeBSD__
				s->srdb = sdb_new0();
#else
				s->srdb = NULL;
#endif
			}
			free(dbName);
		}
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
	o = strdup(s);
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
	si->name = strdup(name);
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
	return (int)sdb_num_get(s->db, "_", NULL);
}

RZ_API RzSyscallItem *rz_syscall_get(RzSyscall *s, int num, int swi) {
	rz_return_val_if_fail(s, NULL);
	if (!s->db) {
		return NULL;
	}
	const char *ret, *ret2, *key;
	swi = getswi(s, swi);
	if (swi < 16) {
		key = sdb_fmt("%d.%d", swi, num);
	} else {
		key = sdb_fmt("0x%02x.%d", swi, num);
	}
	ret = sdb_const_get(s->db, key, 0);
	if (!ret) {
		key = sdb_fmt("0x%02x.0x%02x", swi, num); // Workaround until Syscall SDB is fixed
		ret = sdb_const_get(s->db, key, 0);
		if (!ret) {
			key = sdb_fmt("0x%02x.%d", num, swi); // Workaround until Syscall SDB is fixed
			ret = sdb_const_get(s->db, key, 0);
			if (!ret) {
				return NULL;
			}
		}
	}
	ret2 = sdb_const_get(s->db, ret, 0);
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
	int sn = (int)sdb_array_get_num(s->db, str, 1, NULL);
	if (sn == 0) {
		return (int)sdb_array_get_num(s->db, str, 0, NULL);
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
	return sdb_const_get(s->db, foo, 0);
}

static bool callback_list(void *u, const char *k, const char *v) {
	RzList *list = (RzList *)u;
	if (!strchr(k, '.')) {
		RzSyscallItem *si = rz_syscall_item_new_from_string(k, v);
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

RZ_API RzList *rz_syscall_list(RzSyscall *s) {
	rz_return_val_if_fail(s, NULL);
	if (!s->db) {
		return NULL;
	}
	RzList *list = rz_list_newf((RzListFree)rz_syscall_item_free);
	sdb_foreach(s->db, callback_list, list);
	return list;
}

/* io and sysregs */
RZ_API const char *rz_syscall_get_io(RzSyscall *s, int ioport) {
	rz_return_val_if_fail(s, NULL);
	int i;
	const char *name = rz_syscall_sysreg(s, "io", ioport);
	if (name) {
		return name;
	}
	for (i = 0; s->sysport[i].name; i++) {
		if (ioport == s->sysport[i].port) {
			return s->sysport[i].name;
		}
	}
	return NULL;
}

RZ_API const char *rz_syscall_sysreg(RzSyscall *s, const char *type, ut64 num) {
	rz_return_val_if_fail(s, NULL);
	if (!s->db) {
		return NULL;
	}
	const char *key = sdb_fmt("%s,%" PFMT64d, type, num);
	return sdb_const_get(s->db, key, 0);
}
