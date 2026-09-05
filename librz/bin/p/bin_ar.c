// SPDX-FileCopyrightText: 2026 Karna
// SPDX-License-Identifier: LGPL-3.0-only

// Unix `ar` archive RzBin plugin.
//
// Parses the common-format `ar` archive (as produced by GNU binutils `ar`
// and used for static libraries, `.a` files) well enough to map every
// member's raw bytes linearly into memory. This is useful for commands
// that only need the raw bytes of the contained object files (e.g.
// function-prologue based detection), without requiring a full per-object
// bin plugin (ELF/Mach-O/COFF) to be loaded for each member.
//
// References:
// https://en.wikipedia.org/wiki/Ar_(Unix)
// https://www.freebsd.org/cgi/man.cgi?query=ar&sektion=5

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define AR_MAGIC       "!<arch>\n"
#define AR_MAGIC_SIZE  8
#define AR_HDR_SIZE    60
#define AR_HDR_END0    0x60
#define AR_HDR_END1    0x0a
#define AR_NAME_SIZE   16
#define AR_SIZE_SIZE   10
#define AR_SIZE_OFF    48
#define AR_EXT_NAME_ID "//"
#define AR_SYM_NAME_ID "/"
#define AR_BSD_EXT_PFX "#1/"

typedef struct ar_member_t {
	char *name; ///< resolved member (file) name
	ut64 hdr_paddr; ///< offset of the 60 byte ar header for this member
	ut64 paddr; ///< offset of the raw data for this member (after any BSD extended name)
	ut64 size; ///< size in bytes of the raw data for this member
	ut64 vaddr; ///< linear virtual address this member is mapped to
	const char *arch; ///< best-effort detected architecture, may be NULL
	int bits;
	bool big_endian;
	bool arch_detected;
} ArMember;

typedef struct ar_obj_t {
	RzPVector /*<ArMember *>*/ members;
	char *extended_names; ///< GNU extended filename table (member "//"), if present
	ut64 extended_names_size;
	bool has_symtab;
	bool any_arch_detected;
	bool arch_mismatch;
	const char *arch;
	int bits;
	bool big_endian;
} ArObj;

static void ar_member_free(void *p) {
	ArMember *m = (ArMember *)p;
	if (!m) {
		return;
	}
	free(m->name);
	free(m);
}

static void ar_obj_free(ArObj *o) {
	if (!o) {
		return;
	}
	rz_pvector_fini(&o->members);
	free(o->extended_names);
	free(o);
}

static void ar_destroy(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return;
	}
	ar_obj_free((ArObj *)bf->o->bin_obj);
	bf->o->bin_obj = NULL;
}

static bool ar_check_buffer(RzBuffer *buf) {
	rz_return_val_if_fail(buf, false);
	ut8 magic[AR_MAGIC_SIZE];
	if (rz_buf_read_at(buf, 0, magic, sizeof(magic)) != sizeof(magic)) {
		return false;
	}
	return !memcmp(magic, AR_MAGIC, AR_MAGIC_SIZE);
}

static bool ar_check_filename(const char *filename) {
	return rz_str_endswith_icase(filename, ".a");
}

/// Parse an ASCII decimal field of \p len bytes (space padded) into a ut64.
static ut64 ar_parse_decimal(const char *field, size_t len) {
	char tmp[32] = { 0 };
	size_t n = RZ_MIN(len, sizeof(tmp) - 1);
	memcpy(tmp, field, n);
	// trim trailing spaces
	for (size_t i = n; i > 0 && (tmp[i - 1] == ' ' || tmp[i - 1] == '\0'); i--) {
		tmp[i - 1] = 0;
	}
	rz_str_trim(tmp);
	if (!*tmp) {
		return 0;
	}
	return (ut64)strtoull(tmp, NULL, 10);
}

/// Resolve a raw 16-byte ar header name field into a proper member name.
/// Handles GNU short names ("name/"), GNU long names via the "//" extended
/// name table ("/123"), and leaves BSD "#1/N" names as-is (resolved later
/// once the member data, which holds the actual name, is available).
static char *ar_resolve_name(const ArObj *o, const char *raw_name) {
	char tmp[AR_NAME_SIZE + 1] = { 0 };
	memcpy(tmp, raw_name, AR_NAME_SIZE);
	// trim trailing spaces first (BSD-style short names are space padded)
	for (int i = AR_NAME_SIZE - 1; i >= 0 && tmp[i] == ' '; i--) {
		tmp[i] = 0;
	}

	if (!strncmp(tmp, AR_BSD_EXT_PFX, strlen(AR_BSD_EXT_PFX))) {
		// BSD extended name, resolved from the member data by the caller.
		return rz_str_dup(tmp);
	}

	if (tmp[0] == '/' && (isdigit((ut8)tmp[1]) || tmp[1] == '\0')) {
		// GNU long name: "/<offset>" into the extended name table.
		if (!o->extended_names || tmp[1] == '\0') {
			return rz_str_dup(tmp);
		}
		ut64 off = (ut64)strtoull(tmp + 1, NULL, 10);
		if (off >= o->extended_names_size) {
			return rz_str_dup(tmp);
		}
		const char *start = o->extended_names + off;
		const char *end = memchr(start, '\n', o->extended_names_size - off);
		size_t len = end ? (size_t)(end - start) : strlen(start);
		// GNU long names are terminated with "/\n"
		if (len > 0 && start[len - 1] == '/') {
			len--;
		}
		return rz_str_ndup(start, len);
	}

	// GNU short name, terminated by a trailing '/'
	size_t len = strlen(tmp);
	if (len > 0 && tmp[len - 1] == '/') {
		tmp[len - 1] = 0;
	}
	return rz_str_dup(tmp);
}

static bool ar_name_is_symtab(const char *raw_name) {
	// GNU symbol table ("/") and its 64-bit variant ("/SYM64/"), and the
	// BSD ranlib symbol table ("__.SYMDEF" or "__.SYMDEF SORTED").
	if (!strncmp(raw_name, "/ ", 2) || !strncmp(raw_name, "/SYM64/", 7)) {
		return true;
	}
	if (!strncmp(raw_name, "__.SYMDEF", 9)) {
		return true;
	}
	return false;
}

static bool ar_name_is_ext_table(const char *raw_name) {
	return !strncmp(raw_name, AR_EXT_NAME_ID, strlen(AR_EXT_NAME_ID));
}

/// Best-effort architecture detection by peeking at the magic of the raw
/// object bytes. Mirrors the way fat Mach-O binaries bundle multiple
/// architectures: if members disagree, we keep the first one found and
/// flag the mismatch rather than failing to load the archive.
static bool ar_detect_arch(RzBuffer *buf, ut64 paddr, ut64 size, const char **arch, int *bits, bool *big_endian) {
	if (size < 20) {
		return false;
	}
	ut8 hdr[20] = { 0 };
	if (rz_buf_read_at(buf, paddr, hdr, sizeof(hdr)) != sizeof(hdr)) {
		return false;
	}

	// ELF: \x7fELF
	if (hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F') {
		*bits = hdr[4] == 2 ? 64 : 32;
		*big_endian = hdr[5] == 2;
		ut16 machine = *big_endian
			? (ut16)((hdr[18] << 8) | hdr[19])
			: (ut16)(hdr[18] | (hdr[19] << 8));
		switch (machine) {
		case 3: *arch = "x86"; break; // EM_386
		case 62: *arch = "x86"; break; // EM_X86_64
		case 40: *arch = "arm"; break; // EM_ARM
		case 183: *arch = "arm"; break; // EM_AARCH64
		case 8: *arch = "mips"; break; // EM_MIPS
		case 20: *arch = "ppc"; break; // EM_PPC
		case 21: *arch = "ppc"; break; // EM_PPC64
		case 243: *arch = "riscv"; break; // EM_RISCV
		default: *arch = NULL; break; // recognized as ELF, but unmapped machine
		}
		return true;
	}

	// Mach-O (32/64, either endianness)
	ut32 magic = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16) | (hdr[3] << 24);
	if (magic == 0xfeedface || magic == 0xfeedfacf ||
		magic == 0xcefaedfe || magic == 0xcffaedfe) {
		bool be = (magic == 0xcefaedfe || magic == 0xcffaedfe);
		*big_endian = be;
		*bits = (magic == 0xfeedfacf || magic == 0xcffaedfe) ? 64 : 32;
		ut32 cputype = be
			? (ut32)((hdr[4] << 24) | (hdr[5] << 16) | (hdr[6] << 8) | hdr[7])
			: (ut32)(hdr[4] | (hdr[5] << 8) | (hdr[6] << 16) | (hdr[7] << 24));
		switch (cputype & ~0x01000000u) {
		case 7: *arch = "x86"; break; // CPU_TYPE_X86 / X86_64
		case 12: *arch = "arm"; break; // CPU_TYPE_ARM / ARM64
		default: *arch = NULL; break; // recognized as Mach-O, but unmapped cputype
		}
		return true;
	}

	return false;
}

static bool ar_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && buf, false);

	ut64 size = rz_buf_size(buf);
	if (size < AR_MAGIC_SIZE) {
		return false;
	}

	ArObj *o = RZ_NEW0(ArObj);
	if (!o) {
		return false;
	}
	rz_pvector_init(&o->members, ar_member_free);
	obj->bin_obj = o;

	ut64 off = AR_MAGIC_SIZE;
	ut64 vaddr_cursor = 0;

	while (off + AR_HDR_SIZE <= size) {
		ut8 hdr[AR_HDR_SIZE];
		if (rz_buf_read_at(buf, off, hdr, AR_HDR_SIZE) != AR_HDR_SIZE) {
			break;
		}
		if (hdr[AR_HDR_SIZE - 2] != AR_HDR_END0 || hdr[AR_HDR_SIZE - 1] != AR_HDR_END1) {
			// Not a valid header terminator: stop parsing here but keep
			// whatever members we already found.
			RZ_LOG_WARN("bin.ar: malformed member header at 0x%" PFMT64x ", stopping\n", off);
			break;
		}

		char raw_name[AR_NAME_SIZE + 1] = { 0 };
		memcpy(raw_name, hdr, AR_NAME_SIZE);
		ut64 data_size = ar_parse_decimal((const char *)hdr + AR_SIZE_OFF, AR_SIZE_SIZE);
		ut64 data_off = off + AR_HDR_SIZE;

		if (data_off + data_size > size) {
			RZ_LOG_WARN("bin.ar: member '%s' size overflows the archive, truncating\n", raw_name);
			data_size = data_size > size - data_off ? size - data_off : data_size;
		}

		if (ar_name_is_ext_table(raw_name)) {
			free(o->extended_names);
			o->extended_names = malloc(data_size + 1);
			if (o->extended_names) {
				rz_buf_read_at(buf, data_off, (ut8 *)o->extended_names, data_size);
				o->extended_names[data_size] = 0;
				o->extended_names_size = data_size;
			}
		} else if (ar_name_is_symtab(raw_name)) {
			o->has_symtab = true;
		} else {
			ArMember *m = RZ_NEW0(ArMember);
			if (!m) {
				break;
			}
			m->hdr_paddr = off;
			m->paddr = data_off;
			m->size = data_size;
			m->name = ar_resolve_name(o, raw_name);

			// Resolve BSD extended names: "#1/<len>" means the first <len>
			// bytes of the member data are the name itself.
			if (m->name && !strncmp(m->name, AR_BSD_EXT_PFX, strlen(AR_BSD_EXT_PFX))) {
				ut64 name_len = (ut64)strtoull(m->name + strlen(AR_BSD_EXT_PFX), NULL, 10);
				if (name_len > 0 && name_len <= m->size) {
					char *real_name = malloc(name_len + 1);
					if (real_name) {
						rz_buf_read_at(buf, m->paddr, (ut8 *)real_name, name_len);
						real_name[name_len] = 0;
						rz_str_trim(real_name);
						free(m->name);
						m->name = real_name;
					}
					m->paddr += name_len;
					m->size -= name_len;
				}
			}
			if (!m->name || !*m->name) {
				free(m->name);
				m->name = rz_str_newf("member_%" PFMT64u, (ut64)rz_pvector_len(&o->members));
			}

			if (ar_detect_arch(buf, m->paddr, m->size, &m->arch, &m->bits, &m->big_endian)) {
				m->arch_detected = true;
				if (!o->any_arch_detected) {
					o->any_arch_detected = true;
					o->arch = m->arch;
					o->bits = m->bits;
					o->big_endian = m->big_endian;
				} else if (o->arch && m->arch && strcmp(o->arch, m->arch) != 0) {
					o->arch_mismatch = true;
				}
			}

			m->vaddr = vaddr_cursor;
			vaddr_cursor += m->size;
			// keep members 16-byte aligned in the virtual mapping, similar
			// in spirit to how fat Mach-O slices are aligned.
			if (vaddr_cursor % 16) {
				vaddr_cursor += 16 - (vaddr_cursor % 16);
			}

			rz_pvector_push(&o->members, m);
		}

		off = data_off + data_size;
		if (off % 2) {
			// members are padded to an even offset
			off++;
		}
	}

	if (rz_pvector_empty(&o->members)) {
		RZ_LOG_WARN("bin.ar: archive '%s' unpacked but no object members were found in it\n", bf->file);
	} else if (!o->any_arch_detected) {
		RZ_LOG_WARN("bin.ar: could not detect an object file format inside any member of '%s'\n", bf->file);
	} else if (o->arch_mismatch) {
		RZ_LOG_WARN("bin.ar: archive '%s' contains members of different architectures\n", bf->file);
	}

	return true;
}

static ut64 ar_baddr(RzBinFile *bf) {
	return 0;
}

static RzPVector /*<RzBinMap *>*/ *ar_maps(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	ArObj *o = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	void **it;
	rz_pvector_foreach (&o->members, it) {
		ArMember *m = *it;
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			break;
		}
		map->name = rz_str_dup(m->name);
		map->paddr = m->paddr;
		map->psize = m->size;
		map->vaddr = m->vaddr;
		map->vsize = m->size;
		map->perm = RZ_PERM_RX;
		rz_pvector_push(ret, map);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *ar_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	ArObj *o = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	void **it;
	rz_pvector_foreach (&o->members, it) {
		ArMember *m = *it;
		RzBinSection *s = rz_bin_section_new(m->name);
		if (!s) {
			break;
		}
		s->paddr = m->paddr;
		s->vaddr = m->vaddr;
		s->size = m->size;
		s->vsize = m->size;
		s->perm = RZ_PERM_RX;
		s->is_segment = true;
		s->arch = m->arch_detected ? m->arch : NULL;
		s->bits = m->arch_detected ? m->bits : 0;
		rz_pvector_push(ret, s);
	}
	return ret;
}

static RzBinInfo *ar_info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	ArObj *o = bf->o->bin_obj;

	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("ar archive");
	ret->bclass = rz_str_dup("archive");
	ret->rclass = rz_str_dup("ar");
	ret->os = rz_str_dup("any");
	ret->subsystem = rz_str_dup("unknown");
	// Leave arch/machine unset (NULL) when no member's format could be
	// detected: an empty string is treated by RzCore as "no arch to
	// switch to", whereas a bogus placeholder name (e.g. "any") would
	// make rz_asm_use() fail and print a spurious error on file open.
	ret->machine = o->any_arch_detected ? rz_str_dup(o->arch) : NULL;
	ret->arch = o->any_arch_detected ? rz_str_dup(o->arch) : NULL;
	ret->bits = o->any_arch_detected ? o->bits : 32;
	ret->big_endian = o->big_endian;
	ret->has_va = true;
	ret->dbg_info = RZ_BIN_DBG_STRIPPED;
	return ret;
}

static RzStructuredData *ar_bin_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	ArObj *o = bf->o->bin_obj;

	RzStructuredData *sd = rz_structured_data_new_map();
	if (!sd) {
		return NULL;
	}
	rz_structured_data_map_add_unsigned(sd, "members_count", rz_pvector_len(&o->members), false);
	rz_structured_data_map_add_string(sd, "has_symbol_table", o->has_symtab ? "true" : "false");
	rz_structured_data_map_add_string(sd, "arch_mismatch", o->arch_mismatch ? "true" : "false");

	RzStructuredData *members = rz_structured_data_map_add_array(sd, "members");
	if (!members) {
		return sd;
	}
	void **it;
	rz_pvector_foreach (&o->members, it) {
		ArMember *m = *it;
		RzStructuredData *e = rz_structured_data_array_add_map(members);
		if (!e) {
			continue;
		}
		rz_structured_data_map_add_string(e, "name", m->name);
		rz_structured_data_map_add_unsigned(e, "offset", m->paddr, true);
		rz_structured_data_map_add_unsigned(e, "size", m->size, false);
		rz_structured_data_map_add_string(e, "arch", m->arch_detected ? m->arch : "unknown");
	}
	return sd;
}

RzBinPlugin rz_bin_plugin_ar = {
	.name = "ar",
	.desc = "Unix ar archive (static library)",
	.author = "Karna",
	.license = "LGPL3",
	.load_buffer = &ar_load_buffer,
	.destroy = &ar_destroy,
	.check_buffer = &ar_check_buffer,
	.check_filename = &ar_check_filename,
	.baddr = &ar_baddr,
	.maps = &ar_maps,
	.sections = &ar_sections,
	.info = &ar_info,
	.bin_structure = &ar_bin_structure,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_ar,
	.version = RZ_VERSION
};
#endif
