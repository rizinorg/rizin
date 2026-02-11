// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2014-2019 LemonBoy <thatlemon@gmail.com>
// SPDX-FileCopyrightText: 2014-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>
#include "../format/xbe/xbe.h"

static const char *kt_name[] = {
#include "../format/xbe/kernel.h"
};

typedef struct {
	ut32 bit;
	const char *name;
} XbeFlagDesc;

static const XbeFlagDesc xbe_section_flags[] = {
	{ SECTION_WRITEABLE, "WRITE" },
	{ SECTION_PRELOAD, "PRELOAD" },
	{ SECTION_EXECUTABLE, "EXEC" },
	{ SECTION_INSERTFILE, "INSERT" },
	{ SECTION_HEAD_PAGE_READONLY, "HEAD_READONLY" },
	{ SECTION_TAIL_PAGE_READONLY, "TAIL_READONLY" },
};

static bool read_xbe_header(xbe_header *hdr, RzBuffer *b, ut64 off) {
	if (rz_buf_read_at(b, off, hdr->magic, sizeof(hdr->magic)) != sizeof(hdr->magic) ||
		rz_buf_read_at(b, off + 4, hdr->signature, sizeof(hdr->signature)) != sizeof(hdr->signature) ||
		!rz_buf_read_le32_at(b, off + 0x104, &hdr->base) ||
		!rz_buf_read_le32_at(b, off + 0x104 + sizeof(ut32), &hdr->headers_size) ||
		!rz_buf_read_le32_at(b, off + 0x104 + sizeof(ut32) * 2, &hdr->image_size) ||
		!rz_buf_read_le32_at(b, off + 0x104 + sizeof(ut32) * 3, &hdr->image_header_size) ||
		!rz_buf_read_le32_at(b, off + 0x104 + sizeof(ut32) * 4, &hdr->timestamp) ||
		!rz_buf_read_le32_at(b, off + 0x104 + sizeof(ut32) * 5, &hdr->cert_addr) ||
		!rz_buf_read_le32_at(b, off + 0x104 + sizeof(ut32) * 6, &hdr->sections) ||
		!rz_buf_read_le32_at(b, off + 0x104 + sizeof(ut32) * 7, &hdr->sechdr_addr) ||
		!rz_buf_read_le32_at(b, off + 0x104 + sizeof(ut32) * 8, &hdr->init_flags) ||
		!rz_buf_read_le32_at(b, off + 0x104 + sizeof(ut32) * 9, &hdr->ep) ||
		!rz_buf_read_le32_at(b, off + 0x104 + sizeof(ut32) * 10, &hdr->tls_addr)) {
		return false;
	}
	off += 0x104 + sizeof(ut32) * 11;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(hdr->pe_data); i++) {
		if (!rz_buf_read_le32_at(b, off, &hdr->pe_data[i])) {
			return false;
		}
		off += sizeof(ut32);
	}
	return rz_buf_read_le32_at(b, off, &hdr->debug_path_addr) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32), &hdr->debug_name_addr) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 2, &hdr->debug_uname_addr) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 3, &hdr->kernel_thunk_addr) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 4, &hdr->nonkernel_import_dir_addr) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 5, &hdr->lib_versions) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 6, &hdr->lib_versions_addr) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 7, &hdr->kernel_lib_addr) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 8, &hdr->xapi_lib_addr) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 9, &hdr->padding[0]) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 10, &hdr->padding[1]);
}

static bool read_xbe_section(xbe_section *sect, RzBuffer *b, ut64 off) {
	return rz_buf_read_le32_at(b, off, &sect->flags) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32), &sect->vaddr) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 2, &sect->vsize) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 3, &sect->offset) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 4, &sect->size) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 5, &sect->name_addr) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 6, &sect->refcount) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 7, &sect->padding[0]) &&
		rz_buf_read_le32_at(b, off + sizeof(ut32) * 8, &sect->padding[1]) &&
		rz_buf_read_at(b, off + sizeof(ut32) * 9, sect->digest, sizeof(sect->digest)) == sizeof(sect->digest);
}

static bool read_xbe_lib(xbe_lib *lib, RzBuffer *b, ut64 off) {
	return rz_buf_read_at(b, off, lib->name, sizeof(lib->name)) == sizeof(lib->name) &&
		rz_buf_read_le16_at(b, off + 8, &lib->major) &&
		rz_buf_read_le16_at(b, off + 8 + sizeof(ut16), &lib->minor) &&
		rz_buf_read_le16_at(b, off + 8 + sizeof(ut16) * 2, &lib->build) &&
		rz_buf_read_le16_at(b, off + 8 + sizeof(ut16) * 3, &lib->flags);
}

static bool check_buffer(RzBuffer *b) {
	ut8 magic[4];
	if (rz_buf_read_at(b, 0, magic, sizeof(magic)) == 4) {
		return !memcmp(magic, "XBEH", 4);
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *o, RzBuffer *buf, Sdb *sdb) {
	rz_bin_xbe_obj_t *obj = RZ_NEW(rz_bin_xbe_obj_t);
	if (!obj) {
		return false;
	}
	if (!read_xbe_header(&obj->header, buf, 0)) {
		RZ_FREE(obj);
		return false;
	}

	if ((obj->header.ep & 0xf0000000) == 0x40000000) {
		// Sega Chihiro xbe
		obj->ep_key = XBE_EP_CHIHIRO;
		obj->kt_key = XBE_KP_CHIHIRO;
	} else if ((obj->header.ep ^ XBE_EP_RETAIL) > 0x1000000) {
		// Debug xbe
		obj->ep_key = XBE_EP_DEBUG;
		obj->kt_key = XBE_KP_DEBUG;
	} else {
		// Retail xbe
		obj->ep_key = XBE_EP_RETAIL;
		obj->kt_key = XBE_KP_RETAIL;
	}
	o->bin_obj = obj;

	rz_vector_init(&obj->sections, sizeof(xbe_section), NULL, NULL);
	rz_vector_init(&obj->libs, sizeof(xbe_lib), NULL, NULL);

	/* read sections */
	ut32 addr = obj->header.sechdr_addr - obj->header.base;
	for (ut32 i = 0; i < obj->header.sections; i++) {
		xbe_section sec = { 0 };
		if (!read_xbe_section(&sec, buf, addr + i * sizeof(xbe_section))) {
			break;
		}
		rz_vector_push(&obj->sections, &sec);
	}

	/* read libs */
	for (ut32 i = 0; i < obj->header.lib_versions; i++) {
		ut64 addr = obj->header.lib_versions_addr - obj->header.base + i * sizeof(xbe_lib);
		xbe_lib lib = { 0 };
		if (!read_xbe_lib(&lib, buf, addr)) {
			break;
		}
		rz_vector_push(&obj->libs, &lib);
	}

	return true;
}

static void destroy(RzBinFile *bf) {
	rz_bin_xbe_obj_t *obj = bf->o->bin_obj;
	if (!obj) {
		return;
	}
	rz_vector_fini(&obj->sections);
	rz_vector_fini(&obj->libs);
	RZ_FREE(bf->o->bin_obj);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	if (!bf || !bf->buf || type != RZ_BIN_SPECIAL_SYMBOL_MAIN) {
		return NULL;
	}
	rz_bin_xbe_obj_t *obj = bf->o->bin_obj;
	RzBinAddr *ret = RZ_NEW0(RzBinAddr);
	if (!ret) {
		return NULL;
	}
	ret->vaddr = obj->header.ep ^ obj->ep_key;
	ret->paddr = ret->vaddr - obj->header.base;
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	const rz_bin_xbe_obj_t *obj;
	RzPVector *ret;
	RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
	if (!bf || !bf->buf || !bf->o->bin_obj || !ptr) {
		free(ptr);
		return NULL;
	}
	ret = rz_pvector_new(free);
	if (!ret) {
		free(ptr);
		return NULL;
	}
	obj = bf->o->bin_obj;
	ptr->vaddr = obj->header.ep ^ obj->ep_key;
	ptr->paddr = ptr->vaddr - obj->header.base;
	rz_pvector_push(ret, ptr);
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *sections(RzBinFile *bf) {
	rz_bin_xbe_obj_t *obj = NULL;
	xbe_header *h = NULL;
	RzPVector *ret = NULL;
	char tmp[0x100];
	int i, r;
	ut32 addr;

	if (!bf || !bf->o || !bf->o->bin_obj || !bf->buf) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	h = &obj->header;
	if (h->sections < 1) {
		return NULL;
	}
	ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}
	if (h->sections < 1 || h->sections > 255) {
		goto out_error;
	}
	addr = h->sechdr_addr - h->base;
	if (addr > bf->size || addr + (sizeof(xbe_section) * h->sections) > bf->size) {
		goto out_error;
	}
	for (i = 0; i < h->sections; i++) {
		xbe_section sect;
		if (!read_xbe_section(&sect, bf->buf, addr + i * sizeof(xbe_section))) {
			goto out_error;
		}
		RzBinSection *item = RZ_NEW0(RzBinSection);
		ut32 name_addr = sect.name_addr - h->base;
		tmp[0] = 0;
		if (name_addr > bf->size || name_addr + sizeof(tmp) > bf->size) {
			free(item);
			goto out_error;
		}
		r = rz_buf_read_at(bf->buf, name_addr, (ut8 *)tmp, sizeof(tmp));
		if (r < 1) {
			free(item);
			goto out_error;
		}
		tmp[sizeof(tmp) - 1] = 0;
		item->name = rz_str_newf("%s.%i", tmp, i);
		item->paddr = sect.offset;
		item->vaddr = sect.vaddr;
		item->size = sect.size;
		item->vsize = sect.vsize;

		item->perm = RZ_PERM_R;
		if (sect.flags & SECTION_EXECUTABLE) {
			item->perm |= RZ_PERM_X;
		}
		if (sect.flags & SECTION_WRITEABLE) {
			item->perm |= RZ_PERM_W;
		}
		rz_pvector_push(ret, item);
	}
	return ret;
out_error:
	rz_pvector_free(ret);
	return NULL;
}

/**
 * Generate a string like "<LIBNAME> <MAJOR>.<MINOR>.<BUILD>"
 * by reading an xbe_lib at the given offset.
 */
static char *describe_xbe_lib_at(RzBuffer *b, ut64 off, ut64 filesz) {
	if (off + sizeof(xbe_lib) > filesz) {
		return NULL;
	}
	xbe_lib lib;
	if (!read_xbe_lib(&lib, b, off)) {
		return NULL;
	}
	// lib.name may not be 0-terminated
	char name[9];
	RZ_STATIC_ASSERT(sizeof(name) == sizeof(lib.name) + 1);
	memcpy(name, lib.name, sizeof(lib.name));
	name[sizeof(lib.name)] = 0;
	return rz_str_newf("%s %i.%i.%i", name, lib.major, lib.minor, lib.build);
}

static RzPVector /*<char *>*/ *libs(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	rz_bin_xbe_obj_t *obj = bf->o->bin_obj;
	xbe_header *h = &obj->header;
	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	// Hint: h->kernel_lib_addr and h->xapi_lib_addr also point to xbe_lib structs,
	// but in our known samples, they just point into the array below, so no need
	// to check them explicitly.

	for (ut32 i = 0; i < h->lib_versions; i++) {
		ut64 addr = h->lib_versions_addr - h->base + (i * sizeof(xbe_lib));
		char *lib = describe_xbe_lib_at(bf->buf, addr, bf->size);
		if (!lib) {
			break;
		}
		rz_pvector_push(ret, lib);
	}

	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	rz_bin_xbe_obj_t *obj;
	xbe_header *h;
	RzPVector *ret;
	ut32 kt_addr;
	ut32 addr;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	obj = bf->o->bin_obj;
	h = &obj->header;
	kt_addr = h->kernel_thunk_addr ^ obj->kt_key;
	ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}
	int limit = h->sections;
	if (limit * (sizeof(xbe_section)) >= bf->size - h->sechdr_addr) {
		goto out_error;
	}
	xbe_section sect;
	bool found = false;
	for (size_t i = 0; found == false && i < limit; i++) {
		addr = h->sechdr_addr - h->base + (sizeof(xbe_section) * i);
		if (addr > bf->size || addr + sizeof(sect) > bf->size ||
			!read_xbe_section(&sect, bf->buf, addr)) {
			goto out_error;
		}
		if (kt_addr >= sect.vaddr && kt_addr < sect.vaddr + sect.vsize) {
			found = true;
		}
	}
	if (!found) {
		goto out_error;
	}
	addr = sect.offset + (kt_addr - sect.vaddr);
	ut32 thunk_addr[XBE_MAX_THUNK];
	if (addr > bf->size || addr + sizeof(thunk_addr) > bf->size) {
		goto out_error;
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(thunk_addr); i++) {
		if (!rz_buf_read_le32_at(bf->buf, addr + i * sizeof(ut32), &thunk_addr[i])) {
			goto out_error;
		}
	}
	for (size_t i = 0; i < XBE_MAX_THUNK && thunk_addr[i]; i++) {
		RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			goto out_error;
		}
		const ut32 thunk_index = thunk_addr[i] ^ 0x80000000;
		// Basic sanity checks
		if (thunk_addr[i] & 0x80000000 && thunk_index > 0 && thunk_index <= XBE_MAX_THUNK) {
			sym->name = rz_str_newf("kt.%s", kt_name[thunk_index - 1]);
			sym->vaddr = (h->kernel_thunk_addr ^ obj->kt_key) + (4 * i);
			sym->paddr = sym->vaddr - h->base;
			sym->size = 4;
			sym->ordinal = i;
			rz_pvector_push(ret, sym);
		} else {
			free(sym);
		}
	}
	return ret;
out_error:
	rz_pvector_free(ret);
	return NULL;
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_bin_xbe_obj_t *obj;
	RzBinInfo *ret;
	ut8 dbg_name[256];

	if (!bf || !bf->buf) {
		return NULL;
	}

	ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	obj = bf->o->bin_obj;

	memset(dbg_name, 0, sizeof(dbg_name));
	rz_buf_read_at(bf->buf, obj->header.debug_name_addr - obj->header.base, dbg_name, sizeof(dbg_name));
	dbg_name[sizeof(dbg_name) - 1] = 0;
	ret->file = rz_str_dup((char *)dbg_name);
	ret->bclass = rz_str_dup("program");
	ret->machine = rz_str_dup("Microsoft Xbox");
	ret->os = rz_str_dup("xbox");
	ret->type = rz_str_dup("Microsoft Xbox executable");
	ret->arch = rz_str_dup("x86");
	ret->has_va = 1;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	ret->lang = NULL;
	return ret;
}

static char *xbe_section_flags_to_string(ut32 flags) {
	RzStrBuf sb;
	bool first = true;

	rz_strbuf_init(&sb);

	if (flags == 0) {
		rz_strbuf_set(&sb, "NONE");
		return rz_strbuf_drain_nofree(&sb);
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(xbe_section_flags); i++) {
		if (flags & xbe_section_flags[i].bit) {
			if (!first) {
				rz_strbuf_append(&sb, " | ");
			}
			rz_strbuf_append(&sb, xbe_section_flags[i].name);
			first = false;
		}
	}

	if (first) {
		rz_strbuf_set(&sb, "UNKNOWN");
	}

	return rz_strbuf_drain_nofree(&sb);
}

static RzStructuredData *xbe_sections_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	rz_bin_xbe_obj_t *obj = bf->o->bin_obj;

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	xbe_section *sec;
	rz_vector_foreach (&obj->sections, sec) {
		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}
		RzStructuredData *flags_map = rz_structured_data_map_add_map(m, "flags");
		if (!flags_map) {
			rz_structured_data_free(m);
			rz_structured_data_free(arr);
			return NULL;
		}
		rz_structured_data_map_add_unsigned(flags_map, "value", sec->flags, false);
		rz_structured_data_map_add_string(flags_map, "readable", xbe_section_flags_to_string(sec->flags));
		rz_structured_data_map_add_unsigned(m, "vaddr", sec->vaddr, true);
		rz_structured_data_map_add_unsigned(m, "vsize", sec->vsize, false);
		rz_structured_data_map_add_unsigned(m, "offset", sec->offset, false);
		rz_structured_data_map_add_unsigned(m, "size", sec->size, false);
		rz_structured_data_map_add_unsigned(m, "name_addr", sec->name_addr, true);
		rz_structured_data_map_add_unsigned(m, "refcount", sec->refcount, false);

		RzStructuredData *pad = rz_structured_data_map_add_array(m, "padding");
		if (pad) {
			for (size_t j = 0; j < 2; j++) {
				rz_structured_data_array_add_unsigned(
					pad, sec->padding[j], true);
			}
		}

		rz_structured_data_map_add_bytes(m, "digest", sec->digest, sizeof(sec->digest), RZ_STRUCTURED_DATA_FORMAT_COLON);
		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *xbe_libs_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	rz_bin_xbe_obj_t *obj = bf->o->bin_obj;

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	xbe_lib *lib;
	rz_vector_foreach (&obj->libs, lib) {
		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		char name_buf[9] = { 0 };
		memcpy(name_buf, lib->name, 8);
		rz_structured_data_map_add_string_n(m, "name", (const char *)lib->name, sizeof(lib->name));
		rz_structured_data_map_add_unsigned(m, "major", lib->major, false);
		rz_structured_data_map_add_unsigned(m, "minor", lib->minor, false);
		rz_structured_data_map_add_unsigned(m, "build", lib->build, false);
		rz_structured_data_map_add_unsigned(m, "flags", lib->flags, false);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *xbe_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	rz_bin_xbe_obj_t *obj = bf->o->bin_obj;
	xbe_header *xh = &obj->header;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *xbe = rz_structured_data_map_add_map(info, "xbe");
	if (!xbe) {
		rz_structured_data_free(info);
		return NULL;
	}

	RzStructuredData *identity = rz_structured_data_map_add_map(xbe, "identity");
	if (!identity) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_bytes(identity, "magic", xh->magic, sizeof(xh->magic), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_bytes(identity, "signature", xh->signature, sizeof(xh->signature), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_unsigned(identity, "timestamp", xh->timestamp, false);

	RzStructuredData *memory = rz_structured_data_map_add_map(xbe, "memory");
	if (!memory) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add_unsigned(memory, "base", xh->base, true);
	rz_structured_data_map_add_unsigned(memory, "headers_size", xh->headers_size, false);
	rz_structured_data_map_add_unsigned(memory, "image_size", xh->image_size, false);
	rz_structured_data_map_add_unsigned(memory, "image_header_size", xh->image_header_size, false);
	rz_structured_data_map_add_unsigned(memory, "entry_point", xh->ep, true);
	rz_structured_data_map_add_unsigned(memory, "tls_addr", xh->tls_addr, true);

	RzStructuredData *sections = rz_structured_data_map_add_map(xbe, "sections");
	if (!sections) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add_unsigned(sections, "count", xh->sections, false);
	rz_structured_data_map_add_unsigned(sections, "header_addr", xh->sechdr_addr, true);

	RzStructuredData *pe = rz_structured_data_map_add_array(xbe, "pe_data");
	if (!pe) {
		rz_structured_data_free(info);
		return NULL;
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(xh->pe_data); i++) {
		rz_structured_data_array_add_unsigned(pe, xh->pe_data[i], true);
	}

	RzStructuredData *debug = rz_structured_data_map_add_map(xbe, "debug");
	if (!debug) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add_unsigned(debug, "path_addr", xh->debug_path_addr, true);
	rz_structured_data_map_add_unsigned(debug, "name_addr", xh->debug_name_addr, true);
	rz_structured_data_map_add_unsigned(debug, "uname_addr", xh->debug_uname_addr, true);

	RzStructuredData *libs = rz_structured_data_map_add_map(xbe, "libraries");
	if (!libs) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add_unsigned(libs, "count", xh->lib_versions, false);
	rz_structured_data_map_add_unsigned(libs, "versions_addr", xh->lib_versions_addr, true);
	rz_structured_data_map_add_unsigned(libs, "kernel_addr", xh->kernel_lib_addr, true);
	rz_structured_data_map_add_unsigned(libs, "xapi_addr", xh->xapi_lib_addr, true);
	rz_structured_data_map_add_unsigned(libs, "kernel_thunk_addr", xh->kernel_thunk_addr, true);
	rz_structured_data_map_add_unsigned(libs, "nonkernel_import_dir_addr", xh->nonkernel_import_dir_addr, true);

	RzStructuredData *misc = rz_structured_data_map_add_map(xbe, "misc");
	if (!misc) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add_unsigned(misc, "init_flags", xh->init_flags, false);

	RzStructuredData *pad = rz_structured_data_map_add_array(misc, "padding");
	if (pad) {
		for (size_t i = 0; i < 2; i++) {
			rz_structured_data_array_add_unsigned(pad, xh->padding[i], true);
		}
	}

	RzStructuredData *sections_detail = xbe_sections_structure(bf);
	if (!sections_detail) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add(xbe, "sections_detail", sections_detail);

	RzStructuredData *libs_detail = xbe_libs_structure(bf);
	if (!libs_detail) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add(xbe, "libraries_detail", libs_detail);

	return info;
}

static ut64 baddr(RzBinFile *bf) {
	rz_bin_xbe_obj_t *obj = bf->o->bin_obj;
	return obj->header.base;
}

RzBinPlugin rz_bin_plugin_xbe = {
	.name = "xbe",
	.desc = "Microsoft Xbox XBE (Xbox Executable)",
	.license = "LGPL3",
	.author = "LemonBoy",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.libs = &libs,
	.bin_structure = &xbe_structure
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_xbe,
	.version = RZ_VERSION
};
#endif
