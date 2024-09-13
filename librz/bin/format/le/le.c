// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-FileCopyrightText: 2023 svr <svr.work@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file le.c
 * \brief LE/LX/LC binary format plugin.
 *
 * The LE and LX are two very similar binary formats. Both acronyms stand for "linear executable".
 * The bulk of information about formats comes in the form of the LX spec by IBM. It's incomplete
 * and vague in places, so few open source projects have been used to fill in the blanks. The LC
 * is a variety of LX and is handled in the same way here.
 *
 * The LE format is commonly used for:
 * - For DOS protected mode software using an extender such as DOS/4GW (most common).
 * - VxD device drivers by a number of MS and Novel OSes.
 * - In OS/2 occasionally.
 *
 * The LX/LC format is used as a main binary format in OS/2.
 *
 * The following sources have been used:
 *
 * [1] IBM OS/2 16/32-BIT OBJECT MODULE FORMAT (OMF) AND LINEAR EXECUTABLE MODULE FORMAT (LX) rev10:
 *     http://www.edm2.com/index.php/IBM_OS/2_16/32-bit_Object_Module_Format_%28OMF%29_and_Linear_eXecutable_Module_Format_%28LX%29
 *
 * [2] lxLite LX executable packer:
 *     https://github.com/bitwiseworks/lxlite/blob/master/src/os2exe.pas
 *
 * [3] DOS/32 Advanced DOS Extender unbind utility:
 *     https://github.com/abbec/dos32a/blob/master/src/sb/sbind.asm
 **/

#include "le.h"
#include <rz_bin.h>
#include <rz_types.h>
#include <sdbht.h>

#define CHECK(expr) \
	if (!(expr)) { \
		goto fail_cleanup; \
	}

#define CHECK_READ(X, tmp, out) \
	CHECK(rz_buf_read##X##_offset(buf, offset, &tmp) && *offset <= offset_end) \
	out = tmp;

#define CHECK_READ8(out)  CHECK_READ(8, tmp8, out)
#define CHECK_READ16(out) CHECK_READ(_le16, tmp16, out)
#define CHECK_READ32(out) CHECK_READ(_le32, tmp32, out)

/// --- Auxilliary functions ----------------------------------------------------------------------

static const char *le_get_module_type(rz_bin_le_obj_t *bin) {
	switch (bin->header->mflags & M_TYPE_MASK) {
	case M_TYPE_EXE: return "Program module (EXE)";
	case M_TYPE_DLL: return "Library module (DLL)";
	case M_TYPE_PDD: return "Physical Device Driver";
	case M_TYPE_VDD: return "Virtual Device Driver";
	default: return "Unknown";
	}
}

static const char *le_get_os_type(rz_bin_le_obj_t *bin) {
	switch (bin->header->os) {
	case 1: return "OS/2";
	case 2: return "Windows";
	case 3: return "DOS 4.x";
	case 4: return "Windows 386";
	case 5: return "IBM Microkernel Personality Neutral";
	default: return "Unknown";
	}
}

static const char *le_get_cpu_type(rz_bin_le_obj_t *bin) {
	switch (bin->header->cpu) {
	case 1: return "80286";
	case 2: return "80386";
	case 3: return "80486";
	case 0x20: return "N10";
	case 0x21: return "N11";
	case 0x40: return "R3000";
	case 0x41: return "R6000";
	case 0x42: return "R4000";
	default: return "Unknown";
	}
}

static const char *le_get_arch(rz_bin_le_obj_t *bin) {
	switch (bin->header->cpu) {
	case 1:
	case 2:
	case 3:
		return "x86";
	case 0x20:
	case 0x21:
		return "i860";
	case 0x40:
	case 0x41:
	case 0x42:
		return "mips";
	default:
		return "Unknown";
	}
}

static bool le_read_len_str_offset(RzBuffer *buf, ut64 *offset, char **out) {
	*out = NULL;
	ut8 len;
	if (!rz_buf_read8_offset(buf, offset, &len)) {
		return false;
	}

	if (!len) {
		return true; // success yet *out == NULL, this is why the return value is bool
	}

	ut8 *str = calloc((size_t)len + 1, sizeof(char));
	if (!str) {
		return false;
	}
	if (!rz_buf_read_offset(buf, offset, str, len)) {
		free(str);
		return false;
	}
	for (ut8 *s = str; s != str + len; s++) {
		// non-ascii characters should not appear here
		if (*s == 0 || *s > 127) {
			free(str);
			return false;
		}
	}
	*out = (char *)str;
	return true;
}

static ut32 le_reloc_target_offset(ut32 i) {
	// TODO supposedly i860 / mips binaries exist, will 4 byte alignment suffice?
	return i * 4;
}

static ut32 le_reloc_target_vaddr(rz_bin_le_obj_t *bin, ut32 i) {
	return bin->reloc_target_map_base + le_reloc_target_offset(i);
}

static ut32 le_reloc_targets_vfile_size(rz_bin_le_obj_t *bin) {
	return le_reloc_target_offset(bin->reloc_targets_count);
}

static ut32 le_obj_perm(LE_object *obj) {
	ut32 perm = 0;
	perm |= obj->flags & O_READABLE ? RZ_PERM_R : 0;
	perm |= obj->flags & O_WRITABLE ? RZ_PERM_W : 0;
	perm |= obj->flags & O_EXECUTABLE ? RZ_PERM_X : 0;
	return perm;
}

static ut64 le_vaddr_to_paddr(rz_bin_le_obj_t *bin, ut32 vaddr) {
	LE_map *m;
	rz_vector_foreach (bin->le_maps, m) {
		if (m->vaddr <= vaddr && vaddr <= m->vaddr + m->vsize) {
			if (vaddr > m->vaddr + m->size) {
				return 0;
			} else {
				return m->paddr + (vaddr - m->vaddr);
			}
		}
	}
	return 0;
}

static void le_import_free(LE_import *imp) {
	if (!imp) {
		return;
	}
	free(imp->proc_name);
	free(imp);
}

static ut32 le_import_hash(LE_import *imp) {
	ut32 ord_mix = (((ut32)imp->mod_ord + 1) << 16) ^ (imp->proc_ord + 1);
	return sdb_hash(imp->proc_name) ^ ((ord_mix + 1013904223) * 1664525);
}

static int le_import_cmp(LE_import *a, LE_import *b) {
	if (a->mod_ord != b->mod_ord) {
		return a->mod_ord < b->mod_ord ? -1 : 1;
	}
	if (a->proc_ord != b->proc_ord) {
		return a->proc_ord < b->proc_ord ? -1 : 1;
	}
	return rz_str_cmp(a->proc_name, b->proc_name, -1);
}

static void le_fini_import_kv(HtPPKv *kv) {
	le_import_free(kv->key);
}

static RZ_BORROW RzBinImport *le_add_bin_import(rz_bin_le_obj_t *bin, const LE_import *le_imp) {
	if (!le_imp) {
		return NULL;
	}
	RzBinImport *import = RZ_NEW0(RzBinImport);
	if (!import) {
	fail_cleanup:
		rz_bin_import_free(import);
		return NULL;
	}
	const char *libname = "";
	if (le_imp->mod_ord - 1 < rz_pvector_len(bin->imp_mod_names)) {
		libname = rz_pvector_at(bin->imp_mod_names, le_imp->mod_ord - 1);
	}
	if (le_imp->proc_name) {
		CHECK(import->name = rz_str_newf("%s_%s", libname, le_imp->proc_name));
	} else {
		CHECK(import->name = rz_str_newf("%s_%u", libname, le_imp->proc_ord));
	}
	import->bind = RZ_BIN_BIND_GLOBAL_STR;
	import->type = RZ_BIN_TYPE_UNKNOWN_STR;
	CHECK(rz_pvector_push(bin->imports, import));
	import->ordinal = ++bin->reloc_targets_count;
	return import;
}

static RZ_BORROW RzBinSymbol *le_add_symbol(rz_bin_le_obj_t *bin, ut32 ordinal, ut32 vaddr) {
	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (!sym) {
		return NULL;
	}
	if (!ordinal) {
		if (rz_list_empty(bin->symbols)) {
			ordinal = 1;
		} else {
			ordinal = ((RzBinSymbol *)rz_list_last(bin->symbols))->ordinal + 1;
		}
	}
	if (!rz_list_append(bin->symbols, sym)) {
		rz_bin_symbol_free(sym);
		return NULL;
	}
	sym->ordinal = ordinal;
	sym->vaddr = vaddr;
	sym->paddr = le_vaddr_to_paddr(bin, vaddr);
	sym->bind = RZ_BIN_BIND_GLOBAL_STR;
	sym->type = RZ_BIN_TYPE_UNKNOWN_STR;
	return sym;
}

static RZ_BORROW LE_import *le_add_import(rz_bin_le_obj_t *bin,
	ut16 mod_ord, bool proc_by_ord, ut32 proc, ut32 sym_ord) {

	RzBinImport *bin_imp = NULL;
	LE_import *le_imp = NULL;
	char *proc_name = NULL;
	if (false) {
	fail_cleanup:
		le_import_free(le_imp);
		rz_bin_import_free(bin_imp);
		free(proc_name);
		return NULL;
	}

	if (!bin->le_import_ht) {
		HtPPOptions opt = {
			.finiKV = (HtPPFiniKv)le_fini_import_kv,
			.cmp = (HtPPComparator)le_import_cmp,
			.hashfn = (HtPPHashFunction)le_import_hash,
		};
		CHECK(bin->le_import_ht = ht_pp_new_opt(&opt));
	}

	ut32 proc_ord = 0;
	if (proc_by_ord) {
		proc_ord = proc;
	} else {
		// The "overload bit" described in "[1] 3.15 Import Procedure Name Table" makes no
		// sense, so using the same le_read_len_str_offset() that is used elsewhere
		ut64 off = bin->le_off + bin->header->impproc + proc;
		CHECK(le_read_len_str_offset(bin->buf, &off, &proc_name));
	}
	LE_import key = { .mod_ord = mod_ord, .proc_name = proc_name, .proc_ord = proc_ord };
	HtPPKv *kv = ht_pp_find_kv(bin->le_import_ht, &key, NULL);
	if (kv) {
		free(proc_name);
		return kv->key;
	}

	// import does not exists yet, insert a new one
	CHECK(le_imp = RZ_NEW0(LE_import));
	*le_imp = key;
	proc_name = NULL;

	CHECK(le_imp->import = le_add_bin_import(bin, le_imp));

	ut32 sym_vaddr = le_reloc_target_vaddr(bin, le_imp->import->ordinal - 1);
	RzBinSymbol *sym = le_add_symbol(bin, sym_ord, sym_vaddr);
	CHECK(le_imp->symbol = sym);
	sym->is_imported = true;
	CHECK(sym->name = rz_str_dup(le_imp->import->name));

	CHECK(ht_pp_insert(bin->le_import_ht, le_imp, NULL));
	return le_imp;
}

/**
 * \brief Read/write bytes from/to virtual memory range possibly crossing upper page boundary.
 * \param bin rz_bin_le_obj_t, LE binary
 * \param page LE_page*, the page where the first written byte lies
 * \param data_vaddr ut32, virtual address where data is read from / written to
 * \param data ut*, a buffer for reading / a data for writing
 * \param data_len ut32, buffer length
 * \param read bool, read if true, otherwise write
 * \return success bool, false if any read/write errors occurred, true otherwise
 *
 * LX fixups (aka relocations) are a bit tricky. This function is needed to support:
 *   - parsing fixup chains (read mode, read=true)
 *   - applying fixups (write mode, read=false)
 *
 * In LE/LX format such reads / writes can happen on a page boundary, or on a partial page,
 * where two parts of a page belong to different vfiles. Consider two adjacent pages,
 * \p io_page, and its next page in virtual space:
 *
 *                      io_page                         next page
 *     ..][...............oooooooooooooooooo][...............ooooooooooooooooo][..
 *         \physical part/\zeroed virt part/  \physical part/\zeroed virt part/
 *               (1)             (2)                (3)             (4)
 *
 * Intervals (1), (2), (3), (4) can each correspond to its own map+vfile pair. Consider few
 * possible I/O scenarios:
 *
 *   - inside (1)
 *   - on the boundary (1)-(2)
 *   - inside (2)
 *   - on the boundary (2)-(3)
 *   - touching (1)-(2)-(3) -- possible when (2) is very small and is covered by I/O
 *
 * Note that \p data_vaddr is required to be inside \p io_page, so it's impossible
 * for I/O to cross the lower boundary of (1) or happen wholly to the right of (2).
 *
 * The function works by iterating maps left to right for as long as there's hope of finding
 * intersections with the I/O interval. When patching fixups \p data_len never exceeds
 * 6 bytes (for 16:32 fixups), but the algorithm should work for any \p data_len.
 **/
static bool page_io(rz_bin_le_obj_t *bin, LE_page *io_page,
	ut32 data_vaddr, ut8 *data, ut32 data_len, bool read) {

	for (ut32 mi = io_page->le_map_num - 1; mi < rz_vector_len(bin->le_maps); mi++) {
		LE_map *m = rz_vector_index_ptr(bin->le_maps, mi);
		if (m->obj_num != io_page->obj_num) {
			return true; // the map belonging to another object reached, stop
		}

		ut32 vfile_beg = m->vaddr;
		ut32 vfile_end = m->vaddr + m->size;
		ut32 vdata_beg = data_vaddr;
		ut32 vdata_end = data_vaddr + data_len;
		if (vdata_end <= vfile_beg) {
			return true; // no further intersections possible, stop
		}
		if (vfile_end <= vdata_beg) {
			continue; // no intersection yet, try next map
		}

		ut32 vbeg = RZ_MAX(vfile_beg, vdata_beg);
		ut32 vend = RZ_MIN(vfile_end, vdata_end);
		ut32 len = vend - vbeg;

		RzBuffer *vfile_buf = m->is_physical ? bin->buf_patched : m->vfile_buf;
		ut64 paddr = m->paddr + vbeg - vfile_beg;
		ut8 *buf = data + vbeg - vdata_beg;
		if (!vfile_buf) {
			// likely vfiles haven't been created correctly
			RZ_LOG_ERROR("LE: attempted %s %d byte(s) at 0x%" PFMT64x " of map %s "
				     "with no buffer.\n",
				read ? "reading" : "writing", len, paddr,
				m->vfile_name ? m->vfile_name : "NULL");
			rz_return_val_if_reached(false);
		}
		bool good;
		if (read) {
			good = rz_buf_read_at(vfile_buf, paddr, buf, len) == len;
		} else {
			good = rz_buf_write_at(vfile_buf, paddr, buf, len) == len;
		}
		if (!good) {
			// likely data_vaddr is outside page_io, misused this function
			RZ_LOG_ERROR("LE: error %s vfile, %d byte(s) at 0x%" PFMT64x ".\n",
				read ? "reading" : "writing", len, paddr);
			rz_return_val_if_reached(false);
		}
	}
	return true;
}

static bool page_read(rz_bin_le_obj_t *bin, LE_page *io_page, ut32 vaddr, ut8 *buf, ut32 len) {
	return page_io(bin, io_page, vaddr, buf, len, true);
}

static bool page_write(rz_bin_le_obj_t *bin, LE_page *io_page, ut32 vaddr, ut8 *buf, ut32 len) {
	return page_io(bin, io_page, vaddr, buf, len, false);
}

static ut32 le_reloc_vaddr(rz_bin_le_obj_t *bin, LE_reloc *reloc) {
	return bin->le_pages[reloc->src_page].vaddr + reloc->src_off;
}

static ut32 le_reloc_size(LE_reloc *reloc) {
	static const ut8 szmap[] = {
		[FIXUP_BYTE] = 1,
		[FIXUP_SEL16] = 2,
		[FIXUP_OFF16] = 2,
		[FIXUP_OFF32] = 4,
		[FIXUP_SEL16_OFF16] = 4,
		[FIXUP_REL32] = 4,
		[FIXUP_SEL16_OFF32] = 6,
	};
	return reloc->type < sizeof(szmap) ? szmap[reloc->type] : 0;
}

/// --- Loading all things LE from the binary -----------------------------------------------------

/**
 * \brief Find offsets of an LE header or an MZ/LE header pair.
 *
 *  Supported cases:
 *  - A standalone LE binary (just an LE header).
 *  - An MZ stub followed by an LE executbale (MZ-LE).
 *  - A DOS extender bound executable typical for DOS protected mode software (MZ-BW-MZ-LE).
 *
 * Header search is implemented after the code in [3]
 **/
static bool le_get_header_offset(RzBuffer *b, ut64 *mz_off, ut64 *le_off) {
	for (ut64 pos = 0, mz = 0;;) {
		ut8 magic[2];
		if (rz_buf_read_at(b, pos, magic, 2) != 2) {
			break;
		}

		if (!memcmp(magic, "LE", 2) || !memcmp(magic, "LX", 2) || !memcmp(magic, "LC", 2)) {
			if (mz_off) {
				*mz_off = mz;
			}
			if (le_off) {
				*le_off = pos;
			}
			return true;
		}

		bool is_mz = !memcmp(magic, "MZ", 2);
		if (is_mz) {
			ut32 bound_le_off;
			if (!rz_buf_read_le32_at(b, pos + 0x3c, &bound_le_off)) {
				break;
			}
			if (bound_le_off & 0xFFFF) {
				mz = pos;
				pos += bound_le_off;
				continue;
			}
		}

		// BW is a DOS extender related header similar to MZ
		if (is_mz || !memcmp(magic, "BW", 2)) {
			ut16 page_count;
			ut16 last_page_bytes;
			if (!rz_buf_read_le16_at(b, pos + 2, &last_page_bytes) ||
				!rz_buf_read_le16_at(b, pos + 4, &page_count)) {
				break;
			}
			pos += ((ut64)page_count - is_mz) * 512 + last_page_bytes;
			continue;
		}
		break;
	}
	return false;
}

// See [1] 3.2 LX Header
static bool le_load_header(rz_bin_le_obj_t *bin) {
	if (!le_get_header_offset(bin->buf, &bin->mz_off, &bin->le_off)) {
		return false;
	}

	ut64 off = bin->le_off;
	bin->header = RZ_NEW0(LE_header);
	if (!bin->header ||
		!rz_buf_read_offset(bin->buf, &off, bin->header->magic, 2) ||
		!rz_buf_read8_offset(bin->buf, &off, &bin->header->border) ||
		!rz_buf_read8_offset(bin->buf, &off, &bin->header->worder) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->level) ||
		!rz_buf_read_le16_offset(bin->buf, &off, &bin->header->cpu) ||
		!rz_buf_read_le16_offset(bin->buf, &off, &bin->header->os) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->ver) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->mflags) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->mpages) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->startobj) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->eip) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->stackobj) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->esp) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->pagesize) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->pageshift) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->fixupsize) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->fixupsum) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->ldrsize) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->ldrsum) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->objtab) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->objcnt) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->objmap) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->itermap) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->rsrctab) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->rsrccnt) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->restab) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->enttab) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->dirtab) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->dircnt) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->fpagetab) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->frectab) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->impmod) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->impmodcnt) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->impproc) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->pagesum) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->datapage) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->preload) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->nrestab) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->cbnrestab) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->nressum) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->autodata) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->debuginfo) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->debuglen) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->instpreload) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->instdemand) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->heapsize) ||
		!rz_buf_read_le32_offset(bin->buf, &off, &bin->header->stacksize)) {
		return false;
	}

	if (bin->header->border || bin->header->worder) {
		// shouldn't be hard to support, but I couldn't find any such binaries to test on
		RZ_LOG_ERROR("LE: only little-endian byte and word order is supported, "
			     "got (%d, %d), expected (0, 0).\n",
			bin->header->border, bin->header->worder);
		return false;
	}
	bin->is_le = !memcmp("LE", bin->header->magic, 2);

	return true;
}

// Loading objects, see [1] 3.4 Object Table
static bool le_load_objects(rz_bin_le_obj_t *bin) {
	LE_header *h = bin->header;
	if (!h->objcnt) {
		return true; // no objects, binary is a forwarders-only library
	}
	ut64 offset = bin->le_off + h->objtab;
	if (rz_buf_size(bin->buf) < offset + sizeof(LE_object) * h->objcnt) {
		return false;
	}
	bin->objects = calloc(h->objcnt, sizeof(LE_object));
	if (!bin->objects) {
		return false;
	}
	for (LE_object *obj = bin->objects; obj != bin->objects + h->objcnt; obj++) {
		if (!rz_buf_read_le32_offset(bin->buf, &offset, &obj->virtual_size) ||
			!rz_buf_read_le32_offset(bin->buf, &offset, &obj->reloc_base_addr) ||
			!rz_buf_read_le32_offset(bin->buf, &offset, &obj->flags) ||
			!rz_buf_read_le32_offset(bin->buf, &offset, &obj->page_tbl_idx) ||
			!rz_buf_read_le32_offset(bin->buf, &offset, &obj->page_tbl_entries) ||
			!rz_buf_read_le32_offset(bin->buf, &offset, &obj->reserved)) {
			return false;
		}
	}
	return true;
}

// Loading a single non-empty entry, see [1] 3.8.1-4
static bool le_load_entry_record(rz_bin_le_obj_t *bin, ut64 *offset, ut8 type, ut32 obj_num,
	RzVector /*<LE_entry>*/ *entries) {

	if (false) {
	fail_cleanup:
		return false;
	}
	LE_entry e = { .is_empty = false };

	ut32 sym_ord = rz_vector_len(entries) + 1;
	ut8 entry_flags;
	ut32 entry_off;
	switch (type) {
	case ENTRY_16: {
		ut16 offset16;
		CHECK(rz_buf_read8_offset(bin->buf, offset, &entry_flags));
		CHECK(rz_buf_read_le16_offset(bin->buf, offset, &offset16));
		entry_off = offset16;
		break;
	}

	case ENTRY_CALLGATE: {
		ut16 offset16;
		ut16 callgate; // unused
		CHECK(rz_buf_read8_offset(bin->buf, offset, &entry_flags));
		CHECK(rz_buf_read_le16_offset(bin->buf, offset, &offset16));
		CHECK(rz_buf_read_le16_offset(bin->buf, offset, &callgate));
		entry_off = offset16;
		break;
	}

	case ENTRY_32: {
		CHECK(rz_buf_read8_offset(bin->buf, offset, &entry_flags));
		CHECK(rz_buf_read_le32_offset(bin->buf, offset, &entry_off));
		break;
	}

	case ENTRY_FORWARDER: {
		ut16 imp_mod_ord;
		ut32 imp_proc;
		CHECK(rz_buf_read8_offset(bin->buf, offset, &entry_flags));
		CHECK(rz_buf_read_le16_offset(bin->buf, offset, &imp_mod_ord));
		CHECK(rz_buf_read_le32_offset(bin->buf, offset, &imp_proc));
		e.is_forwarder = true;
		e.is_exported = true;
		bool proc_by_ord = entry_flags & E_IMPORT_BY_ORD;
		e.is_forwarder_import_by_ord = proc_by_ord;
		LE_import *le_imp;
		CHECK(le_imp = le_add_import(bin, imp_mod_ord, proc_by_ord, imp_proc, sym_ord));
		e.symbol = le_imp->symbol;
		break;
	}
	}

	if (type == ENTRY_16 || type == ENTRY_CALLGATE || type == ENTRY_32) {
		e.is_exported = entry_flags & E_EXPORTED;
		e.is_shared = entry_flags & E_SHARED;
		e.is_param_dword = type == ENTRY_32;
		e.param_count = entry_flags >> E_PARAM_COUNT_SHIFT;
		e.obj_num = obj_num;
		if (obj_num - 1 < bin->header->objcnt) {
			ut32 entry_vaddr = bin->objects[obj_num - 1].reloc_base_addr + entry_off;
			CHECK(e.symbol = le_add_symbol(bin, sym_ord, entry_vaddr));
		} else {
			// rare, 16 bit only, TODO what is it?
			RZ_LOG_WARN("LE: invalid object #%u specified for symbol %u\n",
				obj_num, sym_ord);
		}
	}

	CHECK(rz_vector_push(entries, &e));
	return true;
}

// Loading symbols, see [1] 3.8 Entry Table
static RZ_OWN RzVector /*<LE_entry>*/ *le_load_entries(rz_bin_le_obj_t *bin) {
	char *name = NULL;
	RzVector *entries = rz_vector_new(sizeof(LE_entry), NULL, NULL);
	if (!entries) {
	fail_cleanup:
		rz_vector_free(entries);
		free(name);
		return NULL;
	}

	ut64 offset = bin->le_off + bin->header->enttab;
	while (true) {
		ut8 entry_count;
		CHECK(rz_buf_read8_offset(bin->buf, &offset, &entry_count));
		if (!entry_count) {
			break;
		}
		ut8 entry_type;
		CHECK(rz_buf_read8_offset(bin->buf, &offset, &entry_type));
		ut8 type = entry_type & ~E_PARAM_TYPING_PRESENT;
		rz_vector_reserve(entries, rz_vector_len(entries) + entry_count);

		switch (type) {
		case ENTRY_EMPTY: {
			LE_entry e = { .is_empty = true };
			while (entry_count--) {
				rz_vector_push(entries, &e);
			}
			continue;
		}

		case ENTRY_16:
		case ENTRY_CALLGATE:
		case ENTRY_32:
		case ENTRY_FORWARDER: {
			ut16 obj_num = 0;
			CHECK(rz_buf_read_le16_offset(bin->buf, &offset, &obj_num));
			for (int i = 0; i < entry_count; i++) {
				CHECK(le_load_entry_record(bin, &offset, type, obj_num, entries));
			}
			continue;
		}
		}
		RZ_LOG_WARN("LE: unsupported entry bundle type %d, skipping the remainder "
			    "of the table after having read %" PFMTSZu " entries.\n",
			type, rz_vector_len(entries));
		break;
	}

	// Load symbol names, see [1] 3.7 Resident or Non-resident Name Table Entry
	LE_header *h = bin->header;
	ut64 offset_beg[2] = { bin->le_off + h->restab, bin->mz_off + h->nrestab };
	ut64 offset_end[2] = { bin->le_off + h->enttab, bin->mz_off + h->nrestab + h->cbnrestab };
	for (ut32 i = 0; i < 2; i++) {
		ut64 off = offset_beg[i], end = offset_end[i];
		while (off + 1 <= end) {
			if (!le_read_len_str_offset(bin->buf, &off, &name)) {
				break;
			}
			if (off + 2 > end) {
				RZ_FREE(name);
				break;
			}
			ut16 entry_ord;
			CHECK(rz_buf_read_le16_offset(bin->buf, &off, &entry_ord));
			if (name && entry_ord - 1 < rz_vector_len(entries)) {
				LE_entry *e = rz_vector_index_ptr(entries, entry_ord - 1);
				if (e->symbol && !e->symbol->name) {
					e->symbol->name = name;
					name = NULL;
					continue;
				}
			}
			RZ_FREE(name);
		}
	}

	// try naming entries accessible only by ordinal
	LE_entry *e;
	int ei = 0;
	rz_vector_foreach (entries, e) {
		ei++;
		if (!e->is_empty && !e->is_forwarder && e->symbol && !e->symbol->name) {
			e->symbol->name = rz_str_newf("%u", ei);
		}
	}

	return entries;
}

// Loading page map, see [1] 3.5 Object Page Table
static RZ_OWN LE_page *le_load_pages(rz_bin_le_obj_t *bin) {
	LE_header *h = bin->header;
	ut64 offset = bin->le_off + h->objmap;
	LE_page *le_pages = NULL;
	if (rz_buf_size(bin->buf) < offset + (ut64)h->mpages * (bin->is_le ? 4 : 8)) {
	fail_cleanup:
		free(le_pages);
		return NULL;
	}
	CHECK(le_pages = calloc(h->mpages, sizeof(LE_header)));

	LE_page *page = le_pages;
	for (ut32 page_i = 0; page_i < h->mpages; page_i++, page++) {
		if (bin->is_le) {
			// 4 byte record: 3 byte big endian page number, 1 byte flags
			ut32 record;
			CHECK(rz_buf_read_be32_offset(bin->buf, &offset, &record));
			ut32 page_num = record >> 8;
			ut8 page_flags = record & 0xFF;
			if (page_flags != 0) {
				RZ_LOG_WARN("LE: unsupported LE page flags 0x%02x for page #%d.\n",
					page_flags, page_i + 1);
			}
			if (!page_num) {
				// This is likely the result of file damage or tempering, guessing
				// number being just an 1-based index would work for typical LE.
				page_num = page_i + 1;
				RZ_LOG_WARN("LE: page #%u invalid page number corrected.\n", page_num);
			}
			page->type = PAGE_LEGAL;
			page->paddr = bin->mz_off + h->datapage + (ut64)(page_num - 1) * h->pagesize;
			page->psize = page_i != h->mpages - 1 ? h->pagesize : h->le_last_page_size;
		} else {
			// 8 byte record: 4 offset, 2 size, 2 flags
			ut32 page_offset;
			ut16 page_size;
			ut16 page_flags;
			CHECK(rz_buf_read_le32_offset(bin->buf, &offset, &page_offset));
			CHECK(rz_buf_read_le16_offset(bin->buf, &offset, &page_size));
			CHECK(rz_buf_read_le16_offset(bin->buf, &offset, &page_flags));
			ut32 off = page_offset << h->pageshift;
			switch (page_flags) {
			case PAGE_LEGAL:
				page->paddr = bin->mz_off + h->datapage + off;
				break;
			case PAGE_ITERATED:
			case PAGE_COMPRESSED:
				page->paddr = bin->mz_off + h->itermap + off;
				break;
			case PAGE_INVALID:
			case PAGE_RANGE:
			default:
				page_flags = PAGE_ZEROED;
				RZ_LOG_WARN("LE: unsupported LX page flags 0x%04x for page #%d.\n",
					page_flags, page_i + 1);
			case PAGE_ZEROED:
				break;
			}
			page->type = (LE_page_type)page_flags;
			page->psize = page_size;
		}
	}

	// assign object number to pages, calculate vaddr
	for (ut32 oi = 0; oi < h->objcnt; oi++) {
		LE_object *obj = &bin->objects[oi];
		ut32 voff = 0;
		LE_page *page = &le_pages[obj->page_tbl_idx - 1];
		for (ut32 i = 0; i < obj->page_tbl_entries; i++, page++) {
			unsigned int pi = (obj->page_tbl_idx - 1) + i;
			if (pi >= h->mpages) {
				RZ_LOG_ERROR("LE: object #%u page table entry index %u is out "
					     "of range.\n",
					oi + 1, pi + 1);
				goto fail_cleanup;
			}
			page->obj_num = oi + 1;
			page->vaddr = obj->reloc_base_addr + voff;
			page->vsize = h->pagesize;
			voff += h->pagesize;
		}
		if (voff > obj->virtual_size) {
			ut32 extra = voff - obj->virtual_size;
			if (extra < h->pagesize) {
				page->vsize -= extra;
			} else {
				RZ_LOG_WARN("LE: object #%u vsize is smaller than the sum of its "
					    "pages 0x%x < 0x%x, object has been extended.\n",
					oi + 1, obj->virtual_size, voff);
				obj->virtual_size = voff;
			}
		}
	}

	// assign fixup page map boundaries
	ut32 fixup_page_base_paddr = bin->le_off + h->frectab;
	ut64 fixup_map_paddr = bin->le_off + h->fpagetab;
	for (ut32 pi = 0; pi <= h->mpages; pi++) {
		ut32 start;
		if (!rz_buf_read_le32_offset(bin->buf, &fixup_map_paddr, &start)) {
			goto fail_cleanup;
		}
		start += fixup_page_base_paddr;
		if (pi < h->mpages) {
			le_pages[pi].fixup_page_start = start;
		}
		if (pi > 0) {
			le_pages[pi - 1].fixup_page_end = start;
		}
	}

	return le_pages;
}

// See [2] UnpackMethod1 for the algortihm.
static void le_unpack_iterated(rz_bin_le_obj_t *bin, ut8 *out, ut32 out_size, LE_page *page) {
	if (false) {
	fail_cleanup:
		RZ_LOG_WARN("LE: unpacking type 1 (iterated) page at 0x%" PFMT64x " failed.\n",
			page->paddr);
		return;
	}
	ut64 off = page->paddr;
	ut64 end = off + page->psize;
	while (off < end) {
		ut16 reps, len;
		CHECK(off + 2 <= end);
		CHECK(rz_buf_read_le16_offset(bin->buf, &off, &reps));
		if (reps == 0) {
			break;
		}
		CHECK(off + 2 <= end);
		CHECK(rz_buf_read_le16_offset(bin->buf, &off, &len));
		CHECK(len <= out_size && off + len <= end);
		CHECK(rz_buf_read_offset(bin->buf, &off, out, len));
		ut8 *pattern = out;
		out += len;
		out_size -= len;
		for (ut32 i = 1; i < reps; i++) {
			memcpy(out, pattern, RZ_MIN(out_size, len));
			if (out_size < len) {
				break;
			}
			out += len;
			out_size -= len;
		}
		break;
	}
}

// See [2] UnpackMethod2 for the algortihm.
static void le_unpack_compressed(rz_bin_le_obj_t *bin, ut8 *out, ut32 out_size, LE_page *page) {
	ut8 tmp8;
	ut16 tmp16;
	RzBuffer *buf = bin->buf;
	ut64 off = page->paddr, *offset = &off;
	ut64 offset_end = *offset + page->psize;
	ut32 out_size_total = out_size;

	if (false) {
	fail_cleanup:
		RZ_LOG_WARN("LE: unpacking type 5 (compressed) page at 0x%" PFMT64x " failed.\n",
			page->paddr);
		return;
	}

// copy N bytes from source
#define COPY(N) \
	CHECK(*offset + (N) <= offset_end && (N) <= out_size); \
	CHECK(rz_buf_read_offset(buf, offset, out, (N))); \
	out += (N); \
	out_size -= (N);

// appends N bytes at *(out - backstep) to *out, ranges can overlap!
#define DUP(backstep, N) \
	CHECK(out_size_total - out_size >= backstep); \
	for (ut32 i = (N); i; i--, out++, out_size--) { \
		*out = *(out - backstep); \
	}

	while (*offset < offset_end) {
		ut8 b1;
		CHECK_READ8(b1);

		ut8 type = b1 & 3;
		if (type == 0) {
			if (b1 == 0) {
				ut8 b2, b3;
				CHECK_READ8(b2);
				if (b2 == 0) {
					break;
				}
				CHECK_READ8(b3);
				CHECK(b2 <= out_size);
				memset(out, b3, b2);
				out += b2;
				out_size -= b2;
			} else {
				COPY(b1 >> 2);
			}

		} else if (type == 1) {
			ut16 bof;
			ut8 b2;
			*offset -= 1;
			CHECK_READ16(bof);
			bof >>= 7;
			b2 = ((b1 >> 4) & 7) + 3;
			b1 = ((b1 >> 2) & 3);
			COPY(b1);
			DUP(bof, b2);

		} else if (type == 2) {
			ut16 bof;
			*offset -= 1;
			CHECK_READ16(bof);
			bof >>= 4;
			b1 = ((b1 >> 2) & 3) + 3;
			DUP(bof, b1);

		} else if (type == 3) {
			ut8 b2;
			ut16 word1, word2, bof;
			*offset -= 1;
			CHECK_READ16(word1);
			*offset -= 1;
			CHECK_READ16(word2);
			b1 = (word1 >> 2) & 0xf;
			b2 = (word1 >> 6) & 0x3f;
			bof = word2 >> 4;
			COPY(b1);
			DUP(bof, b2);
		}
	}
#undef DUP
#undef COPY
}

static void le_map_fini(void *map, void *unused) {
	LE_map *m = map;
	rz_buf_free(m->vfile_buf);
	free(m->vfile_buf_data);
	free(m->vfile_name);
}

static bool le_add_map(RzVector /*<LE_map>*/ *le_maps, LE_map *map, LE_page *page) {
	if (map->vsize == 0 || (map->size == 0 && map->is_physical)) {
		return true; // adding empty maps makes no sense, might happen in a crafted binary
	}
	LE_map *prev = rz_vector_empty(le_maps) ? NULL : rz_vector_tail(le_maps);
	bool prev_ok = prev && prev->obj_num == map->obj_num && prev->is_physical == map->is_physical;
	bool merge_virtual = prev_ok && !map->is_physical;
	bool merge_physical = prev_ok && map->is_physical && prev->paddr + prev->size == map->paddr;
	if (merge_virtual || merge_physical) {
		prev->size += map->size;
		prev->vsize += map->vsize;
	} else {
		if (!rz_vector_push(le_maps, map)) {
			return false;
		}
	}
	if (!page->le_map_num) {
		page->le_map_num = rz_vector_len(le_maps);
	}
	return true;
}

static RzVector /*<LE_map>*/ *le_create_maps(rz_bin_le_obj_t *bin) {
	RzVector *le_maps = rz_vector_new(sizeof(LE_map), le_map_fini, NULL);
	ut8 *tmp_buf = NULL;
	if (!le_maps) {
	fail_cleanup:
		rz_vector_free(le_maps);
		free(tmp_buf);
		return NULL;
	}

	LE_header *h = bin->header;
	for (ut32 oi = 0; oi != h->objcnt; oi++) {
		LE_object *obj = &bin->objects[oi];
		LE_map m = { .obj_num = oi + 1 };
		size_t len_before = rz_vector_len(le_maps);
		ut32 beg = obj->page_tbl_idx - 1, end = beg + obj->page_tbl_entries;
		for (ut32 pi = beg; pi != end; pi++) {
			if (pi >= h->mpages) {
				RZ_LOG_ERROR("LE: object #%u page table entry index %u is out "
					     "of range.\n",
					oi + 1, pi + 1);
				goto fail_cleanup;
			}
			LE_page *page = &bin->le_pages[pi];
			m.first_page_num = pi + 1;
			if (page->type == PAGE_LEGAL) {
				// physical part of a normal page
				m.size = page->psize;
				m.vsize = page->psize;
				m.paddr = page->paddr;
				m.vaddr = page->vaddr;
				m.is_physical = true;
				CHECK(le_add_map(le_maps, &m, page));
				if (page->psize < page->vsize) {
					// zero padded virtual remainder of a normal page
					m.size = 0;
					m.vsize = h->pagesize - page->psize;
					m.paddr = 0;
					m.vaddr = page->vaddr + page->psize;
					m.is_physical = false;
					CHECK(le_add_map(le_maps, &m, page));
				}
			} else {
				// virtual unpacked or zero filled page
				m.size = page->vsize;
				m.vsize = page->vsize;
				m.paddr = 0;
				m.vaddr = page->vaddr;
				m.is_physical = false;
				CHECK(le_add_map(le_maps, &m, page));
			}
		}

		// if the last map is zero-filled virtual, merge it with the preceding map
		if (rz_vector_len(le_maps) >= len_before + 2) {
			LE_map *last = rz_vector_tail(le_maps), *prev = last - 1;
			if (last->size == 0) {
				prev->vsize += last->vsize;
				rz_vector_pop(le_maps, NULL);
			}
		}

		// if an object has no pages, create a single map for the whole object
		if (rz_vector_len(le_maps) == len_before) {
			m.size = 0;
			m.vsize = obj->virtual_size;
			m.paddr = 0;
			m.vaddr = obj->reloc_base_addr;
			m.is_physical = false;
			CHECK(rz_vector_push(le_maps, &m));
		} else {
			// otherwise extend last map to match object vsize
			LE_map *last = rz_vector_tail(le_maps);
			ut32 obj_vend = obj->reloc_base_addr + obj->virtual_size;
			if (obj_vend > last->vaddr + last->vsize) {
				last->vsize = obj_vend - last->vaddr;
			}
		}

		((LE_map *)rz_vector_tail(le_maps))->is_obj_last = true;
	}

	// name maps
	LE_map *m;
	ut32 num = 1;
	rz_vector_foreach (le_maps, m) {
		const char *map_kind = m->is_physical ? "physical" : "virtual";
		CHECK(m->vfile_name = rz_str_newf("obj%d-%s%u", m->obj_num, map_kind, num++));
	}

	// allocate buffers, fill zero pages, unpack compressed pages
	rz_vector_foreach (le_maps, m) {
		if (m->is_physical) {
			continue;
		}
		if (m->size == 0 && m->is_obj_last) {
			continue; // fully virtual and last map in object, no need for vfile
		}
		ut32 buf_size = m->size ? m->size : m->vsize;
		CHECK(tmp_buf = RZ_NEWS0(ut8, buf_size));
		ut32 offset = 0;
		for (ut32 pi = m->first_page_num - 1; pi < bin->header->mpages; pi++) {
			LE_page *page = &bin->le_pages[pi];
			if (page->le_map_num - 1 != m - (LE_map *)rz_vector_head(le_maps)) {
				break;
			}
			ut32 size = page->vsize;
			if (page->type == PAGE_LEGAL) {
				// !is_physical && type == PAGE_LEGAL means zero padded remainder
				// of a normal page, thus its size is physical size inverted
				size = h->pagesize - page->psize;
			}
			CHECK(offset + size <= buf_size);
			switch (page->type) {
			case PAGE_ITERATED:
				le_unpack_iterated(bin, tmp_buf + offset, size, page);
				break;
			case PAGE_COMPRESSED:
				le_unpack_compressed(bin, tmp_buf + offset, size, page);
				break;
			default:
				break;
			}
			offset += size;
		}
		CHECK(m->vfile_buf = rz_buf_new_with_pointers(tmp_buf, m->size, false));
		m->vfile_buf_data = tmp_buf;
		tmp_buf = NULL;
	}

	// calculate reloc_target_map_base
	ut32 max_vaddr = 0;
	rz_vector_foreach (le_maps, m) {
		max_vaddr = RZ_MAX(max_vaddr, m->vaddr + m->vsize);
	}
	CHECK(h->pagesize);
	bin->reloc_target_map_base = max_vaddr - (max_vaddr % h->pagesize) + (h->pagesize * 2);

	return le_maps;
}

static RZ_OWN RzPVector /*<char *>*/ *le_load_import_mod_names(rz_bin_le_obj_t *bin) {
	RzPVector *names = rz_pvector_new(free);
	char *modname = NULL;
	if (!names) {
	fail_cleanup:
		rz_pvector_free(names);
		free(modname);
		return NULL;
	}
	ut64 off = bin->le_off + bin->header->impmod;
	for (ut32 i = 0; i < bin->header->impmodcnt; i++) {
		if (!le_read_len_str_offset(bin->buf, &off, &modname)) {
			break;
		}
		CHECK(rz_pvector_push(names, modname));
		modname = NULL;
	}
	return names;
}

static bool le_patch_relocs(rz_bin_le_obj_t *bin) {
	// possibly resize vfiles
	ut32 *max_vaddr = NULL;
	LE_map **last_map = NULL;
	if (false) {
	fail_cleanup:
		free(max_vaddr);
		free(last_map);
		return false;
	}

	// mark last map for each object
	CHECK(last_map = RZ_NEWS0(LE_map *, bin->header->objcnt));
	LE_map *m;
	rz_vector_foreach (bin->le_maps, m) {
		last_map[m->obj_num - 1] = m;
	}

	// search maximum vaddr patched by relocs for each object
	CHECK(max_vaddr = RZ_NEWS0(ut32, bin->header->objcnt));
	for (ut32 oi = 0; oi < bin->header->objcnt; oi++) {
		max_vaddr[oi] = bin->objects[oi].reloc_base_addr; // set minimum
	}
	RzListIter *iter;
	LE_reloc *reloc;
	rz_list_foreach (bin->le_relocs, iter, reloc) {
		LE_page *page = &bin->le_pages[reloc->src_page];
		if (page->obj_num) {
			ut32 *max = &max_vaddr[page->obj_num - 1];
			*max = RZ_MAX(*max, le_reloc_vaddr(bin, reloc) + le_reloc_size(reloc));
		}
	}

	// extending allocated parts of objects to allow patching virtual region
	for (ut32 oi = 0; oi < bin->header->objcnt; oi++) {
		m = last_map[oi];
		if (max_vaddr[oi] > m->vaddr + m->size) {
			ut32 sz = max_vaddr[oi] - m->vaddr;

			// without tmp realloc failure would result in a leak
			ut8 *tmp = realloc(m->vfile_buf_data, sz);
			CHECK(m->vfile_buf_data = tmp);
			rz_buf_free(m->vfile_buf);
			CHECK(m->vfile_buf = rz_buf_new_with_pointers(tmp, sz, false));
			m->size = sz;
		}
	}

	RZ_FREE(max_vaddr);
	RZ_FREE(last_map);

	rz_list_foreach (bin->le_relocs, iter, reloc) {
		LE_page *page = &bin->le_pages[reloc->src_page];
		if (page->obj_num == 0) {
			continue;
		}

		LE_fixup_type t = reloc->type;
		ut32 vaddr = le_reloc_vaddr(bin, reloc);

		if (t == FIXUP_BYTE) {
			// TODO FIXUP_BYTE is unsupported, occurances are extremely rare though.
			continue;
		}

		// write 32 bit offset
		if (t == FIXUP_REL32 || t == FIXUP_SEL16_OFF32 || t == FIXUP_OFF32) {
			ut8 tmp[4];
			ut32 target = reloc->target_vaddr + reloc->addend;
			if (t == FIXUP_REL32) {
				target -= vaddr + 4; // relative offset, for call/jump
			}
			rz_write_le32(tmp, target);
			CHECK(page_write(bin, page, vaddr, tmp, sizeof(tmp)));
		}

		// write 16 bit offset
		if (t == FIXUP_SEL16_OFF16 || t == FIXUP_OFF16) {
			ut8 tmp[2];
			ut32 obj = reloc->trg_obj_num;
			if (obj) {
				ut32 obj_base = obj <= bin->header->objcnt
					? bin->objects[obj - 1].reloc_base_addr
					: bin->reloc_target_map_base;
				ut32 target = reloc->target_vaddr + reloc->addend - obj_base;
				if (target <= UT16_MAX) {
					rz_write_le16(tmp, target);
					CHECK(page_write(bin, page, vaddr, tmp, 2));
				} else {
					RZ_LOG_WARN("LE: failed to apply fixup at vaddr=0x%x, "
						    "16 bit target offset=0x%x is too big.\n",
						vaddr, target);
				}
			} else {
				RZ_LOG_WARN("LE: failed to apply fixup at vaddr=0x%x, "
					    "no target object specified.\n",
					vaddr);
			}
		}

		// write selector
		if (t == FIXUP_SEL16_OFF32 || t == FIXUP_SEL16_OFF16 || t == FIXUP_SEL16) {
			ut8 tmp[2];
			rz_write_le16(tmp, reloc->trg_obj_num);
			vaddr += le_reloc_size(reloc) - 2; // selector is patched at tailing 2 bytes
			CHECK(page_write(bin, page, vaddr, tmp, 2));
		}
	}

	if (bin->buf_patched) {
		rz_buf_sparse_set_write_mode(bin->buf_patched, RZ_BUF_SPARSE_WRITE_MODE_THROUGH);
	}
	return true;
}

static bool le_append_fixup(rz_bin_le_obj_t *bin, LE_reloc *reloc, RzList /*<RzBinReloc *>*/ *out,
	bool skip_fixup) {

	if (skip_fixup) {
		return true; // Fixup has been parsed but contains invalid data, ignore and proceed
	}

	if (reloc->src_off < 0) {
		// Skipping fixups with negative source offset, since they are already accounted for
		// on the preceding page as per [1] 3.13 Fixup Record Table:
		//
		//  Note: For fixups that cross page boundaries, a separate fixup record is
		//  specified for each page. An offset is still used for the 2nd page, but it
		//  now becomes a negative offset since the fixup originated on the preceding
		//  page. (For example if only the last one byte of a 32-bit address is on
		//  the page to be fixed up, then the offset would have a value of -3)"
		//
		return true; // Not an error
	}

	LE_reloc *tmp = RZ_NEWCOPY(LE_reloc, reloc);
	if (!tmp || !rz_list_append(out, tmp)) {
		free(tmp);
		return false;
	}
	rz_list_append(bin->le_fixups, tmp);
	return true;
}

static bool le_load_fixup_record(rz_bin_le_obj_t *bin, RzList /*<RzBinReloc *>*/ *relocs_out,
	ut32 page_i, ut64 *offset, ut64 offset_end) {

	LE_header *h = bin->header;
	ut64 start_offset = *offset;
	if (false) {
	fail_cleanup:
		RZ_LOG_WARN("LE: unsupported or malformed fixup record at 0x%" PFMT64x
			    ", skipping the rest of the page.\n",
			start_offset);
		return false;
	}

	// variables used in CHECK_READ*
	RzBuffer *buf = bin->buf;
	ut32 tmp32 = 0;
	ut16 tmp16 = 0;
	ut8 tmp8 = 0;

	LE_page *cur_page = &bin->le_pages[page_i];
	LE_reloc rel = { .src_page = page_i };

	ut8 src_flags;
	CHECK_READ8(src_flags);
	rel.type = src_flags & F_SOURCE_TYPE_MASK;
	// TODO what does src_flags & F_SOURCE_ALIAS do? only valid when segment selector is present

	ut8 trg_flags;
	CHECK_READ8(trg_flags);
	ut8 trg_type = trg_flags & F_TARGET_TYPE_MASK;

	ut8 src_list_count = 0;
	st16 src_off = 0; // signed integer, can be negative!
	if (src_flags & F_SOURCE_LIST) {
		CHECK_READ8(src_list_count);
	} else {
		CHECK_READ16(src_off);
	}

	ut16 ordinal;
	if (trg_flags & F_TARGET_ORD16) {
		CHECK_READ16(ordinal);
	} else {
		CHECK_READ8(ordinal);
	}

	bool skip_fixup = false;
	ut16 imp_mod_ord = 0;
	ut32 imp_proc_ord = 0;
	ut32 imp_proc_name_off = 0;
	ut32 target_base_vaddr = 0;
	switch (trg_type) {
	case TARGET_INTERNAL:
		if (ordinal - 1 < h->objcnt) {
			rel.trg_obj_num = ordinal;
			target_base_vaddr = bin->objects[ordinal - 1].reloc_base_addr;
		} else {
			skip_fixup = true;
		}
		if (rel.type != FIXUP_SEL16) {
			ut32 target_offset;
			if (trg_flags & F_TARGET_OFF32) {
				CHECK_READ32(target_offset);
			} else {
				CHECK_READ16(target_offset);
			}
			rel.target_vaddr = target_base_vaddr + target_offset;
		} else {
			// FIXUP_SEL16 doesn't truly have a target_vaddr, it targets a segment as a
			// whole and writes a "segment selector". Here target_vaddr is set to its
			// target segment's start. It's purely for informational purposes, otherwise
			// there would be no way to understand its target by ir command output.
			rel.target_vaddr = target_base_vaddr;
		}
		break;

	case TARGET_IMPORT_ORDINAL:
		imp_mod_ord = ordinal;
		if (trg_flags & F_TARGET_ORD8) {
			CHECK_READ8(imp_proc_ord);
		} else if (trg_flags & F_TARGET_OFF32) {
			CHECK_READ32(imp_proc_ord);
		} else {
			CHECK_READ16(imp_proc_ord);
		}
		break;

	case TARGET_IMPORT_NAME:
		imp_mod_ord = ordinal;
		if (trg_flags & F_TARGET_OFF32) {
			CHECK_READ32(imp_proc_name_off);
		} else {
			CHECK_READ16(imp_proc_name_off);
		}
		break;

	case TARGET_INTERNAL_ENTRY: {
		LE_entry *e = NULL;
		if (ordinal - 1 < rz_vector_len(bin->le_entries)) {
			e = rz_vector_index_ptr(bin->le_entries, ordinal - 1);
		}
		if (!e || e->is_empty || e->is_forwarder || !e->symbol) {
			RZ_LOG_WARN("LE: relocation references invalid entry #%d.\n", ordinal);
			skip_fixup = true;
			break;
		}
		rel.symbol = e->symbol;
		rel.target_vaddr = e->symbol->vaddr;
		rel.trg_obj_num = e->obj_num;
		if (e->obj_num - 1 < h->objcnt) {
			target_base_vaddr = bin->objects[e->obj_num - 1].reloc_base_addr;
		}
		break;
	}

	default:
		RZ_LOG_WARN("LE: unsupported fixup target type %u.\n", trg_type);
		goto fail_cleanup;
	}

	if (imp_mod_ord) {
		rel.trg_obj_num = h->objcnt + 1; // pseudo object for imports
		bool proc_by_ord = imp_proc_ord > 0;
		ut32 proc = proc_by_ord ? imp_proc_ord : imp_proc_name_off;
		LE_import *le_imp;
		CHECK(le_imp = le_add_import(bin, imp_mod_ord, proc_by_ord, proc, 0));
		rel.import = le_imp->import;
		rel.target_vaddr = le_imp->symbol->vaddr;
	}

	if (trg_flags & F_TARGET_ADDITIVE) {
		if (trg_flags & F_TARGET_ADD32) {
			CHECK_READ32(rel.addend);
		} else {
			CHECK_READ16(rel.addend);
		}
	}

	// handle fixup chain, sources list, or just a single fixup
	RzListIter *prev_tail = rz_list_tail(relocs_out);
	if (!src_list_count) {
		rel.src_off = src_off; // in non-list cases src_off has already been read by now

		// [1] 3.13.5 Internal Chaining Fixups
		bool is_chain = trg_flags & F_TARGET_CHAIN;
		if (is_chain) {
			ut64 start_paddr = cur_page->paddr + src_off;
			for (ut32 cnt = 0; src_off != 0xFFF; cnt++) {
				if (src_off < 0 || src_off + 4 > h->pagesize || cnt > h->pagesize) {
					RZ_LOG_WARN("LE: malformed or circular fixup chain at 0x%" PFMT64x ".\n",
						start_paddr);
					while (relocs_out->tail != prev_tail) {
						rz_bin_reloc_free(rz_list_pop(relocs_out));
					}
					break;
				}

				union {
					ut32 fixupinfo;
					ut8 buf[4];
				} u = { .fixupinfo = 0 };
				CHECK(page_read(bin, cur_page, cur_page->vaddr + src_off, u.buf, 4));
				rel.target_vaddr = target_base_vaddr + (u.fixupinfo & 0xFFFFF);
				rel.src_off = src_off;
				CHECK(le_append_fixup(bin, &rel, relocs_out, skip_fixup));
				src_off = u.fixupinfo >> 20;
			}
		} else if (!is_chain) {
			CHECK(le_append_fixup(bin, &rel, relocs_out, skip_fixup));
		}
	} else {
		while (src_list_count--) {
			CHECK_READ16(rel.src_off);
			CHECK(le_append_fixup(bin, &rel, relocs_out, skip_fixup));
		}
	}

	return true;
}

static RZ_OWN RzList /*<LE_reloc *>*/ *le_load_relocs(rz_bin_le_obj_t *bin) {
	RzList *relocs = rz_list_newf(NULL);
	if (!relocs) {
		return NULL;
	}
	for (ut32 pi = 0; pi < bin->header->mpages; pi++) {
		LE_page *page = &bin->le_pages[pi];
		ut64 off = page->fixup_page_start, end = page->fixup_page_end;
		while (off < end) {
			if (!le_load_fixup_record(bin, relocs, pi, &off, end)) {
				break; // malformed page, continue reading from the next page
			}
		}
	}
	return relocs;
}

/// --- Plugin callbacks --------------------------------------------------------------------------

static void rz_bin_le_free(rz_bin_le_obj_t *bin) {
	if (!bin) {
		return;
	}
	free(bin->header);
	free(bin->modname);
	rz_buf_free(bin->buf_patched);
	free(bin->objects);
	free(bin->le_pages);
	rz_vector_free(bin->le_maps);
	rz_pvector_free(bin->imp_mod_names);
	rz_list_free(bin->symbols);
	rz_vector_free(bin->le_entries);
	rz_pvector_free(bin->imports);
	ht_pp_free(bin->le_import_ht);
	rz_list_free(bin->le_relocs);
	rz_list_free(bin->le_fixups);
	free(bin);
}

void rz_bin_le_destroy(RzBinFile *bf) {
	rz_bin_le_free(bf->o->bin_obj);
}

bool rz_bin_le_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && buf, false);
	rz_bin_le_obj_t *bin = RZ_NEW0(rz_bin_le_obj_t);
	char const *err_ctx = ", unable to load file header.";
	if (!bin) {
	fail_cleanup:
		RZ_LOG_ERROR("LE: loading binary failed%s\n", err_ctx);
		rz_bin_le_free(bin);
		return false;
	}
	bin->buf = buf;
	CHECK(le_load_header(bin));

	if (bin->header->objcnt) {
		CHECK(bin->buf_patched = rz_buf_new_sparse_overlay(buf, RZ_BUF_SPARSE_WRITE_MODE_SPARSE));
	} else {
		RZ_LOG_WARN("LE: binary has no code, probably a forwarder-only library.\n");
	}

	bin->type = le_get_module_type(bin);
	bin->cpu = le_get_cpu_type(bin);
	bin->os = le_get_os_type(bin);
	bin->arch = le_get_arch(bin);

	ut64 off = bin->le_off + bin->header->restab;
	le_read_len_str_offset(bin->buf, &off, &bin->modname);

	err_ctx = ", unable to load objects.";
	CHECK(le_load_objects(bin));
	err_ctx = ", unable to load data pages.";
	CHECK(bin->le_pages = le_load_pages(bin));
	err_ctx = ", unable to build maps.";
	CHECK(bin->le_maps = le_create_maps(bin));
	err_ctx = ", unable to load imports.";
	CHECK(bin->imports = rz_pvector_new((RzListFree)rz_bin_import_free));
	CHECK(bin->symbols = rz_list_newf((RzListFree)rz_bin_symbol_free));
	CHECK(bin->imp_mod_names = le_load_import_mod_names(bin));
	CHECK(bin->le_entries = le_load_entries(bin));
	err_ctx = ", unable to load and apply relocations.";
	CHECK(bin->le_fixups = rz_list_newf(free));
	CHECK(bin->le_relocs = le_load_relocs(bin));
	CHECK(le_patch_relocs(bin));

	obj->bin_obj = bin;
	return true;
}

bool rz_bin_le_check_buffer(RzBuffer *b) {
	return le_get_header_offset(b, NULL, NULL);
}

static void no_free(void *unused) {}

RZ_OWN RzPVector /*<RzBinImport *>*/ *rz_bin_le_get_imports(RzBinFile *bf) {
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	if (rz_pvector_empty(bin->imports)) {
		return NULL;
	}
	RzPVector *l = rz_pvector_clone(bin->imports);
	l->v.free_user = no_free; // silence assertion, there's no need to delete imports
	return l;
}

RZ_OWN RzPVector /*<RzBinSymbol *>*/ *rz_bin_le_get_symbols(RzBinFile *bf) {
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	if (rz_list_empty(bin->symbols)) {
		return NULL;
	}
	RzListIter *iter;
	RzBinSymbol *sym;
	RzPVector *vec = rz_pvector_new(NULL);
	rz_list_foreach (bin->symbols, iter, sym) {
		rz_pvector_push(vec, sym);
	}
	return vec;
}

RZ_OWN RzPVector /*<RzBinSection *>*/ *rz_bin_le_get_sections(RzBinFile *bf) {
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	RzPVector *sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	RzBinSection *sec = NULL;
	if (!sections) {
	fail_cleanup:
		rz_pvector_free(sections);
		rz_bin_section_free(sec);
		return NULL;
	}

	ut32 obj_num = 0, sec_num = 0;
	LE_map *le_map;
	rz_vector_foreach (bin->le_maps, le_map) {
		CHECK(sec = RZ_NEW0(RzBinSection));

		if (obj_num == le_map->obj_num) {
			sec_num++;
		} else {
			obj_num = le_map->obj_num;
			sec_num = 1;
		}
		CHECK(sec->name = rz_str_newf("obj%u_%u", obj_num, sec_num));

		sec->size = le_map->size;
		sec->vsize = le_map->vsize;
		sec->vaddr = le_map->vaddr;
		sec->paddr = le_map->paddr;

		LE_object *obj = &bin->objects[obj_num - 1];
		sec->perm = le_obj_perm(obj);
		sec->bits = obj->flags & O_BIG_BIT ? RZ_SYS_BITS_32 : RZ_SYS_BITS_16;
		sec->is_data = obj->flags & O_RESOURCE || !(sec->perm & RZ_PERM_X);

		CHECK(rz_pvector_push(sections, sec));
		sec = NULL;
	}

	return sections;
}

RZ_OWN RzPVector /*<RzBinAddr *>*/ *rz_bin_le_get_entry_points(RzBinFile *bf) {
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	LE_header *h = bin->header;
	RzBinAddr *addr = NULL;
	RzPVector *entries = rz_pvector_new((RzPVectorFree)free);
	if (!entries) {
	fail_cleanup:
		rz_pvector_free(entries);
		free(addr);
		return NULL;
	}

	// EXE entry point or DLL initialization routine, h->startobj can be 0 (invalid) for DLL,
	// which means this particular DLL does not need initialization.
	if (h->startobj - 1 < h->objcnt) {
		CHECK(addr = RZ_NEW0(RzBinAddr));
		addr->vaddr = bin->objects[h->startobj - 1].reloc_base_addr + h->eip;
		addr->paddr = le_vaddr_to_paddr(bin, addr->vaddr);
		CHECK(rz_pvector_push(entries, addr));
		addr = NULL;
	}

	// Exported functions, only DLLs have these.
	LE_entry *e;
	rz_vector_foreach (bin->le_entries, e) {
		if (!e->is_empty && !e->is_forwarder && e->is_exported && e->symbol) {
			CHECK(addr = RZ_NEW0(RzBinAddr));
			addr->vaddr = e->symbol->vaddr;
			addr->paddr = le_vaddr_to_paddr(bin, addr->vaddr);
			CHECK(rz_pvector_push(entries, addr));
			addr = NULL;
		}
	}

	return entries;
}

static void str_copy(void *dst, void *src) {
	char **_dst = (char **)dst;
	char **_src = (char **)src;
	*_dst = rz_str_dup(*_src);
}

RZ_OWN RzPVector /*<char *>*/ *rz_bin_le_get_libs(RzBinFile *bf) {
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	if (rz_pvector_empty(bin->imp_mod_names)) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_clonef(bin->imp_mod_names, str_copy);
	if (ret) {
		ret->v.free = bin->imp_mod_names->v.free;
		ret->v.free_user = bin->imp_mod_names->v.free_user;
	}
	return ret;
}

#define VFILE_NAME_PATCHED       "patched"
#define VFILE_NAME_RELOC_TARGETS "reloc-targets"

RZ_OWN RzPVector /*<RzBinVirtualFile *>*/ *rz_bin_le_get_virtual_files(RzBinFile *bf) {
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	RzBinVirtualFile *vf = NULL;
	RzBuffer *buf = NULL;
	RzPVector *vfiles = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!vfiles) {
	fail_cleanup:
		rz_bin_virtual_file_free(vf);
		rz_pvector_free(vfiles);
		rz_buf_free(buf);
		return NULL;
	}

	if (bin->buf_patched) {
		// patched vfile over main buffer
		CHECK(vf = RZ_NEW0(RzBinVirtualFile));
		CHECK(vf->name = rz_str_dup(VFILE_NAME_PATCHED));
		vf->buf = bin->buf_patched;
		vf->buf_owned = false;
		CHECK(rz_pvector_push(vfiles, vf));
		vf = NULL;
	}

	// virtual file per memory range not backed by physical pages (unpacked & zero-filled pages)
	LE_map *le_map;
	rz_vector_foreach (bin->le_maps, le_map) {
		if (le_map->is_physical) {
			continue;
		}
		CHECK(vf = RZ_NEW0(RzBinVirtualFile));
		CHECK(vf->name = rz_str_dup(le_map->vfile_name));
		vf->buf = le_map->vfile_buf;
		vf->buf_owned = false;
		CHECK(rz_pvector_push(vfiles, vf));
		vf = NULL;
	}

	// virtual file for reloc targets
	ut64 rtmsz = le_reloc_targets_vfile_size(bin);
	if (rtmsz) {
		CHECK(vf = RZ_NEW0(RzBinVirtualFile));
		CHECK(vf->name = rz_str_dup(VFILE_NAME_RELOC_TARGETS))
		CHECK(vf->buf = rz_buf_new_empty(rtmsz));
		vf->buf_owned = true;
		CHECK(rz_pvector_push(vfiles, vf));
		vf = NULL;
	}

	return vfiles;
}

RZ_OWN RzPVector /*<RzBinReloc *>*/ *rz_bin_le_get_relocs(RzBinFile *bf) {
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	RzList /*<LE_reloc *>*/ *le_relocs = bin->le_relocs;
	RzPVector /*<RzBinReloc *>*/ *relocs = rz_pvector_new(free);
	RzBinReloc *reloc = NULL;
	if (!relocs) {
	fail_cleanup:
		rz_pvector_free(relocs);
		rz_bin_reloc_free(reloc);
		return NULL;
	}

	RzListIter *it;
	LE_reloc *le_reloc;
	rz_list_foreach (le_relocs, it, le_reloc) {
		CHECK(reloc = RZ_NEW0(RzBinReloc));
		CHECK(rz_pvector_push(relocs, reloc));
		reloc->symbol = le_reloc->symbol;
		reloc->import = le_reloc->import;
		reloc->addend = le_reloc->addend;
		reloc->vaddr = le_reloc_vaddr(bin, le_reloc);
		reloc->paddr = le_vaddr_to_paddr(bin, reloc->vaddr);
		reloc->target_vaddr = le_reloc->target_vaddr;

		switch (le_reloc->type) {
		case FIXUP_BYTE:
			reloc->type = RZ_BIN_RELOC_8;
			break;

		case FIXUP_SEL16:
		case FIXUP_OFF16:
			reloc->type = RZ_BIN_RELOC_16;
			break;

		case FIXUP_OFF32:
		case FIXUP_SEL16_OFF16:
		case FIXUP_REL32:
			reloc->type = RZ_BIN_RELOC_32;
			break;

		case FIXUP_SEL16_OFF32:
			reloc->type = RZ_BIN_RELOC_32;
			reloc = NULL;

			// adding additional 2-byte relocation right after the 4-byte one
			// to represent a 48 bit 16:32 relocation
			CHECK(reloc = RZ_NEW0(RzBinReloc));
			*reloc = *(RzBinReloc *)rz_pvector_tail(relocs);
			reloc->vaddr += 4;
			reloc->paddr += 4;
			reloc->type = RZ_BIN_RELOC_16;
			CHECK(rz_pvector_push(relocs, reloc));
			reloc = NULL;
			break;

		default:
			break;
		}
	}
	return relocs;
}

RZ_OWN RzPVector /*<RzBinMap *>*/ *rz_bin_le_get_maps(RzBinFile *bf) {
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	RzPVector *maps = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	RzBinMap *map = NULL;
	if (!maps) {
	fail_cleanup:
		rz_pvector_free(maps);
		rz_bin_map_free(map);
		return NULL;
	}

	LE_map *le_map;
	ut32 map_num = 0;
	ut32 obj_num = 0;
	rz_vector_foreach (bin->le_maps, le_map) {
		LE_object *obj = &bin->objects[le_map->obj_num - 1];
		if (le_map->obj_num != obj_num) {
			obj_num = le_map->obj_num;
			map_num = 1;
		} else {
			map_num++;
		}
		CHECK(map = RZ_NEW0(RzBinMap));
		map->perm = le_obj_perm(obj);
		map->vaddr = le_map->vaddr;
		map->psize = le_map->size;
		map->vsize = le_map->vsize;
		CHECK(map->name = rz_str_newf("obj%u_map%u", obj_num, map_num));
		if (le_map->is_physical) {
			map->paddr = le_map->paddr;
			CHECK(map->vfile_name = rz_str_dup(VFILE_NAME_PATCHED));
		} else {
			map->paddr = 0;
			if (map->psize != 0) {
				CHECK(map->vfile_name = rz_str_dup(le_map->vfile_name));
			}
		}
		CHECK(rz_pvector_push(maps, map));
		map = NULL;
	}

	CHECK(map = RZ_NEW0(RzBinMap));
	ut64 rtmsz = le_reloc_targets_vfile_size(bin);
	map->perm = RZ_PERM_R | RZ_PERM_X;
	map->vaddr = bin->reloc_target_map_base;
	map->psize = rtmsz;
	map->vsize = rtmsz;
	CHECK(map->name = rz_str_dup(VFILE_NAME_RELOC_TARGETS));
	CHECK(map->vfile_name = rz_str_dup(VFILE_NAME_RELOC_TARGETS));
	CHECK(rz_pvector_push(maps, map));

	return maps;
}
