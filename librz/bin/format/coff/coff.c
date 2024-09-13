// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#include "coff.h"

RZ_API bool rz_coff_supported_arch(const ut8 *buf) {
	ut16 arch = rz_read_le16(buf);
	switch (arch) {
	case COFF_FILE_MACHINE_MIPS16:
	case COFF_FILE_MACHINE_MIPSFPU:
	case COFF_FILE_MACHINE_MIPSFPU16:
	case COFF_FILE_MACHINE_AMD64:
	case COFF_FILE_MACHINE_I386:
	case COFF_FILE_MACHINE_H8300:
	case COFF_FILE_TI_COFF:
	case COFF_FILE_MACHINE_R4000:
	case COFF_FILE_MACHINE_AMD29KBE:
	case COFF_FILE_MACHINE_AMD29KLE:
	case COFF_FILE_MACHINE_SH3:
	case COFF_FILE_MACHINE_SH3DSP:
	case COFF_FILE_MACHINE_SH4:
	case COFF_FILE_MACHINE_SH5:
	case COFF_FILE_MACHINE_THUMB:
	case COFF_FILE_MACHINE_ARM:
	case COFF_FILE_MACHINE_ARM64:
	case COFF_FILE_MACHINE_ARMNT:
		return true;
	default:
		return false;
	}
}

RZ_API ut64 rz_coff_perms_from_section_flags(ut32 flags) {
	ut32 r = 0;
	if (flags & COFF_SCN_MEM_READ) {
		r |= RZ_PERM_R;
	}
	if (flags & COFF_SCN_MEM_WRITE) {
		r |= RZ_PERM_W;
	}
	if (flags & COFF_SCN_MEM_EXECUTE) {
		r |= RZ_PERM_X;
	}
	if (flags & COFF_SCN_MEM_SHARED) {
		r |= RZ_PERM_SHAR;
	}
	return r;
}

/*
 * Resolve a coff name to a C string.
 * \param ptr buffer of at least 8 bytes
 */
RZ_API char *rz_coff_symbol_name(struct rz_bin_coff_obj *obj, const ut8 *ptr) {
	rz_return_val_if_fail(obj && ptr, NULL);
	ut32 zero = rz_read_at_ble32(ptr, 0, obj->endian == COFF_IS_BIG_ENDIAN);
	ut32 offset = rz_read_at_ble32(ptr, 4, obj->endian == COFF_IS_BIG_ENDIAN);
	if (!ptr) {
		return rz_str_dup("");
	}
	if (zero) {
		return rz_str_ndup((const char *)ptr, 8);
	}
	ut32 addr = obj->hdr.f_symptr + obj->hdr.f_nsyms * sizeof(struct coff_symbol) + offset;
	if (addr > obj->size) {
		return rz_str_dup("");
	}
	char n[256] = { 0 };
	st64 len = rz_buf_read_at(obj->b, addr, (ut8 *)n, sizeof(n) - 1);
	if (len < 1) {
		return rz_str_dup("");
	}
	return rz_str_dup(n);
}

static int rz_coff_rebase_sym(struct rz_bin_coff_obj *obj, RzBinAddr *addr, struct coff_symbol *sym) {
	if (sym->n_scnum < 1 || sym->n_scnum > obj->hdr.f_nscns) {
		return 0;
	}
	addr->paddr = obj->scn_hdrs[sym->n_scnum - 1].s_scnptr + sym->n_value;
	return 1;
}

/* Try to get a valid entrypoint using the methods outlined in
 * http://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_mono/ld.html#SEC24 */
RZ_API RzBinAddr *rz_coff_get_entry(struct rz_bin_coff_obj *obj) {
	RzBinAddr *addr = RZ_NEW0(RzBinAddr);
	int i;
	if (!addr) {
		return NULL;
	}
	/* Simplest case, the header provides the entrypoint address */
	if (obj->hdr.f_opthdr) {
		addr->paddr = obj->opt_hdr.entry;
		return addr;
	}
	/* No help from the header eh? Use the address of the symbols '_start'
	 * or 'main' if present */
	if (obj->symbols) {
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			if ((!strcmp(obj->symbols[i].n_name, "_start") ||
				    !strcmp(obj->symbols[i].n_name, "start")) &&
				rz_coff_rebase_sym(obj, addr, &obj->symbols[i])) {
				return addr;
			}
		}
		for (i = 0; i < obj->hdr.f_nsyms; i++) {
			if ((!strcmp(obj->symbols[i].n_name, "_main") ||
				    !strcmp(obj->symbols[i].n_name, "main")) &&
				rz_coff_rebase_sym(obj, addr, &obj->symbols[i])) {
				return addr;
			}
		}
	}
#if 0
	/* Still clueless ? Let's just use the address of .text */
	if (obj->scn_hdrs) {
		for (i = 0; i < obj->hdr.f_nscns; i++) {
			// avoid doing string matching and use x bit from the section
			if (obj->scn_hdrs[i].s_flags & COFF_SCN_MEM_EXECUTE) {
				addr->paddr = obj->scn_hdrs[i].s_scnptr;
				return addr;
			}
		}
	}
#else
	free(addr);
	return NULL;
#endif
	return addr;
}

static bool rz_bin_coff_init_hdr(struct rz_bin_coff_obj *obj) {
	ut16 magic;
	if (!rz_buf_read_le16_at(obj->b, 0, &magic)) {
		return false;
	}

	switch (magic) {
	case COFF_FILE_MACHINE_H8300:
	case COFF_FILE_MACHINE_AMD29KBE:
		obj->endian = COFF_IS_BIG_ENDIAN;
		break;
	default:
		obj->endian = COFF_IS_LITTLE_ENDIAN;
	}
	int ret = 0;
	ret = rz_buf_fread_at(obj->b, 0, (ut8 *)&obj->hdr, obj->endian ? "2S3I2S" : "2s3i2s", 1);
	if (ret != sizeof(struct coff_hdr)) {
		return false;
	}
	if (obj->hdr.f_magic == COFF_FILE_TI_COFF) {
		ret = rz_buf_fread(obj->b, (ut8 *)&obj->target_id, obj->endian ? "S" : "s", 1);
		if (ret != sizeof(ut16)) {
			return false;
		}
	}
	return true;
}

static bool rz_bin_coff_init_opt_hdr(struct rz_bin_coff_obj *obj) {
	int ret;
	if (!obj->hdr.f_opthdr) {
		return false;
	}
	ret = rz_buf_fread_at(obj->b, sizeof(struct coff_hdr),
		(ut8 *)&obj->opt_hdr, obj->endian ? "2S6I" : "2s6i", 1);
	if (ret != sizeof(struct coff_opt_hdr)) {
		return false;
	}
	return true;
}

static bool rz_bin_coff_init_scn_hdr(struct rz_bin_coff_obj *obj) {
	int ret, size;
	ut64 offset = sizeof(struct coff_hdr) + (obj->hdr.f_opthdr ? sizeof(struct coff_opt_hdr) : 0);
	if (obj->hdr.f_magic == COFF_FILE_TI_COFF) {
		offset += 2;
	}
	size = obj->hdr.f_nscns * sizeof(struct coff_scn_hdr);
	if (offset > obj->size || offset + size > obj->size || size < 0) {
		return false;
	}
	obj->scn_hdrs = calloc(1, size + sizeof(struct coff_scn_hdr));
	if (!obj->scn_hdrs) {
		return false;
	}
	ret = rz_buf_fread_at(obj->b, offset, (ut8 *)obj->scn_hdrs, obj->endian ? "8c6I2S1I" : "8c6i2s1i", obj->hdr.f_nscns);
	if (ret != size) {
		RZ_FREE(obj->scn_hdrs);
		return false;
	}
	return true;
}

static bool rz_bin_coff_init_symtable(struct rz_bin_coff_obj *obj) {
	int ret, size;
	ut64 offset = obj->hdr.f_symptr;
	if (obj->hdr.f_nsyms >= 0xffff || !obj->hdr.f_nsyms) { // too much symbols, probably not allocatable
		return false;
	}
	size = obj->hdr.f_nsyms * sizeof(struct coff_symbol);
	if (size < 0 ||
		size > obj->size ||
		offset > obj->size ||
		offset + size > obj->size) {
		return false;
	}
	obj->symbols = calloc(1, size + sizeof(struct coff_symbol));
	if (!obj->symbols) {
		return false;
	}
	ret = rz_buf_fread_at(obj->b, offset, (ut8 *)obj->symbols, obj->endian ? "8c1I2S2c" : "8c1i2s2c", obj->hdr.f_nsyms);
	if (ret != size) {
		RZ_FREE(obj->symbols);
		return false;
	}
	return true;
}

static bool rz_bin_coff_init_scn_va(struct rz_bin_coff_obj *obj) {
	obj->scn_va = RZ_NEWS(ut64, obj->hdr.f_nscns);
	if (!obj->scn_va) {
		return false;
	}
	int i;
	ut64 va = 0;
	for (i = 0; i < obj->hdr.f_nscns; i++) {
		obj->scn_va[i] = va;
		va += obj->scn_hdrs[i].s_size ? obj->scn_hdrs[i].s_size : 16;
		va = RZ_ROUND(va, 16ULL);
	}
	return true;
}

static int rz_bin_coff_init(struct rz_bin_coff_obj *obj, RzBuffer *buf, bool verbose) {
	obj->b = rz_buf_ref(buf);
	obj->size = rz_buf_size(buf);
	obj->verbose = verbose;
	obj->sym_ht = ht_up_new(NULL, NULL);
	obj->imp_ht = ht_up_new(NULL, NULL);
	obj->imp_index = ht_uu_new();
	if (!rz_bin_coff_init_hdr(obj)) {
		RZ_LOG_ERROR("failed to init hdr\n");
		return false;
	}
	rz_bin_coff_init_opt_hdr(obj);
	if (!rz_bin_coff_init_scn_hdr(obj)) {
		RZ_LOG_ERROR("failed to init section header\n");
		return false;
	}
	if (!rz_bin_coff_init_scn_va(obj)) {
		RZ_LOG_ERROR("failed to init section VA table\n");
		return false;
	}
	if (!rz_bin_coff_init_symtable(obj)) {
		RZ_LOG_ERROR("failed to init symtable\n");
		return false;
	}
	return true;
}

RZ_API void rz_bin_coff_free(struct rz_bin_coff_obj *obj) {
	ht_up_free(obj->sym_ht);
	ht_up_free(obj->imp_ht);
	ht_uu_free(obj->imp_index);
	free(obj->scn_va);
	free(obj->scn_hdrs);
	free(obj->symbols);
	rz_buf_free(obj->buf_patched);
	rz_buf_free(obj->b);
	free(obj);
}

RZ_API struct rz_bin_coff_obj *rz_bin_coff_new_buf(RzBuffer *buf, bool verbose) {
	struct rz_bin_coff_obj *bin = RZ_NEW0(struct rz_bin_coff_obj);
	rz_bin_coff_init(bin, buf, verbose);
	return bin;
}
