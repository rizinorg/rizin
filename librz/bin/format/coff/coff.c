// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#include "coff.h"

static bool coff_is_supported_arch(ut16 arch) {
	switch (arch) {
	case COFF_FILE_MACHINE_ALPHA:
		/* fall-thru */
	case COFF_FILE_MACHINE_ALPHA64:
		/* fall-thru */
	case COFF_FILE_MACHINE_AM33:
		/* fall-thru */
	case COFF_FILE_MACHINE_AMD64:
		/* fall-thru */
	case COFF_FILE_MACHINE_ARM:
		/* fall-thru */
	case COFF_FILE_MACHINE_ARMNT:
		/* fall-thru */
	case COFF_FILE_MACHINE_ARM64:
		/* fall-thru */
	case COFF_FILE_MACHINE_EBC:
		/* fall-thru */
	case COFF_FILE_MACHINE_I386:
		/* fall-thru */
	case COFF_FILE_MACHINE_I386_PTX:
		/* fall-thru */
	case COFF_FILE_MACHINE_I386_AIX:
		/* fall-thru */
	case COFF_FILE_MACHINE_IA64:
		/* fall-thru */
	case COFF_FILE_MACHINE_M32R:
		/* fall-thru */
	case COFF_FILE_MACHINE_MIPS16:
		/* fall-thru */
	case COFF_FILE_MACHINE_MIPSFPU:
		/* fall-thru */
	case COFF_FILE_MACHINE_MIPSFPU16:
		/* fall-thru */
	case COFF_FILE_MACHINE_AMD29KBE:
		/* fall-thru */
	case COFF_FILE_MACHINE_AMD29KLE:
		/* fall-thru */
	case COFF_FILE_MACHINE_POWERPC:
		/* fall-thru */
	case COFF_FILE_MACHINE_POWERPCFP:
		/* fall-thru */
	case COFF_FILE_MACHINE_SH3:
		/* fall-thru */
	case COFF_FILE_MACHINE_SH3DSP:
		/* fall-thru */
	case COFF_FILE_MACHINE_SH4:
		/* fall-thru */
	case COFF_FILE_MACHINE_SH5:
		/* fall-thru */
	case COFF_FILE_MACHINE_THUMB:
		/* fall-thru */
	case COFF_FILE_MACHINE_WCEMIPSV2:
		/* fall-thru */
	case COFF_FILE_MACHINE_H8300:
		/* fall-thru */
	case COFF_FILE_MACHINE_M68K:
		/* fall-thru */
	case COFF_FILE_MACHINE_68KAUX:
		/* fall-thru */
	case COFF_FILE_MACHINE_PIC30:
		/* fall-thru */
	case COFF_FILE_MACHINE_I960RO:
		/* fall-thru */
	case COFF_FILE_MACHINE_I960RW:
		/* fall-thru */
	case COFF_FILE_MACHINE_R3000:
		/* fall-thru */
	case COFF_FILE_MACHINE_R4000:
		/* fall-thru */
	case COFF_FILE_MACHINE_R10000:
		/* fall-thru */
	case COFF_FILE_MACHINE_RISCV32:
		/* fall-thru */
	case COFF_FILE_MACHINE_RISCV64:
		/* fall-thru */
	case COFF_FILE_MACHINE_RISCV128:
		/* fall-thru */
	case COFF_FILE_MACHINE_TI_1:
		/* fall-thru */
	case COFF_FILE_MACHINE_TI_2:
		return true;
	default:
		return false;
	}
}

RZ_API bool rz_coff_supported_arch(const ut8 *buf) {
	ut16 arch = rz_read_le16(buf);
	if (coff_is_supported_arch(arch)) {
		return true;
	}
	arch = rz_read_be16(buf);
	return coff_is_supported_arch(arch);
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

/**
 * \brief      Resolve a coff name to a C string.
 *
 * \param      obj   The object
 * \param[in]  ptr   The pointer to a buffer of at least 8 bytes
 *
 * \return     Returns always a valid pointer.
 */
RZ_API RZ_OWN char *rz_coff_symbol_name(RZ_NONNULL struct rz_bin_coff_obj *obj, RZ_NULLABLE const ut8 *ptr) {
	rz_return_val_if_fail(obj, NULL);
	if (!ptr) {
		return rz_str_dup("");
	}
	ut32 zero = rz_read_at_ble32(ptr, 0, obj->endian == COFF_IS_BIG_ENDIAN);
	ut32 offset = rz_read_at_ble32(ptr, 4, obj->endian == COFF_IS_BIG_ENDIAN);
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

static bool coff_rebase_sym(struct rz_bin_coff_obj *obj, RzBinAddr *addr, struct coff_symbol *sym) {
	if (sym->n_scnum < 1 || sym->n_scnum > obj->hdr.f_nscns) {
		return false;
	}
	addr->paddr = obj->scn_hdrs[sym->n_scnum - 1].s_scnptr + sym->n_value;
	return true;
}

static inline bool coff_is_symbol_name(const char *name, const char *expected) {
	if (RZ_STR_ISEMPTY(name)) {
		return false;
	} else if (name[0] == '_') {
		return RZ_STR_EQ(name + 1, expected);
	}
	return RZ_STR_EQ(name, expected);
}

/* Try to get a valid entrypoint using the methods outlined in
 * http://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_mono/ld.html#SEC24 */
RZ_API RzBinAddr *rz_coff_get_entry(struct rz_bin_coff_obj *obj) {
	if (!!obj->hdr.f_nsyms) {
		return NULL;
	}

	RzBinAddr *addr = RZ_NEW0(RzBinAddr);
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
	if (!obj->symbols) {
		free(addr);
		return NULL;
	}

	for (size_t i = 0; i < obj->hdr.f_nsyms; i++) {
		if ((coff_is_symbol_name(obj->symbols[i].n_name, "start") ||
			    coff_is_symbol_name(obj->symbols[i].n_name, "main")) &&
			coff_rebase_sym(obj, addr, &obj->symbols[i])) {
			return addr;
		}
	}

	free(addr);
	return NULL;
}

static bool coff_is_ti_machine(struct rz_bin_coff_obj *obj) {
	return obj->hdr.f_magic == COFF_FILE_MACHINE_TI_1 ||
		obj->hdr.f_magic == COFF_FILE_MACHINE_TI_2;
}

static bool bin_coff_init_hdr(struct rz_bin_coff_obj *obj) {
	ut16 magic = 0;
	if (!rz_buf_read_be16_at(obj->b, 0, &magic)) {
		return false;
	}
	if (coff_is_supported_arch(magic)) {
		// big endian
		obj->endian = true;
	} else {
		magic = rz_read_le16(&magic);
		if (!coff_is_supported_arch(magic)) {
			return false;
		}
		// little endian
		obj->endian = false;
	}

	int ret = rz_buf_fread_at(obj->b, 0, (ut8 *)&obj->hdr, obj->endian ? "2S3I2S" : "2s3i2s", 1);
	if (ret != sizeof(struct coff_hdr)) {
		return false;
	}

	if (coff_is_ti_machine(obj)) {
		ret = rz_buf_fread(obj->b, (ut8 *)&obj->target_id, obj->endian ? "S" : "s", 1);
		if (ret != sizeof(ut16)) {
			return false;
		}
	}
	return true;
}

static bool bin_coff_init_opt_hdr(struct rz_bin_coff_obj *obj) {
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

static bool bin_coff_init_scn_hdr(struct rz_bin_coff_obj *obj) {
	int ret, size;
	ut64 offset = sizeof(struct coff_hdr) + (obj->hdr.f_opthdr ? sizeof(struct coff_opt_hdr) : 0);
	if (coff_is_ti_machine(obj)) {
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

static bool bin_coff_init_symtable(struct rz_bin_coff_obj *obj) {
	int ret, size;
	ut64 offset = obj->hdr.f_symptr;
	if (obj->hdr.f_nsyms >= 0xffff) { // too much symbols, probably not allocatable
		return false;
	} else if (!obj->hdr.f_nsyms) {
		return true;
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

static bool bin_coff_init_scn_va(struct rz_bin_coff_obj *obj) {
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

RZ_API struct rz_bin_coff_obj *rz_bin_coff_new_buf(RzBuffer *buf, bool verbose) {
	struct rz_bin_coff_obj *obj = RZ_NEW0(struct rz_bin_coff_obj);
	if (!obj) {
		return NULL;
	}
	obj->b = rz_buf_ref(buf);
	obj->size = rz_buf_size(buf);
	obj->verbose = verbose;
	obj->sym_ht = ht_up_new(NULL, NULL);
	obj->imp_ht = ht_up_new(NULL, NULL);
	obj->imp_index = ht_uu_new();

	if (!bin_coff_init_hdr(obj)) {
		RZ_LOG_ERROR("failed to init hdr\n");
		rz_bin_coff_free(obj);
		return NULL;
	}

	bin_coff_init_opt_hdr(obj);
	if (!bin_coff_init_scn_hdr(obj)) {
		RZ_LOG_ERROR("failed to init section header\n");
		rz_bin_coff_free(obj);
		return NULL;
	}

	if (!bin_coff_init_scn_va(obj)) {
		RZ_LOG_ERROR("failed to init section VA table\n");
		rz_bin_coff_free(obj);
		return NULL;
	}

	if (!bin_coff_init_symtable(obj)) {
		RZ_LOG_ERROR("failed to init symtable\n");
		rz_bin_coff_free(obj);
		return NULL;
	}

	return obj;
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
