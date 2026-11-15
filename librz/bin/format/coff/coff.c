// SPDX-FileCopyrightText: 2019-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#include "coff.h"

static bool coff_is_magic(ut16 arch) {
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
	case COFF_FILE_MACHINE_H8500:
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
		/* fall-thru */
	case COFF_FILE_TARGET_TI_TMS320C1x2x5x:
		/* first-generation TI fixed-point COFF (C1x/C2x/C5x): the target id
		 * doubles as the file magic, unlike the later COFF1/COFF2 (0xc1/0xc2)
		 * which carry a separate target id field. */
		/* fall-thru */
	case COFF_FILE_MACHINE_MIL1750:
		return true;
	default:
		return false;
	}
}

static bool coff_is_ti_machine(struct rz_bin_coff_obj *obj) {
	return obj->hdr.f_magic == COFF_FILE_MACHINE_TI_1 ||
		obj->hdr.f_magic == COFF_FILE_MACHINE_TI_2;
}

static bool coff_guess_endianness(RzBuffer *b, bool *big_endian) {
	ut16 magic = 0;
	if (!rz_buf_read_le16_at(b, 0, &magic)) {
		return false;
	} else if (coff_is_magic(magic)) {
		*big_endian = false;
		return true;
	} else if (!rz_buf_read_be16_at(b, 0, &magic)) {
		return false;
	} else if (coff_is_magic(magic)) {
		*big_endian = true;
		return true;
	}
	return false;
}

RZ_API bool rz_coff_supported_arch(RzBuffer *b) {
	bool big_endian = false;
	return coff_guess_endianness(b, &big_endian);
}

/**
 * \brief Bytes per target address unit of \p obj.
 * \param obj COFF object
 * \return 1 for byte-addressed targets, 2 for the 16-bit word-addressed TI DSPs
 *
 * The C54x and C28x address 16-bit words, so their loadable section
 * sizes and every address in the file count words, not bytes. Rizin's address
 * space is byte-based, so those have to be scaled to line up with the section
 * data. Debug sections are byte streams even on these targets and are excluded
 * by the caller.
 */
RZ_API ut32 rz_coff_addr_scale(RZ_NONNULL struct rz_bin_coff_obj *obj) {
	rz_return_val_if_fail(obj, 1);
	switch (obj->target_id) {
	case COFF_FILE_TARGET_TI_TMS320C1x2x5x:
	case COFF_FILE_TARGET_TI_TMS320C5400:
	case COFF_FILE_TARGET_TI_TMS320C2800:
		return 2;
	default:
		// The C55x addresses program memory by byte, so its objects need no
		// scaling despite being a fixed-point DSP.
		return 1;
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
	ut32 zero = rz_read_at_ble32(ptr, 0, obj->big_endian);
	ut32 offset = rz_read_at_ble32(ptr, 4, obj->big_endian);
	if (zero) {
		return rz_str_ndup((const char *)ptr, 8);
	}
	ut32 addr = obj->hdr.f_symptr + (obj->hdr.f_nsyms * COFF_SYMBOL_SIZE) + offset;
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
	CoffScnHdr *scn_hdr = rz_vector_index_ptr(obj->scn_hdrs, sym->n_scnum - 1);
	addr->paddr = scn_hdr->s_scnptr + sym->n_value;
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
	if (rz_vector_empty(obj->symbols)) {
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

	CoffSym *sym;
	rz_vector_foreach (obj->symbols, sym) {
		if ((coff_is_symbol_name(sym->n_name, "start") ||
			    coff_is_symbol_name(sym->n_name, "main")) &&
			coff_rebase_sym(obj, addr, sym)) {
			return addr;
		}
	}

	free(addr);
	return NULL;
}

static bool coff_init_hdr(RzBuffer *b, ut64 *offset, struct coff_hdr *hdr, bool big_endian) {
	return rz_buf_read_ble16_offset(b, offset, &hdr->f_magic, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &hdr->f_nscns, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &hdr->f_timdat, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &hdr->f_symptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &hdr->f_nsyms, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &hdr->f_opthdr, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &hdr->f_flags, big_endian);
}

static bool bin_coff_init_hdr(RzBuffer *b, struct rz_bin_coff_obj *obj, ut64 *offset) {
	if (!coff_init_hdr(b, offset, &obj->hdr, obj->big_endian)) {
		return false;
	} else if (coff_is_ti_machine(obj)) {
		return rz_buf_read_ble16_offset(b, offset, &obj->target_id, obj->big_endian);
	} else if (obj->hdr.f_magic == COFF_FILE_TARGET_TI_TMS320C1x2x5x) {
		// Original TI COFF has no separate field: the magic is the target id.
		obj->target_id = obj->hdr.f_magic;
	}
	return true;
}

static bool bin_coff_init_opt_hdr(RzBuffer *b, struct rz_bin_coff_obj *obj, ut64 *offset) {
	if (!obj->hdr.f_opthdr) {
		// optional header is not present.
		return true;
	}

	return rz_buf_read_ble16_offset(b, offset, &obj->opt_hdr.magic, obj->big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &obj->opt_hdr.vstamp, obj->big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &obj->opt_hdr.tsize, obj->big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &obj->opt_hdr.dsize, obj->big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &obj->opt_hdr.bsize, obj->big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &obj->opt_hdr.entry, obj->big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &obj->opt_hdr.text_start, obj->big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &obj->opt_hdr.data_start, obj->big_endian);
}

static bool coff_init_scn_hdr(RzBuffer *b, ut64 *offset, struct coff_scn_hdr *scn, bool big_endian) {
	return rz_buf_read_offset(b, offset, (ut8 *)scn->s_name, sizeof(scn->s_name)) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_paddr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_vaddr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_size, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_scnptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_relptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_lnnoptr, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &scn->s_nreloc, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &scn->s_nlnno, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_flags, big_endian);
}

/* TI COFF v2 section header is 48 bytes (vs 40 for the standard
 * COFF1 form). The relocation and line-number counts are widened
 * from 16 to 32 bits, and a 2-byte reserved field plus a 2-byte
 * memory-page-number field are appended. The TI 'Common Object File
 * Format Specification' (SPRAAO8) documents this; the asm55p /
 * cl55 toolchain in the TI C55x+ SDK produces this layout. Mis-
 * parsing as the 40-byte form leaves the section table walking
 * off-by-8 per section, which in practice produces vaddr and size
 * fields full of garbage (e.g. 0x7461642e, ASCII '.dat' from the
 * adjacent section name). */
static bool coff_init_scn_hdr_ti(RzBuffer *b, ut64 *offset, struct coff_scn_hdr *scn, bool big_endian) {
	ut32 nreloc32 = 0;
	ut32 nlnno32 = 0;
	ut16 reserved = 0;
	ut16 mempage = 0;
	bool ok = rz_buf_read_offset(b, offset, (ut8 *)scn->s_name, sizeof(scn->s_name)) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_paddr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_vaddr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_size, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_scnptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_relptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_lnnoptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &nreloc32, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &nlnno32, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &scn->s_flags, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &reserved, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &mempage, big_endian);
	if (ok) {
		/* Clamp the wider TI counts to the 16-bit fields that the
		 * rest of the COFF code uses; the section table is the only
		 * place where TI widens these. Real-world section relocation
		 * counts well above 64K are unheard of. */
		scn->s_nreloc = (ut16)(nreloc32 > UT16_MAX ? UT16_MAX : nreloc32);
		scn->s_nlnno = (ut16)(nlnno32 > UT16_MAX ? UT16_MAX : nlnno32);
	}
	return ok;
}

static bool bin_coff_init_scn_hdr(RzBuffer *b, struct rz_bin_coff_obj *obj, ut64 *offset) {
	obj->scn_hdrs = rz_vector_new(sizeof(struct coff_scn_hdr), NULL, NULL);
	if (!obj->scn_hdrs) {
		return false;
	}

	const bool ti_v2 = coff_is_ti_machine(obj);
	for (size_t i = 0; i < obj->hdr.f_nscns; ++i) {
		struct coff_scn_hdr scn = { 0 };
		const bool ok = ti_v2
			? coff_init_scn_hdr_ti(b, offset, &scn, obj->big_endian)
			: coff_init_scn_hdr(b, offset, &scn, obj->big_endian);
		if (!ok) {
			return false;
		}
		rz_vector_push(obj->scn_hdrs, &scn);
	}

	return true;
}

static bool coff_init_sym(RzBuffer *b, ut64 *offset, struct coff_symbol *sym, bool big_endian) {
	return rz_buf_read_offset(b, offset, (ut8 *)sym->n_name, sizeof(sym->n_name)) &&
		rz_buf_read_ble32_offset(b, offset, &sym->n_value, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &sym->n_scnum, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &sym->n_type, big_endian) &&
		rz_buf_read_ble8_offset(b, offset, &sym->n_sclass, big_endian) &&
		rz_buf_read_ble8_offset(b, offset, &sym->n_numaux, big_endian);
}

static bool bin_coff_init_symtable(RzBuffer *b, struct rz_bin_coff_obj *obj) {
	ut64 offset = obj->hdr.f_symptr;
	if (obj->hdr.f_nsyms >= 0xffff) {
		// too many symbols, probably not allocatable
		return false;
	}

	obj->symbols = rz_vector_new(sizeof(struct coff_symbol), NULL, NULL);
	if (!obj->symbols) {
		return false;
	}

	for (size_t i = 0; i < obj->hdr.f_nsyms; ++i) {
		struct coff_symbol sym = { 0 };
		if (!coff_init_sym(b, &offset, &sym, obj->big_endian)) {
			return false;
		}
		rz_vector_push(obj->symbols, &sym);
	}

	return true;
}

static bool bin_coff_init_scn_va(struct rz_bin_coff_obj *obj) {
	obj->scn_va = RZ_NEWS(ut64, obj->hdr.f_nscns);
	if (!obj->scn_va) {
		return false;
	}
	// A fully linked executable (F_EXEC) carries the real load addresses in
	// each section's s_vaddr; honor them so section and symbol VAs match the
	// binary (e.g. TI COFF executables place .text at 0x100, .bss high, and
	// vectors at 0xffff00 -- not a packed sequential layout). For relocatable
	// objects (s_vaddr typically all zero) keep the historical sequential,
	// 16-aligned fallback so each section still gets a distinct base.
	const bool is_exec = (obj->hdr.f_flags & COFF_FLAGS_TI_F_EXEC) != 0;
	size_t i = 0;
	ut64 va = 0;
	CoffScnHdr *scn_hdr;
	rz_vector_enumerate (obj->scn_hdrs, scn_hdr, i) {
		if (is_exec) {
			obj->scn_va[i] = (ut64)scn_hdr->s_vaddr * rz_coff_addr_scale(obj);
			continue;
		}
		obj->scn_va[i] = va;
		// Advance by the mapped byte length so the synthetic bases cannot
		// overlap once a word-counted section is scaled.
		const ut32 loadable = COFF_SCN_CNT_CODE | COFF_SCN_CNT_INIT_DATA | COFF_SCN_CNT_UNIN_DATA;
		const ut32 scale = (scn_hdr->s_flags & loadable) ? rz_coff_addr_scale(obj) : 1;
		va += scn_hdr->s_size ? (ut64)scn_hdr->s_size * scale : 16;
		va = RZ_ROUND(va, 16ULL);
	}
	return true;
}

RZ_API struct rz_bin_coff_obj *rz_bin_coff_new_buf(RzBuffer *buf) {
	ut64 offset = 0;
	struct rz_bin_coff_obj *obj = RZ_NEW0(struct rz_bin_coff_obj);
	if (!obj) {
		return NULL;
	}
	obj->b = rz_buf_ref(buf);
	obj->size = rz_buf_size(buf);
	obj->sym_ht = ht_up_new(NULL, NULL);
	obj->imp_ht = ht_up_new(NULL, NULL);
	obj->imp_index = ht_uu_new();

	if (!coff_guess_endianness(buf, &obj->big_endian)) {
		RZ_LOG_ERROR("failed to guess magic & endianness\n");
		rz_bin_coff_free(obj);
		return NULL;
	} else if (!bin_coff_init_hdr(buf, obj, &offset)) {
		RZ_LOG_ERROR("failed to init hdr\n");
		rz_bin_coff_free(obj);
		return NULL;
	} else if (!bin_coff_init_opt_hdr(buf, obj, &offset)) {
		RZ_LOG_ERROR("failed to init optional hdr\n");
		rz_bin_coff_free(obj);
		return NULL;
	} else if (!bin_coff_init_scn_hdr(buf, obj, &offset)) {
		RZ_LOG_ERROR("failed to init section header\n");
		rz_bin_coff_free(obj);
		return NULL;
	} else if (!bin_coff_init_scn_va(obj)) {
		RZ_LOG_ERROR("failed to init section VA table\n");
		rz_bin_coff_free(obj);
		return NULL;
	} else if (!bin_coff_init_symtable(buf, obj)) {
		RZ_LOG_ERROR("failed to init symtable\n");
		rz_bin_coff_free(obj);
		return NULL;
	}

	return obj;
}

RZ_API void rz_bin_coff_free(struct rz_bin_coff_obj *obj) {
	if (!obj) {
		return;
	}
	ht_up_free(obj->sym_ht);
	ht_up_free(obj->imp_ht);
	ht_uu_free(obj->imp_index);
	free(obj->scn_va);
	rz_vector_free(obj->scn_hdrs);
	rz_vector_free(obj->symbols);
	rz_buf_free(obj->buf_patched);
	free(obj);
}
