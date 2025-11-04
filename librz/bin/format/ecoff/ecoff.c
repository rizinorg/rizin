// SPDX-FileCopyrightText: 2025-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025-2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ecoff.h"
#include "ecoff_gen.c"

#define ECOFF_SECTION_TYPE_DATA_MASK (ECOFF_SECTION_TYPE_DATA | \
	ECOFF_SECTION_TYPE_BSS | \
	ECOFF_SECTION_TYPE_RDATA | \
	ECOFF_SECTION_TYPE_SDATA | \
	ECOFF_SECTION_TYPE_SBSS)

static ut32 ecoff_section_flags_to_perms(ut64 s_flags);
static bool ecoff_is_data_section(const ut32 s_flags);
static bool ecoff_section_flags_to_structure(const ut32 flags, RzStructuredData *parent);
static const char *ecoff_file_descr_entry_get_lang(const ut16 lang);
static const char *ecoff_file_descr_entry_get_glevel(const ut16 glevel);
static const char *ecoff_local_symbol_get_type(const ut32 st);
static const char *ecoff_local_symbol_get_storage_class(const ut32 sc);

static bool ecoff_is_big_endian(const ut16 magic) {
	switch (magic) {
	case ECOFF_MACHINE_MIPS1_BE:
		return true;
	case ECOFF_MACHINE_MIPS2_BE:
		return true;
	case ECOFF_MACHINE_MIPS3_BE:
		return true;
	default:
		return false;
	}
}

static bool ecoff_is_little_endian(const ut16 magic) {
	switch (magic) {
	case ECOFF_MACHINE_MIPS1:
		return true;
	case ECOFF_MACHINE_MIPS1_EL:
		return true;
	case ECOFF_MACHINE_MIPS2_EL:
		return true;
	case ECOFF_MACHINE_MIPS3_EL:
		return true;
	case ECOFF_MACHINE_ALPHA:
		return true;
	case ECOFF_MACHINE_ALPHA_BSD:
		return true;
	default:
		return false;
	}
}

static inline bool ecoff_is_ecoff64(const ECoff *ecoff) {
	return ecoff->type == ECOFF64;
}

static ut16 ecoff_machine(const ECoff *ecoff) {
	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff->ecoff64.header.f_magic;
	}
	return ecoff->ecoff32.header.f_magic;
}

static inline bool ecoff_is_mips_magic(const ut16 magic) {
	switch (magic) {
	case ECOFF_MACHINE_MIPS1:
		return true;
	case ECOFF_MACHINE_MIPS1_EL:
		return true;
	case ECOFF_MACHINE_MIPS2_EL:
		return true;
	case ECOFF_MACHINE_MIPS3_EL:
		return true;
	case ECOFF_MACHINE_MIPS1_BE:
		return true;
	case ECOFF_MACHINE_MIPS2_BE:
		return true;
	case ECOFF_MACHINE_MIPS3_BE:
		return true;
	default:
		return false;
	}
}

static inline bool ecoff_is_alpha_magic(const ut16 magic) {
	switch (magic) {
	case ECOFF_MACHINE_ALPHA:
		return true;
	case ECOFF_MACHINE_ALPHA_BSD:
		return true;
	default:
		return false;
	}
}

ECOFF_GEN_FUNCTIONS(32);
ECOFF_GEN_FUNCTIONS(64);

static inline bool ecoff_has_aouthdr(const ECoff *ecoff) {
	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff->ecoff64.header.f_opthdr;
	}

	return ecoff->ecoff32.header.f_opthdr;
}

void ecoff_free(ECoff *ecoff) {
	if (!ecoff) {
		return;
	}

	if (ecoff->type == ECOFF64) {
		rz_vector_free(ecoff->ecoff64.sections);
		rz_vector_free(ecoff->ecoff64.file_descs);
		rz_vector_free(ecoff->ecoff64.proc_descs);
		rz_vector_free(ecoff->ecoff64.local_symbols);
		rz_vector_free(ecoff->ecoff64.extern_symbols);
	} else {
		rz_vector_free(ecoff->ecoff32.sections);
		rz_vector_free(ecoff->ecoff32.file_descs);
		rz_vector_free(ecoff->ecoff32.proc_descs);
		rz_vector_free(ecoff->ecoff32.local_symbols);
		rz_vector_free(ecoff->ecoff32.extern_symbols);
		rz_vector_free(ecoff->ecoff32.symbols_old);
	}

	free(ecoff);
}

static bool ecoff_parse_magic(RzBuffer *buffer, ut16 *magic, bool *big_endian) {
	if (!rz_buf_read_be16_at(buffer, 0, magic)) {
		return false;
	} else if (ecoff_is_big_endian(*magic)) {
		*big_endian = true;
		return true;
	}
	if (!rz_buf_read_le16_at(buffer, 0, magic)) {
		return false;
	} else if (ecoff_is_little_endian(*magic)) {
		*big_endian = false;
		return true;
	}
	return false;
}

bool ecoff_is_valid_buffer(RzBuffer *buffer) {
	ut16 magic = 0;
	bool big_endian = false;
	return ecoff_parse_magic(buffer, &magic, &big_endian);
}

static bool ecoff_init_aouthdr_alpha(RzBuffer *b, ut64 *offset, ECoff_AOutHdr_Alpha *alpha, const bool big_endian) {
	return rz_buf_read_ble16_offset(b, offset, &alpha->magic, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, (ut16 *)alpha->vstamp, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->bldrev, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->padding, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->tsize, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->dsize, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->bsize, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->entry, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->text_start, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->data_start, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->bss_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->gpr_mask, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->fpr_mask, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->gp_value, big_endian);
}

static bool ecoff_init_aouthdr_mips(RzBuffer *b, ut64 *offset, ECoff_AOutHdr_Mips *mips, const bool big_endian) {
	return rz_buf_read_ble16_offset(b, offset, &mips->magic, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, (ut16 *)mips->vstamp, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->tsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->dsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->bsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->entry, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->text_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->data_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->bss_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->gpr_mask, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[0], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[1], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[2], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[3], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->gp_value, big_endian);
}

static bool ecoff_init_symbol_old(RzBuffer *b, ut64 *offset, ECoff_Symbol_Old *symbol, const bool big_endian) {
	return rz_buf_read_offset(b, offset, (ut8 *)symbol->e_name, sizeof(symbol->e_name)) &&
		rz_buf_read_ble32_offset(b, offset, &symbol->e_value, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, (ut16 *)&symbol->e_scnum, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &symbol->e_type, big_endian) &&
		rz_buf_read_ble8_offset(b, offset, (ut8 *)&symbol->e_sclass, big_endian) &&
		rz_buf_read_ble8_offset(b, offset, &symbol->e_numaux, big_endian);
}

static void ecoff_symbol_old_fini(void *element, void *x) {
	ECoff_Symbol_Old *symbol = element;
	free(symbol->resolved_name);
}

static bool ecoff_parse_old_symbols(RzBuffer *b, ECoff_32 *ecoff) {
	ut64 offset = ecoff->header.f_symptr;
	const size_t count = ecoff->header.f_nsyms;
	for (size_t i = 0; i < count; ++i) {
		ut64 location = offset;
		ECoff_Symbol_Old symbol = { 0 };
		if (!ecoff_init_symbol_old(b, &offset, &symbol, ecoff->big_endian)) {
			return false;
		}
		symbol.resolved_name = ecoff_resolve_name_32(b, ecoff, symbol.e_name);
		if (!symbol.resolved_name) {
			symbol.resolved_name = rz_str_newf("unknown_%" PFMT64x, location);
		}
		rz_vector_push(ecoff->symbols_old, &symbol);
	}

	return true;
}

static bool ecoff_parse_symbols_64(RzBuffer *buffer, ECoff_64 *ecoff) {
	if (ecoff->header.f_symptr < 0) {
		return false;
	} else if (!ecoff->header.f_symptr) {
		// there are no symbols so we do not fail.
		return true;
	}

	ut64 offset = ecoff->header.f_symptr;
	return ecoff_init_symbolic_header_64(buffer, &offset, &ecoff->symhdr, ecoff->big_endian) &&
		ecoff_has_symbolic_header_64(ecoff) &&
		ecoff_parse_local_symbols_64(buffer, ecoff) &&
		ecoff_parse_external_symbols_64(buffer, ecoff) &&
		ecoff_parse_file_descriptor_entries_64(buffer, ecoff) &&
		ecoff_parse_proc_descriptor_entries_64(buffer, ecoff) &&
		ecoff_resolve_symbols_64(buffer, ecoff);
}

static bool ecoff_init_aouthdr_64(RzBuffer *buffer, ut64 *offset, ECoff_64 *ecoff) {
	if (!ecoff->header.f_opthdr) {
		RZ_LOG_ERROR("ecoff: f_opthdr in ecoff64 header is 0\n");
		return false;
	} else if (ecoff_is_alpha_magic(ecoff->header.f_magic)) {
		return ecoff_init_aouthdr_alpha(buffer, offset, &ecoff->aouthdr.alpha, ecoff->big_endian);
	}
	RZ_LOG_ERROR("ecoff: unsupported aouthdr for ecoff64\n");
	return false;
}

static bool ecoff_parse_ecoff_64(RzBuffer *buffer, ECoff_64 *ecoff, const bool big_endian) {
	ut64 offset = 0;
	ecoff->big_endian = big_endian;

	ecoff->sections = rz_vector_new(sizeof(ECoff_Section_64), ecoff_section_fini_64, NULL);
	if (!ecoff->sections) {
		RZ_LOG_ERROR("ecoff: failed to allocate sections vector\n");
		return false;
	}

	ecoff->file_descs = rz_vector_new(sizeof(ECoff_FileDescEntry_64), NULL, NULL);
	if (!ecoff->file_descs) {
		RZ_LOG_ERROR("ecoff: failed to allocate fde vector\n");
		return false;
	}

	ecoff->proc_descs = rz_vector_new(sizeof(ECoff_ProcDescEntry_64), NULL, NULL);
	if (!ecoff->proc_descs) {
		RZ_LOG_ERROR("ecoff: failed to allocate pde vector\n");
		return false;
	}

	ecoff->local_symbols = rz_vector_new(sizeof(ECoff_LocalSymbol_64), ecoff_fini_local_symbol_64, NULL);
	if (!ecoff->local_symbols) {
		RZ_LOG_ERROR("ecoff: failed to allocate local symbols vector\n");
		return false;
	}

	ecoff->extern_symbols = rz_vector_new(sizeof(ECoff_ExternSymbol_64), ecoff_fini_external_symbol_64, NULL);
	if (!ecoff->extern_symbols) {
		RZ_LOG_ERROR("ecoff: failed to allocate external symbols vector\n");
		return false;
	}

	if (!ecoff_init_hdr_64(buffer, &offset, &ecoff->header, ecoff->big_endian)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff64 header\n");
		return false;
	} else if (!ecoff_init_aouthdr_64(buffer, &offset, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff64 aouthdr\n");
		return false;
		// first we parse the symbols, then the sections because we depend on the magic
	} else if (!ecoff_parse_symbols_64(buffer, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to parse ecoff64 symbols\n");
		return false;
	} else if (!ecoff_parse_sections_64(buffer, &offset, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff32 section table\n");
		return false;
	}
	return true;
}

static bool ecoff_parse_symbols_32(RzBuffer *buffer, ECoff_32 *ecoff) {
	if (ecoff->header.f_symptr < 0) {
		return false;
	} else if (!ecoff->header.f_symptr) {
		// there are no symbols so we do not fail.
		return true;
	}

	ut64 offset = ecoff->header.f_symptr;
	if (!ecoff_init_symbolic_header_32(buffer, &offset, &ecoff->symhdr, ecoff->big_endian)) {
		return false;
	}

	if (!ecoff_has_symbolic_header_32(ecoff)) {
		// there is no symbolic header, so it must be using the old format
		return ecoff_parse_old_symbols(buffer, ecoff);
	}

	return ecoff_parse_local_symbols_32(buffer, ecoff);

	return ecoff_parse_local_symbols_32(buffer, ecoff) &&
		ecoff_parse_external_symbols_32(buffer, ecoff) &&
		ecoff_parse_file_descriptor_entries_32(buffer, ecoff) &&
		ecoff_parse_proc_descriptor_entries_32(buffer, ecoff) &&
		ecoff_resolve_symbols_32(buffer, ecoff);
}

static bool ecoff_init_aouthdr_32(RzBuffer *buffer, ut64 *offset, ECoff_32 *ecoff) {
	if (!ecoff->header.f_opthdr) {
		RZ_LOG_ERROR("ecoff: f_opthdr in ecoff32 header is 0\n");
		return false;
	} else if (ecoff_is_mips_magic(ecoff->header.f_magic)) {
		return ecoff_init_aouthdr_mips(buffer, offset, &ecoff->aouthdr.mips, ecoff->big_endian);
	}
	RZ_LOG_ERROR("ecoff: unsupported aouthdr for ecoff32\n");
	return false;
}

static bool ecoff_parse_ecoff_32(RzBuffer *buffer, ECoff_32 *ecoff, const bool big_endian) {
	ut64 offset = 0;
	ecoff->big_endian = big_endian;

	ecoff->sections = rz_vector_new(sizeof(ECoff_Section_32), ecoff_section_fini_32, NULL);
	if (!ecoff->sections) {
		RZ_LOG_ERROR("ecoff: failed to allocate sections vector\n");
		return false;
	}

	ecoff->file_descs = rz_vector_new(sizeof(ECoff_FileDescEntry_32), NULL, NULL);
	if (!ecoff->file_descs) {
		RZ_LOG_ERROR("ecoff: failed to allocate fde vector\n");
		return false;
	}

	ecoff->proc_descs = rz_vector_new(sizeof(ECoff_ProcDescEntry_32), NULL, NULL);
	if (!ecoff->proc_descs) {
		RZ_LOG_ERROR("ecoff: failed to allocate pde vector\n");
		return false;
	}

	ecoff->local_symbols = rz_vector_new(sizeof(ECoff_LocalSymbol_32), ecoff_fini_local_symbol_32, NULL);
	if (!ecoff->local_symbols) {
		RZ_LOG_ERROR("ecoff: failed to allocate local symbols vector\n");
		return false;
	}

	ecoff->extern_symbols = rz_vector_new(sizeof(ECoff_ExternSymbol_32), ecoff_fini_external_symbol_32, NULL);
	if (!ecoff->extern_symbols) {
		RZ_LOG_ERROR("ecoff: failed to allocate external symbols vector\n");
		return false;
	}

	ecoff->symbols_old = rz_vector_new(sizeof(ECoff_Symbol_Old), ecoff_symbol_old_fini, NULL);
	if (!ecoff->symbols_old) {
		RZ_LOG_ERROR("ecoff: failed to allocate symbols (old format)\n");
		return false;
	}

	if (!ecoff_init_hdr_32(buffer, &offset, &ecoff->header, ecoff->big_endian)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff32 header\n");
		return false;
	} else if (!ecoff_init_aouthdr_32(buffer, &offset, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff32 aouthdr\n");
		return false;
		// first we parse the symbols, then the sections because we depend on the magic
	} else if (!ecoff_parse_symbols_32(buffer, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to parse ecoff32 symbols\n");
		return false;
	} else if (!ecoff_parse_sections_32(buffer, &offset, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff32 section table\n");
		return false;
	}

	return true;
}

ECoff *ecoff_parse_from_buffer(RzBuffer *buffer) {
	ut16 f_magic = 0;
	bool big_endian = false;

	ECoff *ecoff = RZ_NEW0(ECoff);
	if (!ecoff) {
		return NULL;
	} else if (!ecoff_parse_magic(buffer, &f_magic, &big_endian)) {
		RZ_LOG_ERROR("ecoff: is not an ecoff file\n");
		goto fail;
	}

	if (ecoff_is_alpha_magic(f_magic)) {
		ecoff->type = ECOFF64;
		if (!ecoff_parse_ecoff_64(buffer, &ecoff->ecoff64, big_endian)) {
			goto fail;
		}
	} else if (ecoff_is_mips_magic(f_magic)) {
		ecoff->type = ECOFF32;
		if (!ecoff_parse_ecoff_32(buffer, &ecoff->ecoff32, big_endian)) {
			goto fail;
		}
	} else {
		goto fail;
	}

	return ecoff;
fail:
	ecoff_free(ecoff);
	return NULL;
}

static ut32 ecoff_section_flags_to_perms(ut64 s_flags) {
	ut32 perms = 0;
	if (s_flags & ECOFF_SECTION_TYPE_REG) {
		// Regular section: allocated, relocated, loaded.
		perms |= RZ_PERM_RWX;
	}
	if (s_flags & ECOFF_SECTION_TYPE_TEXT) {
		// Text section
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DATA) {
		// Data section
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_BSS) {
		// Bss section
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_RDATA) {
		// Read-only data section
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_SDATA) {
		// Small data
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_SBSS) {
		// Small bss
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_UCODE) {
		// U-Code
		perms |= RZ_PERM_RX;
	}
	if (s_flags & ECOFF_SECTION_TYPE_GOT1) {
		// Global offset table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DYNAMIC1) {
		// Dynamic linking information
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DYNSYM1) {
		// Dynamic linking symbol table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_REL_DYN1) {
		// Dynamic relocation information
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DYNSTR1) {
		// Dynamic linking symbol table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_HASH1) {
		// Dynamic symbol hash table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DSOLIST1) {
		// Shared library dependency list
		perms |= RZ_PERM_R | RZ_PERM_SHAR;
	}
	if (s_flags & ECOFF_SECTION_TYPE_MSYM1) {
		// Additional dynamic linking symbol table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_LIT4) {
		// 4-byte literals
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_NRELOC_OVFL2) {
		// Indicates that section header field s_nreloc overflowed
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_LIB) {
		// Shared Library
		perms |= RZ_PERM_RX | RZ_PERM_SHAR;
	}
	if (s_flags & ECOFF_SECTION_TYPE_INIT) {
		// Initialization text
		perms |= RZ_PERM_RX;
	}

	ut32 extmask = s_flags & ECOFF_SECTION_EXT_TYPE_MASK;
	if (extmask == ECOFF_SECTION_EXT_TYPE_CONFLICT1) {
		// Additional dynamic linking information
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_RESOURCE) {
		// Resource
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_FINI) {
		// Termination text
		perms |= RZ_PERM_RX;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_RCONST) {
		// Read-only constants
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_XDATA) {
		// Exception scope table
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_TLSDATA) {
		// Initialized TLS data
		perms |= RZ_PERM_RW;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_TLSBSS) {
		// Uninitialized TLS data
		perms |= RZ_PERM_RW;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_TLSINIT) {
		// Initialization for TLS data
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_PDATA) {
		// Exception procedure table
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_LITA) {
		// Address literals
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_LIT8) {
		// 8-byte literals
		perms |= RZ_PERM_R;
	}

	return perms;
}

static bool ecoff_is_data_section(const ut32 s_flags) {
	const ut32 extflag = s_flags & ECOFF_SECTION_EXT_TYPE_MASK;

	return (s_flags & ECOFF_SECTION_TYPE_DATA_MASK) ||
		extflag == ECOFF_SECTION_EXT_TYPE_RESOURCE ||
		extflag == ECOFF_SECTION_EXT_TYPE_RCONST ||
		extflag == ECOFF_SECTION_EXT_TYPE_XDATA ||
		extflag == ECOFF_SECTION_EXT_TYPE_TLSDATA ||
		extflag == ECOFF_SECTION_EXT_TYPE_TLSBSS ||
		extflag == ECOFF_SECTION_EXT_TYPE_PDATA;
}

static RzBinAddr *ecoff_get_entrypoint(const ECoff *ecoff) {
	ut64 vaddr = 0;
	const ut16 magic = ecoff_machine(ecoff);
	if (ecoff_is_alpha_magic(magic)) {
		vaddr = ecoff->ecoff64.aouthdr.alpha.entry;
	} else if (ecoff_is_mips_magic(magic)) {
		vaddr = ecoff->ecoff32.aouthdr.mips.entry;
	}

	if (!vaddr) {
		// entry is invalid.
		return NULL;
	}

	RzBinAddr *baddr = RZ_NEW0(RzBinAddr);
	if (!baddr) {
		return NULL;
	}

	baddr->type = RZ_BIN_ENTRY_TYPE_INIT;
	baddr->paddr = UT64_MAX;
	baddr->vaddr = vaddr;
	if (ecoff_is_ecoff64(ecoff)) {
		ecoff_find_paddr_from_vaddr_64(&ecoff->ecoff64, baddr->vaddr, &baddr->paddr);
	} else {
		ecoff_find_paddr_from_vaddr_32(&ecoff->ecoff32, baddr->vaddr, &baddr->paddr);
	}
	return baddr;
}

static bool ecoff_local_symbol_is_function(const ut32 st) {
	return st == ECOFF_LOCAL_SYM_ST_PROC || st == ECOFF_LOCAL_SYM_ST_STATICPROC;
}

static RzBinAddr *ecoff_get_main_symbols_64(const ECoff_64 *ecoff) {
	ut64 vaddr = 0;
	const ECoff_LocalSymbol_64 *lsym = NULL;
	rz_vector_foreach (ecoff->local_symbols, lsym) {
		if (!ecoff_local_symbol_is_function(lsym->sc)) {
			continue;
		} else if (lsym->resolved_name && RZ_STR_EQ(lsym->resolved_name, "main")) {
			vaddr = lsym->value;
			break;
		}
	}

	if (!vaddr) {
		// main pointer is invalid.
		return NULL;
	}

	RzBinAddr *baddr = RZ_NEW0(RzBinAddr);
	if (!baddr) {
		return NULL;
	}

	baddr->type = RZ_BIN_ENTRY_TYPE_MAIN;
	baddr->paddr = UT64_MAX;
	baddr->vaddr = vaddr;
	ecoff_find_paddr_from_vaddr_64(ecoff, baddr->vaddr, &baddr->paddr);
	return baddr;
}

static RzBinAddr *ecoff_get_main_old_symbols(const ECoff *ecoff) {
	ut64 vaddr = 0;
	const ECoff_Symbol_Old *esym;
	rz_vector_foreach (ecoff->ecoff32.symbols_old, esym) {
		if (esym->resolved_name && RZ_STR_EQ(esym->resolved_name, "main")) {
			vaddr = esym->e_value;
			break;
		}
	}

	if (!vaddr) {
		// main pointer is invalid.
		return NULL;
	}

	RzBinAddr *baddr = RZ_NEW0(RzBinAddr);
	if (!baddr) {
		return NULL;
	}

	baddr->type = RZ_BIN_ENTRY_TYPE_MAIN;
	baddr->paddr = UT64_MAX;
	baddr->vaddr = vaddr;
	if (ecoff_is_ecoff64(ecoff)) {
		ecoff_find_paddr_from_vaddr_64(&ecoff->ecoff64, baddr->vaddr, &baddr->paddr);
	} else {
		ecoff_find_paddr_from_vaddr_32(&ecoff->ecoff32, baddr->vaddr, &baddr->paddr);
	}
	return baddr;
}

static RzBinAddr *ecoff_get_main_symbols_32(const ECoff_32 *ecoff) {
	ut64 vaddr = 0;
	const ECoff_LocalSymbol_32 *lsym = NULL;
	rz_vector_foreach (ecoff->local_symbols, lsym) {
		if (!ecoff_local_symbol_is_function(lsym->sc)) {
			continue;
		} else if (lsym->resolved_name && RZ_STR_EQ(lsym->resolved_name, "main")) {
			vaddr = lsym->value;
			break;
		}
	}

	if (!vaddr) {
		// main pointer is invalid.
		return NULL;
	}

	RzBinAddr *baddr = RZ_NEW0(RzBinAddr);
	if (!baddr) {
		return NULL;
	}

	baddr->type = RZ_BIN_ENTRY_TYPE_MAIN;
	baddr->paddr = UT64_MAX;
	baddr->vaddr = vaddr;
	ecoff_find_paddr_from_vaddr_32(ecoff, baddr->vaddr, &baddr->paddr);
	return baddr;
}

static RzBinAddr *ecoff_get_main(const ECoff *ecoff) {
	if (ecoff_is_ecoff64(ecoff)) {
		if (!ecoff_has_symbolic_header_64(&ecoff->ecoff64)) {
			return NULL;
		}
		return ecoff_get_main_symbols_64(&ecoff->ecoff64);
	} else if (ecoff_has_symbolic_header_32(&ecoff->ecoff32)) {
		return ecoff_get_main_symbols_32(&ecoff->ecoff32);
	}
	return ecoff_get_main_old_symbols(ecoff);
}

RzPVector /*<RzBinAddr *>*/ *ecoff_get_entries(const ECoff *ecoff) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)free);
	if (!ret) {
		return NULL;
	}

	RzBinAddr *baddr = ecoff_get_entrypoint(ecoff);
	if (baddr) {
		rz_pvector_push(ret, baddr);
	}

	baddr = ecoff_get_main(ecoff);
	if (baddr) {
		rz_pvector_push(ret, baddr);
	}

	return ret;
}

static bool ecoff_symbol_old_is_function(const ECoff_Symbol_Old *esym) {
	ut16 derived_type = (esym->e_type & ECOFF_SYMBOL_OLD_DERIVED_TYPE_MASK) >> 4;
	if (!derived_type) {
		return true;
	}
	return derived_type == ECOFF_SYMBOL_OLD_DERIVED_TYPE_FCN;
}

static bool ecoff_symbol_old_is_imported(const ECoff_Symbol_Old *esym) {
	return esym->e_scnum == ECOFF_SYMBOL_SECT_NUM_UNDEF &&
		esym->e_sclass == ECOFF_SYMBOL_OLD_SC_EFCN;
}

static bool ecoff_symbol_old_has_vaddr(const ECoff_Symbol_Old *esym) {
	ut16 derived_type = (esym->e_type & ECOFF_SYMBOL_OLD_DERIVED_TYPE_MASK) >> 4;
	if (!derived_type) {
		return true;
	}
	return derived_type == ECOFF_SYMBOL_OLD_DERIVED_TYPE_PTR ||
		derived_type == ECOFF_SYMBOL_OLD_DERIVED_TYPE_FCN;
}

static ut32 ecoff_symbol_old_type_to_size(const ECoff_Symbol_Old *esym) {
	switch (esym->e_type & ECOFF_SYMBOL_OLD_BASE_TYPE_MASK) {
	default: return 0;
	case ECOFF_SYMBOL_OLD_BASE_TYPE_CHAR: return 1;
	case ECOFF_SYMBOL_OLD_BASE_TYPE_SHORT: return 2;
	case ECOFF_SYMBOL_OLD_BASE_TYPE_INT: return 4;
	case ECOFF_SYMBOL_OLD_BASE_TYPE_LONG: return 8;
	case ECOFF_SYMBOL_OLD_BASE_TYPE_FLOAT: return 4;
	case ECOFF_SYMBOL_OLD_BASE_TYPE_DOUBLE: return 8;
	case ECOFF_SYMBOL_OLD_BASE_TYPE_ENUM: return 4;
	case ECOFF_SYMBOL_OLD_BASE_TYPE_UCHAR: return 1;
	case ECOFF_SYMBOL_OLD_BASE_TYPE_USHORT: return 2;
	case ECOFF_SYMBOL_OLD_BASE_TYPE_UINT: return 4;
	case ECOFF_SYMBOL_OLD_BASE_TYPE_ULONG: return 8;
	}
}

static const char *ecoff_symbol_old_type_to_bin_symbol_type(const ECoff_Symbol_Old *esym) {
	ut16 derived_type = (esym->e_type & ECOFF_SYMBOL_OLD_DERIVED_TYPE_MASK) >> 4;
	switch (derived_type) {
	default: return NULL;
	case ECOFF_SYMBOL_OLD_DERIVED_TYPE_PTR: return RZ_BIN_TYPE_OBJECT_STR;
	case ECOFF_SYMBOL_OLD_DERIVED_TYPE_FCN: return RZ_BIN_TYPE_FUNC_STR;
	case ECOFF_SYMBOL_OLD_DERIVED_TYPE_ARY: return RZ_BIN_TYPE_STATIC_STR;
	}
}

static RzBinSymbol *ecoff_symbol_old_to_bin_symbol(const ECoff_32 *ecoff, const ECoff_Symbol_Old *esym) {
	RzBinSymbol *bsym = RZ_NEW0(RzBinSymbol);
	if (!bsym) {
		return NULL;
	}

	bsym->type = ecoff_symbol_old_type_to_bin_symbol_type(esym);
	bsym->size = ecoff_symbol_old_type_to_size(esym);
	bsym->name = rz_str_dup(esym->resolved_name);
	bsym->forwarder = "NONE";
	bsym->is_imported = ecoff_symbol_old_is_imported(esym);
	if (bsym->is_imported) {
		bsym->bind = RZ_BIN_BIND_IMPORT_STR;
	} else if (ecoff_symbol_old_is_function(esym)) {
		bsym->bind = RZ_BIN_BIND_GLOBAL_STR;
	} else {
		bsym->bind = RZ_BIN_BIND_LOCAL_STR;
	}
	bsym->paddr = UT64_MAX;
	bsym->vaddr = UT64_MAX;
	if (esym->e_value && ecoff_symbol_old_has_vaddr(esym)) {
		bsym->vaddr = esym->e_value;
		ecoff_find_paddr_from_vaddr_32(ecoff, bsym->vaddr, &bsym->paddr);
	}
	return bsym;
}

// this is a special symbol that is used for analysis.
// the analysis step will use `loc._gp` to know how to
// resolve values, pointers and functions.
static RzBinSymbol *ecoff_gp_to_bin_symbol(const ECoff *ecoff) {
	ut64 vaddr = 0;
	const ut16 magic = ecoff_machine(ecoff);
	if (ecoff_is_alpha_magic(magic)) {
		vaddr = ecoff->ecoff64.aouthdr.alpha.gp_value;
	} else if (ecoff_is_mips_magic(magic)) {
		vaddr = ecoff->ecoff32.aouthdr.mips.gp_value;
	}

	if (!vaddr) {
		return NULL;
	}

	RzBinSymbol *bsym = RZ_NEW0(RzBinSymbol);
	if (!bsym) {
		return NULL;
	}

	bsym->name = rz_str_dup("_gp");
	bsym->forwarder = "NONE";
	bsym->bind = RZ_BIN_BIND_LOCAL_STR;
	bsym->type = RZ_BIN_TYPE_NOTYPE_STR;
	bsym->paddr = UT64_MAX;
	bsym->vaddr = vaddr;

	if (ecoff_is_ecoff64(ecoff)) {
		ecoff_find_paddr_from_vaddr_64(&ecoff->ecoff64, bsym->vaddr, &bsym->paddr);
	} else {
		ecoff_find_paddr_from_vaddr_32(&ecoff->ecoff32, bsym->vaddr, &bsym->paddr);
	}

	return bsym;
}

static const char *ecoff_local_symbol_type_to_bin_symbol_type(const ut32 st) {
	switch (st) {
	default: return RZ_BIN_TYPE_NOTYPE_STR;
	case ECOFF_LOCAL_SYM_ST_GLOBAL: return RZ_BIN_TYPE_STATIC_STR;
	case ECOFF_LOCAL_SYM_ST_STATIC: return RZ_BIN_TYPE_STATIC_STR;
	case ECOFF_LOCAL_SYM_ST_PARAM: return RZ_BIN_TYPE_FIELD_STR;
	case ECOFF_LOCAL_SYM_ST_LOCAL: return RZ_BIN_TYPE_FIELD_STR;
	case ECOFF_LOCAL_SYM_ST_PROC: return RZ_BIN_TYPE_FUNC_STR;
	case ECOFF_LOCAL_SYM_ST_BLOCK: return RZ_BIN_TYPE_OBJECT_STR;
	case ECOFF_LOCAL_SYM_ST_MEMBER: return RZ_BIN_TYPE_OBJECT_STR;
	case ECOFF_LOCAL_SYM_ST_FILE: return RZ_BIN_TYPE_FILE_STR;
	case ECOFF_LOCAL_SYM_ST_STATICPROC: return RZ_BIN_TYPE_FUNC_STR;
	case ECOFF_LOCAL_SYM_ST_CONSTANT: return RZ_BIN_TYPE_STATIC_STR;
	case ECOFF_LOCAL_SYM_ST_STAPARAM: return RZ_BIN_TYPE_FIELD_STR;
	case ECOFF_LOCAL_SYM_ST_BASE: return RZ_BIN_TYPE_OBJECT_STR;
	case ECOFF_LOCAL_SYM_ST_VIRTBASE: return RZ_BIN_TYPE_IFACE_STR;
	case ECOFF_LOCAL_SYM_ST_TAG: return RZ_BIN_TYPE_OBJECT_STR;
	case ECOFF_LOCAL_SYM_ST_NAMESPACE: return RZ_BIN_TYPE_OBJECT_STR;
	case ECOFF_LOCAL_SYM_ST_STRUCT: return RZ_BIN_TYPE_OBJECT_STR;
	case ECOFF_LOCAL_SYM_ST_UNION: return RZ_BIN_TYPE_OBJECT_STR;
	case ECOFF_LOCAL_SYM_ST_ENUM: return RZ_BIN_TYPE_OBJECT_STR;
	case ECOFF_LOCAL_SYM_ST_STR: return RZ_BIN_TYPE_STATIC_STR;
	case ECOFF_LOCAL_SYM_ST_NUMBER: return RZ_BIN_TYPE_NUM_STR;
	case ECOFF_LOCAL_SYM_ST_EXPR: return RZ_BIN_TYPE_OBJECT_STR;
	}
}

static bool ecoff_local_symbol_value_is_size(const ut32 st, const ut32 sc) {
	return (st == ECOFF_LOCAL_SYM_ST_GLOBAL && sc == ECOFF_LOCAL_SYM_SC_COMMON) ||
		(st == ECOFF_LOCAL_SYM_ST_GLOBAL && sc == ECOFF_LOCAL_SYM_SC_SCOMMON) ||
		(st == ECOFF_LOCAL_SYM_ST_GLOBAL && sc == ECOFF_LOCAL_SYM_SC_TLS_COMMON) ||
		(st == ECOFF_LOCAL_SYM_ST_BLOCK && sc == ECOFF_LOCAL_SYM_SC_INFO) ||
		(st == ECOFF_LOCAL_SYM_ST_BLOCK && sc == ECOFF_LOCAL_SYM_SC_COMMON) ||
		(st == ECOFF_LOCAL_SYM_ST_END && sc == ECOFF_LOCAL_SYM_SC_TEXT);
}

static bool ecoff_local_symbol_value_is_address(const ut32 st, const ut32 sc) {
	return (st == ECOFF_LOCAL_SYM_ST_GLOBAL && sc == ECOFF_LOCAL_SYM_SC_SDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_GLOBAL && sc == ECOFF_LOCAL_SYM_SC_DATA) ||
		(st == ECOFF_LOCAL_SYM_ST_GLOBAL && sc == ECOFF_LOCAL_SYM_SC_SBSS) ||
		(st == ECOFF_LOCAL_SYM_ST_GLOBAL && sc == ECOFF_LOCAL_SYM_SC_BSS) ||
		(st == ECOFF_LOCAL_SYM_ST_GLOBAL && sc == ECOFF_LOCAL_SYM_SC_RDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_GLOBAL && sc == ECOFF_LOCAL_SYM_SC_RCONST) ||
		(st == ECOFF_LOCAL_SYM_ST_STATIC && sc == ECOFF_LOCAL_SYM_SC_SDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_STATIC && sc == ECOFF_LOCAL_SYM_SC_DATA) ||
		(st == ECOFF_LOCAL_SYM_ST_STATIC && sc == ECOFF_LOCAL_SYM_SC_SBSS) ||
		(st == ECOFF_LOCAL_SYM_ST_STATIC && sc == ECOFF_LOCAL_SYM_SC_BSS) ||
		(st == ECOFF_LOCAL_SYM_ST_STATIC && sc == ECOFF_LOCAL_SYM_SC_RDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_STATIC && sc == ECOFF_LOCAL_SYM_SC_RCONST) ||
		(st == ECOFF_LOCAL_SYM_ST_PARAM && sc == ECOFF_LOCAL_SYM_SC_SDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_PARAM && sc == ECOFF_LOCAL_SYM_SC_DATA) ||
		(st == ECOFF_LOCAL_SYM_ST_PARAM && sc == ECOFF_LOCAL_SYM_SC_SBSS) ||
		(st == ECOFF_LOCAL_SYM_ST_PARAM && sc == ECOFF_LOCAL_SYM_SC_BSS) ||
		(st == ECOFF_LOCAL_SYM_ST_PARAM && sc == ECOFF_LOCAL_SYM_SC_RDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_PARAM && sc == ECOFF_LOCAL_SYM_SC_RCONST) ||
		(st == ECOFF_LOCAL_SYM_ST_LOCAL && sc == ECOFF_LOCAL_SYM_SC_TEXT) ||
		(st == ECOFF_LOCAL_SYM_ST_LOCAL && sc == ECOFF_LOCAL_SYM_SC_INIT) ||
		(st == ECOFF_LOCAL_SYM_ST_LOCAL && sc == ECOFF_LOCAL_SYM_SC_FINI) ||
		(st == ECOFF_LOCAL_SYM_ST_LOCAL && sc == ECOFF_LOCAL_SYM_SC_SDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_LOCAL && sc == ECOFF_LOCAL_SYM_SC_DATA) ||
		(st == ECOFF_LOCAL_SYM_ST_LOCAL && sc == ECOFF_LOCAL_SYM_SC_SBSS) ||
		(st == ECOFF_LOCAL_SYM_ST_LOCAL && sc == ECOFF_LOCAL_SYM_SC_BSS) ||
		(st == ECOFF_LOCAL_SYM_ST_LOCAL && sc == ECOFF_LOCAL_SYM_SC_RDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_LOCAL && sc == ECOFF_LOCAL_SYM_SC_RCONST) ||
		(st == ECOFF_LOCAL_SYM_ST_LOCAL && sc == ECOFF_LOCAL_SYM_SC_TLS_DATA) ||
		(st == ECOFF_LOCAL_SYM_ST_LOCAL && sc == ECOFF_LOCAL_SYM_SC_TLS_BSS) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_TEXT) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_INIT) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_FINI) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_SDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_DATA) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_XDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_PDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_SBSS) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_BSS) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_RDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_RCONST) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_TLS_DATA) ||
		(st == ECOFF_LOCAL_SYM_ST_LABEL && sc == ECOFF_LOCAL_SYM_SC_TLS_BSS) ||
		(st == ECOFF_LOCAL_SYM_ST_PROC && sc == ECOFF_LOCAL_SYM_SC_TEXT) ||
		(st == ECOFF_LOCAL_SYM_ST_STATICPROC && sc == ECOFF_LOCAL_SYM_SC_TEXT) ||
		(st == ECOFF_LOCAL_SYM_ST_STATICPROC && sc == ECOFF_LOCAL_SYM_SC_INIT) ||
		(st == ECOFF_LOCAL_SYM_ST_STATICPROC && sc == ECOFF_LOCAL_SYM_SC_FINI) ||
		(st == ECOFF_LOCAL_SYM_ST_CONSTANT && sc == ECOFF_LOCAL_SYM_SC_SDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_CONSTANT && sc == ECOFF_LOCAL_SYM_SC_DATA) ||
		(st == ECOFF_LOCAL_SYM_ST_CONSTANT && sc == ECOFF_LOCAL_SYM_SC_SBSS) ||
		(st == ECOFF_LOCAL_SYM_ST_CONSTANT && sc == ECOFF_LOCAL_SYM_SC_BSS) ||
		(st == ECOFF_LOCAL_SYM_ST_CONSTANT && sc == ECOFF_LOCAL_SYM_SC_RDATA) ||
		(st == ECOFF_LOCAL_SYM_ST_CONSTANT && sc == ECOFF_LOCAL_SYM_SC_RCONST);
}

static RzBinSymbol *ecoff_local_symbol_64_to_bin_symbol(const ECoff_64 *ecoff, const ECoff_LocalSymbol_64 *lsym, bool is_imported) {
	RzBinSymbol *bsym = RZ_NEW0(RzBinSymbol);
	if (!bsym) {
		return NULL;
	}

	bsym->type = ecoff_local_symbol_type_to_bin_symbol_type(lsym->st);
	if (ecoff_local_symbol_value_is_size(lsym->st, lsym->sc)) {
		bsym->size = lsym->value;
	}
	bsym->name = rz_str_dup(lsym->resolved_name);
	bsym->forwarder = "NONE";
	bsym->is_imported = is_imported;
	if (bsym->is_imported) {
		bsym->bind = RZ_BIN_BIND_IMPORT_STR;
	} else if (ecoff_local_symbol_is_function(lsym->st)) {
		bsym->bind = RZ_BIN_BIND_GLOBAL_STR;
	} else {
		bsym->bind = RZ_BIN_BIND_LOCAL_STR;
	}
	bsym->paddr = UT64_MAX;
	bsym->vaddr = UT64_MAX;
	if (lsym->value && ecoff_local_symbol_value_is_address(lsym->st, lsym->sc)) {
		bsym->vaddr = lsym->value;
		ecoff_find_paddr_from_vaddr_64(ecoff, bsym->vaddr, &bsym->paddr);
	}
	return bsym;
}

static RzBinSymbol *ecoff_proc_desc_entry_64_to_bin_symbol(const ECoff_64 *ecoff, const ECoff_ProcDescEntry_64 *pde) {
	RzBinSymbol *bsym = RZ_NEW0(RzBinSymbol);
	if (!bsym) {
		return NULL;
	}

	if (ecoff->symhdr.magic == ECOFF_SYMBOLIC_HEADER_MAGIC_1992) {
		bsym->vaddr = pde->_1992.adr;
	} else {
		bsym->vaddr = pde->_7009.adr;
	}

	bsym->paddr = UT64_MAX;
	ecoff_find_paddr_from_vaddr_64(ecoff, bsym->vaddr, &bsym->paddr);

	bsym->type = RZ_BIN_TYPE_FUNC_STR;
	bsym->name = rz_str_newf("fcn.%08" PFMT64x, bsym->vaddr);
	bsym->forwarder = "NONE";
	bsym->bind = RZ_BIN_BIND_GLOBAL_STR;
	return bsym;
}

static bool ecoff_get_symbols_64(const ECoff_64 *ecoff, RzPVector /*<RzBinSymbol *>*/ *syms) {
	const ECoff_ExternSymbol_64 *esym;
	const ECoff_LocalSymbol_64 *lsym;
	const ECoff_ProcDescEntry_64 *pde;
	HtUP *local_syms = ht_up_new(NULL, NULL);
	if (!local_syms) {
		return false;
	}

	rz_vector_foreach (ecoff->extern_symbols, esym) {
		RzBinSymbol *bsym = ecoff_local_symbol_64_to_bin_symbol(ecoff, &esym->asym, true);
		if (!bsym) {
			goto fail;
		}
		rz_pvector_push(syms, bsym);
	}

	size_t i = 0;
	rz_vector_enumerate (ecoff->local_symbols, lsym, i) {
		RzBinSymbol *bsym = ecoff_local_symbol_64_to_bin_symbol(ecoff, lsym, false);
		if (!bsym) {
			goto fail;
		}

		ht_up_insert(local_syms, i, bsym);
		rz_pvector_push(syms, bsym);
	}

	rz_vector_foreach (ecoff->proc_descs, pde) {
		ut64 adr = 0;
		st32 isym = 0;

		if (ecoff->symhdr.magic == ECOFF_SYMBOLIC_HEADER_MAGIC_1992) {
			adr = pde->_1992.adr;
			isym = pde->_1992.isym;
		} else {
			adr = pde->_7009.adr;
			isym = pde->_7009.isym;
		}

		if (adr == UT32_MAX) {
			continue;
		}

		bool found = false;
		RzBinSymbol *bsym = ht_up_find(local_syms, (st64)isym, &found);
		if (found) {
			// resolve the symbol address using the procedure info
			if (bsym->vaddr == UT64_MAX) {
				bsym->vaddr = adr;
				ecoff_find_paddr_from_vaddr_64(ecoff, bsym->vaddr, &bsym->paddr);
			}
			// procedures are always functions.
			bsym->type = RZ_BIN_TYPE_FUNC_STR;
			continue;
		}

		bsym = ecoff_proc_desc_entry_64_to_bin_symbol(ecoff, pde);
		if (!bsym) {
			goto fail;
		}
		rz_pvector_push(syms, bsym);
	}

	ht_up_free(local_syms);
	return true;

fail:
	ht_up_free(local_syms);
	return false;
}

static RzBinSymbol *ecoff_local_symbol_32_to_bin_symbol(const ECoff_32 *ecoff, const ECoff_LocalSymbol_32 *lsym, bool is_imported) {
	RzBinSymbol *bsym = RZ_NEW0(RzBinSymbol);
	if (!bsym) {
		return NULL;
	}

	bsym->type = ecoff_local_symbol_type_to_bin_symbol_type(lsym->st);
	if (ecoff_local_symbol_value_is_size(lsym->st, lsym->sc)) {
		bsym->size = lsym->value;
	}
	bsym->name = rz_str_dup(lsym->resolved_name);
	bsym->forwarder = "NONE";
	bsym->is_imported = is_imported;
	if (bsym->is_imported) {
		bsym->bind = RZ_BIN_BIND_IMPORT_STR;
	} else if (ecoff_local_symbol_is_function(lsym->st)) {
		bsym->bind = RZ_BIN_BIND_GLOBAL_STR;
	} else {
		bsym->bind = RZ_BIN_BIND_LOCAL_STR;
	}
	bsym->paddr = UT64_MAX;
	bsym->vaddr = UT64_MAX;
	if (lsym->value && ecoff_local_symbol_value_is_address(lsym->st, lsym->sc)) {
		bsym->vaddr = lsym->value;
		ecoff_find_paddr_from_vaddr_32(ecoff, bsym->vaddr, &bsym->paddr);
	}
	return bsym;
}

static RzBinSymbol *ecoff_proc_desc_entry_32_to_bin_symbol(const ECoff_32 *ecoff, const ECoff_ProcDescEntry_32 *pde) {
	RzBinSymbol *bsym = RZ_NEW0(RzBinSymbol);
	if (!bsym) {
		return NULL;
	}
	if (ecoff->symhdr.magic == ECOFF_SYMBOLIC_HEADER_MAGIC_1992) {
		bsym->vaddr = pde->_1992.adr;
	} else {
		bsym->vaddr = pde->_7009.adr;
	}

	bsym->paddr = UT64_MAX;
	ecoff_find_paddr_from_vaddr_32(ecoff, bsym->vaddr, &bsym->paddr);

	bsym->type = RZ_BIN_TYPE_FUNC_STR;
	bsym->name = rz_str_newf("fcn.%08" PFMT64x, bsym->vaddr);
	bsym->forwarder = "NONE";
	bsym->bind = RZ_BIN_BIND_GLOBAL_STR;
	return bsym;
}

static bool ecoff_get_symbols_32(const ECoff_32 *ecoff, RzPVector /*<RzBinSymbol *>*/ *syms) {
	const ECoff_ExternSymbol_32 *esym;
	const ECoff_LocalSymbol_32 *lsym;
	const ECoff_ProcDescEntry_32 *pde;
	HtUP *local_syms = ht_up_new(NULL, NULL);
	if (!local_syms) {
		return false;
	}

	rz_vector_foreach (ecoff->extern_symbols, esym) {
		RzBinSymbol *bsym = ecoff_local_symbol_32_to_bin_symbol(ecoff, &esym->asym, true);
		if (!bsym) {
			goto fail;
		}
		rz_pvector_push(syms, bsym);
	}

	size_t i = 0;
	rz_vector_enumerate (ecoff->local_symbols, lsym, i) {
		RzBinSymbol *bsym = ecoff_local_symbol_32_to_bin_symbol(ecoff, lsym, false);
		if (!bsym) {
			goto fail;
		}

		ht_up_insert(local_syms, i, bsym);
		rz_pvector_push(syms, bsym);
	}

	rz_vector_foreach (ecoff->proc_descs, pde) {
		ut32 adr = 0;
		st32 isym = 0;

		if (ecoff->symhdr.magic == ECOFF_SYMBOLIC_HEADER_MAGIC_1992) {
			adr = pde->_1992.adr;
			isym = pde->_1992.isym;
		} else {
			adr = pde->_7009.adr;
			isym = pde->_7009.isym;
		}

		if (adr == UT32_MAX) {
			continue;
		}

		bool found = false;
		RzBinSymbol *bsym = ht_up_find(local_syms, (st64)isym, &found);
		if (found) {
			// resolve the symbol address using the procedure info
			if (bsym->vaddr == UT64_MAX) {
				bsym->vaddr = adr;
				ecoff_find_paddr_from_vaddr_32(ecoff, bsym->vaddr, &bsym->paddr);
			}
			// procedures are always functions.
			bsym->type = RZ_BIN_TYPE_FUNC_STR;
			continue;
		}

		bsym = ecoff_proc_desc_entry_32_to_bin_symbol(ecoff, pde);
		if (!bsym) {
			goto fail;
		}
		rz_pvector_push(syms, bsym);
	}

	ht_up_free(local_syms);
	return true;

fail:
	ht_up_free(local_syms);
	return false;
}

static bool ecoff_get_symbols_old(const ECoff *ecoff, RzPVector /*<RzBinSymbol *>*/ *syms) {
	const ECoff_Symbol_Old *esym;
	rz_vector_foreach (ecoff->ecoff32.symbols_old, esym) {
		RzBinSymbol *bsym = ecoff_symbol_old_to_bin_symbol(&ecoff->ecoff32, esym);
		if (!bsym) {
			return false;
		}
		rz_pvector_push(syms, bsym);
	}

	return true;
}

RzPVector /*<RzBinSymbol *>*/ *ecoff_get_symbols(const ECoff *ecoff) {
	RzPVector *syms = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!syms) {
		return NULL;
	}

	RzBinSymbol *bsym = ecoff_gp_to_bin_symbol(ecoff);
	if (bsym) {
		// only push the _gp symbol if valid
		rz_pvector_push(syms, bsym);
	}

	if (ecoff_is_ecoff64(ecoff)) {
		if (!ecoff_has_symbolic_header_64(&ecoff->ecoff64)) {
			return syms;
		}
		ecoff_get_symbols_64(&ecoff->ecoff64, syms);
	} else if (ecoff_has_symbolic_header_32(&ecoff->ecoff32)) {
		ecoff_get_symbols_32(&ecoff->ecoff32, syms);
	} else {
		ecoff_get_symbols_old(ecoff, syms);
	}

	return syms;
}

RzPVector /*<RzBinImport *>*/ *ecoff_get_imports(const ECoff *ecoff) {
	RzPVector *imports = rz_pvector_new((RzPVectorFree)rz_bin_import_free);
	if (!imports) {
		return NULL;
	}

	// TODO

	return imports;
}

RzPVector /*<RzBinSection *>*/ *ecoff_get_sections(const ECoff *ecoff) {
	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff_get_sections_64(&ecoff->ecoff64);
	}

	return ecoff_get_sections_32(&ecoff->ecoff32);
}

static ut64 ecoff_to_debug_info(const ECoff *ecoff) {
	ut64 dbg_info = 0;
	ut16 f_flags = 0;
	st64 f_symptr = 0;

	if (ecoff_is_ecoff64(ecoff)) {
		f_flags = ecoff->ecoff64.header.f_flags;
		f_symptr = ecoff->ecoff64.header.f_symptr;
	} else {
		f_flags = ecoff->ecoff32.header.f_flags;
		f_symptr = ecoff->ecoff32.header.f_symptr;
	}

	if (f_flags & ECOFF_F_FLAGS_IS_STRIPPED || !f_symptr) {
		return RZ_BIN_DBG_STRIPPED;
	}
	if (!(f_flags & ECOFF_F_FLAGS_RELFLG)) {
		dbg_info |= RZ_BIN_DBG_RELOCS;
	}
	if (!(f_flags & ECOFF_F_FLAGS_LNNO)) {
		dbg_info |= RZ_BIN_DBG_LINENUMS;
	}
	if (!(f_flags & ECOFF_F_FLAGS_LSYMS)) {
		dbg_info |= RZ_BIN_DBG_SYMS;
	}
	return dbg_info;
}

RzBinInfo *ecoff_get_info(const ECoff *ecoff) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->rclass = rz_str_dup(ecoff_is_ecoff64(ecoff) ? "ecoff64" : "ecoff");
	ret->bclass = rz_str_dup("coff");
	ret->type = rz_str_dup("ECOFF (Executable file)");
	ret->os = rz_str_dup("any");
	ret->subsystem = rz_str_dup("any");
	ret->has_va = true;
	ret->dbg_info = ecoff_to_debug_info(ecoff);
	ret->bits = 32;

	const ut16 magic = ecoff_machine(ecoff);

	switch (magic) {
	case ECOFF_MACHINE_MIPS1:
		ret->machine = rz_str_dup("MIPS I");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips1");
		break;
	case ECOFF_MACHINE_MIPS1_EL:
		ret->machine = rz_str_dup("MIPS I LE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips1");
		break;
	case ECOFF_MACHINE_MIPS1_BE:
		ret->big_endian = true;
		ret->machine = rz_str_dup("MIPS I BE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips1");
		break;
	case ECOFF_MACHINE_MIPS2_EL:
		ret->machine = rz_str_dup("MIPS II EL");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips2");
		break;
	case ECOFF_MACHINE_MIPS2_BE:
		ret->big_endian = true;
		ret->machine = rz_str_dup("MIPS II BE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips2");
		break;
	case ECOFF_MACHINE_MIPS3_EL:
		ret->machine = rz_str_dup("MIPS III EL");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips3");
		break;
	case ECOFF_MACHINE_MIPS3_BE:
		ret->big_endian = true;
		ret->machine = rz_str_dup("MIPS III BE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips3");
		break;
	case ECOFF_MACHINE_ALPHA:
		ret->machine = rz_str_dup("Alpha");
		ret->arch = rz_str_dup("alpha");
		break;
	case ECOFF_MACHINE_ALPHA_BSD:
		ret->machine = rz_str_dup("Alpha BSD");
		ret->arch = rz_str_dup("alpha");
		ret->bits = 64;
		break;
	default:
		ret->machine = rz_str_dup("unknown");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips32");
		break;
	}
	return ret;
}

static const char *ecoff_header_magic_to_string(const ECoff *ecoff) {
	const ut16 magic = ecoff_machine(ecoff);

	switch (magic) {
	case ECOFF_MACHINE_MIPS1:
		return "MIPS1 (" RZ_STR_DEF(ECOFF_MACHINE_MIPS1) ")";
	case ECOFF_MACHINE_MIPS1_EL:
		return "MIPS1 little endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS1_EL) ")";
	case ECOFF_MACHINE_MIPS1_BE:
		return "MIPS1 big endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS1_BE) ")";
	case ECOFF_MACHINE_MIPS2_EL:
		return "MIPS2 little endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS2_EL) ")";
	case ECOFF_MACHINE_MIPS2_BE:
		return "MIPS2 big endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS2_BE) ")";
	case ECOFF_MACHINE_MIPS3_EL:
		return "MIPS3 little endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS3_EL) ")";
	case ECOFF_MACHINE_MIPS3_BE:
		return "MIPS3 big endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS3_BE) ")";
	case ECOFF_MACHINE_ALPHA:
		return "ALPHA (" RZ_STR_DEF(ECOFF_MACHINE_ALPHA) ")";
	case ECOFF_MACHINE_ALPHA_BSD:
		return "ALPHA (" RZ_STR_DEF(ECOFF_MACHINE_ALPHA_BSD) ")";
	default:
		return "unknown magic";
	}
}

static bool ecoff_header_timedate_to_string(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}

	st32 f_timedate = 0;
	if (ecoff_is_ecoff64(ecoff)) {
		f_timedate = ecoff->ecoff64.header.f_timedate;
	} else {
		f_timedate = ecoff->ecoff32.header.f_timedate;
	}

	if (f_timedate <= 0) {
		// can be zero or negative, we ignore it.
		return rz_structured_data_map_add_unsigned(parent, "f_timdat", f_timedate, true);
	}

	char *timestamp = rz_time_stamp_to_str(f_timedate);
	if (!timestamp) {
		return false;
	}
	bool res = rz_structured_data_map_add_string(parent, "f_timdat", timestamp);
	free(timestamp);
	return res;
}

static bool ecoff_header_flags_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}
	ut16 flags = 0;
	ut16 magic = 0;

	if (ecoff_is_ecoff64(ecoff)) {
		magic = ecoff->ecoff64.header.f_magic;
		flags = ecoff->ecoff64.header.f_flags;
	} else {
		magic = ecoff->ecoff32.header.f_magic;
		flags = ecoff->ecoff32.header.f_flags;
	}

	RzStructuredData *f_flags = rz_structured_data_map_add_map(parent, "f_flags");
	if (!f_flags) {
		return false;
	}

	rz_structured_data_map_add_unsigned(f_flags, "value", flags, true);

	RzStructuredData *readable = rz_structured_data_map_add_array(f_flags, "readable");
	if (!readable) {
		return false;
	}

#define HAS_FLAG(flag, name) \
	if (flags & flag && !rz_structured_data_array_add_string(readable, name)) { \
		return false; \
	}

	HAS_FLAG(ECOFF_F_FLAGS_RELFLG, "F_RELFLG");
	HAS_FLAG(ECOFF_F_FLAGS_EXEC, "F_EXEC");
	HAS_FLAG(ECOFF_F_FLAGS_LNNO, "F_LNNO");
	HAS_FLAG(ECOFF_F_FLAGS_LSYMS, "F_LSYMS");
	HAS_FLAG(ECOFF_F_FLAGS_NO_SHARED, "F_NO_SHARED");
	HAS_FLAG(ECOFF_F_FLAGS_NO_CALL_SHARED, "F_NO_CALL_SHARED");
	HAS_FLAG(ECOFF_F_FLAGS_LOMAP, "F_LOMAP");
	HAS_FLAG(ECOFF_F_FLAGS_NO_REORG, "F_NO_REORG");
	HAS_FLAG(ECOFF_F_FLAGS_NO_REMOVE, "F_NO_REMOVE");
#undef HAS_FLAG

	if (magic == ECOFF_MACHINE_ALPHA ||
		magic == ECOFF_MACHINE_ALPHA_BSD) {
		const ut16 object = flags & ECOFF_F_FLAGS_ALPHA_OBJ_MASK;
		if (object == ECOFF_F_FLAGS_ALPHA_NO_SHARED && !rz_structured_data_array_add_string(readable, "NO_SHARED")) {
			return false;
		} else if (object == ECOFF_F_FLAGS_ALPHA_SHARABLE && !rz_structured_data_array_add_string(readable, "SHARABLE")) {
			return false;
		} else if (object == ECOFF_F_FLAGS_ALPHA_CALL_SHARED && !rz_structured_data_array_add_string(readable, "CALL_SHARED")) {
			return false;
		}
	}

	return true;
}

static bool ecoff_header_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}

	ut16 f_nscns = 0;
	ut64 f_symptr = 0;
	st32 f_nsyms = 0;
	ut16 f_opthdr = 0;

	if (ecoff_is_ecoff64(ecoff)) {
		f_nscns = ecoff->ecoff64.header.f_nscns;
		f_symptr = (ut64)ecoff->ecoff64.header.f_symptr;
		f_nsyms = ecoff->ecoff64.header.f_nsyms;
		f_opthdr = ecoff->ecoff64.header.f_opthdr;
	} else {
		f_nscns = ecoff->ecoff32.header.f_nscns;
		f_symptr = (ut64)ecoff->ecoff32.header.f_symptr;
		f_nsyms = ecoff->ecoff32.header.f_nsyms;
		f_opthdr = ecoff->ecoff32.header.f_opthdr;
	}

	RzStructuredData *filehdr = rz_structured_data_map_add_map(parent, "filehdr");
	if (!filehdr) {
		return false;
	}

	const char *f_magic = ecoff_header_magic_to_string(ecoff);
	return rz_structured_data_map_add_string(filehdr, "f_magic", f_magic) &&
		rz_structured_data_map_add_unsigned(filehdr, "f_nscns", f_nscns, false) &&
		ecoff_header_timedate_to_string(ecoff, filehdr) &&
		rz_structured_data_map_add_unsigned(filehdr, "f_symptr", f_symptr, true) &&
		rz_structured_data_map_add_signed(filehdr, "f_nsyms", f_nsyms) &&
		rz_structured_data_map_add_unsigned(filehdr, "f_opthdr", f_opthdr, true) &&
		ecoff_header_flags_to_structure(ecoff, filehdr);
}

static const char *ecoff_aouthdr_magic_to_string(const ut16 magic) {
	switch (magic) {
	case ECOFF_AOUTHDR_OMAGIC:
		return "OMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_OMAGIC) ")";
	case ECOFF_AOUTHDR_NMAGIC:
		return "NMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_NMAGIC) ")";
	case ECOFF_AOUTHDR_SMAGIC:
		return "SMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_SMAGIC) ")";
	case ECOFF_AOUTHDR_ZMAGIC:
		return "ZMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_ZMAGIC) ")";
	case ECOFF_AOUTHDR_LIBMAGIC:
		return "LIBMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_LIBMAGIC) ")";
	default:
		rz_warn_if_reached();
		return "unknown";
	}
}

static bool ecoff_aouthdr_alpha_to_structure(const ECoff_64 *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}

	char vstamp[16] = { 0 };
	const ECoff_AOutHdr_Alpha *alpha = &ecoff->aouthdr.alpha;
	const char *magic = ecoff_aouthdr_magic_to_string(alpha->magic);
	rz_strf(vstamp, "v%u.%u", alpha->vstamp[1], alpha->vstamp[0]);

	return rz_structured_data_map_add_string(parent, "magic", magic) &&
		rz_structured_data_map_add_string(parent, "vstamp", vstamp) &&
		rz_structured_data_map_add_unsigned(parent, "bldrev", alpha->bldrev, true) &&
		rz_structured_data_map_add_unsigned(parent, "padding", alpha->padding, true) &&
		rz_structured_data_map_add_unsigned(parent, "tsize", alpha->tsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "dsize", alpha->dsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "bsize", alpha->bsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "entry", alpha->entry, true) &&
		rz_structured_data_map_add_unsigned(parent, "text_start", alpha->text_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "data_start", alpha->data_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "bss_start", alpha->bss_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "gpr_mask", alpha->gpr_mask, true) &&
		rz_structured_data_map_add_unsigned(parent, "fpr_mask", alpha->fpr_mask, true) &&
		rz_structured_data_map_add_unsigned(parent, "gp_value", alpha->gp_value, true);
}

static bool ecoff_aouthdr_mips_to_structure(const ECoff_32 *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}

	char vstamp[16] = { 0 };
	const ECoff_AOutHdr_Mips *mips = &ecoff->aouthdr.mips;
	const char *magic = ecoff_aouthdr_magic_to_string(mips->magic);
	rz_strf(vstamp, "v%u.%u", mips->vstamp[1], mips->vstamp[0]);

	bool res = rz_structured_data_map_add_string(parent, "magic", magic) &&
		rz_structured_data_map_add_string(parent, "vstamp", vstamp) &&
		rz_structured_data_map_add_unsigned(parent, "tsize", mips->tsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "dsize", mips->dsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "bsize", mips->bsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "entry", mips->entry, true) &&
		rz_structured_data_map_add_unsigned(parent, "text_start", mips->text_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "data_start", mips->data_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "bss_start", mips->bss_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "gpr_mask", mips->gpr_mask, true);
	if (!res) {
		return false;
	}

	RzStructuredData *cpr_mask = rz_structured_data_map_add_array(parent, "cpr_mask");
	if (!cpr_mask) {
		return false;
	}

	return rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[0], true) &&
		rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[1], true) &&
		rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[2], true) &&
		rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[3], true) &&
		rz_structured_data_map_add_unsigned(parent, "gp_value", mips->gp_value, true);
}

static bool ecoff_aouthdr_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	const ut16 magic = ecoff_machine(ecoff);
	RzStructuredData *aouthdr = rz_structured_data_map_add_map(parent, "aouthdr");
	if (!aouthdr) {
		return false;
	}

	if (ecoff_is_alpha_magic(magic)) {
		return ecoff_aouthdr_alpha_to_structure(&ecoff->ecoff64, aouthdr);
	} else if (ecoff_is_mips_magic(magic)) {
		return ecoff_aouthdr_mips_to_structure(&ecoff->ecoff32, aouthdr);
	} else {
		rz_warn_if_reached();
	}
	return true;
}

static bool ecoff_section_flags_to_structure(const ut32 flags, RzStructuredData *parent) {
	const ut32 extflag = flags & ECOFF_SECTION_EXT_TYPE_MASK;
	if (!parent) {
		return false;
	}
	RzStructuredData *s_flags = rz_structured_data_map_add_map(parent, "s_flags");
	if (!s_flags) {
		return false;
	}
	rz_structured_data_map_add_unsigned(s_flags, "value", flags, true);

	RzStructuredData *readable = rz_structured_data_map_add_array(s_flags, "readable");
	if (!readable) {
		return false;
	}

	if (flags == ECOFF_SECTION_TYPE_REG) {
		// when zero is always this type.
		return rz_structured_data_array_add_string(readable, "STYP_REG");
	}

#define HAS_FLAG(flag, name) \
	if (flags & flag && !rz_structured_data_array_add_string(readable, name)) { \
		return false; \
	}
	HAS_FLAG(ECOFF_SECTION_TYPE_TEXT, "STYP_TEXT");
	HAS_FLAG(ECOFF_SECTION_TYPE_DATA, "STYP_DATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_BSS, "STYP_BSS");

	HAS_FLAG(ECOFF_SECTION_TYPE_RDATA, "STYP_RDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SDATA, "STYP_SDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SBSS, "STYP_SBSS");
	HAS_FLAG(ECOFF_SECTION_TYPE_UCODE, "STYP_UCODE");
	HAS_FLAG(ECOFF_SECTION_TYPE_GOT1, "STYP_GOT1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNAMIC1, "STYP_DYNAMIC1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSYM1, "STYP_DYNSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_REL_DYN1, "STYP_REL_DYN1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSTR1, "STYP_DYNSTR1");
	HAS_FLAG(ECOFF_SECTION_TYPE_HASH1, "STYP_HASH1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DSOLIST1, "STYP_DSOLIST1");
	HAS_FLAG(ECOFF_SECTION_TYPE_MSYM1, "STYP_MSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIT4, "STYP_LIT4");
	HAS_FLAG(ECOFF_SECTION_TYPE_NRELOC_OVFL2, "STYP_NRELOC_OVFL2");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIB, "STYP_LIB");
	HAS_FLAG(ECOFF_SECTION_TYPE_INIT, "STYP_INIT");
#undef HAS_FLAG

#define HAS_EXT_FLAG(flag, name) \
	if (extflag == flag && !rz_structured_data_array_add_string(readable, name)) { \
		return false; \
	}
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_CONFLICT1, "STYP_CONFLICT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RESOURCE, "STYP_RESOURCE");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_FINI, "STYP_FINI");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT1, "STYP_COMMENT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT2, "STYP_COMMENT2");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RCONST, "STYP_RCONST");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_XDATA, "STYP_XDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSDATA, "STYP_TLSDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSBSS, "STYP_TLSBSS");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSINIT, "STYP_TLSINIT");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_PDATA, "STYP_PDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LITA, "STYP_LITA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LIT8, "STYP_LIT8");
#undef HAS_EXT_FLAG

	return true;
}

static const char *ecoff_symbol_sclass(const ECoff_Symbol_Old *symbol) {
	switch (symbol->e_sclass) {
	case ECOFF_SYMBOL_OLD_SC_EFCN:
		return "C_EFCN";
	case ECOFF_SYMBOL_OLD_SC_NULL:
		return "C_NULL";
	case ECOFF_SYMBOL_OLD_SC_AUTO:
		return "C_AUTO";
	case ECOFF_SYMBOL_OLD_SC_EXT:
		return "C_EXT";
	case ECOFF_SYMBOL_OLD_SC_STAT:
		return "C_STAT";
	case ECOFF_SYMBOL_OLD_SC_REG:
		return "C_REG";
	case ECOFF_SYMBOL_OLD_SC_EXTDEF:
		return "C_EXTDEF";
	case ECOFF_SYMBOL_OLD_SC_LABEL:
		return "C_LABEL";
	case ECOFF_SYMBOL_OLD_SC_ULABEL:
		return "C_ULABEL";
	case ECOFF_SYMBOL_OLD_SC_MOS:
		return "C_MOS";
	case ECOFF_SYMBOL_OLD_SC_ARG:
		return "C_ARG";
	case ECOFF_SYMBOL_OLD_SC_STRTAG:
		return "C_STRTAG";
	case ECOFF_SYMBOL_OLD_SC_MOU:
		return "C_MOU";
	case ECOFF_SYMBOL_OLD_SC_UNTAG:
		return "C_UNTAG";
	case ECOFF_SYMBOL_OLD_SC_TPDEF:
		return "C_TPDEF";
	case ECOFF_SYMBOL_OLD_SC_USTATIC:
		return "C_USTATIC";
	case ECOFF_SYMBOL_OLD_SC_ENTAG:
		return "C_ENTAG";
	case ECOFF_SYMBOL_OLD_SC_MOE:
		return "C_MOE";
	case ECOFF_SYMBOL_OLD_SC_REGPARM:
		return "C_REGPARM";
	case ECOFF_SYMBOL_OLD_SC_FIELD:
		return "C_FIELD";
	case ECOFF_SYMBOL_OLD_SC_BLOCK:
		return "C_BLOCK";
	case ECOFF_SYMBOL_OLD_SC_FCN:
		return "C_FCN";
	case ECOFF_SYMBOL_OLD_SC_EOS:
		return "C_EOS";
	case ECOFF_SYMBOL_OLD_SC_FILE:
		return "C_FILE";
	case ECOFF_SYMBOL_OLD_SC_LINE:
		return "C_LINE";
	case ECOFF_SYMBOL_OLD_SC_ALIAS:
		return "C_ALIAS";
	case ECOFF_SYMBOL_OLD_SC_HIDDEN:
		return "C_HIDDEN";
	default:
		rz_warn_if_reached();
		return "unknown";
	}
}

static bool ecoff_symbol_old_to_structure(const ECoff_32 *ecoff, const ECoff_Symbol_Old *symbol, RzStructuredData *parent) {
	const char *e_scnum = "unknown";
	const char *e_sclass = ecoff_symbol_sclass(symbol);

	if (symbol->e_scnum == ECOFF_SYMBOL_SECT_NUM_DEBUG) {
		// Special symbolic debugging symbol
		e_scnum = "N_DEBUG";
	} else if (symbol->e_scnum == ECOFF_SYMBOL_SECT_NUM_ABS) {
		// Absolute symbol
		e_scnum = "N_ABS";
	} else if (symbol->e_scnum == ECOFF_SYMBOL_SECT_NUM_UNDEF) {
		// Undefined external symbol
		e_scnum = "N_UNDEF";
	} else if (symbol->e_scnum > 0 && symbol->e_scnum < rz_vector_len(ecoff->sections)) {
		const ECoff_Section_32 *esec = rz_vector_index_ptr(ecoff->sections, symbol->e_scnum);
		if (esec) {
			e_scnum = esec->resolved_name;
		}
	}

	return rz_structured_data_map_add_string(parent, "e_name", symbol->resolved_name) &&
		rz_structured_data_map_add_unsigned(parent, "e_value", symbol->e_value, true) &&
		rz_structured_data_map_add_string(parent, "e_scnum", e_scnum) &&
		rz_structured_data_map_add_unsigned(parent, "e_type", symbol->e_type, true) &&
		rz_structured_data_map_add_string(parent, "e_sclass", e_sclass) &&
		rz_structured_data_map_add_unsigned(parent, "e_numaux", symbol->e_numaux, true);
}

static bool ecoff_symbols_to_structure_old(const ECoff_32 *ecoff, RzStructuredData *parent) {
	RzStructuredData *symbols = rz_structured_data_map_add_array(parent, "symbols");
	if (!symbols) {
		return false;
	}

	const ECoff_Symbol_Old *symbol;
	rz_vector_foreach (ecoff->symbols_old, symbol) {
		RzStructuredData *section = rz_structured_data_array_add_map(symbols);
		if (!section) {
			return false;
		} else if (!ecoff_symbol_old_to_structure(ecoff, symbol, section)) {
			return false;
		}
	}

	return true;
}

static const char *ecoff_file_descr_entry_get_lang(const ut16 lang) {
	switch (lang) {
	case ECOFF_FDE_LANG_C:
		return "C";
	case ECOFF_FDE_LANG_PASCAL:
		return "Pascal";
	case ECOFF_FDE_LANG_FORTRAN:
		return "Fortran";
	case ECOFF_FDE_LANG_ASSEMBLER:
		return "Assembly";
	case ECOFF_FDE_LANG_MACHINE:
		return "Machine";
	case ECOFF_FDE_LANG_NIL:
		return "Nil";
	case ECOFF_FDE_LANG_ADA:
		return "Ada";
	case ECOFF_FDE_LANG_PL1:
		return "Pl1";
	case ECOFF_FDE_LANG_COBOL:
		return "Cobol";
	case ECOFF_FDE_LANG_STDC:
		return "stdC";
	case ECOFF_FDE_LANG_MIPS_CXX:
		return "Mips C++";
	case ECOFF_FDE_LANG_DEC_CXX:
		return "Dec C++";
	case ECOFF_FDE_LANG_CXX:
		return "C++";
	case ECOFF_FDE_LANG_FORTRAN90:
		return "Fortran 90";
	case ECOFF_FDE_LANG_BLISS:
		return "Bliss";
	case ECOFF_FDE_LANG_PTAL:
		return "PTAL";
	case ECOFF_FDE_LANG_CXX_V1:
		return "C++v1";
	case ECOFF_FDE_LANG_CXX_V2:
		return "C++v2";
	default:
		return "unknown";
	}
}

static const char *ecoff_file_descr_entry_get_glevel(const ut16 glevel) {
	switch (glevel) {
	case ECOFF_FDE_GLEVEL_0:
		return "-g0";
	case ECOFF_FDE_GLEVEL_1:
		return "-g1";
	case ECOFF_FDE_GLEVEL_2:
		return "-g2";
	case ECOFF_FDE_GLEVEL_3:
		return "-g3";
	default:
		return "unknown";
	}
}

static const char *ecoff_local_symbol_get_type(const ut32 st) {
	switch (st) {
	default: return "Unknown";
	case ECOFF_LOCAL_SYM_ST_NIL: return "Nil";
	case ECOFF_LOCAL_SYM_ST_GLOBAL: return "Global Var";
	case ECOFF_LOCAL_SYM_ST_STATIC: return "Static Var";
	case ECOFF_LOCAL_SYM_ST_PARAM: return "Procedure Arg";
	case ECOFF_LOCAL_SYM_ST_LOCAL: return "Local Var";
	case ECOFF_LOCAL_SYM_ST_LABEL: return "Label";
	case ECOFF_LOCAL_SYM_ST_PROC: return "Global Procedure";
	case ECOFF_LOCAL_SYM_ST_BLOCK: return "Block";
	case ECOFF_LOCAL_SYM_ST_END: return "End";
	case ECOFF_LOCAL_SYM_ST_MEMBER: return "Member";
	case ECOFF_LOCAL_SYM_ST_TYPEDEF: return "Typedef";
	case ECOFF_LOCAL_SYM_ST_FILE: return "Source File";
	case ECOFF_LOCAL_SYM_ST_REGRELOC: return "Register Relocation";
	case ECOFF_LOCAL_SYM_ST_FORWARD: return "Forwarding Address";
	case ECOFF_LOCAL_SYM_ST_STATICPROC: return "Static Procedure";
	case ECOFF_LOCAL_SYM_ST_CONSTANT: return "Constant";
	case ECOFF_LOCAL_SYM_ST_STAPARAM: return "Static Param";
	case ECOFF_LOCAL_SYM_ST_BASE: return "Base";
	case ECOFF_LOCAL_SYM_ST_VIRTBASE: return "VirtBase";
	case ECOFF_LOCAL_SYM_ST_TAG: return "Tag";
	case ECOFF_LOCAL_SYM_ST_INTER: return "Interlude";
	// case ECOFF_LOCAL_SYM_ST_MODULE: return "Module"; // Conflicts with namespace
	case ECOFF_LOCAL_SYM_ST_NAMESPACE: return "Namespace";
	// case ECOFF_LOCAL_SYM_ST_MODVIEW: return "Modview"; // Conflicts with using
	case ECOFF_LOCAL_SYM_ST_USING: return "Using";
	case ECOFF_LOCAL_SYM_ST_ALIAS: return "Alias";
	case ECOFF_LOCAL_SYM_ST_STRUCT: return "Struct";
	case ECOFF_LOCAL_SYM_ST_UNION: return "Union";
	case ECOFF_LOCAL_SYM_ST_ENUM: return "Enum";
	case ECOFF_LOCAL_SYM_ST_INDIRECT: return "Indirect";
	case ECOFF_LOCAL_SYM_ST_STR: return "String";
	case ECOFF_LOCAL_SYM_ST_NUMBER: return "Number";
	case ECOFF_LOCAL_SYM_ST_EXPR: return "Expr";
	case ECOFF_LOCAL_SYM_ST_TYPE: return "Type";
	}
}

static const char *ecoff_local_symbol_get_storage_class(const ut32 sc) {
	switch (sc) {
	default: return "Unknown";
	case ECOFF_LOCAL_SYM_SC_NIL: return "nil";
	case ECOFF_LOCAL_SYM_SC_TEXT: return ".text";
	case ECOFF_LOCAL_SYM_SC_DATA: return ".data";
	case ECOFF_LOCAL_SYM_SC_BSS: return ".bss";
	case ECOFF_LOCAL_SYM_SC_REGISTER: return "register";
	case ECOFF_LOCAL_SYM_SC_ABS: return "abs";
	case ECOFF_LOCAL_SYM_SC_UNDEFINED: return "undefined";
	case ECOFF_LOCAL_SYM_SC_UNALLOCATED: return "unallocated";
	case ECOFF_LOCAL_SYM_SC_TLSUNDEFINED: return "tls undefined";
	case ECOFF_LOCAL_SYM_SC_INFO: return "debugger info";
	case ECOFF_LOCAL_SYM_SC_SDATA: return ".sdata";
	case ECOFF_LOCAL_SYM_SC_SBSS: return ".sbss";
	case ECOFF_LOCAL_SYM_SC_RDATA: return ".rdata";
	case ECOFF_LOCAL_SYM_SC_VAR: return "var";
	case ECOFF_LOCAL_SYM_SC_COMMON: return "common";
	case ECOFF_LOCAL_SYM_SC_SCOMMON: return "small common";
	case ECOFF_LOCAL_SYM_SC_VARREGISTER: return "var register";
	case ECOFF_LOCAL_SYM_SC_VARIANT: return "variant";
	// case ECOFF_LOCAL_SYM_SC_FILEDESC: return "file descriptor"; // Conflicts with variant
	case ECOFF_LOCAL_SYM_SC_SUNDEFINED: return "small undefined";
	case ECOFF_LOCAL_SYM_SC_INIT: return ".init";
	case ECOFF_LOCAL_SYM_SC_REPORTDESC: return "report descriptor";
	case ECOFF_LOCAL_SYM_SC_XDATA: return ".xdata";
	case ECOFF_LOCAL_SYM_SC_PDATA: return ".pdata";
	case ECOFF_LOCAL_SYM_SC_FINI: return ".fini";
	case ECOFF_LOCAL_SYM_SC_RCONST: return ".rconst";
	case ECOFF_LOCAL_SYM_SC_TLS_COMMON: return "tls common";
	case ECOFF_LOCAL_SYM_SC_TLS_DATA: return "tls .data";
	case ECOFF_LOCAL_SYM_SC_TLS_BSS: return "tls .bss";
	}
}

static bool ecoff_sections_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}

	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff_sections_to_structure_64(&ecoff->ecoff64, parent);
	}
	return ecoff_sections_to_structure_32(&ecoff->ecoff32, parent);
}

static bool ecoff_symbols_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}

	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff_symbols_to_structure_64(&ecoff->ecoff64, parent);
	} else if (ecoff_has_symbolic_header_32(&ecoff->ecoff32)) {
		return ecoff_symbols_to_structure_32(&ecoff->ecoff32, parent);
	}
	return ecoff_symbols_to_structure_old(&ecoff->ecoff32, parent);
}

bool ecoff_new_structure(const ECoff *ecoff, RzStructuredData *parent) {
	return ecoff_header_to_structure(ecoff, parent) &&
		ecoff_aouthdr_to_structure(ecoff, parent) &&
		ecoff_sections_to_structure(ecoff, parent) &&
		ecoff_symbols_to_structure(ecoff, parent);
}

RzList /*<char *>*/ *ecoff_resolve_section_flags(ut64 s_flags) {
	const ut32 extflag = s_flags & ECOFF_SECTION_EXT_TYPE_MASK;
	RzList *flags = rz_list_new();
	if (!flags) {
		return false;
	}

	if (s_flags == ECOFF_SECTION_TYPE_REG) {
		// when zero is always this type.
		rz_list_append(flags, "STYP_REG");
		return flags;
	}

#define HAS_FLAG(flag, name) \
	if (s_flags & flag) { \
		rz_list_append(flags, name); \
	}
	HAS_FLAG(ECOFF_SECTION_TYPE_TEXT, "STYP_TEXT");
	HAS_FLAG(ECOFF_SECTION_TYPE_DATA, "STYP_DATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_BSS, "STYP_BSS");

	HAS_FLAG(ECOFF_SECTION_TYPE_RDATA, "STYP_RDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SDATA, "STYP_SDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SBSS, "STYP_SBSS");
	HAS_FLAG(ECOFF_SECTION_TYPE_UCODE, "STYP_UCODE");
	HAS_FLAG(ECOFF_SECTION_TYPE_GOT1, "STYP_GOT1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNAMIC1, "STYP_DYNAMIC1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSYM1, "STYP_DYNSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_REL_DYN1, "STYP_REL_DYN1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSTR1, "STYP_DYNSTR1");
	HAS_FLAG(ECOFF_SECTION_TYPE_HASH1, "STYP_HASH1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DSOLIST1, "STYP_DSOLIST1");
	HAS_FLAG(ECOFF_SECTION_TYPE_MSYM1, "STYP_MSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIT4, "STYP_LIT4");
	HAS_FLAG(ECOFF_SECTION_TYPE_NRELOC_OVFL2, "STYP_NRELOC_OVFL2");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIB, "STYP_LIB");
	HAS_FLAG(ECOFF_SECTION_TYPE_INIT, "STYP_INIT");
#undef HAS_FLAG

#define HAS_EXT_FLAG(flag, name) \
	if (extflag == flag) { \
		rz_list_append(flags, name); \
	}
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_CONFLICT1, "STYP_CONFLICT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RESOURCE, "STYP_RESOURCE");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_FINI, "STYP_FINI");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT1, "STYP_COMMENT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT2, "STYP_COMMENT2");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RCONST, "STYP_RCONST");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_XDATA, "STYP_XDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSDATA, "STYP_TLSDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSBSS, "STYP_TLSBSS");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSINIT, "STYP_TLSINIT");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_PDATA, "STYP_PDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LITA, "STYP_LITA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LIT8, "STYP_LIT8");
#undef HAS_EXT_FLAG

	return flags;
}
