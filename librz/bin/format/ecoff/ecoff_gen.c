// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#define ECOFF_GEN_HAS_SYMBOLIC_HEADER(bits) \
	static inline bool ecoff_has_symbolic_header_##bits(const ECoff_##bits *ecoff) { \
		const ut16 magic = ecoff->symhdr.magic; \
		return magic == ECOFF_SYMBOLIC_HEADER_MAGIC_7009 || \
			magic == ECOFF_SYMBOLIC_HEADER_MAGIC_1992; \
	}

#define ECOFF_GEN_INIT_HDR(bits) \
	static bool ecoff_init_hdr_##bits(RzBuffer *b, ut64 *offset, ECoff_Header_##bits *header, const bool big_endian) { \
		return rz_buf_read_ble16_offset(b, offset, &header->f_magic, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, &header->f_nscns, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&header->f_timedate, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, (ut##bits *)&header->f_symptr, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&header->f_nsyms, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, &header->f_opthdr, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, &header->f_flags, big_endian); \
	}

#define ECOFF_GEN_RESOLVE_NAME(bits) \
	static char *ecoff_resolve_name_##bits(RzBuffer *b, const ECoff_##bits *ecoff, const char name[8]) { \
		ut32 zero = rz_read_at_ble32((const ut8 *)name, 0, ecoff->big_endian); \
		if (zero) { \
			return rz_str_ndup((const char *)name, 8); \
		} \
\
		ut64 offset = rz_read_at_ble32((const ut8 *)name, 4, ecoff->big_endian); \
		offset += ecoff->header.f_symptr; \
		if (ecoff_has_symbolic_header_##bits(ecoff)) { \
			return NULL; \
		} else { \
			offset += ecoff->header.f_nsyms * COFF_SYMBOL_OLD_SIZE; \
		} \
\
		ut8 resolved[256] = { 0 }; \
		st64 len = rz_buf_read_at(b, offset, resolved, sizeof(resolved) - 1); \
		if (len < 1) { \
			return NULL; \
		} \
		resolved[sizeof(resolved) - 1] = 0; \
		return rz_str_dup((const char *)resolved); \
	}

#define ECOFF_GEN_INIT_SECTION(bits) \
	static bool ecoff_init_section_##bits(RzBuffer *b, ut64 *offset, ECoff_Section_##bits *section, const bool big_endian) { \
		return rz_buf_read_offset(b, offset, (ut8 *)section->s_name, sizeof(section->s_name)) && \
			rz_buf_read_ble##bits##_offset(b, offset, &section->s_paddr, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &section->s_vaddr, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &section->s_size, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &section->s_scnptr, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &section->s_relptr, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &section->s_lnnoptr, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, &section->s_nreloc, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, &section->s_nlnno, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, &section->s_flags, big_endian); \
	}

#define ECOFF_GEN_FINI_SECTION(bits) \
	static void ecoff_section_fini_##bits(void *element, void *x) { \
		ECoff_Section_##bits *section = element; \
		free(section->resolved_name); \
	}

#define ECOFF_GEN_PARSE_SECTIONS(bits) \
	static bool ecoff_parse_sections_##bits(RzBuffer *b, ut64 *offset, ECoff_##bits *ecoff) { \
		const size_t count = ecoff->header.f_nscns; \
		for (size_t i = 0; i < count; ++i) { \
			ut64 location = *offset; \
			ECoff_Section_##bits section = { 0 }; \
			if (!ecoff_init_section_##bits(b, offset, &section, ecoff->big_endian)) { \
				return false; \
			} \
			section.resolved_name = ecoff_resolve_name_##bits(b, ecoff, section.s_name); \
			if (!section.resolved_name) { \
				section.resolved_name = rz_str_newf("unknown_%" PFMT64x, location); \
			} \
			rz_vector_push(ecoff->sections, &section); \
		} \
		return true; \
	}

#define ECOFF_GEN_INIT_SYMBOLIC_HEADER_1992(bits) \
	static bool ecoff_init_symbolic_header_1992_##bits(RzBuffer *b, ut64 *offset, ECoff_SymHdr1992_##bits *symhdr, const bool big_endian) { \
		return rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iline_max, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->idn_max, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->ipd_max, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->isym_max, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iopt_max, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iaux_max, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iss_max, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iss_ext_max, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->ifd_max, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->crfd, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iext_max, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, (ut##bits *)&symhdr->cb_line, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_line_offset, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_dn_offset, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_pd_offset, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_sym_offset, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_opt_offset, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_aux_offset, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_ss_offset, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_ss_ext_offset, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_fd_offset, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_rfd_offset, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_ext_offset, big_endian); \
	}

#define ECOFF_GEN_INIT_SYMBOLIC_HEADER_7009(bits) \
	static bool ecoff_init_symbolic_header_7009_##bits(RzBuffer *b, ut64 *offset, ECoff_SymHdr7009_##bits *symhdr, const bool big_endian) { \
		return rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iline_max, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, (ut##bits *)&symhdr->cb_line, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_line_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->idn_max, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_dn_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->ipd_max, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_pd_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->isym_max, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_sym_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iopt_max, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_opt_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iaux_max, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_aux_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iss_max, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_ss_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iss_ext_max, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_ss_ext_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->ifd_max, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_fd_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->crfd, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_rfd_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iext_max, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, &symhdr->cb_ext_offset, big_endian); \
	}

#define ECOFF_GEN_INIT_SYMBOLIC_HEADER(bits) \
	ECOFF_GEN_INIT_SYMBOLIC_HEADER_1992(bits); \
	ECOFF_GEN_INIT_SYMBOLIC_HEADER_7009(bits); \
	static bool ecoff_init_symbolic_header_##bits(RzBuffer *b, ut64 *offset, ECoff_SymHdr_##bits *symhdr, const bool big_endian) { \
		bool ok = rz_buf_read_ble16_offset(b, offset, (ut16 *)&symhdr->magic, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, &symhdr->vstamp, big_endian); \
		if (!ok) { \
			return false; \
		} \
		switch (symhdr->magic) { \
		case ECOFF_SYMBOLIC_HEADER_MAGIC_1992: \
			return ecoff_init_symbolic_header_1992_##bits(b, offset, &symhdr->_1992, big_endian); \
		case ECOFF_SYMBOLIC_HEADER_MAGIC_7009: \
			return ecoff_init_symbolic_header_7009_##bits(b, offset, &symhdr->_7009, big_endian); \
		default: \
			return false; \
		} \
	}

#define ECOFF_GEN_INIT_LOCAL_SYMBOL(bits) \
	static bool ecoff_init_local_symbol_##bits(RzBuffer *b, ut64 *offset, ECoff_LocalSymbol_##bits *lsym, const bool big_endian) { \
		ut32 bit_fields = 0; \
		bool ok = rz_buf_read_ble##bits##_offset(b, offset, (ut##bits *)&lsym->value, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&lsym->iss, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, &bit_fields, big_endian); \
		if (ok) { \
			lsym->st = bit_fields & 0x3f; \
			lsym->sc = (bit_fields >> 6) & 0x3f; \
			lsym->reserved = (bit_fields >> 11) & 1; \
			lsym->index = (bit_fields >> 12) & 0xfffff; \
		} \
		return ok; \
	}

#define ECOFF_GEN_FINI_LOCAL_SYMBOL(bits) \
	static void ecoff_fini_local_symbol_##bits(void *element, void *x) { \
		ECoff_LocalSymbol_##bits *lsym = element; \
		free(lsym->resolved_name); \
	}

#define ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, field, ctype) \
	static inline ctype ecoff_symhdr_##field##_##bits(const ECoff_SymHdr_##bits *symhdr) { \
		switch (symhdr->magic) { \
		case ECOFF_SYMBOLIC_HEADER_MAGIC_1992: \
			return symhdr->_1992.field; \
		case ECOFF_SYMBOLIC_HEADER_MAGIC_7009: \
			return symhdr->_7009.field; \
		default: \
			return 0; \
		} \
	}

#define ECOFF_GEN_FDE_GET(bits, field, ctype) \
	static inline ctype ecoff_fde_##field##_##bits(const ECoff_##bits *ecoff, const ECoff_FileDescEntry_##bits *fde) { \
		switch (ecoff->symhdr.magic) { \
		case ECOFF_SYMBOLIC_HEADER_MAGIC_1992: \
			return fde->_1992.field; \
		case ECOFF_SYMBOLIC_HEADER_MAGIC_7009: \
			return fde->_7009.field; \
		default: \
			return 0; \
		} \
	}

#define ECOFF_GEN_RESOLVE_SYMBOL_NAME(bits) \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, cb_ss_ext_offset, ut##bits) \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, iss_ext_max, st32) \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, cb_ss_offset, ut##bits) \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, iss_max, st32) \
	ECOFF_GEN_FDE_GET(bits, iss_base, st32) \
	static bool ecoff_resolve_symbol_name_##bits(RzBuffer *b, const ECoff_##bits *ecoff, const ECoff_FileDescEntry_##bits *fde, const bool is_external, ECoff_LocalSymbol_##bits *lsym) { \
		if (!ecoff_has_symbolic_header_##bits(ecoff) || lsym->iss < 1) { \
			return false; \
		} \
		ut64 offset_beg = 0; \
		ut64 offset_end = 0; \
		if (is_external) { \
			offset_beg = ecoff_symhdr_cb_ss_ext_offset_##bits(&ecoff->symhdr); \
			offset_end = offset_beg + ecoff_symhdr_iss_ext_max_##bits(&ecoff->symhdr); \
		} else { \
			offset_beg = ecoff_symhdr_cb_ss_offset_##bits(&ecoff->symhdr); \
			offset_end = offset_beg + ecoff_symhdr_iss_max_##bits(&ecoff->symhdr); \
		} \
		offset_beg += ecoff_fde_iss_base_##bits(ecoff, fde) + lsym->iss; \
		ut8 resolved[512] = { 0 }; \
		size_t leftovers = offset_end - offset_beg; \
		size_t max_size = RZ_MIN(leftovers, sizeof(resolved)); \
		st64 len = rz_buf_read_at(b, offset_beg, resolved, max_size); \
		resolved[sizeof(resolved) - 1] = 0; \
		if (len < 1) { \
			return false; \
		} \
		resolved[sizeof(resolved) - 1] = 0; \
		if (!*resolved) { \
			return false; \
		} \
		lsym->resolved_name = rz_str_dup((const char *)resolved); \
		return true; \
	}

#define ECOFF_GEN_PARSE_LOCAL_SYMBOLS(bits) \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, cb_sym_offset, ut##bits) \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, isym_max, st32) \
	static bool ecoff_parse_local_symbols_##bits(RzBuffer *b, ECoff_##bits *ecoff) { \
		const st32 count = ecoff_symhdr_isym_max_##bits(&ecoff->symhdr); \
		if (count < 1) { \
			return true; \
		} \
		ut64 offset = ecoff_symhdr_cb_sym_offset_##bits(&ecoff->symhdr); \
		for (st32 i = 0; i < count; ++i) { \
			ECoff_LocalSymbol_##bits lsym = { 0 }; \
			if (!ecoff_init_local_symbol_##bits(b, &offset, &lsym, ecoff->big_endian)) { \
				return false; \
			} \
			rz_vector_push(ecoff->local_symbols, &lsym); \
		} \
		return true; \
	}

#define ECOFF_GEN_INIT_EXTERNAL_SYMBOL(bits) \
	static bool ecoff_init_external_symbol_##bits(RzBuffer *b, ut64 *offset, ECoff_ExternSymbol_##bits *esym, const bool big_endian) { \
		ut32 bit_fields = 0; \
		bool ok = ecoff_init_local_symbol_##bits(b, offset, &esym->asym, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, &bit_fields, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&esym->ifd, big_endian); \
		if (ok) { \
			esym->jmptbl = bit_fields & 1; \
			esym->cobol_main = (bit_fields >> 1) & 1; \
			esym->weakext = (bit_fields >> 2) & 1; \
			esym->alignment = 1 << ((bit_fields >> 3) & 0xf); \
			esym->xport = (bit_fields >> 7) & 1; \
			esym->multiext = (bit_fields >> 8) & 1; \
			esym->reserved = (bit_fields >> 9) & 0x7fffff; \
		} \
		return ok; \
	}

#define ECOFF_GEN_FINI_EXTERNAL_SYMBOL(bits) \
	static void ecoff_fini_external_symbol_##bits(void *element, void *x) { \
		ECoff_ExternSymbol_##bits *esym = element; \
		free(esym->asym.resolved_name); \
	}

#define ECOFF_GEN_PARSE_EXTERNAL_SYMBOLS(bits) \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, cb_ext_offset, ut##bits) \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, iext_max, st32) \
	static bool ecoff_parse_external_symbols_##bits(RzBuffer *b, ECoff_##bits *ecoff) { \
		const st32 count = ecoff_symhdr_iext_max_##bits(&ecoff->symhdr); \
		if (count < 1) { \
			return true; \
		} \
		ut64 offset = ecoff_symhdr_cb_ext_offset_##bits(&ecoff->symhdr); \
		for (st32 i = 0; i < count; ++i) { \
			ECoff_ExternSymbol_##bits esym = { 0 }; \
			if (!ecoff_init_external_symbol_##bits(b, &offset, &esym, ecoff->big_endian)) { \
				return false; \
			} \
			rz_vector_push(ecoff->extern_symbols, &esym); \
		} \
		return true; \
	}

#define ECOFF_GEN_INIT_FILE_DESCRIPTOR_ENTRY_7009(bits) \
	static bool ecoff_init_file_descriptor_entry_7009_##bits(RzBuffer *b, ut64 *offset, ECoff_FileDescEntry7009_##bits *fde, const bool big_endian) { \
		ut32 bit_fields = 0; \
		bool ok = rz_buf_read_ble##bits##_offset(b, offset, &fde->adr, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->rss, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iss_base, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, (ut##bits *)&fde->cb_ss, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->isym_base, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->csym, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iopt_base, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->copt, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->ipd_first, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->cpd, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iaux_base, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->caux, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iind_base, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->cind, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, &bit_fields, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, (ut##bits *)&fde->cb_line_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->cline, big_endian); \
		if (ok) { \
			fde->lang = bit_fields & 0x1f; \
			fde->f_merge = (bit_fields >> 5) & 1; \
			fde->f_readin = (bit_fields >> 6) & 1; \
			fde->f_bigendian = (bit_fields >> 7) & 1; \
			fde->glevel = (bit_fields >> 8) & 3; \
			fde->reserved = (bit_fields >> 10) & 0x3fffff; \
		} \
		return ok; \
	}

#define ECOFF_GEN_INIT_FILE_DESCRIPTOR_ENTRY_1992(bits) \
	static bool ecoff_init_file_descriptor_entry_1992_##bits(RzBuffer *b, ut64 *offset, ECoff_FileDescEntry1992_##bits *fde, const bool big_endian) { \
		ut16 bit_fields = 0; \
		bool ok = rz_buf_read_ble##bits##_offset(b, offset, &fde->adr, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, (ut##bits *)&fde->cb_line_offset, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, (ut##bits *)&fde->cb_line, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, (ut##bits *)&fde->cb_ss, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->rss, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iss_base, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->isym_base, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->csym, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iline_base, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->cline, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iopt_base, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->copt, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->ipd_first, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->cpd, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iaux_base, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->caux, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->rfd_base, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->crfd, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, &bit_fields, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, &fde->vstamp, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, &fde->reserved2, big_endian); \
		if (ok) { \
			fde->lang = bit_fields & 0x1f; \
			fde->f_merge = (bit_fields >> 5) & 1; \
			fde->f_readin = (bit_fields >> 6) & 1; \
			fde->f_bigendian = (bit_fields >> 7) & 1; \
			fde->glevel = (bit_fields >> 8) & 3; \
			fde->f_trim = (bit_fields >> 10) & 1; \
			fde->reserved = (bit_fields >> 11) & 0x1f; \
		} \
		return ok; \
	}

#define ECOFF_GEN_PARSE_FILE_DESCRIPTOR_ENTRIES(bits) \
	ECOFF_GEN_INIT_FILE_DESCRIPTOR_ENTRY_1992(bits) \
	ECOFF_GEN_INIT_FILE_DESCRIPTOR_ENTRY_7009(bits) \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, cb_fd_offset, ut##bits) \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, ifd_max, st32) \
	static bool ecoff_init_file_descriptor_entry_##bits(RzBuffer *b, ut64 *offset, const ECoff_##bits *ecoff, ECoff_FileDescEntry_##bits *fde) { \
		switch (ecoff->symhdr.magic) { \
		case ECOFF_SYMBOLIC_HEADER_MAGIC_1992: \
			return ecoff_init_file_descriptor_entry_1992_##bits(b, offset, &fde->_1992, ecoff->big_endian); \
		case ECOFF_SYMBOLIC_HEADER_MAGIC_7009: \
			return ecoff_init_file_descriptor_entry_7009_##bits(b, offset, &fde->_7009, ecoff->big_endian); \
		default: \
			return false; \
		} \
	} \
	static bool ecoff_parse_file_descriptor_entries_##bits(RzBuffer *b, ECoff_##bits *ecoff) { \
		st32 count = ecoff_symhdr_ifd_max_##bits(&ecoff->symhdr); \
		if (count < 1) { \
			return true; \
		} \
		ut64 offset = ecoff_symhdr_cb_fd_offset_##bits(&ecoff->symhdr); \
		for (st32 i = 0; i < count; ++i) { \
			ECoff_FileDescEntry_##bits fde = { 0 }; \
			if (!ecoff_init_file_descriptor_entry_##bits(b, &offset, ecoff, &fde)) { \
				return false; \
			} \
			rz_vector_push(ecoff->file_descs, &fde); \
		} \
		return true; \
	}

#define ECOFF_GEN_INIT_PROC_DESCRIPTOR_ENTRY_7009(bits) \
	static bool ecoff_init_proc_descriptor_entry_7009_##bits(RzBuffer *b, ut64 *offset, ECoff_ProcDescEntry7009_##bits *pde, const bool big_endian) { \
		return rz_buf_read_ble##bits##_offset(b, offset, &pde->adr, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->isym, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, (ut##bits *)&pde->cb_line_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, &pde->regmask, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->regoffset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->iopt, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, &pde->fregmask, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->fregoffset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->frameoffset, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, (ut16 *)&pde->framereg, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, (ut16 *)&pde->pcreg, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->sline, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->eline, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->oline, big_endian); \
	}

#define ECOFF_GEN_INIT_PROC_DESCRIPTOR_ENTRY_1992(bits) \
	static bool ecoff_init_proc_descriptor_entry_1992_##bits(RzBuffer *b, ut64 *offset, ECoff_ProcDescEntry1992_##bits *pde, const bool big_endian) { \
		ut32 bit_fields = 0; \
		bool ok = rz_buf_read_ble##bits##_offset(b, offset, &pde->adr, big_endian) && \
			rz_buf_read_ble##bits##_offset(b, offset, (ut##bits *)&pde->cb_line_offset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->isym, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->iline, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, &pde->regmask, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->regoffset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->iopt, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, &pde->fregmask, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->fregoffset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->frameoffset, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->ln_low, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, (ut32 *)&pde->ln_high, big_endian) && \
			rz_buf_read_ble32_offset(b, offset, &bit_fields, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, (ut16 *)&pde->framereg, big_endian) && \
			rz_buf_read_ble16_offset(b, offset, (ut16 *)&pde->pcreg, big_endian); \
		if (ok) { \
			pde->gp_prologue = bit_fields & 0xff; \
			pde->gp_used = (bit_fields >> 8) & 1; \
			pde->reg_frame = (bit_fields >> 9) & 1; \
			pde->prof = (bit_fields >> 10) & 1; \
			pde->reserved = (bit_fields >> 11) & 0x1fff; \
			pde->localoff = (bit_fields >> 24) & 0xff; \
		} \
		return ok; \
	}

#define ECOFF_GEN_PARSE_PROC_DESCRIPTOR_ENTRIES(bits) \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, cb_pd_offset, ut##bits); \
	ECOFF_GEN_SYMBOLIC_HEADER_GET(bits, ipd_max, st32); \
	ECOFF_GEN_INIT_PROC_DESCRIPTOR_ENTRY_7009(bits); \
	ECOFF_GEN_INIT_PROC_DESCRIPTOR_ENTRY_1992(bits); \
	static bool ecoff_init_proc_descriptor_entry_##bits(RzBuffer *b, ut64 *offset, const ECoff_##bits *ecoff, ECoff_ProcDescEntry_##bits *pde, const bool big_endian) { \
		switch (ecoff->symhdr.magic) { \
		case ECOFF_SYMBOLIC_HEADER_MAGIC_1992: \
			return ecoff_init_proc_descriptor_entry_1992_##bits(b, offset, &pde->_1992, big_endian); \
		case ECOFF_SYMBOLIC_HEADER_MAGIC_7009: \
			return ecoff_init_proc_descriptor_entry_7009_##bits(b, offset, &pde->_7009, big_endian); \
		default: \
			return false; \
		} \
	} \
	static bool ecoff_parse_proc_descriptor_entries_##bits(RzBuffer *b, ECoff_##bits *ecoff) { \
		const st32 count = ecoff_symhdr_ipd_max_##bits(&ecoff->symhdr); \
		if (count < 1) { \
			return true; \
		} \
		ut64 offset = ecoff_symhdr_cb_pd_offset_##bits(&ecoff->symhdr); \
		for (st32 i = 0; i < count; ++i) { \
			ECoff_ProcDescEntry_##bits pde = { 0 }; \
			if (!ecoff_init_proc_descriptor_entry_##bits(b, &offset, ecoff, &pde, ecoff->big_endian)) { \
				return false; \
			} \
			rz_vector_push(ecoff->proc_descs, &pde); \
		} \
		return true; \
	}

#define ECOFF_GEN_RESOLVE_SYMBOLS(bits) \
	ECOFF_GEN_FDE_GET(bits, csym, st32) \
	ECOFF_GEN_FDE_GET(bits, isym_base, st32) \
	static bool ecoff_resolve_symbols_##bits(RzBuffer *b, ECoff_##bits *ecoff) { \
		const ECoff_FileDescEntry_##bits *fde; \
		rz_vector_foreach (ecoff->file_descs, fde) { \
			st32 csym = ecoff_fde_csym_##bits(ecoff, fde); \
			st32 isym_base = ecoff_fde_isym_base_##bits(ecoff, fde); \
			st32 iss_base = ecoff_fde_iss_base_##bits(ecoff, fde); \
			if (csym < 1 || isym_base < 0 || iss_base < 0) { \
				continue; \
			} \
			for (st32 i = 0; i < csym; ++i) { \
				size_t lsym_idx = isym_base + i; \
				if (lsym_idx >= rz_vector_len(ecoff->local_symbols)) { \
					continue; \
				} \
				ECoff_LocalSymbol_##bits *lsym = rz_vector_index_ptr(ecoff->local_symbols, lsym_idx); \
				if (!ecoff_resolve_symbol_name_##bits(b, ecoff, fde, false, lsym)) { \
					lsym->resolved_name = rz_str_newf("no_name_%" PFMTSZu, lsym_idx); \
				} \
			} \
		} \
		return true; \
	}

#define ECOFF_GEN_FIND_PADDR_FROM_VADDR(bits) \
	static bool ecoff_find_paddr_from_vaddr_##bits(const ECoff_##bits *ecoff, const ut64 vaddr, ut64 *paddr) { \
		const ECoff_Section_##bits *esec; \
		rz_vector_foreach (ecoff->sections, esec) { \
			ut64 pstart = esec->s_scnptr; \
			ut64 vend = esec->s_vaddr + esec->s_size; \
			ut64 vstart = esec->s_vaddr; \
			if (vaddr >= vstart && vaddr <= vend) { \
				*paddr = pstart + (vaddr - vstart); \
				return true; \
			} \
		} \
		return false; \
	}

#define ECOFF_GEN_SECTION_TO_BIN_SECTION(bits) \
	static RzBinSection *ecoff_section_##bits##_to_bin_section(const ECoff_Section_##bits *esec) { \
		RzBinSection *bsec = RZ_NEW0(RzBinSection); \
		if (!bsec) { \
			return NULL; \
		} \
		bsec->size = esec->s_size; \
		bsec->vsize = esec->s_size; \
		bsec->paddr = esec->s_scnptr; \
		bsec->vaddr = esec->s_vaddr; \
		bsec->flags = esec->s_flags; \
		bsec->perm = ecoff_section_flags_to_perms(bsec->flags); \
		bsec->name = rz_str_dup(esec->resolved_name); \
		if (ecoff_is_data_section(bsec->flags)) { \
			bsec->is_data = true; \
		} \
		return bsec; \
	}

#define ECOFF_GEN_GET_SECTIONS(bits) \
	static void *ecoff_get_sections_##bits(const ECoff_##bits *ecoff) { \
		RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free); \
		if (!ret) { \
			return NULL; \
		} \
		const ECoff_Section_##bits *esec; \
		rz_vector_foreach (ecoff->sections, esec) { \
			RzBinSection *bsec = NULL; \
			bsec = ecoff_section_##bits##_to_bin_section(esec); \
			if (!bsec) { \
				return ret; \
			} \
			rz_pvector_push(ret, bsec); \
		} \
		return ret; \
	}

#define ECOFF_GEN_SECTION_TO_STRUCTURE(bits) \
	static bool ecoff_section_to_structure_##bits(const ECoff_Section_##bits *section, RzStructuredData *parent) { \
		return rz_structured_data_map_add_string(parent, "s_name", rz_str_get(section->resolved_name)) && \
			rz_structured_data_map_add_unsigned(parent, "s_paddr", section->s_paddr, true) && \
			rz_structured_data_map_add_unsigned(parent, "s_vaddr", section->s_vaddr, true) && \
			rz_structured_data_map_add_unsigned(parent, "s_size", section->s_size, true) && \
			rz_structured_data_map_add_unsigned(parent, "s_scnptr", section->s_scnptr, true) && \
			rz_structured_data_map_add_unsigned(parent, "s_relptr", section->s_relptr, true) && \
			rz_structured_data_map_add_unsigned(parent, "s_lnnoptr", section->s_lnnoptr, true) && \
			rz_structured_data_map_add_unsigned(parent, "s_nreloc", section->s_nreloc, true) && \
			rz_structured_data_map_add_unsigned(parent, "s_nlnno", section->s_nlnno, true) && \
			ecoff_section_flags_to_structure(section->s_flags, parent); \
	}

#define ECOFF_GEN_SECTIONS_TO_STRUCTURE(bits) \
	static bool ecoff_sections_to_structure_##bits(const ECoff_##bits *ecoff, RzStructuredData *parent) { \
		if (!parent) { \
			return false; \
		} \
		RzStructuredData *sections_arr = rz_structured_data_map_add_array(parent, "sections"); \
		if (!sections_arr) { \
			return false; \
		} \
		const ECoff_Section_##bits *esec; \
		rz_vector_foreach (ecoff->sections, esec) { \
			RzStructuredData *section = rz_structured_data_array_add_map(sections_arr); \
			if (!section || !ecoff_section_to_structure_##bits(esec, section)) { \
				return false; \
			} \
		} \
		return true; \
	}

#define ECOFF_GEN_FILE_DESCR_ENTRY_7009_TO_STRUCTURE(bits) \
	static bool ecoff_file_descr_entry_7009_to_structure_##bits(const ECoff_FileDescEntry7009_##bits *fde, RzStructuredData *parent, void *v_pdes) { \
		RzVector *pdes = v_pdes; \
		RzStructuredData *fde_info = rz_structured_data_array_add_map(parent); \
		RzStructuredData *pde_info = rz_structured_data_new_map(); \
		if (!fde_info || !pde_info) { \
			rz_structured_data_free(pde_info); \
			return false; \
		} \
		const ECoff_ProcDescEntry_##bits *pde = NULL; \
		if (fde->ipd_first >= 0 && fde->ipd_first < rz_vector_len(pdes)) { \
			pde = rz_vector_index_ptr(pdes, fde->ipd_first); \
			ecoff_proc_descr_entry_7009_to_structure_##bits(&pde->_7009, pde_info); \
		} \
		const char *glevel = ecoff_file_descr_entry_get_glevel(fde->glevel); \
		const char *lang = ecoff_file_descr_entry_get_lang(fde->lang); \
		return rz_structured_data_map_add_unsigned(fde_info, "adr", fde->adr, true) && \
			rz_structured_data_map_add_signed(fde_info, "rss", fde->rss) && \
			rz_structured_data_map_add_signed(fde_info, "iss_base", fde->iss_base) && \
			rz_structured_data_map_add_signed(fde_info, "cb_ss", fde->cb_ss) && \
			rz_structured_data_map_add_signed(fde_info, "isym_base", fde->isym_base) && \
			rz_structured_data_map_add_signed(fde_info, "csym", fde->csym) && \
			rz_structured_data_map_add_signed(fde_info, "iopt_base", fde->iopt_base) && \
			rz_structured_data_map_add_signed(fde_info, "copt", fde->copt) && \
			rz_structured_data_map_add_signed(fde_info, "ipd_first", fde->ipd_first) && \
			rz_structured_data_map_add(fde_info, "pde", pde_info) && \
			rz_structured_data_map_add_signed(fde_info, "cpd", fde->cpd) && \
			rz_structured_data_map_add_signed(fde_info, "iaux_base", fde->iaux_base) && \
			rz_structured_data_map_add_signed(fde_info, "caux", fde->caux) && \
			rz_structured_data_map_add_signed(fde_info, "iind_base", fde->iind_base) && \
			rz_structured_data_map_add_signed(fde_info, "cind", fde->cind) && \
			rz_structured_data_map_add_string(fde_info, "lang", lang) && \
			rz_structured_data_map_add_boolean(fde_info, "f_merge", fde->f_merge) && \
			rz_structured_data_map_add_boolean(fde_info, "f_readin", fde->f_readin) && \
			rz_structured_data_map_add_boolean(fde_info, "f_bigendian", fde->f_bigendian) && \
			rz_structured_data_map_add_string(fde_info, "glevel", glevel) && \
			rz_structured_data_map_add_unsigned(fde_info, "reserved", fde->reserved, true) && \
			rz_structured_data_map_add_signed(fde_info, "cb_line_offset", fde->cb_line_offset) && \
			rz_structured_data_map_add_signed(fde_info, "cline", fde->cline); \
	}

#define ECOFF_GEN_FILE_DESCR_ENTRY_1992_TO_STRUCTURE(bits) \
	static bool ecoff_file_descr_entry_1992_to_structure_##bits(const ECoff_FileDescEntry1992_##bits *fde, RzStructuredData *parent, void *v_pdes) { \
		RzVector *pdes = v_pdes; \
		RzStructuredData *fde_info = rz_structured_data_array_add_map(parent); \
		RzStructuredData *pde_info = rz_structured_data_new_map(); \
		if (!fde_info || !pde_info) { \
			rz_structured_data_free(pde_info); \
			return false; \
		} \
		const ECoff_ProcDescEntry_##bits *pde = NULL; \
		if (fde->ipd_first >= 0 && fde->ipd_first < rz_vector_len(pdes)) { \
			pde = rz_vector_index_ptr(pdes, fde->ipd_first); \
			ecoff_proc_descr_entry_1992_to_structure_##bits(&pde->_1992, pde_info); \
		} \
		const char *glevel = ecoff_file_descr_entry_get_glevel(fde->glevel); \
		const char *lang = ecoff_file_descr_entry_get_lang(fde->lang); \
		char vstamp[16] = { 0 }; \
		rz_strf(vstamp, "v%u.%u", fde->vstamp >> 8, fde->vstamp & 0xFF); \
		return rz_structured_data_map_add_unsigned(fde_info, "adr", fde->adr, true) && \
			rz_structured_data_map_add_signed(fde_info, "cb_line_offset", (st64)fde->cb_line_offset) && \
			rz_structured_data_map_add_signed(fde_info, "cb_line", (st64)fde->cb_line) && \
			rz_structured_data_map_add_signed(fde_info, "cb_ss", (st64)fde->cb_ss) && \
			rz_structured_data_map_add_signed(fde_info, "rss", (st64)fde->rss) && \
			rz_structured_data_map_add_signed(fde_info, "iss_base", (st64)fde->iss_base) && \
			rz_structured_data_map_add_signed(fde_info, "isym_base", (st64)fde->isym_base) && \
			rz_structured_data_map_add_signed(fde_info, "csym", (st64)fde->csym) && \
			rz_structured_data_map_add_signed(fde_info, "iline_base", (st64)fde->iline_base) && \
			rz_structured_data_map_add_signed(fde_info, "cline", (st64)fde->cline) && \
			rz_structured_data_map_add_signed(fde_info, "iopt_base", (st64)fde->iopt_base) && \
			rz_structured_data_map_add_signed(fde_info, "copt", (st64)fde->copt) && \
			rz_structured_data_map_add_signed(fde_info, "ipd_first", (st64)fde->ipd_first) && \
			rz_structured_data_map_add(fde_info, "pde", pde_info) && \
			rz_structured_data_map_add_signed(fde_info, "cpd", (st64)fde->cpd) && \
			rz_structured_data_map_add_signed(fde_info, "iaux_base", (st64)fde->iaux_base) && \
			rz_structured_data_map_add_signed(fde_info, "caux", (st64)fde->caux) && \
			rz_structured_data_map_add_signed(fde_info, "rfd_base", (st64)fde->rfd_base) && \
			rz_structured_data_map_add_signed(fde_info, "crfd", (st64)fde->crfd) && \
			rz_structured_data_map_add_string(fde_info, "lang", lang) && \
			rz_structured_data_map_add_boolean(fde_info, "f_merge", fde->f_merge) && \
			rz_structured_data_map_add_boolean(fde_info, "f_readin", fde->f_readin) && \
			rz_structured_data_map_add_boolean(fde_info, "f_bigendian", fde->f_bigendian) && \
			rz_structured_data_map_add_string(fde_info, "glevel", glevel) && \
			rz_structured_data_map_add_boolean(fde_info, "f_trim", fde->f_trim) && \
			rz_structured_data_map_add_unsigned(fde_info, "reserved", fde->reserved, true) && \
			rz_structured_data_map_add_string(fde_info, "vstamp", vstamp) && \
			rz_structured_data_map_add_unsigned(fde_info, "reserved2", fde->reserved2, true); \
	}

#define ECOFF_GEN_FILE_DESCR_ENTRIES_TO_STRUCTURE(bits) \
	ECOFF_GEN_FILE_DESCR_ENTRY_1992_TO_STRUCTURE(bits) \
	ECOFF_GEN_FILE_DESCR_ENTRY_7009_TO_STRUCTURE(bits) \
	static bool ecoff_file_descr_entry_to_structure_##bits(const ECoff_##bits *ecoff, const ECoff_FileDescEntry_##bits *fde, RzStructuredData *parent, void *pdes) { \
		if (ecoff->symhdr.magic == ECOFF_SYMBOLIC_HEADER_MAGIC_7009) { \
			return ecoff_file_descr_entry_7009_to_structure_##bits(&fde->_7009, parent, pdes); \
		} \
		return ecoff_file_descr_entry_1992_to_structure_##bits(&fde->_1992, parent, pdes); \
	} \
	static bool ecoff_file_descr_entries_to_structure_##bits(const ECoff_##bits *ecoff, RzStructuredData *parent) { \
		RzStructuredData *fdes = rz_structured_data_map_add_array(parent, "fdes"); \
		if (!fdes) { \
			return false; \
		} \
		const ECoff_FileDescEntry_##bits *fde; \
		rz_vector_foreach (ecoff->file_descs, fde) { \
			if (!ecoff_file_descr_entry_to_structure_##bits(ecoff, fde, fdes, ecoff->proc_descs)) { \
				return false; \
			} \
		} \
		return true; \
	}

#define ECOFF_GEN_PROC_DESCR_ENTRY_7009_TO_STRUCTURE(bits) \
	static bool ecoff_proc_descr_entry_7009_to_structure_##bits(const ECoff_ProcDescEntry7009_##bits *pde, RzStructuredData *pde_info) { \
		return rz_structured_data_map_add_unsigned(pde_info, "adr", pde->adr, true) && \
			rz_structured_data_map_add_signed(pde_info, "isym", pde->isym) && \
			rz_structured_data_map_add_signed(pde_info, "cb_line_offset", pde->cb_line_offset) && \
			rz_structured_data_map_add_unsigned(pde_info, "regmask", pde->regmask, true) && \
			rz_structured_data_map_add_signed(pde_info, "regoffset", pde->regoffset) && \
			rz_structured_data_map_add_signed(pde_info, "iopt", pde->iopt) && \
			rz_structured_data_map_add_unsigned(pde_info, "fregmask", pde->fregmask, true) && \
			rz_structured_data_map_add_signed(pde_info, "fregoffset", pde->fregoffset) && \
			rz_structured_data_map_add_signed(pde_info, "frameoffset", pde->frameoffset) && \
			rz_structured_data_map_add_signed(pde_info, "framereg", pde->framereg) && \
			rz_structured_data_map_add_signed(pde_info, "pcreg", pde->pcreg) && \
			rz_structured_data_map_add_signed(pde_info, "sline", pde->sline) && \
			rz_structured_data_map_add_signed(pde_info, "eline", pde->eline) && \
			rz_structured_data_map_add_signed(pde_info, "oline", pde->oline); \
	}

#define ECOFF_GEN_PROC_DESCR_ENTRY_1992_TO_STRUCTURE(bits) \
	static bool ecoff_proc_descr_entry_1992_to_structure_##bits(const ECoff_ProcDescEntry1992_##bits *pde, RzStructuredData *pde_info) { \
		return rz_structured_data_map_add_unsigned(pde_info, "adr", pde->adr, true) && \
			rz_structured_data_map_add_signed(pde_info, "cb_line_offset", (st64)pde->cb_line_offset) && \
			rz_structured_data_map_add_signed(pde_info, "isym", (st64)pde->isym) && \
			rz_structured_data_map_add_signed(pde_info, "iline", (st64)pde->iline) && \
			rz_structured_data_map_add_unsigned(pde_info, "regmask", pde->regmask, true) && \
			rz_structured_data_map_add_signed(pde_info, "regoffset", (st64)pde->regoffset) && \
			rz_structured_data_map_add_signed(pde_info, "iopt", (st64)pde->iopt) && \
			rz_structured_data_map_add_unsigned(pde_info, "fregmask", pde->fregmask, true) && \
			rz_structured_data_map_add_signed(pde_info, "fregoffset", (st64)pde->fregoffset) && \
			rz_structured_data_map_add_signed(pde_info, "frameoffset", (st64)pde->frameoffset) && \
			rz_structured_data_map_add_signed(pde_info, "ln_low", (st64)pde->ln_low) && \
			rz_structured_data_map_add_signed(pde_info, "ln_high", (st64)pde->ln_high) && \
			rz_structured_data_map_add_unsigned(pde_info, "gp_prologue", pde->gp_prologue, true) && \
			rz_structured_data_map_add_boolean(pde_info, "gp_used", pde->gp_used) && \
			rz_structured_data_map_add_boolean(pde_info, "reg_frame", pde->reg_frame) && \
			rz_structured_data_map_add_boolean(pde_info, "prof", pde->prof) && \
			rz_structured_data_map_add_unsigned(pde_info, "reserved", pde->reserved, true) && \
			rz_structured_data_map_add_unsigned(pde_info, "localoff", pde->localoff, true) && \
			rz_structured_data_map_add_signed(pde_info, "framereg", (st64)pde->framereg) && \
			rz_structured_data_map_add_signed(pde_info, "pcreg", (st64)pde->pcreg); \
	}

#define ECOFF_GEN_PROC_DESCR_ENTRIES_TO_STRUCTURE(bits) \
	ECOFF_GEN_PROC_DESCR_ENTRY_1992_TO_STRUCTURE(bits) \
	ECOFF_GEN_PROC_DESCR_ENTRY_7009_TO_STRUCTURE(bits) \
	static bool ecoff_proc_descr_entry_to_structure_##bits(const ECoff_##bits *ecoff, const ECoff_ProcDescEntry_##bits *pde, RzStructuredData *parent) { \
		RzStructuredData *pde_info = rz_structured_data_array_add_map(parent); \
		if (!pde_info) { \
			return false; \
		} \
		if (ecoff->symhdr.magic == ECOFF_SYMBOLIC_HEADER_MAGIC_7009) { \
			return ecoff_proc_descr_entry_7009_to_structure_##bits(&pde->_7009, pde_info); \
		} \
		return ecoff_proc_descr_entry_1992_to_structure_##bits(&pde->_1992, pde_info); \
	} \
	static bool ecoff_proc_descr_entries_to_structure_##bits(const ECoff_##bits *ecoff, RzStructuredData *parent) { \
		RzStructuredData *pdes = rz_structured_data_map_add_array(parent, "pdes"); \
		if (!pdes) { \
			return false; \
		} \
		const ECoff_ProcDescEntry_##bits *pde; \
		rz_vector_foreach (ecoff->proc_descs, pde) { \
			if (!ecoff_proc_descr_entry_to_structure_##bits(ecoff, pde, pdes)) { \
				return false; \
			} \
		} \
		return true; \
	}

#define ECOFF_GEN_SYMBOLIC_HDR_1992_TO_STRUCTURE(bits) \
	static bool ecoff_symbolic_hdr_1992_to_structure_##bits(const ECoff_SymHdr1992_##bits *symhdr, RzStructuredData *symbolic_hdr) { \
		return rz_structured_data_map_add_signed(symbolic_hdr, "iline_max", (st64)symhdr->iline_max) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "idn_max", (st64)symhdr->idn_max) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "ipd_max", (st64)symhdr->ipd_max) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "isym_max", (st64)symhdr->isym_max) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "iopt_max", (st64)symhdr->iopt_max) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "iaux_max", (st64)symhdr->iaux_max) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "iss_max", (st64)symhdr->iss_max, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "iss_ext_max", (st64)symhdr->iss_ext_max, true) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "ifd_max", (st64)symhdr->ifd_max) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "crfd", (st64)symhdr->crfd) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "iext_max", (st64)symhdr->iext_max) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "cb_line", (st64)symhdr->cb_line) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_line_offset", symhdr->cb_line_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_dn_offset", symhdr->cb_dn_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_pd_offset", symhdr->cb_pd_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_sym_offset", symhdr->cb_sym_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_opt_offset", symhdr->cb_opt_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_aux_offset", symhdr->cb_aux_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_ss_offset", symhdr->cb_ss_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_ss_ext_offset", symhdr->cb_ss_ext_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_fd_offset", symhdr->cb_fd_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_rfd_offset", symhdr->cb_rfd_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_ext_offset", symhdr->cb_ext_offset, true); \
	}

#define ECOFF_GEN_SYMBOLIC_HDR_7009_TO_STRUCTURE(bits) \
	static bool ecoff_symbolic_hdr_7009_to_structure_##bits(const ECoff_SymHdr7009_##bits *symhdr, RzStructuredData *symbolic_hdr) { \
		return rz_structured_data_map_add_signed(symbolic_hdr, "iline_max", symhdr->iline_max) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "cb_line", symhdr->cb_line) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_line_offset", symhdr->cb_line_offset, true) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "idn_max", symhdr->idn_max) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_dn_offset", symhdr->cb_dn_offset, true) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "ipd_max", symhdr->ipd_max) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_pd_offset", symhdr->cb_pd_offset, true) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "isym_max", symhdr->isym_max) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_sym_offset", symhdr->cb_sym_offset, true) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "iopt_max", symhdr->iopt_max) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_opt_offset", symhdr->cb_opt_offset, true) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "iaux_max", symhdr->iaux_max) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_aux_offset", symhdr->cb_aux_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "iss_max", symhdr->iss_max, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_ss_offset", symhdr->cb_ss_offset, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "iss_ext_max", symhdr->iss_ext_max, true) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_ss_ext_offset", symhdr->cb_ss_ext_offset, true) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "ifd_max", symhdr->ifd_max) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_fd_offset", symhdr->cb_fd_offset, true) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "crfd", symhdr->crfd) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_rfd_offset", symhdr->cb_rfd_offset, true) && \
			rz_structured_data_map_add_signed(symbolic_hdr, "iext_max", symhdr->iext_max) && \
			rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_ext_offset", symhdr->cb_ext_offset, true); \
	}

#define ECOFF_GEN_SYMBOLIC_HDR_TO_STRUCTURE(bits) \
	ECOFF_GEN_SYMBOLIC_HDR_1992_TO_STRUCTURE(bits); \
	ECOFF_GEN_SYMBOLIC_HDR_7009_TO_STRUCTURE(bits); \
	static bool ecoff_symbolic_hdr_to_structure_##bits(const ECoff_##bits *ecoff, RzStructuredData *parent) { \
		const ECoff_SymHdr_##bits *symhdr = &ecoff->symhdr; \
		RzStructuredData *symbolic_hdr = rz_structured_data_map_add_map(parent, "symbolic_hdr"); \
		if (!symbolic_hdr) { \
			return false; \
		} \
		char vstamp[16] = { 0 }; \
		rz_strf(vstamp, "v%u.%u", symhdr->vstamp >> 8, symhdr->vstamp & 0xFF); \
		bool ok = rz_structured_data_map_add_unsigned(symbolic_hdr, "magic", symhdr->magic, true) && \
			rz_structured_data_map_add_string(symbolic_hdr, "vstamp", vstamp); \
		if (!ok) { \
			return false; \
		} else if (symhdr->magic == ECOFF_SYMBOLIC_HEADER_MAGIC_1992) { \
			return ecoff_symbolic_hdr_1992_to_structure_##bits(&symhdr->_1992, symbolic_hdr); \
		} \
		return ecoff_symbolic_hdr_7009_to_structure_##bits(&symhdr->_7009, symbolic_hdr); \
	}

#define ECOFF_GEN_LOCAL_SYMBOL_TO_STRUCTURE(bits) \
	static bool ecoff_local_symbol_to_structure_##bits(const ECoff_LocalSymbol_##bits *lsym, RzStructuredData *sym) { \
		const char *st = ecoff_local_symbol_get_type(lsym->st); \
		const char *sc = ecoff_local_symbol_get_storage_class(lsym->sc); \
		return rz_structured_data_map_add_string(sym, "name", rz_str_get(lsym->resolved_name)) && \
			rz_structured_data_map_add_unsigned(sym, "value", lsym->value, true) && \
			rz_structured_data_map_add_signed(sym, "iss", (st64)lsym->iss) && \
			rz_structured_data_map_add_string(sym, "st", st) && \
			rz_structured_data_map_add_string(sym, "sc", sc) && \
			rz_structured_data_map_add_unsigned(sym, "reserved", lsym->reserved, true) && \
			rz_structured_data_map_add_unsigned(sym, "index", lsym->index, false); \
	}

#define ECOFF_GEN_LOCAL_SYMBOLS_TO_STRUCTURE(bits) \
	static bool ecoff_local_symbols_to_structure_##bits(const ECoff_##bits *ecoff, RzStructuredData *parent) { \
		RzStructuredData *local_syms = rz_structured_data_map_add_array(parent, "local_syms"); \
		if (!local_syms) { \
			return false; \
		} \
		const ECoff_LocalSymbol_##bits *lsym; \
		rz_vector_foreach (ecoff->local_symbols, lsym) { \
			RzStructuredData *sym = rz_structured_data_array_add_map(local_syms); \
			if (!sym || !ecoff_local_symbol_to_structure_##bits(lsym, sym)) { \
				return false; \
			} \
		} \
		return true; \
	}

#define ECOFF_GEN_EXTERNAL_SYMBOL_TO_STRUCTURE(bits) \
	static bool ecoff_external_symbol_to_structure_##bits(const ECoff_ExternSymbol_##bits *esym, RzStructuredData *parent) { \
		RzStructuredData *sym = rz_structured_data_array_add_map(parent); \
		if (!sym) { \
			return false; \
		} \
		RzStructuredData *asym = rz_structured_data_map_add_map(sym, "asym"); \
		if (!asym) { \
			return false; \
		} \
		return ecoff_local_symbol_to_structure_##bits(&esym->asym, asym) && \
			rz_structured_data_map_add_boolean(sym, "jmptbl", esym->jmptbl) && \
			rz_structured_data_map_add_boolean(sym, "cobol_main", esym->cobol_main) && \
			rz_structured_data_map_add_boolean(sym, "weakext", esym->weakext) && \
			rz_structured_data_map_add_unsigned(sym, "alignment", esym->alignment, false) && \
			rz_structured_data_map_add_boolean(sym, "xport", esym->xport) && \
			rz_structured_data_map_add_boolean(sym, "multiext", esym->multiext) && \
			rz_structured_data_map_add_unsigned(sym, "reserved", esym->reserved, true) && \
			rz_structured_data_map_add_signed(sym, "ifd", (st64)esym->ifd); \
	}

#define ECOFF_GEN_EXTERNAL_SYMBOLS_TO_STRUCTURE(bits) \
	static bool ecoff_external_symbols_to_structure_##bits(const ECoff_##bits *ecoff, RzStructuredData *parent) { \
		RzStructuredData *external_syms = rz_structured_data_map_add_array(parent, "external_syms"); \
		if (!external_syms) { \
			return false; \
		} \
		const ECoff_ExternSymbol_##bits *esym; \
		rz_vector_foreach (ecoff->extern_symbols, esym) { \
			if (!ecoff_external_symbol_to_structure_##bits(esym, external_syms)) { \
				return false; \
			} \
		} \
		return true; \
	}

#define ECOFF_GEN_SYMBOLS_TO_STRUCTURE(bits) \
	static bool ecoff_symbols_to_structure_##bits(const ECoff_##bits *ecoff, RzStructuredData *parent) { \
		return ecoff_symbolic_hdr_to_structure_##bits(ecoff, parent) && \
			ecoff_local_symbols_to_structure_##bits(ecoff, parent) && \
			ecoff_external_symbols_to_structure_##bits(ecoff, parent) && \
			ecoff_file_descr_entries_to_structure_##bits(ecoff, parent) && \
			ecoff_proc_descr_entries_to_structure_##bits(ecoff, parent); \
	}

#define ECOFF_GEN_FUNCTIONS(bits) \
	ECOFF_GEN_HAS_SYMBOLIC_HEADER(bits) \
	ECOFF_GEN_INIT_HDR(bits) \
	ECOFF_GEN_RESOLVE_NAME(bits) \
	ECOFF_GEN_INIT_SECTION(bits) \
	ECOFF_GEN_FINI_SECTION(bits) \
	ECOFF_GEN_PARSE_SECTIONS(bits) \
	ECOFF_GEN_INIT_SYMBOLIC_HEADER(bits) \
	ECOFF_GEN_PARSE_FILE_DESCRIPTOR_ENTRIES(bits) \
	ECOFF_GEN_PARSE_PROC_DESCRIPTOR_ENTRIES(bits) \
	ECOFF_GEN_RESOLVE_SYMBOL_NAME(bits) \
	ECOFF_GEN_INIT_LOCAL_SYMBOL(bits) \
	ECOFF_GEN_FINI_LOCAL_SYMBOL(bits) \
	ECOFF_GEN_PARSE_LOCAL_SYMBOLS(bits) \
	ECOFF_GEN_INIT_EXTERNAL_SYMBOL(bits) \
	ECOFF_GEN_FINI_EXTERNAL_SYMBOL(bits) \
	ECOFF_GEN_RESOLVE_SYMBOLS(bits) \
	ECOFF_GEN_PARSE_EXTERNAL_SYMBOLS(bits) \
	ECOFF_GEN_FIND_PADDR_FROM_VADDR(bits) \
	ECOFF_GEN_SECTION_TO_BIN_SECTION(bits) \
	ECOFF_GEN_GET_SECTIONS(bits) \
	ECOFF_GEN_SECTION_TO_STRUCTURE(bits) \
	ECOFF_GEN_SECTIONS_TO_STRUCTURE(bits) \
	ECOFF_GEN_PROC_DESCR_ENTRIES_TO_STRUCTURE(bits) \
	ECOFF_GEN_FILE_DESCR_ENTRIES_TO_STRUCTURE(bits) \
	ECOFF_GEN_SYMBOLIC_HDR_TO_STRUCTURE(bits) \
	ECOFF_GEN_LOCAL_SYMBOL_TO_STRUCTURE(bits) \
	ECOFF_GEN_LOCAL_SYMBOLS_TO_STRUCTURE(bits) \
	ECOFF_GEN_EXTERNAL_SYMBOL_TO_STRUCTURE(bits) \
	ECOFF_GEN_EXTERNAL_SYMBOLS_TO_STRUCTURE(bits) \
	ECOFF_GEN_SYMBOLS_TO_STRUCTURE(bits)
