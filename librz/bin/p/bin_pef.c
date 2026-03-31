// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Reference: https://developer.apple.com/library/archive/documentation/mac/pdf/MacOS_RT_Architectures.pdf#G20.827
 */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>
#include "../format/pef/pef.h"

static bool read_pef_header(PefHeader *hdr, RzBuffer *b, ut64 offset) {
	rz_return_val_if_fail(hdr && b, false);

	return rz_buf_read_offset(b, &offset, hdr->magic1, 4) &&
		rz_buf_read_offset(b, &offset, hdr->magic2, 4) &&
		rz_buf_read_be32_offset(b, &offset, &hdr->arch) &&
		rz_buf_read_be32_offset(b, &offset, &hdr->format_version) &&
		rz_buf_read_be32_offset(b, &offset, &hdr->timestamp) &&
		rz_buf_read_be32_offset(b, &offset, &hdr->old_def_version) &&
		rz_buf_read_be32_offset(b, &offset, &hdr->old_imp_version) &&
		rz_buf_read_be32_offset(b, &offset, &hdr->current_version) &&
		rz_buf_read_be16_offset(b, &offset, &hdr->section_count) &&
		rz_buf_read_be16_offset(b, &offset, &hdr->inst_section_count) &&
		rz_buf_read_be32_offset(b, &offset, &hdr->reserved);
}

static bool read_pef_section_header(PefSectionHeader *sh, RzBuffer *b, ut64 offset) {
	rz_return_val_if_fail(sh && b, false);

	return rz_buf_read_be32_offset(b, &offset, &sh->nameOffset) &&
		rz_buf_read_be32_offset(b, &offset, &sh->defaultAddress) &&
		rz_buf_read_be32_offset(b, &offset, &sh->totalSize) &&
		rz_buf_read_be32_offset(b, &offset, &sh->unpackedSize) &&
		rz_buf_read_be32_offset(b, &offset, &sh->packedSize) &&
		rz_buf_read_be32_offset(b, &offset, &sh->containerOffset) &&
		rz_buf_read_offset(b, &offset, &sh->sectionKind, 1) &&
		rz_buf_read_offset(b, &offset, &sh->shareKind, 1) &&
		rz_buf_read_offset(b, &offset, &sh->alignment, 1) &&
		rz_buf_read_offset(b, &offset, &sh->reservedA, 1);
}

static void pef_container_free(PefContainer *c) {
	if (!c) {
		return;
	}
	rz_vector_fini(&c->sections);
	rz_vector_fini(&c->loader_section.loader_library);
	rz_vector_fini(&c->loader_section.loader_import_symbol);
	rz_vector_fini(&c->loader_section.loader_reloc_header);
	rz_vector_fini(&c->loader_section.loader_export_hash_entry);
	rz_vector_fini(&c->loader_section.loader_export_hash_key);
	rz_vector_fini(&c->loader_section.loader_export_symbol);
	free(c);
}

static bool pef_check_buffer(RzBuffer *buf) {
	if (!buf || rz_buf_size(buf) < PEF_HDR_SIZE) {
		return false;
	}

	ut32 tag1 = 0;
	ut32 tag2 = 0;
	ut32 arch = 0;

	ut64 offset = 0;

	if (!rz_buf_read_be32_offset(buf, &offset, &tag1) ||
		!rz_buf_read_be32_offset(buf, &offset, &tag2) ||
		!rz_buf_read_be32_offset(buf, &offset, &arch)) {
		return false;
	}

	if (tag1 != MAGIC_HEADER_T1 || tag2 != MAGIC_HEADER_T2) {
		return false;
	}

	if (arch != PEF_ARCH_PWPC && arch != PEF_ARCH_M68K) {
		return false;
	}

	return true;
}

static bool pef_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && buf, false);

	if (!pef_check_buffer(buf)) {
		return false;
	}

	ut64 buf_sz = rz_buf_size(buf);
	PefContainer *container = RZ_NEW0(PefContainer);
	if (!container) {
		return false;
	}

	if (!read_pef_header(&container->header, buf, 0)) {
		pef_container_free(container);
		return false;
	}

	ut16 count = container->header.section_count;

	rz_vector_init(&container->sections, sizeof(PefSectionHeader), NULL, NULL);
	rz_vector_init(&container->loader_section.loader_library, sizeof(PEFLoaderImportLibrary), NULL, NULL);
	rz_vector_init(&container->loader_section.loader_import_symbol, sizeof(PEFLoaderImportSymbol), NULL, NULL);
	rz_vector_init(&container->loader_section.loader_reloc_header, sizeof(PEFLoaderRelocationHeader), NULL, NULL);
	rz_vector_init(&container->loader_section.loader_export_hash_entry, sizeof(PEFLoaderExportHashEntry), NULL, NULL);
	rz_vector_init(&container->loader_section.loader_export_hash_key, sizeof(PEFLoaderExportHashKey), NULL, NULL);
	rz_vector_init(&container->loader_section.loader_export_symbol, sizeof(PEFLoaderExportSymbol), NULL, NULL);

	// Initialize loader section header with default values
	memset(&container->loader_section.header, 0, sizeof(PEFLoaderSectionHeader));
	container->loader_section.header.main_symbol_index = -1;
	container->loader_section.header.init_symbol_index = -1;
	container->loader_section.header.term_symbol_index = -1;

	ut64 section_off = PEF_HDR_SIZE;
	for (ut16 i = 0; i < count; i++) {
		if (section_off + PEF_SECTION_HEADER_SIZE > buf_sz) {
			pef_container_free(container);
			return false;
		}

		PefSectionHeader sh = { 0 };
		if (!read_pef_section_header(&sh, buf, section_off)) {
			pef_container_free(container);
			return false;
		}

		rz_vector_push(&container->sections, &sh);
		section_off += PEF_SECTION_HEADER_SIZE;
	}

	obj->bin_obj = container;
	return true;
}

static const char *pef_arch(const PefContainer *c) {
	switch (c->header.arch) {
	case PEF_ARCH_PWPC:
		return "ppc";
	case PEF_ARCH_M68K:
		return "m68k";
	default:
		return "unknown";
	}
}

static const char *pef_machine(const PefContainer *c) {
	switch (c->header.arch) {
	case PEF_ARCH_PWPC:
		return "PowerPC";
	case PEF_ARCH_M68K:
		return "Motorola 68000";
	default:
		return "unknown";
	}
}

static RzBinInfo *pef_info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	PefContainer *c = (PefContainer *)bf->o->bin_obj;
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->file = strdup(bf->file);
	ret->type = strdup("Executable");
	ret->bclass = strdup("PEF");
	ret->rclass = strdup("pef");
	ret->os = strdup("Mac OS");
	ret->arch = strdup(pef_arch(c));
	ret->machine = strdup(pef_machine(c));
	ret->bits = 32;
	ret->big_endian = true;
	ret->has_va = true;
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *pef_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	PefContainer *c = (PefContainer *)bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	for (ut32 i = 0; i < rz_vector_len(&c->sections); i++) {
		PefSectionHeader *sh = rz_vector_index_ptr(&c->sections, i);
		RzBinSection *section = RZ_NEW0(RzBinSection);
		if (!section) {
			continue;
		}

		section->paddr = sh->containerOffset;
		section->vaddr = sh->defaultAddress;
		section->size = sh->packedSize;
		section->vsize = sh->totalSize;

		switch (sh->sectionKind) {
		case EXECUTABLE_READONLY:
			section->perm = RZ_PERM_R | RZ_PERM_X;
			section->name = strdup(".text");
			break;

		case EXECUTABLE_READWRITE:
			section->perm = RZ_PERM_RWX;
			section->name = rz_str_newf("section_%u", i);
			break;

		case UNPACKED_DATA:
			section->perm = RZ_PERM_RW;
			section->name = strdup(".data");
			break;

		case CONSTANT:
			section->perm = RZ_PERM_R;
			section->name = strdup(".rodata");
			break;

		case LOADER:
			section->perm = RZ_PERM_R;
			section->name = strdup(".loader");
			break;

		default:
			section->perm = RZ_PERM_R;
			section->name = rz_str_newf("section_%u", i);
			break;
		}

		rz_pvector_push(ret, section);
	}

	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *pef_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	PefContainer *c = (PefContainer *)bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)free);
	if (!ret) {
		return NULL;
	}

	// For now, we'll use the base address of the first executable section as entry
	for (ut32 i = 0; i < rz_vector_len(&c->sections); i++) {
		PefSectionHeader *sh = rz_vector_index_ptr(&c->sections, i);
		if (sh->sectionKind == EXECUTABLE_READONLY) {
			RzBinAddr *addr = RZ_NEW0(RzBinAddr);
			if (!addr) {
				break;
			}
			addr->vaddr = sh->defaultAddress;
			addr->paddr = sh->containerOffset;
			rz_pvector_push(ret, addr);
			break;
		}
	}

	return ret;
}

static ut64 pef_baddr(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, 0);

	PefContainer *c = (PefContainer *)bf->o->bin_obj;

	// Find the first code section and return its default address
	for (ut32 i = 0; i < rz_vector_len(&c->sections); i++) {
		PefSectionHeader *sh = rz_vector_index_ptr(&c->sections, i);
		if (sh->sectionKind == EXECUTABLE_READONLY) {
			return sh->defaultAddress;
		}
	}
	return 0;
}

static const char *pef_section_kind_to_string(ut8 k) {
	switch (k) {
	case EXECUTABLE_READONLY: return "executable_readonly";
	case UNPACKED_DATA: return "unpacked_data";
	case PATTERN_DATA: return "pattern_data";
	case CONSTANT: return "constant";
	case LOADER: return "loader";
	case EXECUTABLE_READWRITE: return "executable_readwrite";
	default: return "reserved";
	}
}

static const char *pef_share_kind_to_string(ut8 k) {
	switch (k) {
	case PROCESS: return "process";
	case GLOBAL: return "global";
	case PROTECTED: return "protected";
	default: return "unknown";
	}
}

static RzStructuredData *pef_header_structure(PefContainer *c) {
	RzStructuredData *m = rz_structured_data_new_map();
	if (!m) {
		return NULL;
	}

	rz_structured_data_map_add_bytes(m, "magic1", c->header.magic1, 4, RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_bytes(m, "magic2", c->header.magic2, 4, RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_unsigned(m, "arch_raw", c->header.arch, false);
	rz_structured_data_map_add_unsigned(m, "format_version", c->header.format_version, false);
	rz_structured_data_map_add_unsigned(m, "timestamp", c->header.timestamp, false);
	rz_structured_data_map_add_unsigned(m, "old_def_version", c->header.old_def_version, false);
	rz_structured_data_map_add_unsigned(m, "old_imp_version", c->header.old_imp_version, false);
	rz_structured_data_map_add_unsigned(m, "current_version", c->header.current_version, false);
	rz_structured_data_map_add_unsigned(m, "section_count", c->header.section_count, false);
	rz_structured_data_map_add_unsigned(m, "inst_section_count", c->header.inst_section_count, false);

	return m;
}

static RzStructuredData *pef_sections_structure(PefContainer *c) {
	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	PefSectionHeader *sh;
	rz_vector_foreach (&c->sections, sh) {
		RzStructuredData *m = rz_structured_data_array_add_map(arr);
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "name_offset", sh->nameOffset, true);
		rz_structured_data_map_add_unsigned(m, "default_address", sh->defaultAddress, true);
		rz_structured_data_map_add_unsigned(m, "total_size", sh->totalSize, false);
		rz_structured_data_map_add_unsigned(m, "unpacked_size", sh->unpackedSize, false);
		rz_structured_data_map_add_unsigned(m, "packed_size", sh->packedSize, false);
		rz_structured_data_map_add_unsigned(m, "container_offset", sh->containerOffset, true);
		rz_structured_data_map_add_unsigned(m, "section_kind", sh->sectionKind, true);
		rz_structured_data_map_add_string(m, "section_kind_name", pef_section_kind_to_string(sh->sectionKind));
		rz_structured_data_map_add_unsigned(m, "share_kind", sh->shareKind, true);
		rz_structured_data_map_add_string(m, "share_kind_name", pef_share_kind_to_string(sh->shareKind));
		rz_structured_data_map_add_unsigned(m, "alignment_power", sh->alignment, false);
	}

	return arr;
}

static RzStructuredData *pef_loader_header_structure(PefContainer *c) {
	PEFLoaderSectionHeader *lh = &c->loader_section.header;

	RzStructuredData *m = rz_structured_data_new_map();
	if (!m) {
		return NULL;
	}

	rz_structured_data_map_add_unsigned(m, "main_symbol_index", lh->main_symbol_index, false);
	rz_structured_data_map_add_unsigned(m, "main_symbol_offset", lh->main_symbol_offset, true);
	rz_structured_data_map_add_unsigned(m, "init_symbol_index", lh->init_symbol_index, false);
	rz_structured_data_map_add_unsigned(m, "init_symbol_offset", lh->init_symbol_offset, true);
	rz_structured_data_map_add_unsigned(m, "term_symbol_index", lh->term_symbol_index, false);
	rz_structured_data_map_add_unsigned(m, "term_symbol_offset", lh->term_symbol_offset, true);
	rz_structured_data_map_add_unsigned(m, "imported_lib_count", lh->imported_lib_count, false);
	rz_structured_data_map_add_unsigned(m, "imported_symbol_count", lh->imported_symbol_count, false);
	rz_structured_data_map_add_unsigned(m, "rel_section_count", lh->rel_section_count, false);
	rz_structured_data_map_add_unsigned(m, "rel_commands_offset", lh->rel_commands_offset, true);
	rz_structured_data_map_add_unsigned(m, "string_table_offset", lh->string_table_offset, true);
	rz_structured_data_map_add_unsigned(m, "export_hash_offset", lh->export_hash_offset, true);
	rz_structured_data_map_add_unsigned(m, "export_hash_power", lh->export_hash_power, false);
	rz_structured_data_map_add_unsigned(m, "exported_symbol_count", lh->exported_symbol_count, false);

	return m;
}

static RzStructuredData *pef_import_libs_structure(PefContainer *c) {
	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	PEFLoaderImportLibrary *lib;
	rz_vector_foreach (&c->loader_section.loader_library, lib) {
		RzStructuredData *m = rz_structured_data_array_add_map(arr);
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "name_offset", lib->name_offset, true);
		rz_structured_data_map_add_unsigned(m, "old_imp_version", lib->old_imp_version, false);
		rz_structured_data_map_add_unsigned(m, "current_version", lib->current_version, false);
		rz_structured_data_map_add_unsigned(m, "imported_symbol_count", lib->imported_symbol_count, false);
		rz_structured_data_map_add_unsigned(m, "start_index", lib->start_index, false);
		rz_structured_data_map_add_unsigned(m, "options", lib->options, false);
	}

	return arr;
}

static RzStructuredData *pef_import_symbols_structure(PefContainer *c) {
	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	PEFLoaderImportSymbol *sym;
	rz_vector_foreach (&c->loader_section.loader_import_symbol, sym) {
		RzStructuredData *m = rz_structured_data_array_add_map(arr);
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "raw", sym->u, false);
		rz_structured_data_map_add_unsigned(m, "flags", pef_import_flags(sym->u), false);
		rz_structured_data_map_add_unsigned(m, "type", pef_import_type(sym->u), false);
		rz_structured_data_map_add_unsigned(m, "name_offset", pef_import_name_offset(sym->u), true);
	}

	return arr;
}

static RzStructuredData *pef_export_symbols_structure(PefContainer *c) {
	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	PEFLoaderExportSymbol *sym;
	rz_vector_foreach (&c->loader_section.loader_export_symbol, sym) {
		RzStructuredData *m = rz_structured_data_array_add_map(arr);
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "raw", sym->type_and_name, false);
		rz_structured_data_map_add_unsigned(m, "flags", pef_export_symbol_flags(sym->type_and_name), false);
		rz_structured_data_map_add_unsigned(m, "type", pef_export_symbol_type(sym->type_and_name), false);
		rz_structured_data_map_add_unsigned(m, "name_offset", pef_export_symbol_name_offset(sym->type_and_name), true);
		rz_structured_data_map_add_unsigned(m, "value", sym->value, true);
		rz_structured_data_map_add_unsigned(m, "section_index", sym->section_index, false);
	}

	return arr;
}

static RzStructuredData *pef_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	PefContainer *c = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *pef = rz_structured_data_map_add_map(info, "pef");
	if (!pef) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add(pef, "header", pef_header_structure(c));
	rz_structured_data_map_add(pef, "sections", pef_sections_structure(c));

	RzStructuredData *loader = rz_structured_data_map_add_map(pef, "loader");
	if (!loader) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add(loader, "header", pef_loader_header_structure(c));
	rz_structured_data_map_add(loader, "import_libraries", pef_import_libs_structure(c));
	rz_structured_data_map_add(loader, "import_symbols", pef_import_symbols_structure(c));
	rz_structured_data_map_add(loader, "export_symbols", pef_export_symbols_structure(c));

	return info;
}

RZ_API RzBinPlugin rz_bin_plugin_pef = {
	.name = "pef",
	.desc = "Preferred Executable Format",
	.license = "LGPL3",
	.author = "farhan-25",
	.check_buffer = &pef_check_buffer,
	.load_buffer = &pef_load_buffer,
	.entries = &pef_entries,
	.sections = &pef_sections,
	.maps = &rz_bin_maps_of_file_sections,
	.info = &pef_info,
	.baddr = &pef_baddr,
	.bin_structure = &pef_structure
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_pef,
	.version = RZ_VERSION
};
#endif
