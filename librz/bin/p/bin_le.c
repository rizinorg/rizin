// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-FileCopyrightText: 2023 svr <svr.work@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "../format/le/le.h"

static RzBinInfo *le_info(RzBinFile *bf) {
	RzBinInfo *info = RZ_NEW0(RzBinInfo);
	if (!info) {
		return NULL;
	}
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	LE_header *h = bin->header;
	info->bits = 32;
	info->type = rz_str_dup(bin->type);
	info->cpu = rz_str_dup(bin->cpu);
	info->os = rz_str_dup(bin->os);
	info->arch = rz_str_dup(bin->arch);
	info->file = rz_str_dup(bin->modname ? bin->modname : "");
	info->big_endian = h->border || h->worder;
	info->has_va = true;
	info->baddr = 0;
	return info;
}

static RzStructuredData *le_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->rbin && bf->o && bf->o->bin_obj, NULL);

	char magic[4] = { 0 };
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	if (!bin) {
		return NULL;
	}

	LE_header *h = bin->header;
	if (!h) {
		return NULL;
	}

	memcpy(magic, h->magic, sizeof(h->magic));

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *le_info = rz_structured_data_map_add_map(info, "le");
	if (!le_info) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_string(le_info, "signature", magic);
	rz_structured_data_map_add_unsigned(le_info, "le_offset", bin->le_off, true);
	if (bin->mz_off && bin->mz_off != bin->le_off) {
		rz_structured_data_map_add_unsigned(le_info, "mz_offset", bin->mz_off, true);
	}

	rz_structured_data_map_add_string(le_info, "byte_order", h->border ? "big endian" : "little endian");
	rz_structured_data_map_add_string(le_info, "word_order", h->worder ? "big endian" : "little endian");
	rz_structured_data_map_add_unsigned(le_info, "format_level", h->level, false);
	rz_structured_data_map_add_string(le_info, "module_name", rz_str_get(bin->modname));
	rz_structured_data_map_add_string(le_info, "type", rz_str_get(bin->type));
	rz_structured_data_map_add_string(le_info, "cpu", rz_str_get(bin->cpu));
	rz_structured_data_map_add_string(le_info, "os", rz_str_get(bin->os));
	rz_structured_data_map_add_string(le_info, "arch", rz_str_get(bin->arch));
	rz_structured_data_map_add_unsigned(le_info, "version", h->ver, false);
	rz_structured_data_map_add_unsigned(le_info, "mflags", h->mflags, true);
	RzStructuredData *flags = rz_structured_data_map_add_array(le_info, "flags");
	if (!flags) {
		rz_structured_data_free(info);
		return NULL;
	}

	if (h->mflags) {
#define PF_(mask, cond, name) \
	if ((h->mflags & mask) cond) { \
		rz_structured_data_array_add_string(flags, name); \
	}
		PF_(M_SINGLE_DATA, , "SINGLEDATA");
		PF_(M_PP_LIB_INIT, , "INITINSTANCE");
		PF_(M_PP_LIB_TERM, , "TERMINSTANCE");
		PF_(M_INTERNAL_FIXUP, , "NOINTFIXUPS");
		PF_(M_EXTERNAL_FIXUP, , "NOEXTFIXUPS");
		if (h->mflags & M_USES_PM_WINDOWING) {
			rz_structured_data_array_add_string(flags, "PMWINAPI");
		} else {
			PF_(M_PM_WINDOWING_INCOMP, , "PMWININCOMP");
			PF_(M_PM_WINDOWING_COMPAT, , "PMWINCOMPAT");
		}
		PF_(M_TYPE_PM_DLL, , "PROTDLL");
		PF_(M_TYPE_MASK, == M_TYPE_EXE, "EXE");
		PF_(M_TYPE_MASK, == M_TYPE_DLL, "DLL");
		PF_(M_TYPE_MASK, == M_TYPE_PDD, "PDD");
		PF_(M_TYPE_MASK, == M_TYPE_VDD, "VDD");
		PF_(M_MP_UNSAFE, , "MPUNSAFE");
	}

	rz_structured_data_map_add_unsigned(le_info, "mpages", h->mpages, false);
	rz_structured_data_map_add_unsigned(le_info, "initial_eip_obj", h->startobj, false);
	rz_structured_data_map_add_unsigned(le_info, "initial_eip", h->eip, true);
	rz_structured_data_map_add_unsigned(le_info, "initial_stack_obj", h->stackobj, false);
	rz_structured_data_map_add_unsigned(le_info, "initial_esp", h->esp, true);
	rz_structured_data_map_add_unsigned(le_info, "page_size", h->pagesize, true);

	if (bin->is_le) {
		rz_structured_data_map_add_unsigned(le_info, "last_page_size", h->le_last_page_size, true);
	} else {
		rz_structured_data_map_add_unsigned(le_info, "page_shift", h->pageshift, true);
	}

	rz_structured_data_map_add_unsigned(le_info, "fixup_size", h->fixupsize, true);
	rz_structured_data_map_add_unsigned(le_info, "fixup_checksum", h->fixupsum, true);
	rz_structured_data_map_add_unsigned(le_info, "loader_size", h->ldrsize, true);
	rz_structured_data_map_add_unsigned(le_info, "loader_checksum", h->ldrsum, true);
	rz_structured_data_map_add_unsigned(le_info, "obj_table", h->objtab, true);
	rz_structured_data_map_add_unsigned(le_info, "obj_count", h->objcnt, false);
	rz_structured_data_map_add_unsigned(le_info, "obj_page_map", h->objmap, true);
	rz_structured_data_map_add_unsigned(le_info, "obj_iter_data_map", h->itermap, true);
	rz_structured_data_map_add_unsigned(le_info, "resource_table", h->rsrctab, true);
	rz_structured_data_map_add_unsigned(le_info, "resource_count", h->rsrccnt, false);
	rz_structured_data_map_add_unsigned(le_info, "resident_name_table", h->restab, true);
	rz_structured_data_map_add_unsigned(le_info, "entry_table", h->enttab, true);
	rz_structured_data_map_add_unsigned(le_info, "directives_table", h->dirtab, true);
	rz_structured_data_map_add_unsigned(le_info, "directives_count", h->dircnt, false);
	rz_structured_data_map_add_unsigned(le_info, "fixup_page_table", h->fpagetab, true);
	rz_structured_data_map_add_unsigned(le_info, "fixup_record_table", h->frectab, true);
	rz_structured_data_map_add_unsigned(le_info, "import_module_name_table", h->impmod, true);
	rz_structured_data_map_add_unsigned(le_info, "import_module_name_count", h->impmodcnt, false);
	rz_structured_data_map_add_unsigned(le_info, "import_procedure_name_table", h->impproc, true);
	rz_structured_data_map_add_unsigned(le_info, "per_page_checksum_table", h->pagesum, true);
	rz_structured_data_map_add_unsigned(le_info, "enumerated_data_pages", h->datapage, true);
	rz_structured_data_map_add_unsigned(le_info, "number_of_preload_pages", h->preload, false);
	rz_structured_data_map_add_unsigned(le_info, "non_resident_names_table", h->nrestab, true);
	rz_structured_data_map_add_unsigned(le_info, "size_non_resident_names", h->cbnrestab, false);
	rz_structured_data_map_add_unsigned(le_info, "checksum_non_resident_names", h->nressum, true);
	rz_structured_data_map_add_unsigned(le_info, "autodata_obj", h->autodata, false);
	rz_structured_data_map_add_unsigned(le_info, "debug_info", h->debuginfo, true);
	rz_structured_data_map_add_unsigned(le_info, "debug_length", h->debuglen, true);
	rz_structured_data_map_add_unsigned(le_info, "preload_pages", h->instpreload, false);
	rz_structured_data_map_add_unsigned(le_info, "demand_pages", h->instdemand, false);
	rz_structured_data_map_add_unsigned(le_info, "heap_size", h->heapsize, true);
	rz_structured_data_map_add_unsigned(le_info, "stack_size", h->stacksize, true);

	return info;
}

RzBinPlugin rz_bin_plugin_le = {
	.name = "le",
	.desc = "LE/LX",
	.author = "GustavoLCR",
	.license = "LGPL3",
	.check_buffer = &rz_bin_le_check_buffer,
	.load_buffer = &rz_bin_le_load_buffer,
	.destroy = &rz_bin_le_destroy,
	.info = &le_info,
	.bin_structure = &le_structure,
	.virtual_files = &rz_bin_le_get_virtual_files,
	.maps = &rz_bin_le_get_maps,
	.sections = &rz_bin_le_get_sections,
	.entries = &rz_bin_le_get_entry_points,
	.symbols = &rz_bin_le_get_symbols,
	.imports = &rz_bin_le_get_imports,
	.libs = &rz_bin_le_get_libs,
	.relocs = &rz_bin_le_get_relocs,
	// .regstate = &regstate
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_le,
	.version = RZ_VERSION
};
#endif
