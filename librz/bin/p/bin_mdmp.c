// SPDX-FileCopyrightText: 2016-2018 Davis
// SPDX-FileCopyrightText: 2016-2018 Alex Kornitzer <alex.kornitzer@countercept.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_util/rz_print.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "mdmp/mdmp.h"

static Sdb *mdmp_get_sdb(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	MiniDmpObj *obj = (MiniDmpObj *)bf->o->bin_obj;
	return (obj && obj->kv) ? obj->kv : NULL;
}

static void mdmp_destroy(RzBinFile *bf) {
	rz_bin_mdmp_free((MiniDmpObj *)bf->o->bin_obj);
}

static RzPVector /*<RzBinAddr *>*/ *mdmp_entries(RzBinFile *bf) {
	MiniDmpObj *obj;
	struct Pe32_rz_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_rz_bin_mdmp_pe_bin *pe64_bin;
	RzListIter *it;
	RzPVector *ret, *vec;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}

	obj = (MiniDmpObj *)bf->o->bin_obj;

	rz_list_foreach (obj->pe32_bins, it, pe32_bin) {
		vec = Pe32_rz_bin_mdmp_pe_get_entrypoint(pe32_bin);
		rz_pvector_join(ret, vec);
		rz_pvector_free(vec);
	}
	rz_list_foreach (obj->pe64_bins, it, pe64_bin) {
		vec = Pe64_rz_bin_mdmp_pe_get_entrypoint(pe64_bin);
		rz_pvector_join(ret, vec);
		rz_pvector_free(vec);
	}

	return ret;
}

static RzBinInfo *mdmp_info(RzBinFile *bf) {
	MiniDmpObj *obj;
	RzBinInfo *ret;

	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}

	char tmpbuf[32];
	obj = (MiniDmpObj *)bf->o->bin_obj;

	ret->big_endian = false;
	ret->claimed_checksum = rz_str_newf("0x%08x", obj->hdr->check_sum);
	ret->file = bf->file ? strdup(bf->file) : NULL;
	ret->has_va = true;
	ret->rclass = strdup("mdmp");
	ret->rpath = strdup("NONE");
	ret->type = strdup("MDMP (MiniDump crash report data)");

	sdb_set(bf->sdb, "mdmp.flags", rz_strf(tmpbuf, "0x%08" PFMT64x, obj->hdr->flags));
	sdb_num_set(bf->sdb, "mdmp.streams", obj->hdr->number_of_streams);

	if (obj->streams.system_info) {
		switch (obj->streams.system_info->processor_architecture) {
		case MDMP_PROCESSOR_ARCHITECTURE_INTEL:
			ret->machine = strdup("i386");
			ret->arch = strdup("x86");
			ret->bits = 32;
			break;
		case MDMP_PROCESSOR_ARCHITECTURE_ARM:
			ret->machine = strdup("ARM");
			ret->big_endian = false;
			break;
		case MDMP_PROCESSOR_ARCHITECTURE_IA64:
			ret->machine = strdup("IA64");
			ret->arch = strdup("IA64");
			ret->bits = 64;
			break;
		case MDMP_PROCESSOR_ARCHITECTURE_AMD64:
			ret->machine = strdup("AMD64");
			ret->arch = strdup("x86");
			ret->bits = 64;
			break;
		default:
			ret->machine = strdup("Unknown");
			break;
		}

		switch (obj->streams.system_info->product_type) {
		case MDMP_VER_NT_WORKSTATION:
			ret->os = rz_str_newf("Windows NT Workstation %d.%d.%d",
				obj->streams.system_info->major_version,
				obj->streams.system_info->minor_version,
				obj->streams.system_info->build_number);
			break;
		case MDMP_VER_NT_DOMAIN_CONTROLLER:
			ret->os = rz_str_newf("Windows NT Server Domain Controller %d.%d.%d",
				obj->streams.system_info->major_version,
				obj->streams.system_info->minor_version,
				obj->streams.system_info->build_number);
			break;
		case MDMP_VER_NT_SERVER:
			ret->os = rz_str_newf("Windows NT Server %d.%d.%d",
				obj->streams.system_info->major_version,
				obj->streams.system_info->minor_version,
				obj->streams.system_info->build_number);
			break;
		default:
			ret->os = strdup("Unknown");
		}
	}

	return ret;
}

static RzPVector /*<char *>*/ *mdmp_libs(RzBinFile *bf) {
	char *ptr = NULL;
	MiniDmpObj *obj;
	RzPVector *libs = NULL;
	RzPVector *ret = NULL;
	RzListIter *it;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}

	obj = (MiniDmpObj *)bf->o->bin_obj;

	/* TODO: Resolve module name for lib, or filter to remove duplicates,
	** rather than the vaddr :) */
	struct Pe32_rz_bin_mdmp_pe_bin *pe32_bin;
	rz_list_foreach (obj->pe32_bins, it, pe32_bin) {
		if (!(libs = Pe32_rz_bin_pe_get_libs(pe32_bin->bin))) {
			continue;
		}
		void **libs_iter;
		rz_pvector_foreach (libs, libs_iter) {
			ptr = rz_str_newf("[0x%.08" PFMT64x "] - %s", pe32_bin->vaddr, (char *)*libs_iter);
			rz_pvector_push(ret, ptr);
		}
		rz_pvector_free(libs);
	}
	struct Pe64_rz_bin_mdmp_pe_bin *pe64_bin;
	rz_list_foreach (obj->pe64_bins, it, pe64_bin) {
		if (!(libs = Pe64_rz_bin_pe_get_libs(pe64_bin->bin))) {
			continue;
		}
		void **libs_iter;
		rz_pvector_foreach (libs, libs_iter) {
			ptr = rz_str_newf("[0x%.08" PFMT64x "] - %s", pe64_bin->vaddr, (char *)*libs_iter);
			rz_pvector_push(ret, ptr);
		}
		rz_pvector_free(libs);
	}
	return ret;
}

static bool mdmp_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(buf, false);
	MiniDmpObj *res = rz_bin_mdmp_new_buf(buf);
	if (res) {
		sdb_ns_set(sdb, "mdmp_info", res->kv);
		obj->bin_obj = res;
		return true;
	}
	return false;
}

static RzPVector /*<RzBinMap *>*/ *mdmp_maps(RzBinFile *bf) {
	MiniDmpObj *obj = (MiniDmpObj *)bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzListIter *it;
	MiniDmpMemDescr32 *memory;
	rz_list_foreach (obj->streams.memories, it, memory) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		map->paddr = (memory->memory).rva;
		map->psize = (memory->memory).data_size;
		map->vaddr = memory->start_of_memory_range;
		map->vsize = (memory->memory).data_size;
		map->perm = rz_bin_mdmp_get_perm(obj, map->vaddr);
		map->name = rz_str_newf("memory.0x%" PFMT64x, map->vaddr);
		rz_pvector_push(ret, map);
	}

	ut64 index = obj->streams.memories64.base_rva;
	MiniDmpMemDescr64 *memory64;
	rz_list_foreach (obj->streams.memories64.memories, it, memory64) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		map->paddr = index;
		map->psize = memory64->data_size;
		map->vaddr = memory64->start_of_memory_range;
		map->vsize = memory64->data_size;
		map->perm = rz_bin_mdmp_get_perm(obj, map->vaddr);
		map->name = rz_str_newf("memory64.0x%" PFMT64x, map->vaddr);
		rz_pvector_push(ret, map);
		index += memory64->data_size;
	}

	return ret;
}

static RzPVector /*<RzBinSection *>*/ *mdmp_sections(RzBinFile *bf) {
	MiniDmpModule *module;
	MiniDmpObj *obj;
	struct Pe32_rz_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_rz_bin_mdmp_pe_bin *pe64_bin;
	RzPVector *pe_secs;
	RzPVector *ret;
	RzListIter *it, *it0;
	RzBinSection *ptr;
	ut8 str_buffer[512];
	ut32 str_length = 0;

	obj = (MiniDmpObj *)bf->o->bin_obj;

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free))) {
		return NULL;
	}

	// XXX: Never add here as they are covered above
	rz_list_foreach (obj->streams.modules, it, module) {
		if (!rz_buf_read_le32_at(obj->b, module->module_name_rva, &str_length)) {
			RZ_LOG_ERROR("bin: mdmp: failed to read utf16 string length\n");
			break;
		}

		size_t ptr_name_len = (str_length + 2) * 4;
		if (ptr_name_len < 1 || ptr_name_len > (sizeof(str_buffer) + sizeof(str_length))) {
			continue;
		} else if ((module->module_name_rva + sizeof(str_length) + str_length) > rz_buf_size(obj->b)) {
			break;
		}

		memset(str_buffer, 0, sizeof(str_buffer));

		// best effor reading
		if (rz_buf_read_at(obj->b, module->module_name_rva + sizeof(str_length), str_buffer, sizeof(str_buffer)) < 2) {
			RZ_LOG_ERROR("bin: mdmp: failed to read utf16 string\n");
			break;
		}

		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}

		ptr->name = RZ_NEWS0(char, ptr_name_len);
		if (!ptr->name) {
			free(ptr);
			continue;
		}
		rz_str_utf16_to_utf8((ut8 *)ptr->name, str_length * 4, str_buffer, str_length, true);
		ptr->vaddr = module->base_of_image;
		ptr->vsize = module->size_of_image;
		ptr->paddr = rz_bin_mdmp_get_paddr(obj, ptr->vaddr);
		ptr->size = module->size_of_image;
		ptr->has_strings = false;
		/* As this is an encompassing section we will set the RWX to 0 */
		ptr->perm = 0;

		if (!rz_pvector_push(ret, ptr)) {
			free(ptr);
			break;
		}

		/* Grab the pe sections */
		rz_list_foreach (obj->pe32_bins, it0, pe32_bin) {
			if (pe32_bin->vaddr == module->base_of_image && pe32_bin->bin) {
				pe_secs = Pe32_rz_bin_mdmp_pe_get_sections(pe32_bin);
				rz_pvector_join(ret, pe_secs);
				rz_pvector_free(pe_secs);
			}
		}
		rz_list_foreach (obj->pe64_bins, it0, pe64_bin) {
			if (pe64_bin->vaddr == module->base_of_image && pe64_bin->bin) {
				pe_secs = Pe64_rz_bin_mdmp_pe_get_sections(pe64_bin);
				rz_pvector_join(ret, pe_secs);
				rz_pvector_free(pe_secs);
			}
		}
	}
	RZ_LOG_WARN("Parsing data sections for large dumps can take time, "
		    "please be patient (if strings are not needed, try with -z)!\n");
	return ret;
}

static RzPVector /*<RzBinMem *>*/ *mdmp_mem(RzBinFile *bf) {
	MiniDmpLocDescr32 *location = NULL;
	MiniDmpMemDescr32 *module;
	MiniDmpMemDescr64 *module64;
	MiniDmpMemInfo *mem_info;
	MiniDmpObj *obj;
	RzPVector *ret;
	RzListIter *it;
	RzBinMem *ptr;
	ut64 index;
	ut64 state, type, a_protect;

	if (!(ret = rz_pvector_new(rz_bin_mem_free))) {
		return NULL;
	}

	obj = (MiniDmpObj *)bf->o->bin_obj;

	/* [1] As there isnt a better place to put this mdmp_info at the moment we will
	** mash it into the name field, but without enumeration for now  */
	rz_list_foreach (obj->streams.memories, it, module) {
		if (!(ptr = RZ_NEW0(RzBinMem))) {
			return ret;
		}
		ptr->addr = module->start_of_memory_range;
		ptr->size = location ? location->data_size : 0;
		ptr->perms = rz_bin_mdmp_get_perm(obj, ptr->addr);

		/* [1] */
		state = type = a_protect = 0;
		if ((mem_info = rz_bin_mdmp_get_mem_info(obj, ptr->addr))) {
			state = mem_info->state;
			type = mem_info->type;
			a_protect = mem_info->allocation_protect;
		}
		location = &(module->memory);
		ptr->name = rz_str_newf("paddr=0x%08" PFMT32x " state=0x%08" PFMT64x
					" type=0x%08" PFMT64x " allocation_protect=0x%08" PFMT64x " Memory_Section",
			location->rva, state, type, a_protect);

		rz_pvector_push(ret, ptr);
	}

	index = obj->streams.memories64.base_rva;
	rz_list_foreach (obj->streams.memories64.memories, it, module64) {
		if (!(ptr = RZ_NEW0(RzBinMem))) {
			return ret;
		}
		ptr->addr = module64->start_of_memory_range;
		ptr->size = module64->data_size;
		ptr->perms = rz_bin_mdmp_get_perm(obj, ptr->addr);

		/* [1] */
		state = type = a_protect = 0;
		if ((mem_info = rz_bin_mdmp_get_mem_info(obj, ptr->addr))) {
			state = mem_info->state;
			type = mem_info->type;
			a_protect = mem_info->allocation_protect;
		}
		ptr->name = rz_str_newf("paddr=0x%08" PFMT64x " state=0x%08" PFMT64x
					" type=0x%08" PFMT64x " allocation_protect=0x%08" PFMT64x " Memory_Section",
			index, state, type, a_protect);

		index += module64->data_size;

		rz_pvector_push(ret, ptr);
	}

	return ret;
}

static RzPVector /*<RzBinReloc *>*/ *mdmp_relocs(RzBinFile *bf) {
	MiniDmpObj *obj;
	struct Pe32_rz_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_rz_bin_mdmp_pe_bin *pe64_bin;
	RzListIter *it;

	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	obj = (MiniDmpObj *)bf->o->bin_obj;

	rz_list_foreach (obj->pe32_bins, it, pe32_bin) {
		if (pe32_bin->bin && pe32_bin->bin->relocs) {
			rz_pvector_join(ret, pe32_bin->bin->relocs);
		}
	}
	rz_list_foreach (obj->pe64_bins, it, pe64_bin) {
		if (pe64_bin->bin && pe64_bin->bin->relocs) {
			rz_pvector_join(ret, pe64_bin->bin->relocs);
		}
	}

	return ret;
}

static RzPVector /*<RzBinImport *>*/ *mdmp_imports(RzBinFile *bf) {
	MiniDmpObj *obj;
	struct Pe32_rz_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_rz_bin_mdmp_pe_bin *pe64_bin;
	RzPVector *vec;
	RzListIter *it;

	RzPVector *ret = rz_pvector_new((RzListFree)rz_bin_import_free);
	if (!ret) {
		return NULL;
	}

	obj = (MiniDmpObj *)bf->o->bin_obj;

	rz_list_foreach (obj->pe32_bins, it, pe32_bin) {
		vec = Pe32_rz_bin_mdmp_pe_get_imports(pe32_bin);
		if (vec) {
			rz_pvector_join(ret, vec);
			rz_pvector_free(vec);
		}
	}
	rz_list_foreach (obj->pe64_bins, it, pe64_bin) {
		vec = Pe64_rz_bin_mdmp_pe_get_imports(pe64_bin);
		if (vec) {
			rz_pvector_join(ret, vec);
			rz_pvector_free(vec);
		}
	}
	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *mdmp_symbols(RzBinFile *bf) {
	MiniDmpObj *obj;
	struct Pe32_rz_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_rz_bin_mdmp_pe_bin *pe64_bin;
	RzList *list;
	RzPVector *ret;
	RzListIter *it, *iter;
	RzBinSymbol *sym;

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free))) {
		return NULL;
	}

	obj = (MiniDmpObj *)bf->o->bin_obj;

	rz_list_foreach (obj->pe32_bins, it, pe32_bin) {
		list = Pe32_rz_bin_mdmp_pe_get_symbols(bf->rbin, pe32_bin);
		rz_list_foreach (list, iter, sym) {
			rz_pvector_push(ret, sym);
		}
		list->length = 0;
		list->head = list->tail = NULL;
		rz_list_free(list);
	}
	rz_list_foreach (obj->pe64_bins, it, pe64_bin) {
		list = Pe64_rz_bin_mdmp_pe_get_symbols(bf->rbin, pe64_bin);
		rz_list_foreach (list, iter, sym) {
			rz_pvector_push(ret, sym);
		}
		list->length = 0;
		list->head = list->tail = NULL;
		rz_list_free(list);
	}
	return ret;
}

static bool mdmp_check_buffer(RzBuffer *b) {
	ut8 magic[6];
	if (rz_buf_read_at(b, 0, magic, sizeof(magic)) == 6) {
		return !memcmp(magic, MDMP_MAGIC, 6);
	}
	return false;
}

RzBinPlugin rz_bin_plugin_mdmp = {
	.name = "mdmp",
	.desc = "Windows MiniDump plugin",
	.license = "LGPL3",
	.destroy = &mdmp_destroy,
	.entries = mdmp_entries,
	.get_sdb = &mdmp_get_sdb,
	.imports = &mdmp_imports,
	.info = &mdmp_info,
	.libs = &mdmp_libs,
	.load_buffer = &mdmp_load_buffer,
	.check_buffer = &mdmp_check_buffer,
	.mem = &mdmp_mem,
	.relocs = &mdmp_relocs,
	.maps = &mdmp_maps,
	.sections = &mdmp_sections,
	.symbols = &mdmp_symbols,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_mdmp,
	.version = RZ_VERSION
};
#endif
