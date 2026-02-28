
/**
 * \file bin_os360.c
 * \brief Plugin implementation for OS/360 object file format.
 *
 * \xrefitem sources "Sources of information" "Sources of information"
 *
 *
 * \todo Some disadvantages:
 *  - END record have field \ref RzBinOS360EndRecord.module_size
 * that's currently not used, but it may be useful for validating
 * the module size.
 */

#include <rz_types.h>
#include <rz_bin.h>
#include <rz_lib.h>
#include "os360/os360bin.h"

static ut64 size(RzBinFile *bf) {
	if (!bf || !bf->buf) {
		return 0;
	}
	return rz_buf_size(bf->buf);
}

static char *section_type_to_string(ut64 type) {
	/* TODO */
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzBinOS360Obj *obj = bf->o->bin_obj;

	RzPVector *symbols = rz_pvector_new((RzPVectorFree)free);

	void **it;
	rz_pvector_foreach (obj->records, it) {
		RzBinOS360BaseRecord *record = *it;

		/* TODO */
		// if(record->type == OS360_RECORD_TYPE_SYM) {
		//     RzBinOS360SymRecord *sym_record = record->content;
		//     for(ut8 i = 0; i < sym_record->sym_num; i++) {
		//         RzBinOS360SymbolData *sym_data = &sym_record->data[i];

		//         if(IS_DATA_TYPE_PROBE(sym_data->organization)) {
		//             RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);

		//             if(IS_HAS_NAME_PROBE(sym_data->organization)) {
		//                 sym->name = rz_str_dup(sym_data->name);
		//             }
		//             sym->is_imported = false;
		//             sym->forwarder = "NONE";
		//             sym->bind = "NONE";
		//             sym->type = ;
		//             sym->vaddr = ;

		//             sym->size = ;
		//             rz_pvector_push(symbols, sym);
		//         }
		//     }
		// }

		if (record->type == OS360_RECORD_TYPE_END) {
			RzBinOS360EndRecord *end_record = record->content;
			RzBinAddr *entry = rz_bin_os360_extract_entry_address(obj, record);

			if (RZ_STR_ISNOTEMPTY(end_record->start_name) && entry) {
				RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
				sym->name = rz_str_dup(end_record->start_name);
				sym->is_imported = true;
				sym->forwarder = "NONE";
				sym->bind = "NONE";
				sym->type = RZ_BIN_TYPE_FUNC_STR;
				sym->vaddr = entry->vaddr;

				rz_pvector_push(symbols, sym);
				free(entry);
			}
		}
	}

	return symbols;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzBinOS360Obj *obj = bf->o->bin_obj;

	RzPVector *entries = rz_pvector_new((RzPVectorFree)free);

	void **it;
	rz_pvector_foreach (obj->records, it) {
		RzBinOS360BaseRecord *record = *it;

		if (record->type == OS360_RECORD_TYPE_END) {
			RzBinAddr *entry = rz_bin_os360_extract_entry_address(obj, record);
			if (entry) {
				rz_pvector_push(entries, entry);
			}
		}
	}

	return entries;
}

static RzPVector /*<RzBinVirtualFile *>*/ *virtual_files(RzBinFile *bf) {
	RzBinOS360Obj *obj = bf->o->bin_obj;

	RzPVector *entries = rz_pvector_new((RzPVectorFree)free);

	void **it;
	rz_pvector_foreach (obj->records, it) {
		RzBinOS360BaseRecord *record = *it;

		if (record->type == OS360_RECORD_TYPE_TXT) {
			RzBinOS360TxtRecord *txt_record = record->content;

			RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
			vf->name = rz_str_newf("TXT_record_%u", txt_record->esdid);
			vf->buf = rz_buf_new_from_bytes(txt_record->data, txt_record->data_size);
			vf->buf_owned = true;

			rz_pvector_push(entries, vf);
		}
	}

	return entries;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	RzBinOS360Obj *obj = bf->o->bin_obj;

	RzPVector *entries = rz_pvector_new((RzPVectorFree)free);

	void **it;
	rz_pvector_foreach (obj->records, it) {
		RzBinOS360BaseRecord *record = *it;

		if (record->type == OS360_RECORD_TYPE_TXT) {
			RzBinOS360TxtRecord *txt_record = record->content;

			RzBinMap *map = RZ_NEW0(RzBinMap);
			map->vfile_name = rz_str_newf("TXT_record_%u", txt_record->esdid);
			map->vaddr = txt_record->rel_addr;
			map->vsize = txt_record->data_size;

			rz_pvector_push(entries, map);
		}
	}

	return entries;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	const ut8 *buf_data = rz_buf_data(buf, &obj->size);
	obj->bin_obj = rz_bin_os360_init(buf_data, obj->size);
	return obj->bin_obj != NULL;
}

static void destroy(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return;
	}

	rz_bin_os360_destroy(bf->o->bin_obj);
}

RzBinPlugin rz_bin_plugin_os360 = {
	.name = "os360",
	.desc = "OS/360 binary format",
	.author = "godcodehunter",
	.version = "0.1.0",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.size = &size,
	.virtual_files = &virtual_files,
	.maps = &maps,
	.symbols = &symbols,
	.entries = &entries,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_os360,
	.version = RZ_VERSION
};
#endif