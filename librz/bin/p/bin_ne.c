// SPDX-FileCopyrightText: 2009-2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 alvarofe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "../i/private.h"
#include "../format/ne/ne.h"

static bool ne_check_buffer(RzBuffer *b) {
	ut64 length = rz_buf_size(b);
	if (length <= 0x3d) {
		return false;
	}

	ut16 idx;
	if (!rz_buf_read_le16_at(b, 0x3c, &idx)) {
		return false;
	}

	if ((ut64)idx + 26 < length) {
		ut8 buf[2];
		rz_buf_read_at(b, 0, buf, sizeof(buf));
		if (!memcmp(buf, "MZ", 2)) {
			rz_buf_read_at(b, idx, buf, sizeof(buf));
			if (!memcmp(buf, "NE", 2)) {
				return true;
			}
		}
	}
	return false;
}

static bool ne_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && buf, false);
	rz_bin_ne_obj_t *res = rz_bin_ne_new_buf(buf, bf->rbin->verbose);
	if (res) {
		obj->bin_obj = res;
		return true;
	}
	return false;
}

static void ne_destroy(RzBinFile *bf) {
	rz_bin_ne_free(bf->o->bin_obj);
}

static RzStructuredData *ne_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	rz_bin_ne_obj_t *ne_obj = bf->o->bin_obj;
	char tmp[256] = { 0 };

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *ne = rz_structured_data_map_add_map(info, "ne");
	if (!ne) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(ne, "MajLinkerVersion", ne_obj->ne_header->MajLinkerVersion, false);
	rz_structured_data_map_add_unsigned(ne, "MinLinkerVersion", ne_obj->ne_header->MinLinkerVersion, false);
	rz_structured_data_map_add_unsigned(ne, "EntryTableOffset", ne_obj->ne_header->EntryTableOffset, true);
	rz_structured_data_map_add_unsigned(ne, "EntryTableLength", ne_obj->ne_header->EntryTableLength, false);
	rz_structured_data_map_add_unsigned(ne, "FileLoadCRC", ne_obj->ne_header->FileLoadCRC, true);
	rz_structured_data_map_add_unsigned(ne, "ProgFlags", ne_obj->ne_header->ProgFlags, true);
	rz_structured_data_map_add_unsigned(ne, "ApplFlags", ne_obj->ne_header->ApplFlags, true);
	rz_structured_data_map_add_unsigned(ne, "AutoDataSegIndex", ne_obj->ne_header->AutoDataSegIndex, false);
	rz_structured_data_map_add_unsigned(ne, "InitHeapSize", ne_obj->ne_header->InitHeapSize, false);
	rz_structured_data_map_add_unsigned(ne, "InitStackSize", ne_obj->ne_header->InitStackSize, false);
	rz_structured_data_map_add_unsigned(ne, "EntryPointCSIndex", ne_obj->ne_header->csEntryPoint, false);
	rz_structured_data_map_add_unsigned(ne, "EntryPointIPOff", ne_obj->ne_header->ipEntryPoint, true);
	rz_structured_data_map_add_unsigned(ne, "InitStack", ne_obj->ne_header->InitStack, true);
	rz_structured_data_map_add_unsigned(ne, "SegCount", ne_obj->ne_header->SegCount, false);
	rz_structured_data_map_add_unsigned(ne, "ModuleRefsCount", ne_obj->ne_header->ModRefs, false);
	rz_structured_data_map_add_unsigned(ne, "NonResNamesTblSiz", ne_obj->ne_header->NoResNamesTabSiz, true);
	rz_structured_data_map_add_unsigned(ne, "SegTableOffset", ne_obj->ne_header->SegTableOffset, true);
	rz_structured_data_map_add_unsigned(ne, "ResourceTblOff", ne_obj->ne_header->ResTableOffset, true);
	rz_structured_data_map_add_unsigned(ne, "ResidentNameTblOff", ne_obj->ne_header->ResidNamTable, true);
	rz_structured_data_map_add_unsigned(ne, "ModuleRefTblOff", ne_obj->ne_header->ModRefTable, true);
	rz_structured_data_map_add_unsigned(ne, "ImportNameTblOff", ne_obj->ne_header->ImportNameTable, true);
	rz_structured_data_map_add_unsigned(ne, "OffStartNonResTab", ne_obj->ne_header->OffStartNonResTab, false);
	rz_structured_data_map_add_unsigned(ne, "MovEntryCount", ne_obj->ne_header->MovEntryCount, false);
	rz_structured_data_map_add_unsigned(ne, "FileAlnSzShftCnt", ne_obj->ne_header->FileAlnSzShftCnt, false);
	rz_structured_data_map_add_unsigned(ne, "nResTabEntries", ne_obj->ne_header->nResTabEntries, false);
	rz_structured_data_map_add_string(ne, "OS", ne_obj->os);
	rz_structured_data_map_add_unsigned(ne, "OS2EXEFlags", ne_obj->ne_header->OS2EXEFlags, true);
	rz_structured_data_map_add_unsigned(ne, "retThunkOffset", ne_obj->ne_header->retThunkOffset, true);
	rz_structured_data_map_add_unsigned(ne, "segRefThunksOff", ne_obj->ne_header->segrefthunksoff, true);
	rz_structured_data_map_add_unsigned(ne, "mincodeswap", ne_obj->ne_header->mincodeswap, false);

	rz_strf(tmp, "%d.%d", ne_obj->ne_header->expctwinver[1], ne_obj->ne_header->expctwinver[0]);
	rz_structured_data_map_add_string(ne, "winver", tmp);

	return info;
}

RzBinInfo *ne_info(RzBinFile *bf) {
	rz_bin_ne_obj_t *ne = bf->o->bin_obj;
	RzBinInfo *i = RZ_NEW0(RzBinInfo);
	if (i) {
		i->bits = 16;
		i->arch = rz_str_dup("x86");
		i->os = rz_str_dup(ne->os);
		i->claimed_checksum = rz_str_newf("%08x", ne->ne_header->FileLoadCRC);
	}
	return i;
}

RzPVector /*<RzBinAddr *>*/ *ne_entries(RzBinFile *bf) {
	return rz_bin_ne_get_entrypoints(bf->o->bin_obj);
}

RzPVector /*<RzBinSymbol *>*/ *ne_symbols(RzBinFile *bf) {
	return rz_bin_ne_get_symbols(bf->o->bin_obj);
}

RzPVector /*<RzBinImport *>*/ *ne_imports(RzBinFile *bf) {
	return rz_bin_ne_get_imports(bf->o->bin_obj);
}

RzPVector /*<RzBinSection *>*/ *ne_sections(RzBinFile *bf) {
	return rz_bin_ne_get_segments(bf->o->bin_obj);
}

RzPVector /*<RzBinReloc *>*/ *ne_relocs(RzBinFile *bf) {
	return rz_bin_ne_get_relocs(bf->o->bin_obj);
}

RzBinPlugin rz_bin_plugin_ne = {
	.name = "ne",
	.desc = "NE (New Executable)",
	.author = "GustavoLCR",
	.license = "LGPL3",
	.check_buffer = &ne_check_buffer,
	.load_buffer = &ne_load_buffer,
	.destroy = &ne_destroy,
	.bin_structure = &ne_structure,
	.info = &ne_info,
	.entries = &ne_entries,
	.sections = &ne_sections,
	.symbols = &ne_symbols,
	.imports = &ne_imports,
	.relocs = &ne_relocs,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_ne,
	.version = RZ_VERSION
};
#endif
