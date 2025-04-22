// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2017-2018 rkx1209 <rkx1209dev@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "nxo/nxo.h"
#include <lz4.h>

#define NSO_OFF(x)           rz_offsetof(NSOHeader, x)
#define NSO_OFFSET_MODMEMOFF rz_offsetof(NXOStart, mod_memoffset)

#define VFILE_NAME_DECOMPRESSED "decompressed"

// starting at 0
typedef struct {
	ut32 magic; // NSO0
	ut32 pad0; // 4
	ut32 pad1; // 8
	ut32 pad2; // 12
	ut32 text_memoffset; // 16
	ut32 text_loc; // 20
	ut32 text_size; // 24
	ut32 pad3; // 28
	ut32 ro_memoffset; // 32
	ut32 ro_loc; // 36
	ut32 ro_size; // 40
	ut32 pad4; // 44
	ut32 data_memoffset; // 48
	ut32 data_loc; // 52
	ut32 data_size; // 56
	ut32 bss_size; // 60
} NSOHeader;

static ut64 baddr(RzBinFile *bf) {
	return 0x8000000;
}

static bool check_buffer(RzBuffer *b) {
	if (rz_buf_size(b) >= 0x20) {
		ut8 magic[4];
		if (rz_buf_read_at(b, 0, magic, sizeof(magic)) != 4) {
			return false;
		}
		return fileType(magic) != NULL;
	}
	return false;
}

static bool parse_header_aux(RzBuffer *buf, NSOHeader *r) {
	return rz_buf_read_le32_at(buf, NSO_OFF(magic), &r->magic) &&
		rz_buf_read_le32_at(buf, NSO_OFF(pad0), &r->pad0) &&
		rz_buf_read_le32_at(buf, NSO_OFF(pad1), &r->pad1) &&
		rz_buf_read_le32_at(buf, NSO_OFF(pad2), &r->pad2) &&
		rz_buf_read_le32_at(buf, NSO_OFF(text_memoffset), &r->text_memoffset) &&
		rz_buf_read_le32_at(buf, NSO_OFF(text_loc), &r->text_loc) &&
		rz_buf_read_le32_at(buf, NSO_OFF(text_size), &r->text_size) &&
		rz_buf_read_le32_at(buf, NSO_OFF(pad3), &r->pad3) &&
		rz_buf_read_le32_at(buf, NSO_OFF(ro_memoffset), &r->ro_memoffset) &&
		rz_buf_read_le32_at(buf, NSO_OFF(ro_loc), &r->ro_loc) &&
		rz_buf_read_le32_at(buf, NSO_OFF(ro_size), &r->ro_size) &&
		rz_buf_read_le32_at(buf, NSO_OFF(pad4), &r->pad4) &&
		rz_buf_read_le32_at(buf, NSO_OFF(data_memoffset), &r->data_memoffset) &&
		rz_buf_read_le32_at(buf, NSO_OFF(data_loc), &r->data_loc) &&
		rz_buf_read_le32_at(buf, NSO_OFF(data_size), &r->data_size) &&
		rz_buf_read_le32_at(buf, NSO_OFF(bss_size), &r->bss_size);
}

static NSOHeader *parse_header(RzBuffer *buf) {
	RZ_STATIC_ASSERT(sizeof(NSOHeader) == 64);
	if (rz_buf_size(buf) < sizeof(NSOHeader)) {
		return NULL;
	}
	NSOHeader *r = RZ_NEW0(NSOHeader);
	if (!r) {
		return NULL;
	}

	if (!parse_header_aux(buf, r)) {
		free(r);
		return NULL;
	}

	return r;
}

static RzBinNXOObj *nso_new(RzBuffer *buf) {
	RzBinNXOObj *bin = RZ_NEW0(RzBinNXOObj);
	if (!bin) {
		return NULL;
	}
	bin->header = parse_header(buf);
	if (!bin->header) {
		free(bin);
		return NULL;
	}
	return bin;
}

static void nso_free(RzBinNXOObj *bin) {
	if (!bin) {
		return;
	}
	rz_buf_free(bin->decompressed);
	free(bin->header);
	free(bin);
}

static bool decompress(RzBuffer *source_buf, ut64 source_offset, ut64 source_size, ut8 *dst_buf, ut64 decompressed_size) {
	if (!source_size || decompressed_size > (ut64)SIZE_MAX || source_size > (ut64)INT_MAX || decompressed_size > (ut64)INT_MAX) {
		return false;
	}
	ut8 *tmp = RZ_NEWS0(ut8, source_size);
	if (!tmp) {
		return false;
	}
	if (rz_buf_read_at(source_buf, source_offset, tmp, source_size) != source_size) {
		free(tmp);
		return false;
	}
	int r = LZ4_decompress_safe((const char *)tmp, (char *)dst_buf, source_size, decompressed_size);
	free(tmp);
	return r == decompressed_size;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(bf && buf, false);
	RzBinNXOObj *bin = nso_new(buf);
	if (!bin) {
		return false;
	}
	ut8 *tmp = NULL;
	NSOHeader *hdr = bin->header;
	if (hdr->ro_memoffset >= rz_buf_size(buf)) {
		RZ_LOG_ERROR("NSO file smaller than ro section offset\n");
		goto another_castle;
	}
	ut64 total_size = hdr->text_size + hdr->ro_size + hdr->data_size;
	if (total_size < hdr->text_size) {
		// Prevent integer overflow
		goto another_castle;
	}
	tmp = RZ_NEWS0(ut8, total_size);
	if (!tmp) {
		goto another_castle;
	}
	ut64 ba = baddr(bf);

	/* Decompress each section */
	if (!decompress(buf, hdr->text_memoffset, hdr->ro_memoffset - hdr->text_memoffset, tmp, hdr->text_size)) {
		RZ_LOG_ERROR("Failed to decompress NSO text section\n");
		goto another_castle;
	}
	if (!decompress(buf, hdr->ro_memoffset, hdr->data_memoffset - hdr->ro_memoffset, tmp + hdr->text_size, hdr->ro_size)) {
		RZ_LOG_ERROR("Failed to decompress NSO ro section\n");
		goto another_castle;
	}
	if (!decompress(buf, hdr->data_memoffset, rz_buf_size(buf) - hdr->data_memoffset, tmp + hdr->text_size + hdr->ro_size, hdr->data_size)) {
		RZ_LOG_ERROR("Failed to decompress NSO data section\n");
		goto another_castle;
	}
	bin->decompressed = rz_buf_new_with_pointers(tmp, total_size, true);
	if (!bin->decompressed) {
		goto another_castle;
	}

	/* Load unpacked binary */
	ut32 modoff;
	if (!rz_buf_read_le32_at(bin->decompressed, NSO_OFFSET_MODMEMOFF, &modoff)) {
		goto another_castle;
	}

	RZ_LOG_INFO("MOD Offset = 0x%" PFMT64x "\n", (ut64)modoff);
	parseMod(bin->decompressed, bin, modoff, ba);
	obj->bin_obj = bin;
	return true;
another_castle:
	nso_free(bin);
	free(tmp);
	obj->bin_obj = NULL;
	return false;
}

static void destroy(RzBinFile *bf) {
	if (!bf->o) {
		return;
	}
	nso_free(bf->o->bin_obj);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	return NULL; // TODO
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBuffer *b = bf->buf;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}

	RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
	if (!ptr) {
		rz_pvector_free(ret);
		return NULL;
	}

	ut32 tmp;
	if (!rz_buf_read_le32_at(b, NSO_OFF(text_memoffset), &tmp)) {
		rz_pvector_free(ret);
		free(ptr);
		return NULL;
	}
	ptr->paddr = tmp;

	if (!rz_buf_read_le32_at(b, NSO_OFF(text_loc), &tmp)) {
		rz_pvector_free(ret);
		free(ptr);
		return NULL;
	}
	ptr->vaddr = tmp;

	ptr->vaddr += baddr(bf);

	rz_pvector_push(ret, ptr);

	return ret;
}

static Sdb *get_sdb(RzBinFile *bf) {
	Sdb *kv = sdb_new0();
	sdb_num_set(kv, "nso_start.offset", 0);
	sdb_num_set(kv, "nso_start.size", 16);
	sdb_set(kv, "nso_start.format", "xxq unused mod_memoffset padding");
	sdb_num_set(kv, "nso_header.offset", 0);
	sdb_num_set(kv, "nso_header.size", 0x40);
	sdb_set(kv, "nso_header.format", "xxxxxxxxxxxx magic unk size unk2 text_offset text_size ro_offset ro_size data_offset data_size bss_size unk3");
	sdb_ns_set(bf->sdb, "info", kv);
	return kv;
}

static RzPVector /*<RzBinVirtualFile *>*/ *virtual_files(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!ret) {
		return NULL;
	}
	RzBinNXOObj *bin = bf->o->bin_obj;
	if (bin->decompressed) {
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			return ret;
		}
		vf->buf = bin->decompressed;
		vf->buf_owned = false;
		vf->name = rz_str_dup(VFILE_NAME_DECOMPRESSED);
		rz_pvector_push(ret, vf);
	}
	return ret;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzBinNXOObj *bin = bf->o->bin_obj;
	NSOHeader *hdr = bin->header;
	ut64 ba = baddr(bf);

	RzBinMap *map = RZ_NEW0(RzBinMap);
	if (!map) {
		return ret;
	}
	map->name = rz_str_dup("text");
	map->paddr = bin->decompressed ? 0 : hdr->text_memoffset;
	map->vsize = map->psize = hdr->text_size;
	map->vaddr = hdr->text_loc + ba;
	map->perm = RZ_PERM_RX;
	map->vfile_name = bin->decompressed ? rz_str_dup(VFILE_NAME_DECOMPRESSED) : NULL;
	rz_pvector_push(ret, map);

	// add ro segment
	map = RZ_NEW0(RzBinMap);
	if (!map) {
		return ret;
	}
	map->name = rz_str_dup("ro");
	map->paddr = bin->decompressed ? hdr->text_size : hdr->ro_memoffset;
	map->vsize = map->psize = hdr->ro_size;
	map->vaddr = hdr->ro_loc + ba;
	map->perm = RZ_PERM_R;
	map->vfile_name = bin->decompressed ? rz_str_dup(VFILE_NAME_DECOMPRESSED) : NULL;
	rz_pvector_push(ret, map);

	// add data segment
	map = RZ_NEW0(RzBinMap);
	if (!map) {
		return ret;
	}
	map->name = rz_str_dup("data");
	map->paddr = bin->decompressed ? hdr->text_size + hdr->ro_size : hdr->data_memoffset;
	map->vsize = map->psize = hdr->data_size;
	map->vaddr = hdr->data_loc + ba;
	map->perm = RZ_PERM_RW;
	map->vfile_name = bin->decompressed ? rz_str_dup(VFILE_NAME_DECOMPRESSED) : NULL;
	rz_pvector_push(ret, map);
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;
	RzBuffer *b = bf->buf;
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free))) {
		return NULL;
	}

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("header");
	ut32 tmp;
	if (!rz_buf_read_le32_at(b, NSO_OFF(text_memoffset), &tmp)) {
		rz_pvector_free(ret);
		return NULL;
	}
	ptr->size = tmp;

	if (!rz_buf_read_le32_at(b, NSO_OFF(text_memoffset), &tmp)) {
		rz_pvector_free(ret);
		return NULL;
	}
	ptr->vsize = tmp;

	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->perm = RZ_PERM_R;
	rz_pvector_push(ret, ptr);

	RzPVector *mappies = maps(bf);
	if (mappies) {
		RzPVector *msecs = rz_bin_sections_of_maps(mappies);
		if (msecs) {
			void **iter;
			RzBinSection *section;
			rz_pvector_foreach (msecs, iter) {
				section = *iter;
				rz_pvector_push(ret, section);
			}
			msecs->v.len = 0;
			rz_pvector_free(msecs);
		}
		rz_pvector_free(mappies);
	}
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ut8 magic[4];
	if (rz_buf_read_at(bf->buf, NSO_OFF(magic), magic, sizeof(magic)) != sizeof(magic)) {
		free(ret);
		return NULL;
	}

	const char *ft = fileType(magic);
	if (!ft) {
		ft = "nso";
	}
	ret->file = rz_str_dup(bf->file);
	ret->rclass = rz_str_dup(ft);
	ret->os = rz_str_dup("switch");
	ret->arch = rz_str_dup("arm");
	ret->machine = rz_str_dup("Nintendo Switch");
	ret->subsystem = rz_str_dup(ft);
	ret->bclass = rz_str_dup("program");
	ret->type = rz_str_dup("EXEC (executable file)");
	ret->bits = 64;
	ret->has_va = true;
	ret->big_endian = false;
	ret->dbg_info = 0;
	return ret;
}

#if !RZ_BIN_NSO

RzBinPlugin rz_bin_plugin_nso = {
	.name = "nso",
	.desc = "Nintendo Switch NSO0 binaries",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.virtual_files = &virtual_files,
	.maps = &maps,
	.sections = &sections,
	.get_sdb = &get_sdb,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_nso,
	.version = RZ_VERSION
};
#endif
#endif
