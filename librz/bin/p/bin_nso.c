// SPDX-FileCopyrightText: 2017-2018 rkx1209 <rkx1209dev@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_io.h>
#include <rz_cons.h>
#include "nxo/nxo.h"
#include <lz4.h>

#define NSO_OFF(x)           rz_offsetof(NSOHeader, x)
#define NSO_OFFSET_MODMEMOFF rz_offsetof(NXOStart, mod_memoffset)

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

static uint32_t decompress(const ut8 *cbuf, ut8 *obuf, int32_t csize, int32_t usize) {
	if (csize < 0 || usize < 0 || !cbuf || !obuf) {
		return -1;
	}
	return LZ4_decompress_safe((const char *)cbuf, (char *)obuf, (uint32_t)csize, (uint32_t)usize);
}

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

static RzBinNXOObj *nso_new(void) {
	RzBinNXOObj *bin = RZ_NEW0(RzBinNXOObj);
	if (bin) {
		bin->methods_list = rz_list_newf((RzListFree)free);
		bin->imports_list = rz_list_newf((RzListFree)free);
		bin->classes_list = rz_list_newf((RzListFree)free);
	}
	return bin;
}

static bool load_bytes(RzBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	eprintf("load_bytes in bin.nso must die\n");
	RzBin *rbin = bf->rbin;
	ut32 toff = rz_buf_read_le32_at(bf->buf, NSO_OFF(text_memoffset));
	ut32 tsize = rz_buf_read_le32_at(bf->buf, NSO_OFF(text_size));
	ut32 rooff = rz_buf_read_le32_at(bf->buf, NSO_OFF(ro_memoffset));
	ut32 rosize = rz_buf_read_le32_at(bf->buf, NSO_OFF(ro_size));
	ut32 doff = rz_buf_read_le32_at(bf->buf, NSO_OFF(data_memoffset));
	ut32 dsize = rz_buf_read_le32_at(bf->buf, NSO_OFF(data_size));
	ut64 total_size = tsize + rosize + dsize;
	RzBuffer *newbuf = rz_buf_new_empty(total_size);
	ut64 ba = baddr(bf);
	ut8 *tmp = NULL;

	if (rbin->iob.io && !(rbin->iob.io->cached & RZ_PERM_W)) {
		eprintf("Please add \'-e io.cache=true\' option to rz command. This is required to decompress the code.\n");
		goto fail;
	}
	/* Decompress each sections */
	tmp = RZ_NEWS(ut8, tsize);
	if (!tmp) {
		goto fail;
	}
	if (decompress(buf + toff, tmp, rooff - toff, tsize) != tsize) {
		eprintf("decompression failure\n");
		goto fail;
	}
	rz_buf_write_at(newbuf, 0, tmp, tsize);
	RZ_FREE(tmp);

	tmp = RZ_NEWS(ut8, rosize);
	if (!tmp) {
		goto fail;
	}
	if (decompress(buf + rooff, tmp, doff - rooff, rosize) != rosize) {
		eprintf("decompression2 failure\n");
		goto fail;
	}
	rz_buf_write_at(newbuf, tsize, tmp, rosize);
	RZ_FREE(tmp);

	tmp = RZ_NEWS(ut8, dsize);
	if (!tmp) {
		goto fail;
	}
	if (decompress(buf + doff, tmp, rz_buf_size(bf->buf) - doff, dsize) != dsize) {
		eprintf("decompression3 failure\n");
		goto fail;
	}
	rz_buf_write_at(newbuf, tsize + rosize, tmp, dsize);
	RZ_FREE(tmp);

	/* Load unpacked binary */
	const ut8 *tmpbuf = rz_buf_data(newbuf, &total_size);
	rz_io_write_at(rbin->iob.io, ba, tmpbuf, total_size);
	ut32 modoff = rz_buf_read_le32_at(newbuf, NSO_OFFSET_MODMEMOFF);
	RzBinNXOObj *bin = nso_new();
	eprintf("MOD Offset = 0x%" PFMT64x "\n", (ut64)modoff);
	parseMod(newbuf, bin, modoff, ba);
	rz_buf_free(newbuf);
	*bin_obj = bin;
	return true;
fail:
	free(tmp);
	rz_buf_free(newbuf);
	*bin_obj = NULL;
	return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	rz_return_val_if_fail(bf && buf, NULL);
	const ut64 la = bf->loadaddr;
	ut64 sz = 0;
	const ut8 *bytes = rz_buf_data(buf, &sz);
	return load_bytes(bf, bin_obj, bytes, sz, la, bf->sdb);
}

static RzBinAddr *binsym(RzBinFile *bf, int type) {
	return NULL; // TODO
}

static RzList *entries(RzBinFile *bf) {
	RzList *ret;
	RzBinAddr *ptr = NULL;
	RzBuffer *b = bf->buf;
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		ptr->paddr = rz_buf_read_le32_at(b, NSO_OFF(text_memoffset));
		ptr->vaddr = rz_buf_read_le32_at(b, NSO_OFF(text_loc)) + baddr(bf);
		rz_list_append(ret, ptr);
	}
	return ret;
}

static Sdb *get_sdb(RzBinFile *bf) {
	Sdb *kv = sdb_new0();
	sdb_num_set(kv, "nso_start.offset", 0, 0);
	sdb_num_set(kv, "nso_start.size", 16, 0);
	sdb_set(kv, "nso_start.format", "xxq unused mod_memoffset padding", 0);
	sdb_num_set(kv, "nso_header.offset", 0, 0);
	sdb_num_set(kv, "nso_header.size", 0x40, 0);
	sdb_set(kv, "nso_header.format", "xxxxxxxxxxxx magic unk size unk2 text_offset text_size ro_offset ro_size data_offset data_size bss_size unk3", 0);
	sdb_ns_set(bf->sdb, "info", kv);
	return kv;
}

static RzList *sections(RzBinFile *bf) {
	RzList *ret = NULL;
	RzBinSection *ptr = NULL;
	RzBuffer *b = bf->buf;
	if (!bf->o->info) {
		return NULL;
	}
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;

	ut64 ba = baddr(bf);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("header");
	ptr->size = rz_buf_read_le32_at(b, NSO_OFF(text_memoffset));
	ptr->vsize = rz_buf_read_le32_at(b, NSO_OFF(text_memoffset));
	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->perm = RZ_PERM_R;
	ptr->add = false;
	rz_list_append(ret, ptr);

	// add text segment
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("text");
	ptr->vsize = rz_buf_read_le32_at(b, NSO_OFF(text_size));
	ptr->size = ptr->vsize;
	ptr->paddr = rz_buf_read_le32_at(b, NSO_OFF(text_memoffset));
	ptr->vaddr = rz_buf_read_le32_at(b, NSO_OFF(text_loc)) + ba;
	ptr->perm = RZ_PERM_RX; // r-x
	ptr->add = true;
	rz_list_append(ret, ptr);

	// add ro segment
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("ro");
	ptr->vsize = rz_buf_read_le32_at(b, NSO_OFF(ro_size));
	ptr->size = ptr->vsize;
	ptr->paddr = rz_buf_read_le32_at(b, NSO_OFF(ro_memoffset));
	ptr->vaddr = rz_buf_read_le32_at(b, NSO_OFF(ro_loc)) + ba;
	ptr->perm = RZ_PERM_R; // r--
	ptr->add = true;
	rz_list_append(ret, ptr);

	// add data segment
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("data");
	ptr->vsize = rz_buf_read_le32_at(b, NSO_OFF(data_size));
	ptr->size = ptr->vsize;
	ptr->paddr = rz_buf_read_le32_at(b, NSO_OFF(data_memoffset));
	ptr->vaddr = rz_buf_read_le32_at(b, NSO_OFF(data_loc)) + ba;
	ptr->perm = RZ_PERM_RW;
	ptr->add = true;
	eprintf("BSS Size 0x%08" PFMT64x "\n", (ut64)rz_buf_read_le32_at(bf->buf, NSO_OFF(bss_size)));
	rz_list_append(ret, ptr);
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
	ret->file = strdup(bf->file);
	ret->rclass = strdup(ft);
	ret->os = strdup("switch");
	ret->arch = strdup("arm");
	ret->machine = strdup("Nintendo Switch");
	ret->subsystem = strdup(ft);
	ret->bclass = strdup("program");
	ret->type = strdup("EXEC (executable file)");
	ret->bits = 64;
	ret->has_va = true;
	ret->has_lit = true;
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
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
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
