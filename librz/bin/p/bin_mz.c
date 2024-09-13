// SPDX-FileCopyrightText: 2015-2019 nodepad <nod3pad@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_bin.h>
#include <rz_lib.h>
#include "mz/mz.h"

/* half-magic */
#define HM(x) (int)((int)(x[0] << 8) | (int)(x[1]))

static Sdb *get_sdb(RzBinFile *bf) {
	const struct rz_bin_mz_obj_t *bin;
	if (bf && bf->o && bf->o->bin_obj) {
		bin = (struct rz_bin_mz_obj_t *)bf->o->bin_obj;
		if (bin && bin->kv) {
			return bin->kv;
		}
	}
	return NULL;
}

static bool knownHeaderBuffer(RzBuffer *b, ut16 offset) {
	ut8 h[2];
	if (rz_buf_read_at(b, offset, h, sizeof(h)) != sizeof(h)) {
		return false;
	}
	if (!memcmp(h, "PE", 2)) {
		if (offset + 0x20 < rz_buf_size(b)) {
			if (rz_buf_read_at(b, offset + 0x18, h, sizeof(h)) != 2) {
				return false;
			}
			if (!memcmp(h, "\x0b\x01", 2)) {
				return true;
			}
		}
	} else {
		if (!memcmp(h, "NE", 2) || !memcmp(h, "LE", 2) || !memcmp(h, "LX", 2) || !memcmp(h, "PL", 2)) {
			return true;
		}
	}
	return false;
}

static bool checkEntrypointBuffer(RzBuffer *b) {
	ut16 cs;
	if (!rz_buf_read_le16_at(b, 0x16, &cs)) {
		return false;
	}

	ut16 ip;
	if (!rz_buf_read_le16_at(b, 0x14, &ip)) {
		return false;
	}

	ut16 tmp;
	if (!rz_buf_read_le16_at(b, 0x08, &tmp)) {
		return false;
	}

	ut32 pa = ((tmp + cs) << 4) + ip;

	/* A minimal MZ header is 0x1B bytes.  Header length is measured in
	 * 16-byte paragraphs so the minimum header must occupy 2 paragraphs.
	 * This means that the entrypoint should be at least 0x20 unless someone
	 * cleverly fit a few instructions inside the header.
	 */
	pa &= 0xffff;
	ut64 length = rz_buf_size(b);
	if (pa >= 0x20 && pa + 1 < length) {
		ut16 pe;
		if (!rz_buf_read_le16_at(b, 0x3c, &pe)) {
			return false;
		}

		if (pe + 2 < length && length > 0x104) {
			ut8 h[2];
			if (rz_buf_read_at(b, pe, h, 2) == 2) {
				if (!memcmp(h, "PE", 2)) {
					return false;
				}
			}
		}
		return true;
	}
	return false;
}

static bool check_buffer(RzBuffer *b) {
	rz_return_val_if_fail(b, false);
	ut64 b_size = rz_buf_size(b);
	if (b_size <= 0x3d) {
		return false;
	}

	// Check for MZ magic.
	ut8 h[2];
	if (rz_buf_read_at(b, 0, h, 2) != 2) {
		return false;
	}
	if (memcmp(h, "MZ", 2)) {
		return false;
	}

	// See if there is a new exe header.
	ut16 new_exe_header_offset;
	if (!rz_buf_read_le16_at(b, 0x3c, &new_exe_header_offset)) {
		return false;
	}

	if (b_size > new_exe_header_offset + 2) {
		if (knownHeaderBuffer(b, new_exe_header_offset)) {
			return false;
		}
	}

	// Raw plain MZ executable (watcom)
	if (!checkEntrypointBuffer(b)) {
		return false;
	}
	return true;
}

static bool load(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	struct rz_bin_mz_obj_t *mz_obj = rz_bin_mz_new_buf(buf);
	if (mz_obj) {
		sdb_ns_set(sdb, "info", mz_obj->kv);
		obj->bin_obj = mz_obj;
		return true;
	}
	return false;
}

static void destroy(RzBinFile *bf) {
	rz_bin_mz_free((struct rz_bin_mz_obj_t *)bf->o->bin_obj);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	RzBinAddr *mzaddr = NULL;
	if (bf && bf->o && bf->o->bin_obj) {
		switch (type) {
		case RZ_BIN_SPECIAL_SYMBOL_MAIN:
			mzaddr = rz_bin_mz_get_main_vaddr(bf->o->bin_obj);
			break;
		default:
			break;
		}
	}
	return mzaddr;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzBinAddr *ptr = NULL;
	RzPVector *res = NULL;
	if (!(res = rz_pvector_new(free))) {
		return NULL;
	}
	ptr = rz_bin_mz_get_entrypoint(bf->o->bin_obj);
	if (ptr) {
		rz_pvector_push(res, ptr);
	}
	return res;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	return rz_bin_mz_get_segments(bf->o->bin_obj);
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *const ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("MZ");
	ret->rclass = rz_str_dup("mz");
	ret->os = rz_str_dup("DOS");
	ret->arch = rz_str_dup("x86");
	ret->machine = rz_str_dup("i386");
	ret->type = rz_str_dup("EXEC (Executable file)");
	ret->subsystem = rz_str_dup("DOS");
	ret->bits = 16;
	ret->dbg_info = 0;
	ret->big_endian = false;
	ret->has_crypto = false;
	ret->has_canary = false;
	ret->has_retguard = -1;
	ret->has_nx = false;
	ret->has_pi = false;
	ret->has_va = true;
	return ret;
}

static void header(RzBinFile *bf) {
	const struct rz_bin_mz_obj_t *mz = (struct rz_bin_mz_obj_t *)bf->o->bin_obj;
	eprintf("[0000:0000]  Signature           %c%c\n",
		mz->dos_header->signature & 0xFF,
		mz->dos_header->signature >> 8);
	eprintf("[0000:0002]  BytesInLastBlock    0x%04x\n",
		mz->dos_header->bytes_in_last_block);
	eprintf("[0000:0004]  BlocksInFile        0x%04x\n",
		mz->dos_header->blocks_in_file);
	eprintf("[0000:0006]  NumRelocs           0x%04x\n",
		mz->dos_header->num_relocs);
	eprintf("[0000:0008]  HeaderParagraphs    0x%04x\n",
		mz->dos_header->header_paragraphs);
	eprintf("[0000:000a]  MinExtraParagraphs  0x%04x\n",
		mz->dos_header->min_extra_paragraphs);
	eprintf("[0000:000c]  MaxExtraParagraphs  0x%04x\n",
		mz->dos_header->max_extra_paragraphs);
	eprintf("[0000:000e]  InitialSs           0x%04x\n",
		mz->dos_header->ss);
	eprintf("[0000:0010]  InitialSp           0x%04x\n",
		mz->dos_header->sp);
	eprintf("[0000:0012]  Checksum            0x%04x\n",
		mz->dos_header->checksum);
	eprintf("[0000:0014]  InitialIp           0x%04x\n",
		mz->dos_header->ip);
	eprintf("[0000:0016]  InitialCs           0x%04x\n",
		mz->dos_header->cs);
	eprintf("[0000:0018]  RelocTableOffset    0x%04x\n",
		mz->dos_header->reloc_table_offset);
	eprintf("[0000:001a]  OverlayNumber       0x%04x\n",
		mz->dos_header->overlay_number);
}

static RzPVector /*<RzBinReloc *>*/ *relocs(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinReloc *rel = NULL;
	const struct rz_bin_mz_reloc_t *relocs = NULL;
	int i;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_reloc_free))) {
		return NULL;
	}
	if (!(relocs = rz_bin_mz_get_relocs(bf->o->bin_obj))) {
		return ret;
	}
	for (i = 0; !relocs[i].last; i++) {
		if (!(rel = RZ_NEW0(RzBinReloc))) {
			free((void *)relocs);
			rz_pvector_free(ret);
			return NULL;
		}
		rel->type = RZ_BIN_RELOC_16;
		rel->vaddr = relocs[i].vaddr;
		rel->paddr = relocs[i].paddr;
		rz_pvector_push(ret, rel);
	}
	free((void *)relocs);
	return ret;
}

RzBinPlugin rz_bin_plugin_mz = {
	.name = "mz",
	.desc = "MZ bin plugin",
	.license = "MIT",
	.get_sdb = &get_sdb,
	.load_buffer = &load,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.binsym = &binsym,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.info = &info,
	.header = &header,
	.relocs = &relocs,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_mz,
	.version = RZ_VERSION
};
#endif
