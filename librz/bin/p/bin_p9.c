// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "../format/p9/p9bin.h"

static bool check_buffer(RzBuffer *buf) {
	return rz_bin_p9_get_arch(buf, NULL, NULL);
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	return check_buffer(b);
}

static void destroy(RzBinFile *bf) {
	rz_buf_free(bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	return 0x1000000; // XXX
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	return NULL; // TODO
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinAddr *ptr = NULL;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		ptr->paddr = 8 * 4;
		ptr->vaddr = 8 * 4; // + baddr (bf);
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;
	if (!bf->o->info) {
		return NULL;
	}

	if (!(ret = rz_pvector_new((RzPVectorFree)free))) {
		return NULL;
	}
	if (rz_buf_size(bf->buf) < 28) {
		rz_pvector_free(ret);
		return NULL;
	}
	// add text segment
	ut32 textsize;
	if (!rz_buf_read_le32_at(bf->buf, 4, &textsize)) {
		rz_pvector_free(ret);
		return NULL;
	}

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		rz_pvector_free(ret);
		return NULL;
	}
	ptr->name = rz_str_dup("text");
	ptr->size = textsize;
	ptr->vsize = textsize + (textsize % 4096);
	ptr->paddr = 8 * 4;
	ptr->vaddr = ptr->paddr;
	ptr->perm = RZ_PERM_RX; // r-x
	rz_pvector_push(ret, ptr);
	// add data segment
	ut32 datasize;
	if (!rz_buf_read_le32_at(bf->buf, 8, &datasize)) {
		rz_pvector_free(ret);
		return NULL;
	}
	if (datasize > 0) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = rz_str_dup("data");
		ptr->size = datasize;
		ptr->vsize = datasize + (datasize % 4096);
		ptr->paddr = textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = RZ_PERM_RW;
		rz_pvector_push(ret, ptr);
	}
	// ignore bss or what
	// add syms segment
	ut32 symssize;
	if (!rz_buf_read_le32_at(bf->buf, 16, &symssize)) {
		rz_pvector_free(ret);
		return NULL;
	}

	if (symssize) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = rz_str_dup("syms");
		ptr->size = symssize;
		ptr->vsize = symssize + (symssize % 4096);
		ptr->paddr = datasize + textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = RZ_PERM_R; // r--
		rz_pvector_push(ret, ptr);
	}
	// add spsz segment
	ut32 spszsize;
	if (!rz_buf_read_le32_at(bf->buf, 24, &spszsize)) {
		rz_pvector_free(ret);
		return NULL;
	}
	if (spszsize) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = rz_str_dup("spsz");
		ptr->size = spszsize;
		ptr->vsize = spszsize + (spszsize % 4096);
		ptr->paddr = symssize + datasize + textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = RZ_PERM_R; // r--
		rz_pvector_push(ret, ptr);
	}

	// add pcsz segment
	ut32 pcszsize;
	if (!rz_buf_read_le32_at(bf->buf, 24, &pcszsize)) {
		rz_pvector_free(ret);
		return NULL;
	}

	if (pcszsize) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = rz_str_dup("pcsz");
		ptr->size = pcszsize;
		ptr->vsize = pcszsize + (pcszsize % 4096);
		ptr->paddr = spszsize + symssize + datasize + textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = RZ_PERM_R; // r--
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	// TODO: parse symbol table
	return NULL;
}

static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf) {
	return NULL;
}

static RzPVector /*<char *>*/ *libs(RzBinFile *bf) {
	return NULL;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	int bits = 32, bina, big_endian = 0;

	if (!(bina = rz_bin_p9_get_arch(bf->buf, &bits, &big_endian))) {
		return NULL;
	}
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("program");
	ret->rclass = rz_str_dup("p9");
	ret->os = rz_str_dup("Plan9");
	ret->arch = rz_str_dup(rz_sys_arch_str(bina));
	ret->machine = rz_str_dup(ret->arch);
	ret->subsystem = rz_str_dup("plan9");
	ret->type = rz_str_dup("EXEC (executable file)");
	ret->bits = bits;
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

static ut64 size(RzBinFile *bf) {
	if (!bf) {
		return 0;
	}
	if (!bf->o->info) {
		bf->o->info = info(bf);
	}
	if (!bf->o->info) {
		return 0;
	}
	// TODO: reuse section list
	if (rz_buf_size(bf->buf) < 28) {
		return 0;
	}

	ut32 text;
	if (!rz_buf_read_le32_at(bf->buf, 4, &text)) {
		return 0;
	}

	ut32 data;
	if (!rz_buf_read_le32_at(bf->buf, 8, &data)) {
		return 0;
	}

	ut32 syms;
	if (!rz_buf_read_le32_at(bf->buf, 16, &syms)) {
		return 0;
	}

	ut32 spsz;
	if (!rz_buf_read_le32_at(bf->buf, 24, &spsz)) {
		return 0;
	}

	return text + data + syms + spsz + (6 * 4);
}

#if !RZ_BIN_P9

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RzBuffer *create(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt) {
	RzBuffer *buf = rz_buf_new_with_bytes(NULL, 0);
#define B(x, y) rz_buf_append_bytes(buf, (const ut8 *)(x), y)
#define D(x)    rz_buf_append_ut32(buf, x)
	D(I_MAGIC); // i386 only atm
	D(codelen);
	D(datalen);
	D(4096); // bss
	D(0); // syms
	D(8 * 4); // entry
	D(4096); // spsz
	D(4096); // pcsz
	B(code, codelen);
	if (datalen > 0) {
		B(data, datalen);
	}
	return buf;
}

RzBinPlugin rz_bin_plugin_p9 = {
	.name = "p9",
	.desc = "Plan9 bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.size = &size,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	.create = &create,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_p9,
	.version = RZ_VERSION
};
#endif
#endif
