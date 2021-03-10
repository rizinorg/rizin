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

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *b, ut64 loadaddr, Sdb *sdb) {
	return check_buffer(b);
}

static void destroy(RzBinFile *bf) {
	rz_buf_free(bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	return 0x1000000; // XXX
}

static RzBinAddr *binsym(RzBinFile *bf, int type) {
	return NULL; // TODO
}

static RzList *entries(RzBinFile *bf) {
	RzList *ret;
	RzBinAddr *ptr = NULL;

	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		ptr->paddr = 8 * 4;
		ptr->vaddr = 8 * 4; // + baddr (bf);
		rz_list_append(ret, ptr);
	}
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	RzList *ret = NULL;
	RzBinSection *ptr = NULL;
	ut64 textsize, datasize, symssize, spszsize, pcszsize;
	if (!bf->o->info) {
		return NULL;
	}

	if (!(ret = rz_list_newf((RzListFree)free))) {
		return NULL;
	}
	if (rz_buf_size(bf->buf) < 28) {
		rz_list_free(ret);
		return NULL;
	}
	// add text segment
	textsize = rz_buf_read_le32_at(bf->buf, 4);
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		rz_list_free(ret);
		return NULL;
	}
	ptr->name = strdup("text");
	ptr->size = textsize;
	ptr->vsize = textsize + (textsize % 4096);
	ptr->paddr = 8 * 4;
	ptr->vaddr = ptr->paddr;
	ptr->perm = RZ_PERM_RX; // r-x
	ptr->add = true;
	rz_list_append(ret, ptr);
	// add data segment
	datasize = rz_buf_read_le32_at(bf->buf, 8);
	if (datasize > 0) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = strdup("data");
		ptr->size = datasize;
		ptr->vsize = datasize + (datasize % 4096);
		ptr->paddr = textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = RZ_PERM_RW;
		ptr->add = true;
		rz_list_append(ret, ptr);
	}
	// ignore bss or what
	// add syms segment
	symssize = rz_buf_read_le32_at(bf->buf, 16);
	if (symssize) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = strdup("syms");
		ptr->size = symssize;
		ptr->vsize = symssize + (symssize % 4096);
		ptr->paddr = datasize + textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = RZ_PERM_R; // r--
		ptr->add = true;
		rz_list_append(ret, ptr);
	}
	// add spsz segment
	spszsize = rz_buf_read_le32_at(bf->buf, 24);
	if (spszsize) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = strdup("spsz");
		ptr->size = spszsize;
		ptr->vsize = spszsize + (spszsize % 4096);
		ptr->paddr = symssize + datasize + textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = RZ_PERM_R; // r--
		ptr->add = true;
		rz_list_append(ret, ptr);
	}
	// add pcsz segment
	pcszsize = rz_buf_read_le32_at(bf->buf, 24);
	if (pcszsize) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = strdup("pcsz");
		ptr->size = pcszsize;
		ptr->vsize = pcszsize + (pcszsize % 4096);
		ptr->paddr = spszsize + symssize + datasize + textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = RZ_PERM_R; // r--
		ptr->add = true;
		rz_list_append(ret, ptr);
	}
	return ret;
}

static RzList *symbols(RzBinFile *bf) {
	// TODO: parse symbol table
	return NULL;
}

static RzList *imports(RzBinFile *bf) {
	return NULL;
}

static RzList *libs(RzBinFile *bf) {
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
	ret->file = strdup(bf->file);
	ret->bclass = strdup("program");
	ret->rclass = strdup("p9");
	ret->os = strdup("Plan9");
	ret->arch = strdup(rz_sys_arch_str(bina));
	ret->machine = strdup(ret->arch);
	ret->subsystem = strdup("plan9");
	ret->type = strdup("EXEC (executable file)");
	ret->bits = bits;
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

static ut64 size(RzBinFile *bf) {
	ut64 text, data, syms, spsz;
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
	text = rz_buf_read_le32_at(bf->buf, 4);
	data = rz_buf_read_le32_at(bf->buf, 8);
	syms = rz_buf_read_le32_at(bf->buf, 16);
	spsz = rz_buf_read_le32_at(bf->buf, 24);
	return text + data + syms + spsz + (6 * 4);
}

#if !RZ_BIN_P9

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RzBuffer *create(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt) {
	RzBuffer *buf = rz_buf_new();
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
