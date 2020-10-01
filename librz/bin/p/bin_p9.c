/* rizin - LGPL - Copyright 2009-2019 - nibble, pancake */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "../format/p9/p9bin.h"

static bool check_buffer(RBuffer *buf) {
	return rz_bin_p9_get_arch (buf, NULL, NULL);
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb){
	return check_buffer (b);
}

static void destroy(RBinFile *bf) {
	rz_buf_free (bf->o->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	return 0x1000000; // XXX
}

static RBinAddr *binsym(RBinFile *bf, int type) {
	return NULL; // TODO
}

static RzList *entries(RBinFile *bf) {
	RzList *ret;
	RBinAddr *ptr = NULL;

	if (!(ret = rz_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = 8 * 4;
		ptr->vaddr = 8 * 4;// + baddr (bf);
		rz_list_append (ret, ptr);
	}
	return ret;
}

static RzList *sections(RBinFile *bf) {
	RzList *ret = NULL;
	RBinSection *ptr = NULL;
	ut64 textsize, datasize, symssize, spszsize, pcszsize;
	if (!bf->o->info) {
		return NULL;
	}

	if (!(ret = rz_list_newf ((RzListFree)free))) {
		return NULL;
	}
	if (rz_buf_size (bf->buf) < 28) {
		rz_list_free (ret);
		return NULL;
	}
	// add text segment
	textsize = rz_buf_read_le32_at (bf->buf, 4);
	if (!(ptr = R_NEW0 (RBinSection))) {
		rz_list_free (ret);
		return NULL;
	}
	ptr->name = strdup ("text");
	ptr->size = textsize;
	ptr->vsize = textsize + (textsize % 4096);
	ptr->paddr = 8 * 4;
	ptr->vaddr = ptr->paddr;
	ptr->perm = R_PERM_RX; // r-x
	ptr->add = true;
	rz_list_append (ret, ptr);
	// add data segment
	datasize = rz_buf_read_le32_at (bf->buf, 8);
	if (datasize > 0) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ptr->name = strdup ("data");
		ptr->size = datasize;
		ptr->vsize = datasize + (datasize % 4096);
		ptr->paddr = textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = R_PERM_RW;
		ptr->add = true;
		rz_list_append (ret, ptr);
	}
	// ignore bss or what
	// add syms segment
	symssize = rz_buf_read_le32_at (bf->buf, 16);
	if (symssize) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ptr->name = strdup ("syms");
		ptr->size = symssize;
		ptr->vsize = symssize + (symssize % 4096);
		ptr->paddr = datasize + textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = R_PERM_R; // r--
		ptr->add = true;
		rz_list_append (ret, ptr);
	}
	// add spsz segment
	spszsize = rz_buf_read_le32_at (bf->buf, 24);
	if (spszsize) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ptr->name = strdup ("spsz");
		ptr->size = spszsize;
		ptr->vsize = spszsize + (spszsize % 4096);
		ptr->paddr = symssize + datasize + textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = R_PERM_R; // r--
		ptr->add = true;
		rz_list_append (ret, ptr);
	}
	// add pcsz segment
	pcszsize = rz_buf_read_le32_at (bf->buf, 24);
	if (pcszsize) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ptr->name = strdup ("pcsz");
		ptr->size = pcszsize;
		ptr->vsize = pcszsize + (pcszsize % 4096);
		ptr->paddr = spszsize + symssize + datasize + textsize + (8 * 4);
		ptr->vaddr = ptr->paddr;
		ptr->perm = R_PERM_R; // r--
		ptr->add = true;
		rz_list_append (ret, ptr);
	}
	return ret;
}

static RzList *symbols(RBinFile *bf) {
	// TODO: parse symbol table
	return NULL;
}

static RzList *imports(RBinFile *bf) {
	return NULL;
}

static RzList *libs(RBinFile *bf) {
	return NULL;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	int bits = 32, bina, big_endian = 0;

	if (!(bina = rz_bin_p9_get_arch (bf->buf, &bits, &big_endian))) {
		return NULL;
	}
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("program");
	ret->rclass = strdup ("p9");
	ret->os = strdup ("Plan9");
	ret->arch = strdup (rz_sys_arch_str (bina));
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("plan9");
	ret->type = strdup ("EXEC (executable file)");
	ret->bits = bits;
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

static ut64 size(RBinFile *bf) {
	ut64 text, data, syms, spsz;
	if (!bf) {
		return 0;
	}
	if (!bf->o->info) {
		bf->o->info = info (bf);
	}
	if (!bf->o->info) {
		return 0;
	}
	// TODO: reuse section list
	if (rz_buf_size (bf->buf) < 28) {
		return 0;
	}
	text = rz_buf_read_le32_at (bf->buf, 4);
	data = rz_buf_read_le32_at (bf->buf, 8);
	syms = rz_buf_read_le32_at (bf->buf, 16);
	spsz = rz_buf_read_le32_at (bf->buf, 24);
	return text + data + syms + spsz + (6 * 4);
}

#if !R_BIN_P9

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer *create(RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt) {
	RBuffer *buf = rz_buf_new ();
#define B(x, y) rz_buf_append_bytes (buf, (const ut8 *) (x), y)
#define D(x) rz_buf_append_ut32 (buf, x)
	D (I_MAGIC); // i386 only atm
	D (codelen);
	D (datalen);
	D (4096); // bss
	D (0); // syms
	D (8 * 4); // entry
	D (4096); // spsz
	D (4096); // pcsz
	B (code, codelen);
	if (datalen > 0) {
		B (data, datalen);
	}
	return buf;
}

RBinPlugin rz_bin_plugin_p9 = {
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

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_p9,
	.version = R2_VERSION
};
#endif
#endif
