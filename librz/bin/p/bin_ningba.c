/* radare - LGPL - 2014-2019 - condret@runas-racer.com */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>
#include "../format/nin/gba.h"

static bool check_buffer(RBuffer *b) {
	ut8 lict[156];
	rz_return_val_if_fail (b, false);
	rz_buf_read_at (b, 4, (ut8*)lict, sizeof (lict));
	return !memcmp (lict, lic_gba, 156);
}

static bool load_buffer(RBinFile * bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer (buf);
}

static RzList *entries(RBinFile *bf) {
	RzList *ret = rz_list_newf (free);
	RBinAddr *ptr = NULL;

	if (bf && bf->buf) {
		if (!ret) {
			return NULL;
		}
		if (!(ptr = R_NEW0 (RBinAddr))) {
			return ret;
		}
		ptr->paddr = ptr->vaddr = 0x8000000;
		rz_list_append (ret, ptr);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	ut8 rom_info[16];
	RBinInfo *ret = R_NEW0 (RBinInfo);

	if (!ret) {
		return NULL;
	}

	if (!bf || !bf->buf) {
		free (ret);
		return NULL;
	}

	ret->lang = NULL;
	rz_buf_read_at (bf->buf, 0xa0, rom_info, 16);
	ret->file = rz_str_ndup ((const char *) rom_info, 12);
	ret->type = rz_str_ndup ((char *) &rom_info[12], 4);
	ret->machine = strdup ("GameBoy Advance");
	ret->os = strdup ("any");
	ret->arch = strdup ("arm");
	ret->has_va = 1;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static RzList *sections(RBinFile *bf) {
	RzList *ret = NULL;
	RBinSection *s = R_NEW0 (RBinSection);
	ut64 sz = rz_buf_size (bf->buf);
	if (!(ret = rz_list_new ())) {
		free (s);
		return NULL;
	}
	s->name = strdup ("ROM");
	s->paddr = 0;
	s->vaddr = 0x8000000;
	s->size = sz;
	s->vsize = 0x2000000;
	s->perm = R_PERM_RX;
	s->add = true;

	rz_list_append (ret, s);
	return ret;
}

RBinPlugin rz_bin_plugin_ningba = {
	.name = "ningba",
	.desc = "Game Boy Advance format rz_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.info = &info,
	.sections = &sections,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_ningba,
	.version = RZ_VERSION
};
#endif
