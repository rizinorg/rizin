/* radare - LGPL - 2015-2019 - maijin */

#include <rz_bin.h>
#include <rz_lib.h>
#include "../format/spc700/spc_specs.h"

static bool check_buffer(RBuffer *b) {
	ut8 buf[27];
	if (rz_buf_read_at (b, 0, buf, sizeof (buf)) == 27) {
		return !memcmp (buf, SPC_MAGIC, 27);
	}
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb){
	return check_buffer (b);
}

static RBinInfo* info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	spc_hdr spchdr;
	memset (&spchdr, 0, SPC_HDR_SIZE);
	int reat = rz_buf_read_at (bf->buf, 0, (ut8*)&spchdr, SPC_HDR_SIZE);
	if (reat != SPC_HDR_SIZE) {
		eprintf ("Truncated Header\n");
		return NULL;
	}
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("Sound File Data");
	ret->machine = strdup ("SPC700");
	ret->os = strdup ("spc700");
	ret->arch = strdup ("spc700");
	ret->bits = 16;
	ret->has_va = 1;
	return ret;
}

static RzList* sections(RBinFile *bf) {
	RzList *ret = NULL;
	RBinSection *ptr = NULL;
	spc_hdr spchdr;
	memset (&spchdr, 0, SPC_HDR_SIZE);
	int reat = rz_buf_read_at (bf->buf, 0, (ut8*)&spchdr, SPC_HDR_SIZE);
	if (reat != SPC_HDR_SIZE) {
		eprintf ("Truncated Header\n");
		return NULL;
	}
	if (!(ret = rz_list_new ())) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinSection))) {
		rz_list_free (ret);
		return NULL;
	}
	ptr->name = strdup ("RAM");
	ptr->paddr = RAM_START_ADDRESS;
	ptr->size = RAM_SIZE;
	ptr->vaddr = 0x0;
	ptr->vsize = RAM_SIZE;
	ptr->perm = R_PERM_R;
	ptr->add = true;
	rz_list_append (ret, ptr);
	return ret;
}

static RzList* entries(RBinFile *bf) {
	RzList *ret = rz_list_newf (free);
	if (ret) {
		RBinAddr *ptr = R_NEW0 (RBinAddr);
		if (ptr) {
			ptr->paddr = RAM_START_ADDRESS;
			ptr->vaddr = 0;
			rz_list_append (ret, ptr);
		}
	}
	return ret;
}

RBinPlugin rz_bin_plugin_spc700 = {
	.name = "spc700",
	.desc = "SNES-SPC700 Sound File Data",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_spc700,
	.version = R2_VERSION
};
#endif
