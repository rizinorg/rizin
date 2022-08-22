// SPDX-FileCopyrightText: 2015-2019 deepakchethan <deepakchethan@outlook.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "qnx/qnx.h"
#include "../i/private.h"

static int lmf_header_load(lmf_header *lmfh, RzBuffer *buf, Sdb *db) {
	if (rz_buf_size(buf) < sizeof(lmf_header)) {
		return false;
	}
	if (rz_buf_fread_at(buf, QNX_HEADER_ADDR, (ut8 *)lmfh, "iiiiiiiicccciiiicc", 1) < QNX_HDR_SIZE) {
		return false;
	}
	sdb_set(db, "qnx.version", sdb_fmt("0x%xH", lmfh->version), 0);
	sdb_set(db, "qnx.cflags", sdb_fmt("0x%xH", lmfh->cflags), 0);
	sdb_set(db, "qnx.cpu", sdb_fmt("0x%xH", lmfh->cpu), 0);
	sdb_set(db, "qnx.fpu", sdb_fmt("0x%xH", lmfh->fpu), 0);
	sdb_set(db, "qnx.code_index", sdb_fmt("0x%x", lmfh->code_index), 0);
	sdb_set(db, "qnx.stack_index", sdb_fmt("0x%x", lmfh->stack_index), 0);
	sdb_set(db, "qnx.heap_index", sdb_fmt("0x%x", lmfh->heap_index), 0);
	sdb_set(db, "qnx.argv_index", sdb_fmt("0x%x", lmfh->argv_index), 0);
	sdb_set(db, "qnx.code_offset", sdb_fmt("0x%x", lmfh->code_offset), 0);
	sdb_set(db, "qnx.stack_nbytes", sdb_fmt("0x%x", lmfh->stack_nbytes), 0);
	sdb_set(db, "qnx.heap_nbytes", sdb_fmt("0x%x", lmfh->heap_nbytes), 0);
	sdb_set(db, "qnx.image_base", sdb_fmt("0x%x", lmfh->image_base), 0);
	return true;
}

static bool check_buffer(RzBuffer *buf) {
	ut8 tmp[6];
	int r = rz_buf_read_at(buf, 0, tmp, sizeof(tmp));
	return r == sizeof(tmp) && !memcmp(tmp, QNX_MAGIC, sizeof(tmp));
}

// Frees the bin_obj of the binary file
static void destroy(RzBinFile *bf) {
	QnxObj *qo = bf->o->bin_obj;
	rz_list_free(qo->sections);
	rz_list_free(qo->maps);
	rz_list_free(qo->fixups);
	bf->o->bin_obj = NULL;
	free(qo);
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	lmf_record lrec;
	lmf_resource lres;
	lmf_data ldata;
	ut64 offset = QNX_RECORD_SIZE;

	QnxObj *qo = RZ_NEW0(QnxObj);
	if (!qo) {
		return false;
	}

	RzList *sections = rz_list_newf((RzListFree)rz_bin_section_free);
	RzList *maps = rz_list_newf((RzListFree)rz_bin_map_free);
	RzList *fixups = rz_list_newf(free);
	if (!sections || !maps || !fixups) {
		goto beach;
	}
	qo->kv = sdb_new0();
	if (!qo->kv) {
		goto beach;
	}
	// Read the first record
	if (rz_buf_fread_at(bf->buf, 0, (ut8 *)&lrec, "ccss", 1) < QNX_RECORD_SIZE) {
		goto beach;
	}
	// Load the header
	lmf_header_load(&qo->lmfh, bf->buf, qo->kv);
	offset += lrec.data_nbytes;

	for (;;) {
		if (rz_buf_fread_at(bf->buf, offset, (ut8 *)&lrec, "ccss", 1) < QNX_RECORD_SIZE) {
			goto beach;
		}
		offset += sizeof(lmf_record);

		if (lrec.rec_type == LMF_IMAGE_END_REC) {
			break;
		} else if (lrec.rec_type == LMF_RESOURCE_REC) {
			if (rz_buf_fread_at(bf->buf, offset, (ut8 *)&lres, "ssss", 1) < sizeof(lmf_resource)) {
				goto beach;
			}
			RzBinSection *ptr = RZ_NEW0(RzBinSection);
			if (!ptr) {
				goto beach;
			}
			ptr->name = strdup("LMF_RESOURCE");
			ptr->paddr = offset;
			ptr->vsize = lrec.data_nbytes - sizeof(lmf_resource);
			ptr->size = ptr->vsize;
			rz_list_append(sections, ptr);

			RzBinMap *map = RZ_NEW0(RzBinMap);
			if (!map) {
				goto beach;
			}
			map->name = ptr->name ? strdup(ptr->name) : NULL;
			map->paddr = ptr->paddr;
			map->psize = ptr->size;
			map->vsize = ptr->vsize;
			rz_list_append(maps, map);
		} else if (lrec.rec_type == LMF_LOAD_REC) {
			RzBinSection *ptr = RZ_NEW0(RzBinSection);
			if (!ptr) {
				goto beach;
			}
			if (rz_buf_fread_at(bf->buf, offset, (ut8 *)&ldata, "si", 1) < sizeof(lmf_data)) {
				free(ptr);
				goto beach;
			}
			ptr->name = strdup("LMF_LOAD");
			ptr->paddr = offset;
			ptr->vaddr = ldata.offset;
			ptr->vsize = lrec.data_nbytes - sizeof(lmf_data);
			ptr->size = ptr->vsize;
			rz_list_append(sections, ptr);

			RzBinMap *map = RZ_NEW0(RzBinMap);
			if (!map) {
				goto beach;
			}
			map->name = ptr->name ? strdup(ptr->name) : NULL;
			map->paddr = ptr->paddr;
			map->psize = ptr->size;
			map->vsize = ptr->vsize;
			rz_list_append(maps, map);
		} else if (lrec.rec_type == LMF_FIXUP_REC) {
			RzBinReloc *ptr = RZ_NEW0(RzBinReloc);
			if (!ptr || rz_buf_fread_at(bf->buf, offset, (ut8 *)&ldata, "si", 1) < sizeof(lmf_data)) {
				free(ptr);
				goto beach;
			}
			ptr->vaddr = ptr->paddr = ldata.offset;
			ptr->type = 'f'; // "LMF_FIXUP";
			rz_list_append(fixups, ptr);
		} else if (lrec.rec_type == LMF_8087_FIXUP_REC) {
			RzBinReloc *ptr = RZ_NEW0(RzBinReloc);
			if (!ptr || rz_buf_fread_at(bf->buf, offset, (ut8 *)&ldata, "si", 1) < sizeof(lmf_data)) {
				free(ptr);
				goto beach;
			}
			ptr->vaddr = ptr->paddr = ldata.offset;
			ptr->type = 'F'; // "LMF_8087_FIXUP";
			rz_list_append(fixups, ptr);
		} else if (lrec.rec_type == LMF_RW_END_REC) {
			rz_buf_fread_at(bf->buf, offset, (ut8 *)&qo->rwend, "si", 1);
		}
		offset += lrec.data_nbytes;
	}
	sdb_ns_set(sdb, "info", qo->kv);
	qo->sections = sections;
	qo->maps = maps;
	qo->fixups = fixups;
	obj->bin_obj = qo;
	return true;
beach:
	free(qo);
	rz_list_free(fixups);
	rz_list_free(maps);
	rz_list_free(sections);
	return false;
}

/*
 * Provides the info about the binary file
 * @param RzBinFile to extract the data from
 * @return RzBinInfo file with the info
 */
static RzBinInfo *info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = bf->file ? strdup(bf->file) : NULL;
	ret->type = strdup("QNX Executable");
	ret->bclass = strdup("qnx");
	ret->machine = strdup("i386");
	ret->rclass = strdup("QNX");
	ret->arch = strdup("x86");
	ret->os = strdup("any");
	ret->subsystem = strdup("any");
	ret->lang = "C/C++";
	ret->signature = true;
	return ret;
}

static RzList *relocs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	QnxObj *qo = bf->o->bin_obj;
	RzBinReloc *reloc = NULL;
	RzListIter *it = NULL;
	RzList *relocs = rz_list_newf(free);
	if (!relocs) {
		return NULL;
	}

	rz_list_foreach (qo->fixups, it, reloc) {
		RzBinReloc *copy = RZ_NEW0(RzBinReloc);
		copy->vaddr = reloc->vaddr;
		copy->paddr = reloc->paddr;
		copy->type = reloc->type;
		rz_list_append(relocs, copy);
	}
	return relocs;
}

static void header(RzBinFile *bf) {
	rz_return_if_fail(bf && bf->o && bf->rbin);
	QnxObj *bin = bf->o->bin_obj;
	RzBin *rbin = bf->rbin;
	rbin->cb_printf("QNX file header:\n");
	rbin->cb_printf("version : 0x%xH\n", bin->lmfh.version);
	rbin->cb_printf("cflags : 0x%xH\n", bin->lmfh.cflags);
	rbin->cb_printf("cpu : 0x%xH\n", bin->lmfh.cpu);
	rbin->cb_printf("fpu : 0x%xH\n", bin->lmfh.fpu);
	rbin->cb_printf("code_index : 0x%xH\n", bin->lmfh.code_index);
	rbin->cb_printf("stack_index : 0x%xH\n", bin->lmfh.stack_index);
	rbin->cb_printf("heap_index : 0x%xH\n", bin->lmfh.heap_index);
	rbin->cb_printf("argv_index : 0x%xH\n", bin->lmfh.argv_index);
	rbin->cb_printf("spare2[4] : 0x0H\n");
	rbin->cb_printf("code_offset : 0x%xH\n", bin->lmfh.code_offset);
	rbin->cb_printf("stack_nbytes : 0x%xH\n", bin->lmfh.stack_nbytes);
	rbin->cb_printf("heap_nbytes : 0x%xH\n", bin->lmfh.heap_nbytes);
	rbin->cb_printf("image_base : 0x%xH\n", bin->lmfh.image_base);
	rbin->cb_printf("spare3[2] : 0x0H\n");
}

/*
 * No mention of symbols in the doc
 */
static RzList *symbols(RzBinFile *bf) {
	return NULL;
}

static RzList *maps(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	QnxObj *qo = bf->o->bin_obj;
	return rz_list_clone(qo->maps);
}

// Returns the sections
static RzList *sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	QnxObj *qo = bf->o->bin_obj;
	return rz_list_clone(qo->sections);
}

/*
 * Returns the sdb
 * @param RzBinFile
 * @return sdb of the bin_obj
 */
static Sdb *get_sdb(RzBinFile *bf) {
	RzBinObject *o = bf->o;
	if (!o) {
		return NULL;
	}
	QnxObj *qo = o->bin_obj;
	return qo ? qo->kv : NULL;
}

/*
 * Returns the base address of the image from the binary header
 * @param RzBinFile
 * @return image_base address
 */
static ut64 baddr(RzBinFile *bf) {
	QnxObj *qo = bf->o->bin_obj;
	return qo ? qo->lmfh.image_base : 0;
}

/*
 * Currently both physical and virtual address are set to 0
 * The memory map has different values for entry
 */
static RzList *entries(RzBinFile *bf) {
	RzList *ret;
	RzBinAddr *ptr = NULL;
	QnxObj *qo = bf->o->bin_obj;
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	ptr->paddr = qo->lmfh.code_offset;
	ptr->vaddr = qo->lmfh.code_offset + baddr(bf);
	rz_list_append(ret, ptr);
	return ret;
}

/*
 * @param RzBinFile
 * @return signature of the binary
 */
static char *signature(RzBinFile *bf, bool json) {
	char buf[64];
	QnxObj *qo = bf->o->bin_obj;
	if (!qo) {
		return NULL;
	}
	if (json) {
		PJ *pj = pj_new();
		pj_n(pj, qo->rwend.signature);
		return pj_drain(pj);
	} else {
		return rz_str_dup(NULL, sdb_itoa(qo->rwend.signature, buf, 10));
	}
}

/*
 * @return: returns the vaddr
 */
static ut64 get_vaddr(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return vaddr;
}

// Declaration of the plugin
RzBinPlugin rz_bin_plugin_qnx = {
	.name = "qnx",
	.desc = "QNX executable file support",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.relocs = &relocs,
	.baddr = &baddr,
	.author = "deepakchethan",
	.check_buffer = &check_buffer,
	.header = &header,
	.get_sdb = &get_sdb,
	.entries = &entries,
	.maps = &maps,
	.sections = &sections,
	.symbols = &symbols,
	.signature = &signature,
	.get_vaddr = &get_vaddr,
	.info = &info
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_qnx,
	.version = RZ_VERSION
};
#endif
