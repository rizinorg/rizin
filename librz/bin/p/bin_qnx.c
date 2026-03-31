// SPDX-FileCopyrightText: 2015-2019 deepakchethan <deepakchethan@outlook.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "qnx/qnx.h"
#include "../i/private.h"

static bool read_lmf_header(lmf_header *lmfh, RzBuffer *buf, ut64 off) {
	ut64 offset = off;
	return (rz_buf_read_le16_offset(buf, &offset, &lmfh->version) &&
		rz_buf_read_le16_offset(buf, &offset, &lmfh->cflags) &&
		rz_buf_read_le16_offset(buf, &offset, &lmfh->cpu) &&
		rz_buf_read_le16_offset(buf, &offset, &lmfh->fpu) &&
		rz_buf_read_le16_offset(buf, &offset, &lmfh->code_index) &&
		rz_buf_read_le16_offset(buf, &offset, &lmfh->stack_index) &&
		rz_buf_read_le16_offset(buf, &offset, &lmfh->heap_index) &&
		rz_buf_read_le16_offset(buf, &offset, &lmfh->argv_index) &&
		rz_buf_read_le16_offset(buf, &offset, &lmfh->spare2[0]) &&
		rz_buf_read_le16_offset(buf, &offset, &lmfh->spare2[1]) &&
		rz_buf_read_le16_offset(buf, &offset, &lmfh->spare2[2]) &&
		rz_buf_read_le16_offset(buf, &offset, &lmfh->spare2[3]) &&
		rz_buf_read_le32_offset(buf, &offset, &lmfh->code_offset) &&
		rz_buf_read_le32_offset(buf, &offset, &lmfh->stack_nbytes) &&
		rz_buf_read_le32_offset(buf, &offset, &lmfh->heap_nbytes) &&
		rz_buf_read_le32_offset(buf, &offset, &lmfh->image_base) &&
		rz_buf_read_le32_offset(buf, &offset, &lmfh->spare3[0]) &&
		rz_buf_read_le32_offset(buf, &offset, &lmfh->spare3[1]));
}

static bool lmf_header_load(lmf_header *lmfh, RzBuffer *buf, Sdb *db) {
	if (rz_buf_size(buf) < sizeof(lmf_header)) {
		return false;
	}
	if (!read_lmf_header(lmfh, buf, QNX_HEADER_ADDR)) {
		return false;
	}
	char tmpbuf[32];
	sdb_set(db, "qnx.version", rz_strf(tmpbuf, "0x%xH", lmfh->version));
	sdb_set(db, "qnx.cflags", rz_strf(tmpbuf, "0x%xH", lmfh->cflags));
	sdb_set(db, "qnx.cpu", rz_strf(tmpbuf, "0x%xH", lmfh->cpu));
	sdb_set(db, "qnx.fpu", rz_strf(tmpbuf, "0x%xH", lmfh->fpu));
	sdb_set(db, "qnx.code_index", rz_strf(tmpbuf, "0x%x", lmfh->code_index));
	sdb_set(db, "qnx.stack_index", rz_strf(tmpbuf, "0x%x", lmfh->stack_index));
	sdb_set(db, "qnx.heap_index", rz_strf(tmpbuf, "0x%x", lmfh->heap_index));
	sdb_set(db, "qnx.argv_index", rz_strf(tmpbuf, "0x%x", lmfh->argv_index));
	sdb_set(db, "qnx.code_offset", rz_strf(tmpbuf, "0x%x", lmfh->code_offset));
	sdb_set(db, "qnx.stack_nbytes", rz_strf(tmpbuf, "0x%x", lmfh->stack_nbytes));
	sdb_set(db, "qnx.heap_nbytes", rz_strf(tmpbuf, "0x%x", lmfh->heap_nbytes));
	sdb_set(db, "qnx.image_base", rz_strf(tmpbuf, "0x%x", lmfh->image_base));
	return true;
}

static bool qnx_check_buffer(RzBuffer *buf) {
	ut8 tmp[6];
	int r = rz_buf_read_at(buf, 0, tmp, sizeof(tmp));
	return r == sizeof(tmp) && !memcmp(tmp, QNX_MAGIC, sizeof(tmp));
}

static void qnx_destroy(RzBinFile *bf) {
	QnxObj *qo = bf->o->bin_obj;
	rz_pvector_free(qo->sections);
	rz_pvector_free(qo->maps);
	rz_list_free(qo->fixups);
	bf->o->bin_obj = NULL;
	free(qo);
}

static bool qnx_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	lmf_record lrec;
	lmf_resource lres;
	lmf_data ldata;
	ut64 offset = QNX_RECORD_SIZE;

	QnxObj *qo = RZ_NEW0(QnxObj);
	if (!qo) {
		return false;
	}

	RzPVector *sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	RzPVector *maps = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	RzList *fixups = rz_list_newf(free);
	if (!sections || !maps || !fixups) {
		goto beach;
	}
	qo->kv = sdb_new0();
	if (!qo->kv) {
		goto beach;
	}
	// Read the first lmf_record
	ut64 off = 0;
	if (!(rz_buf_read8_offset(buf, &off, &lrec.rec_type) &&
		    rz_buf_read8_offset(buf, &off, &lrec.reserved) &&
		    rz_buf_read_le16_offset(buf, &off, &lrec.data_nbytes) &&
		    rz_buf_read_le16_offset(buf, &off, &lrec.spare))) {
		goto beach;
	}
	// Load the header
	if (!lmf_header_load(&qo->lmfh, bf->buf, qo->kv)) {
		goto beach;
	}
	offset += lrec.data_nbytes;

	for (;;) {
		if (!(rz_buf_read8_offset(buf, &offset, &lrec.rec_type) &&
			    rz_buf_read8_offset(buf, &offset, &lrec.reserved) &&
			    rz_buf_read_le16_offset(buf, &offset, &lrec.data_nbytes) &&
			    rz_buf_read_le16_offset(buf, &offset, &lrec.spare))) {
			goto beach;
		}

		if (lrec.rec_type == LMF_IMAGE_END_REC) {
			break;
		} else if (lrec.rec_type == LMF_RESOURCE_REC) {
			if (lrec.data_nbytes <= LMF_RESOURCE_SIZE) {
				goto beach;
			}
			off = offset;
			if (!(rz_buf_read_le16_offset(buf, &off, &lres.res_type) &&
				    rz_buf_read_le16_offset(buf, &off, &lres.spare[0]) &&
				    rz_buf_read_le16_offset(buf, &off, &lres.spare[1]) &&
				    rz_buf_read_le16_offset(buf, &off, &lres.spare[2]))) {
				goto beach;
			}
			RzBinSection *ptr = RZ_NEW0(RzBinSection);
			if (!ptr) {
				goto beach;
			}
			ptr->name = rz_str_dup("LMF_RESOURCE");
			ptr->paddr = offset;
			ptr->vsize = lrec.data_nbytes - LMF_RESOURCE_SIZE;
			ptr->size = ptr->vsize;
			rz_pvector_push(sections, ptr);

			RzBinMap *map = RZ_NEW0(RzBinMap);
			if (!map) {
				goto beach;
			}
			map->name = rz_str_dup(ptr->name);
			map->paddr = ptr->paddr;
			map->psize = ptr->size;
			map->vsize = ptr->vsize;
			rz_pvector_push(maps, map);
		} else if (lrec.rec_type == LMF_LOAD_REC) {
			if (lrec.data_nbytes <= LMF_DATA_SIZE) {
				goto beach;
			}
			RzBinSection *ptr = RZ_NEW0(RzBinSection);
			if (!ptr) {
				goto beach;
			}
			off = offset;
			if (!(rz_buf_read_le16_offset(buf, &off, &ldata.segment) &&
				    rz_buf_read_le32_offset(buf, &off, &ldata.offset))) {
				free(ptr);
				goto beach;
			}
			ptr->name = rz_str_dup("LMF_LOAD");
			ptr->paddr = offset;
			ptr->vaddr = ldata.offset;
			ptr->vsize = lrec.data_nbytes - LMF_DATA_SIZE;
			ptr->size = ptr->vsize;
			rz_pvector_push(sections, ptr);

			RzBinMap *map = RZ_NEW0(RzBinMap);
			if (!map) {
				goto beach;
			}
			map->name = rz_str_dup(ptr->name);
			map->paddr = ptr->paddr;
			map->psize = ptr->size;
			map->vsize = ptr->vsize;
			rz_pvector_push(maps, map);
		} else if (lrec.rec_type == LMF_FIXUP_REC) {
			RzBinReloc *ptr = RZ_NEW0(RzBinReloc);
			if (!ptr) {
				goto beach;
			}
			off = offset;
			if (!(rz_buf_read_le16_offset(buf, &off, &ldata.segment) &&
				    rz_buf_read_le32_offset(buf, &off, &ldata.offset))) {
				free(ptr);
				goto beach;
			}
			ptr->vaddr = ptr->paddr = ldata.offset;
			ptr->type = 'f'; // "LMF_FIXUP";
			rz_list_append(fixups, ptr);
		} else if (lrec.rec_type == LMF_8087_FIXUP_REC) {
			RzBinReloc *ptr = RZ_NEW0(RzBinReloc);
			if (!ptr) {
				goto beach;
			}
			off = offset;
			if (!(rz_buf_read_le16_offset(buf, &off, &ldata.segment) &&
				    rz_buf_read_le32_offset(buf, &off, &ldata.offset))) {
				free(ptr);
				goto beach;
			}
			ptr->vaddr = ptr->paddr = ldata.offset;
			ptr->type = 'F'; // "LMF_8087_FIXUP";
			rz_list_append(fixups, ptr);
		} else if (lrec.rec_type == LMF_RW_END_REC) {
			off = offset;
			if (!(rz_buf_read_le16_offset(buf, &off, &qo->rwend.verify) &&
				    rz_buf_read_le32_offset(buf, &off, &qo->rwend.signature))) {
				goto beach;
			}
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
	rz_pvector_free(maps);
	rz_pvector_free(sections);
	return false;
}

/*
 * Provides the info about the binary file
 * \param RzBinFile to extract the data from
 * \return RzBinInfo file with the info
 */
static RzBinInfo *qnx_info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("QNX Executable");
	ret->bclass = rz_str_dup("qnx");
	ret->machine = rz_str_dup("i386");
	ret->rclass = rz_str_dup("QNX");
	ret->arch = rz_str_dup("x86");
	ret->os = rz_str_dup("any");
	ret->subsystem = rz_str_dup("any");
	ret->lang = "C/C++";
	ret->bits = 32;
	ret->signature = true;
	return ret;
}

static RzPVector /*<RzBinReloc *>*/ *qnx_relocs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	QnxObj *qo = bf->o->bin_obj;
	RzBinReloc *reloc = NULL;
	RzListIter *it = NULL;
	RzPVector *relocs = rz_pvector_new((RzPVectorFree)rz_bin_reloc_free);
	if (!relocs) {
		return NULL;
	}

	rz_list_foreach (qo->fixups, it, reloc) {
		RzBinReloc *copy = RZ_NEW0(RzBinReloc);
		if (!copy) {
			break;
		}
		copy->vaddr = reloc->vaddr;
		copy->paddr = reloc->paddr;
		copy->type = reloc->type;
		rz_pvector_push(relocs, copy);
	}
	return relocs;
}

static RzStructuredData *qnx_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	QnxObj *bin = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *qnx_lmf = rz_structured_data_map_add_map(info, "qnx_lmf");
	if (!qnx_lmf) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(qnx_lmf, "version", bin->lmfh.version, false);
	rz_structured_data_map_add_unsigned(qnx_lmf, "cflags", bin->lmfh.cflags, true);
	rz_structured_data_map_add_unsigned(qnx_lmf, "cpu", bin->lmfh.cpu, false);
	rz_structured_data_map_add_unsigned(qnx_lmf, "fpu", bin->lmfh.fpu, false);
	rz_structured_data_map_add_unsigned(qnx_lmf, "code_index", bin->lmfh.code_index, false);
	rz_structured_data_map_add_unsigned(qnx_lmf, "stack_index", bin->lmfh.stack_index, false);
	rz_structured_data_map_add_unsigned(qnx_lmf, "heap_index", bin->lmfh.heap_index, false);
	rz_structured_data_map_add_unsigned(qnx_lmf, "argv_index", bin->lmfh.argv_index, false);

	RzStructuredData *spare2 = rz_structured_data_map_add_array(qnx_lmf, "spare2");
	if (!spare2) {
		rz_structured_data_free(info);
		return NULL;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(bin->lmfh.spare2); ++i) {
		rz_structured_data_array_add_unsigned(spare2, bin->lmfh.spare2[i], true);
	}

	rz_structured_data_map_add_unsigned(qnx_lmf, "code_offset", bin->lmfh.code_offset, true);
	rz_structured_data_map_add_unsigned(qnx_lmf, "stack_nbytes", bin->lmfh.stack_nbytes, true);
	rz_structured_data_map_add_unsigned(qnx_lmf, "heap_nbytes", bin->lmfh.heap_nbytes, true);
	rz_structured_data_map_add_unsigned(qnx_lmf, "image_base", bin->lmfh.image_base, true);

	RzStructuredData *spare3 = rz_structured_data_map_add_array(qnx_lmf, "spare3");
	if (!spare3) {
		rz_structured_data_free(info);
		return NULL;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(bin->lmfh.spare3); ++i) {
		rz_structured_data_array_add_unsigned(spare3, bin->lmfh.spare3[i], true);
	}

	return info;
}

/*
 * No mention of symbols in the doc
 */
static RzPVector /*<RzBinSymbol *>*/ *qnx_symbols(RzBinFile *bf) {
	return NULL;
}

static RzPVector /*<RzBinMap *>*/ *qnx_maps(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	QnxObj *qo = bf->o->bin_obj;
	return rz_pvector_clone(qo->maps);
}

// Returns the sections
static RzPVector /*<RzBinSection *>*/ *qnx_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	QnxObj *qo = bf->o->bin_obj;
	return rz_pvector_clone(qo->sections);
}

/*
 * Returns the sdb
 * \param RzBinFile
 * \return sdb of the bin_obj
 */
static Sdb *qnx_get_sdb(RzBinFile *bf) {
	RzBinObject *o = bf->o;
	if (!o) {
		return NULL;
	}
	QnxObj *qo = o->bin_obj;
	return qo ? qo->kv : NULL;
}

/*
 * Returns the base address of the image from the binary header
 * \param RzBinFile
 * \return image_base address
 */
static ut64 qnx_baddr(RzBinFile *bf) {
	QnxObj *qo = bf->o->bin_obj;
	return qo ? qo->lmfh.image_base : 0;
}

/*
 * Currently both physical and virtual address are set to 0
 * The memory map has different values for entry
 */
static RzPVector /*<RzBinAddr *>*/ *qnx_entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinAddr *ptr = NULL;
	QnxObj *qo = bf->o->bin_obj;
	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	ptr->paddr = qo->lmfh.code_offset;
	ptr->vaddr = qo->lmfh.code_offset + qnx_baddr(bf);
	rz_pvector_push(ret, ptr);
	return ret;
}

/*
 * \param RzBinFile
 * \return signature of the binary
 */
static char *qnx_signature(RzBinFile *bf, bool json) {
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
		return rz_str_dup(sdb_itoa(qo->rwend.signature, buf, 10));
	}
}

/*
 * \return: returns the vaddr
 */
static ut64 qnx_get_vaddr(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return vaddr;
}

// Declaration of the plugin
RzBinPlugin rz_bin_plugin_qnx = {
	.name = "qnx",
	.desc = "QNX executable",
	.license = "LGPL3",
	.load_buffer = &qnx_load_buffer,
	.destroy = &qnx_destroy,
	.relocs = &qnx_relocs,
	.baddr = &qnx_baddr,
	.author = "deepakchethan",
	.check_buffer = &qnx_check_buffer,
	.bin_structure = &qnx_structure,
	.get_sdb = &qnx_get_sdb,
	.entries = &qnx_entries,
	.maps = &qnx_maps,
	.sections = &qnx_sections,
	.symbols = &qnx_symbols,
	.signature = &qnx_signature,
	.get_vaddr = &qnx_get_vaddr,
	.info = &qnx_info
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_qnx,
	.version = RZ_VERSION
};
#endif
