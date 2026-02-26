// SPDX-FileCopyrightText: 2025 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Implementation of MediaTek GFH firmware image parser (md1rom).
 *
 * The GFH (Generic File Header) format is used by MediaTek for bootloader
 * and modem firmware images. The file starts with a chain of GFH headers
 * (the first must be FILE_INFO), followed by the code/data payload.
 *
 * References:
 * - https://github.com/nccgroup/mtk_bp/blob/main/mtk_structs/mtk_img.ksy
 * - https://github.com/u-boot/u-boot/blob/master/tools/mtk_image.h
 */
#include "mtk.h"

static inline bool mtk_is_gfh_magic(ut32 magic_version) {
	return (magic_version & MTK_GFH_MAGIC_MASK) == MTK_GFH_MAGIC;
}

static bool mtk_read_common_hdr(RzBuffer *b, ut64 *offset, MtkGfhCommonHdr *hdr) {
	return rz_buf_read_le32_offset(b, offset, &hdr->magic_version) &&
		rz_buf_read_le16_offset(b, offset, &hdr->size) &&
		rz_buf_read_le16_offset(b, offset, &hdr->type);
}

static bool mtk_read_file_info(RzBuffer *b, ut64 *offset, MtkGfhFileInfo *fi) {
	if (!rz_buf_read_offset(b, offset, (ut8 *)fi->name, MTK_GFH_FILE_INFO_NAME_SIZE)) {
		return false;
	}
	fi->name[MTK_GFH_FILE_INFO_NAME_SIZE - 1] = '\0';
	return rz_buf_read_le32_offset(b, offset, &fi->unused) &&
		rz_buf_read_le16_offset(b, offset, &fi->file_type) &&
		rz_buf_read8_offset(b, offset, &fi->flash_type) &&
		rz_buf_read8_offset(b, offset, &fi->sig_type) &&
		rz_buf_read_le32_offset(b, offset, &fi->load_addr) &&
		rz_buf_read_le32_offset(b, offset, &fi->total_size) &&
		rz_buf_read_le32_offset(b, offset, &fi->max_size) &&
		rz_buf_read_le32_offset(b, offset, &fi->hdr_size) &&
		rz_buf_read_le32_offset(b, offset, &fi->sig_size) &&
		rz_buf_read_le32_offset(b, offset, &fi->jump_offset) &&
		rz_buf_read_le32_offset(b, offset, &fi->processed);
}

RZ_IPI const char *mtk_gfh_type_str(ut16 type) {
	switch (type) {
	case MTK_GFH_TYPE_FILE_INFO:
		return "file_info";
	case MTK_GFH_TYPE_BL_INFO:
		return "bl_info";
	case MTK_GFH_TYPE_ANTI_CLONE:
		return "anti_clone";
	case MTK_GFH_TYPE_BL_SEC_KEY:
		return "bl_sec_key";
	case MTK_GFH_TYPE_BROM_CFG:
		return "brom_cfg";
	case MTK_GFH_TYPE_BROM_SEC_CFG:
		return "brom_sec_cfg";
	case MTK_GFH_TYPE_0x200:
		return "type_0x200";
	case MTK_GFH_TYPE_RSA_MAYBE:
		return "rsa_maybe";
	default:
		return "unknown";
	}
}

// --- GFH format parsing ---

RZ_IPI bool mtk_check_buffer(RzBuffer *b) {
	rz_return_val_if_fail(b, false);

	ut64 buf_size = rz_buf_size(b);
	if (buf_size < MTK_GFH_MIN_FILE_SIZE) {
		return false;
	}

	ut64 offset = 0;
	MtkGfhCommonHdr hdr;
	if (!mtk_read_common_hdr(b, &offset, &hdr)) {
		return false;
	}

	if (!mtk_is_gfh_magic(hdr.magic_version)) {
		return false;
	}
	if (hdr.type != MTK_GFH_TYPE_FILE_INFO) {
		return false;
	}
	if (hdr.size < MTK_GFH_MIN_FILE_SIZE) {
		return false;
	}

	MtkGfhFileInfo fi;
	if (!mtk_read_file_info(b, &offset, &fi)) {
		return false;
	}

	if (fi.hdr_size < hdr.size || fi.hdr_size > buf_size) {
		return false;
	}
	if (fi.load_addr == 0) {
		return false;
	}

	return true;
}

RZ_IPI MtkObj *mtk_obj_new(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);

	MtkObj *mtk = RZ_NEW0(MtkObj);
	if (!mtk) {
		return NULL;
	}

	mtk->extra_headers = rz_vector_new(sizeof(MtkGfhHeader), NULL, NULL);
	if (!mtk->extra_headers) {
		free(mtk);
		return NULL;
	}

	ut64 offset = 0;
	if (!mtk_read_common_hdr(b, &offset, &mtk->first_common)) {
		goto fail;
	}
	if (!mtk_is_gfh_magic(mtk->first_common.magic_version) ||
		mtk->first_common.type != MTK_GFH_TYPE_FILE_INFO) {
		goto fail;
	}
	if (!mtk_read_file_info(b, &offset, &mtk->file_info)) {
		goto fail;
	}

	ut64 buf_size = rz_buf_size(b);
	if (mtk->file_info.hdr_size > buf_size) {
		RZ_LOG_ERROR("MTK: header size (0x%x) exceeds file size\n", mtk->file_info.hdr_size);
		goto fail;
	}

	mtk->code_offset = mtk->file_info.hdr_size;
	if (buf_size > mtk->code_offset) {
		mtk->code_size = buf_size - mtk->code_offset;
	}
	// jump_offset is from the start of the file, not from load_addr
	mtk->entry_vaddr = mtk->file_info.load_addr + (mtk->file_info.jump_offset - mtk->code_offset);

	// Parse additional GFH headers between the first header and the code area
	offset = mtk->first_common.size;
	int count = 0;
	while (offset + MTK_GFH_COMMON_HDR_SIZE <= mtk->file_info.hdr_size && count < 100) {
		ut64 hdr_start = offset;
		MtkGfhCommonHdr extra_common;
		if (!mtk_read_common_hdr(b, &offset, &extra_common)) {
			break;
		}
		if (!mtk_is_gfh_magic(extra_common.magic_version)) {
			break;
		}
		if (extra_common.size < MTK_GFH_COMMON_HDR_SIZE) {
			break;
		}

		MtkGfhHeader entry = {
			.common = extra_common,
			.file_offset = hdr_start,
		};
		rz_vector_push(mtk->extra_headers, &entry);

		offset = hdr_start + extra_common.size;
		count++;
	}

	return mtk;

fail:
	rz_vector_free(mtk->extra_headers);
	free(mtk);
	return NULL;
}

RZ_IPI void mtk_obj_free(MtkObj *mtk) {
	if (!mtk) {
		return;
	}
	rz_vector_free(mtk->extra_headers);
	free(mtk);
}

RZ_IPI bool mtk_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && b, false);
	MtkObj *mtk = mtk_obj_new(b);
	if (!mtk) {
		return false;
	}
	obj->bin_obj = mtk;
	return true;
}

RZ_IPI void mtk_destroy(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return;
	}
	mtk_obj_free(bf->o->bin_obj);
}

RZ_IPI ut64 mtk_baddr(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, 0);
	MtkObj *mtk = bf->o->bin_obj;
	return mtk->file_info.load_addr;
}

RZ_IPI RzPVector /*<RzBinAddr *>*/ *mtk_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	MtkObj *mtk = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	RzBinAddr *entry = RZ_NEW0(RzBinAddr);
	if (entry) {
		entry->paddr = mtk->file_info.jump_offset;
		entry->vaddr = mtk->entry_vaddr;
		rz_pvector_push(ret, entry);
	}

	return ret;
}

RZ_IPI RzPVector /*<RzBinSection *>*/ *mtk_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	MtkObj *mtk = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	// Header section
	RzBinSection *hdr_section = RZ_NEW0(RzBinSection);
	if (hdr_section) {
		hdr_section->name = rz_str_dup("header");
		hdr_section->paddr = 0;
		hdr_section->size = mtk->code_offset;
		hdr_section->vsize = mtk->code_offset;
		hdr_section->vaddr = 0;
		hdr_section->perm = RZ_PERM_R;
		rz_pvector_push(ret, hdr_section);
	}

	// Code section
	if (mtk->code_size > 0) {
		RzBinSection *code_section = RZ_NEW0(RzBinSection);
		if (code_section) {
			code_section->name = rz_str_dup("code");
			code_section->paddr = mtk->code_offset;
			code_section->size = mtk->code_size;
			code_section->vsize = mtk->code_size;
			code_section->vaddr = mtk->file_info.load_addr;
			code_section->perm = RZ_PERM_RX;
			rz_pvector_push(ret, code_section);
		}
	}

	return ret;
}

RZ_IPI RzBinInfo *mtk_info(RzBinFile *bf) {
	RzBinInfo *info = RZ_NEW0(RzBinInfo);
	if (!info) {
		return NULL;
	}

	info->file = bf->file ? rz_str_dup(bf->file) : NULL;
	info->type = rz_str_dup("MediaTek GFH");
	info->machine = rz_str_dup("MediaTek Modem");
	info->arch = rz_str_dup("mips");
	info->rclass = rz_str_dup("firmware");
	info->subsystem = rz_str_dup("modem");
	info->has_va = true;
	info->bits = 32;
	info->big_endian = false;

	return info;
}

RZ_IPI RzStructuredData *mtk_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	MtkObj *mtk = bf->o->bin_obj;
	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	// File info header
	RzStructuredData *fi = rz_structured_data_map_add_map(root, "gfh_file_info");
	if (fi) {
		rz_structured_data_map_add_unsigned(fi, "magic_version", mtk->first_common.magic_version, true);
		rz_structured_data_map_add_unsigned(fi, "header_block_size", mtk->first_common.size, false);
		rz_structured_data_map_add_string(fi, "header_type", mtk_gfh_type_str(mtk->first_common.type));
		rz_structured_data_map_add_string(fi, "name", mtk->file_info.name);
		rz_structured_data_map_add_unsigned(fi, "file_type", mtk->file_info.file_type, true);
		rz_structured_data_map_add_unsigned(fi, "flash_type", mtk->file_info.flash_type, true);
		rz_structured_data_map_add_unsigned(fi, "sig_type", mtk->file_info.sig_type, true);
		rz_structured_data_map_add_unsigned(fi, "load_addr", mtk->file_info.load_addr, true);
		rz_structured_data_map_add_unsigned(fi, "total_size", mtk->file_info.total_size, true);
		rz_structured_data_map_add_unsigned(fi, "max_size", mtk->file_info.max_size, true);
		rz_structured_data_map_add_unsigned(fi, "hdr_size", mtk->file_info.hdr_size, true);
		rz_structured_data_map_add_unsigned(fi, "sig_size", mtk->file_info.sig_size, true);
		rz_structured_data_map_add_unsigned(fi, "jump_offset", mtk->file_info.jump_offset, true);
		rz_structured_data_map_add_unsigned(fi, "entry_point", mtk->entry_vaddr, true);
	}

	// Extra GFH headers
	if (rz_vector_len(mtk->extra_headers) > 0) {
		RzStructuredData *hdrs = rz_structured_data_map_add_array(root, "gfh_headers");
		if (hdrs) {
			MtkGfhHeader *extra;
			rz_vector_foreach(mtk->extra_headers, extra) {
				RzStructuredData *h = rz_structured_data_array_add_map(hdrs);
				if (!h) {
					continue;
				}
				rz_structured_data_map_add_unsigned(h, "file_offset", extra->file_offset, true);
				rz_structured_data_map_add_string(h, "type", mtk_gfh_type_str(extra->common.type));
				rz_structured_data_map_add_unsigned(h, "type_id", extra->common.type, true);
				rz_structured_data_map_add_unsigned(h, "size", extra->common.size, false);
			}
		}
	}

	// Derived values
	rz_structured_data_map_add_unsigned(root, "code_offset", mtk->code_offset, true);
	rz_structured_data_map_add_unsigned(root, "code_size", mtk->code_size, true);

	return root;
}
