// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The MBN file format is not publicly documented currently.
 * It is used in Qualcomm firmware images to verify the firmware binaries against the root of trust.
 * There are more than one version of the MBN file format.
 * This implementation only handles the signature bundle for the Qualcomm secure boot mechanism.
 * For details see:
 * https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/secure-boot-and-image-authentication-version_final.pdf
 *
 * Another, more complete, MBN implantation can be found here:
 * https://github.com/openpst/libopenpst/blob/master/include/qualcomm/mbn.h
 */

#include "mbn.h"
#include <rz_util/rz_str.h>
#include <stddef.h>

bool mbn_read_sbl_header(RzBuffer *b, SblHeader *sb, ut64 *offset) {
	return rz_buf_read_le32_offset(b, offset, &sb->image_id) &&
		rz_buf_read_le32_offset(b, offset, &sb->version) &&
		rz_buf_read_le32_offset(b, offset, &sb->paddr) &&
		rz_buf_read_le32_offset(b, offset, &sb->vaddr) &&
		rz_buf_read_le32_offset(b, offset, &sb->psize) &&
		rz_buf_read_le32_offset(b, offset, &sb->code_pa) &&
		rz_buf_read_le32_offset(b, offset, &sb->sign_va) &&
		rz_buf_read_le32_offset(b, offset, &sb->sign_sz) &&
		rz_buf_read_le32_offset(b, offset, &sb->cert_va) &&
		rz_buf_read_le32_offset(b, offset, &sb->cert_sz);
}

bool mbn_check_buffer(RzBuffer *b) {
	ut64 offset = 0;
	SblHeader sb = { 0 };
	rz_return_val_if_fail(b, false);
	if (!mbn_read_sbl_header(b, &sb, &offset)) {
		return false;
	}
	if (sb.version != 3) { // NAND
		return false;
	}
	if (sb.paddr + sizeof(SblHeader) > offset) { // NAND
		return false;
	}
	if (sb.vaddr < 0x100 || sb.psize > offset) { // NAND
		return false;
	}
	if (sb.cert_va < sb.vaddr) {
		return false;
	}
	if (sb.cert_sz >= 0xf0000) {
		return false;
	}
	if (sb.sign_va < sb.vaddr) {
		return false;
	}
	if (sb.sign_sz >= 0xf0000) {
		return false;
	}
	if (sb.image_id == RZ_MBN_kMbnImageNone || sb.image_id > RZ_MBN_kMbnImageLast) {
		return false;
	}
	return true;
}

bool mbn_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	ut64 offset = 0;
	SblHeader *sb = RZ_NEW0(SblHeader);
	if (!sb || !mbn_read_sbl_header(b, sb, &offset)) {
		free(sb);
		return false;
	}

	obj->bin_obj = sb;
	return true;
}

ut64 mbn_baddr(RzBinFile *bf) {
	SblHeader *sb = mbn_file_get_hdr(bf);
	return sb->vaddr;
}

RzPVector /*<RzBinAddr *>*/ *mbn_entries(RzBinFile *bf) {
	SblHeader *sb = mbn_file_get_hdr(bf);
	RzPVector *ret = rz_pvector_new(free);
	if (ret) {
		RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
		if (ptr) {
			ptr->paddr = 40 + sb->code_pa;
			ptr->vaddr = 40 + sb->code_pa + sb->vaddr;
			rz_pvector_push(ret, ptr);
		}
	}
	return ret;
}

RzPVector /*<RzBinSection *>*/ *mbn_sections(RzBinFile *bf) {
	SblHeader *sb = mbn_file_get_hdr(bf);
	RzBinSection *ptr = NULL;
	RzPVector *ret = NULL;
	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}

	// add text segment
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("text");
	ptr->size = sb->psize;
	ptr->vsize = sb->psize;
	ptr->paddr = sb->paddr + 40;
	ptr->vaddr = sb->vaddr;
	ptr->perm = RZ_PERM_RX; // r-x
	ptr->has_strings = true;
	rz_pvector_push(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("sign");
	ptr->size = sb->sign_sz;
	ptr->vsize = sb->sign_sz;
	ptr->paddr = sb->sign_va - sb->vaddr;
	ptr->vaddr = sb->sign_va;
	ptr->perm = RZ_PERM_R; // r--
	ptr->has_strings = true;
	rz_pvector_push(ret, ptr);

	if (sb->cert_sz && sb->cert_va > sb->vaddr) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = rz_str_dup("cert");
		ptr->size = sb->cert_sz;
		ptr->vsize = sb->cert_sz;
		ptr->paddr = sb->cert_va - sb->vaddr;
		ptr->vaddr = sb->cert_va;
		ptr->perm = RZ_PERM_R; // r--
		ptr->has_strings = true;
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

RzBinInfo *mbn_info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	const int bits = 16;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("bootloader");
	ret->rclass = rz_str_dup("mbn");
	ret->os = rz_str_dup("MBN");
	ret->arch = rz_str_dup("arm");
	ret->machine = rz_str_dup(ret->arch);
	ret->subsystem = rz_str_dup("mbn");
	ret->type = rz_str_dup("sbl"); // secondary boot loader
	ret->bits = bits;
	ret->has_va = true;
	ret->has_crypto = true; // must be false if there' no sign or cert sections
	ret->has_pi = false;
	ret->has_nx = false;
	ret->big_endian = false;
	ret->dbg_info = false;
	return ret;
}

ut64 mbn_size(RzBinFile *bf) {
	SblHeader *sb = mbn_file_get_hdr(bf);
	return sizeof(SblHeader) + sb->psize;
}

void mbn_destroy_obj(SblHeader *sb) {
	free(sb);
}

void mbn_destroy(RzBinFile *bf) {
	SblHeader *sb = mbn_file_get_hdr(bf);
	mbn_destroy_obj(sb);
}

RzPVector /*<RzBinString *>*/ *mbn_strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	// we only search strings with a minimum length of 10 bytes.
	opt.mode = RZ_BIN_STRING_SEARCH_MODE_READ_ONLY_SECTIONS;
	opt.min_length = 10;
	return rz_bin_file_strings(bf, &opt);
}

RzStructuredData *mbn_structure(SblHeader *sb) {
	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *mbn = rz_structured_data_map_add_map(info, "mbn");
	if (!mbn) {
		rz_structured_data_free(info);
		return NULL;
	}

	RzStructuredData *image = rz_structured_data_map_add_map(mbn, "image");
	if (!image) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_string(image, "name", rz_mbn_image_id_str(sb->image_id));
	rz_structured_data_map_add_unsigned(image, "id", sb->image_id, true);
	rz_structured_data_map_add_unsigned(mbn, "version", sb->version, true);
	rz_structured_data_map_add_unsigned(mbn, "paddr", sb->paddr, true);
	rz_structured_data_map_add_unsigned(mbn, "vaddr", sb->vaddr, true);
	rz_structured_data_map_add_unsigned(mbn, "psize", sb->psize, true);
	rz_structured_data_map_add_unsigned(mbn, "code_pa", sb->code_pa, true);
	rz_structured_data_map_add_unsigned(mbn, "sign_va", sb->sign_va, true);
	rz_structured_data_map_add_unsigned(mbn, "sign_sz", sb->sign_sz, true);
	rz_structured_data_map_add_unsigned(mbn, "cert_va", sb->cert_va, true);
	rz_structured_data_map_add_unsigned(mbn, "cert_sz", sb->cert_sz, true);

	return info;
}

RzStructuredData *mbn_structure_bin(RzBinFile *bf) {
	SblHeader *sb = mbn_file_get_hdr(bf);
	return mbn_structure(sb);
}
