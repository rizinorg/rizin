// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define mbn_file_get_hdr(bf) ((SblHeader *)bf->o->bin_obj)

typedef struct sbl_header {
	ut32 load_index;
	ut32 version; // (flash_partition_version) 3 = nand
	ut32 paddr; // This + 40 is the start of the code in the file
	ut32 vaddr; // Where it's loaded in memory
	ut32 psize; // code_size + signature_size + cert_chain_size
	ut32 code_pa; // Only what's loaded to memory
	ut32 sign_va;
	ut32 sign_sz;
	ut32 cert_va; // Max of 3 certs?
	ut32 cert_sz;
} SblHeader;

static bool read_sbl_header(RzBuffer *b, SblHeader *sb, ut64 *offset) {
	return rz_buf_read_le32_offset(b, offset, &sb->load_index) &&
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

static bool check_buffer(RzBuffer *b) {
	ut64 offset = 0;
	SblHeader sb = { 0 };
	rz_return_val_if_fail(b, false);
	if (!read_sbl_header(b, &sb, &offset)) {
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
	if (sb.load_index < 1 || sb.load_index > 0x40) {
		return false; // should be 0x19 ?
	}
	return true;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	ut64 offset = 0;
	SblHeader *sb = RZ_NEW0(SblHeader);
	if (!sb || !read_sbl_header(b, sb, &offset)) {
		free(sb);
		return false;
	}

	obj->bin_obj = sb;
	return true;
}

static ut64 baddr(RzBinFile *bf) {
	SblHeader *sb = mbn_file_get_hdr(bf);
	return sb->vaddr;
}

static RzList /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	SblHeader *sb = mbn_file_get_hdr(bf);
	RzList *ret = rz_list_newf(free);
	if (ret) {
		RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
		if (ptr) {
			ptr->paddr = 40 + sb->code_pa;
			ptr->vaddr = 40 + sb->code_pa + sb->vaddr;
			rz_list_append(ret, ptr);
		}
	}
	return ret;
}

static RzList /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	SblHeader *sb = mbn_file_get_hdr(bf);
	RzBinSection *ptr = NULL;
	RzList *ret = NULL;
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;

	// add text segment
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("text");
	ptr->size = sb->psize;
	ptr->vsize = sb->psize;
	ptr->paddr = sb->paddr + 40;
	ptr->vaddr = sb->vaddr;
	ptr->perm = RZ_PERM_RX; // r-x
	ptr->has_strings = true;
	rz_list_append(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("sign");
	ptr->size = sb->sign_sz;
	ptr->vsize = sb->sign_sz;
	ptr->paddr = sb->sign_va - sb->vaddr;
	ptr->vaddr = sb->sign_va;
	ptr->perm = RZ_PERM_R; // r--
	ptr->has_strings = true;
	rz_list_append(ret, ptr);

	if (sb->cert_sz && sb->cert_va > sb->vaddr) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = strdup("cert");
		ptr->size = sb->cert_sz;
		ptr->vsize = sb->cert_sz;
		ptr->paddr = sb->cert_va - sb->vaddr;
		ptr->vaddr = sb->cert_va;
		ptr->perm = RZ_PERM_R; // r--
		ptr->has_strings = true;
		rz_list_append(ret, ptr);
	}
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	const int bits = 16;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = strdup(bf->file);
	ret->bclass = strdup("bootloader");
	ret->rclass = strdup("mbn");
	ret->os = strdup("MBN");
	ret->arch = strdup("arm");
	ret->machine = strdup(ret->arch);
	ret->subsystem = strdup("mbn");
	ret->type = strdup("sbl"); // secondary boot loader
	ret->bits = bits;
	ret->has_va = true;
	ret->has_crypto = true; // must be false if there' no sign or cert sections
	ret->has_pi = false;
	ret->has_nx = false;
	ret->big_endian = false;
	ret->dbg_info = false;
	return ret;
}

static ut64 size(RzBinFile *bf) {
	SblHeader *sb = mbn_file_get_hdr(bf);
	return sizeof(SblHeader) + sb->psize;
}

static void destroy(RzBinFile *bf) {
	SblHeader *sb = mbn_file_get_hdr(bf);
	free(sb);
}

RzBinPlugin rz_bin_plugin_mbn = {
	.name = "mbn",
	.desc = "MBN/SBL bootloader things",
	.license = "LGPL3",
	.minstrlen = 10,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.size = &size,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_mbn,
	.version = RZ_VERSION
};
#endif
