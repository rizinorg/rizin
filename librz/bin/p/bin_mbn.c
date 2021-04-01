// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// XXX: this plugin have 0 tests and no binaries
//

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

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

// TODO avoid globals
static SblHeader sb = { 0 };

static bool check_buffer(RzBuffer *b) {
	rz_return_val_if_fail(b, false);
	ut64 bufsz = rz_buf_size(b);
	if (sizeof(SblHeader) < bufsz) {
		int ret = rz_buf_fread_at(b, 0, (ut8 *)&sb, "10i", 1);
		if (!ret) {
			return false;
		}
#if 0
		eprintf ("V=%d\n", sb.version);
		eprintf ("PA=0x%08x sz=0x%x\n", sb.paddr, sb.psize);
		eprintf ("VA=0x%08x sz=0x%x\n", sb.vaddr, sb.psize);
		eprintf ("CODE=0x%08x\n", sb.code_pa + sb.vaddr + 40);
		eprintf ("SIGN=0x%08x sz=0x%x\n", sb.sign_va, sb.sign_sz);
		if (sb.cert_sz > 0) {
			eprintf ("CERT=0x%08x sz=0x%x\n", sb.cert_va, sb.cert_sz);
		} else {
			eprintf ("No certificate found.\n");
		}
#endif
		if (sb.version != 3) { // NAND
			return false;
		}
		if (sb.paddr + sizeof(SblHeader) > bufsz) { // NAND
			return false;
		}
		if (sb.vaddr < 0x100 || sb.psize > bufsz) { // NAND
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
		// TODO: Add more checks here
		return true;
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *b, ut64 loadaddr, Sdb *sdb) {
	return check_buffer(b);
}

static ut64 baddr(RzBinFile *bf) {
	return sb.vaddr; // XXX
}

static RzList *entries(RzBinFile *bf) {
	RzList *ret = rz_list_newf(free);
	;
	if (ret) {
		RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
		if (ptr) {
			ptr->paddr = 40 + sb.code_pa;
			ptr->vaddr = 40 + sb.code_pa + sb.vaddr;
			rz_list_append(ret, ptr);
		}
	}
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	RzBinSection *ptr = NULL;
	RzList *ret = NULL;
	int rc;

	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;
	rc = rz_buf_fread_at(bf->buf, 0, (ut8 *)&sb, "10i", 1);
	if (!rc) {
		rz_list_free(ret);
		return false;
	}

	// add text segment
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("text");
	ptr->size = sb.psize;
	ptr->vsize = sb.psize;
	ptr->paddr = sb.paddr + 40;
	ptr->vaddr = sb.vaddr;
	ptr->perm = RZ_PERM_RX; // r-x
	ptr->add = true;
	ptr->has_strings = true;
	rz_list_append(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("sign");
	ptr->size = sb.sign_sz;
	ptr->vsize = sb.sign_sz;
	ptr->paddr = sb.sign_va - sb.vaddr;
	ptr->vaddr = sb.sign_va;
	ptr->perm = RZ_PERM_R; // r--
	ptr->has_strings = true;
	ptr->add = true;
	rz_list_append(ret, ptr);

	if (sb.cert_sz && sb.cert_va > sb.vaddr) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = strdup("cert");
		ptr->size = sb.cert_sz;
		ptr->vsize = sb.cert_sz;
		ptr->paddr = sb.cert_va - sb.vaddr;
		ptr->vaddr = sb.cert_va;
		ptr->perm = RZ_PERM_R; // r--
		ptr->has_strings = true;
		ptr->add = true;
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
	return sizeof(SblHeader) + sb.psize;
}

RzBinPlugin rz_bin_plugin_mbn = {
	.name = "mbn",
	.desc = "MBN/SBL bootloader things",
	.license = "LGPL3",
	.minstrlen = 10,
	.load_buffer = &load_buffer,
	.size = &size,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = &entries,
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
