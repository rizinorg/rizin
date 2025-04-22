// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2018-2019 a0rtega
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>

#include "../format/nin/n3ds.h"

#define N3DS_STR_ARM9      "entry.arm9"
#define N3DS_STR_ARM11     "entry.arm11"
#define N3DS_STR_SYSMODULE "sysmodule.arm11"
#define N3DS_STR_K11_EXT   "extensions.arm11"

#define N3DS_DESCR_ARM9      "Arm9 Kernel"
#define N3DS_DESCR_ARM11     "Arm11 Kernel"
#define N3DS_DESCR_SYSMODULE "Arm11 SysModule"
#define N3DS_DESCR_K11_EXT   "Arm11 Kernel Extensions"

#define n3ds_get_hdr(bf) ((N3DSFirmHdr *)bf->o->bin_obj)

enum {
	N3DS_TYPE_ARM9 = 0,
	N3DS_TYPE_ARM11,
	N3DS_TYPE_SYSMODULE,
	N3DS_TYPE_K11_EXT,
};

static bool n3ds_read_firm_sect_hdr(RzBuffer *buf, ut64 *offset, N3DSFirmSectHdr *hdr, ut64 arm11_ep, ut64 arm9_ep) {
	if (!(rz_buf_read_le32_offset(buf, offset, &hdr->offset) &&
		    rz_buf_read_le32_offset(buf, offset, &hdr->address) &&
		    rz_buf_read_le32_offset(buf, offset, &hdr->size) &&
		    rz_buf_read_le32_offset(buf, offset, &hdr->copy_mode) &&
		    rz_buf_read_offset(buf, offset, hdr->sha256, sizeof(hdr->sha256)))) {
		return false;
	}

	ut64 beg_section = hdr->address;
	ut64 end_section = hdr->address + hdr->size;

	if (beg_section <= arm9_ep && arm9_ep < end_section) {
		hdr->type = N3DS_TYPE_ARM9;
	} else if (beg_section <= arm11_ep && arm11_ep < end_section) {
		hdr->type = N3DS_TYPE_ARM11;
	} else {
		ut8 tmp[4];
		if (rz_buf_read_at(buf, hdr->offset + 0x100, tmp, sizeof(tmp)) != sizeof(tmp)) {
			return false;
		}
		if (!memcmp(tmp, "NCCH", 4)) {
			hdr->type = N3DS_TYPE_SYSMODULE;
		} else {
			hdr->type = N3DS_TYPE_K11_EXT;
		}
	}
	return true;
}

static bool n3ds_read_firm_hdr(RzBuffer *buf, N3DSFirmHdr *hdr) {
	ut64 offset = 0;
	return rz_buf_read_offset(buf, &offset, hdr->magic, sizeof(hdr->magic)) &&
		rz_buf_read_offset(buf, &offset, hdr->reserved1, sizeof(hdr->reserved1)) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm11_ep) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->arm9_ep) &&
		rz_buf_read_offset(buf, &offset, hdr->reserved2, sizeof(hdr->reserved2)) &&
		n3ds_read_firm_sect_hdr(buf, &offset, &hdr->sections[0], hdr->arm11_ep, hdr->arm9_ep) &&
		n3ds_read_firm_sect_hdr(buf, &offset, &hdr->sections[1], hdr->arm11_ep, hdr->arm9_ep) &&
		n3ds_read_firm_sect_hdr(buf, &offset, &hdr->sections[2], hdr->arm11_ep, hdr->arm9_ep) &&
		n3ds_read_firm_sect_hdr(buf, &offset, &hdr->sections[3], hdr->arm11_ep, hdr->arm9_ep) &&
		rz_buf_read_offset(buf, &offset, hdr->rsa2048, sizeof(hdr->rsa2048));
}

static bool n3ds_check_buffer(RzBuffer *b) {
	ut8 magic[4];
	rz_buf_read_at(b, 0, magic, sizeof(magic));
	return (!memcmp(magic, "FIRM", 4));
}

static bool n3ds_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	N3DSFirmHdr *hdr = RZ_NEW0(N3DSFirmHdr);
	if (!n3ds_read_firm_hdr(b, hdr)) {
		free(hdr);
		return false;
	}
	obj->bin_obj = hdr;
	return true;
}

static void n3ds_destroy(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return;
	}

	N3DSFirmHdr *hdr = n3ds_get_hdr(bf);
	free(hdr);
}

static char *n3ds_section_name(N3DSFirmSectHdr *shdr) {
	switch (shdr->type) {
	case N3DS_TYPE_ARM9:
		return rz_str_dup(N3DS_STR_ARM9);
	case N3DS_TYPE_ARM11:
		return rz_str_dup(N3DS_STR_ARM11);
	case N3DS_TYPE_SYSMODULE:
		return rz_str_dup(N3DS_STR_SYSMODULE);
	case N3DS_TYPE_K11_EXT:
		return rz_str_dup(N3DS_STR_K11_EXT);
	default:
		return rz_str_newf("section_%x", shdr->address);
	}
}

static RzBinSection *n3ds_firm_section_new(N3DSFirmSectHdr *shdr) {
	if (!shdr->size) {
		/* when a section size is 0, then is not used. */
		return NULL;
	}

	RzBinSection *section = RZ_NEW0(RzBinSection);
	if (!section) {
		RZ_LOG_ERROR("bin: failed to allocate RzBinSection\n");
		return NULL;
	}

	section->size = shdr->size;
	section->vsize = shdr->size;
	section->paddr = shdr->offset;
	section->vaddr = shdr->address;
	section->name = n3ds_section_name(shdr);
	section->perm = RZ_PERM_RWX;
	section->type = shdr->type;
	section->flags = shdr->copy_mode;
	return section;
}

static RzPVector /*<RzBinSection *>*/ *n3ds_sections(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return NULL;
	}

	N3DSFirmHdr *hdr = n3ds_get_hdr(bf);

	RzPVector *ret = NULL;
	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}

	/* FIRM has always 4 sections */
	for (size_t i = 0; i < 4; i++) {
		/* Check if section is used */
		RzBinSection *sect = n3ds_firm_section_new(&hdr->sections[i]);
		if (!sect) {
			continue;
		}
		rz_pvector_push(ret, sect);
	}

	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *n3ds_entries(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return NULL;
	}

	RzBinAddr *ptr9 = NULL, *ptr11 = NULL;
	RzPVector *ret = rz_pvector_new(free);
	if (!ret ||
		!(ptr9 = RZ_NEW0(RzBinAddr)) ||
		!(ptr11 = RZ_NEW0(RzBinAddr))) {
		rz_pvector_free(ret);
		free(ptr9);
		return NULL;
	}
	N3DSFirmHdr *hdr = n3ds_get_hdr(bf);

	/* ARM9 entry point */
	ptr9->vaddr = hdr->arm9_ep;
	rz_pvector_push(ret, ptr9);

	/* ARM11 entry point */
	ptr11->vaddr = hdr->arm11_ep;
	rz_pvector_push(ret, ptr11);

	for (size_t i = 0; i < 4; i++) {
		N3DSFirmSectHdr *shdr = &hdr->sections[i];
		if (!shdr->size) {
			continue;
		}

		ut64 beg_section = shdr->address;
		ut64 end_section = shdr->address + shdr->size;
		if (beg_section <= ptr9->vaddr && ptr9->vaddr < end_section) {
			ut32 diff = shdr->address - hdr->arm9_ep;
			ptr9->paddr = shdr->offset + diff;
		} else if (beg_section <= ptr11->vaddr && ptr11->vaddr < end_section) {
			ut32 diff = shdr->address - hdr->arm11_ep;
			ptr11->paddr = shdr->offset + diff;
		}
	}

	return ret;
}

static RzBinInfo *n3ds_info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->type = rz_str_dup("FIRM");
	ret->machine = rz_str_dup("Nintendo 3DS");
	ret->os = rz_str_dup("n3ds");
	ret->arch = rz_str_dup("arm");
	ret->has_va = true;
	ret->bits = 32;
	return ret;
}

static RzBinFileHash *n3ds_hash_buffer(const char *name, const ut8 *hash, size_t size) {
	RzBinFileHash *fh = RZ_NEW0(RzBinFileHash);
	if (!fh) {
		return NULL;
	}
	fh->type = rz_str_dup(name);
	fh->hex = rz_hex_bin2strdup(hash, size);
	return fh;
}

static RzPVector /*<RzBinFileHash *>*/ *n3ds_hashes(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return NULL;
	}

	RzPVector *vec = rz_pvector_new((RzPVectorFree)rz_bin_file_hash_free);
	if (!vec) {
		return NULL;
	}

	N3DSFirmHdr *hdr = n3ds_get_hdr(bf);
	RzBinFileHash *fh = n3ds_hash_buffer("rsa2048:firmware", hdr->rsa2048, sizeof(hdr->rsa2048));
	if (fh && !rz_pvector_push(vec, fh)) {
		rz_bin_file_hash_free(fh);
	}

	for (size_t i = 0; i < 4; i++) {
		N3DSFirmSectHdr *shdr = &hdr->sections[i];
		if (!shdr->size) {
			continue;
		}

		switch (shdr->type) {
		case N3DS_TYPE_ARM9:
			fh = n3ds_hash_buffer("sha256:arm9", shdr->sha256, sizeof(shdr->sha256));
			break;
		case N3DS_TYPE_ARM11:
			fh = n3ds_hash_buffer("sha256:arm11", shdr->sha256, sizeof(shdr->sha256));
			break;
		case N3DS_TYPE_SYSMODULE:
			fh = n3ds_hash_buffer("sha256:sysmodule", shdr->sha256, sizeof(shdr->sha256));
			break;
		case N3DS_TYPE_K11_EXT:
			fh = n3ds_hash_buffer("sha256:k11ext", shdr->sha256, sizeof(shdr->sha256));
			break;
		default:
			fh = NULL;
			break;
		}

		if (fh && !rz_pvector_push(vec, fh)) {
			rz_bin_file_hash_free(fh);
		}
	}

	return vec;
}

static RZ_OWN char *n3ds_section_type_to_string(ut64 type) {
	switch (type) {
	case N3DS_TYPE_ARM9:
		return rz_str_dup(N3DS_DESCR_ARM9);
	case N3DS_TYPE_ARM11:
		return rz_str_dup(N3DS_DESCR_ARM11);
	case N3DS_TYPE_SYSMODULE:
		return rz_str_dup(N3DS_DESCR_SYSMODULE);
	case N3DS_TYPE_K11_EXT:
		return rz_str_dup(N3DS_DESCR_K11_EXT);
	default:
		return NULL;
	}
}

static RZ_OWN RzList /*<char *>*/ *n3ds_section_flag_to_rzlist(ut64 type) {
	RzList *list = rz_list_newf(NULL);
	switch (type) {
	case N3DS_COPY_MODE_NDMA:
		rz_list_append(list, "ndma");
		break;
	case N3DS_COPY_MODE_XDMA:
		rz_list_append(list, "xdma");
		break;
	case N3DS_COPY_MODE_MEMCPY:
		rz_list_append(list, "memcpy");
		break;
	default:
		break;
	}
	return list;
}

RzBinPlugin rz_bin_plugin_nin3ds = {
	.name = "nin3ds",
	.desc = "Nintendo 3DS Firmware plugin",
	.license = "LGPL3",
	.load_buffer = &n3ds_load_buffer,
	.check_buffer = &n3ds_check_buffer,
	.destroy = &n3ds_destroy,
	.entries = &n3ds_entries,
	.maps = &rz_bin_maps_of_file_sections,
	.section_type_to_string = &n3ds_section_type_to_string,
	.section_flag_to_rzlist = &n3ds_section_flag_to_rzlist,
	.sections = &n3ds_sections,
	.hashes = &n3ds_hashes,
	.info = &n3ds_info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_nin3ds,
	.version = RZ_VERSION
};
#endif
