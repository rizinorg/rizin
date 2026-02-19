// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2016 Oscar Salvador <osalvador.vilardaga@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * uClinux bFLT file format
 * For reference, see
 *   linux/include/uapi/linux/flat.h
 *   linux/fs/binfmt_flat.c
 * in the uClinux kernel, e.g. from uClinux-dist-20160919
 */

#include <rz_util.h>
#include "bflt.h"

#define MAX_SHARED_LIBS 1 // this may be 4 depending on kernel config
#define FLAT_DATA_ALIGN 0x20

static bool bflt_init_hdr(RzBfltObj *bin) {
	ut64 offset = 0;
	if (!(rz_buf_read_offset(bin->b, &offset, (ut8 *)(bin->hdr.magic), 4))) {
		RZ_LOG_WARN("read bFLT hdr failed\n");
		return false;
	}

	if (strncmp(bin->hdr.magic, "bFLT", 4)) {
		RZ_LOG_WARN("wrong magic number in bFLT file\n");
		return false;
	}

	bool check = rz_buf_read_be32_offset(bin->b, &offset, &bin->hdr.rev) &&
		rz_buf_read_be32_offset(bin->b, &offset, &bin->hdr.entry) &&
		rz_buf_read_be32_offset(bin->b, &offset, &bin->hdr.data_start) &&
		rz_buf_read_be32_offset(bin->b, &offset, &bin->hdr.data_end) &&
		rz_buf_read_be32_offset(bin->b, &offset, &bin->hdr.bss_end) &&
		rz_buf_read_be32_offset(bin->b, &offset, &bin->hdr.stack_size) &&
		rz_buf_read_be32_offset(bin->b, &offset, &bin->hdr.reloc_start) &&
		rz_buf_read_be32_offset(bin->b, &offset, &bin->hdr.reloc_count) &&
		rz_buf_read_be32_offset(bin->b, &offset, &bin->hdr.flags) &&
		rz_buf_read_be32_offset(bin->b, &offset, &bin->hdr.build_date);

	if (bin->hdr.rev != FLAT_VERSION) {
		RZ_LOG_WARN("only bFLT v4 is supported! This file has version %" PFMT32u "\n", bin->hdr.rev);
		return false;
	}
	if (bin->hdr.flags & FLAT_FLAG_GZIP || bin->hdr.flags & FLAT_FLAG_GZDATA) {
		RZ_LOG_WARN("this bFLT file is compressed. This is not (yet) supported.\n");
	}
	return check;
}

static bool bflt_reloc_big_endian(RzBfltObj *bin) {
	// if bin->hdr.flags & FLAT_FLAG_GOTPIC, then all relocs
	// are already in target order, otherwise they are always be
	return (bin->hdr.flags & FLAT_FLAG_GOTPIC)
		? bin->big_endian
		: true;
}

static void bflt_load_relocs(RzBfltObj *bin) {
	bool big_endian = bflt_reloc_big_endian(bin);

	// got is a single table of 32bit values at the beginning of data
	// to be rebased in-place, and terminated by -1
	if (bin->hdr.flags & FLAT_FLAG_GOTPIC) {
		for (ut64 offset = 0;; offset += 4) {
			ut32 paddr = bin->hdr.data_start + offset;
			if (paddr + 4 > bin->size || paddr + 4 < paddr) {
				break;
			}
			ut32 value;
			if (!rz_buf_read_ble32_at(bin->b, paddr, &value, big_endian)) {
				break;
			}
			if (value == 0xffffffff) {
				break;
			}
			RzBfltReloc *reloc = rz_vector_push(&bin->got_relocs, NULL);
			if (!reloc) {
				break;
			}
			reloc->reloc_paddr = paddr;
			reloc->value_orig = value ? value + BFLT_HDR_SIZE : 0; // uClinux kernel leaves 0 relocs alone
		}
	}

	// addresses of other places to rebase are indirectly given in the reloc table
	for (ut32 i = 0; i < bin->hdr.reloc_count; i++) {
		ut32 table_paddr = bin->hdr.reloc_start + i * 4;
		if (table_paddr + 4 > bin->size || table_paddr + 4 < bin->hdr.reloc_start) {
			break;
		}
		ut32 reloc_paddr;
		if (!rz_buf_read_be32_at(bin->b, table_paddr, &reloc_paddr)) {
			break;
		}
		reloc_paddr += BFLT_HDR_SIZE;
		if (reloc_paddr + 4 < reloc_paddr || reloc_paddr > bin->size) {
			continue;
		}
		ut32 value;
		if (!rz_buf_read_ble32_at(bin->b, reloc_paddr, &value, big_endian)) {
			continue;
		}
		RzBfltReloc *reloc = rz_vector_push(&bin->got_relocs, NULL);
		if (!reloc) {
			break;
		}
		reloc->reloc_paddr = reloc_paddr;
		reloc->value_orig = value + BFLT_HDR_SIZE;
	}
}

static void patch_relocs_in(RzBfltObj *bin, RzVector /*<RzBfltReloc>*/ *relocs) {
	RzBfltReloc *reloc;
	rz_vector_foreach (relocs, reloc) {
		if (!reloc->value_orig) {
			// 0 relocs are not patched (this is some workaround for null pointers in the uClinux kernel)
			continue;
		}
		rz_buf_write_ble32_at(bin->buf_patched,
			reloc->reloc_paddr,
			rz_bflt_paddr_to_vaddr(bin, reloc->value_orig),
			bin->big_endian);
	}
}

static void bflt_patch_relocs(RzBfltObj *bin) {
	bin->buf_patched = rz_buf_new_sparse_overlay(bin->b, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!bin->buf_patched) {
		return;
	}
	patch_relocs_in(bin, &bin->got_relocs);
	patch_relocs_in(bin, &bin->relocs);
	rz_buf_sparse_set_write_mode(bin->buf_patched, RZ_BUF_SPARSE_WRITE_MODE_THROUGH);
}

static bool rz_bflt_init(RzBfltObj *obj, RzBuffer *buf, ut64 baddr, bool big_endian, bool patch_relocs) {
	obj->b = rz_buf_ref(buf);
	obj->size = rz_buf_size(buf);
	obj->big_endian = big_endian;
	rz_vector_init(&obj->relocs, sizeof(RzBfltReloc), NULL, NULL);
	rz_vector_init(&obj->got_relocs, sizeof(RzBfltReloc), NULL, NULL);
	obj->baddr = baddr == UT64_MAX ? 0 : baddr;
	if (!bflt_init_hdr(obj)) {
		return false;
	}
	bflt_load_relocs(obj);
	if (patch_relocs) {
		bflt_patch_relocs(obj);
	}
	return true;
}

RzBfltObj *rz_bflt_new_buf(RzBuffer *buf, ut64 baddr, bool big_endian, bool patch_relocs) {
	RzBfltObj *bin = RZ_NEW0(RzBfltObj);
	if (bin && rz_bflt_init(bin, buf, baddr, big_endian, patch_relocs)) {
		return bin;
	}
	rz_bflt_free(bin);
	return NULL;
}

void rz_bflt_free(RzBfltObj *obj) {
	if (obj) {
		rz_buf_free(obj->b);
		rz_buf_free(obj->buf_patched);
		rz_vector_fini(&obj->relocs);
		rz_vector_fini(&obj->got_relocs);
		RZ_FREE(obj);
	}
}

RzBinAddr *rz_bflt_get_entry(RzBfltObj *bin) {
	RzBinAddr *addr = RZ_NEW0(RzBinAddr);
	if (addr && bin) {
		addr->paddr = bin->hdr.entry;
		addr->vaddr = rz_bflt_get_text_base(bin) + bin->hdr.entry;
	}
	return addr;
}

/// Address to map text segment to
ut64 rz_bflt_get_text_base(RzBfltObj *bin) {
	return bin->baddr;
}

/// Address to map data+bss segment to
ut64 rz_bflt_get_data_base(RzBfltObj *bin) {
	ut64 r = bin->baddr + bin->hdr.data_start + MAX_SHARED_LIBS * sizeof(ut32);
	return r + rz_num_align_delta(r, FLAT_DATA_ALIGN);
}

/// Total size of data+bss
ut64 rz_bflt_get_data_vsize(RzBfltObj *bin) {
	return RZ_MAX(bin->hdr.data_end, bin->hdr.bss_end) - bin->hdr.data_start;
}

ut64 rz_bflt_paddr_to_vaddr(RzBfltObj *bin, ut32 paddr) {
	if (paddr >= bin->hdr.data_start) {
		return rz_bflt_get_data_base(bin) + paddr - bin->hdr.data_start;
	}
	return bin->baddr + paddr;
}
