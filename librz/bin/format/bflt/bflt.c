// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
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
#include <rz_types.h>

#include "bflt.h"

#define MAX_SHARED_LIBS 1 // this may be 4 depending on kernel config
#define FLAT_DATA_ALIGN 0x20

static bool bflt_parse_hdr(RzBuffer *buf, ut64 off, RzBfltHdr *h, bool big_endian) {
	return rz_buf_read_offset(buf, &off, (ut8 *)h->magic, sizeof(h->magic)) &&
		rz_buf_read_ble32_offset(buf, &off, &h->rev, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->entry, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->data_start, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->data_end, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->bss_end, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->stack_size, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->reloc_start, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->reloc_count, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->flags, big_endian) &&
		rz_buf_read_ble32_offset(buf, &off, &h->build_date, big_endian) &&
		rz_buf_read_offset(buf, &off, (ut8 *)h->padding, sizeof(h->padding));
}

static bool bflt_init_hdr(RzBfltObj *bin) {
	if (!bflt_parse_hdr(bin->b, 0, &bin->hdr, true)) {
		return false;
	} else if (bin->hdr.rev != FLAT_VERSION) {
		RZ_LOG_WARN("only bFLT v4 is supported! This file has version %" PFMT32u "\n", bin->hdr.rev);
		return false;
	} else if (bin->hdr.flags & FLAT_FLAG_GZIP || bin->hdr.flags & FLAT_FLAG_GZDATA) {
		RZ_LOG_WARN("this bFLT file is compressed. This is not (yet) supported.\n");
	}
	return true;
}

static bool bflt_reloc_big_endian(RzBfltObj *bin) {
	// if bin->hdr.flags & FLAT_FLAG_GOTPIC, then all relocs
	// are already in target order, otherwise they are always be
	return (bin->hdr.flags & FLAT_FLAG_GOTPIC) ? bin->big_endian : true;
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
			if (!rz_buf_read_ble32_at(bin->b, paddr, &value, bin->big_endian)) {
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

static void bflt_guess_arch(RzBuffer *buf, ut64 entry, const char **arch, bool *big_endian) {
	*arch = "arm";
	*big_endian = false;

	ut8 code[4] = { 0 };
	if (rz_buf_read_at(buf, entry, code, sizeof(code)) != sizeof(code)) {
		return;
	}

#define IS_BYTE(i, b, m)                           ((code[i] & m) == b)
#define IS_1_BYTES(b0, m0)                         IS_BYTE(0, b0, m0)
#define IS_2_BYTES(b0, m0, b1, m1)                 (IS_BYTE(0, b0, m0) && IS_BYTE(1, b1, m1))
#define IS_4_BYTES(b0, m0, b1, m1, b2, m2, b3, m3) (IS_BYTE(0, b0, m0) && IS_BYTE(1, b1, m1) && IS_BYTE(2, b2, m2) && IS_BYTE(3, b3, m3))

	if (IS_2_BYTES(0x20, 0xf1, 0x00, 0x40 /* move.l  */) ||
		IS_2_BYTES(0x20, 0xf1, 0x40, 0x40 /* movea.l */) ||
		IS_2_BYTES(0x30, 0xf1, 0x40, 0x40 /* move.w  */) ||
		IS_2_BYTES(0x48, 0xff, 0xe0, 0xff /* movem.l */) ||
		IS_2_BYTES(0x4e, 0xff, 0x50, 0xf8 /* link.w  */) ||
		IS_2_BYTES(0x90, 0xf0, 0x80, 0xc0 /* sub.l   */) ||
		IS_2_BYTES(0x90, 0xf0, 0x40, 0xc0 /* sub.w   */) ||
		IS_2_BYTES(0x91, 0xf1, 0x80, 0xa0 /* suba.l  */) ||
		IS_2_BYTES(0x90, 0xf1, 0x80, 0xa0 /* suba.w  */) ||
		IS_1_BYTES(0x70, 0xff /*             moveq   */)) {
		*arch = "m68k";
		*big_endian = true;
		return;
	} else if (IS_4_BYTES(0xe1, 0xfd, 0xa0, 0xff, 0x00, 0x00, 0x00, 0x00 /*  mov  */) ||
		IS_4_BYTES(0xe9, 0xfd, 0x2d, 0xff, 0x00, 0x00, 0x00, 0x00 /*         push */)) {
		// it's arm32:be
		*big_endian = true;
		return;
	}
	// it's arm32:le

#undef IS_BYTE
#undef IS_1_BYTES
#undef IS_2_BYTES
#undef IS_4_BYTES
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
	bflt_guess_arch(obj->b, 0x44, &obj->arch, &obj->big_endian);
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
