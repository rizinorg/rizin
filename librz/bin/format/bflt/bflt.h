// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2016 Oscar Salvador <osalvador.vilardaga@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef BFLT_H
#define BFLT_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

/* Version 4 */
#define FLAT_VERSION     0x00000004L
#define FLAT_FLAG_RAM    0x1 /* load program entirely into RAM */
#define FLAT_FLAG_GOTPIC 0x2 /* program is PIC with GOT */
#define FLAT_FLAG_GZIP   0x4 /* all but the header is compressed */
#define FLAT_FLAG_GZDATA 0x8 /* only data/relocs are compressed (for XIP) */
#define FLAT_FLAG_KTRACE 0x10 /* output useful kernel trace for debugging */

typedef struct rz_bflt_hdr_t {
	char magic[4];
	ut32 rev;
	ut32 entry;
	ut32 data_start;
	ut32 data_end;
	ut32 bss_end;
	ut32 stack_size;
	ut32 reloc_start;
	ut32 reloc_count;
	ut32 flags;
	ut32 build_date;
	ut8 padding[20];
} RzBfltHdr;

typedef struct rz_bflt_reloc_t {
	ut32 reloc_paddr; ///< where to patch, offset from the beginning of the file
	ut32 value_orig; ///< original value at that address
} RzBfltReloc;

typedef struct rz_bflt_obj_t {
	RzBfltHdr hdr;
	RzVector /*<RzBfltReloc>*/ relocs;
	RzVector /*<RzBfltReloc>*/ got_relocs;
	RzBuffer *b;
	RzBuffer *buf_patched; ///< overlay over the original file with relocs patched
	ut64 baddr;
	bool big_endian;
	const char *arch;
	size_t size;
	uint32_t n_got;
} RzBfltObj;

#define BFLT_HDR_SIZE sizeof(RzBfltHdr)

RzBfltObj *rz_bflt_new_buf(RzBuffer *buf, ut64 baddr, bool big_endian, bool patch_relocs);
void rz_bflt_free(RzBfltObj *obj);
RzBinAddr *rz_bflt_get_entry(RzBfltObj *bin);
ut64 rz_bflt_get_text_base(RzBfltObj *bin);
ut64 rz_bflt_get_data_base(RzBfltObj *bin);
ut64 rz_bflt_get_data_vsize(RzBfltObj *bin);
ut64 rz_bflt_paddr_to_vaddr(RzBfltObj *bin, ut32 paddr);

#endif
