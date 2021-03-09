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

struct bflt_hdr {
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
	ut32 filler[5];
};

//typedef reloc_struct_t

struct reloc_struct_t {
	ut32 addr_to_patch;
	ut32 data_offset;
};

struct rz_bin_bflt_obj {
	struct bflt_hdr *hdr;
	struct reloc_struct_t *reloc_table;
	struct reloc_struct_t *got_table;
	RzBuffer *b;
	ut8 endian;
	size_t size;
	uint32_t n_got;
};

#define BFLT_HDR_SIZE      sizeof(struct bflt_hdr)
#define VALID_GOT_ENTRY(x) (x != 0xFFFFFFFF)

RzBinAddr *rz_bflt_get_entry(struct rz_bin_bflt_obj *bin);
struct rz_bin_bflt_obj *rz_bin_bflt_new_buf(RzBuffer *buf);
void rz_bin_bflt_free(struct rz_bin_bflt_obj *obj);

#endif
