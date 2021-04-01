// SPDX-FileCopyrightText: 2015 nodepad <nod3pad@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MZ_H
#define MZ_H

#include <rz_types.h>
#include <rz_list.h>
#include <rz_util.h>
#include <rz_bin.h>
#include "mz_specs.h"

struct rz_bin_mz_segment_t {
	ut64 paddr;
	ut64 vaddr;
	ut64 size;
	int last;
};

struct rz_bin_mz_reloc_t {
	ut64 paddr;
	ut64 vaddr;
	int last;
};

struct rz_bin_mz_obj_t {
	const MZ_image_dos_header *dos_header;
	const void *dos_extended_header;
	MZ_image_relocation_entry *relocation_entries;

	int dos_extended_header_size;

	int size;
	int dos_file_size; /* Size of dos file from dos executable header */
	int load_module_size; /* Size of load module: dos_file_size - header size */
	const char *file;
	RzBuffer *b;
	Sdb *kv;
};

RzBinAddr *rz_bin_mz_get_entrypoint(const struct rz_bin_mz_obj_t *bin);
RzList *rz_bin_mz_get_segments(const struct rz_bin_mz_obj_t *bin);
struct rz_bin_mz_reloc_t *rz_bin_mz_get_relocs(const struct rz_bin_mz_obj_t *bin);
void *rz_bin_mz_free(struct rz_bin_mz_obj_t *bin);
struct rz_bin_mz_obj_t *rz_bin_mz_new(const char *file);
struct rz_bin_mz_obj_t *rz_bin_mz_new_buf(RzBuffer *buf);
RzBinAddr *rz_bin_mz_get_main_vaddr(struct rz_bin_mz_obj_t *bin);

#endif
