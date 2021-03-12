// SPDX-FileCopyrightText: 2020 abcSup <zifan.tan@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DMP64_H
#define DMP64_H

#include <rz_util.h>

#include "dmp_specs.h"

typedef struct {
	ut64 start;
	ut64 file_offset;
} dmp_page_desc;

struct rz_bin_dmp64_obj_t {
	dmp64_header *header;
	dmp_bmp_header *bmp_header;

	dmp_p_memory_run *runs;
	ut8 *bitmap;
	ut64 dtb;
	RzList *pages;

	RzBuffer *b;
	int size;
	Sdb *kv;
};

void rz_bin_dmp64_free(struct rz_bin_dmp64_obj_t *obj);
struct rz_bin_dmp64_obj_t *rz_bin_dmp64_new_buf(RzBuffer *buf);

#endif /* DMP64_H */
