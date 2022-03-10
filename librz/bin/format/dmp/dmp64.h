// SPDX-FileCopyrightText: 2020 abcSup <zifan.tan@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DMP64_H
#define DMP64_H

#include <rz_util.h>

#include "dmp_specs.h"

typedef struct {
	ut64 start;
	ut64 file_offset;
	ut64 size;
} dmp_page_desc;

typedef struct {
	char *file;
	ut32 size;
	ut32 timestamp; // hex of timestamp concatenated with hex of size is used to download the file from a ms symbol server
	ut64 base;
} dmp_driver_desc;

struct rz_bin_dmp64_obj_t {
	dmp64_header *header;
	dmp_bmp_header *bmp_header;
	dmp64_triage *triage64_header;

	dmp_p_memory_run *runs;
	ut8 *bitmap;
	ut64 dtb;
	RzList *pages;
	RzList *datablocks;
	RzList *drivers;

	RzBuffer *b;
	int size;
	Sdb *kv;
};

void rz_bin_dmp64_free(struct rz_bin_dmp64_obj_t *obj);
struct rz_bin_dmp64_obj_t *rz_bin_dmp64_new_buf(RzBuffer *buf);
const char *rz_bin_dmp64_bugcheckcode_as_str(ut32 BugCheckCode);

#endif /* DMP64_H */
