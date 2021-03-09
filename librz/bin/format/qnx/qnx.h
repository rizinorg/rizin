// SPDX-FileCopyrightText: 2019 deepakchethan <deepakchethan@outlook.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _QNX_H
#define _QNX_H

#include "qnx_specs.h"

#include <rz_util.h>
#include <rz_lib.h>
#include <rz_types.h>
#include <rz_bin.h>

enum {
	LMF_HEADER_REC = 0,
	LMF_COMMENT_REC,
	LMF_LOAD_REC,
	LMF_FIXUP_REC,
	LMF_8087_FIXUP_REC,
	LMF_IMAGE_END_REC,
	LMF_RESOURCE_REC,
	LMF_RW_END_REC,
	LMF_LINEAR_FIXUP_REC
};

RZ_PACKED(
	typedef struct lmf_record {
		ut8 rec_type;
		ut8 reserved; // must be 0
		ut16 data_nbytes; // size of the data record after this.
		ut16 spare; // must be 0
	})
lmf_record;

RZ_PACKED(
	typedef struct lmf_data {
		ut16 segment;
		ut32 offset;
	})
lmf_data;

RZ_PACKED(
	typedef struct lmf_header {
		ut16 version;
		ut16 cflags;
		ut16 cpu; // 86,186,286,386,486
		ut16 fpu; // 0, 87,287,387
		ut16 code_index; // segment of code start;
		ut16 stack_index; // segment to put the stack
		ut16 heap_index; // segment to start DS at.
		ut16 argv_index; // segment to put argv & environment.
		ut16 spare2[4]; // must be zero;
		ut32 code_offset; // starting offset of code.
		ut32 stack_nbytes; // stack size
		ut32 heap_nbytes; // initial size of heap (optional).
		ut32 image_base; // starting address of image
		ut32 spare3[2];
	})
lmf_header;

RZ_PACKED(
	typedef struct lmf_eof {
		ut8 spare[6];
	})
lmf_eof;

/* values for the res_type field in the lmf_resource structure */
enum {
	RES_USAGE = 0
};

RZ_PACKED(
	typedef struct lmf_resource {
		ut16 res_type;
		ut16 spare[3];
	})
lmf_resource;

RZ_PACKED(
	typedef struct lmf_rw_end {
		ut16 verify;
		ut32 signature;
	})
lmf_rw_end;

RZ_PACKED(
	typedef struct {
		Sdb *kv;
		lmf_header lmfh;
		RzList *fixups;
		RzList *sections;
		lmf_rw_end rwend;
	})
QnxObj;

#endif