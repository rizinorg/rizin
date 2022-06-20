// SPDX-FileCopyrightText: 2018 JohnPeng47 <johnpeng47@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include "pe.h"

#define SUB_BIN_DOS    0
#define SUB_BIN_NATIVE 1
#define SUB_BIN_NET    2

#ifndef _INCLUDE_RZ_BIN_PEMIXED_H_
#define _INCLUDE_RZ_BIN_PEMIXED_H_

struct rz_bin_pemixed_obj_t {
	const char *file;
	int size;
	RzBinPEObj *sub_bin_dos;
	RzBinPEObj *sub_bin_native;
	RzBinPEObj *sub_bin_net;

	RzBuffer *b;
};

// static int rz_bin_pemixed_init(struct rz_bin_pemixed_obj_t* bin, RzBinPEObj* pe_bin);
RzBinPEObj *rz_bin_pemixed_init_dos(RzBinPEObj *pe_bin);
RzBinPEObj *rz_bin_pemixed_init_native(RzBinPEObj *pe_bin);
RzBinPEObj *rz_bin_pemixed_extract(struct rz_bin_pemixed_obj_t *bin, int sub_bin);
// static bool check_il_only(ut32 flags);
void *rz_bin_pemixed_free(struct rz_bin_pemixed_obj_t *bin);
struct rz_bin_pemixed_obj_t *rz_bin_pemixed_from_bytes_new(const ut8 *buf, ut64 size);

#endif
