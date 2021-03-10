// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef COFF_H
#define COFF_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <ht_up.h>

#define COFF_IS_BIG_ENDIAN    1
#define COFF_IS_LITTLE_ENDIAN 0

#include "coff_specs.h"

struct rz_bin_coff_obj {
	struct coff_hdr hdr;
	struct coff_opt_hdr opt_hdr;
	struct coff_scn_hdr *scn_hdrs;
	struct coff_symbol *symbols;

	ut16 target_id; /* TI COFF specific */

	RzBuffer *b;
	size_t size;
	ut8 endian;
	Sdb *kv;
	bool verbose;
	HtUP *sym_ht;
	HtUP *imp_ht;
	ut64 *scn_va;
};

bool rz_coff_supported_arch(const ut8 *buf); /* Reads two bytes from buf. */
struct rz_bin_coff_obj *rz_bin_coff_new_buf(RzBuffer *buf, bool verbose);
void rz_bin_coff_free(struct rz_bin_coff_obj *obj);
RzBinAddr *rz_coff_get_entry(struct rz_bin_coff_obj *obj);
char *rz_coff_symbol_name(struct rz_bin_coff_obj *obj, void *ptr);

#endif /* COFF_H */
