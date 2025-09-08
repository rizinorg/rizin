// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef COFF_H
#define COFF_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_util/ht_up.h>
#include <rz_util/ht_uu.h>

#include "coff_specs.h"

struct rz_bin_coff_obj {
	struct coff_hdr hdr;
	struct coff_opt_hdr opt_hdr;
	RzVector /*<struct coff_scn_hdr>*/ *scn_hdrs;
	RzVector /*<struct coff_symbol>*/ *symbols;

	ut16 target_id; /* TI COFF specific */

	RzBuffer *b;
	size_t size;
	bool big_endian;
	Sdb *kv;
	HtUP /*<symidx, RzBinSymbol>*/ *sym_ht;
	HtUP /*<symidx, RzBinImport>*/ *imp_ht;
	HtUU /*<symidx, ut64>*/ *imp_index; ///< locally-generated indices for imports, in particular for deterministically assigning reloc targets
	ut64 *scn_va;
	ut64 reloc_targets_map_base;
	bool reloc_targets_map_base_calculated;
	RzBuffer *buf_patched; ///< overlay over the original file with relocs patched
	bool relocs_patched;
};

RZ_API bool rz_coff_supported_arch(RzBuffer *b);
RZ_API ut64 rz_coff_perms_from_section_flags(ut32 flags);
RZ_API struct rz_bin_coff_obj *rz_bin_coff_new_buf(RzBuffer *buf);
RZ_API void rz_bin_coff_free(struct rz_bin_coff_obj *obj);
RZ_API RzBinAddr *rz_coff_get_entry(struct rz_bin_coff_obj *obj);
RZ_API RZ_OWN char *rz_coff_symbol_name(RZ_NONNULL struct rz_bin_coff_obj *obj, RZ_NULLABLE const ut8 *ptr);

RZ_API ut64 rz_coff_import_index_addr(struct rz_bin_coff_obj *obj, ut64 imp_index);
RZ_API ut64 rz_coff_get_reloc_targets_map_base(struct rz_bin_coff_obj *obj);
RZ_API RzPVector /*<RzBinReloc *>*/ *rz_coff_get_relocs(struct rz_bin_coff_obj *bin);
RZ_API ut64 rz_coff_get_reloc_targets_vfile_size(struct rz_bin_coff_obj *obj);
RZ_API RZ_BORROW RzBuffer *rz_coff_get_patched_buf(struct rz_bin_coff_obj *bin);

#define RZ_COFF_RELOC_TARGET_SIZE 8

#endif /* COFF_H */
