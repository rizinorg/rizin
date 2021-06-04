// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef COFF_H
#define COFF_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <ht_up.h>
#include <ht_uu.h>

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
	HtUP /*<symidx, RzBinSymbol>*/ *sym_ht;
	HtUP /*<symidx, RzBinImport>*/ *imp_ht;
	HtUU /*<symidx, ut64>*/ *imp_index; ///< locally-generated indices for imports, in particular for deterministically assigning reloc targets
	ut64 *scn_va;
	ut64 reloc_targets_map_base;
	bool reloc_targets_map_base_calculated;
	RzBuffer *buf_patched; ///< overlay over the original file with relocs patched
	bool relocs_patched;
};

RZ_API bool rz_coff_supported_arch(const ut8 *buf); /* Reads two bytes from buf. */
RZ_API ut64 rz_coff_perms_from_section_flags(ut32 flags);
RZ_API struct rz_bin_coff_obj *rz_bin_coff_new_buf(RzBuffer *buf, bool verbose);
RZ_API void rz_bin_coff_free(struct rz_bin_coff_obj *obj);
RZ_API RzBinAddr *rz_coff_get_entry(struct rz_bin_coff_obj *obj);
RZ_API char *rz_coff_symbol_name(struct rz_bin_coff_obj *obj, void *ptr);

RZ_API ut64 rz_coff_import_index_addr(struct rz_bin_coff_obj *obj, ut64 imp_index);
RZ_API ut64 rz_coff_get_reloc_targets_map_base(struct rz_bin_coff_obj *obj);
RZ_API RzList *rz_coff_get_relocs(struct rz_bin_coff_obj *bin);
RZ_API ut64 rz_coff_get_reloc_targets_vfile_size(struct rz_bin_coff_obj *obj);
RZ_API RZ_BORROW RzBuffer *rz_coff_get_patched_buf(struct rz_bin_coff_obj *bin);

#define RZ_COFF_RELOC_TARGET_SIZE 8

#endif /* COFF_H */
