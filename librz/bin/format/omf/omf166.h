// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef OMF166_H
#define OMF166_H

#include "rz_type.h"
#include "omf/omf.h"
#include "c166/c166_raw.h"

typedef struct {
	ut8 bits;
	ut64 base_addr;
	C16xCpuType cpu;
	// ut64 isr_table[128];
	// ut8 isr_count;
	ut8 modinfo;
	int TI_INDEX;
	int SEC_INDEX;
	RzTypeDB *typedb;
	HtUP /*<OMF_type *>*/ *ht_types;
	RzPVector /*<OMF_debug_includes *>*/ *includes_vec;
	RzPVector /*<OMF_ledatas *>*/ *ledatas_vec;
	RzPVector /*<OMF_lnames *>*/ *lnames_vec;
	RzPVector /*<OMF_deplsts *>*/ *deplsts_vec;
	RzPVector /*<OMF_linnums *>*/ *linnums_vec;
	RzPVector /*<OMF_regmsks *>*/ *regmsks_vec;
	RzPVector /*<OMF_coments *>*/ *coments_vec;
	RzPVector /*<OMF_sections *>*/ *sections_vec;
	RzPVector /*<OMF_symbol *>*/ *symbols_vec;
	RzPVector /*<OMF_blocks *>*/ *blocks_vec;
	RzPVector /*<OMF_pes *>*/ *pe_vec;
	RzVector /*<ut64>*/ *interrupts;
	ut32 nb_symbol;
} rz_bin_omf166_obj;

RZ_API const char *name_of_ti(const rz_bin_omf166_obj *obj, ut16 ti_index);
rz_bin_omf166_obj *rz_bin_format_omf166_load(const ut8 *buf, ut64 size);
void rz_bin_format_omf166_fini(rz_bin_omf166_obj *obj);
void rz_bin_free_all_omf166_obj(rz_bin_omf166_obj *obj);
bool rz_bin_omf166_get_entry(const rz_bin_omf166_obj *obj, RzBinAddr *addr);
ut64 rz_bin_omf166_get_paddr_sym(rz_bin_omf166_obj *obj, OMF_symbol *sym);
ut64 rz_bin_omf166_get_vaddr_sym(rz_bin_omf166_obj *obj, OMF_symbol *sym);
const char *rz_bin_omf166_get_module_information(rz_bin_omf166_obj *obj);

#endif // OMF166_H
