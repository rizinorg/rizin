// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef OMF51_H
#define OMF51_H

#include "rz_type.h"
#include "omf/omf.h"
#include "c166/c166_raw.h"

typedef struct {
	ut16 index;
	ut8 path_n; ///< n max 255, so name array len is 255
	char path[MAX_NAME_LEN];
	ut8 name_n; ///< n max 255, so name array len is 255
	char name[MAX_NAME_LEN];
} OMF_groupdef;

typedef struct {
	ut16 unk1;
	ut8 type;
	ut16 unk2;
	ut16 unk3;
	ut32 addr;
	ut16 unk4;
	ut16 unk5;
	ut16 unk6;
	ut8 n; ///< n max 255, so name array len is 255
	char name[MAX_NAME_LEN];
} OMF_regs;

typedef struct {
	ut16 index;
	ut8 class_index;
	ut8 Type; ///< The ’Type’ field is two bits and specifies the type of the section as follows: 0:=BIT, 1:=DATA, 2:=CODE, 3:=CONST
	bool X; ///< The ’X’ bit is set if the section is of type ’xhuge’ (length 0 ... 16M).
	bool H; ///< The ’H’ bit is set if the section is of type ’huge’ (length 0 ... 64K).
	ut8 bitpos; ///< The ’bitpos’ field has the same meaning as defined in the Siemens OMF166 spec.
	ut8 SecAtr; ///< May be Alignment, always equals 0 (Absolute segment in omf51)
	ut8 SegmentNumber8; ///< The segment number specifies the segment, which is in range 0 to 3 for the 80C166 and 0 to 256 for the 80C167.
	ut32 offset;
	ut32 Seclen;
	bool isXSec; ///< XSECDEF and SECDEF is same records
} OMF51_sections;

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
	RzPVector /*<OMF_regs *>*/ *regs_vec;
	RzPVector /*<OMF_groupdef *>*/ *group_vec;
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
} rz_bin_omf51_obj;

rz_bin_omf51_obj *rz_bin_format_omf51_load(const ut8 *buf, ut64 size);
void rz_bin_format_omf51_fini(rz_bin_omf51_obj *obj);
bool rz_bin_omf51_get_entry(const rz_bin_omf51_obj *obj, RzBinAddr *addr);

#endif // OMF51_H
