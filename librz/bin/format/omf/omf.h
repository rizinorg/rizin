#ifndef OMF_H_
#define OMF_H_

#include <rz_util.h>
#include <rz_types.h>
#include <rz_bin.h>

#include "omf_specs.h"

typedef struct OMF_record_handler {
	OMF_record record;
	struct OMF_record_handler *next;
} OMF_record_handler;

typedef struct {
	ut32 nb_elem;
	void *elems;
} OMF_multi_datas;

typedef struct OMF_DATA {
	ut64 paddr; // offset in file
	ut64 size;
	ut32 offset;
	ut16 seg_idx;
	struct OMF_DATA *next;
} OMF_data;

// sections return by the plugin are the addr of datas because sections are
// separate on non contiguous block on the omf file
typedef struct {
	ut32 name_idx;
	ut64 size;
	ut8 bits;
	ut64 vaddr;
	OMF_data *data;
} OMF_segment;

typedef struct {
	char *name;
	ut16 seg_idx;
	ut32 offset;
} OMF_symbol;

typedef struct {
	ut8 bits;
	char **names;
	ut32 nb_name;
	OMF_segment **sections;
	ut32 nb_section;
	OMF_symbol **symbols;
	ut32 nb_symbol;
	OMF_record_handler *records;
} rz_bin_omf_obj;

// this value was chosen arbitrarily to made the loader work correctly
// if someone want to implement rellocation for omf he has to remove this
#define OMF_BASE_ADDR 0x1000

bool rz_bin_checksum_omf_ok(const ut8 *buf, ut64 buf_size);
rz_bin_omf_obj *rz_bin_internal_omf_load(const ut8 *buf, ut64 size);
void rz_bin_free_all_omf_obj(rz_bin_omf_obj *obj);
bool rz_bin_omf_get_entry(rz_bin_omf_obj *obj, RzBinAddr *addr);
int rz_bin_omf_get_bits(rz_bin_omf_obj *obj);
int rz_bin_omf_send_sections(RzList *list, OMF_segment *section, rz_bin_omf_obj *obj);
ut64 rz_bin_omf_get_paddr_sym(rz_bin_omf_obj *obj, OMF_symbol *sym);
ut64 rz_bin_omf_get_vaddr_sym(rz_bin_omf_obj *obj, OMF_symbol *sym);

#endif
