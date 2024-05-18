// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-FileCopyrightText: 2023 svr <svr.work@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef LE_H
#define LE_H
#include <rz_bin.h>
#include <rz_types.h>
#include <sdbht.h>
#include "le_specs.h"

typedef struct LE_object_s {
	ut32 virtual_size;
	ut32 reloc_base_addr;
	ut32 flags;
	ut32 page_tbl_idx; // The number of the first object page table entry for this object, 1-based
	ut32 page_tbl_entries;
	ut32 reserved;
} LE_object;

typedef struct LE_page_s {
	ut64 paddr;
	ut32 vaddr;
	ut32 psize;
	ut32 vsize;
	ut16 type;
	ut32 obj_num; // 1-base objects entry index
	ut32 le_map_num; // first map corresponding to this page
	ut32 fixup_page_start;
	ut32 fixup_page_end;
} LE_page;

typedef struct LE_map_s {
	RZ_NULLABLE ut8 *vfile_buf_data;
	RZ_NULLABLE RzBuffer *vfile_buf;
	RZ_NULLABLE char *vfile_name;
	ut64 paddr;
	ut32 vaddr;
	ut32 size;
	ut32 vsize;
	ut32 obj_num;
	ut32 first_page_num;
	bool is_physical : 1;
	bool is_obj_last : 1;
} LE_map;

typedef struct LE_entry_s {
	bool is_empty : 1;
	bool is_exported : 1;
	bool is_shared : 1;
	bool is_forwarder : 1;
	bool is_forwarder_import_by_ord : 1;
	bool is_param_dword : 1;
	ut8 param_count; // word or dword count depending on is_param_dword
	ut32 obj_num;
	RZ_BORROW RzBinSymbol *symbol;
} LE_entry;

typedef struct LE_import_s {
	ut16 mod_ord;
	ut32 proc_ord;
	char *proc_name;
	RZ_BORROW RzBinImport *import;
	RZ_BORROW RzBinSymbol *symbol;
} LE_import;

typedef struct LE_reloc_s {
	LE_fixup_type type;
	RZ_NULLABLE RZ_BORROW RzBinSymbol *symbol;
	RZ_NULLABLE RZ_BORROW RzBinImport *import;
	ut32 addend;
	ut32 src_page;
	st16 src_off;
	ut32 trg_obj_num;
	ut32 target_vaddr;
} LE_reloc;

typedef struct rz_bin_le_obj_s {
	ut64 mz_off; /* File offset of the MZ header if present */
	ut64 le_off; /* File offset of the LE header */
	LE_header *header;
	char *modname;
	bool is_le;
	const char *type;
	const char *cpu;
	const char *os;
	const char *arch;
	RZ_BORROW RzBuffer *buf; /* Pointer to RzBuffer of file */
	RzBuffer *buf_patched; /* overlay over the original file with relocs patched */
	LE_object *objects; // contains header->objcnt elements
	LE_page *le_pages; // contains header->mpages elements
	RzVector /*<LE_map>*/ *le_maps;
	RzPVector /*<char *>*/ *imp_mod_names;
	RzList /*<RzBinSymbol *>*/ *symbols;
	RzVector /*<LE_entry>*/ *le_entries;
	RzPVector /*<RzBinImport *>*/ *imports;
	HtPP /*<LE_import *, NULL>*/ *le_import_ht;
	RzList /*<LE_reloc *>*/ *le_relocs;
	RzList /*<LE_reloc *>*/ *le_fixups;
	ut32 reloc_target_map_base;
	ut32 reloc_targets_count;
} rz_bin_le_obj_t;

bool rz_bin_le_check_buffer(RzBuffer *b);
bool rz_bin_le_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb);
void rz_bin_le_destroy(RzBinFile *bf);
RZ_OWN RzPVector /*<RzBinMap *>*/ *rz_bin_le_get_maps(RzBinFile *bf);
RZ_OWN RzPVector /*<RzBinAddr *>*/ *rz_bin_le_get_entry_points(RzBinFile *bf);
RZ_OWN RzPVector /*<RzBinSection *>*/ *rz_bin_le_get_sections(RzBinFile *bf);
RZ_OWN RzPVector /*<RzBinSymbol *>*/ *rz_bin_le_get_symbols(RzBinFile *bf);
RZ_OWN RzPVector /*<RzBinImport *>*/ *rz_bin_le_get_imports(RzBinFile *bf);
RZ_OWN RzPVector /*<char *>*/ *rz_bin_le_get_libs(RzBinFile *bf);
RZ_OWN RzPVector /*<RzBinReloc *>*/ *rz_bin_le_get_relocs(RzBinFile *bf);
RZ_OWN RzPVector /*<RzBinVirtualFile *>*/ *rz_bin_le_get_virtual_files(RzBinFile *bf);

#endif
