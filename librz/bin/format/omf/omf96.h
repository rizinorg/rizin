// SPDX-FileCopyrightText: 2015 ampotos <mercie_i@epitech.eu>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef OMF_H_
#define OMF_H_

#include <rz_util.h>
#include <rz_types.h>
#include <rz_bin.h>
#include "omf_specs.h"
#include "omf_common.h"

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
	ut8 type;
	bool is_data;
	bool is_segment;
	struct OMF_DATA *next;
} OMF_data;

// sections return by the plugin are the addr of datas because sections are
// separate on non contiguous block on the omf file
typedef struct {
	ut32 index;
	ut32 name_idx;
	ut64 size;
	ut8 bits;
	ut64 vaddr;
	ut8 type;
	OMF_data *data;
} OMF_segment;

typedef struct {
	ut8 index;
	ut8 seg_attr;
	ut8 seg_alignment;
	ut8 seg_combination;
	bool seg_b;
	bool seg_p;
	ut32 seg_length;
	// ut64 seg_length;
	ut16 seg_name_idx;
	ut16 class_name_idx;
	ut16 overlay_name_idx;
	ut16 frame_number;
	ut32 offset;
	ut32 paddr;
	ut8 bits;
	bool in_group;
	ut64 vaddr;
} OMF1_1_sections;

typedef struct {
	ut16 locat;
	/**
	 * mode
	 * M=1 for segment-relative fixups,
	 * M=0 for self-relative fixups.
	 */
	bool mode;
	/**
	 * Is a 4-bit field that determines what type of LOCATION is to be fixed up
	 */
	ut8 location;
	/**
	 * Data Record Offset
	 * Indicates the position of the LOCATION to be fixed up in
	 * the LEDATA or LIDATA record immediately preceding the FIXUPP record.
	 * This offset indicates either a byte in the Data Bytes field of
	 * an LEDATA record or a data byte in the Content field of a Data Block
	 * field in an LIDATA record.
	 */
	ut32 data_record_offset;
	ut8 fix_data;
	bool F;
	ut8 Frame;
	bool T;
	bool P;
	ut8 Targt;
	ut32 targdisp;
	ut8 ledata_index;
	ut8 ledata_seg_index;
	ut8 Frame_Datum;
	ut8 Target_Datum;
} OMF1_1_relocs;

/**
 * \brief The DEPLST record is used to describe the dependency list of the module.
 * This information is used by the automatic project maintenance utility AutoMAKE for recreation of projects.
 *
 * ******************************************
 * * 0x70 | RecLen | Info | ChkS *          *
 * ******************************************
 *
 * The DEPLST records describes the components, which the current module
 * consist of. The current module may be one single object file or a completely
 * bound application consisting of many object files.
 *
 * The Info field delivers all information necessary to recreate one or more
 * components of the module and has the follwing format:
 *
 * | iTyp | Mark8 | Time32 | Name(s)          |
 * | ---- | ----- | ------ | ---------------- |
 * | 0x00 | mark8 | time32 | Path_OutputFile  |
 * | 0x01 | mark8 | time32 | Path_InputFile   |
 * | 0x02 | mark8 | time32 | Path_IncludeFile |
 * | 0x03 | mark8 | time32 | Path_CommandFile |
 * | 0x04 | mark8 | time32 | ObjInputFile     |
 * | 0xFF |       |        | Invocation_Line  |
 */
typedef struct {
	ut16 index;
	ut8 mark; ///< Byte, required to be zero.
	ut32 timestamp; ///< File creation date in Microsoft’s ’fstat()’ format.
	ut8 n; ///< Pathname length, n max 255, so name array len is 255
	char pathname[MAX_NAME_LEN]; ///< specifies the Pathname of one file. In case of iTyp 4, more than one pathname may be specified.
} OMF_deplsts;

/**
 * \brief The REGMSK is used to describe the register usage of one or more functions. Note
 * that this record is created only by the C166 compiler and updated by the linker
 * L166. The record is used to perform apllication wide register optimization by
 * recoloring registers use in functions by means of retranslations.
 *
 * ```
 * ****************************************
 * * 0x72 | RecLen | RegMask [...] | Chks *
 * ****************************************
 * ```
 * One RegMsk-Record may contain zero, one or more RegMask descriptors. The
 * layout of the RegMask field is as follows:
 *
 * ```
 * +------+-------+-----+
 * | E8 | R16 | N |
 * +------+-------+-----+
 * ```
 *
 * ```
 * **************************************************************
 * * 0x94 | RecLen | AddressBase | LinNum16 | Offset16 | ChkSum *
 * **************************************************************
 *                               |                     |
 *                               +-----> repeated <----+
 * ```
 *
 * Since several modules may be linked together to form an output module, the line
 * numbers have to be associated to some source or list file. This file is identified
 * using a comment record with comment type ’K’. The comment record is
 * preceeded by a THEADR record which signals the start of a module within the
 * object file.
 */
typedef struct {
	ut16 index;
} OMF_regmsks;

typedef struct {
	ut16 index;
	ut8 count;
	ut32 sections[MAX_NAME_LEN];
	ut32 vaddr;
} OMF_group;

typedef struct {
	ut16 type_index;
	ut8 n;
	char name[MAX_NAME_LEN];
	ut8 record_type;
} OMF_extdef;

typedef struct {
	ut8 bits;
	ut64 base_addr;
	ut8 modinfo;
	char **names;
	ut32 nb_name;
	OMF_segment **sections;
	int SEC_INDEX;
	ut32 nb_section;
	char source_filename[MAX_NAME_LEN];
	OMF_record_handler *records;
	RzPVector /*<OMF_lnames *>*/ *lnames_vec;
	RzPVector /*<OMF_pes *>*/ *pe_vec;
	RzPVector /*<OMF_coments *>*/ *coments_vec;
	RzPVector /*<OMF_linnums *>*/ *linnums_vec;
	RzPVector /*<OMF_symbol *>*/ *symbols_vec;
	RzPVector /*<OMF_extdef *>*/ *extdef_vec;
	RzPVector /*<OMF_group *>*/ *groups_vec;
	RzPVector /*<OMF1_1_sections *>*/ *sections_vec;
	RzPVector /*<OMF1_1_relocs *>*/ *relocs_vec;
} rz_bin_omf96_obj;

typedef struct {
	ut8 index;
	ut8 descr_type;
	void *data;
} OMF_typedata;

// this value was chosen arbitrarily to made the loader work correctly
// if someone want to implement rellocation for omf he has to remove this
#define OMF166_BASE_ADDR 0x00

#define CPUCON1_NAME        "CPUCON1"
#define SP_RESET_VALUE      0xFC00
#define CPUCON1_RESET_VALUE 0x0000

#define SEGMENT_OFFSET(seg, offset) \
	(0x10000 + ((seg << 4) + offset))

#define SEGMENT_OFFSET1(seg, offset) \
	(0x10000 + ((seg << 16) | offset))

#define SEGMENT_OFFSET16(seg, offset) \
	((seg << 16) | offset)

bool rz_bin_format_omf96_init_internal_storage(RZ_NONNULL void *target_obj);
rz_bin_omf_base_obj *rz_bin_format_omf_load(const ut8 *buf, ut64 size);
const char *omf96_seg_alignment_desc(const ut8 type);
const char *omf96_seg_combination_desc(const ut8 type);
void rz_bin_free_all_omf96_obj(RZ_NONNULL void *target_obj);
bool rz_bin_omf_get_entry(const rz_bin_omf96_obj *obj, RzBinAddr *addr);
ut8 rz_bin_omf96_get_bits(RZ_NONNULL void *target_obj);
ut64 rz_bin_omf_get_vaddr_sym(const rz_bin_omf96_obj *obj, const OMF_symbol *sym);
bool rz_bin_format_omf96_load_omf_content(RZ_NONNULL void *target_obj, OMF_record *record, const ut8 *buf, const ut64 global_ct, const size_t buf_size);
bool omf_is_valid_omf96_type(const ut8 type);
RzStructuredData *omf96_structure(RZ_NONNULL const void *target_obj);
bool rz_bin_format_omf96_post_init(RZ_NONNULL const void *target_obj);
RzPVector /*<RzBinSection *>*/ *omf96_sections(RZ_NONNULL const void *target_obj);
RzPVector /*<RzBinSection *>*/ *omf96_maps(RZ_NONNULL const void *target_obj);
RzPVector /*<RzBinSection *>*/ *omf96_symbols(RZ_NONNULL const void *target_obj);

const char *get_data_type(const ut8 data_type);
ut8 fixup_location_bits(const ut8 type);
ut64 omf_align_to_bytes(const ut8 seg_alignment);

ut64 rz_bin_omf96_get_paddr_sym(RZ_NONNULL const void *target_obj, const ut16 symbol_seg_idx, const ut32 symbol_offset);

#endif
