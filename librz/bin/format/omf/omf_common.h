// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef OMF_COMMON_H
#define OMF_COMMON_H

#include <rz_util.h>
#include <rz_bin.h>
#include "omf/omf_specs.h"

#define MAX_NAME_LEN UT8_MAX

typedef enum omf_memory_model_t {
	OMF166_MEMORY_MODEL_XLARGE = 0x0, ///< XLarge: 'xhuge' data, 'far' funcs
	OMF166_MEMORY_MODEL_TINY = 0x1, ///< Tiny: program 64K or less
	OMF166_MEMORY_MODEL_SMALL = 0x2, ///< Small: 'near' functions and data
	OMF166_MEMORY_MODEL_COMPACT = 0x3, ///< Compact: 'far' data, 'near' funcs
	OMF166_MEMORY_MODEL_MEDIUM = 0x4, ///< Medium: 'near' data, 'far' funcs
	OMF166_MEMORY_MODEL_LARGE = 0x5, ///< Large: 'far' functions and data
	OMF166_MEMORY_MODEL_HCOMPACT = 0x6, ///< HCompact: 'huge' data, 'near' funcs
	OMF166_MEMORY_MODEL_HLARGE = 0x7, ///< HLarge: 'huge' data, 'far' funcs
} OMF166_MEMORY_MODEL_TYPE;

#define new_pv_and_check2(vec, destructor) \
	if (!((vec) = rz_pvector_new((RzPVectorFree)(destructor)))) \
		return false;

#define new_pv_and_check(vec, destructor, ret) \
	vec = rz_pvector_new((RzPVectorFree)(destructor)); \
	if (!vec) { \
		return ret; \
	}

#define PVEC_FREE(vec) \
	if (vec) { \
		rz_pvector_free(vec); \
	}

/**
 * PEDATA and VECTAB records provides contiguous data, from which a portion of a memory image is
 * to be constructed.
 *
 * ******************************************************
 * * 0xB9 | RecLen | ABS-Address | DatTyp | Data | Chks *
 * ******************************************************
 *
 * The segment number specifies the segment, which is in range 0 to 3 for the
 * 80C166 and 0 to 256 for the 80C167.
 * The ’DatTyp’ field is a byte and may have the following values:
 * 0: BIT
 * 1: DATA
 * 2: CODE
 * 3: CONST
 *
 * Note that DatTyp values 0 and 1 do not apply to the INTVEC record. (VECTAB)
 *
 * The ’Data’ field provides consecutive bytes of vector table image. (VECTAB)
 * The ’Data’ field provides consecutive bytes of the memory image. (PEDATA)
 * The number of bytes are the rest of the record not counting the checksum field.
 */
typedef struct {
	ut32 size; ///< Binary size
	ut8 SegmentNumber8; ///< The segment number specifies the segment, which is in range 0 to 3 for the 80C166 and 0 to 256 for the 80C167.
	bool use32; ///< omf1.1
	ut16 seg_idx; ///< omf1.1
	bool isVector; ///< PEDATA and VECTAB is same records
	/**
	 * The ’Data Type’ field is a byte and may have the following values:
	 * 0: BIT
	 * 1: DATA
	 * 2: CODE
	 * 3: CONST
	 */
	ut8 data_type;
	ut32 offset;
	ut32 paddr;
	ut32 psize;
} OMF_pes;

/**
 * \brief The LINNUM record provides the correspondence between line number of a source
 * program and the associated object code created by a translator.
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
	ut16 fileIndex;
	ut16 LineNumber; ///< gives the line number in range 0 to 32767. The most significant bit is reserved for future use and is always zero.
	ut64 address; ///< Specifies the address of the following line numbers using the base address + offset format.
	ut8 n;
	char filename[MAX_NAME_LEN];
} OMF_linnums;

typedef struct {
	ut16 index;
	char name[MAX_NAME_LEN];
} OMF_lnames;

typedef struct {
	ut16 seg_idx;
	ut16 offset;
} OMF_ledatas;

typedef struct {
	ut16 index; // 51
	ut8 n; ///< n max 255, so name array len is 255
	char name[MAX_NAME_LEN];
	ut32 timestamp;
} OMF_debug_includes;

/**
 * \brief The BLKDEF record provides information about blocks that were defined in the source
 * program input to the tanslator which produced the module.
 *
 * ***************************************************************
 * * 0xB7 | RecLen | BlockBase | BlockInfo | PInfo | TI | ChkSum *
 * ***************************************************************
 *
 * A BLKDEF record will be generated for each procedure and each block that contains variables.
 * The purpose of this information is to specify the live range (scope) of the debug
 * symbol record(s) enclosed by a BLKDEF and a BLKEND record.
 *
 * BLKDEF records may be nested.
 * Each BLKDEF record is matched by a corresponding BLKEND record in the the same nesting level.
 * The maximum nesting is 32 (introduced by the C166 compiler).
 * The sequence of BLKDEF records defines the implicite number of each BLKDEF record.
 * This sequence number may be referred to by a BlockIndex, as may be the case in DEBSYM records.
 */
typedef struct {
	ut16 GroupIndex;
	ut16 SectionIndex;
	ut16 FrameNumber; // (optional) if GroupIndex and SectionIndex equals 0
	ut8 n; ///< Pathname length, n max 255, so name array len is 255
	char name[MAX_NAME_LEN]; ///< is the block name. If the record describes an unnamed block, then a null name is used.
	ut16 BlockOffset16; ///< is a 16 Bit value which is the offset of the first byte of the block with respect to the referent value specified by ’BlockBase’.
	ut16 BlockLength16; ///< this field gives the length of the block in bytes.

	bool PInfoProcedure; ///< is the high order Bit of the first byte. If the bit is set, then the
	///< BLKDEF record was generated from a procedure.
	ut16 TI; ///< The TypeIndex field represents a final type or refers to a
	///< previous NEWTYP record by sequence, depending upon the type index value.
} OMF_blocks;

typedef struct {
	ut16 index;
	bool nopurge; ///< NOPURGE bit; 1 = comment may not be purged from the file
	bool nolist; ///< no list bit; 1 = comment may not be purged from the file
	bool is_filename;
	ut8 n;
	char text[MAX_NAME_LEN]; ///< this field provides the commentary text.
} OMF_coments;

/**
 * The XSECDEF record is almost identical to the OMF166 SECDEF record
 * with minor changes to represent sections which are bigger than 64K.
 *
 * Changes have been made in the ’SecTyp’ field and the ’SecLen’ field, the
 * remaining fields and meanings are left unchanged.
 *
 * **********************************************************
 * * 0xC5 | RecLen | SecTyp | SecAtr | Seclen |    | ChkSum *
 * **********************************************************
 *
 * SecTyp Field:
 * Bit-7 ..... Bit-0
 * *************************
 * * Type | X | H | bitpos *
 * *************************
 * The ’Type’ field is two bits and specifies the type of the section as follows:
 * 0:=BIT, 1:=DATA, 2:=CODE, 3:=CONST
 * The ’X’ bit is set if the section is of type ’xhuge’ (length 0 ... 16M).
 * The ’H’ bit is set if the section is of type ’huge’ (length 0 ... 64K).
 * The ’bitpos’ field has the same meaning as defined in the Siemens OMF166 spec.
 *
 * SecLen-Field:
 * The SecLen field is now a 32 bit value which represents the length of the section.
 * The SecLen field of the OMF166-Secdef record is only 16 Bits.
 */
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
	ut8 n51; ///< name length, n max 255, so name array len is 255
	char name51[MAX_NAME_LEN];
} OMF_sections;

/**
 * LOCSYM, GLBDEF, PUBDEF, DEBSYM records.
 */
typedef struct {
	bool is_data;
	ut32 base; ///< specifies the local address base for the following symbolic formation using the base address format.
	ut8 n; ///< n max 255, so name array len is 255
	char *name;
	char name2[MAX_NAME_LEN]; ///< represents the symbol name
	ut64 size;
	ut16 seg_idx;
	ut32 offset; ///< is a 16 Bit offset of the symbol with respect to the referent value pecified by ’LocBase’.
	ut8 rec_type;
	ut16 ti; ///< the TypeIndex field represents a final type or refers to a previous NEWTYP record by sequence,
		 ///< depending upon the type index value.
	bool V;
	ut8 REP;
	ut8 REP8; ///< a byte specifying the representation value as follows:
	/**
	 * Bit: 7 6 5 4 3 2 1 0
	 * +---+---+---+---+---+---+---+---+
	 * | V | REP | bpos |
	 * +---+---+---+---+---+---+---+---+
	 * V: represents the sign of the value stored in the local symbol offset
	 * ’Offset16’. V=0 means a positive, V=1 a negative value.
	 *
	 * REP: these three bits encode the representation type of the Offset16 field as follows:
	 * 0: BIT - the symbol is a bit symbol. The ’bpos’ field contains the
	 * position of the bit in the bitaddressable word. If V=1, then the
	 * Offset16 field specifies a register (0=R0, 1=R1, 15=R15).
	 * 1: VAR - the symbol is a variable, whose type is specified with the type index.
	 * 2: LAB - the symbol represents a label or procedure.
	 * 3: REGBANK - the symbol represents the name of a register bank. ’Offset16’ is an address relative to segment zero.
	 * 4: INTNO - the symbol represents a symbolic interrupt number. ’Offset16’ is the absolute interrupt number
	 * 5: CONST - the symbol represents the numeric constant given by Offset16.
	 * 6: REGVAR - the symbol represents a register variable.
	 *             The register number is defined by the Offset16 field.
	 *             The type of the variable given by TypeIndex decides the
	 *             interpretation of the register number (WORD or BYTE register).
	 * 7: AUTO - the symbol represents a an automatic variable, which are located on the stack.
	 *             Automatics are relative to R0 with an offset given by Offset16 [R0+Offset16]).
	 */
	ut8 bpos;
	ut8 type51;
	bool is_extdef;
} OMF_symbol;

typedef enum {
	OMF_FILE_TARGET_C166,
	OMF_FILE_TARGET_51,
	OMF_FILE_TARGET_96,
	OMF_FILE_TARGET_NOT_OMF
} OMF_FILE_TARGET_TYPE;

typedef struct {
	RzBuffer *b;
	ut64 size;
	ut8 bits;
	ut64 base_addr;
	ut16 target_id;
	void *target_obj;
	OMF_record *(*load_record)(void *bf);
	bool (*init_internal_storage)(RZ_NONNULL void *target_obj);
	ut8 (*get_bits)(RZ_NONNULL void *target_obj);
	bool (*load_omf_content)(RZ_NONNULL void *target_obj, OMF_record *record, const ut8 *buf, const ut64 global_ct, const size_t buf_size);
	bool (*is_valid_omf_type)(const ut8 type);
	RzStructuredData *(*omf_structure)(RZ_NONNULL const void *target_obj);
	void (*free_all_omf_obj)(RZ_NONNULL void *target_obj);
	bool (*post_init)(RZ_NONNULL const void *target_obj);

	ut16 (*max_record_size)(void);

	RzPVector /*<RzBinSection *>*/ *(*sections)(RZ_NONNULL const void *target_obj);
	RzPVector /*<RzBinMap *>*/ *(*maps)(RZ_NONNULL const void *target_obj);
	RzPVector /*<RzBinSymbol *>*/ *(*symbols)(RZ_NONNULL const void *target_obj);
	RzBinAddr *(*get_entry)(RZ_NONNULL const void *target_obj);
	RzBinInfo *(*info)(RZ_NONNULL const void *target_obj);

	ut64 (*baddr)(RZ_NONNULL const void *target_obj);
} rz_bin_omf_base_obj;

RzBinInfo *omf96_info(RZ_NONNULL const void *target_obj);
ut64 omf96_baddr(RZ_NONNULL const void *target_obj);
ut16 omf96_max_record_size(void);
RzBinAddr *rz_bin_omf96_get_entry(RZ_NONNULL const void *target_obj);
bool rz_bin_checksum_omf_ok(const ut8 *buf, ut64 buf_size);

ut32 get_perm_by_type(ut8 data_type);
ut32 c166_get_perms_from_class(const ut8 class_id);
RZ_IPI OMF_FILE_TARGET_TYPE check_omf_type(RzBuffer *b);
ut8 rz_bin_omf_get_bits(RZ_NONNULL const void *target_obj);

int omf_line_sample_cmp(const void *a, const void *b, void *user);
bool rz_bin_format_omf_load_all_records(RZ_NONNULL rz_bin_omf_base_obj *base_obj, RZ_NONNULL const ut8 *buf, const ut64 size);
RZ_IPI bool omf_check_buffer(RzBuffer *b);
RZ_API ut16 omf_get_idx_offset(RZ_NONNULL const void *src, const size_t buf_size, RZ_NONNULL RZ_INOUT size_t *offset);
RZ_API ut8 c166_memory_model_type(ut8 modinfo);
RZ_API char *c166_get_memory_model(ut8 modinfo);
void omf_linnums_free(void *it);
int omf_cmp_pes(const void *a, const void *b);

#endif // OMF_COMMON_H
