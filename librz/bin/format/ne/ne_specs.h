// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef NE_SPECS_H
#define NE_SPECS_H

enum FlagWord {
	NOAUTODATA = 0x0000,
	SINGLEDATA = 0x0001, // shared among instances of the same program
	MULTIPLEDATA = 0x0002, // separate for each instance of the same program
	// additional flags:
	LINKERROR = 0x2000, // Linker error, module cannot load
	LIBMODULE = 0x8000, // if this flag is set, this is a DLL
};

#define ENTRY_SEGMENT_INDICATOR_UNUSED  0
#define ENTRY_SEGMENT_INDICATOR_MOVABLE 0xFF

#define ENTRY_FLAGS_EXPORTED   0x01
#define ENTRY_FLAGS_GLOBALDATA 0x02

#define RELOC_SOURCE_LOW_BYTE    0x00
#define RELOC_SOURCE_SEGMENT     0x02
#define RELOC_SOURCE_FAR_ADDR_32 0x03 /* (32-bit pointer) */
#define RELOC_SOURCE_OFFSET_16   0x05 /* (16-bit offset) */
#define RELOC_SOURCE_FAR_ADDR_48 0x0B /* (48-bit pointer) */
#define RELOC_SOURCE_OFFSET_32   0x0D /* (32-bit offset) */

#define RELOC_TARGET_INTERNAL_REF   0x00
#define RELOC_TARGET_IMPORT_ORDINAL 0x01
#define RELOC_TARGET_IMPORT_NAME    0x02
#define RELOC_TARGET_OS_FIXUP       0x03
#define RELOC_TARGET_MASK           0x03

#define RELOC_FLAGS_ADDITIVE 0x04
#define RELOC_FLAGS_MASK     0xFC

#define OS_FIXUP_TYPE_FIARQQ_FJARQQ 0x0001
#define OS_FIXUP_TYPE_FISRQQ_FJSRQQ 0x0002
#define OS_FIXUP_TYPE_FICRQQ_FJCRQQ 0x0003
#define OS_FIXUP_TYPE_FIERQQ        0x0004
#define OS_FIXUP_TYPE_FIDRQQ        0x0005
#define OS_FIXUP_TYPE_FIWRQQ        0x0006

#define SEGFLAGS_TYPE_CODE 0
#define SEGFLAGS_TYPE_DATA 1
#define SEGFLAGS_TYPE_MASK 0x0007

#define SEGFLAGS_MOVABLE    0x0010
#define SEGFLAGS_PRELOAD    0x0040
#define SEGFLAGS_HAS_RELOCS 0x0100
#define SEGFLAGS_DISCARD    0xF000

#define RESOURCE_FLAGS_MOVEABLE 0x0010
#define RESOURCE_FLAGS_PURE     0x0020
#define RESOURCE_FLAGS_PRELOAD  0x0040

typedef struct ne_seg_relocation_entry_s {
	ut8 source;
	ut8 flags_and_target;
	ut16 source_chain_offset;
	union {
		struct {
			ut8 segment_number; // 0xFF == movable segment, other value == fixed segment
			ut8 zero; // always 0
			ut16 segment_index; // if fixed segment: offset into segment; if movable segment: ordinal number index into Entry Table
		} internal_ref;
		struct {
			ut16 mod_ref_table_index; // index into module reference table
			ut16 proc_name_offset; // offset from start of imported-names table to procedure name string
		} import_name;
		struct {
			ut16 mod_ref_table_index; // index into module reference table
			ut16 ordinal_number; // ordinal number of the procedure (index of sdb entry)
		} import_ordinal;
		struct {
			ut16 os_fixup_type; // see OS_FIXUP_TYPE_*
			ut16 zero; // always 0
		} os_fixup;
	};
} NE_seg_relocation_entry;

/*
 * the actual structure looks like this.
 * typedef struct {
 *    ut8  name_length;
 *    char name[name_length];
 *    ut16 ordinal_number; ///< index into entry table
 * } NE_resident_name_entry;
 *
 * but we simplify it for parsing as we don't cast it.
 */
typedef struct ne_resident_name_entry_s {
	char *name;
	ut16 ordinal_number;
} NE_resident_name_entry;

typedef struct {
	ut8 entry_flags; ///< see ENTRY_FLAGS_*
	ut16 entry_point_offset; ///< entry point offset within segment
} NE_fixed_segment_entry;

typedef struct {
	ut8 entry_flags; ///< see ENTRY_FLAGS_*
	ut16 int3fh; ///< constant value (interrupt opcode)
	ut8 segment_number; ///< number of the movable segment
	ut16 entry_point_offset; ///< entry point offset within segment
} NE_movable_segment_entry;

typedef struct ne_segment_entry_s {
	ut8 segment_indicator; ///< ENTRY_SEGMENT_INDICATOR_*
	union {
		NE_fixed_segment_entry fixed;
		NE_movable_segment_entry movable;
	};
} NE_segment_entry;

typedef struct ne_image_segment_entry_s {
	ut16 sector_base; ///< offset in sectors from beginning of file; offset: sector_base * (1 << neHeader.FileAlnSzShftCnt)
	ut16 seg_bytes; ///< length of segment in file, in bytes. A value of zero indicates that the segment length is 64K, unless the selector offset is also zero.
	ut16 seg_flags; ///< see SEGFLAGS_*
	ut16 min_alloc; ///< A value of zero indicates that the minimum allocation size is 64K
} NE_image_segment_entry;

/* this is a custom structure to link segment to the reloc data. */
typedef struct ne_relocation_entry_s {
	NE_seg_relocation_entry seg_reloc; ///< Actual relocation data
	const NE_image_segment_entry *segment; ///< pointer to NE_image_segment_entry
	char *procedure_name; ///< Resolved procedure name
} NE_relocation_entry;

typedef struct ne_image_nameinfo_entry_s {
	ut16 rnOffset;
	ut16 rnLength;
	ut16 rnFlags;
	ut16 rnID;
	ut16 rnHandle;
	ut16 rnUsage;
} NE_image_nameinfo_entry;

typedef struct ne_image_typeinfo_entry_s {
	ut16 rtTypeID;
	ut16 rtResourceCount;
	ut32 rtReserved;
	NE_image_nameinfo_entry rtNameInfo[];
} NE_image_typeinfo_entry;

typedef struct {
	char sig[2]; ///<  {'N', 'E'}
	ut8 MajLinkerVersion; ///< The major linker version
	ut8 MinLinkerVersion; ///< The minor linker version (also known as the linker revision)
	ut16 EntryTableOffset; ///< Offset of entry table from start of NE_Header
	ut16 EntryTableLength; ///< Length of entry table in bytes
	ut32 FileLoadCRC; ///< 32-bit CRC of entire contents of file
	ut16 FlagWord; ///<  Uses the FlagWord enum
	ut16 AutoDataSegIndex; ///< The automatic data segment index
	ut16 InitHeapSize; ///< The initial local heap size
	ut16 InitStackSize; ///< The initial stack size
	ut16 ipEntryPoint; ///< IP entry point, CS is index into segment table
	ut16 csEntryPoint; ///< CS entry point, CS is index into segment table
	ut32 InitStack; ///< SS:SP initial stack pointer, SS is index into segment table
	ut16 SegCount; ///< Number of segments in segment table
	ut16 ModRefs; ///< Number of module references (DLLs)
	ut16 NoResNamesTabSiz; ///< Size of non-resident names table in bytes
	ut16 SegTableOffset; ///< Offset of segment table from start of NE_Header
	ut16 ResTableOffset; ///< Offset of resources table from start of NE_Header
	ut16 ResidNamTable; ///< Offset of resident names table from start of NE_Header
	ut16 ModRefTable; ///< Offset of module reference table from start of NE_Header
	ut16 ImportNameTable; ///< Offset of imported names table from start of NE_Header
	ut32 OffStartNonResTab; ///< Offset of non-resident names table from start of file (!)
	ut16 MovEntryCount; ///< Count of moveable entry point listed in entry table
	ut16 FileAlnSzShftCnt; ///< File alignment size shift count (0=9(default 512 byte pages))
	ut16 nResTabEntries; ///< Number of resource table entries (often inaccurate!)
	ut8 targOS; ///< Target OS
	ut8 OS2EXEFlags; ///< Other OS/2 flags
	ut16 retThunkOffset; ///< Offset to return thunks or start of gangload area - what is gangload?
	ut16 segrefthunksoff; ///< Offset to segment reference thunks or size of gangload area
	ut16 mincodeswap; ///< Minimum code swap area size
	ut8 expctwinver[2]; ///< Expected windows version (minor first)
} NE_image_header;

#endif
