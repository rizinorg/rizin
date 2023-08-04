// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-FileCopyrightText: 2023 svr <svr.work@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef LE_SPECS_H
#define LE_SPECS_H
#include <rz_types.h>

typedef enum {
	ENTRY_EMPTY = 0,
	ENTRY_16 = 1,
	ENTRY_CALLGATE = 2,
	ENTRY_32 = 3,
	ENTRY_FORWARDER = 4,
} LE_entry_type;

typedef enum {
	LE_RT_POINTER = 1, /* mouse pointer shape */
	LE_RT_BITMAP = 2, /* bitmap */
	LE_RT_MENU = 3, /* menu template */
	LE_RT_DIALOG = 4, /* dialog template */
	LE_RT_STRING = 5, /* string tables */
	LE_RT_FONTDIR = 6, /* font directory */
	LE_RT_FONT = 7, /* font */
	LE_RT_ACCELTABLE = 8, /* accelerator tables */
	LE_RT_RCDATA = 9, /* binary data */
	LE_RT_MESSAGE = 10, /* error msg tables */
	LE_RT_DLGINCLUDE = 11, /* dialog include file name */
	LE_RT_VKEYTBL = 12, /* key to vkey tables */
	LE_RT_KEYTBL = 13, /* key to UGL tables */
	LE_RT_CHARTBL = 14, /* glyph to character tables */
	LE_RT_DISPLAYINFO = 15, /* screen display information */
	LE_RT_FKASHORT = 16, /* function key area short form */
	LE_RT_FKALONG = 17, /* function key area long form */
	LE_RT_HELPTABLE = 18, /* Help table for Cary Help manager */
	LE_RT_HELPSUBTABLE = 19, /* Help subtable for Cary Help manager */
	LE_RT_FDDIR = 20, /* DBCS uniq/font driver directory */
	LE_RT_FD = 21, /* DBCS uniq/font driver */
} LE_resource_type;

// This bit signifies that additional information is contained in the linear EXE module
// and will be used in the future for parameter type checking.
#define E_PARAM_TYPING_PRESENT 0x80
#define E_EXPORTED             1
#define E_SHARED               2
#define E_PARAM_COUNT_SHIFT    3
#define E_IMPORT_BY_ORD        1

#define F_SOURCE_TYPE_MASK 0xF
#define F_SOURCE_ALIAS     0x10
#define F_SOURCE_LIST      0x20

typedef enum {
	FIXUP_BYTE = 0,
	FIXUP_UNDEF1 = 1,
	FIXUP_SEL16 = 2,
	FIXUP_SEL16_OFF16 = 3, // 16:16
	FIXUP_UNDEF2 = 4,
	FIXUP_OFF16 = 5,
	FIXUP_SEL16_OFF32 = 6, // 16:32
	FIXUP_OFF32 = 7,
	FIXUP_REL32 = 8,
} LE_fixup_type;

#define F_TARGET_TYPE_MASK 0x3
#define F_TARGET_ADDITIVE  0x4
#define F_TARGET_CHAIN     0x8
#define F_TARGET_OFF32     0x10 // Else 16
#define F_TARGET_ADD32     0x20 // Else 16
#define F_TARGET_ORD16     0x40 // Else 8
#define F_TARGET_ORD8      0x80 // Else 16

typedef enum {
	TARGET_INTERNAL = 0,
	TARGET_IMPORT_ORDINAL = 1,
	TARGET_IMPORT_NAME = 2,
	TARGET_INTERNAL_ENTRY = 3,
} LE_fixup_target_type;

#define O_READABLE    1
#define O_WRITABLE    1 << 1
#define O_EXECUTABLE  1 << 2
#define O_RESOURCE    1 << 3
#define O_DISCARTABLE 1 << 4
#define O_SHARED      1 << 5
#define O_PRELOAD     1 << 6
#define O_INVALID     1 << 7
#define O_ZEROED      1 << 8
#define O_RESIDENT    1 << 9
#define O_CONTIGUOUS  O_RESIDENT | O_ZEROED
#define O_LOCKABLE    1 << 10
#define O_RESERVED    1 << 11
#define O_ALIASED     1 << 12
#define O_BIG_BIT     1 << 13
#define O_CODE        1 << 14
#define O_IO_PRIV     1 << 15

typedef enum {
	PAGE_LEGAL = 0,
	PAGE_ITERATED = 1,
	PAGE_INVALID = 2,
	PAGE_ZEROED = 3,
	PAGE_RANGE = 4,
	PAGE_COMPRESSED = 5,
} LE_page_type;

#define M_SINGLE_DATA         1
#define M_PP_LIB_INIT         4
#define M_SYS_DLL             8 // No internal fixups
#define M_INTERNAL_FIXUP      0x10
#define M_EXTERNAL_FIXUP      0x20
#define M_PM_WINDOWING_INCOMP 0x100 // Fullscreen only
#define M_PM_WINDOWING_COMPAT 0x200
#define M_USES_PM_WINDOWING   (M_PM_WINDOWING_INCOMP | M_PM_WINDOWING_COMPAT)
#define M_NOT_LOADABLE        0x2000
#define M_TYPE_MASK           0x38000
#define M_TYPE_EXE            0
#define M_TYPE_DLL            0x08000
#define M_TYPE_PM_DLL         0x10000
#define M_TYPE_PDD            0x20000 // Physical Device Driver
#define M_TYPE_VDD            0x28000 // Virtual Device Driver
#define M_MP_UNSAFE           0x80000
#define M_PP_LIB_TERM         0x40000000

typedef struct LE_header_s { /* New 32-bit .EXE header */
	ut8 magic[2]; /* Magic number MAGIC */
	ut8 border; /* The byte ordering for the .EXE */
	ut8 worder; /* The word ordering for the .EXE */
	ut32 level; /* The EXE format level for now = 0 */
	ut16 cpu; /* The CPU type */
	ut16 os; /* The OS type */
	ut32 ver; /* Module version */
	ut32 mflags; /* Module flags */
	ut32 mpages; /* Module # pages */
	ut32 startobj; /* Object # for instruction pointer */
	ut32 eip; /* Extended instruction pointer */
	ut32 stackobj; /* Object # for stack pointer */
	ut32 esp; /* Extended stack pointer */
	ut32 pagesize; /* .EXE page size */
	union {
		ut32 pageshift; /* Page alignment shift unless LE */
		ut32 le_last_page_size;
	};
	ut32 fixupsize; /* Fixup section size */
	ut32 fixupsum; /* Fixup section checksum */
	ut32 ldrsize; /* Loader section size */
	ut32 ldrsum; /* Loader section checksum */
	ut32 objtab; /* Object table offset */
	ut32 objcnt; /* Number of objects in module */
	ut32 objmap; /* Object page map offset */
	ut32 itermap; /* Object iterated data map offset (File Relative) */
	ut32 rsrctab; /* Offset of Resource Table */
	ut32 rsrccnt; /* Number of resource entries */
	ut32 restab; /* Offset of resident name table */
	ut32 enttab; /* Offset of Entry Table */
	ut32 dirtab; /* Offset of Module Directive Table */
	ut32 dircnt; /* Number of module directives */
	ut32 fpagetab; /* Offset of Fixup Page Table */
	ut32 frectab; /* Offset of Fixup Record Table */
	ut32 impmod; /* Offset of Import Module Name Table */
	ut32 impmodcnt; /* Number of entries in Import Module Name Table */
	ut32 impproc; /* Offset of Import Procedure Name Table */
	ut32 pagesum; /* Offset of Per-Page Checksum Table */
	ut32 datapage; /* Offset of Enumerated Data Pages (File Relative) */
	ut32 preload; /* Number of preload pages */
	ut32 nrestab; /* Offset of Non-resident Names Table (File Relative) */
	ut32 cbnrestab; /* Size of Non-resident Name Table */
	ut32 nressum; /* Non-resident Name Table Checksum */
	ut32 autodata; /* Object # for automatic data object */
	ut32 debuginfo; /* Offset of the debugging information */
	ut32 debuglen; /* The length of the debugging info. in bytes */
	ut32 instpreload; /* Number of instance pages in preload section of .EXE file */
	ut32 instdemand; /* Number of instance pages in demand load section of EXE file */
	ut32 heapsize; /* Size of heap - for 16-bit apps */
	ut32 stacksize; /* Size of stack */
} LE_header;
#endif
