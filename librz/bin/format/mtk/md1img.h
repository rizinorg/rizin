// SPDX-FileCopyrightText: 2025 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Header for MediaTek md1img container format parser.
 *
 * The md1img format packages modem firmware components: md1rom (GFH image),
 * debug info (CATI format), DSP images, certificates, etc.
 *
 * References:
 * - https://github.com/nccgroup/mtk_bp/blob/main/mtk_structs/mtk_img.ksy (md1img)
 * - https://github.com/nccgroup/mtk_bp/blob/main/mtk_structs/mtk_dbg_info.ksy (CATI)
 */

#ifndef MD1IMG_H
#define MD1IMG_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "mtk.h"

#define MD1IMG_MAGIC          "\x88\x16\x88\x58"
#define MD1IMG_MAGIC_SIZE     4
#define MD1IMG_EXT_MAGIC      "\x89\x16\x89\x58"
#define MD1IMG_EXT_MAGIC_SIZE 4
#define MD1IMG_NAME_SIZE      32
/* Minimum section header size (fields before reserved) */
#define MD1IMG_MIN_HDR_SIZE 0x50

#define MTK_CATI_MAGIC      "CATI"
#define MTK_CATI_MAGIC_SIZE 4
/* "CTNR" as LE u32 */
#define MTK_CATI_TYPE_CONTAINER 0x524E5443
#define MTK_CATI_TYPE_DEBUG     1
#define MTK_CATI_TYPE_DEBUG_DSP 2

/**
 * \brief A debug symbol parsed from a CATI debug info section.
 *
 * Reference: https://github.com/nccgroup/mtk_bp/blob/main/mtk_structs/mtk_dbg_info.ksy
 */
typedef struct mtk_dbg_symbol {
	char *name; ///< Symbol name
	ut32 addr; ///< Symbol address
	ut32 size; ///< Symbol size (addr2 - addr1, or 0 if addr2 <= addr1)
} MtkDbgSymbol;

/**
 * \brief Parsed section from an md1img container.
 *
 * Each section has a header (magic + metadata) followed by data and
 * alignment padding.
 */
typedef struct md1img_section {
	char name[MD1IMG_NAME_SIZE]; ///< Section name (null-terminated)
	ut32 dsize; ///< Data size
	ut32 maddr; ///< Memory address
	ut32 mode; ///< Mode flags
	ut32 hdr_size; ///< Header size (total, from start of section to data)
	ut32 hdr_version; ///< Header version
	ut32 img_type; ///< Image type
	ut32 img_list_end; ///< Image list end marker
	ut32 align_size; ///< Alignment size for padding after data
	ut32 dsize_extend; ///< Extended data size (high bits)
	ut32 maddr_extend; ///< Extended memory address (high bits)
	ut64 data_offset; ///< File offset where section data starts
} Md1imgSection;

/**
 * \brief Top-level parsed object for md1img container.
 */
typedef struct md1img_obj {
	RzVector /*<Md1imgSection>*/ *sections; ///< All parsed container sections
	RzPVector /*<RzBinVirtualFile *>*/ *vfiles; ///< Virtual file per section
	RzPVector /*<MtkDbgSymbol *>*/ *dbg_symbols; ///< Debug symbols from CATI section
	MtkObj *mtk; ///< Parsed GFH from md1rom section (or NULL)
	ut64 gfh_offset; ///< Offset of GFH within md1rom vfile
	int md1rom_idx; ///< Index of md1rom section, or -1
} Md1imgObj;

RZ_IPI bool md1img_check_buffer(RZ_BORROW RZ_NONNULL RzBuffer *b);
RZ_IPI bool md1img_load_buffer(RZ_BORROW RZ_NONNULL RzBinFile *bf, RZ_BORROW RZ_NONNULL RzBinObject *obj, RZ_BORROW RZ_NONNULL RzBuffer *b, RZ_BORROW RZ_NULLABLE Sdb *sdb);
RZ_IPI void md1img_destroy(RZ_BORROW RZ_NONNULL RzBinFile *bf);
RZ_IPI RZ_OWN RzBinInfo *md1img_info(RZ_BORROW RZ_NONNULL RzBinFile *bf);
RZ_IPI ut64 md1img_baddr(RZ_BORROW RZ_NONNULL RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinAddr *>*/ *md1img_entries(RZ_BORROW RZ_NONNULL RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinVirtualFile *>*/ *md1img_virtual_files(RZ_BORROW RZ_NONNULL RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinMap *>*/ *md1img_maps(RZ_BORROW RZ_NONNULL RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinSection *>*/ *md1img_sections(RZ_BORROW RZ_NONNULL RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinSymbol *>*/ *md1img_symbols(RZ_BORROW RZ_NONNULL RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinString *>*/ *md1img_strings(RZ_BORROW RZ_NONNULL RzBinFile *bf);
RZ_IPI RZ_OWN RzStructuredData *md1img_structure(RZ_BORROW RZ_NONNULL RzBinFile *bf);

#endif
