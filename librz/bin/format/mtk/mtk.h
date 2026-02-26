// SPDX-FileCopyrightText: 2025 mrsmith
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MTK_H
#define MTK_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define MTK_GFH_MAGIC_MASK          0x00FFFFFF
#define MTK_GFH_MAGIC               0x004D4D4D ///< "MMM" in lower 3 bytes
#define MTK_GFH_COMMON_HDR_SIZE     8
#define MTK_GFH_FILE_INFO_BODY_SIZE 48
#define MTK_GFH_MIN_FILE_SIZE       (MTK_GFH_COMMON_HDR_SIZE + MTK_GFH_FILE_INFO_BODY_SIZE)
#define MTK_GFH_FILE_INFO_NAME_SIZE 12

typedef enum {
	MTK_GFH_TYPE_FILE_INFO = 0x0000,
	MTK_GFH_TYPE_BL_INFO = 0x0001,
	MTK_GFH_TYPE_ANTI_CLONE = 0x0002,
	MTK_GFH_TYPE_BL_SEC_KEY = 0x0003,
	MTK_GFH_TYPE_BROM_CFG = 0x0007,
	MTK_GFH_TYPE_BROM_SEC_CFG = 0x0008,
	MTK_GFH_TYPE_0x200 = 0x0200,
	MTK_GFH_TYPE_RSA_MAYBE = 0x0202,
} MtkGfhType;

/**
 * \brief GFH Common Header (8 bytes, present in every GFH block).
 *
 * MediaTek Generic File Header format. The magic_version field encodes
 * "MMM" (0x4D4D4D) in the lower 3 bytes and a version number in the
 * upper byte.
 *
 * Reference: https://github.com/u-boot/u-boot/blob/master/tools/mtk_image.h
 */
typedef struct mtk_gfh_common_hdr {
	ut32 magic_version; ///< Lower 3 bytes = "MMM" (0x4D4D4D), upper byte = version
	ut16 size; ///< Total size of this header block (common + body)
	ut16 type; ///< Header type (MtkGfhType)
} MtkGfhCommonHdr;

/**
 * \brief GFH File Info body (48 bytes, follows common header when type=FILE_INFO).
 *
 * Contains the primary metadata for a MediaTek firmware image: load address,
 * entry point offset, header area size, and signature information.
 *
 * Reference: https://github.com/nccgroup/mtk_bp/blob/main/mtk_structs/mtk_img.ksy
 */
typedef struct mtk_gfh_file_info {
	char name[MTK_GFH_FILE_INFO_NAME_SIZE]; ///< Null-terminated identifier
	ut32 unused;
	ut16 file_type;
	ut8 flash_type;
	ut8 sig_type;
	ut32 load_addr; ///< Base load address in memory
	ut32 total_size; ///< Total image size
	ut32 max_size;
	ut32 hdr_size; ///< Total header area size; code starts at this file offset
	ut32 sig_size; ///< Signature size in bytes
	ut32 jump_offset; ///< File offset of entry point (from start of image)
	ut32 processed;
} MtkGfhFileInfo;

/**
 * \brief A parsed additional GFH header (stored generically).
 */
typedef struct mtk_gfh_header {
	MtkGfhCommonHdr common; ///< Common header fields
	ut64 file_offset; ///< File offset where this header starts
} MtkGfhHeader;

/**
 * \brief Top-level parsed object stored as bin_obj.
 */
typedef struct mtk_obj {
	MtkGfhCommonHdr first_common; ///< Common header of the first (file_info) block
	MtkGfhFileInfo file_info; ///< Parsed file_info body
	RzVector /*<MtkGfhHeader>*/ *extra_headers; ///< Additional GFH headers after file_info
	ut32 code_offset; ///< File offset where code starts (= file_info.hdr_size)
	ut32 code_size; ///< Size of code section
	ut32 entry_vaddr; ///< = load_addr + (jump_offset - code_offset)
} MtkObj;

RZ_IPI MtkObj *mtk_obj_new(RzBuffer *b);
RZ_IPI void mtk_obj_free(MtkObj *mtk);
RZ_IPI const char *mtk_gfh_type_str(ut16 type);

RZ_IPI bool mtk_check_buffer(RzBuffer *b);
RZ_IPI bool mtk_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb);
RZ_IPI void mtk_destroy(RzBinFile *bf);
RZ_IPI RzBinInfo *mtk_info(RzBinFile *bf);
RZ_IPI ut64 mtk_baddr(RzBinFile *bf);
RZ_IPI RzPVector /*<RzBinAddr *>*/ *mtk_entries(RzBinFile *bf);
RZ_IPI RzPVector /*<RzBinSection *>*/ *mtk_sections(RzBinFile *bf);
RZ_IPI RzStructuredData *mtk_structure(RzBinFile *bf);

#endif
