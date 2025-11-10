// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Loader for the Qualcomm peripheral firmware images.
 *
 * Reference: https://github.com/torvalds/linux/blob/master/drivers/soc/qcom/mdt_loader.c
 */

#ifndef RZ_MDT_H
#define RZ_MDT_H

#include <rz_bin.h>
#include "../format/elf/elf.h"
#include "../format/mbn/mbn.h"

#define qcom_p_flags(p_flags) (p_flags >> 24)

/**
 * \brief Mask for the segment type.
 */
#define QCOM_MDT_TYPE_MASK (7 << 24)
/**
 * \brief Bits set for the first firmware part.
 */
#define QCOM_MDT_TYPE_LAYOUT (7 << 24)
/**
 * \brief Type of the signature segment.
 */
#define QCOM_MDT_TYPE_SIGNATURE (2 << 24)
/**
 * \brief Relocatable segment.
 */
#define QCOM_MDT_RELOCATABLE (1 << 27)

/**
 * \brief The segment type/p_type as it is in the ELF.
 */
typedef ut32 RzBinMdtPFlags;

typedef enum rz_bin_mdt_seg_type {
	RZ_BIN_MDT_PART_UNIDENTIFIED = 0,
	RZ_BIN_MDT_PART_ELF, ///< An ELF file.
	RZ_BIN_MDT_PART_MBN, ///< The secure boot authentication signature segment.
	RZ_BIN_MDT_PART_COMPRESSED_Q6ZIP, ///< Q6ZIP compressed segment (if identified).
	RZ_BIN_MDT_PART_COMPRESSED_CLADE2, ///< CLADE2 compressed segment (if identified).
	RZ_BIN_MDT_PART_COMPRESSED_ZLIB, ///< Zlib compressed segment (if identified).
} RzBinMdtSegBinFormat;

/**
 * \brief An MDT firmware part and some descriptions.
 */
typedef struct {
	char *name; ///< The name of the part. Should be equal to the base name of the file.
	bool relocatable; ///< True if the Qualcomm relocatable flag is set for the segment.
	bool is_layout; ///< True if the ELF segment is the firmware layout.
	RzBinMdtSegBinFormat format; ///< The segment type.
	RzBinMdtPFlags pflags; ///< The segment p_flags.
	RzBinVirtualFile *vfile; ///< The virtual file for the `.bNN` file.
	union {
		ELFOBJ *elf; ///< Set if this part is an ELF.
		SblHeader *mbn; ///< Set if this part is an MBN auth segment.
	} obj;
	RzBinAddr *entry; ///< The entry point, if any.
	RzBinMap *map; ///< The mapping of the part in memory.
	/**
	 * \brief The physical address as in the layout. This is not the same as map->paddr!
	 * Because map is used to read from the files. So it has be zero (to not mess up the reading offsets).
	 */
	ut64 paddr;
	char *patches_vfile_name; ///< Name of the vfile of patches to the binary. If NULL, no patches are supported.
	char *relocs_vfile_name; ///< Name of the vfile of relocs to the binary. If NULL, no relocs are supported.
	RzPVector /*<RzBinSymbol *>*/ *symbols; ///< Symbols in this part.
	RzPVector /*<RzBinReloc *>*/ *relocs; ///< Relocs in this part.
	RzPVector /*<RzBinSection *>*/ *sections; ///< Sections in this part.
	RzPVector /*<RzBinMap *>*/ *sub_maps; ///< Maps of the obj, if any.
} RzBinMdtPart;

typedef struct {
	char *name; ///< The name of the peripheral firmware. E.g. modem, adsp, cdsp or npu.
	ELFOBJ *header; ///< The ELF header of the whole firmware. From `<peripheral>.mdt`.
	RzPVector /*<RzBinMdtPart *>*/ *parts; ///< All parts from the `<peripheral>.bNN` files.
} RzBinMdtObj;

RZ_IPI RzBinMdtPart *rz_bin_mdt_part_new(const char *name, size_t p_flags);
RZ_IPI void rz_bin_mdt_part_free(RZ_OWN RZ_NULLABLE RzBinMdtPart *part);
RZ_IPI RzBinMdtObj *rz_bin_mdt_obj_new();
RZ_IPI void rz_bin_mdt_obj_free(RzBinMdtObj *obj);
RZ_IPI bool rz_bin_mdt_check_filename(const char *filename);
RZ_IPI bool rz_bin_mdt_load_buffer(RZ_UNUSED RzBinFile *bf, RZ_OUT RzBinObject *obj, RzBuffer *buf, RZ_UNUSED Sdb *sdb);
RZ_IPI bool rz_bin_mdt_check_buffer(RzBuffer *b);
RZ_IPI void rz_bin_mdt_destroy(RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinMap *>*/ *rz_bin_mdt_get_maps(RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinAddr *>*/ *rz_bin_mdt_get_entry_points(RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinVirtualFile *>*/ *rz_bin_mdt_virtual_files(RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinSymbol *>*/ *rz_bin_mdt_symbols(RzBinFile *bf);
RZ_IPI RzStructuredData *rz_bin_mdt_structure(RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinSection *>*/ *rz_bin_mdt_sections(RzBinFile *bf);
RZ_IPI RZ_OWN RzPVector /*<RzBinReloc *>*/ *rz_bin_mdt_relocs(RzBinFile *bf);

#endif // RZ_MDT_H
