// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define mbn_file_get_hdr(bf) ((SblHeader *)bf->o->bin_obj)

/**
 * \brief A 40 bytes MBN header for a chain of attestation.
 * For a more general intro to MBN, see the file comment in mbn.c.
 *
 * For firmware attestation scheme details see:
 * https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/secure-boot-and-image-authentication-version_final.pdf
 */
typedef struct sbl_header {
	ut32 /*<RzMBNImageId>*/ image_id; ///< Identifies the type of image this header represents (OEM SBL, AMSS, Apps boot loader, etc.).
	ut32 version; ///< Header version
	ut32 paddr; ///< Offset from the _end of the header_ where the image starts.
	ut32 vaddr; ///< Memory address it is loaded at.
	ut32 psize; ///< Size of complete image in bytes.
	ut32 code_pa; ///< Size of code region in bytes.
	ut32 sign_va; ///< Memory address to the attestation signature.
	ut32 sign_sz; ///< Size of the attestation signature in bytes.
	ut32 cert_va; ///< Memory address to the chain of attestation of this image.
	ut32 cert_sz; ///< Size of the attestation chain in bytes.
} SblHeader;

/**
 * \brief Known MBN image IDs.
 *
 * Reference:
 * https://github.com/openpst/libopenpst/blob/master/include/qualcomm/mbn.h
 */
typedef enum {
	RZ_MBN_kMbnImageNone = 0x00,
	RZ_MBN_kMbnImageOemSbl = 0x01,
	RZ_MBN_kMbnImageAmss = 0x02,
	RZ_MBN_kMbnImageOcbl = 0x03,
	RZ_MBN_kMbnImageHash = 0x04,
	RZ_MBN_kMbnImageAppbl = 0x05,
	RZ_MBN_kMbnImageApps = 0x06,
	RZ_MBN_kMbnImageHostDl = 0x07,
	RZ_MBN_kMbnImageDsp1 = 0x08,
	RZ_MBN_kMbnImageFsbl = 0x09,
	RZ_MBN_kMbnImageDbl = 0x0A,
	RZ_MBN_kMbnImageOsbl = 0x0B,
	RZ_MBN_kMbnImageDsp2 = 0x0C,
	RZ_MBN_kMbnImageEhostdl = 0x0D,
	RZ_MBN_kMbnImageNandprg = 0x0E,
	RZ_MBN_kMbnImageNorprg = 0x0F,
	RZ_MBN_kMbnImageRamfs1 = 0x10,
	RZ_MBN_kMbnImageRamfs2 = 0x11,
	RZ_MBN_kMbnImageAdspQ5 = 0x12,
	RZ_MBN_kMbnImageAppsKernel = 0x13,
	RZ_MBN_kMbnImageBackupRamfs = 0x14,
	RZ_MBN_kMbnImageSbl1 = 0x15,
	RZ_MBN_kMbnImageSbl2 = 0x16,
	RZ_MBN_kMbnImageRpm = 0x17,
	RZ_MBN_kMbnImageSbl3 = 0x18,
	RZ_MBN_kMbnImageTz = 0x19,
	RZ_MBN_kMbnImageSsdKeys = 0x1A,
	RZ_MBN_kMbnImageGen = 0x1B,
	RZ_MBN_kMbnImageDsp3 = 0x1C,
	RZ_MBN_kMbnImageAcdb = 0x1D,
	RZ_MBN_kMbnImageWdt = 0x1E,
	RZ_MBN_kMbnImageMba = 0x1F,
	RZ_MBN_kMbnImageLast = RZ_MBN_kMbnImageMba
} RzMBNImageId;

static inline const char *rz_mbn_image_id_str(RzMBNImageId id) {
	switch (id) {
	case RZ_MBN_kMbnImageNone:
		return "kMbnImageNone";
	case RZ_MBN_kMbnImageOemSbl:
		return "kMbnImageOemSbl";
	case RZ_MBN_kMbnImageAmss:
		return "kMbnImageAmss";
	case RZ_MBN_kMbnImageOcbl:
		return "kMbnImageOcbl";
	case RZ_MBN_kMbnImageHash:
		return "kMbnImageHash";
	case RZ_MBN_kMbnImageAppbl:
		return "kMbnImageAppbl";
	case RZ_MBN_kMbnImageApps:
		return "kMbnImageApps";
	case RZ_MBN_kMbnImageHostDl:
		return "kMbnImageHostDl";
	case RZ_MBN_kMbnImageDsp1:
		return "kMbnImageDsp1";
	case RZ_MBN_kMbnImageFsbl:
		return "kMbnImageFsbl";
	case RZ_MBN_kMbnImageDbl:
		return "kMbnImageDbl";
	case RZ_MBN_kMbnImageOsbl:
		return "kMbnImageOsbl";
	case RZ_MBN_kMbnImageDsp2:
		return "kMbnImageDsp2";
	case RZ_MBN_kMbnImageEhostdl:
		return "kMbnImageEhostdl";
	case RZ_MBN_kMbnImageNandprg:
		return "kMbnImageNandprg";
	case RZ_MBN_kMbnImageNorprg:
		return "kMbnImageNorprg";
	case RZ_MBN_kMbnImageRamfs1:
		return "kMbnImageRamfs1";
	case RZ_MBN_kMbnImageRamfs2:
		return "kMbnImageRamfs2";
	case RZ_MBN_kMbnImageAdspQ5:
		return "kMbnImageAdspQ5";
	case RZ_MBN_kMbnImageAppsKernel:
		return "kMbnImageAppsKernel";
	case RZ_MBN_kMbnImageBackupRamfs:
		return "kMbnImageBackupRamfs";
	case RZ_MBN_kMbnImageSbl1:
		return "kMbnImageSbl1";
	case RZ_MBN_kMbnImageSbl2:
		return "kMbnImageSbl2";
	case RZ_MBN_kMbnImageRpm:
		return "kMbnImageRpm";
	case RZ_MBN_kMbnImageSbl3:
		return "kMbnImageSbl3";
	case RZ_MBN_kMbnImageTz:
		return "kMbnImageTz";
	case RZ_MBN_kMbnImageSsdKeys:
		return "kMbnImageSsdKeys";
	case RZ_MBN_kMbnImageGen:
		return "kMbnImageGen";
	case RZ_MBN_kMbnImageDsp3:
		return "kMbnImageDsp3";
	case RZ_MBN_kMbnImageAcdb:
		return "kMbnImageAcdb";
	case RZ_MBN_kMbnImageWdt:
		return "kMbnImageWdt";
	case RZ_MBN_kMbnImageMba:
		return "kMbnImageMba";
	}
	return "unknown";
}

bool mbn_read_sbl_header(RzBuffer *b, SblHeader *sb, ut64 *offset);
bool mbn_check_buffer(RzBuffer *b);
bool mbn_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb);
ut64 mbn_baddr(RzBinFile *bf);
RzPVector /*<RzBinAddr *>*/ *mbn_entries(RzBinFile *bf);
RzPVector /*<RzBinSection *>*/ *mbn_sections(RzBinFile *bf);
RzBinInfo *mbn_info(RzBinFile *bf);
ut64 mbn_size(RzBinFile *bf);
void mbn_destroy_obj(SblHeader *sb);
void mbn_destroy(RzBinFile *bf);
RzPVector /*<RzBinString *>*/ *mbn_strings(RzBinFile *bf);
RzStructuredData *mbn_structure(SblHeader *sb);
RzStructuredData *mbn_structure_bin(RzBinFile *bf);
