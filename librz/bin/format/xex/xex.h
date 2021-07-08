// SPDX-FileCopyrightText: 2021 smac89 <noblechuk5[at]web[dot]de>
// SPDX-License-Identifier: LPGL-3.0-only

#ifndef BUILD_XEX_H
#define BUILD_XEX_H

#include <rz_util.h>

/**
 * \brief XEX header flags
 *
 * https://free60project.github.io/wiki/XEX/#xex-header
 */
#define XEX_MAGIC        "\x58\x45\x58\x32"
#define XEX_MAGIC_OFFSET 0x0 /* "XEX2" */
#define XEX_MAGIC_SIZE   0x4

#define XEX_MODULE_OFFSET           0x4 /* flags */
#define XEX_PE_DATA_OFFSET          0x8 /* (unused) unsigned int */
#define XEX_RESERVED_OFFSET         0xC /* unsigned int */
#define XEX_SECURITY_INFO_OFFSET    0x10 /* unsigned int */
#define XEX_OPT_HEADER_COUNT_OFFSET 0x14 /* unsigned int */

#define XEX_OPT_HEADER_BASE_OFFSET 0x18
#define XEX_OPT_HEADER_BASE_SIZE   0x12

#define XEX_NS(name) XEX_##name /* namespacing for enums */

/**
 * \brief XEX header module flags
 */
typedef enum xex_header_module_flag_t {
	XEX_NS(TITLE_MODULE), /* bit 0 - Title Module */
	XEX_NS(EXPORTS_TO_TITLE), /* bit 1 - Exports to Title */
	XEX_NS(SYSTEM_DEBUGGER), /* bit 2 - System Debugger */
	XEX_NS(DLL_MODULE), /* bit 3 - DLL Module */
	XEX_NS(MODULE_PATCH), /* bit 4 - Module Patch */
	XEX_NS(PATCH_FULL), /* bit 5 - Patch Full */
	XEX_NS(PATCH_DELTA), /* bit 6 - Patch Delta */
	XEX_NS(USER_MODE), /* bit 7 - User Mode */
} XexHeaderModuleFlag;

/**
 * \brief XEX header ids
 * These correspond to the possible values of the optional headers' Id
 * https://free60project.github.io/wiki/XEX/#header-ids
 */
typedef enum xex_opt_header_data_t {
	XEX_NS(DATA) = 0x1,
	XEX_NS(RESOURCE_INFO) = 0x2FF, /* Resource Info */
	XEX_NS(BASE_FILE_FORMAT) = 0x3FF,
	XEX_NS(BASE_REFERENCE) = 0x405,
	XEX_NS(DELTA_PATCH_DESCRIPTOR) = 0x5FF,
	XEX_NS(BOUNDING_PATH) = 0x80FF,
	XEX_NS(DEVICE_ID) = 0x8105,
	XEX_NS(ORIGINAL_BASE_ADDR) = 0x10001,
	XEX_NS(ENTRY_POINT) = 0x10100,
	XEX_NS(IMAGE_BASE_ADDRESS) = 0x10201,
	XEX_NS(IMPORT_LIBS) = 0x103FF,
	XEX_NS(CHECKSUM_TIMESTAMP) = 0x18002,
	XEX_NS(ENABLED_FOR_CALLCAP) = 0x18102,
	XEX_NS(ENABLED_FOR_FASTCAP) = 0x18200,
	XEX_NS(ORIGINAL_PE_NAME) = 0x183FF,
	XEX_NS(STATIC_LIBS) = 0x200FF,
	XEX_NS(TLS_INFO) = 0x20104,
	XEX_NS(DEFAULT_STACK_SIZE) = 0x20200,
	XEX_NS(DEFAULT_FS_CACHE_SIZE) = 0x20301,
	XEX_NS(DEFAULT_HEAP_SIZE) = 0x20401,
	XEX_NS(PAGE_HEAD_SIZE_AND_FLAGS) = 0x28002,
	XEX_NS(SYSTEM_FLAGS) = 0x30000,
	XEX_NS(EXECUTION_ID) = 0x40006,
	XEX_NS(SERVICE_ID_LIST) = 0x401FF,
	XEX_NS(TITLE_WORKSPACE_SIZE) = 0x40201,
	XEX_NS(GAME_RATINGS) = 0x40310,
	XEX_NS(LAN_KEY) = 0x40404,
	XEX_NS(XBOX_360_LOGO) = 0x405FF,
	XEX_NS(MULTIDISK_MEDIA_IDS) = 0x406FF,
	XEX_NS(ALTERNATE_TITLE_IDS) = 0x407FF,
	XEX_NS(ADDITIONAL_TITLE_MEMORY) = 0x40801,
	XEX_NS(EXPORTS_BY_NAME) = 0xE10402,
} XexOptHeaderData;

/* opt */
typedef char *XexOptHeaderOriginalPeName;

/**
 * \brief xex optional headers
 *
 * https://free60project.github.io/wiki/XEX/#optional-headers
 */
typedef struct rz_bin_xex_opt_header_t {
	ut32 header_id;
	ut64 header_data;
	void (*display_data)(RzBuffer *buf, void *data);
} RzBinXexOptHeader;

typedef struct rz_bin_xex_header_t {
	ut32 module_flags;
	ut32 pe_data_offset; /* protected executable data */
	ut32 security_info_offset; /* ecnryption info (maybe?) */
} RzBinXexHeader;

typedef struct rz_bin_xex_t {
	RzBinXexHeader *xex_header;
	RzList /* <RzBinXexOptHeader> */ *opt_headers;
} RzBinXex;

/**
 * \brief Called to initialize the header
 *
 * \param xex_bin The xex bin abstraction
 * \param buf the buffer to read the binary from
 * \return RzBinXexHeader* a pointer to the created header
 */
RZ_API RzBinXexHeader *RZ_BORROW construct_header(RzBinXex *xex_bin, RzBuffer *buf);

/**
 * \brief Parse the file buffer and lazily populates the RzBinXex object
 *
 * \param buf The bufer to read from
 * \return RzBinXex* The xex binary asbtraction
 */
RZ_API RzBinXex *RZ_BORROW xex_parse(RzBuffer *buf);

/**
 * \brief Frees memory accumulated by the RzBinXex object
 *
 * \param bin_obj The xex binary asbtraction
 */
RZ_API void xex_destroy_bin(RZ_INOUT RzBinXex **bin_obj);

#endif
