// SPDX-FileCopyrightText: 2008 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "pe_specs.h"

#ifndef _INCLUDE_R_BIN_PE_H_
#define _INCLUDE_R_BIN_PE_H_

#define RZ_BIN_PE_SCN_IS_SHAREABLE(x)  x &PE_IMAGE_SCN_MEM_SHARED
#define RZ_BIN_PE_SCN_IS_EXECUTABLE(x) x &PE_IMAGE_SCN_MEM_EXECUTE
#define RZ_BIN_PE_SCN_IS_READABLE(x)   x &PE_IMAGE_SCN_MEM_READ
#define RZ_BIN_PE_SCN_IS_WRITABLE(x)   x &PE_IMAGE_SCN_MEM_WRITE

struct rz_bin_pe_addr_t {
	ut64 vaddr;
	ut64 paddr;
	ut64 haddr;
};

struct rz_bin_pe_section_t {
	ut8 name[PE_IMAGE_SIZEOF_SHORT_NAME * 3];
	ut64 size;
	ut64 vsize;
	ut64 vaddr;
	ut64 paddr;
	ut64 perm;
	int last;
};

struct rz_bin_pe_import_t {
	ut8 name[PE_NAME_LENGTH + 1];
	ut8 libname[PE_NAME_LENGTH + 1];
	ut64 vaddr;
	ut64 paddr;
	ut64 hint;
	ut64 ordinal;
	int last;
};

struct rz_bin_pe_export_t {
	ut8 name[PE_NAME_LENGTH + 1];
	ut8 libname[PE_NAME_LENGTH + 1];
	ut8 forwarder[PE_NAME_LENGTH + 1];
	ut64 vaddr;
	ut64 paddr;
	ut64 ordinal;
	int last;
};

struct rz_bin_pe_string_t {
	char string[PE_STRING_LENGTH];
	ut64 vaddr;
	ut64 paddr;
	ut64 size;
	char type;
	int last;
};

struct rz_bin_pe_lib_t {
	char name[PE_STRING_LENGTH];
	int last;
};

typedef struct _PE_RESOURCE {
	char *timestr;
	char *type;
	char *language;
	char *name;
	Pe_image_resource_data_entry *data;
} rz_pe_resource;

#define GUIDSTR_LEN       41
#define DBG_FILE_NAME_LEN 255

typedef struct SDebugInfo {
	char guidstr[GUIDSTR_LEN];
	char file_name[DBG_FILE_NAME_LEN];
} SDebugInfo;

#endif

struct PE_(rz_bin_pe_obj_t) {
	// these pointers contain a copy of the headers and sections!
	PE_(image_dos_header) * dos_header;
	PE_(image_nt_headers) * nt_headers;
	PE_(image_optional_header) * optional_header; //not free this just pointer into nt_headers
	PE_(image_data_directory) * data_directory; //not free this just pointer into nt_headers
	PE_(image_section_header) * section_header;
	PE_(image_export_directory) * export_directory;
	PE_(image_import_directory) * import_directory;
	PE_(image_tls_directory) * tls_directory;
	Pe_image_resource_directory *resource_directory;
	PE_(image_delay_import_directory) * delay_import_directory;
	Pe_image_security_directory *security_directory;

	// these pointers pertain to the .net relevant sections
	PE_(image_clr_header) * clr_hdr;
	PE_(image_metadata_header) * metadata_header;
	PE_(image_metadata_stream) * *streams;

	/* store the section information for future use */
	struct rz_bin_pe_section_t *sections;

	// these values define the real offset into the untouched binary
	ut64 rich_header_offset;
	ut64 nt_header_offset;
	ut64 section_header_offset;
	ut64 import_directory_offset;
	ut64 export_directory_offset;
	ut64 resource_directory_offset;
	ut64 delay_import_directory_offset;

	int import_directory_size;
	int size;
	int num_sections;
	int endian;
	bool verbose;
	int big_endian;
	RzList *rich_entries;
	RzList *relocs;
	RzList *resources; //RzList of rz_pe_resources
	const char *file;
	RzBuffer *b;
	Sdb *kv;
	RCMS *cms;
	SpcIndirectDataContent *spcinfo;
	char *authentihash;
	bool is_authhash_valid;
	bool is_signed;
};

void PE_(rz_bin_store_all_resource_version_info)(struct PE_(rz_bin_pe_obj_t) * bin);
char *PE_(rz_bin_pe_get_arch)(struct PE_(rz_bin_pe_obj_t) * bin);
char *PE_(rz_bin_pe_get_cc)(struct PE_(rz_bin_pe_obj_t) * bin);
struct rz_bin_pe_addr_t *PE_(rz_bin_pe_get_entrypoint)(struct PE_(rz_bin_pe_obj_t) * bin);
struct rz_bin_pe_addr_t *PE_(rz_bin_pe_get_main_vaddr)(struct PE_(rz_bin_pe_obj_t) * bin);
struct rz_bin_pe_export_t *PE_(rz_bin_pe_get_exports)(struct PE_(rz_bin_pe_obj_t) * bin); // TODO
int PE_(rz_bin_pe_get_file_alignment)(struct PE_(rz_bin_pe_obj_t) * bin);
ut64 PE_(rz_bin_pe_get_image_base)(struct PE_(rz_bin_pe_obj_t) * bin);
struct rz_bin_pe_import_t *PE_(rz_bin_pe_get_imports)(struct PE_(rz_bin_pe_obj_t) * bin); // TODO
struct rz_bin_pe_lib_t *PE_(rz_bin_pe_get_libs)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(rz_bin_pe_get_image_size)(struct PE_(rz_bin_pe_obj_t) * bin);
char *PE_(rz_bin_pe_get_machine)(struct PE_(rz_bin_pe_obj_t) * bin);
char *PE_(rz_bin_pe_get_os)(struct PE_(rz_bin_pe_obj_t) * bin);
char *PE_(rz_bin_pe_get_class)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(rz_bin_pe_get_bits)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(rz_bin_pe_get_section_alignment)(struct PE_(rz_bin_pe_obj_t) * bin);
char *PE_(rz_bin_pe_get_subsystem)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(rz_bin_pe_is_dll)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(rz_bin_pe_is_big_endian)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(rz_bin_pe_is_stripped_relocs)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(rz_bin_pe_is_stripped_line_nums)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(rz_bin_pe_is_stripped_local_syms)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(rz_bin_pe_is_stripped_debug)(struct PE_(rz_bin_pe_obj_t) * bin);
void *PE_(rz_bin_pe_free)(struct PE_(rz_bin_pe_obj_t) * bin);
struct PE_(rz_bin_pe_obj_t) * PE_(rz_bin_pe_new)(const char *file, bool verbose);
struct PE_(rz_bin_pe_obj_t) * PE_(rz_bin_pe_new_buf)(RzBuffer *buf, bool verbose);
int PE_(rz_bin_pe_get_debug_data)(struct PE_(rz_bin_pe_obj_t) * bin, struct SDebugInfo *res);
int PE_(bin_pe_get_claimed_checksum)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(bin_pe_get_actual_checksum)(struct PE_(rz_bin_pe_obj_t) * bin);
const char *PE_(bin_pe_compute_authentihash)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(bin_pe_is_authhash_valid)(struct PE_(rz_bin_pe_obj_t) * bin);
int PE_(bin_pe_get_overlay)(struct PE_(rz_bin_pe_obj_t) * bin, ut64 *size);
void PE_(rz_bin_pe_check_sections)(struct PE_(rz_bin_pe_obj_t) * bin, struct rz_bin_pe_section_t **sects);
struct rz_bin_pe_addr_t *PE_(check_unknow)(struct PE_(rz_bin_pe_obj_t) * bin);
struct rz_bin_pe_addr_t *PE_(check_msvcseh)(struct PE_(rz_bin_pe_obj_t) * bin);
struct rz_bin_pe_addr_t *PE_(check_mingw)(struct PE_(rz_bin_pe_obj_t) * bin);
bool PE_(rz_bin_pe_section_perms)(RzBinFile *bf, const char *name, int perms);
RZ_API void PE_(bin_pe_parse_resource)(struct PE_(rz_bin_pe_obj_t) * bin);
