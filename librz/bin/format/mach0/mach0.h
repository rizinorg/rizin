// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2010-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_types.h>
#include "mach0_specs.h"

#ifndef _INCLUDE_RZ_BIN_MACH0_H_
#define _INCLUDE_RZ_BIN_MACH0_H_

#define RZ_BIN_MACH0_STRING_LENGTH 256

#define CSMAGIC_CODEDIRECTORY      0xfade0c02
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CSMAGIC_DETACHED_SIGNATURE 0xfade0cc1 /* multi-arch collection of embedded signatures */
#define CSMAGIC_ENTITLEMENTS       0xfade7171
#define CSMAGIC_REQUIREMENT        0xfade0c00 /* single Requirement blob */
#define CSMAGIC_REQUIREMENTS       0xfade0c01 /* Requirements vector (internal requirements) */

#define CS_PAGE_SIZE 4096

#define CS_HASHTYPE_SHA1             1
#define CS_HASHTYPE_SHA256           2
#define CS_HASHTYPE_SHA256_TRUNCATED 3

#define CS_HASH_SIZE_SHA1             20
#define CS_HASH_SIZE_SHA256           32
#define CS_HASH_SIZE_SHA256_TRUNCATED 20

#define CSSLOT_CODEDIRECTORY 0
#define CSSLOT_INFOSLOT      1
#define CSSLOT_REQUIREMENTS  2
#define CSSLOT_RESOURCEDIR   3
#define CSSLOT_APPLICATION   4
#define CSSLOT_ENTITLEMENTS  5
#define CSSLOT_CMS_SIGNATURE 0x10000

struct section_t {
	ut64 offset;
	ut64 addr;
	ut64 size;
	ut64 vsize;
	ut32 align;
	ut32 flags;
	int perm;
	char name[RZ_BIN_MACH0_STRING_LENGTH];
	int last;
};

struct symbol_t {
	ut64 offset;
	ut64 addr;
	ut64 size;
	int bits;
	int type;
	bool is_imported;
	char *name;
	bool last;
};

struct reloc_t {
	ut64 offset;
	ut64 addr;
	st64 addend;
	ut8 type;
	int ord;
	int last;
	char name[256];
	bool external : 1,
		pc_relative : 1,
		chained : 1;
	ut8 size;
	ut64 target;
};

struct addr_t {
	ut64 offset;
	ut64 addr;
	ut64 haddr;
	int last;
};

struct lib_t {
	char name[RZ_BIN_MACH0_STRING_LENGTH];
	int last;
};

struct blob_index_t {
	ut32 type;
	ut32 offset;
};

struct blob_t {
	ut32 magic;
	ut32 length;
};

struct super_blob_t {
	struct blob_t blob;
	ut32 count;
	struct blob_index_t index[];
};

struct MACH0_(opts_t) {
	bool verbose;
	ut64 header_at;
	ut64 symbols_off;
	bool patch_relocs;
};

/**
 * Info parsed from struct dyld_chained_fixups_header and descendants, or synthesized from BIND_OPCODE_THREADED
 */
struct mach0_chained_fixups_t {
	struct rz_dyld_chained_starts_in_segment **starts;
	ut32 starts_count;
	enum dyld_chained_import_format imports_format;
	RzVector /*<void>*/ imports; // contained type is dynamically specified by imports_format above
	ut64 symbols_base_paddr; ///< base addr of all string referenced name_offset in dyld_chained_import* structs
};

/**
 * Generic, but not size-optimized container for info contained in any dyld_chained_import* struct
 */
struct MACH0_(chained_import_t) {
	st32 lib_ordinal;
	bool weak_import;
	ut32 name_offset;
	const char *name; ///< if non-null, this is the name, otherwise name_offset should be used
	st64 addend;
};

/**
 * Info about a single chained fixup
 */
struct mach0_chained_fixup_t {
	ut64 paddr;
	ut32 size; ///< bytes
	ut64 result; ///< value to write
	bool is_bind;
	ut64 addend;
	ut32 bind_ordinal; ///< if is_bind, the ordinal of the chained import
};

typedef void (*mach0_import_foreach_cb)(RZ_NONNULL RZ_OWN char *name, int ord, void *user);
typedef void (*mach0_chained_fixup_foreach_cb)(struct mach0_chained_fixup_t *fixup, void *user);

struct MACH0_(obj_t) {
	struct MACH0_(opts_t) options;
	struct MACH0_(mach_header) hdr;
	struct MACH0_(segment_command) * segs;
	char *intrp;
	char *compiler;
	int nsegs;
	struct mach0_chained_fixups_t chained_fixups;
	struct MACH0_(section) * sects;
	int nsects;
	struct MACH0_(nlist) * symtab;
	ut8 *symstr;
	ut8 *func_start; // buffer that hold the data from LC_FUNCTION_STARTS
	int symstrlen;
	int nsymtab;
	ut32 *indirectsyms;
	int nindirectsyms;

	/**
	 * Imports by ordinal from chained imports or undefined symbols, depending on MACH0_(has_chained_fixups)()
	 */
	RzPVector /*<RzBinImport *>*/ imports_by_ord;

	HtPP *imports_by_name; ///< other imports created only by name

	struct dysymtab_command dysymtab;
	struct load_command main_cmd;
	struct dyld_info_command *dyld_info;
	struct dylib_table_of_contents *toc;
	int ntoc;
	struct MACH0_(dylib_module) * modtab;
	int nmodtab;
	struct thread_command thread;
	ut8 *signature;
	union {
		struct x86_thread_state32 x86_32;
		struct x86_thread_state64 x86_64;
		struct ppc_thread_state32 ppc_32;
		struct ppc_thread_state64 ppc_64;
		struct arm_thread_state32 arm_32;
		struct arm_thread_state64 arm_64;
		struct sparc_thread_state64 sparc_64;
		struct mc680x0_thread_state mc680x0;
	} thread_state;
	char (*libs)[RZ_BIN_MACH0_STRING_LENGTH];
	int nlibs;
	int size;
	ut64 baddr;
	ut64 entry;
	bool big_endian;
	const char *file;
	RzBuffer *b;
	ut32 platform; ///< MACH0_PLATFORM_*, or an unknown value from the bin, or UT32_MAX if not determined
	Sdb *kv;
	int has_crypto;
	int has_canary;
	int has_retguard;
	int has_sanitizers;
	int has_blocks_ext;
	int dbg_info;
	const char *lang;
	int uuidn;
	int func_size;
	void *user;
	ut64 (*va2pa)(ut64 p, ut32 *offset, ut32 *left, RzBinFile *bf);
	struct symbol_t *symbols;
	ut64 main_addr;

	RzPVector /*<RzBinSection *>*/ *sections_cache;
	RzSkipList /* struct reloc_t * */ *relocs; ///< lazily loaded, use only MACH0_(get_relocs)() to access this
	bool relocs_parsed; ///< whether relocs have already been parsed and relocs is filled (or NULL on error)
	bool reloc_targets_map_base_calculated;
	bool relocs_patched;
	RzBuffer *buf_patched;
	ut64 reloc_targets_map_base;
	RzPVector /*<struct reloc_t *>*/ *patchable_relocs; ///< weak pointers to relocs in `relocs` which should be patched
	RzHash *hash;
};

#define MACH0_VFILE_NAME_RELOC_TARGETS "reloc-targets"
#define MACH0_VFILE_NAME_PATCHED       "patched"

void MACH0_(opts_set_default)(struct MACH0_(opts_t) * options, RzBinFile *bf);
struct MACH0_(obj_t) * MACH0_(new_buf)(RzBuffer *buf, struct MACH0_(opts_t) * options);
void *MACH0_(mach0_free)(struct MACH0_(obj_t) * bin);
struct section_t *MACH0_(get_sections)(struct MACH0_(obj_t) * bin);
char *MACH0_(section_type_to_string)(ut64 type);
RzList /*<char *>*/ *MACH0_(section_flag_to_rzlist)(ut64 flag);
RzPVector /*<RzBinVirtualFile *>*/ *MACH0_(get_virtual_files)(RzBinFile *bf);
RzPVector /*<RzBinMap *>*/ *MACH0_(get_maps_unpatched)(RzBinFile *bf);
RzPVector /*<RzBinMap *>*/ *MACH0_(get_maps)(RzBinFile *bf);
RzPVector /*<RzBinSection *>*/ *MACH0_(get_segments)(RzBinFile *bf);
const struct symbol_t *MACH0_(get_symbols)(struct MACH0_(obj_t) * bin);
void MACH0_(pull_symbols)(struct MACH0_(obj_t) * mo, RzBinSymbolCallback cb, void *user);
void MACH0_(imports_foreach)(struct MACH0_(obj_t) * bin, mach0_import_foreach_cb cb, void *user);
size_t MACH0_(imports_count)(struct MACH0_(obj_t) * bin);
RZ_BORROW RzSkipList /* struct reloc_t * */ *MACH0_(get_relocs)(struct MACH0_(obj_t) * bin);
struct addr_t *MACH0_(get_entrypoint)(struct MACH0_(obj_t) * bin);
struct lib_t *MACH0_(get_libs)(struct MACH0_(obj_t) * bin);
ut64 MACH0_(get_baddr)(struct MACH0_(obj_t) * bin);
char *MACH0_(get_class)(struct MACH0_(obj_t) * bin);
int MACH0_(get_bits)(struct MACH0_(obj_t) * bin);
bool MACH0_(is_big_endian)(RZ_NONNULL RzBuffer *buf);
bool MACH0_(is_pie)(struct MACH0_(obj_t) * bin);
bool MACH0_(has_nx)(struct MACH0_(obj_t) * bin);
const char *MACH0_(get_intrp)(struct MACH0_(obj_t) * bin);
const char *MACH0_(get_platform)(struct MACH0_(obj_t) * bin);
const char *MACH0_(get_cputype)(struct MACH0_(obj_t) * bin);
char *MACH0_(get_cpusubtype)(struct MACH0_(obj_t) * bin);
char *MACH0_(get_cpusubtype_from_hdr)(struct MACH0_(mach_header) * hdr);
char *MACH0_(get_filetype)(struct MACH0_(obj_t) * bin);
char *MACH0_(get_filetype_from_hdr)(struct MACH0_(mach_header) * hdr);
ut64 MACH0_(get_main)(struct MACH0_(obj_t) * bin);
const char *MACH0_(get_cputype_from_hdr)(struct MACH0_(mach_header) * hdr);
int MACH0_(get_bits_from_hdr)(struct MACH0_(mach_header) * hdr);
struct MACH0_(mach_header) * MACH0_(get_hdr)(RzBuffer *buf, RZ_NULLABLE RZ_OUT bool *is_big_endian);
RzStructuredData *MACH0_(mach_structure)(RzBinFile *bf);
RzPVector /*<RzBinField *>*/ *MACH0_(mach_fields)(RzBinFile *bf);
RZ_API RZ_OWN char *MACH0_(get_name)(struct MACH0_(obj_t) * mo, ut32 stridx, bool filter);
RZ_API ut64 MACH0_(paddr_to_vaddr)(struct MACH0_(obj_t) * bin, ut64 offset);
RZ_API ut64 MACH0_(vaddr_to_paddr)(struct MACH0_(obj_t) * bin, ut64 addr);

RZ_IPI bool MACH0_(parse_chained_fixups)(struct MACH0_(obj_t) * bin, ut32 offset, ut32 size);
RZ_IPI void MACH0_(reconstruct_chained_fixups_from_threaded)(struct MACH0_(obj_t) * bin);
RZ_API bool MACH0_(has_chained_fixups)(struct MACH0_(obj_t) * obj);
RZ_API bool MACH0_(segment_has_chained_fixups)(struct MACH0_(obj_t) * obj, size_t seg_index);
RZ_API void MACH0_(patch_chained_fixups)(struct MACH0_(obj_t) * obj, RzBuffer *dst);
RZ_API void MACH0_(chained_fixups_foreach)(struct MACH0_(obj_t) * obj, mach0_chained_fixup_foreach_cb cb, void *user);
RZ_API size_t MACH0_(chained_imports_count)(struct MACH0_(obj_t) * obj);
RZ_API bool MACH0_(get_chained_import)(struct MACH0_(obj_t) * obj, ut32 ordinal, struct MACH0_(chained_import_t) * dst);
RZ_API RZ_OWN char *MACH0_(chained_import_read_symbol_name)(struct MACH0_(obj_t) * obj, struct MACH0_(chained_import_t) * imp);
RZ_API RZ_OWN char *MACH0_(read_chained_symbol)(struct MACH0_(obj_t) * obj, ut32 name_offset);

RZ_API bool MACH0_(needs_reloc_patching)(struct MACH0_(obj_t) * obj);
RZ_API ut64 MACH0_(reloc_target_size)(struct MACH0_(obj_t) * obj);
RZ_API ut64 MACH0_(reloc_targets_vfile_size)(struct MACH0_(obj_t) * obj);
RZ_API ut64 MACH0_(reloc_targets_map_base)(RzBinFile *bf, struct MACH0_(obj_t) * obj);
RZ_API void MACH0_(patch_relocs)(RzBinFile *bf, struct MACH0_(obj_t) * obj);

typedef void (*BindOpcodesThreadedTableSizeCb)(ut64 table_size, void *user);
typedef void (*BindOpcodesBindCb)(ut64 paddr, ut64 vaddr, st64 addend, ut8 rel_type, int lib_ord, int sym_ord, const char *sym_name, void *user);
typedef void (*BindOpcodesThreadedApplyCb)(int seg_idx, ut64 seg_off, void *user);
RZ_API void MACH0_(bind_opcodes_foreach)(struct MACH0_(obj_t) * bin,
	RZ_NONNULL BindOpcodesThreadedTableSizeCb threaded_table_size_cb,
	RZ_NULLABLE BindOpcodesBindCb do_bind_cb,
	RZ_NONNULL BindOpcodesThreadedApplyCb threaded_apply_cb,
	void *user);

#endif
