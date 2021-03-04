// SPDX-FileCopyrightText: 2009 Nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "elf_specs.h"

#ifndef _INCLUDE_ELF_H_
#define _INCLUDE_ELF_H_

#define RZ_BIN_ELF_SCN_IS_EXECUTABLE(x) x &SHF_EXECINSTR
#define RZ_BIN_ELF_SCN_IS_READABLE(x)   x &SHF_ALLOC
#define RZ_BIN_ELF_SCN_IS_WRITABLE(x)   x &SHF_WRITE

#define RZ_BIN_ELF_SYMTAB_SYMBOLS 1 << 0
#define RZ_BIN_ELF_DYNSYM_SYMBOLS 1 << 1
#define RZ_BIN_ELF_IMPORT_SYMBOLS (1 << 2 | (bin->ehdr.e_type == ET_REL ? RZ_BIN_ELF_SYMTAB_SYMBOLS : RZ_BIN_ELF_DYNSYM_SYMBOLS))
#define RZ_BIN_ELF_ALL_SYMBOLS    (RZ_BIN_ELF_SYMTAB_SYMBOLS | RZ_BIN_ELF_DYNSYM_SYMBOLS)
#define ELFOBJ                    struct Elf_(rz_bin_elf_obj_t)

#if RZ_BIN_ELF64
#define RZ_BIN_ELF_WORDSIZE        0x8
#define RZ_BIN_ELF_WORD_MAX        UT64_MAX
#define RZ_BIN_ELF_READWORD(x, i)  READ64(x, i)
#define RZ_BIN_ELF_BREADWORD(x, i) BREAD64(x, i)
#define RZ_BIN_ELF_ADDR_MAX        UT64_MAX
#define RZ_BIN_ELF_XWORD_MAX       UT64_MAX
#else
#define RZ_BIN_ELF_WORDSIZE        0x4
#define RZ_BIN_ELF_WORD_MAX        UT32_MAX
#define RZ_BIN_ELF_READWORD(x, i)  READ32(x, i)
#define RZ_BIN_ELF_BREADWORD(x, i) BREAD32(x, i)
#define RZ_BIN_ELF_ADDR_MAX        UT32_MAX
#define RZ_BIN_ELF_XWORD_MAX       UT64_MAX
#endif

typedef struct rz_bin_elf_section_t {
	ut64 offset;
	ut64 rva;
	ut64 size;
	ut64 align;
	ut32 flags;
	ut32 link;
	ut32 info;
	char name[ELF_STRING_LENGTH];
	int last;
	int type;
} RzBinElfSection;

typedef struct rz_bin_elf_symbol_t {
	ut64 offset;
	ut64 size;
	ut32 ordinal;
	const char *bind;
	const char *type;
	char name[ELF_STRING_LENGTH];
	char libname[ELF_STRING_LENGTH];
	int last;
	bool in_shdr;
	bool is_sht_null;
	bool is_vaddr; /* when true, offset is virtual address, otherwise it's physical */
	bool is_imported;
} RzBinElfSymbol;

typedef struct rz_bin_elf_reloc_t {
	int sym;
	int type;
	Elf_(Xword) rel_mode;
	st64 addend;
	ut64 offset;
	ut64 rva;
	ut16 section;
	int last;
	ut64 sto;
} RzBinElfReloc;

typedef struct rz_bin_elf_field_t {
	ut64 offset;
	char name[ELF_STRING_LENGTH];
	int last;
} RzBinElfField;

typedef struct rz_bin_elf_string_t {
	ut64 offset;
	ut64 size;
	char type;
	char string[ELF_STRING_LENGTH];
	int last;
} RzBinElfString;

typedef struct Elf_(rz_bin_elf_dynamic_info) {
	Elf_(Xword) dt_pltrelsz;
	Elf_(Addr) dt_pltgot;
	Elf_(Addr) dt_hash;
	Elf_(Addr) dt_strtab;
	Elf_(Addr) dt_symtab;
	Elf_(Addr) dt_rela;
	Elf_(Xword) dt_relasz;
	Elf_(Xword) dt_relaent;
	Elf_(Xword) dt_strsz;
	Elf_(Xword) dt_syment;
	Elf_(Addr) dt_fini;
	Elf_(Addr) dt_rel;
	Elf_(Xword) dt_relsz;
	Elf_(Xword) dt_relent;
	Elf_(Xword) dt_pltrel;
	Elf_(Addr) dt_jmprel;
	Elf_(Addr) dt_mips_pltgot;
	bool dt_bind_now;
	Elf_(Xword) dt_flags;
	Elf_(Xword) dt_flags_1;
	Elf_(Xword) dt_rpath;
	Elf_(Xword) dt_runpath;
	RzVector dt_needed;
}
RzBinElfDynamicInfo;

typedef struct rz_bin_elf_lib_t {
	char name[ELF_STRING_LENGTH];
	int last;
} RzBinElfLib;

struct Elf_(rz_bin_elf_obj_t) {
	Elf_(Ehdr) ehdr;
	Elf_(Phdr) * phdr;
	Elf_(Shdr) * shdr;

	Elf_(Shdr) * strtab_section;
	ut64 strtab_size;
	char *strtab;

	Elf_(Shdr) * shstrtab_section;
	ut64 shstrtab_size;
	char *shstrtab;

	RzBinElfDynamicInfo dyn_info;

	ut64 version_info[DT_VERSIONTAGNUM];

	char *dynstr;
	ut32 dynstr_size;

	RzBinImport **imports_by_ord;
	size_t imports_by_ord_size;
	RzBinSymbol **symbols_by_ord;
	size_t symbols_by_ord_size;

	int bss;
	ut64 size;
	ut64 baddr;
	ut64 boffset;
	int endian;
	bool verbose;
	const char *file;
	RzBuffer *b;
	Sdb *kv;
	/*cache purpose*/
	RzBinElfSection *g_sections;
	RzBinElfSymbol *g_symbols;
	RzBinElfSymbol *g_imports;
	RzBinElfReloc *g_relocs;
	ut32 g_reloc_num;
	RzBinElfSymbol *phdr_symbols;
	RzBinElfSymbol *phdr_imports;
	HtUP *rel_cache;
};

int Elf_(rz_bin_elf_has_va)(struct Elf_(rz_bin_elf_obj_t) * bin);
ut64 Elf_(rz_bin_elf_get_section_addr)(struct Elf_(rz_bin_elf_obj_t) * bin, const char *section_name);
ut64 Elf_(rz_bin_elf_get_section_offset)(struct Elf_(rz_bin_elf_obj_t) * bin, const char *section_name);
ut64 Elf_(rz_bin_elf_get_baddr)(struct Elf_(rz_bin_elf_obj_t) * bin);
ut64 Elf_(rz_bin_elf_p2v)(struct Elf_(rz_bin_elf_obj_t) * bin, ut64 paddr);
ut64 Elf_(rz_bin_elf_v2p)(struct Elf_(rz_bin_elf_obj_t) * bin, ut64 vaddr);
ut64 Elf_(rz_bin_elf_p2v_new)(struct Elf_(rz_bin_elf_obj_t) * bin, ut64 paddr);
ut64 Elf_(rz_bin_elf_v2p_new)(struct Elf_(rz_bin_elf_obj_t) * bin, ut64 vaddr);
ut64 Elf_(rz_bin_elf_get_boffset)(struct Elf_(rz_bin_elf_obj_t) * bin);
ut64 Elf_(rz_bin_elf_get_entry_offset)(struct Elf_(rz_bin_elf_obj_t) * bin);
ut64 Elf_(rz_bin_elf_get_main_offset)(struct Elf_(rz_bin_elf_obj_t) * bin);
ut64 Elf_(rz_bin_elf_get_init_offset)(struct Elf_(rz_bin_elf_obj_t) * bin);
ut64 Elf_(rz_bin_elf_get_fini_offset)(struct Elf_(rz_bin_elf_obj_t) * bin);
char *Elf_(rz_bin_elf_intrp)(struct Elf_(rz_bin_elf_obj_t) * bin);
char *Elf_(rz_bin_elf_compiler)(ELFOBJ *bin);
bool Elf_(rz_bin_elf_get_stripped)(struct Elf_(rz_bin_elf_obj_t) * bin);
bool Elf_(rz_bin_elf_is_static)(struct Elf_(rz_bin_elf_obj_t) * bin);
char *Elf_(rz_bin_elf_get_data_encoding)(struct Elf_(rz_bin_elf_obj_t) * bin);
char *Elf_(rz_bin_elf_get_arch)(struct Elf_(rz_bin_elf_obj_t) * bin);
char *Elf_(rz_bin_elf_get_machine_name)(struct Elf_(rz_bin_elf_obj_t) * bin);
char *Elf_(rz_bin_elf_get_head_flag)(ELFOBJ *bin); //yin
char *Elf_(rz_bin_elf_get_abi)(ELFOBJ *bin);
char *Elf_(rz_bin_elf_get_cpu)(ELFOBJ *bin);
char *Elf_(rz_bin_elf_get_file_type)(struct Elf_(rz_bin_elf_obj_t) * bin);
char *Elf_(rz_bin_elf_get_elf_class)(struct Elf_(rz_bin_elf_obj_t) * bin);
int Elf_(rz_bin_elf_get_bits)(struct Elf_(rz_bin_elf_obj_t) * bin);
char *Elf_(rz_bin_elf_get_osabi_name)(struct Elf_(rz_bin_elf_obj_t) * bin);
int Elf_(rz_bin_elf_is_big_endian)(struct Elf_(rz_bin_elf_obj_t) * bin);
RzBinElfReloc *Elf_(rz_bin_elf_get_relocs)(struct Elf_(rz_bin_elf_obj_t) * bin);
RzBinElfLib *Elf_(rz_bin_elf_get_libs)(struct Elf_(rz_bin_elf_obj_t) * bin);
RzBinElfSection *Elf_(rz_bin_elf_get_sections)(struct Elf_(rz_bin_elf_obj_t) * bin);
RzBinElfSymbol *Elf_(rz_bin_elf_get_symbols)(struct Elf_(rz_bin_elf_obj_t) * bin);
RzBinElfSymbol *Elf_(rz_bin_elf_get_imports)(struct Elf_(rz_bin_elf_obj_t) * bin);
struct rz_bin_elf_field_t *Elf_(rz_bin_elf_get_fields)(struct Elf_(rz_bin_elf_obj_t) * bin);
char *Elf_(rz_bin_elf_get_rpath)(struct Elf_(rz_bin_elf_obj_t) * bin);

struct Elf_(rz_bin_elf_obj_t) * Elf_(rz_bin_elf_new)(const char *file, bool verbose);
struct Elf_(rz_bin_elf_obj_t) * Elf_(rz_bin_elf_new_buf)(RzBuffer *buf, bool verbose);
void Elf_(rz_bin_elf_free)(struct Elf_(rz_bin_elf_obj_t) * bin);

ut64 Elf_(rz_bin_elf_resize_section)(RzBinFile *bf, const char *name, ut64 size);
bool Elf_(rz_bin_elf_section_perms)(RzBinFile *bf, const char *name, int perms);
bool Elf_(rz_bin_elf_entry_write)(RzBinFile *bf, ut64 addr);
bool Elf_(rz_bin_elf_del_rpath)(RzBinFile *bf);

bool Elf_(rz_bin_elf_is_executable)(ELFOBJ *bin);
int Elf_(rz_bin_elf_has_relro)(struct Elf_(rz_bin_elf_obj_t) * bin);
int Elf_(rz_bin_elf_has_nx)(struct Elf_(rz_bin_elf_obj_t) * bin);
ut8 *Elf_(rz_bin_elf_grab_regstate)(struct Elf_(rz_bin_elf_obj_t) * bin, int *len);
RzList *Elf_(rz_bin_elf_get_maps)(ELFOBJ *bin);
RzBinSymbol *Elf_(_r_bin_elf_convert_symbol)(struct Elf_(rz_bin_elf_obj_t) * bin,
	struct rz_bin_elf_symbol_t *symbol,
	const char *namefmt);
#endif
