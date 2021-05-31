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

#define bprintf \
	if (bin->verbose) \
	RZ_LOG_WARN

#define READ8(x, i) \
	rz_read_ble8((x) + (i)); \
	(i) += 1
#define READ16(x, i) \
	rz_read_ble16((x) + (i), bin->endian); \
	(i) += 2
#define READ32(x, i) \
	rz_read_ble32((x) + (i), bin->endian); \
	(i) += 4
#define READ64(x, i) \
	rz_read_ble64((x) + (i), bin->endian); \
	(i) += 8

#define BREAD8(x, i) \
	rz_buf_read_ble8_at(x, i); \
	(i) += 1
#define BREAD16(x, i) \
	rz_buf_read_ble16_at(x, i, bin->endian); \
	(i) += 2
#define BREAD32(x, i) \
	rz_buf_read_ble32_at(x, i, bin->endian); \
	(i) += 4
#define BREAD64(x, i) \
	rz_buf_read_ble64_at(x, i, bin->endian); \
	(i) += 8

#define RZ_BIN_ELF_SCN_IS_EXECUTABLE(x) x &SHF_EXECINSTR
#define RZ_BIN_ELF_SCN_IS_READABLE(x)   x &SHF_ALLOC
#define RZ_BIN_ELF_SCN_IS_WRITABLE(x)   x &SHF_WRITE

#define RZ_BIN_ELF_NO_RELRO   0
#define RZ_BIN_ELF_PART_RELRO 1
#define RZ_BIN_ELF_FULL_RELRO 2

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

/// Information about the binary layout in a NT_PRSTATUS note for core files of a certain architecture and os
typedef struct prstatus_layout_t {
	ut64 regsize;

	/**
	 * This delta is the offset into the actual data of an NT_PRSTATUS note
	 * where the regstate of size regsize lies.
	 * That is, it is the offset after the Elf_(Nhdr) and the variable-length string + optional padding
	 * have already been skipped.
	 *
	 * see size_t ELFLinuxPrStatus::GetSize(const lldb_private::ArchSpec &arch) in lldb source or similar
	 * to determine values for this.
	 */
	ut64 regdelta;

	/// Size of the stack pointer register in bits
	ut8 sp_size;

	/**
	 * Offset of the stack pointer register inside the regstate
	 * To determine the layout of the regstate, see lldb source, for example:
	 *   RegisterContextSP ThreadElfCore::CreateRegisterContextForFrame(StackFrame *frame) decides what to use for the file
	 *   RegisterContextLinux_x86_64 leads to...
	 *   g_register_infos_x86_64 which is eventually filled with info using...
	 *   GPR_OFFSET which takes its info from...
	 *   the offsets into the GPR struct in RegisterContextLinux_x86_64.cpp
	 */
	ut64 sp_offset;

	// These NT_PRSTATUS notes hold much more than this, but it's not needed for us yet.
	// If necessary, new members can be introduced here.
} RzBinElfPrStatusLayout;

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
	st64 addend; ///< exact addend value taken from the ELF, meaning depends on type
	ut64 offset; ///< exact offset value taken from the ELF, meaning depends on the binary type
	ut64 paddr; ///< absolute paddr in the file, calculated from offset, or UT64_MAX if no such addr exists
	ut64 vaddr; ///< source vaddr of the reloc, calculated from offset
	ut64 target_vaddr; ///< after patching, the target that this reloc points to
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
	Elf_(Addr) dt_init;
	Elf_(Addr) dt_fini;
	Elf_(Xword) dt_pltrelsz;
	Elf_(Addr) dt_pltgot;
	Elf_(Addr) dt_hash;
	Elf_(Addr) dt_gnu_hash;
	Elf_(Addr) dt_strtab;
	Elf_(Addr) dt_symtab;
	Elf_(Addr) dt_rela;
	Elf_(Xword) dt_relasz;
	Elf_(Xword) dt_relaent;
	Elf_(Xword) dt_strsz;
	Elf_(Xword) dt_syment;
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

/// A single file entry in a PT_NOTE of type NT_FILE
typedef struct Elf_(rz_bin_elf_note_file_t) {
	Elf_(Addr) start_vaddr;
	Elf_(Addr) end_vaddr;
	Elf_(Addr) file_off;
	char *file;
}
RzBinElfNoteFile;

/// Parsed PT_NOTE of type NT_PRSTATUS
typedef struct Elf_(rz_bin_elf_note_prstatus_t) {
	size_t regstate_size;
	ut8 *regstate;
	// Hint: there is more info in NT_PRSTATUS notes that could be parsed if needed.
}
RzBinElfNotePrStatus;

/// A single PT_NOTE entry, parsed from an ElfW(Nhdr) and associated data.
typedef struct Elf_(rz_bin_elf_note_t) {
	Elf_(Word) type;
	union {
		struct {
			size_t files_count;
			RzBinElfNoteFile *files;
		} file; //< for type == NT_FILE
		RzBinElfNotePrStatus prstatus; //< for type = NT_PRSTATUS
	};
}
RzBinElfNote;

/// A single parsed PT_NOTE segment
typedef struct Elf_(rz_bin_elf_note_segment_t) {
	size_t notes_count;
	RzBinElfNote *notes;
}
RzBinElfNoteSegment;

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

	RzList /*<RzBinElfNoteSegment>*/ *note_segments;

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
	ut64 reloc_targets_map_base;
	bool reloc_targets_map_base_calculated;
	RzBuffer *buf_patched; ///< overlay over the original file with relocs patched
	bool relocs_patched;
};

ut64 Elf_(rz_bin_elf_p2v)(struct Elf_(rz_bin_elf_obj_t) * bin, ut64 paddr);
ut64 Elf_(rz_bin_elf_v2p)(struct Elf_(rz_bin_elf_obj_t) * bin, ut64 vaddr);
ut64 Elf_(rz_bin_elf_p2v_new)(struct Elf_(rz_bin_elf_obj_t) * bin, ut64 paddr);
ut64 Elf_(rz_bin_elf_v2p_new)(struct Elf_(rz_bin_elf_obj_t) * bin, ut64 vaddr);
char *Elf_(rz_bin_elf_compiler)(ELFOBJ *bin);
RzBinElfReloc *Elf_(rz_bin_elf_get_relocs)(struct Elf_(rz_bin_elf_obj_t) * bin);
RzBinElfSymbol *Elf_(rz_bin_elf_get_symbols)(struct Elf_(rz_bin_elf_obj_t) * bin);
RzBinElfSymbol *Elf_(rz_bin_elf_get_imports)(struct Elf_(rz_bin_elf_obj_t) * bin);
struct Elf_(rz_bin_elf_obj_t) * Elf_(rz_bin_elf_new)(const char *file, bool verbose);

ut64 Elf_(rz_bin_elf_resize_section)(RzBinFile *bf, const char *name, ut64 size);
bool Elf_(rz_bin_elf_section_perms)(RzBinFile *bf, const char *name, int perms);
bool Elf_(rz_bin_elf_entry_write)(RzBinFile *bf, ut64 addr);
bool Elf_(rz_bin_elf_del_rpath)(RzBinFile *bf);

RZ_IPI size_t Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(RZ_NONNULL ELFOBJ *bin);
RZ_IPI RZ_BORROW RzBinElfNotePrStatus *Elf_(rz_bin_elf_get_prstatus)(RZ_NONNULL ELFOBJ *bin);
RZ_IPI RZ_BORROW RzBinElfPrStatusLayout *Elf_(rz_bin_elf_get_prstatus_layout)(RZ_NONNULL ELFOBJ *bin);
RZ_IPI RZ_OWN char *Elf_(rz_bin_elf_get_ver_flags)(ut32 flags);
RZ_IPI Elf_(Verdaux) Elf_(rz_bin_elf_get_verdaux_entry)(RZ_NONNULL ELFOBJ *bin, ut64 offset);
RZ_IPI Elf_(Verdef) Elf_(rz_bin_elf_get_verdef_entry)(RZ_NONNULL ELFOBJ *bin, ut64 offset);
RZ_IPI Elf_(Vernaux) Elf_(rz_bin_elf_get_vernaux_entry)(RZ_NONNULL ELFOBJ *bin, ut64 offset);
RZ_IPI Elf_(Verneed) Elf_(rz_bin_elf_get_verneed_entry)(RZ_NONNULL ELFOBJ *bin, ut64 offset);
RZ_IPI RZ_OWN Sdb *Elf_(rz_bin_elf_get_version_info)(RZ_NONNULL ELFOBJ *bin);
RZ_IPI RZ_OWN Sdb *Elf_(rz_bin_elf_get_version_info_gnu_verdef)(RZ_NONNULL ELFOBJ *bin);
RZ_IPI RZ_OWN Sdb *Elf_(rz_bin_elf_get_version_info_gnu_verneed)(RZ_NONNULL ELFOBJ *bin);
RZ_IPI RZ_OWN Sdb *Elf_(rz_bin_elf_get_version_info_gnu_versym)(RZ_NONNULL ELFOBJ *bin);
RZ_IPI bool Elf_(rz_bin_elf_init_dynamic_section)(RZ_NONNULL RZ_INOUT ELFOBJ *bin);
RZ_IPI bool Elf_(rz_bin_elf_init_dynstr)(RZ_NONNULL RZ_INOUT ELFOBJ *bin);
RZ_IPI bool Elf_(rz_bin_elf_init_ehdr)(RZ_NONNULL RZ_INOUT ELFOBJ *bin);
RZ_IPI bool Elf_(rz_bin_elf_init_notes)(RZ_NONNULL RZ_INOUT ELFOBJ *bin);
RZ_IPI bool Elf_(rz_bin_elf_init_phdr)(RZ_NONNULL RZ_INOUT ELFOBJ *bin);
RZ_IPI bool Elf_(rz_bin_elf_init_shdr)(RZ_NONNULL RZ_INOUT ELFOBJ *bin);
RZ_IPI bool Elf_(rz_bin_elf_init_shstrtab)(RZ_NONNULL RZ_INOUT ELFOBJ *bin);
RZ_IPI bool Elf_(rz_bin_elf_init_strtab)(RZ_NONNULL RZ_INOUT ELFOBJ *bin);
RZ_IPI bool Elf_(rz_bin_elf_is_sh_index_valid)(RZ_NONNULL ELFOBJ *bin, Elf_(Half) index);

RZ_OWN RzBinImport *Elf_(rz_bin_elf_convert_import)(RZ_UNUSED ELFOBJ *bin, RZ_NONNULL RzBinElfSymbol *symbol);
RZ_OWN RzBinSymbol *Elf_(rz_bin_elf_convert_symbol)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RzBinElfSymbol *symbol, const char *namefmt);
void Elf_(rz_bin_elf_free)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_abi)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_arch)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_baddr)(RZ_NONNULL ELFOBJ *bin);
int Elf_(rz_bin_elf_get_bits)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_boffset)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_cpu)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_data_encoding)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_elf_class)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_entry_offset)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN RzBinElfField *Elf_(rz_bin_elf_get_fields)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_file_type)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_fini_offset)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_head_flag)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_init_offset)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN RzBinElfLib *Elf_(rz_bin_elf_get_libs)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_machine_name)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_main_offset)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_osabi_name)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_rpath)(RZ_NONNULL ELFOBJ *bin);
RZ_BORROW RzBinElfSection *Elf_(rz_bin_elf_get_section)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *section_name);
ut64 Elf_(rz_bin_elf_get_section_addr)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *section_name);
ut64 Elf_(rz_bin_elf_get_section_addr_end)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *section_name);
ut64 Elf_(rz_bin_elf_get_section_offset)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *section_name);
RZ_OWN RzBinElfSection *Elf_(rz_bin_elf_get_sections)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_sp_val)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_get_stripped)(RZ_NONNULL ELFOBJ *bin);
RZ_BORROW const ut8 *Elf_(rz_bin_elf_grab_regstate)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL size_t *size);
bool Elf_(rz_bin_elf_has_nx)(RZ_NONNULL ELFOBJ *bin);
int Elf_(rz_bin_elf_has_relro)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_has_va)(ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_intrp)(RZ_NONNULL ELFOBJ *bin);
int Elf_(rz_bin_elf_is_big_endian)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_is_executable)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_is_relocatable)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_is_static)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN ELFOBJ *Elf_(rz_bin_elf_new_buf)(RZ_NONNULL RzBuffer *buf, bool verbose);
RZ_OWN RzList *Elf_(section_flag_to_rzlist)(ut64 flag);
RZ_OWN char *Elf_(section_type_to_string)(ut64 type);

#endif
