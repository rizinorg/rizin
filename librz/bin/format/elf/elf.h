// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
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

#define RZ_BIN_ELF_NO_RELRO   0
#define RZ_BIN_ELF_PART_RELRO 1
#define RZ_BIN_ELF_FULL_RELRO 2

#define ELFOBJ struct Elf_(rz_bin_elf_obj_t)

#define rz_bin_elf_foreach_segments(bin, segment) \
	if (Elf_(rz_bin_elf_has_segments)(bin)) \
	rz_vector_foreach((bin)->segments, segment)
#define rz_bin_elf_foreach_sections(bin, section) \
	if (Elf_(rz_bin_elf_has_sections)(bin)) \
	rz_vector_foreach((bin)->sections, section)
#define rz_bin_elf_enumerate_sections(bin, section, i) \
	if (Elf_(rz_bin_elf_has_sections)(bin)) \
	rz_vector_enumerate((bin)->sections, section, i)
#define rz_bin_elf_foreach_relocs(bin, reloc) \
	if (Elf_(rz_bin_elf_has_relocs)(bin)) \
	rz_vector_foreach(bin->relocs, reloc)

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
	ut32 flags;
	ut32 info;
	ut32 link;
	ut32 type;
	ut64 align;
	ut64 offset;
	ut64 rva;
	ut64 size;
	char *name;
	bool is_valid;
} RzBinElfSection;

typedef struct Elf_(rz_bin_elf_segment_t) {
	Elf_(Phdr) data;
	bool is_valid;
}
RzBinElfSegment;

typedef struct rz_bin_elf_symbol_t {
	ut64 offset;
	ut64 size;
	ut32 ordinal;
	const char *bind;
	const char *type;
	const char *name;
	const char *libname;
	int last;
	bool in_shdr;
	bool is_sht_null;
	bool is_vaddr; /* when true, offset is virtual address, otherwise it's physical */
	bool is_imported;
} RzBinElfSymbol;

typedef struct rz_bin_elf_reloc_t {
	ut64 sym;
	int type;
	ut64 mode;
	st64 addend; ///< exact addend value taken from the ELF, meaning depends on type
	ut64 offset; ///< exact offset value taken from the ELF, meaning depends on the binary type
	ut64 paddr; ///< absolute paddr in the file, calculated from offset, or UT64_MAX if no such addr exists
	ut64 vaddr; ///< source vaddr of the reloc, calculated from offset
	ut64 target_vaddr; ///< after patching, the target that this reloc points to
	ut16 section;
	ut64 sto;
} RzBinElfReloc;

typedef struct rz_bin_elf_dt_dynamic_t RzBinElfDtDynamic; // elf_dynamic.h

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

typedef struct rz_bin_elf_strtab RzBinElfStrtab;

struct Elf_(rz_bin_elf_obj_t) {
	RzBuffer *b;
	RzBuffer *buf_patched; ///< overlay over the original file with relocs patched

	Sdb *kv;

	const char *file;
	ut64 size;

	ut64 baddr;
	ut64 boffset;
	int endian;
	int bss;

	Elf_(Ehdr) ehdr;

	RzVector *segments; // should be use with elf_segments.c
	RzVector *sections; // should be use with elf_sections.c

	RzBinElfDtDynamic *dt_dynamic; // should be use with elf_dynamic.c

	RzBinElfStrtab *dynstr; // should be use with elf_strtab.c
	RzBinElfStrtab *shstrtab; // should be use with elf_strtab.c

	RzVector *relocs; // should be use with elf_relocs.c
	bool reloc_targets_map_base_calculated;
	bool relocs_patched;
	ut64 reloc_targets_map_base;

	RzList /*<RzBinElfNoteSegment>*/ *note_segments;

	RzBinImport **imports_by_ord;
	size_t imports_by_ord_size;
	RzBinSymbol **symbols_by_ord;
	size_t symbols_by_ord_size;

	/*cache purpose*/
	RzBinElfSymbol *g_symbols;
	RzBinElfSymbol *g_imports;
	RzBinElfSymbol *phdr_symbols;
	RzBinElfSymbol *phdr_imports;
};

// elf.c

RZ_OWN ELFOBJ *Elf_(rz_bin_elf_new_buf)(RZ_NONNULL RzBuffer *buf);
void Elf_(rz_bin_elf_free)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_p2v_new)(RZ_NONNULL ELFOBJ *bin, ut64 paddr);
ut64 Elf_(rz_bin_elf_v2p_new)(RZ_NONNULL ELFOBJ *bin, ut64 vaddr);

// elf_corefile.c

RZ_BORROW RzBinElfPrStatusLayout *Elf_(rz_bin_elf_get_prstatus_layout)(RZ_NONNULL ELFOBJ *bin);
RZ_BORROW const ut8 *Elf_(rz_bin_elf_grab_regstate)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL size_t *size);
ut64 Elf_(rz_bin_elf_get_sp_val)(RZ_NONNULL ELFOBJ *bin);

// elf_dynamic.c
RZ_BORROW RzVector *Elf_(rz_bin_elf_get_dt_needed)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN RzBinElfDtDynamic *Elf_(rz_bin_elf_dt_dynamic_new)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_get_dt_info)(RZ_NONNULL ELFOBJ *bin, ut64 key, RZ_OUT ut64 *info);
bool Elf_(rz_bin_elf_has_dt_dynamic)(RZ_NONNULL ELFOBJ *bin);
void Elf_(rz_bin_elf_dt_dynamic_free)(RzBinElfDtDynamic *ptr);

// elf_info.c

RZ_OWN RzList *Elf_(rz_bin_elf_get_libs)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN Sdb *Elf_(rz_bin_elf_get_version_info)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_abi)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_arch)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_compiler)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_cpu)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_elf_class)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_file_type)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_head_flag)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_intrp)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_machine_name)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_osabi_name)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_rpath)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_has_nx)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_has_va)(ELFOBJ *bin);
bool Elf_(rz_bin_elf_is_big_endian)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_is_executable)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_is_relocatable)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_is_static)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_is_stripped)(RZ_NONNULL ELFOBJ *bin);
int Elf_(rz_bin_elf_get_bits)(RZ_NONNULL ELFOBJ *bin);
int Elf_(rz_bin_elf_has_relro)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_baddr)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_boffset)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_entry_offset)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_fini_offset)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_init_offset)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_main_offset)(RZ_NONNULL ELFOBJ *bin);

// elf_notes.c

bool Elf_(rz_bin_elf_init_notes)(RZ_NONNULL ELFOBJ *bin);

// elf_misc.c

bool Elf_(rz_bin_elf_check_array)(RZ_NONNULL ELFOBJ *bin, Elf_(Off) offset, Elf_(Off) length, Elf_(Off) entry_size);
bool Elf_(rz_bin_elf_read_addr)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Addr) * result);
bool Elf_(rz_bin_elf_read_char)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT ut8 *result);
bool Elf_(rz_bin_elf_read_half)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Half) * result);
bool Elf_(rz_bin_elf_read_off)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Off) * result);
bool Elf_(rz_bin_elf_read_section)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Section) * result);
bool Elf_(rz_bin_elf_read_sword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Sword) * result);
bool Elf_(rz_bin_elf_read_sxword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Sxword) * result);
bool Elf_(rz_bin_elf_read_versym)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Versym) * result);
bool Elf_(rz_bin_elf_read_word)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Word) * result);
bool Elf_(rz_bin_elf_read_xword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Xword) * result);
#if RZ_BIN_ELF64
bool Elf_(rz_bin_elf_read_word_xword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Xword) * result);
bool Elf_(rz_bin_elf_read_sword_sxword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Sxword) * result);
#else
bool Elf_(rz_bin_elf_read_word_xword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Word) * result);
bool Elf_(rz_bin_elf_read_sword_sxword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Sword) * result);
#endif
bool Elf_(rz_bin_elf_add_addr)(Elf_(Addr) * result, Elf_(Addr) addr, Elf_(Addr) value);
bool Elf_(rz_bin_elf_add_off)(Elf_(Off) * result, Elf_(Off) addr, Elf_(Off) value);
bool Elf_(rz_bin_elf_mul_addr)(Elf_(Addr) * result, Elf_(Addr) addr, Elf_(Addr) value);
bool Elf_(rz_bin_elf_mul_off)(Elf_(Off) * result, Elf_(Off) addr, Elf_(Off) value);

// elf_relocs.c

RZ_OWN RzVector *Elf_(rz_bin_elf_relocs_new)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_has_relocs)(RZ_NONNULL ELFOBJ *bin);
size_t Elf_(rz_bin_elf_get_relocs_count)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_num_relocs_dynamic_plt)(RZ_NONNULL ELFOBJ *bin);

// elf_segments.c

RZ_BORROW RzBinElfSegment *Elf_(rz_bin_elf_get_segment_with_type)(RZ_NONNULL ELFOBJ *bin, Elf_(Word) type);
RZ_OWN RzVector *Elf_(rz_bin_elf_segments_new)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_has_segments)(RZ_NONNULL ELFOBJ *bin);

// elf_sections.c

RZ_BORROW RzBinElfSection *Elf_(rz_bin_elf_get_section)(RZ_NONNULL ELFOBJ *bin, Elf_(Half) index);
RZ_BORROW RzBinElfSection *Elf_(rz_bin_elf_get_section_with_name)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *name);
RZ_OWN RzList *Elf_(rz_bin_elf_section_flag_to_rzlist)(ut64 flag);
RZ_OWN RzVector *Elf_(rz_bin_elf_convert_sections)(RZ_NONNULL ELFOBJ *bin, RzVector *sections);
RZ_OWN RzVector *Elf_(rz_bin_elf_sections_new)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_section_type_to_string)(ut64 type);
bool Elf_(rz_bin_elf_has_sections)(RZ_NONNULL ELFOBJ *bin);

// elf_strtab

RZ_BORROW const char *Elf_(rz_bin_elf_strtab_get)(RZ_NONNULL RzBinElfStrtab *strtab, ut64 index);
RZ_OWN RzBinElfStrtab *Elf_(rz_bin_elf_strtab_new)(RZ_NONNULL ELFOBJ *bin, ut64 offset, ut64 size);
RZ_OWN char *Elf_(rz_bin_elf_strtab_get_dup)(RZ_NONNULL RzBinElfStrtab *strtab, ut64 index);
bool Elf_(rz_bin_elf_strtab_has_index)(RZ_NONNULL RzBinElfStrtab *strtab, ut64 index);
void Elf_(rz_bin_elf_strtab_free)(RzBinElfStrtab *ptr);

// elf_symbols.c

RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_imports)(RZ_NONNULL ELFOBJ *bin);
RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_symbols)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN RzBinImport *Elf_(rz_bin_elf_convert_import)(RZ_UNUSED ELFOBJ *bin, RZ_NONNULL RzBinElfSymbol *symbol);
RZ_OWN RzBinSymbol *Elf_(rz_bin_elf_convert_symbol)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RzBinElfSymbol *symbol, const char *namefmt);
Elf_(Word) Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(RZ_NONNULL ELFOBJ *bin);

#endif
