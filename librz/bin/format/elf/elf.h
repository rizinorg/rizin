// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
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
		rz_vector_foreach ((bin)->segments, segment)

#define rz_bin_elf_foreach_sections(bin, section) \
	if (Elf_(rz_bin_elf_has_sections)(bin)) \
		rz_vector_foreach ((bin)->sections, section)

#define rz_bin_elf_enumerate_sections(bin, section, i) \
	if (Elf_(rz_bin_elf_has_sections)(bin)) \
		rz_vector_enumerate ((bin)->sections, section, i)

#define rz_bin_elf_foreach_relocs(bin, reloc) \
	if (Elf_(rz_bin_elf_has_relocs)(bin)) \
		rz_vector_foreach ((bin)->relocs, reloc)

#define rz_bin_elf_foreach_notes_segment(bin, notes) \
	if (Elf_(rz_bin_elf_has_notes)(bin)) \
		rz_vector_foreach ((bin)->notes, notes)

#define rz_bin_elf_foreach_symbols(bin, symbol) \
	if (Elf_(rz_bin_elf_has_symbols)(bin)) \
		rz_vector_foreach (bin->symbols, symbol)

#define rz_bin_elf_foreach_imports(bin, import) \
	if (Elf_(rz_bin_elf_has_imports)(bin)) \
		rz_vector_foreach (bin->imports, import)

struct gnu_hash_table { // DT_GNU_HASH
	Elf_(Word) nbuckets;
	Elf_(Word) symoffset;
	Elf_(Word) bloom_size;
	Elf_(Word) bloom_shift;
	//	Elf_(Addr) boom[bloom_size];
	//	Elf_(Word) buckets[nbuckets];
	//	Elf_(Word) chains[];
};

typedef struct rz_bin_elf_gnu_hash_table_t {
	ut64 offset; /*!< offset of the dt_gnu_hash struct in memory */
	struct gnu_hash_table data;
} RzBinElfGnuHashTable;

struct elf_hash_table { // DT_HASH
	Elf_(Word) nbuckets;
	Elf_(Word) nchains;
	//	Elf_(Word) buckets[nbuckets];
	//	Elf_(Word) chains[nchains];
};

typedef struct rz_bin_elf_hash_table_ {
	ut64 offset; /*!< offset of the dt_hash struct in memory */
	struct elf_hash_table data;
} RzBinElfHashTable;

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
	ut64 paddr;
	ut64 vaddr;
	ut64 size;
	ut32 ordinal;
	const char *bind;
	const char *type;
	RZ_OWN char *name;
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
typedef struct rz_bin_elf_note_prstatus_t {
	size_t regstate_size;
	ut8 *regstate;
	// Hint: there is more info in NT_PRSTATUS notes that could be parsed if needed.
} RzBinElfNotePrStatus;

/// A single PT_NOTE entry, parsed from an ElfW(Nhdr) and associated data.
typedef struct Elf_(rz_bin_elf_note_t) {
	Elf_(Word) type;
	union {
		RzBinElfNoteFile file; //< for type == NT_FILE
		RzBinElfNotePrStatus prstatus; //< for type = NT_PRSTATUS
	};
}
RzBinElfNote;

typedef struct rz_bin_elf_strtab RzBinElfStrtab;

struct Elf_(rz_bin_elf_obj_t) {
	RzBuffer *b;

	RzBuffer *buf_patched; ///< overlay over the original file with relocs patched
	bool relocs_patched;
	ut64 reloc_targets_map_base;

	Sdb *kv;

	ut64 size;

	bool big_endian;
	int bits;
	ut64 baddr;
	ut64 boffset;

	Elf_(Ehdr) ehdr;

	RzVector /*<RzBinElfSegment>*/ *segments; // should be use with elf_segments.c
	RzVector /*<RzBinElfSection>*/ *sections; // should be use with elf_sections.c

	RzBinElfDtDynamic *dt_dynamic; // should be use with elf_dynamic.c

	RzBinElfStrtab *dynstr; // should be use with elf_strtab.c
	RzBinElfStrtab *shstrtab; // should be use with elf_strtab.c

	RzVector /*<RzBinElfReloc>*/ *relocs; // should be use with elf_relocs.c

	// This is RzVector of note segment reprensented as RzVector<RzBinElfNote>
	RzVector /*<RzVector<RzBinElfNote>>*/ *notes; // RzVector<RzVector<RzBinElfNote>>

	RzVector /*<RzBinElfSymbol>*/ *symbols; // RzVector<RzBinElfSymbol>
	RzVector /*<RzBinElfSymbol>*/ *imports; // RzVector<RzBinElfSymbol>
};

// elf.c
RZ_OWN ELFOBJ *Elf_(rz_bin_elf_new_buf)(RZ_NONNULL RzBuffer *buf, RZ_NONNULL RzBinObjectLoadOptions *options);
void Elf_(rz_bin_elf_free)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_p2v)(RZ_NONNULL ELFOBJ *bin, ut64 paddr);
ut64 Elf_(rz_bin_elf_v2p)(RZ_NONNULL ELFOBJ *bin, ut64 vaddr);

// elf_arm.c
#define rz_bin_elf_fix_arm_thumb_object_dispatch(object) \
	Elf_(rz_bin_elf_fix_arm_thumb_object)(&object->paddr, &object->vaddr, &object->bits)

bool Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_is_thumb_addr)(ut64 addr);
void Elf_(rz_bin_elf_fix_arm_thumb_addr)(ut64 *addr);
void Elf_(rz_bin_elf_fix_arm_thumb_object)(RZ_NONNULL ut64 *paddr, RZ_NONNULL ut64 *vaddr, RZ_NONNULL int *bits);
void Elf_(rz_bin_elf_fix_arm_thumb_symbol)(RZ_NONNULL RzBinSymbol *symbol);

// elf_corefile.c
ut64 Elf_(rz_bin_elf_get_sp_val)(RZ_NONNULL ELFOBJ *bin);

// elf_dynamic.c
RZ_BORROW RzVector /*<ut64>*/ *Elf_(rz_bin_elf_get_dt_needed)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN RzBinElfDtDynamic *Elf_(rz_bin_elf_dt_dynamic_new)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_get_dt_info)(RZ_NONNULL ELFOBJ *bin, ut64 key, RZ_OUT ut64 *info);
bool Elf_(rz_bin_elf_has_dt_dynamic)(RZ_NONNULL ELFOBJ *bin);
void Elf_(rz_bin_elf_dt_dynamic_free)(RzBinElfDtDynamic *ptr);

// elf_ehdr.c
RZ_OWN char *Elf_(rz_bin_elf_get_e_ehsize_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_entry_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_flags_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_indent_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_machine_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_phentsize_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_phnum_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_phoff_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_shentsize_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_shnum_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_shoff_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_shstrndx_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_type_as_string)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_get_e_version_as_string)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_get_ehdr)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_print_ehdr)(ELFOBJ *bin, RZ_NONNULL PrintfCallback cb);

// elf_hash.c
bool Elf_(rz_bin_elf_get_gnu_hash_table)(RZ_NONNULL ELFOBJ *bin, RzBinElfGnuHashTable *result);
bool Elf_(rz_bin_elf_get_hash_table)(RZ_NONNULL ELFOBJ *bin, RzBinElfHashTable *result);
size_t Elf_(rz_bin_elf_get_number_of_symbols_from_gnu_hash_table)(RZ_NONNULL ELFOBJ *bin);
size_t Elf_(rz_bin_elf_get_number_of_symbols_from_hash_table)(RZ_NONNULL ELFOBJ *bin);

// elf_imports.c
RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_import)(RZ_NONNULL ELFOBJ *bin, ut32 ordinal);
RZ_OWN RzVector /*<RzBinElfSymbol>*/ *Elf_(rz_bin_elf_analyse_imports)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_has_imports)(RZ_NONNULL ELFOBJ *bin);

// elf_map.c
ut64 Elf_(rz_bin_elf_get_targets_map_base)(ELFOBJ *bin);

// elf_info.c
RZ_OWN RzPVector /*<char *>*/ *Elf_(rz_bin_elf_get_libs)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN Sdb *Elf_(rz_bin_elf_get_symbols_info)(RZ_NONNULL ELFOBJ *bin);
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
bool Elf_(rz_bin_elf_has_nobtcfi)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_baddr)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_boffset)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_entry_offset)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_fini_offset)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_init_offset)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_main_offset)(RZ_NONNULL ELFOBJ *bin);

// elf_notes.c
RZ_BORROW RzBinElfPrStatusLayout *Elf_(rz_bin_elf_get_prstatus_layout)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN RzVector /*<RzVector<RzBinElfNote>>*/ *Elf_(rz_bin_elf_notes_new)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_has_notes)(RZ_NONNULL ELFOBJ *bin);

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
RZ_OWN RzVector /*<RzBinElfReloc>*/ *Elf_(rz_bin_elf_relocs_new)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_has_relocs)(RZ_NONNULL ELFOBJ *bin);
size_t Elf_(rz_bin_elf_get_relocs_count)(RZ_NONNULL ELFOBJ *bin);
ut64 Elf_(rz_bin_elf_get_num_relocs_dynamic_plt)(RZ_NONNULL ELFOBJ *bin);

// elf_segments.c
RZ_BORROW RzBinElfSegment *Elf_(rz_bin_elf_get_segment_with_type)(RZ_NONNULL ELFOBJ *bin, Elf_(Word) type);
RZ_OWN RzVector /*<RzBinElfSegment>*/ *Elf_(rz_bin_elf_segments_new)(RZ_NONNULL ELFOBJ *bin, RzVector /*<Elf_(Shdr)>*/ *sections, RZ_NONNULL RzBinObjectLoadOptions *options);
bool Elf_(rz_bin_elf_has_segments)(RZ_NONNULL ELFOBJ *bin);

// elf_sections.c
RZ_BORROW RzBinElfSection *Elf_(rz_bin_elf_get_section)(RZ_NONNULL ELFOBJ *bin, Elf_(Half) index);
RZ_BORROW RzBinElfSection *Elf_(rz_bin_elf_get_section_with_name)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *name);
RZ_OWN RzList /*<char *>*/ *Elf_(rz_bin_elf_section_flag_to_rzlist)(ut64 flag);
RZ_OWN RzVector /*<RzBinElfSection>*/ *Elf_(rz_bin_elf_convert_sections)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RzBinObjectLoadOptions *options, RzVector /*<Elf_(Shdr)>*/ *sections);
RZ_OWN RzVector /*<Elf_(Shdr)>*/ *Elf_(rz_bin_elf_sections_new)(RZ_NONNULL ELFOBJ *bin);
RZ_OWN char *Elf_(rz_bin_elf_section_type_to_string)(ut64 type);
bool Elf_(rz_bin_elf_has_sections)(RZ_NONNULL ELFOBJ *bin);

// elf_strtab
RZ_BORROW const char *Elf_(rz_bin_elf_strtab_get)(RZ_NONNULL RzBinElfStrtab *strtab, ut64 index);
RZ_OWN RzBinElfStrtab *Elf_(rz_bin_elf_strtab_new)(RZ_NONNULL ELFOBJ *bin, ut64 offset, ut64 size);
RZ_OWN char *Elf_(rz_bin_elf_strtab_get_dup)(RZ_NONNULL RzBinElfStrtab *strtab, ut64 index);
bool Elf_(rz_bin_elf_strtab_has_index)(RZ_NONNULL RzBinElfStrtab *strtab, ut64 index);
void Elf_(rz_bin_elf_strtab_free)(RzBinElfStrtab *ptr);

// elf_symbols.c
typedef bool (*RzBinElfSymbolFilter)(ELFOBJ *bin, Elf_(Sym) * entry, bool is_dynamic);

Elf_(Word) Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(RZ_NONNULL ELFOBJ *bin);
RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_symbol)(RZ_NONNULL ELFOBJ *bin, ut32 ordinal);
RZ_OWN RzVector /*<RzBinElfSymbol>*/ *Elf_(rz_bin_elf_compute_symbols)(ELFOBJ *bin, RzBinElfSymbolFilter filter);
RZ_OWN RzVector /*<RzBinElfSymbol>*/ *Elf_(rz_bin_elf_symbols_new)(RZ_NONNULL ELFOBJ *bin);
bool Elf_(rz_bin_elf_has_symbols)(RZ_NONNULL ELFOBJ *bin);

#endif
