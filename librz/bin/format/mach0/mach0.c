// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2010-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_util.h>
#include "mach0.h"
#include <rz_hash.h>

#include "mach0_utils.inc"

// TODO: deprecate bprintf and Eprintf and use RZ_LOG_*() instead
#define bprintf \
	if (bin->options.verbose) \
	eprintf
#define Eprintf \
	if (mo->options.verbose) \
	eprintf

typedef struct {
	struct symbol_t *symbols;
	int j;
	int symbols_count;
	HtSP *hash;
} RSymCtx;

typedef void (*RExportsIterator)(struct MACH0_(obj_t) * bin, const char *name, ut64 flags, ut64 offset, void *ctx);

typedef struct {
	ut8 *node;
	char *label;
	int i;
	ut8 *next_child;
} RTrieState;

// OMG; THIS SHOULD BE KILLED; this var exposes the local native endian, which is completely unnecessary
// USE THIS: int ws = bf->o->info->big_endian;
#define mach0_endian 1

static ut64 entry_to_vaddr(struct MACH0_(obj_t) * bin) {
	switch (bin->main_cmd.cmd) {
	case LC_MAIN:
		return bin->entry + bin->baddr;
	case LC_UNIXTHREAD:
	case LC_THREAD:
		return bin->entry;
	default:
		return 0;
	}
}

RZ_API ut64 MACH0_(vaddr_to_paddr)(struct MACH0_(obj_t) * bin, ut64 addr) {
	if (bin->segs) {
		size_t i;
		for (i = 0; i < bin->nsegs; i++) {
			const ut64 segment_base = (ut64)bin->segs[i].vmaddr;
			const ut64 segment_size = (ut64)bin->segs[i].vmsize;
			if (addr >= segment_base && addr < segment_base + segment_size) {
				return bin->segs[i].fileoff + (addr - segment_base);
			}
		}
	}
	return 0;
}

RZ_API ut64 MACH0_(paddr_to_vaddr)(struct MACH0_(obj_t) * bin, ut64 offset) {
	if (bin->segs) {
		size_t i;
		for (i = 0; i < bin->nsegs; i++) {
			ut64 segment_base = (ut64)bin->segs[i].fileoff;
			ut64 segment_size = (ut64)bin->segs[i].filesize;
			if (offset >= segment_base && offset < segment_base + segment_size) {
				return bin->segs[i].vmaddr + (offset - segment_base);
			}
		}
	}
	return 0;
}

static ut64 pa2va(RzBinFile *bf, ut64 offset) {
	rz_return_val_if_fail(bf && bf->rbin, offset);
	RzIO *io = bf->rbin->iob.io;
	if (!io || !io->va) {
		return offset;
	}
	struct MACH0_(obj_t) *bin = bf->o->bin_obj;
	return bin ? MACH0_(paddr_to_vaddr)(bin, offset) : offset;
}

static void init_sdb_formats(struct MACH0_(obj_t) * bin) {
	/*
	 * These definitions are used by rz -nn
	 * must be kept in sync with librz/bin/d/macho
	 */
	sdb_set(bin->kv, "mach0_build_platform.cparse",
		"enum mach0_build_platform"
		"{MACOS=1, IOS=2, TVOS=3, WATCHOS=4, BRIDGEOS=5, IOSMAC=6, IOSSIMULATOR=7, TVOSSIMULATOR=8, WATCHOSSIMULATOR=9};");
	sdb_set(bin->kv, "mach0_build_tool.cparse",
		"enum mach0_build_tool"
		"{CLANG=1, SWIFT=2, LD=3};");
	sdb_set(bin->kv, "mach0_load_command_type.cparse",
		"enum mach0_load_command_type"
		"{ LC_SEGMENT=0x00000001ULL, LC_SYMTAB=0x00000002ULL, LC_SYMSEG=0x00000003ULL, LC_THREAD=0x00000004ULL, LC_UNIXTHREAD=0x00000005ULL, LC_LOADFVMLIB=0x00000006ULL, LC_IDFVMLIB=0x00000007ULL, LC_IDENT=0x00000008ULL, LC_FVMFILE=0x00000009ULL, LC_PREPAGE=0x0000000aULL, LC_DYSYMTAB=0x0000000bULL, LC_LOAD_DYLIB=0x0000000cULL, LC_ID_DYLIB=0x0000000dULL, LC_LOAD_DYLINKER=0x0000000eULL, LC_ID_DYLINKER=0x0000000fULL, LC_PREBOUND_DYLIB=0x00000010ULL, LC_ROUTINES=0x00000011ULL, LC_SUB_FRAMEWORK=0x00000012ULL, LC_SUB_UMBRELLA=0x00000013ULL, LC_SUB_CLIENT=0x00000014ULL, LC_SUB_LIBRARY=0x00000015ULL, LC_TWOLEVEL_HINTS=0x00000016ULL, LC_PREBIND_CKSUM=0x00000017ULL, LC_LOAD_WEAK_DYLIB=0x80000018ULL, LC_SEGMENT_64=0x00000019ULL, LC_ROUTINES_64=0x0000001aULL, LC_UUID=0x0000001bULL, LC_RPATH=0x8000001cULL, LC_CODE_SIGNATURE=0x0000001dULL, LC_SEGMENT_SPLIT_INFO=0x0000001eULL, LC_REEXPORT_DYLIB=0x8000001fULL, LC_LAZY_LOAD_DYLIB=0x00000020ULL, LC_ENCRYPTION_INFO=0x00000021ULL, LC_DYLD_INFO=0x00000022ULL, LC_DYLD_INFO_ONLY=0x80000022ULL, LC_LOAD_UPWARD_DYLIB=0x80000023ULL, LC_VERSION_MIN_MACOSX=0x00000024ULL, LC_VERSION_MIN_IPHONEOS=0x00000025ULL, LC_FUNCTION_STARTS=0x00000026ULL, LC_DYLD_ENVIRONMENT=0x00000027ULL, LC_MAIN=0x80000028ULL, LC_DATA_IN_CODE=0x00000029ULL, LC_SOURCE_VERSION=0x0000002aULL, LC_DYLIB_CODE_SIGN_DRS=0x0000002bULL, LC_ENCRYPTION_INFO_64=0x0000002cULL, LC_LINKER_OPTION=0x0000002dULL, LC_LINKER_OPTIMIZATION_HINT=0x0000002eULL, LC_VERSION_MIN_TVOS=0x0000002fULL, LC_VERSION_MIN_WATCHOS=0x00000030ULL, LC_NOTE=0x00000031ULL, LC_BUILD_VERSION=0x00000032ULL };");
	sdb_set(bin->kv, "mach0_header_filetype.cparse",
		"enum mach0_header_filetype"
		"{MH_OBJECT=1, MH_EXECUTE=2, MH_FVMLIB=3, MH_CORE=4, MH_PRELOAD=5, MH_DYLIB=6, MH_DYLINKER=7, MH_BUNDLE=8, MH_DYLIB_STUB=9, MH_DSYM=10, MH_KEXT_BUNDLE=11};");
	sdb_set(bin->kv, "mach0_header_flags.cparse",
		"enum mach0_header_flags"
		"{MH_NOUNDEFS=1, MH_INCRLINK=2,MH_DYLDLINK=4,MH_BINDATLOAD=8,MH_PREBOUND=0x10, MH_SPLIT_SEGS=0x20,MH_LAZY_INIT=0x40,MH_TWOLEVEL=0x80, MH_FORCE_FLAT=0x100,MH_NOMULTIDEFS=0x200,MH_NOFIXPREBINDING=0x400, MH_PREBINDABLE=0x800, MH_ALLMODSBOUND=0x1000, MH_SUBSECTIONS_VIA_SYMBOLS=0x2000, MH_CANONICAL=0x4000,MH_WEAK_DEFINES=0x8000, MH_BINDS_TO_WEAK=0x10000,MH_ALLOW_STACK_EXECUTION=0x20000, MH_ROOT_SAFE=0x40000,MH_SETUID_SAFE=0x80000, MH_NO_REEXPORTED_DYLIBS=0x100000,MH_PIE=0x200000, MH_DEAD_STRIPPABLE_DYLIB=0x400000, MH_HAS_TLV_DESCRIPTORS=0x800000, MH_NO_HEAP_EXECUTION=0x1000000};");
	sdb_set(bin->kv, "mach0_section_types.cparse",
		"enum mach0_section_types"
		"{S_REGULAR=0, S_ZEROFILL=1, S_CSTRING_LITERALS=2, S_4BYTE_LITERALS=3, S_8BYTE_LITERALS=4, S_LITERAL_POINTERS=5, S_NON_LAZY_SYMBOL_POINTERS=6, S_LAZY_SYMBOL_POINTERS=7, S_SYMBOL_STUBS=8, S_MOD_INIT_FUNC_POINTERS=9, S_MOD_TERM_FUNC_POINTERS=0xa, S_COALESCED=0xb, S_GB_ZEROFILL=0xc, S_INTERPOSING=0xd, S_16BYTE_LITERALS=0xe, S_DTRACE_DOF=0xf, S_LAZY_DYLIB_SYMBOL_POINTERS=0x10, S_THREAD_LOCAL_REGULAR=0x11, S_THREAD_LOCAL_ZEROFILL=0x12, S_THREAD_LOCAL_VARIABLES=0x13, S_THREAD_LOCAL_VARIABLE_POINTERS=0x14, S_THREAD_LOCAL_INIT_FUNCTION_POINTERS=0x15, S_INIT_FUNC_OFFSETS=0x16};");
	sdb_set(bin->kv, "mach0_section_attrs.cparse",
		"enum mach0_section_attrs"
		"{S_ATTR_PURE_INSTRUCTIONS=0x800000ULL, S_ATTR_NO_TOC=0x400000ULL, S_ATTR_STRIP_STATIC_SYMS=0x200000ULL, S_ATTR_NO_DEAD_STRIP=0x100000ULL, S_ATTR_LIVE_SUPPORT=0x080000ULL, S_ATTR_SELF_MODIFYING_CODE=0x040000ULL, S_ATTR_DEBUG=0x020000ULL, S_ATTR_SOME_INSTRUCTIONS=0x000004ULL, S_ATTR_EXT_RELOC=0x000002ULL, S_ATTR_LOC_RELOC=0x000001ULL};");
	sdb_set(bin->kv, "mach0_header.format",
		"xxx[4]Edd[4]B "
		"magic cputype cpusubtype (mach0_header_filetype)filetype ncmds sizeofcmds (mach0_header_flags)flags");
	sdb_set(bin->kv, "mach0_segment.format",
		"[4]Ed[16]zxxxxoodx "
		"(mach0_load_command_type)cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags");
	sdb_set(bin->kv, "mach0_segment64.format",
		"[4]Ed[16]zqqqqoodx "
		"(mach0_load_command_type)cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags");
	sdb_set(bin->kv, "mach0_symtab_command.format",
		"[4]Edxdxd "
		"(mach0_load_command_type)cmd cmdsize symoff nsyms stroff strsize");
	sdb_set(bin->kv, "mach0_dysymtab_command.format",
		"[4]Edddddddddddxdxdxxxd "
		"(mach0_load_command_type)cmd cmdsize ilocalsym nlocalsym iextdefsym nextdefsym iundefsym nundefsym tocoff ntoc moddtaboff nmodtab extrefsymoff nextrefsyms inddirectsymoff nindirectsyms extreloff nextrel locreloff nlocrel");
	sdb_set(bin->kv, "mach0_section.format",
		"[16]z[16]zxxxxxx[1]E[3]Bxx "
		"sectname segname addr size offset align reloff nreloc (mach0_section_types)flags_type (mach0_section_attrs)flags_attr reserved1 reserved2");
	sdb_set(bin->kv, "mach0_section64.format",
		"[16]z[16]zqqxxxx[1]E[3]Bxxx "
		"sectname segname addr size offset align reloff nreloc (mach0_section_types)flags_type (mach0_section_attrs)flags_attr reserved1 reserved2 reserved3");
	sdb_set(bin->kv, "mach0_dylib.format",
		"xxxxz "
		"name_offset timestamp current_version compatibility_version name");
	sdb_set(bin->kv, "mach0_dylib_command.format",
		"[4]Ed? "
		"(mach0_load_command_type)cmd cmdsize (mach0_dylib)dylib");
	sdb_set(bin->kv, "mach0_id_dylib_command.format",
		"[4]Ed? "
		"(mach0_load_command_type)cmd cmdsize (mach0_dylib)dylib");
	sdb_set(bin->kv, "mach0_uuid_command.format",
		"[4]Ed[16]b "
		"(mach0_load_command_type)cmd cmdsize uuid");
	sdb_set(bin->kv, "mach0_rpath_command.format",
		"[4]Edxz "
		"(mach0_load_command_type)cmd cmdsize path_offset path");
	sdb_set(bin->kv, "mach0_entry_point_command.format",
		"[4]Edqq "
		"(mach0_load_command_type)cmd cmdsize entryoff stacksize");
	sdb_set(bin->kv, "mach0_encryption_info64_command.format",
		"[4]Edxddx "
		"(mach0_load_command_type)cmd cmdsize offset size id padding");
	sdb_set(bin->kv, "mach0_encryption_info_command.format",
		"[4]Edxdd "
		"(mach0_load_command_type)cmd cmdsize offset size id");
	sdb_set(bin->kv, "mach0_code_signature_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size");
	sdb_set(bin->kv, "mach0_dyld_info_only_command.format",
		"[4]Edxdxdxdxdxd "
		"(mach0_load_command_type)cmd cmdsize rebase_off rebase_size bind_off bind_size weak_bind_off weak_bind_size lazy_bind_off lazy_bind_size export_off export_size");
	sdb_set(bin->kv, "mach0_load_dylinker_command.format",
		"[4]Edxz "
		"(mach0_load_command_type)cmd cmdsize name_offset name");
	sdb_set(bin->kv, "mach0_id_dylinker_command.format",
		"[4]Edxzi "
		"(mach0_load_command_type)cmd cmdsize name_offset name");
	sdb_set(bin->kv, "mach0_build_version_command.format",
		"[4]Ed[4]Exxd "
		"(mach0_load_command_type)cmd cmdsize (mach0_build_platform)platform minos sdk ntools");
	sdb_set(bin->kv, "mach0_build_version_tool.format",
		"[4]Ex "
		"(mach0_build_tool)tool version");
	sdb_set(bin->kv, "mach0_source_version_command.format",
		"[4]Edq "
		"(mach0_load_command_type)cmd cmdsize version");
	sdb_set(bin->kv, "mach0_function_starts_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size");
	sdb_set(bin->kv, "mach0_data_in_code_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size");
	sdb_set(bin->kv, "mach0_version_min_command.format",
		"[4]Edxx "
		"(mach0_load_command_type)cmd cmdsize version reserved");
	sdb_set(bin->kv, "mach0_segment_split_info_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size");
	sdb_set(bin->kv, "mach0_unixthread_command.format",
		"[4]Eddd "
		"(mach0_load_command_type)cmd cmdsize flavor count");
}

static bool init_hdr(struct MACH0_(obj_t) * bin) {
	ut8 magicbytes[4] = { 0 };
	ut8 machohdrbytes[sizeof(struct MACH0_(mach_header))] = { 0 };
	int len;

	if (rz_buf_read_at(bin->b, 0 + bin->options.header_at, magicbytes, 4) < 1) {
		return false;
	}
	if (rz_read_le32(magicbytes) == 0xfeedface) {
		bin->big_endian = false;
	} else if (rz_read_be32(magicbytes) == 0xfeedface) {
		bin->big_endian = true;
	} else if (rz_read_le32(magicbytes) == FAT_MAGIC) {
		bin->big_endian = false;
	} else if (rz_read_be32(magicbytes) == FAT_MAGIC) {
		bin->big_endian = true;
	} else if (rz_read_le32(magicbytes) == 0xfeedfacf) {
		bin->big_endian = false;
	} else if (rz_read_be32(magicbytes) == 0xfeedfacf) {
		bin->big_endian = true;
	} else {
		return false; // object files are magic == 0, but body is different :?
	}
	len = rz_buf_read_at(bin->b, 0 + bin->options.header_at, machohdrbytes, sizeof(machohdrbytes));
	if (len != sizeof(machohdrbytes)) {
		bprintf("Error: read (hdr)\n");
		return false;
	}
	bin->hdr.magic = rz_read_ble(&machohdrbytes[0], bin->big_endian, 32);
	bin->hdr.cputype = rz_read_ble(&machohdrbytes[4], bin->big_endian, 32);
	bin->hdr.cpusubtype = rz_read_ble(&machohdrbytes[8], bin->big_endian, 32);
	bin->hdr.filetype = rz_read_ble(&machohdrbytes[12], bin->big_endian, 32);
	bin->hdr.ncmds = rz_read_ble(&machohdrbytes[16], bin->big_endian, 32);
	bin->hdr.sizeofcmds = rz_read_ble(&machohdrbytes[20], bin->big_endian, 32);
	bin->hdr.flags = rz_read_ble(&machohdrbytes[24], bin->big_endian, 32);
#if RZ_BIN_MACH064
	bin->hdr.reserved = rz_read_ble(&machohdrbytes[28], bin->big_endian, 32);
#endif
	init_sdb_formats(bin);
	sdb_num_set(bin->kv, "mach0_header.offset", 0); // wat about fatmach0?
	return true;
}

static bool parse_segments(struct MACH0_(obj_t) * bin, ut64 off) {
	size_t i, j, k, sect, len;
	ut32 size_sects;
	ut8 segcom[sizeof(struct MACH0_(segment_command))] = { 0 };
	ut8 sec[sizeof(struct MACH0_(section))] = { 0 };
	char tmpbuf[128];

	if (!UT32_MUL(&size_sects, bin->nsegs, sizeof(struct MACH0_(segment_command)))) {
		return false;
	}
	if (!size_sects || size_sects > bin->size) {
		return false;
	}
	if (off > bin->size || off + sizeof(struct MACH0_(segment_command)) > bin->size) {
		return false;
	}
	if (!(bin->segs = realloc(bin->segs, bin->nsegs * sizeof(struct MACH0_(segment_command))))) {
		perror("realloc (seg)");
		return false;
	}
	j = bin->nsegs - 1;
	len = rz_buf_read_at(bin->b, off, segcom, sizeof(struct MACH0_(segment_command)));
	if (len != sizeof(struct MACH0_(segment_command))) {
		bprintf("Error: read (seg)\n");
		return false;
	}
	i = 0;
	bin->segs[j].cmd = rz_read_ble32(&segcom[i], bin->big_endian);
	i += sizeof(ut32);
	bin->segs[j].cmdsize = rz_read_ble32(&segcom[i], bin->big_endian);
	i += sizeof(ut32);
	memcpy(&bin->segs[j].segname, &segcom[i], 16);
	i += 16;
#if RZ_BIN_MACH064
	bin->segs[j].vmaddr = rz_read_ble64(&segcom[i], bin->big_endian);
	i += sizeof(ut64);
	bin->segs[j].vmsize = rz_read_ble64(&segcom[i], bin->big_endian);
	i += sizeof(ut64);
	bin->segs[j].fileoff = rz_read_ble64(&segcom[i], bin->big_endian);
	i += sizeof(ut64);
	bin->segs[j].filesize = rz_read_ble64(&segcom[i], bin->big_endian);
	i += sizeof(ut64);
#else
	bin->segs[j].vmaddr = rz_read_ble32(&segcom[i], bin->big_endian);
	i += sizeof(ut32);
	bin->segs[j].vmsize = rz_read_ble32(&segcom[i], bin->big_endian);
	i += sizeof(ut32);
	bin->segs[j].fileoff = rz_read_ble32(&segcom[i], bin->big_endian);
	i += sizeof(ut32);
	bin->segs[j].filesize = rz_read_ble32(&segcom[i], bin->big_endian);
	i += sizeof(ut32);
#endif
	bin->segs[j].maxprot = rz_read_ble32(&segcom[i], bin->big_endian);
	i += sizeof(ut32);
	bin->segs[j].initprot = rz_read_ble32(&segcom[i], bin->big_endian);
	i += sizeof(ut32);
	bin->segs[j].nsects = rz_read_ble32(&segcom[i], bin->big_endian);
	i += sizeof(ut32);
	bin->segs[j].flags = rz_read_ble32(&segcom[i], bin->big_endian);

#if RZ_BIN_MACH064
	sdb_num_set(bin->kv, rz_strf(tmpbuf, "mach0_segment64_%zu.offset", j), off);
#else
	sdb_num_set(bin->kv, rz_strf(tmpbuf, "mach0_segment_%zu.offset", j), off);
#endif

	sdb_num_set(bin->kv, "mach0_segments.count", 0);

	if (bin->segs[j].nsects > 0) {
		sect = bin->nsects;
		bin->nsects += bin->segs[j].nsects;
		if (bin->nsects > 128) {
			int new_nsects = bin->nsects & 0xf;
			bprintf("WARNING: mach0 header contains too many sections (%d). Wrapping to %d\n",
				bin->nsects, new_nsects);
			bin->nsects = new_nsects;
		}
		if ((int)bin->nsects < 1) {
			bprintf("Warning: Invalid number of sections\n");
			bin->nsects = sect;
			return false;
		}
		if (!UT32_MUL(&size_sects, bin->nsects - sect, sizeof(struct MACH0_(section)))) {
			bin->nsects = sect;
			return false;
		}
		if (!size_sects || size_sects > bin->size) {
			bin->nsects = sect;
			return false;
		}

		if (bin->segs[j].cmdsize != sizeof(struct MACH0_(segment_command)) + (sizeof(struct MACH0_(section)) * bin->segs[j].nsects)) {
			bin->nsects = sect;
			return false;
		}

		if (off + sizeof(struct MACH0_(segment_command)) > bin->size ||
			off + sizeof(struct MACH0_(segment_command)) + size_sects > bin->size) {
			bin->nsects = sect;
			return false;
		}

		if (!(bin->sects = realloc(bin->sects, bin->nsects * sizeof(struct MACH0_(section))))) {
			perror("realloc (sects)");
			bin->nsects = sect;
			return false;
		}

		for (k = sect, j = 0; k < bin->nsects; k++, j++) {
			ut64 offset = off + sizeof(struct MACH0_(segment_command)) + j * sizeof(struct MACH0_(section));
			len = rz_buf_read_at(bin->b, offset, sec, sizeof(struct MACH0_(section)));
			if (len != sizeof(struct MACH0_(section))) {
				bprintf("Error: read (sects)\n");
				bin->nsects = sect;
				return false;
			}

			i = 0;
			memcpy(&bin->sects[k].sectname, &sec[i], 16);
			i += 16;
			memcpy(&bin->sects[k].segname, &sec[i], 16);
			i += 16;

			sdb_num_set(bin->kv, rz_strf(tmpbuf, "mach0_section_%.16s_%.16s.offset", bin->sects[k].segname, bin->sects[k].sectname), offset);
#if RZ_BIN_MACH064
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_section_%.16s_%.16s.format", bin->sects[k].segname, bin->sects[k].sectname), "mach0_section64");
#else
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_section_%.16s_%.16s.format", bin->sects[k].segname, bin->sects[k].sectname), "mach0_section");
#endif

#if RZ_BIN_MACH064
			bin->sects[k].addr = rz_read_ble64(&sec[i], bin->big_endian);
			i += sizeof(ut64);
			bin->sects[k].size = rz_read_ble64(&sec[i], bin->big_endian);
			i += sizeof(ut64);
#else
			bin->sects[k].addr = rz_read_ble32(&sec[i], bin->big_endian);
			i += sizeof(ut32);
			bin->sects[k].size = rz_read_ble32(&sec[i], bin->big_endian);
			i += sizeof(ut32);
#endif
			bin->sects[k].offset = rz_read_ble32(&sec[i], bin->big_endian);
			i += sizeof(ut32);
			bin->sects[k].align = rz_read_ble32(&sec[i], bin->big_endian);
			i += sizeof(ut32);
			bin->sects[k].reloff = rz_read_ble32(&sec[i], bin->big_endian);
			i += sizeof(ut32);
			bin->sects[k].nreloc = rz_read_ble32(&sec[i], bin->big_endian);
			i += sizeof(ut32);
			bin->sects[k].flags = rz_read_ble32(&sec[i], bin->big_endian);
			i += sizeof(ut32);
			bin->sects[k].reserved1 = rz_read_ble32(&sec[i], bin->big_endian);
			i += sizeof(ut32);
			bin->sects[k].reserved2 = rz_read_ble32(&sec[i], bin->big_endian);
#if RZ_BIN_MACH064
			i += sizeof(ut32);
			bin->sects[k].reserved3 = rz_read_ble32(&sec[i], bin->big_endian);
#endif
		}
	}
	return true;
}

#define Error(x) \
	error_message = x; \
	goto error;
static bool parse_symtab(struct MACH0_(obj_t) * mo, ut64 off) {
	struct symtab_command st;
	ut32 size_sym;
	size_t i;
	const char *error_message = "";
	ut8 symt[sizeof(struct symtab_command)] = { 0 };
	ut8 nlst[sizeof(struct MACH0_(nlist))] = { 0 };
	const bool be = mo->big_endian;

	if (off > (ut64)mo->size || off + sizeof(struct symtab_command) > (ut64)mo->size) {
		return false;
	}
	int len = rz_buf_read_at(mo->b, off, symt, sizeof(struct symtab_command));
	if (len != sizeof(struct symtab_command)) {
		Eprintf("Error: read (symtab)\n");
		return false;
	}
	st.cmd = rz_read_ble32(symt, be);
	st.cmdsize = rz_read_ble32(symt + 4, be);
	st.symoff = rz_read_ble32(symt + 8, be) + mo->options.symbols_off;
	st.nsyms = rz_read_ble32(symt + 12, be);
	st.stroff = rz_read_ble32(symt + 16, be) + mo->options.symbols_off;
	st.strsize = rz_read_ble32(symt + 20, be);

	mo->symtab = NULL;
	mo->nsymtab = 0;
	if (st.strsize > 0 && st.strsize < mo->size && st.nsyms > 0) {
		mo->nsymtab = st.nsyms;
		if (st.stroff > mo->size || st.stroff + st.strsize > mo->size) {
			Error("fail");
		}
		if (!UT32_MUL(&size_sym, mo->nsymtab, sizeof(struct MACH0_(nlist)))) {
			Error("fail2");
		}
		if (!size_sym) {
			Error("symbol size is zero");
		}
		if (st.symoff > mo->size || st.symoff + size_sym > mo->size) {
			Error("symoff is out of bounds");
		}
		if (!(mo->symstr = calloc(1, st.strsize + 2))) {
			Error("symoff is out of bounds");
		}
		mo->symstrlen = st.strsize;
		len = rz_buf_read_at(mo->b, st.stroff, (ut8 *)mo->symstr, st.strsize);
		if (len != st.strsize) {
			Error("Error: read (symstr)");
		}
		if (!(mo->symtab = calloc(mo->nsymtab, sizeof(struct MACH0_(nlist))))) {
			goto error;
		}
		for (i = 0; i < mo->nsymtab; i++) {
			ut64 at = st.symoff + (i * sizeof(struct MACH0_(nlist)));
			len = rz_buf_read_at(mo->b, at, nlst, sizeof(struct MACH0_(nlist)));
			if (len != sizeof(struct MACH0_(nlist))) {
				Error("read (nlist)");
			}
			// XXX not very safe what if is n_un.n_name instead?
			mo->symtab[i].n_strx = rz_read_ble32(nlst, be);
			mo->symtab[i].n_type = rz_read_ble8(nlst + 4);
			mo->symtab[i].n_sect = rz_read_ble8(nlst + 5);
			mo->symtab[i].n_desc = rz_read_ble16(nlst + 6, be);
#if RZ_BIN_MACH064
			mo->symtab[i].n_value = rz_read_ble64(&nlst[8], be);
#else
			mo->symtab[i].n_value = rz_read_ble32(&nlst[8], be);
#endif
		}
	}
	return true;
error:
	RZ_FREE(mo->symstr);
	RZ_FREE(mo->symtab);
	Eprintf("%s\n", error_message);
	return false;
}

static bool parse_dysymtab(struct MACH0_(obj_t) * bin, ut64 off) {
	size_t len, i;
	ut32 size_tab;
	ut8 dysym[sizeof(struct dysymtab_command)] = { 0 };
	ut8 dytoc[sizeof(struct dylib_table_of_contents)] = { 0 };
	ut8 dymod[sizeof(struct MACH0_(dylib_module))] = { 0 };
	ut8 idsyms[sizeof(ut32)] = { 0 };

	if (off > bin->size || off + sizeof(struct dysymtab_command) > bin->size) {
		return false;
	}

	len = rz_buf_read_at(bin->b, off, dysym, sizeof(struct dysymtab_command));
	if (len != sizeof(struct dysymtab_command)) {
		bprintf("Error: read (dysymtab)\n");
		return false;
	}

	bin->dysymtab.cmd = rz_read_ble32(&dysym[0], bin->big_endian);
	bin->dysymtab.cmdsize = rz_read_ble32(&dysym[4], bin->big_endian);
	bin->dysymtab.ilocalsym = rz_read_ble32(&dysym[8], bin->big_endian);
	bin->dysymtab.nlocalsym = rz_read_ble32(&dysym[12], bin->big_endian);
	bin->dysymtab.iextdefsym = rz_read_ble32(&dysym[16], bin->big_endian);
	bin->dysymtab.nextdefsym = rz_read_ble32(&dysym[20], bin->big_endian);
	bin->dysymtab.iundefsym = rz_read_ble32(&dysym[24], bin->big_endian);
	bin->dysymtab.nundefsym = rz_read_ble32(&dysym[28], bin->big_endian);
	bin->dysymtab.tocoff = rz_read_ble32(&dysym[32], bin->big_endian);
	bin->dysymtab.ntoc = rz_read_ble32(&dysym[36], bin->big_endian);
	bin->dysymtab.modtaboff = rz_read_ble32(&dysym[40], bin->big_endian);
	bin->dysymtab.nmodtab = rz_read_ble32(&dysym[44], bin->big_endian);
	bin->dysymtab.extrefsymoff = rz_read_ble32(&dysym[48], bin->big_endian);
	bin->dysymtab.nextrefsyms = rz_read_ble32(&dysym[52], bin->big_endian);
	bin->dysymtab.indirectsymoff = rz_read_ble32(&dysym[56], bin->big_endian);
	bin->dysymtab.nindirectsyms = rz_read_ble32(&dysym[60], bin->big_endian);
	bin->dysymtab.extreloff = rz_read_ble32(&dysym[64], bin->big_endian);
	bin->dysymtab.nextrel = rz_read_ble32(&dysym[68], bin->big_endian);
	bin->dysymtab.locreloff = rz_read_ble32(&dysym[72], bin->big_endian);
	bin->dysymtab.nlocrel = rz_read_ble32(&dysym[76], bin->big_endian);

	bin->ntoc = bin->dysymtab.ntoc;
	if (bin->ntoc > 0) {
		if (!(bin->toc = calloc(bin->ntoc, sizeof(struct dylib_table_of_contents)))) {
			perror("calloc (toc)");
			return false;
		}
		if (!UT32_MUL(&size_tab, bin->ntoc, sizeof(struct dylib_table_of_contents))) {
			RZ_FREE(bin->toc);
			return false;
		}
		if (!size_tab) {
			RZ_FREE(bin->toc);
			return false;
		}
		if (bin->dysymtab.tocoff > bin->size || bin->dysymtab.tocoff + size_tab > bin->size) {
			RZ_FREE(bin->toc);
			return false;
		}
		for (i = 0; i < bin->ntoc; i++) {
			len = rz_buf_read_at(bin->b, bin->dysymtab.tocoff + i * sizeof(struct dylib_table_of_contents),
				dytoc, sizeof(struct dylib_table_of_contents));
			if (len != sizeof(struct dylib_table_of_contents)) {
				bprintf("Error: read (toc)\n");
				RZ_FREE(bin->toc);
				return false;
			}
			bin->toc[i].symbol_index = rz_read_ble32(&dytoc[0], bin->big_endian);
			bin->toc[i].module_index = rz_read_ble32(&dytoc[4], bin->big_endian);
		}
	}
	bin->nmodtab = bin->dysymtab.nmodtab;
	if (bin->nmodtab > 0) {
		if (!(bin->modtab = calloc(bin->nmodtab, sizeof(struct MACH0_(dylib_module))))) {
			perror("calloc (modtab)");
			return false;
		}
		if (!UT32_MUL(&size_tab, bin->nmodtab, sizeof(struct MACH0_(dylib_module)))) {
			RZ_FREE(bin->modtab);
			return false;
		}
		if (!size_tab) {
			RZ_FREE(bin->modtab);
			return false;
		}
		if (bin->dysymtab.modtaboff > bin->size ||
			bin->dysymtab.modtaboff + size_tab > bin->size) {
			RZ_FREE(bin->modtab);
			return false;
		}
		for (i = 0; i < bin->nmodtab; i++) {
			len = rz_buf_read_at(bin->b, bin->dysymtab.modtaboff + i * sizeof(struct MACH0_(dylib_module)),
				dymod, sizeof(struct MACH0_(dylib_module)));
			if (len == -1) {
				bprintf("Error: read (modtab)\n");
				RZ_FREE(bin->modtab);
				return false;
			}

			bin->modtab[i].module_name = rz_read_ble32(&dymod[0], bin->big_endian);
			bin->modtab[i].iextdefsym = rz_read_ble32(&dymod[4], bin->big_endian);
			bin->modtab[i].nextdefsym = rz_read_ble32(&dymod[8], bin->big_endian);
			bin->modtab[i].irefsym = rz_read_ble32(&dymod[12], bin->big_endian);
			bin->modtab[i].nrefsym = rz_read_ble32(&dymod[16], bin->big_endian);
			bin->modtab[i].ilocalsym = rz_read_ble32(&dymod[20], bin->big_endian);
			bin->modtab[i].nlocalsym = rz_read_ble32(&dymod[24], bin->big_endian);
			bin->modtab[i].iextrel = rz_read_ble32(&dymod[28], bin->big_endian);
			bin->modtab[i].nextrel = rz_read_ble32(&dymod[32], bin->big_endian);
			bin->modtab[i].iinit_iterm = rz_read_ble32(&dymod[36], bin->big_endian);
			bin->modtab[i].ninit_nterm = rz_read_ble32(&dymod[40], bin->big_endian);
#if RZ_BIN_MACH064
			bin->modtab[i].objc_module_info_size = rz_read_ble32(&dymod[44], bin->big_endian);
			bin->modtab[i].objc_module_info_addr = rz_read_ble64(&dymod[48], bin->big_endian);
#else
			bin->modtab[i].objc_module_info_addr = rz_read_ble32(&dymod[44], bin->big_endian);
			bin->modtab[i].objc_module_info_size = rz_read_ble32(&dymod[48], bin->big_endian);
#endif
		}
	}
	bin->nindirectsyms = bin->dysymtab.nindirectsyms;
	if (bin->nindirectsyms > 0) {
		if (!(bin->indirectsyms = calloc(bin->nindirectsyms, sizeof(ut32)))) {
			perror("calloc (indirectsyms)");
			return false;
		}
		if (!UT32_MUL(&size_tab, bin->nindirectsyms, sizeof(ut32))) {
			RZ_FREE(bin->indirectsyms);
			return false;
		}
		if (!size_tab) {
			RZ_FREE(bin->indirectsyms);
			return false;
		}
		if (bin->dysymtab.indirectsymoff > bin->size ||
			bin->dysymtab.indirectsymoff + size_tab > bin->size) {
			RZ_FREE(bin->indirectsyms);
			return false;
		}
		for (i = 0; i < bin->nindirectsyms; i++) {
			len = rz_buf_read_at(bin->b, bin->dysymtab.indirectsymoff + i * sizeof(ut32), idsyms, 4);
			if (len == -1) {
				bprintf("Error: read (indirect syms)\n");
				RZ_FREE(bin->indirectsyms);
				return false;
			}
			bin->indirectsyms[i] = rz_read_ble32(&idsyms[0], bin->big_endian);
		}
	}
	/* TODO extrefsyms, extrel, locrel */
	return true;
}

static char *readString(ut8 *p, int off, int len) {
	if (off < 0 || off >= len) {
		return NULL;
	}
	return rz_str_ndup((const char *)p + off, len - off);
}

static void parseCodeDirectory(struct MACH0_(obj_t) * mo, RzBuffer *b, int offset, int datasize) {
	typedef struct __CodeDirectory {
		uint32_t magic; /* magic number (CSMAGIC_CODEDIRECTORY) */
		uint32_t length; /* total length of CodeDirectory blob */
		uint32_t version; /* compatibility version */
		uint32_t flags; /* setup and mode flags */
		uint32_t hashOffset; /* offset of hash slot element at index zero */
		uint32_t identOffset; /* offset of identifier string */
		uint32_t nSpecialSlots; /* number of special hash slots */
		uint32_t nCodeSlots; /* number of ordinary (code) hash slots */
		uint32_t codeLimit; /* limit to main image signature range */
		uint8_t hashSize; /* size of each hash in bytes */
		uint8_t hashType; /* type of hash (cdHashType* constants) */
		uint8_t platform; /* unused (must be zero) */
		uint8_t pageSize; /* log2(page size in bytes); 0 => infinite */
		uint32_t spare2; /* unused (must be zero) */
		/* followed by dynamic content as located by offset fields above */
		uint32_t scatterOffset;
		uint32_t teamIDOffset;
		uint32_t spare3;
		ut64 codeLimit64;
		ut64 execSegBase;
		ut64 execSegLimit;
		ut64 execSegFlags;
	} CS_CodeDirectory;
	ut64 off = offset;
	int psize = datasize;
	ut8 *p = calloc(1, psize);
	if (!p) {
		return;
	}
	eprintf("Offset: 0x%08" PFMT64x "\n", off);
	rz_buf_read_at(b, off, p, datasize);
	CS_CodeDirectory cscd = { 0 };
#define READFIELD(x)  cscd.x = rz_read_ble32(p + rz_offsetof(CS_CodeDirectory, x), 1)
#define READFIELD8(x) cscd.x = p[rz_offsetof(CS_CodeDirectory, x)]
	READFIELD(length);
	READFIELD(version);
	READFIELD(flags);
	READFIELD(hashOffset);
	READFIELD(identOffset);
	READFIELD(nSpecialSlots);
	READFIELD(nCodeSlots);
	READFIELD(hashSize);
	READFIELD(teamIDOffset);
	READFIELD8(hashType);
	READFIELD(pageSize);
	READFIELD(codeLimit);
	eprintf("Version: %x\n", cscd.version);
	eprintf("Flags: %x\n", cscd.flags);
	eprintf("Length: %d\n", cscd.length);
	eprintf("PageSize: %d\n", cscd.pageSize);
	eprintf("hashOffset: %d\n", cscd.hashOffset);
	eprintf("codeLimit: %d\n", cscd.codeLimit);
	eprintf("hashSize: %d\n", cscd.hashSize);
	eprintf("hashType: %d\n", cscd.hashType);
	char *identity = readString(p, cscd.identOffset, psize);
	eprintf("Identity: %s\n", identity);
	char *teamId = readString(p, cscd.teamIDOffset, psize);
	eprintf("TeamID: %s\n", teamId);
	eprintf("CodeSlots: %d\n", cscd.nCodeSlots);
	free(identity);
	free(teamId);

	const char *digest_algo = "sha1";
	switch (cscd.hashType) {
	case 0: // SHA1 == 20 bytes
	case 1: // SHA1 == 20 bytes
		digest_algo = "sha1";
		break;
	case 2: // SHA256 == 32 bytes
		digest_algo = "sha256";
		break;
	}

	// computed cdhash
	RzHashSize digest_size = 0;
	ut8 *digest = NULL;

	int fofsz = cscd.length;
	ut8 *fofbuf = calloc(fofsz, 1);
	if (fofbuf) {
		int i;
		if (rz_buf_read_at(b, off, fofbuf, fofsz) != fofsz) {
			eprintf("Invalid cdhash offset/length values\n");
			goto parseCodeDirectory_end;
		}

		digest = rz_hash_cfg_calculate_small_block(mo->hash, digest_algo, fofbuf, fofsz, &digest_size);
		if (!digest) {
			goto parseCodeDirectory_end;
		}

		eprintf("ph %s @ 0x%" PFMT64x "!%d\n", digest_algo, off, fofsz);
		eprintf("ComputedCDHash: ");
		for (i = 0; i < digest_size; i++) {
			eprintf("%02x", digest[i]);
		}
		eprintf("\n");
		RZ_FREE(digest);
		free(fofbuf);
	}
	// show and check the rest of hashes
	ut8 *hash = p + cscd.hashOffset;
	int j = 0;
	int k = 0;
	eprintf("Hashed region: 0x%08" PFMT64x " - 0x%08" PFMT64x "\n", (ut64)0, (ut64)cscd.codeLimit);
	for (j = 0; j < cscd.nCodeSlots; j++) {
		int fof = 4096 * j;
		int idx = j * digest_size;
		eprintf("0x%08" PFMT64x "  ", off + cscd.hashOffset + idx);
		for (k = 0; k < digest_size; k++) {
			eprintf("%02x", hash[idx + k]);
		}
		ut8 fofbuf[4096];
		int fofsz = RZ_MIN(sizeof(fofbuf), cscd.codeLimit - fof);
		rz_buf_read_at(b, fof, fofbuf, sizeof(fofbuf));

		digest = rz_hash_cfg_calculate_small_block(mo->hash, digest_algo, fofbuf, fofsz, &digest_size);
		if (!digest) {
			goto parseCodeDirectory_end;
		}

		if (memcmp(hash + idx, digest, digest_size)) {
			eprintf("  wx ");
			int i;
			for (i = 0; i < digest_size; i++) {
				eprintf("%02x", digest[i]);
			}
		} else {
			eprintf("  OK");
		}
		eprintf("\n");
		free(digest);
	}

parseCodeDirectory_end:
	free(p);
}

// parse the Load Command
static bool parse_signature(struct MACH0_(obj_t) * bin, ut64 off) {
	int i, len;
	ut32 data;
	bin->signature = NULL;
	struct linkedit_data_command link = { 0 };
	ut8 lit[sizeof(struct linkedit_data_command)] = { 0 };
	struct blob_index_t idx = { 0 };
	struct super_blob_t super = { { 0 } };

	if (off > bin->size || off + sizeof(struct linkedit_data_command) > bin->size) {
		return false;
	}
	len = rz_buf_read_at(bin->b, off, lit, sizeof(struct linkedit_data_command));
	if (len != sizeof(struct linkedit_data_command)) {
		bprintf("Failed to get data while parsing LC_CODE_SIGNATURE command\n");
		return false;
	}
	link.cmd = rz_read_ble32(&lit[0], bin->big_endian);
	link.cmdsize = rz_read_ble32(&lit[4], bin->big_endian);
	link.dataoff = rz_read_ble32(&lit[8], bin->big_endian);
	link.datasize = rz_read_ble32(&lit[12], bin->big_endian);

	data = link.dataoff;
	if (data > bin->size || data + sizeof(struct super_blob_t) > bin->size) {
		bin->signature = (ut8 *)strdup("Malformed entitlement");
		return true;
	}

	if (!rz_buf_read_ble32_at(bin->b, data, &super.blob.magic, mach0_endian) ||
		!rz_buf_read_ble32_at(bin->b, data + 4, &super.blob.length, mach0_endian) ||
		!rz_buf_read_ble32_at(bin->b, data + 8, &super.count, mach0_endian)) {
		return false;
	}

	char *verbose = rz_sys_getenv("RZ_BIN_CODESIGN_VERBOSE");
	bool isVerbose = false;
	if (verbose) {
		isVerbose = *verbose;
		free(verbose);
	}
	// to dump all certificates
	// [0x00053f75]> b 5K;/x 30800609;wtf @@ hit*
	// then do this:
	// $ openssl asn1parse -inform der -in a|less
	// $ openssl pkcs7 -inform DER -print_certs -text -in a
	for (i = 0; i < super.count; i++) {
		if (data + i > bin->size) {
			bin->signature = (ut8 *)strdup("Malformed entitlement");
			break;
		}
		struct blob_index_t bi;
		if (rz_buf_read_at(bin->b, data + 12 + (i * sizeof(struct blob_index_t)),
			    (ut8 *)&bi, sizeof(struct blob_index_t)) < sizeof(struct blob_index_t)) {
			break;
		}
		idx.type = rz_read_ble32(&bi.type, mach0_endian);
		idx.offset = rz_read_ble32(&bi.offset, mach0_endian);
		switch (idx.type) {
		case CSSLOT_ENTITLEMENTS:
			if (true || isVerbose) {
				ut64 off = data + idx.offset;
				if (off > bin->size || off + sizeof(struct blob_t) > bin->size) {
					bin->signature = (ut8 *)strdup("Malformed entitlement");
					break;
				}
				struct blob_t entitlements = { 0 };
				if (!rz_buf_read_ble32_at(bin->b, off, &entitlements.magic, mach0_endian) ||
					!rz_buf_read_ble32_at(bin->b, off + 4, &entitlements.length, mach0_endian)) {
					break;
				}
				len = entitlements.length - sizeof(struct blob_t);
				if (len <= bin->size && len > 1) {
					bin->signature = calloc(1, len + 1);
					if (!bin->signature) {
						break;
					}
					if (off + sizeof(struct blob_t) + len < rz_buf_size(bin->b)) {
						rz_buf_read_at(bin->b, off + sizeof(struct blob_t), (ut8 *)bin->signature, len);
						if (len >= 0) {
							bin->signature[len] = '\0';
						}
					} else {
						bin->signature = (ut8 *)strdup("Malformed entitlement");
					}
				} else {
					bin->signature = (ut8 *)strdup("Malformed entitlement");
				}
			}
			break;
		case CSSLOT_CODEDIRECTORY:
			if (isVerbose) {
				parseCodeDirectory(bin, bin->b, data + idx.offset, link.datasize);
			}
			break;
		case 0x1000:
			// unknown
			break;
		case CSSLOT_CMS_SIGNATURE: // ASN1/DER certificate
			if (isVerbose) {
				ut8 header[8] = { 0 };
				rz_buf_read_at(bin->b, data + idx.offset, header, sizeof(header));
				ut32 length = RZ_MIN(UT16_MAX, rz_read_ble32(header + 4, 1));
				ut8 *p = calloc(length, 1);
				if (p) {
					rz_buf_read_at(bin->b, data + idx.offset + 0, p, length);
					ut32 *words = (ut32 *)p;
					eprintf("Magic: %x\n", words[0]);
					eprintf("wtf DUMP @%d!%d\n",
						(int)data + idx.offset + 8, (int)length);
					eprintf("openssl pkcs7 -print_certs -text -inform der -in DUMP\n");
					eprintf("openssl asn1parse -offset %d -length %d -inform der -in /bin/ls\n",
						(int)data + idx.offset + 8, (int)length);
					eprintf("pFp@%d!%d\n",
						(int)data + idx.offset + 8, (int)length);
					free(p);
				}
			}
			break;
		case CSSLOT_REQUIREMENTS: // 2
		{
			ut8 p[256];
			rz_buf_read_at(bin->b, data + idx.offset + 16, p, sizeof(p));
			p[sizeof(p) - 1] = 0;
			ut32 slot_size = rz_read_ble32(p + 8, 1);
			if (slot_size < sizeof(p)) {
				ut32 ident_size = rz_read_ble32(p + 8, 1);
				char *ident = rz_str_ndup((const char *)p + 28, ident_size);
				if (ident) {
					sdb_set(bin->kv, "mach0.ident", ident);
					free(ident);
				}
			} else {
				if (bin->options.verbose) {
					eprintf("Invalid code slot size\n");
				}
			}
		} break;
		case CSSLOT_INFOSLOT: // 1;
		case CSSLOT_RESOURCEDIR: // 3;
		case CSSLOT_APPLICATION: // 4;
			// TODO: parse those codesign slots
			if (bin->options.verbose) {
				eprintf("TODO: Some codesign slots are not yet supported\n");
			}
			break;
		default:
			if (bin->options.verbose) {
				eprintf("Unknown Code signature slot %d\n", idx.type);
			}
			break;
		}
	}
	if (!bin->signature) {
		bin->signature = (ut8 *)strdup("No entitlement found");
	}
	return true;
}

static int parse_thread(struct MACH0_(obj_t) * bin, struct load_command *lc, ut64 off, bool is_first_thread) {
	ut64 ptr_thread, pc = UT64_MAX, pc_offset = UT64_MAX;
	ut32 flavor, count;
	ut8 *arw_ptr = NULL;
	int arw_sz, len = 0;
	ut8 thc[sizeof(struct thread_command)] = { 0 };
	ut8 tmp[4];

	if (off > bin->size || off + sizeof(struct thread_command) > bin->size) {
		return false;
	}

	len = rz_buf_read_at(bin->b, off, thc, 8);
	if (len < 1) {
		goto wrong_read;
	}
	bin->thread.cmd = rz_read_ble32(&thc[0], bin->big_endian);
	bin->thread.cmdsize = rz_read_ble32(&thc[4], bin->big_endian);
	if (!rz_buf_read_ble32_at(bin->b, off + sizeof(struct thread_command), &flavor, bin->big_endian)) {
		goto wrong_read;
	}

	if (off + sizeof(struct thread_command) + sizeof(flavor) > bin->size ||
		off + sizeof(struct thread_command) + sizeof(flavor) + sizeof(ut32) > bin->size) {
		return false;
	}

	// TODO: use count for checks
	if (rz_buf_read_at(bin->b, off + sizeof(struct thread_command) + sizeof(flavor), tmp, 4) < 4) {
		goto wrong_read;
	}
	ptr_thread = off + sizeof(struct thread_command) + sizeof(flavor) + sizeof(count);

	if (ptr_thread > bin->size) {
		return false;
	}

	switch (bin->hdr.cputype) {
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:
		switch (flavor) {
		case X86_THREAD_STATE32:
			if (ptr_thread + sizeof(struct x86_thread_state32) > bin->size) {
				return false;
			}
			if (rz_buf_fread_at(bin->b, ptr_thread,
				    (ut8 *)&bin->thread_state.x86_32, "16i", 1) == -1) {
				RZ_LOG_ERROR("read thread state x86_32\n");
				return false;
			}
			pc = bin->thread_state.x86_32.eip;
			pc_offset = ptr_thread + rz_offsetof(struct x86_thread_state32, eip);
			arw_ptr = (ut8 *)&bin->thread_state.x86_32;
			arw_sz = sizeof(struct x86_thread_state32);
			break;
		case X86_THREAD_STATE64:
			if (ptr_thread + sizeof(struct x86_thread_state64) > bin->size) {
				return false;
			}
			if (rz_buf_fread_at(bin->b, ptr_thread,
				    (ut8 *)&bin->thread_state.x86_64, "32l", 1) == -1) {
				RZ_LOG_ERROR("read thread state x86_64\n");
				return false;
			}
			pc = bin->thread_state.x86_64.rip;
			pc_offset = ptr_thread + rz_offsetof(struct x86_thread_state64, rip);
			arw_ptr = (ut8 *)&bin->thread_state.x86_64;
			arw_sz = sizeof(struct x86_thread_state64);
			break;
		}
		break;
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		if (flavor == X86_THREAD_STATE32) {
			if (ptr_thread + sizeof(struct ppc_thread_state32) > bin->size) {
				return false;
			}
			if (rz_buf_fread_at(bin->b, ptr_thread,
				    (ut8 *)&bin->thread_state.ppc_32, bin->big_endian ? "40I" : "40i", 1) == -1) {
				RZ_LOG_ERROR("read thread state ppc_32\n");
				return false;
			}
			pc = bin->thread_state.ppc_32.srr0;
			pc_offset = ptr_thread + rz_offsetof(struct ppc_thread_state32, srr0);
			arw_ptr = (ut8 *)&bin->thread_state.ppc_32;
			arw_sz = sizeof(struct ppc_thread_state32);
		} else if (flavor == X86_THREAD_STATE64) {
			if (ptr_thread + sizeof(struct ppc_thread_state64) > bin->size) {
				return false;
			}
			if (rz_buf_fread_at(bin->b, ptr_thread,
				    (ut8 *)&bin->thread_state.ppc_64, bin->big_endian ? "34LI3LI" : "34li3li", 1) == -1) {
				RZ_LOG_ERROR("read thread state ppc_64\n");
				return false;
			}
			pc = bin->thread_state.ppc_64.srr0;
			pc_offset = ptr_thread + rz_offsetof(struct ppc_thread_state64, srr0);
			arw_ptr = (ut8 *)&bin->thread_state.ppc_64;
			arw_sz = sizeof(struct ppc_thread_state64);
		}
		break;
	case CPU_TYPE_ARM:
		if (ptr_thread + sizeof(struct arm_thread_state32) > bin->size) {
			return false;
		}
		if (rz_buf_fread_at(bin->b, ptr_thread,
			    (ut8 *)&bin->thread_state.arm_32, bin->big_endian ? "17I" : "17i", 1) == -1) {
			RZ_LOG_ERROR("read thread state arm\n");
			return false;
		}
		pc = bin->thread_state.arm_32.r15;
		pc_offset = ptr_thread + rz_offsetof(struct arm_thread_state32, r15);
		arw_ptr = (ut8 *)&bin->thread_state.arm_32;
		arw_sz = sizeof(struct arm_thread_state32);
		break;
	case CPU_TYPE_ARM64:
		if (ptr_thread + sizeof(struct arm_thread_state64) > bin->size) {
			return false;
		}
		if (rz_buf_fread_at(bin->b, ptr_thread,
			    (ut8 *)&bin->thread_state.arm_64, bin->big_endian ? "33L2I" : "33l2i", 1) == -1) {
			RZ_LOG_ERROR("read thread state arm64\n");
			return false;
		}
		pc = bin->thread_state.arm_64.pc;
		pc_offset = ptr_thread + rz_offsetof(struct arm_thread_state64, pc);
		arw_ptr = (ut8 *)&bin->thread_state.arm_64;
		arw_sz = sizeof(struct arm_thread_state64);
		break;
	default:
		RZ_LOG_ERROR("unknown thread state structure\n");
		return false;
	}

	// TODO: this shouldnt be an bprintf...
	if (arw_ptr && arw_sz > 0) {
		int i;
		ut8 *p = arw_ptr;
		bprintf("arw ");
		for (i = 0; i < arw_sz; i++) {
			bprintf("%02x", 0xff & p[i]);
		}
		bprintf("\n");
	}

	if (is_first_thread) {
		bin->main_cmd = *lc;
		if (pc != UT64_MAX) {
			bin->entry = pc;
		}
		if (pc_offset != UT64_MAX) {
			sdb_num_set(bin->kv, "mach0.entry.offset", pc_offset);
		}
	}

	return true;
wrong_read:
	bprintf("Error: read (thread)\n");
	return false;
}

static int parse_function_starts(struct MACH0_(obj_t) * bin, ut64 off) {
	struct linkedit_data_command fc;
	ut8 sfc[sizeof(struct linkedit_data_command)] = { 0 };
	int len;

	if (off > bin->size || off + sizeof(struct linkedit_data_command) > bin->size) {
		bprintf("Likely overflow while parsing"
			" LC_FUNCTION_STARTS command\n");
	}
	bin->func_start = NULL;
	len = rz_buf_read_at(bin->b, off, sfc, sizeof(struct linkedit_data_command));
	if (len < 1) {
		bprintf("Failed to get data while parsing"
			" LC_FUNCTION_STARTS command\n");
	}
	fc.cmd = rz_read_ble32(&sfc[0], bin->big_endian);
	fc.cmdsize = rz_read_ble32(&sfc[4], bin->big_endian);
	fc.dataoff = rz_read_ble32(&sfc[8], bin->big_endian);
	fc.datasize = rz_read_ble32(&sfc[12], bin->big_endian);

	if ((int)fc.datasize > 0) {
		ut8 *buf = calloc(1, fc.datasize + 1);
		if (!buf) {
			bprintf("Failed to allocate buffer\n");
			return false;
		}
		bin->func_size = fc.datasize;
		if (fc.dataoff > bin->size || fc.dataoff + fc.datasize > bin->size) {
			free(buf);
			bprintf("Likely overflow while parsing "
				"LC_FUNCTION_STARTS command\n");
			return false;
		}
		len = rz_buf_read_at(bin->b, fc.dataoff, buf, fc.datasize);
		if (len != fc.datasize) {
			free(buf);
			bprintf("Failed to get data while parsing"
				" LC_FUNCTION_STARTS\n");
			return false;
		}
		buf[fc.datasize] = 0; // null-terminated buffer
		bin->func_start = buf;
		return true;
	}
	bin->func_start = NULL;
	return false;
}

static int parse_dylib(struct MACH0_(obj_t) * bin, ut64 off) {
	struct dylib_command dl;
	int lib, len;
	ut8 sdl[sizeof(struct dylib_command)] = { 0 };

	if (off > bin->size || off + sizeof(struct dylib_command) > bin->size) {
		return false;
	}
	lib = bin->nlibs - 1;

	void *relibs = realloc(bin->libs, bin->nlibs * RZ_BIN_MACH0_STRING_LENGTH);
	if (!relibs) {
		perror("realloc (libs)");
		return false;
	}
	bin->libs = relibs;
	len = rz_buf_read_at(bin->b, off, sdl, sizeof(struct dylib_command));
	if (len < 1) {
		bprintf("Error: read (dylib)\n");
		return false;
	}
	dl.cmd = rz_read_ble32(&sdl[0], bin->big_endian);
	dl.cmdsize = rz_read_ble32(&sdl[4], bin->big_endian);
	dl.dylib.name = rz_read_ble32(&sdl[8], bin->big_endian);
	dl.dylib.timestamp = rz_read_ble32(&sdl[12], bin->big_endian);
	dl.dylib.current_version = rz_read_ble32(&sdl[16], bin->big_endian);
	dl.dylib.compatibility_version = rz_read_ble32(&sdl[20], bin->big_endian);

	if (off + dl.dylib.name > bin->size ||
		off + dl.dylib.name + RZ_BIN_MACH0_STRING_LENGTH > bin->size) {
		return false;
	}

	memset(bin->libs[lib], 0, RZ_BIN_MACH0_STRING_LENGTH);
	len = rz_buf_read_at(bin->b, off + dl.dylib.name,
		(ut8 *)bin->libs[lib], RZ_BIN_MACH0_STRING_LENGTH);
	bin->libs[lib][RZ_BIN_MACH0_STRING_LENGTH - 1] = 0;
	if (len < 1) {
		bprintf("Error: read (dylib str)");
		return false;
	}
	return true;
}

static const char *cmd_to_string(ut32 cmd) {
	switch (cmd) {
	case LC_DATA_IN_CODE:
		return "LC_DATA_IN_CODE";
	case LC_CODE_SIGNATURE:
		return "LC_CODE_SIGNATURE";
	case LC_RPATH:
		return "LC_RPATH";
	case LC_TWOLEVEL_HINTS:
		return "LC_TWOLEVEL_HINTS";
	case LC_PREBIND_CKSUM:
		return "LC_PREBIND_CKSUM";
	case LC_SEGMENT:
		return "LC_SEGMENT";
	case LC_SEGMENT_64:
		return "LC_SEGMENT_64";
	case LC_SYMTAB:
		return "LC_SYMTAB";
	case LC_SYMSEG:
		return "LC_SYMSEG";
	case LC_DYSYMTAB:
		return "LC_DYSYMTAB";
	case LC_PREBOUND_DYLIB:
		return "LC_PREBOUND_DYLIB";
	case LC_ROUTINES:
		return "LC_ROUTINES";
	case LC_ROUTINES_64:
		return "LC_ROUTINES_64";
	case LC_SUB_FRAMEWORK:
		return "LC_SUB_FRAMEWORK";
	case LC_SUB_UMBRELLA:
		return "LC_SUB_UMBRELLA";
	case LC_SUB_CLIENT:
		return "LC_SUB_CLIENT";
	case LC_SUB_LIBRARY:
		return "LC_SUB_LIBRARY";
	case LC_FUNCTION_STARTS:
		return "LC_FUNCTION_STARTS";
	case LC_DYLIB_CODE_SIGN_DRS:
		return "LC_DYLIB_CODE_SIGN_DRS";
	case LC_NOTE:
		return "LC_NOTE";
	case LC_BUILD_VERSION:
		return "LC_BUILD_VERSION";
	case LC_VERSION_MIN_MACOSX:
		return "LC_VERSION_MIN_MACOSX";
	case LC_VERSION_MIN_IPHONEOS:
		return "LC_VERSION_MIN_IPHONEOS";
	case LC_VERSION_MIN_TVOS:
		return "LC_VERSION_MIN_TVOS";
	case LC_VERSION_MIN_WATCHOS:
		return "LC_VERSION_MIN_WATCHOS";
	case LC_DYLD_INFO:
		return "LC_DYLD_INFO";
	case LC_DYLD_INFO_ONLY:
		return "LC_DYLD_INFO_ONLY";
	case LC_DYLD_ENVIRONMENT:
		return "LC_DYLD_ENVIRONMENT";
	case LC_SOURCE_VERSION:
		return "LC_SOURCE_VERSION";
	case LC_MAIN:
		return "LC_MAIN";
	case LC_UUID:
		return "LC_UUID";
	case LC_ID_DYLIB:
		return "LC_ID_DYLIB";
	case LC_ID_DYLINKER:
		return "LC_ID_DYLINKER";
	case LC_LAZY_LOAD_DYLIB:
		return "LC_LAZY_LOAD_DYLIB";
	case LC_ENCRYPTION_INFO:
		return "LC_ENCRYPTION_INFO";
	case LC_ENCRYPTION_INFO_64:
		return "LC_ENCRYPTION_INFO_64";
	case LC_SEGMENT_SPLIT_INFO:
		return "LC_SEGMENT_SPLIT_INFO";
	case LC_REEXPORT_DYLIB:
		return "LC_REEXPORT_DYLIB";
	case LC_LINKER_OPTION:
		return "LC_LINKER_OPTION";
	case LC_LINKER_OPTIMIZATION_HINT:
		return "LC_LINKER_OPTIMIZATION_HINT";
	case LC_LOAD_DYLINKER:
		return "LC_LOAD_DYLINKER";
	case LC_LOAD_DYLIB:
		return "LC_LOAD_DYLIB";
	case LC_LOAD_WEAK_DYLIB:
		return "LC_LOAD_WEAK_DYLIB";
	case LC_THREAD:
		return "LC_THREAD";
	case LC_UNIXTHREAD:
		return "LC_UNIXTHREAD";
	case LC_LOADFVMLIB:
		return "LC_LOADFVMLIB";
	case LC_IDFVMLIB:
		return "LC_IDFVMLIB";
	case LC_IDENT:
		return "LC_IDENT";
	case LC_FVMFILE:
		return "LC_FVMFILE";
	case LC_PREPAGE:
		return "LC_PREPAGE";
	}
	return "";
}

static const char *cmd_to_pf_definition(ut32 cmd) {
	switch (cmd) {
	case LC_BUILD_VERSION:
		return "mach0_build_version_command";
	case LC_CODE_SIGNATURE:
		return "mach0_code_signature_command";
	case LC_DATA_IN_CODE:
		return "mach0_data_in_code_command";
	case LC_DYLD_INFO:
	case LC_DYLD_INFO_ONLY:
		return "mach0_dyld_info_only_command";
	case LC_DYLD_ENVIRONMENT:
		return NULL;
	case LC_DYLIB_CODE_SIGN_DRS:
		return NULL;
	case LC_DYSYMTAB:
		return "mach0_dysymtab_command";
	case LC_ENCRYPTION_INFO:
		return "mach0_encryption_info_command";
	case LC_ENCRYPTION_INFO_64:
		return "mach0_encryption_info64_command";
	case LC_FUNCTION_STARTS:
		return "mach0_function_starts_command";
	case LC_FVMFILE:
		return NULL;
	case LC_ID_DYLIB:
		return "mach0_id_dylib_command";
	case LC_ID_DYLINKER:
		return "mach0_id_dylinker_command";
	case LC_IDENT:
		return NULL;
	case LC_IDFVMLIB:
		return NULL;
	case LC_LINKER_OPTION:
		return NULL;
	case LC_LINKER_OPTIMIZATION_HINT:
		return NULL;
	case LC_LOAD_DYLINKER:
		return "mach0_load_dylinker_command";
	case LC_LAZY_LOAD_DYLIB:
	case LC_LOAD_WEAK_DYLIB:
	case LC_LOAD_DYLIB:
		return "mach0_dylib_command";
	case LC_LOADFVMLIB:
		return NULL;
	case LC_MAIN:
		return "mach0_entry_point_command";
	case LC_NOTE:
		return NULL;
	case LC_PREBIND_CKSUM:
		return NULL;
	case LC_PREBOUND_DYLIB:
		return NULL;
	case LC_PREPAGE:
		return NULL;
	case LC_REEXPORT_DYLIB:
		return NULL;
	case LC_ROUTINES:
		return NULL;
	case LC_ROUTINES_64:
		return NULL;
	case LC_RPATH:
		return "mach0_rpath_command";
	case LC_SEGMENT:
		return "mach0_segment";
	case LC_SEGMENT_64:
		return "mach0_segment64";
	case LC_SEGMENT_SPLIT_INFO:
		return "mach0_segment_split_info_command";
	case LC_SOURCE_VERSION:
		return "mach0_source_version_command";
	case LC_SUB_FRAMEWORK:
		return NULL;
	case LC_SUB_UMBRELLA:
		return NULL;
	case LC_SUB_CLIENT:
		return NULL;
	case LC_SUB_LIBRARY:
		return NULL;
	case LC_SYMTAB:
		return "mach0_symtab_command";
	case LC_SYMSEG:
		return NULL;
	case LC_TWOLEVEL_HINTS:
		return NULL;
	case LC_UUID:
		return "mach0_uuid_command";
	case LC_VERSION_MIN_MACOSX:
	case LC_VERSION_MIN_IPHONEOS:
	case LC_VERSION_MIN_TVOS:
	case LC_VERSION_MIN_WATCHOS:
		return "mach0_version_min_command";
	case LC_THREAD:
		return NULL;
	case LC_UNIXTHREAD:
		return "mach0_unixthread_command";
	}
	return NULL;
}

static bool read_load_command(struct load_command *lc, RzBuffer *buf, ut64 base, bool big_endian) {
	ut64 offset = base;
	return rz_buf_read_ble32_offset(buf, &offset, &lc->cmd, big_endian) &&
		rz_buf_read_ble32_offset(buf, &offset, &lc->cmdsize, big_endian);
}

static int init_items(struct MACH0_(obj_t) * bin) {
	struct load_command lc = { 0, 0 };
	bool is_first_thread = true;
	char tmpbuf[64];

	bin->uuidn = 0;
	bin->platform = UT32_MAX;
	bin->has_crypto = 0;
	if (bin->hdr.sizeofcmds > bin->size) {
		bprintf("Warning: chopping hdr.sizeofcmds\n");
		bin->hdr.sizeofcmds = bin->size - 128;
		// return false;
	}
	// bprintf ("Commands: %d\n", bin->hdr.ncmds);
	for (ut64 i = 0, off = sizeof(struct MACH0_(mach_header)) + bin->options.header_at;
		i < bin->hdr.ncmds; i++, off += lc.cmdsize) {
		if (off > bin->size || off + sizeof(struct load_command) > bin->size) {
			bprintf("mach0: out of bounds command\n");
			return false;
		}
		if (!read_load_command(&lc, bin->b, off, bin->big_endian)) {
			bprintf("Error: read (lc) at 0x%08" PFMT64x "\n", off);
			return false;
		}

		if (lc.cmdsize < 1 || off + lc.cmdsize > bin->size) {
			bprintf("Warning: mach0_header %" PFMT64u " = cmdsize<1. (0x%llx vs 0x%llx)\n", i,
				(ut64)(off + lc.cmdsize), (ut64)(bin->size));
			break;
		}

		sdb_num_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".offset", i), off);
		const char *format_name = cmd_to_pf_definition(lc.cmd);
		if (format_name) {
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".format", i), format_name);
		} else {
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".format", i), "[4]Ed (mach_load_command_type)cmd size");
		}

		switch (lc.cmd) {
		case LC_DATA_IN_CODE:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "data_in_code");
			break;
		case LC_RPATH:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "rpath");
			break;
		case LC_SEGMENT_64:
		case LC_SEGMENT:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "segment");
			bin->nsegs++;
			if (!parse_segments(bin, off)) {
				RZ_LOG_ERROR("mach0: error parsing segment\n");
				bin->nsegs--;
				return false;
			}
			break;
		case LC_SYMTAB:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "symtab");
			if (!parse_symtab(bin, off)) {
				RZ_LOG_ERROR("mach0: error parsing symtab\n");
				return false;
			}
			break;
		case LC_DYSYMTAB:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "dysymtab");
			if (!parse_dysymtab(bin, off)) {
				RZ_LOG_ERROR("mach0: error parsing dysymtab\n");
				return false;
			}
			break;
		case LC_DYLIB_CODE_SIGN_DRS:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "dylib_code_sign_drs");
			break;
		case LC_VERSION_MIN_MACOSX:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "version_min_macosx");
			if (bin->platform == UT32_MAX) {
				bin->platform = MACH0_PLATFORM_MACOS;
			}
			break;
		case LC_VERSION_MIN_IPHONEOS:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "version_min_iphoneos");
			if (bin->platform == UT32_MAX) {
				bin->platform = MACH0_PLATFORM_IOS;
			}
			break;
		case LC_VERSION_MIN_TVOS:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "version_min_tvos");
			if (bin->platform == UT32_MAX) {
				bin->platform = MACH0_PLATFORM_TVOS;
			}
			break;
		case LC_VERSION_MIN_WATCHOS:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "version_min_watchos");
			if (bin->platform == UT32_MAX) {
				bin->platform = MACH0_PLATFORM_WATCHOS;
			}
			break;
		case LC_BUILD_VERSION: {
			ut32 platform;
			if (!rz_buf_read_le32_at(bin->b, off + 8, &platform)) {
				break;
			}
			bin->platform = platform;
			break;
		}
		case LC_UUID:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "uuid");
			{
				struct uuid_command uc = { 0 };
				if (off + sizeof(struct uuid_command) > bin->size) {
					RZ_LOG_ERROR("mach0: UUID out of bounds\n");
					return false;
				}
				if (rz_buf_fread_at(bin->b, off, (ut8 *)&uc, "24c", 1) != -1) {
					char key[128];
					char val[128];
					snprintf(key, sizeof(key) - 1, "uuid.%d", bin->uuidn++);
					rz_hex_bin2str((ut8 *)&uc.uuid, 16, val);
					sdb_set(bin->kv, key, val);
					// for (i=0;i<16; i++) bprintf ("%02x%c", uc.uuid[i], (i==15)?'\n':'-');
				}
			}
			break;
		case LC_ENCRYPTION_INFO_64:
			/* TODO: the struct is probably different here */
		case LC_ENCRYPTION_INFO:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "encryption_info");
			{
				struct MACH0_(encryption_info_command) eic = { 0 };
				ut8 seic[sizeof(struct MACH0_(encryption_info_command))] = { 0 };
				if (off + sizeof(struct MACH0_(encryption_info_command)) > bin->size) {
					RZ_LOG_ERROR("mach0: encryption info out of bounds\n");
					return false;
				}
				if (rz_buf_read_at(bin->b, off, seic, sizeof(struct MACH0_(encryption_info_command))) != -1) {
					eic.cmd = rz_read_ble32(&seic[0], bin->big_endian);
					eic.cmdsize = rz_read_ble32(&seic[4], bin->big_endian);
					eic.cryptoff = rz_read_ble32(&seic[8], bin->big_endian);
					eic.cryptsize = rz_read_ble32(&seic[12], bin->big_endian);
					eic.cryptid = rz_read_ble32(&seic[16], bin->big_endian);

					bin->has_crypto = eic.cryptid;
					sdb_set(bin->kv, "crypto", "true");
					sdb_num_set(bin->kv, "cryptid", eic.cryptid);
					sdb_num_set(bin->kv, "cryptoff", eic.cryptoff);
					sdb_num_set(bin->kv, "cryptsize", eic.cryptsize);
					sdb_num_set(bin->kv, "cryptheader", off);
				}
			}
			break;
		case LC_LOAD_DYLINKER: {
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "dylinker");
			RZ_FREE(bin->intrp);
			// bprintf ("[mach0] load dynamic linker\n");
			struct dylinker_command dy = { 0 };
			ut8 sdy[sizeof(struct dylinker_command)] = { 0 };
			if (off + sizeof(struct dylinker_command) > bin->size) {
				RZ_LOG_ERROR("mach0: Cannot parse dylinker command\n");
				return false;
			}
			if (rz_buf_read_at(bin->b, off, sdy, sizeof(struct dylinker_command)) == -1) {
				RZ_LOG_ERROR("mach0: read (LC_DYLD_INFO) at 0x%08" PFMT64x "\n", off);
			} else {
				dy.cmd = rz_read_ble32(&sdy[0], bin->big_endian);
				dy.cmdsize = rz_read_ble32(&sdy[4], bin->big_endian);
				dy.name = rz_read_ble32(&sdy[8], bin->big_endian);

				int len = dy.cmdsize;
				char *buf = malloc(len + 1);
				if (buf) {
					// wtf @ off + 0xc ?
					rz_buf_read_at(bin->b, off + 0xc, (ut8 *)buf, len);
					buf[len] = 0;
					free(bin->intrp);
					bin->intrp = buf;
				}
			}
		} break;
		case LC_MAIN: {
			struct {
				ut64 eo;
				ut64 ss;
			} ep = { 0 };
			ut8 sep[2 * sizeof(ut64)] = { 0 };
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "main");

			if (!is_first_thread) {
				RZ_LOG_ERROR("mach0: LC_MAIN with other threads\n");
				return false;
			}
			if (off + 8 > bin->size || off + sizeof(ep) > bin->size) {
				RZ_LOG_ERROR("mach0: invalid command size for main\n");
				return false;
			}
			rz_buf_read_at(bin->b, off + 8, sep, 2 * sizeof(ut64));
			ep.eo = rz_read_ble64(&sep[0], bin->big_endian);
			ep.ss = rz_read_ble64(&sep[8], bin->big_endian);

			bin->entry = ep.eo;
			bin->main_cmd = lc;

			sdb_num_set(bin->kv, "mach0.entry.offset", off + 8);
			sdb_num_set(bin->kv, "stacksize", ep.ss);

			is_first_thread = false;
		} break;
		case LC_UNIXTHREAD:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "unixthread");
			if (!is_first_thread) {
				RZ_LOG_ERROR("mach0: LC_UNIXTHREAD with other threads\n");
				return false;
			}
			// fallthrough
		case LC_THREAD:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "thread");
			if (!parse_thread(bin, &lc, off, is_first_thread)) {
				RZ_LOG_ERROR("mach0: Cannot parse thread\n");
				return false;
			}
			is_first_thread = false;
			break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "load_dylib");
			bin->nlibs++;
			if (!parse_dylib(bin, off)) {
				RZ_LOG_ERROR("mach0: Cannot parse dylib\n");
				bin->nlibs--;
				return false;
			}
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY: {
			ut8 dyldi[sizeof(struct dyld_info_command)] = { 0 };
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "dyld_info");
			bin->dyld_info = calloc(1, sizeof(struct dyld_info_command));
			if (bin->dyld_info) {
				if (off + sizeof(struct dyld_info_command) > bin->size) {
					RZ_LOG_ERROR("mach0: Cannot parse dyldinfo\n");
					RZ_FREE(bin->dyld_info);
					return false;
				}
				if (rz_buf_read_at(bin->b, off, dyldi, sizeof(struct dyld_info_command)) == -1) {
					RZ_FREE(bin->dyld_info);
					RZ_LOG_ERROR("mach0: read (LC_DYLD_INFO) at 0x%08" PFMT64x "\n", off);
				} else {
					bin->dyld_info->cmd = rz_read_ble32(&dyldi[0], bin->big_endian);
					bin->dyld_info->cmdsize = rz_read_ble32(&dyldi[4], bin->big_endian);
					bin->dyld_info->rebase_off = rz_read_ble32(&dyldi[8], bin->big_endian);
					bin->dyld_info->rebase_size = rz_read_ble32(&dyldi[12], bin->big_endian);
					bin->dyld_info->bind_off = rz_read_ble32(&dyldi[16], bin->big_endian);
					bin->dyld_info->bind_size = rz_read_ble32(&dyldi[20], bin->big_endian);
					bin->dyld_info->weak_bind_off = rz_read_ble32(&dyldi[24], bin->big_endian);
					bin->dyld_info->weak_bind_size = rz_read_ble32(&dyldi[28], bin->big_endian);
					bin->dyld_info->lazy_bind_off = rz_read_ble32(&dyldi[32], bin->big_endian);
					bin->dyld_info->lazy_bind_size = rz_read_ble32(&dyldi[36], bin->big_endian);
					bin->dyld_info->export_off = rz_read_ble32(&dyldi[40], bin->big_endian) + bin->options.symbols_off;
					bin->dyld_info->export_size = rz_read_ble32(&dyldi[44], bin->big_endian);
				}
			}
		} break;
		case LC_CODE_SIGNATURE:
			parse_signature(bin, off);
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "signature");
			/* ut32 dataoff
			// ut32 datasize */
			break;
		case LC_SOURCE_VERSION:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "version");
			/* uint64_t  version;  */
			/* A.B.C.D.E packed as a24.b10.c10.d10.e10 */
			break;
		case LC_SEGMENT_SPLIT_INFO:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "split_info");
			/* TODO */
			break;
		case LC_FUNCTION_STARTS:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "function_starts");
			if (!parse_function_starts(bin, off)) {
				RZ_LOG_ERROR("mach0: Cannot parse LC_FUNCTION_STARTS\n");
			}
			break;
		case LC_REEXPORT_DYLIB:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "dylib");
			/* TODO */
			break;
		default:
			// RZ_LOG_ERROR("mach0: Unknown header command %x\n", lc.cmd);
			break;
		}
	}
	bool has_chained_fixups = false;
	for (ut64 i = 0, off = sizeof(struct MACH0_(mach_header)) + bin->options.header_at;
		i < bin->hdr.ncmds; i++, off += lc.cmdsize) {

		if (!read_load_command(&lc, bin->b, off, bin->big_endian)) {
			bprintf("Error: read (lc) at 0x%08" PFMT64x "\n", off);
			return false;
		}

		if (lc.cmdsize < 1 || off + lc.cmdsize > bin->size) {
			bprintf("Warning: mach0_header %" PFMT64u " = cmdsize<1. (0x%llx vs 0x%llx)\n", i,
				(ut64)(off + lc.cmdsize), (ut64)(bin->size));
			break;
		}

		sdb_num_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".offset", i), off);
		const char *format_name = cmd_to_pf_definition(lc.cmd);
		if (format_name) {
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".format", i), format_name);
		} else {
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".format", i), "[4]Ed (mach_load_command_type)cmd size");
		}

		switch (lc.cmd) {
		case LC_DATA_IN_CODE:
			sdb_set(bin->kv, rz_strf(tmpbuf, "mach0_cmd_%" PFMT64u ".cmd", i), "data_in_code");
			if (bin->options.verbose) {
				ut8 buf[8];
				rz_buf_read_at(bin->b, off + 8, buf, sizeof(buf));
				ut32 dataoff = rz_read_ble32(buf, bin->big_endian);
				ut32 datasize = rz_read_ble32(buf + 4, bin->big_endian);
				eprintf("data-in-code at 0x%x size %d\n", dataoff, datasize);
				ut8 *db = (ut8 *)malloc(datasize);
				if (db) {
					rz_buf_read_at(bin->b, dataoff, db, datasize);
					// TODO table of non-instructions regions in __text
					int j;
					for (j = 0; j < datasize; j += 8) {
						ut32 dw = rz_read_ble32(db + j, bin->big_endian);
						// int kind = rz_read_ble16 (db + i + 4 + 2, bin->big_endian);
						int len = rz_read_ble16(db + j + 4, bin->big_endian);
						ut64 va = MACH0_(paddr_to_vaddr)(bin, dw);
						//	eprintf ("# 0x%d -> 0x%x\n", dw, va);
						//	eprintf ("0x%x kind %d len %d\n", dw, kind, len);
						eprintf("Cd 4 %d @ 0x%" PFMT64x "\n", len / 4, va);
					}
				}
			}
			break;
		case LC_DYLD_EXPORTS_TRIE:
			if (bin->options.verbose) {
				ut8 buf[8];
				rz_buf_read_at(bin->b, off + 8, buf, sizeof(buf));
				ut32 dataoff = rz_read_ble32(buf, bin->big_endian);
				ut32 datasize = rz_read_ble32(buf + 4, bin->big_endian);
				eprintf("exports trie at 0x%x size %d\n", dataoff, datasize);
			}
			break;
		case LC_DYLD_CHAINED_FIXUPS: {
			ut8 buf[8];
			if (rz_buf_read_at(bin->b, off + 8, buf, sizeof(buf)) == sizeof(buf)) {
				ut32 dataoff = rz_read_ble32(buf, bin->big_endian);
				ut32 datasize = rz_read_ble32(buf + 4, bin->big_endian);
				if (bin->options.verbose) {
					eprintf("chained fixups at 0x%x size %d\n", dataoff, datasize);
				}
				has_chained_fixups = MACH0_(parse_chained_fixups)(bin, dataoff, datasize);
			}
		} break;
		}
	}

	if (!has_chained_fixups && bin->hdr.cputype == CPU_TYPE_ARM64 &&
		(bin->hdr.cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
		// clang-format off
		MACH0_(reconstruct_chained_fixups_from_threaded)(bin);
		// clang-format on
	}
	return true;
}

static bool init(struct MACH0_(obj_t) * mo) {
	if (!init_hdr(mo)) {
		return false;
	}
	if (!init_items(mo)) {
		Eprintf("Warning: Cannot initialize items\n");
	}
	mo->baddr = MACH0_(get_baddr)(mo);
	return true;
}

void *MACH0_(mach0_free)(struct MACH0_(obj_t) * mo) {
	if (!mo) {
		return NULL;
	}

	size_t i;
	if (mo->symbols) {
		for (i = 0; !mo->symbols[i].last; i++) {
			free(mo->symbols[i].name);
		}
		free(mo->symbols);
	}
	free(mo->segs);
	free(mo->sects);
	free(mo->symtab);
	free(mo->symstr);
	free(mo->indirectsyms);
	rz_pvector_fini(&mo->imports_by_ord);
	if (mo->imports_by_name) {
		ht_pp_free(mo->imports_by_name);
	}
	free(mo->dyld_info);
	free(mo->toc);
	free(mo->modtab);
	free(mo->libs);
	free(mo->func_start);
	free(mo->signature);
	free(mo->intrp);
	free(mo->compiler);
	struct mach0_chained_fixups_t *cf = &mo->chained_fixups;
	if (cf->starts) {
		for (i = 0; i < cf->starts_count; i++) {
			if (cf->starts[i]) {
				free(cf->starts[i]->page_start);
				free(cf->starts[i]);
			}
		}
		free(cf->starts);
	}
	rz_vector_fini(&cf->imports);
	rz_pvector_free(mo->patchable_relocs);
	rz_skiplist_free(mo->relocs);
	rz_hash_free(mo->hash);
	rz_buf_free(mo->b);
	free(mo);
	return NULL;
}

void MACH0_(opts_set_default)(struct MACH0_(opts_t) * options, RzBinFile *bf) {
	rz_return_if_fail(options && bf && bf->rbin);
	options->header_at = 0;
	options->symbols_off = 0;
	options->verbose = bf->rbin->verbose;
	options->patch_relocs = true;
}

struct MACH0_(obj_t) * MACH0_(new_buf)(RzBuffer *buf, struct MACH0_(opts_t) * options) {
	rz_return_val_if_fail(buf, NULL);
	struct MACH0_(obj_t) *bin = RZ_NEW0(struct MACH0_(obj_t));
	if (bin) {
		bin->b = rz_buf_ref(buf);
		bin->main_addr = UT64_MAX;
		bin->kv = sdb_new(NULL, "bin.mach0", 0);
		bin->hash = rz_hash_new();
		bin->size = rz_buf_size(bin->b);
		rz_pvector_init(&bin->imports_by_ord, NULL);
		if (options) {
			bin->options = *options;
		}
		if (!init(bin)) {
			return MACH0_(mach0_free)(bin);
		}
	}
	return bin;
}

// prot: r = 1, w = 2, x = 4
// perm: r = 4, w = 2, x = 1
static int prot2perm(int x) {
	int r = 0;
	if (x & 1) {
		r |= 4;
	}
	if (x & 2) {
		r |= 2;
	}
	if (x & 4) {
		r |= 1;
	}
	return r;
}

static bool __isDataSection(RzBinSection *sect) {
	if (strstr(sect->name, "_cstring")) {
		return true;
	}
	if (strstr(sect->name, "_objc_methname")) {
		return true;
	}
	if (strstr(sect->name, "_objc_classname")) {
		return true;
	}
	if (strstr(sect->name, "_objc_methtype")) {
		return true;
	}
	return false;
}

RzPVector /*<RzBinVirtualFile *>*/ *MACH0_(get_virtual_files)(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!ret) {
		return NULL;
	}

	struct MACH0_(obj_t) *obj = bf->o->bin_obj;

	// clang-format off
	// relocs
	MACH0_(patch_relocs)(bf, obj);
	// clang-format: on
	// virtual file for reloc targets (where the relocs will point into)
	ut64 rtmsz = MACH0_(reloc_targets_vfile_size)(obj);
	if (rtmsz) {
		RzBuffer *buf = rz_buf_new_empty(rtmsz);
		if (!buf) {
			return ret;
		}
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			rz_buf_free(buf);
			return ret;
		}
		vf->buf = buf;
		vf->buf_owned = true;
		vf->name = strdup(MACH0_VFILE_NAME_RELOC_TARGETS);
		rz_pvector_push(ret, vf);
	}
	// virtual file mirroring the raw file, but with relocs patched
	if (obj->buf_patched) {
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			return ret;
		}
		vf->buf = obj->buf_patched;
		vf->buf_owned = false;
		vf->name = strdup(MACH0_VFILE_NAME_PATCHED);
		rz_pvector_push(ret, vf);
	}
	return ret;
}

RzPVector /*<RzBinMap *>*/ *MACH0_(get_maps_unpatched)(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	struct MACH0_(obj_t) *bin = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}
	for (size_t i = 0; i < bin->nsegs; i++) {
		struct MACH0_(segment_command) *seg = &bin->segs[i];
		if (!seg->initprot) {
			continue;
		}
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			break;
		}
		map->psize = seg->vmsize;
		map->vaddr = seg->vmaddr;
		map->vsize = seg->vmsize;
		map->name = rz_str_ndup(seg->segname, 16);
		rz_str_filter(map->name);
		map->perm = prot2perm(seg->initprot);
		// boffset is relevant for fatmach0 where the mach0 is located boffset into the whole file
		// the rebasing vfile above however is based at the mach0 already
		map->paddr = seg->fileoff + bf->o->boffset;
		rz_pvector_push(ret, map);
	}
	return ret;
}

RzPVector /*<RzBinMap *>*/ *MACH0_(get_maps)(RzBinFile *bf) {
	RzPVector *ret = MACH0_(get_maps_unpatched)(bf);
	if (!ret) {
		return NULL;
	}
	struct MACH0_(obj_t) *obj = bf->o->bin_obj;
	// clang-format off
	MACH0_(patch_relocs)(bf, obj);
	// clang-format on
	rz_bin_relocs_patch_maps(ret, obj->buf_patched, bf->o->boffset,
		MACH0_(reloc_targets_map_base)(bf, obj), MACH0_(reloc_targets_vfile_size)(obj),
		MACH0_VFILE_NAME_PATCHED, MACH0_VFILE_NAME_RELOC_TARGETS);
	return ret;
}

RzPVector /*<RzBinSection *>*/ *MACH0_(get_segments)(RzBinFile *bf) {
	struct MACH0_(obj_t) *bin = bf->o->bin_obj;
	if (bin->sections_cache) {
		return rz_pvector_clone(bin->sections_cache);
	}
	RzPVector *vec = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	size_t i, j;

	if (bin->nsegs > 0) {
		struct MACH0_(segment_command) * seg;
		for (i = 0; i < bin->nsegs; i++) {
			seg = &bin->segs[i];
			if (!seg->initprot) {
				continue;
			}
			RzBinSection *s = rz_bin_section_new(NULL);
			if (!s) {
				break;
			}
			s->vaddr = seg->vmaddr;
			s->vsize = seg->vmsize;
			s->size = seg->vmsize;
			s->paddr = seg->fileoff;
			s->paddr += bf->o->boffset;
			// TODO s->flags = seg->flags;
			s->name = rz_str_ndup(seg->segname, 16);
			s->is_segment = true;
			rz_str_filter(s->name);
			s->perm = prot2perm(seg->initprot);
			rz_pvector_push(vec, s);
		}
	}
	if (bin->nsects > 0) {
		int last_section = RZ_MIN(bin->nsects, 128); // maybe drop this limit?
		for (i = 0; i < last_section; i++) {
			RzBinSection *s = RZ_NEW0(RzBinSection);
			if (!s) {
				break;
			}
			s->vaddr = (ut64)bin->sects[i].addr;
			s->vsize = (ut64)bin->sects[i].size;
			s->align = (ut64)(1ULL << (bin->sects[i].align & 63));
			s->is_segment = false;
			s->size = (bin->sects[i].flags == S_ZEROFILL) ? 0 : (ut64)bin->sects[i].size;
			// The bottom byte of flags is the section type
			s->type = bin->sects[i].flags & 0xFF;
			s->flags = bin->sects[i].flags & 0xFFFFFF00;
			// XXX flags
			s->paddr = (ut64)bin->sects[i].offset;
			int segment_index = 0;
			// s->perm =prot2perm (bin->segs[j].initprot);
			for (j = 0; j < bin->nsegs; j++) {
				if (s->vaddr >= bin->segs[j].vmaddr &&
					s->vaddr < (bin->segs[j].vmaddr + bin->segs[j].vmsize)) {
					s->perm = prot2perm(bin->segs[j].initprot);
					segment_index = j;
					break;
				}
			}
			char *section_name = rz_str_ndup(bin->sects[i].sectname, 16);
			char *segment_name = rz_str_newf("%zu.%s", i, bin->segs[segment_index].segname);
			s->name = rz_str_newf("%s.%s", segment_name, section_name);
			s->is_data = __isDataSection(s);
			if (strstr(section_name, "interpos") || strstr(section_name, "__mod_")) {
#if RZ_BIN_MACH064
				const int ws = 8;
#else
				const int ws = 4;
#endif
				s->format = rz_str_newf("Cd %d[%" PFMT64d "]", ws, s->vsize / ws);
			}
			rz_pvector_push(vec, s);
			free(segment_name);
			free(section_name);
		}
	}
	bin->sections_cache = vec;
	return rz_pvector_clone(vec);
}

char *MACH0_(section_type_to_string)(ut64 type) {
	switch (type) {
	case S_REGULAR:
		return rz_str_dup("REGULAR");
	case S_ZEROFILL:
		return rz_str_dup("ZEROFILL");
	case S_CSTRING_LITERALS:
		return rz_str_dup("CSTRING_LITERALS");
	case S_4BYTE_LITERALS:
		return rz_str_dup("4BYTE_LITERALS");
	case S_LITERAL_POINTERS:
		return rz_str_dup("LITERAL_POINTERS");
	case S_NON_LAZY_SYMBOL_POINTERS:
		return rz_str_dup("NON_LAZY_SYMBOL_POINTERS");
	case S_LAZY_SYMBOL_POINTERS:
		return rz_str_dup("LAZY_SYMBOL_POINTERS");
	case S_SYMBOL_STUBS:
		return rz_str_dup("SYMBOL_STUBS");
	case S_MOD_INIT_FUNC_POINTERS:
		return rz_str_dup("MOD_INIT_FUNC_POINTERS");
	case S_MOD_TERM_FUNC_POINTERS:
		return rz_str_dup("MOD_TERM_FUNC_POINTERS");
	case S_COALESCED:
		return rz_str_dup("COALESCED");
	case S_GB_ZEROFILL:
		return rz_str_dup("GB_ZEROFILL");
	default:
		return rz_str_newf("0x%" PFMT64x, type);
	}
}

RzList /*<char *>*/ *MACH0_(section_flag_to_rzlist)(ut64 flag) {
	RzList *flag_list = rz_list_new();
	if (flag & S_ATTR_PURE_INSTRUCTIONS) {
		rz_list_append(flag_list, "PURE_INSTRUCTIONS");
	}
	if (flag & S_ATTR_NO_TOC) {
		rz_list_append(flag_list, "NO_TOC");
	}
	if (flag & S_ATTR_SOME_INSTRUCTIONS) {
		rz_list_append(flag_list, "SOME_INSTRUCTIONS");
	}
	if (flag & S_ATTR_EXT_RELOC) {
		rz_list_append(flag_list, "EXT_RELOC");
	}
	if (flag & S_ATTR_SELF_MODIFYING_CODE) {
		rz_list_append(flag_list, "SELF_MODIFYING_CODE");
	}
	if (flag & S_ATTR_DEBUG) {
		rz_list_append(flag_list, "DEBUG");
	}
	if (flag & S_ATTR_LIVE_SUPPORT) {
		rz_list_append(flag_list, "LIVE_SUPPORT");
	}
	if (flag & S_ATTR_STRIP_STATIC_SYMS) {
		rz_list_append(flag_list, "STRIP_STATIC_SYMS");
	}
	if (flag & S_ATTR_NO_DEAD_STRIP) {
		rz_list_append(flag_list, "NO_DEAD_STRIP");
	}
	return flag_list;
}

// XXX this function is called so many times
struct section_t *MACH0_(get_sections)(struct MACH0_(obj_t) * bin) {
	rz_return_val_if_fail(bin, NULL);
	struct section_t *sections;
	char sectname[64], raw_segname[17];
	size_t i, j;

	/* for core files */
	if (bin->nsects < 1 && bin->nsegs > 0) {
		struct MACH0_(segment_command) * seg;
		if (!(sections = calloc((bin->nsegs + 1), sizeof(struct section_t)))) {
			return NULL;
		}
		for (i = 0; i < bin->nsegs; i++) {
			seg = &bin->segs[i];
			sections[i].addr = seg->vmaddr;
			sections[i].offset = seg->fileoff;
			sections[i].size = seg->vmsize;
			sections[i].vsize = seg->vmsize;
			sections[i].align = 4096;
			sections[i].flags = seg->flags;
			rz_strf(sectname, "%.16s", seg->segname);
			sectname[16] = 0;
			rz_str_filter(sectname);
			// hack to support multiple sections with same name
			sections[i].perm = prot2perm(seg->initprot);
			sections[i].last = 0;
		}
		sections[i].last = 1;
		return sections;
	}

	if (!bin->sects || bin->nsects < 1) {
		return NULL;
	}
	ut32 to = RZ_MIN(bin->nsects, 128); // limit number of sections here to avoid fuzzed bins
	if (!(sections = calloc(to + 1, sizeof(struct section_t)))) {
		return NULL;
	}
	for (i = 0; i < to; i++) {
		sections[i].offset = (ut64)bin->sects[i].offset;
		sections[i].addr = (ut64)bin->sects[i].addr;
		sections[i].size = (bin->sects[i].flags == S_ZEROFILL) ? 0 : (ut64)bin->sects[i].size;
		sections[i].vsize = (ut64)bin->sects[i].size;
		sections[i].align = bin->sects[i].align;
		sections[i].flags = bin->sects[i].flags;
		rz_strf(sectname, "%.16s", bin->sects[i].sectname);
		rz_str_filter(sectname);
		rz_strf(raw_segname, "%.16s", bin->sects[i].segname);
		for (j = 0; j < bin->nsegs; j++) {
			if (sections[i].addr >= bin->segs[j].vmaddr &&
				sections[i].addr < (bin->segs[j].vmaddr + bin->segs[j].vmsize)) {
				sections[i].perm = prot2perm(bin->segs[j].initprot);
				break;
			}
		}
		snprintf(sections[i].name, sizeof(sections[i].name),
			"%d.%s.%s", (int)i, raw_segname, sectname);
		sections[i].last = 0;
	}
	sections[i].last = 1;
	return sections;
}

static bool parse_import_stub(struct MACH0_(obj_t) * bin, struct symbol_t *symbol, int idx) {
	size_t i, j, nsyms, stridx;
	const char *symstr;
	if (idx < 0) {
		return false;
	}
	symbol->offset = 0LL;
	symbol->addr = 0LL;
	symbol->name = NULL;
	symbol->is_imported = true;

	if (!bin || !bin->sects) {
		return false;
	}
	for (i = 0; i < bin->nsects; i++) {
		if ((bin->sects[i].flags & SECTION_TYPE) == S_SYMBOL_STUBS && bin->sects[i].reserved2 > 0) {
			ut64 sect_size = bin->sects[i].size;
			ut32 sect_fragment = bin->sects[i].reserved2;
			if (bin->sects[i].offset > bin->size) {
				bprintf("mach0: section offset starts way beyond the end of the file\n");
				continue;
			}
			if (sect_size > bin->size) {
				bprintf("mach0: Invalid symbol table size\n");
				sect_size = bin->size - bin->sects[i].offset;
			}
			nsyms = (int)(sect_size / sect_fragment);
			for (j = 0; j < nsyms; j++) {
				if (bin->sects) {
					if (bin->sects[i].reserved1 + j >= bin->nindirectsyms) {
						continue;
					}
				}
				if (bin->indirectsyms) {
					if (idx != bin->indirectsyms[bin->sects[i].reserved1 + j]) {
						continue;
					}
				}
				if (idx > bin->nsymtab) {
					continue;
				}
				symbol->type = RZ_BIN_MACH0_SYMBOL_TYPE_LOCAL;
				int delta = j * bin->sects[i].reserved2;
				if (delta < 0) {
					bprintf("mach0: corrupted reserved2 value leads to int overflow.\n");
					continue;
				}
				symbol->offset = bin->sects[i].offset + delta;
				symbol->addr = bin->sects[i].addr + delta;
				symbol->size = 0;
				stridx = bin->symtab[idx].n_strx;
				if (stridx < bin->symstrlen) {
					symstr = (char *)bin->symstr + stridx;
				} else {
					symstr = "???";
				}
				// Remove the extra underscore that every import seems to have in Mach-O.
				if (*symstr == '_') {
					symstr++;
				}
				symbol->name = strdup(symstr);
				return true;
			}
		}
	}
	return false;
}

static int inSymtab(HtSP *hash, const char *name, ut64 addr) {
	bool found = false;
	char *key = rz_str_newf("%" PFMT64x ".%s", addr, name);
	ht_sp_find(hash, key, &found);
	if (found) {
		free(key);
		return true;
	}
	ht_sp_insert(hash, key, "1", NULL);
	free(key);
	return false;
}

/**
 * \brief Get a string from the string table referenced by the LC_SYMTAB command.
 * \param stridx the index into the string table, such as n_strx from a nlist symbol entry
 * \param filter whether to call rz_str_filter() on the string before returning
 */
RZ_API RZ_OWN char *MACH0_(get_name)(struct MACH0_(obj_t) * mo, ut32 stridx, bool filter) {
	size_t i = 0;
	if (!mo->symstr || stridx >= mo->symstrlen) {
		return NULL;
	}
	int len = mo->symstrlen - stridx;
	const char *symstr = (const char *)mo->symstr + stridx;
	for (i = 0; i < len; i++) {
		if ((ut8)(symstr[i] & 0xff) == 0xff || !symstr[i]) {
			len = i;
			break;
		}
	}
	if (len > 0) {
		char *res = rz_str_ndup(symstr, len);
		if (filter) {
			rz_str_filter(res);
		}
		return res;
	}
	return NULL;
}

static int walk_exports(struct MACH0_(obj_t) * bin, RExportsIterator iterator, void *ctx) {
	rz_return_val_if_fail(bin, 0);
	if (!bin->dyld_info) {
		return 0;
	}

	size_t count = 0;
	ut8 *p = NULL;
	ut8 *trie = NULL;
	RzList *states = NULL;
	ut64 size = bin->dyld_info->export_size;
	if (!size || size >= SIZE_MAX) {
		return count;
	}
	trie = calloc(size + 1, 1);
	if (!trie) {
		return count;
	}
	ut8 *end = trie + size;

	if (rz_buf_read_at(bin->b, bin->dyld_info->export_off, trie, bin->dyld_info->export_size) != size) {
		goto beach;
	}

	states = rz_list_newf((RzListFree)free);
	if (!states) {
		goto beach;
	}

	RTrieState *root = RZ_NEW0(RTrieState);
	if (!root) {
		goto beach;
	}
	root->node = trie;
	root->i = 0;
	root->label = NULL;
	rz_list_push(states, root);

	do {
		RTrieState *state = rz_list_last(states);
		p = state->node;
		ut64 len = read_uleb128(&p, end);
		if (len == UT64_MAX) {
			break;
		}
		if (len) {
			ut64 flags = read_uleb128(&p, end);
			if (flags == UT64_MAX) {
				break;
			}
			ut64 offset = read_uleb128(&p, end);
			if (offset == UT64_MAX) {
				break;
			}
			ut64 resolver = 0;
			bool isReexport = flags & EXPORT_SYMBOL_FLAGS_REEXPORT;
			bool hasResolver = flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER;
			if (hasResolver) {
				ut64 res = read_uleb128(&p, end);
				if (res == UT64_MAX) {
					break;
				}
				resolver = res + bin->options.header_at;
			} else if (isReexport) {
				p += strlen((char *)p) + 1;
				// TODO: handle this
			}
			if (!isReexport) {
				offset += bin->options.header_at;
			}
			if (iterator && !isReexport) {
				char *name = NULL;
				RzListIter *iter;
				RTrieState *s;
				rz_list_foreach (states, iter, s) {
					if (!s->label) {
						continue;
					}
					name = rz_str_append(name, s->label);
				}
				if (!name) {
					RZ_LOG_ERROR("malformed export trie\n");
					goto beach;
				}
				if (hasResolver) {
					char *stub_name = rz_str_newf("stub.%s", name);
					iterator(bin, stub_name, flags, offset, ctx);
					iterator(bin, name, flags, resolver, ctx);
					RZ_FREE(stub_name);
				} else {
					iterator(bin, name, flags, offset, ctx);
				}
				RZ_FREE(name);
			}
			if (!isReexport) {
				if (hasResolver) {
					count++;
				}
				count++;
			}
		}
		ut64 child_count = read_uleb128(&p, end);
		if (child_count == UT64_MAX) {
			goto beach;
		}
		if (state->i == child_count) {
			rz_list_pop(states);
			continue;
		}
		if (!state->next_child) {
			state->next_child = p;
		} else {
			p = state->next_child;
		}
		RTrieState *next = RZ_NEW0(RTrieState);
		if (!next) {
			goto beach;
		}
		next->label = (char *)p;
		p += strlen(next->label) + 1;
		if (p >= end) {
			RZ_LOG_ERROR("malformed export trie\n");
			RZ_FREE(next);
			goto beach;
		}
		ut64 tr = read_uleb128(&p, end);
		if (tr == UT64_MAX) {
			RZ_FREE(next);
			goto beach;
		}
		if (tr >= size) {
			RZ_LOG_ERROR("malformed export trie\n");
			RZ_FREE(next);
			goto beach;
		}
		next->node = trie + (size_t)tr;
		{
			// avoid loops
			RzListIter *it;
			RTrieState *s;
			rz_list_foreach (states, it, s) {
				if (s->node == next->node) {
					RZ_LOG_ERROR("malformed export trie\n");
					RZ_FREE(next);
					goto beach;
				}
			}
		}
		next->i = 0;
		state->i++;
		state->next_child = p;
		rz_list_push(states, next);
	} while (rz_list_length(states));

beach:
	rz_list_free(states);
	RZ_FREE(trie);
	return count;
}

static void assign_export_symbol_t(struct MACH0_(obj_t) * bin, const char *name, ut64 flags, ut64 offset, void *ctx) {
	RSymCtx *sym_ctx = (RSymCtx *)ctx;
	int j = sym_ctx->j;
	if (j < sym_ctx->symbols_count) {
		sym_ctx->symbols[j].offset = offset;
		sym_ctx->symbols[j].addr = MACH0_(paddr_to_vaddr)(bin, offset);
		if (inSymtab(sym_ctx->hash, name, sym_ctx->symbols[j].addr)) {
			return;
		}
		sym_ctx->symbols[j].size = 0;
		sym_ctx->symbols[j].type = RZ_BIN_MACH0_SYMBOL_TYPE_EXT;
		sym_ctx->symbols[j].name = strdup(name);
		sym_ctx->j++;
	}
}

const struct symbol_t *MACH0_(get_symbols)(struct MACH0_(obj_t) * bin) {
	struct symbol_t *symbols;
	int j = 0, s = 0, stridx = 0;
	size_t symbols_size = 0, symbols_count = 0;
	ut64 to = 0, from = 0, i = 0;

	if (bin->symbols) {
		return bin->symbols;
	}

	HtSP *hash = ht_sp_new(HT_STR_DUP, NULL, NULL);
	if (!hash) {
		return NULL;
	}

	rz_return_val_if_fail(bin, NULL);
	int n_exports = walk_exports(bin, NULL, NULL);

	symbols_count = n_exports;
	j = 0; // symbol_idx

	int bits = MACH0_(get_bits_from_hdr)(&bin->hdr);
	if (bin->symtab && bin->symstr) {
		/* parse dynamic symbol table */
		symbols_count = (bin->dysymtab.nextdefsym +
			bin->dysymtab.nlocalsym +
			bin->dysymtab.nundefsym);
		symbols_count += (bin->nsymtab + 1);
		if (SZT_MUL_OVFCHK(symbols_count, 2)) {
			RZ_LOG_ERROR("mach0: detected symbols count overflow\n");
			ht_sp_free(hash);
			return NULL;
		}
		symbols_size = symbols_count * 2;
		symbols = RZ_NEWS0(struct symbol_t, symbols_size);
		if (!symbols) {
			ht_sp_free(hash);
			return NULL;
		}
		bin->main_addr = 0;
		for (s = 0; s < 2; s++) {
			switch (s) {
			case 0:
				from = bin->dysymtab.iextdefsym;
				to = from + bin->dysymtab.nextdefsym;
				break;
			case 1:
				from = bin->dysymtab.ilocalsym;
				to = from + bin->dysymtab.nlocalsym;
				break;
#if NOT_USED
			case 2:
				from = bin->dysymtab.iundefsym;
				to = from + bin->dysymtab.nundefsym;
				break;
#endif
			}
			if (from == to) {
				continue;
			}

			from = RZ_MIN(RZ_MAX(0, from), symbols_size);
			to = RZ_MIN(RZ_MIN(to, bin->nsymtab), symbols_size);

			ut32 maxsymbols = symbols_size;
			if (symbols_count >= maxsymbols) {
				symbols_count = maxsymbols - 1;
				RZ_LOG_WARN("mach0: symbol table is truncated\n");
			}
			for (i = from; i < to && j < symbols_count; i++, j++) {
				symbols[j].offset = MACH0_(vaddr_to_paddr)(bin, bin->symtab[i].n_value);
				symbols[j].addr = bin->symtab[i].n_value;
				symbols[j].size = 0; /* TODO: Is it anywhere? */
				symbols[j].bits = bin->symtab[i].n_desc & N_ARM_THUMB_DEF ? 16 : bits;
				symbols[j].is_imported = false;
				symbols[j].type = (bin->symtab[i].n_type & N_EXT)
					? RZ_BIN_MACH0_SYMBOL_TYPE_EXT
					: RZ_BIN_MACH0_SYMBOL_TYPE_LOCAL;
				stridx = bin->symtab[i].n_strx;
				symbols[j].name = MACH0_(get_name)(bin, stridx, false);
				symbols[j].last = false;

				const char *name = symbols[j].name;
				if (bin->main_addr == 0 && name) {
					if (!strcmp(name, "__Dmain")) {
						bin->main_addr = symbols[j].addr;
					} else if (strstr(name, "4main") && !strstr(name, "STATIC")) {
						bin->main_addr = symbols[j].addr;
					} else if (!strcmp(name, "_main")) {
						bin->main_addr = symbols[j].addr;
					} else if (!strcmp(name, "main")) {
						bin->main_addr = symbols[j].addr;
					}
				}
				if (inSymtab(hash, symbols[j].name, symbols[j].addr)) {
					free(symbols[j].name);
					symbols[j].name = NULL;
					j--;
				}
			}
		}
		to = RZ_MIN((ut32)bin->nsymtab, bin->dysymtab.iundefsym + bin->dysymtab.nundefsym);
		for (i = bin->dysymtab.iundefsym; i < to; i++) {
			if (j > symbols_count) {
				bprintf("mach0-get-symbols: error\n");
				break;
			}
			if (parse_import_stub(bin, &symbols[j], i)) {
				symbols[j++].last = false;
			}
		}

		for (i = 0; i < bin->nsymtab && i < symbols_count; i++) {
			struct MACH0_(nlist) *st = &bin->symtab[i];
			if (st->n_type & N_STAB) {
				continue;
			}
			// 0 is for imports
			// 1 is for symbols
			// 2 is for func.eh (exception handlers?)
			int section = st->n_sect;
			if (section == 1 && j < symbols_count) {
				// check if symbol exists already
				/* is symbol */
				symbols[j].addr = st->n_value;
				symbols[j].offset = MACH0_(vaddr_to_paddr)(bin, symbols[j].addr);
				symbols[j].size = 0; /* find next symbol and crop */
				symbols[j].type = (st->n_type & N_EXT)
					? RZ_BIN_MACH0_SYMBOL_TYPE_EXT
					: RZ_BIN_MACH0_SYMBOL_TYPE_LOCAL;
				char *sym_name = MACH0_(get_name)(bin, st->n_strx, false);
				if (sym_name) {
					symbols[j].name = sym_name;
				} else {
					symbols[j].name = rz_str_newf("entry%" PFMT64u, i);
				}
				symbols[j].last = false;
				if (inSymtab(hash, symbols[j].name, symbols[j].addr)) {
					RZ_FREE(symbols[j].name);
				} else {
					j++;
				}

				const char *name = symbols[i].name;
				if (bin->main_addr == 0 && name) {
					if (name && !strcmp(name, "__Dmain")) {
						bin->main_addr = symbols[i].addr;
					} else if (name && strstr(name, "4main") && !strstr(name, "STATIC")) {
						bin->main_addr = symbols[i].addr;
					} else if (symbols[i].name && !strcmp(symbols[i].name, "_main")) {
						bin->main_addr = symbols[i].addr;
					}
				}
			}
		}
	} else if (!n_exports) {
		ht_sp_free(hash);
		return NULL;
	} else {
		if (SZT_ADD_OVFCHK(symbols_count, 1)) {
			ht_sp_free(hash);
			return NULL;
		}
		symbols_size = symbols_count + 1;
		if (!(symbols = RZ_NEWS0(struct symbol_t, symbols_size))) {
			ht_sp_free(hash);
			return NULL;
		}
	}
	if (n_exports && (symbols_count - j) >= n_exports) {
		RSymCtx sym_ctx;
		sym_ctx.symbols = symbols;
		sym_ctx.j = j;
		sym_ctx.symbols_count = symbols_count;
		sym_ctx.hash = hash;
		walk_exports(bin, assign_export_symbol_t, &sym_ctx);
		j = sym_ctx.j;
	}
	ht_sp_free(hash);
	symbols[j].last = true;
	bin->symbols = symbols;
	return symbols;
}

static void imports_foreach_undefsym(struct MACH0_(obj_t) * bin, mach0_import_foreach_cb cb, void *user) {
	if (!bin->sects || !bin->symtab || !bin->symstr || !bin->indirectsyms || bin->dysymtab.nundefsym > 0xfffff) {
		return;
	}
	for (int i = 0; i < bin->dysymtab.nundefsym; i++) {
		int idx = bin->dysymtab.iundefsym + i;
		if (idx < 0 || idx >= bin->nsymtab) {
			bprintf("WARNING: Imports index out of bounds. Ignoring relocs\n");
			return;
		}
		int stridx = bin->symtab[idx].n_strx;
		char *imp_name = MACH0_(get_name)(bin, stridx, false);
		if (!imp_name) {
			continue;
		}
		cb(imp_name, i, user);
	}
}

static void imports_foreach_chained(struct MACH0_(obj_t) * bin, mach0_import_foreach_cb cb, void *user) {
	size_t ci_count = MACH0_(chained_imports_count)(bin);
	for (size_t i = 0; i < ci_count; i++) {
		struct MACH0_(chained_import_t) import;
		if (!MACH0_(get_chained_import)(bin, i, &import)) {
			continue;
		}
		char *name = MACH0_(chained_import_read_symbol_name)(bin, &import);
		if (!name) {
			continue;
		}
		cb(name, i, user);
	}
}

/**
 * Iterate over all available imports
 * Important: the name string passed to \p cb is not freed automatically and should either be moved
 *            or freed by \p cb itself.
 */
void MACH0_(imports_foreach)(struct MACH0_(obj_t) * bin, mach0_import_foreach_cb cb, void *user) {
	rz_return_if_fail(bin && cb);
	if (MACH0_(has_chained_fixups)(bin)) {
		imports_foreach_chained(bin, cb, user);
	} else {
		imports_foreach_undefsym(bin, cb, user);
	}
}

/**
 * Upper bound for the number of items MACH0_(imports_foreach)() will emit
 */
size_t MACH0_(imports_count)(struct MACH0_(obj_t) * bin) {
	if (MACH0_(has_chained_fixups)(bin)) {
		return MACH0_(chained_imports_count)(bin);
	} else {
		if (bin->dysymtab.nundefsym > bin->nsymtab) {
			RZ_LOG_ERROR("Invalid nundefsym value in LC_DYSYMTAB\n");
			return 0;
		}
		return bin->dysymtab.nundefsym;
	}
}

struct addr_t *MACH0_(get_entrypoint)(struct MACH0_(obj_t) * bin) {
	rz_return_val_if_fail(bin, NULL);

	ut64 ea = entry_to_vaddr(bin);
	if (ea == 0 || ea == UT64_MAX) {
		return NULL;
	}
	struct addr_t *entry = RZ_NEW0(struct addr_t);
	if (!entry) {
		return NULL;
	}
	entry->addr = ea;
	entry->offset = MACH0_(vaddr_to_paddr)(bin, entry->addr);
	entry->haddr = sdb_num_get(bin->kv, "mach0.entry.offset");
	sdb_num_set(bin->kv, "mach0.entry.vaddr", entry->addr);
	sdb_num_set(bin->kv, "mach0.entry.paddr", bin->entry);

	if (entry->offset == 0 && !bin->sects) {
		int i;
		for (i = 0; i < bin->nsects; i++) {
			// XXX: section name shoudnt matter .. just check for exec flags
			if (!strncmp(bin->sects[i].sectname, "__text", 6)) {
				entry->offset = (ut64)bin->sects[i].offset;
				sdb_num_set(bin->kv, "mach0.entry", entry->offset);
				entry->addr = (ut64)bin->sects[i].addr;
				if (!entry->addr) { // workaround for object files
					eprintf("entrypoint is 0...\n");
					// XXX(lowlyw) there's technically not really entrypoints
					// for .o files, so ignore this...
					// entry->addr = entry->offset;
				}
				break;
			}
		}
		bin->entry = entry->addr;
	}
	return entry;
}

void MACH0_(kv_loadlibs)(struct MACH0_(obj_t) * bin) {
	int i;
	char tmpbuf[32];
	for (i = 0; i < bin->nlibs; i++) {
		sdb_set(bin->kv, rz_strf(tmpbuf, "libs.%d.name", i), bin->libs[i]);
	}
}

struct lib_t *MACH0_(get_libs)(struct MACH0_(obj_t) * bin) {
	struct lib_t *libs;
	int i;

	if (!bin->nlibs) {
		return NULL;
	}
	if (!(libs = calloc((bin->nlibs + 1), sizeof(struct lib_t)))) {
		return NULL;
	}
	char tmpbuf[32];
	for (i = 0; i < bin->nlibs; i++) {
		sdb_set(bin->kv, rz_strf(tmpbuf, "libs.%d.name", i), bin->libs[i]);
		strncpy(libs[i].name, bin->libs[i], RZ_BIN_MACH0_STRING_LENGTH - 1);
		libs[i].name[RZ_BIN_MACH0_STRING_LENGTH - 1] = '\0';
		libs[i].last = 0;
	}
	libs[i].last = 1;
	return libs;
}

ut64 MACH0_(get_baddr)(struct MACH0_(obj_t) * bin) {
	int i;

	if (bin->hdr.filetype != MH_EXECUTE && bin->hdr.filetype != MH_DYLINKER &&
		bin->hdr.filetype != MH_FILESET) {
		return 0;
	}
	for (i = 0; i < bin->nsegs; i++) {
		if (bin->segs[i].fileoff == 0 && bin->segs[i].filesize != 0) {
			return bin->segs[i].vmaddr;
		}
	}
	return 0;
}

char *MACH0_(get_class)(struct MACH0_(obj_t) * bin) {
#if RZ_BIN_MACH064
	return rz_str_dup("MACH064");
#else
	return rz_str_dup("MACH0");
#endif
}

// XXX we are mixing up bits from cpu and opcodes
// since thumb use 16 bits opcode but run in 32 bits
// cpus  so here we should only return 32 or 64
int MACH0_(get_bits)(struct MACH0_(obj_t) * bin) {
	if (bin) {
		int bits = MACH0_(get_bits_from_hdr)(&bin->hdr);
		if (bin->hdr.cputype == CPU_TYPE_ARM && bin->entry & 1) {
			return 16;
		}
		return bits;
	}
	return 32;
}

int MACH0_(get_bits_from_hdr)(struct MACH0_(mach_header) * hdr) {
	if (hdr->magic == MH_MAGIC_64 || hdr->magic == MH_CIGAM_64) {
		return 64;
	}
	if (hdr->cputype == CPU_TYPE_ARM64_32) { // new apple watch aka arm64_32
		return 64;
	}
	if ((hdr->cpusubtype & CPU_SUBTYPE_MASK) == (CPU_SUBTYPE_ARM_V7K << 24)) {
		return 16;
	}
	return 32;
}

bool MACH0_(is_big_endian)(struct MACH0_(obj_t) * bin) {
	if (bin) {
		const int cpu = bin->hdr.cputype;
		return cpu == CPU_TYPE_POWERPC || cpu == CPU_TYPE_POWERPC64;
	}
	return false;
}

const char *MACH0_(get_intrp)(struct MACH0_(obj_t) * bin) {
	return bin ? bin->intrp : NULL;
}

const char *MACH0_(get_platform)(struct MACH0_(obj_t) * bin) {
	rz_return_val_if_fail(bin, "unknown");
	return rz_mach0_platform_to_string(bin->platform);
}

const char *MACH0_(get_cputype_from_hdr)(struct MACH0_(mach_header) * hdr) {
	rz_return_val_if_fail(hdr, "unknown");
	return rz_mach0_cputype_to_string(hdr->cputype);
}

const char *MACH0_(get_cputype)(struct MACH0_(obj_t) * bin) {
	return bin ? MACH0_(get_cputype_from_hdr)(&bin->hdr) : "unknown";
}

char *MACH0_(get_cpusubtype_from_hdr)(struct MACH0_(mach_header) * hdr) {
	rz_return_val_if_fail(hdr, NULL);
	return strdup(rz_mach0_cpusubtype_tostring(hdr->cputype, hdr->cpusubtype));
}

char *MACH0_(get_cpusubtype)(struct MACH0_(obj_t) * bin) {
	return bin ? MACH0_(get_cpusubtype_from_hdr)(&bin->hdr) : strdup("Unknown");
}

bool MACH0_(is_pie)(struct MACH0_(obj_t) * bin) {
	return (bin && bin->hdr.filetype == MH_EXECUTE && bin->hdr.flags & MH_PIE);
}

bool MACH0_(has_nx)(struct MACH0_(obj_t) * bin) {
	return (bin && bin->hdr.filetype == MH_EXECUTE &&
		bin->hdr.flags & MH_NO_HEAP_EXECUTION);
}

char *MACH0_(get_filetype_from_hdr)(struct MACH0_(mach_header) * hdr) {
	const char *mhtype = "Unknown";
	switch (hdr->filetype) {
	case MH_OBJECT: mhtype = "Relocatable object"; break;
	case MH_EXECUTE: mhtype = "Executable file"; break;
	case MH_FVMLIB: mhtype = "Fixed VM shared library"; break;
	case MH_CORE: mhtype = "Core file"; break;
	case MH_PRELOAD: mhtype = "Preloaded executable file"; break;
	case MH_DYLIB: mhtype = "Dynamically bound shared library"; break;
	case MH_DYLINKER: mhtype = "Dynamic link editor"; break;
	case MH_BUNDLE: mhtype = "Dynamically bound bundle file"; break;
	case MH_DYLIB_STUB: mhtype = "Shared library stub for static linking (no sections)"; break;
	case MH_DSYM: mhtype = "Companion file with only debug sections"; break;
	case MH_KEXT_BUNDLE: mhtype = "Kernel extension bundle file"; break;
	case MH_FILESET: mhtype = "Kernel cache file"; break;
	}
	return strdup(mhtype);
}

char *MACH0_(get_filetype)(struct MACH0_(obj_t) * bin) {
	return bin ? MACH0_(get_filetype_from_hdr)(&bin->hdr) : strdup("Unknown");
}

ut64 MACH0_(get_main)(struct MACH0_(obj_t) * bin) {
	ut64 addr = UT64_MAX;
	int i;

	// 0 = sscanned but no main found
	// -1 = not scanned, so no main
	// other = valid main addr
	if (bin->main_addr == UT64_MAX) {
		(void)MACH0_(get_symbols)(bin);
	}
	if (bin->main_addr != 0 && bin->main_addr != UT64_MAX) {
		return bin->main_addr;
	}
	// dummy call to initialize things
	free(MACH0_(get_entrypoint)(bin));

	bin->main_addr = 0;

	if (addr == UT64_MAX && bin->main_cmd.cmd == LC_MAIN) {
		addr = bin->entry + bin->baddr;
	}

	if (!addr) {
		ut8 b[128];
		ut64 entry = MACH0_(vaddr_to_paddr)(bin, bin->entry);
		// XXX: X86 only and hacky!
		if (entry > bin->size || entry + sizeof(b) > bin->size) {
			return UT64_MAX;
		}
		i = rz_buf_read_at(bin->b, entry, b, sizeof(b));
		if (i < 80) {
			return UT64_MAX;
		}
		for (i = 0; i < 64; i++) {
			if (b[i] == 0xe8 && !b[i + 3] && !b[i + 4]) {
				int delta = b[i + 1] | (b[i + 2] << 8) | (b[i + 3] << 16) | (b[i + 4] << 24);
				addr = bin->entry + i + 5 + delta;
				break;
			}
		}
		if (!addr) {
			addr = entry;
		}
	}
	return bin->main_addr = addr;
}

void MACH0_(mach_headerfields)(RzBinFile *bf) {
	PrintfCallback cb_printf = bf->rbin->cb_printf;
	if (!cb_printf) {
		cb_printf = printf;
	}
	RzBuffer *buf = bf->buf;
	ut64 length = rz_buf_size(buf);
	int n = 0;
	struct MACH0_(mach_header) *mh = MACH0_(get_hdr)(buf);
	if (!mh) {
		return;
	}
	ut64 pvaddr = pa2va(bf, 0);
	cb_printf("pf.mach0_header @ 0x%08" PFMT64x "\n", pvaddr);
	cb_printf("0x%08" PFMT64x "  Magic       0x%x\n", pvaddr, mh->magic);
	pvaddr += 4;
	cb_printf("0x%08" PFMT64x "  CpuType     0x%x\n", pvaddr, mh->cputype);
	pvaddr += 4;
	cb_printf("0x%08" PFMT64x "  CpuSubType  0x%x\n", pvaddr, mh->cpusubtype);
	pvaddr += 4;
	cb_printf("0x%08" PFMT64x "  FileType    0x%x\n", pvaddr, mh->filetype);
	pvaddr += 4;
	cb_printf("0x%08" PFMT64x "  nCmds       %d\n", pvaddr, mh->ncmds);
	pvaddr += 4;
	cb_printf("0x%08" PFMT64x "  sizeOfCmds  %d\n", pvaddr, mh->sizeofcmds);
	pvaddr += 4;
	cb_printf("0x%08" PFMT64x "  Flags       0x%x\n", pvaddr, mh->flags);
	pvaddr += 4;
	bool is64 = mh->cputype >> 16;

	ut64 addr = 0x20 - 4;
	ut32 word = 0;
	ut8 wordbuf[sizeof(word)];
	bool isBe = false;
	switch (mh->cputype) {
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		isBe = true;
		break;
	}
#define READWORD() \
	if (rz_buf_read_at(buf, addr, (ut8 *)wordbuf, 4) != 4) { \
		eprintf("Invalid address in buffer."); \
		break; \
	} \
	addr += 4; \
	pvaddr += 4; \
	word = isBe ? rz_read_be32(wordbuf) : rz_read_le32(wordbuf);
	if (is64) {
		addr += 4;
		pvaddr += 4;
	}
	for (n = 0; n < mh->ncmds; n++) {
		READWORD();
		ut32 lcType = word;
		const char *pf_definition = cmd_to_pf_definition(lcType);
		if (pf_definition) {
			cb_printf("pf.%s @ 0x%08" PFMT64x "\n", pf_definition, pvaddr - 4);
		}
		cb_printf("0x%08" PFMT64x "  cmd %7d 0x%x %s\n",
			pvaddr - 4, n, lcType, cmd_to_string(lcType));
		READWORD();
		if (addr > length) {
			break;
		}
		int lcSize = word;
		word &= 0xFFFFFF;
		cb_printf("0x%08" PFMT64x "  cmdsize     %d\n", pvaddr - 4, word);
		if (lcSize < 1) {
			eprintf("Invalid size for a load command\n");
			break;
		}
		switch (lcType) {
		case LC_BUILD_VERSION: {
			ut32 platform;
			if (!rz_buf_read_le32_at(buf, addr, &platform)) {
				break;
			}
			cb_printf("0x%08" PFMT64x "  platform    %s\n", pvaddr, rz_mach0_platform_to_string(platform));

			ut16 minos1;
			if (!rz_buf_read_le16_at(buf, addr + 6, &minos1)) {
				break;
			}
			ut8 minos2;
			if (!rz_buf_read8_at(buf, addr + 5, &minos2)) {
				break;
			}
			ut8 minos3;
			if (!rz_buf_read8_at(buf, addr + 4, &minos3)) {
				break;
			}
			cb_printf("0x%08" PFMT64x "  minos       %d.%d.%d\n", pvaddr + 4, minos1, minos2, minos3);

			ut16 sdk1;
			if (!rz_buf_read_le16_at(buf, addr + 10, &sdk1)) {
				break;
			}
			ut8 sdk2;
			if (!rz_buf_read8_at(buf, addr + 9, &sdk2)) {
				break;
			}
			ut8 sdk3;
			if (!rz_buf_read8_at(buf, addr + 8, &sdk3)) {
				break;
			}
			cb_printf("0x%08" PFMT64x "  sdk         %d.%d.%d\n", pvaddr + 8, sdk1, sdk2, sdk3);

			ut32 ntools;
			if (!rz_buf_read_le32_at(buf, addr + 12, &ntools)) {
				break;
			}
			cb_printf("0x%08" PFMT64x "  ntools      %d\n", pvaddr + 12, ntools);

			ut64 off = 16;
			while (off < (lcSize - 8) && ntools--) {
				cb_printf("pf.mach0_build_version_tool @ 0x%08" PFMT64x "\n", pvaddr + off);

				ut32 tool;
				if (!rz_buf_read_le32_at(buf, addr + off, &tool)) {
					break;
				}
				cb_printf("0x%08" PFMT64x "  tool        %s\n", pvaddr + off, rz_mach0_build_version_tool_to_string(tool));

				off += 4;
				if (off >= (lcSize - 8)) {
					break;
				}

				ut16 version1;
				if (!rz_buf_read_le16_at(buf, addr + off + 2, &version1)) {
					break;
				}
				ut8 version2;
				if (!rz_buf_read8_at(buf, addr + off + 1, &version2)) {
					break;
				}
				ut8 version3;
				if (!rz_buf_read8_at(buf, addr + off, &version3)) {
					break;
				}
				cb_printf("0x%08" PFMT64x "  version     %d.%d.%d\n", pvaddr + off, version1, version2, version3);

				off += 4;
			}
			break;
		}
		case LC_MAIN: {
			ut8 data[64] = { 0 };
			rz_buf_read_at(buf, addr, data, sizeof(data));
#if RZ_BIN_MACH064
			ut64 ep = rz_read_ble64(&data, false); //  bin->big_endian);
			cb_printf("0x%08" PFMT64x "  entry0      0x%" PFMT64x "\n", pvaddr, ep);
			ut64 ss = rz_read_ble64(&data[8], false); //  bin->big_endian);
			cb_printf("0x%08" PFMT64x "  stacksize   0x%" PFMT64x "\n", pvaddr + 8, ss);
#else
			ut32 ep = rz_read_ble32(&data, false); //  bin->big_endian);
			cb_printf("0x%08" PFMT32x "  entry0      0x%" PFMT32x "\n", (ut32)pvaddr, ep);
			ut32 ss = rz_read_ble32(&data[4], false); //  bin->big_endian);
			cb_printf("0x%08" PFMT32x "  stacksize   0x%" PFMT32x "\n", (ut32)pvaddr + 4, ss);
#endif
		} break;
		case LC_SYMTAB:
#if 0
			{
			char *id = rz_buf_get_string (buf, addr + 20);
			cb_printf ("0x%08"PFMT64x"  id         0x%x\n", addr + 20, id? id: "");
			cb_printf ("0x%08"PFMT64x"  symooff    0x%x\n", addr + 20, id? id: "");
			cb_printf ("0x%08"PFMT64x"  nsyms      %d\n", addr + 20, id? id: "");
			cb_printf ("0x%08"PFMT64x"  stroff     0x%x\n", addr + 20, id? id: "");
			cb_printf ("0x%08"PFMT64x"  strsize    0x%x\n", addr + 20, id? id: "");
			free (id);
			}
#endif
			break;
		case LC_ID_DYLIB: { // install_name_tool
			ut32 str_off;
			if (!rz_buf_read_ble32_at(buf, addr, &str_off, isBe)) {
				break;
			}

			char *id = rz_buf_get_string(buf, addr + str_off - 8);

			ut16 current1;
			if (!rz_buf_read_le16_at(buf, addr + 10, &current1)) {
				free(id);
				break;
			}
			ut8 current2;
			if (!rz_buf_read8_at(buf, addr + 9, &current2)) {
				free(id);
				break;
			}
			ut8 current3;
			if (!rz_buf_read8_at(buf, addr + 8, &current3)) {
				free(id);
				break;
			}
			cb_printf("0x%08" PFMT64x "  current     %d.%d.%d\n", pvaddr + 8, current1, current2, current3);

			ut16 compat1;
			if (!rz_buf_read_le16_at(buf, addr + 14, &compat1)) {
				free(id);
				break;
			}
			ut8 compat2;
			if (!rz_buf_read8_at(buf, addr + 13, &compat2)) {
				free(id);
				break;
			}
			ut8 compat3;
			if (!rz_buf_read8_at(buf, addr + 12, &compat3)) {
				free(id);
				break;
			}
			cb_printf("0x%08" PFMT64x "  compat      %d.%d.%d\n", pvaddr + 12, compat1, compat2, compat3);

			cb_printf("0x%08" PFMT64x "  id          %s\n",
				pvaddr + str_off - 8, id ? id : "");
			free(id);
			break;
		}
		case LC_UUID: {
			ut8 i, uuid[16];
			rz_buf_read_at(buf, addr, uuid, sizeof(uuid));
			cb_printf("0x%08" PFMT64x "  uuid        ", pvaddr);
			for (i = 0; i < sizeof(uuid); i++) {
				cb_printf("%02x", uuid[i]);
			}
			cb_printf("\n");
		} break;
		case LC_SEGMENT:
		case LC_SEGMENT_64: {
			ut8 name[17] = { 0 };
			rz_buf_read_at(buf, addr, name, sizeof(name) - 1);
			cb_printf("0x%08" PFMT64x "  name        %s\n", pvaddr, name);
			ut32 nsects;
			if (!rz_buf_read_le32_at(buf, addr - 8 + (is64 ? 64 : 48), &nsects)) {
				break;
			}
			ut64 off = is64 ? 72 : 56;
			while (off < lcSize && nsects--) {
				if (is64) {
					cb_printf("pf.mach0_section64 @ 0x%08" PFMT64x "\n", pvaddr - 8 + off);
					off += 80;
				} else {
					cb_printf("pf.mach0_section @ 0x%08" PFMT64x "\n", pvaddr - 8 + off);
					off += 68;
				}
			}
		} break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB: {
			ut32 str_off;
			if (!rz_buf_read_ble32_at(buf, addr, &str_off, isBe)) {
				break;
			}
			char *load_dylib = rz_buf_get_string(buf, addr + str_off - 8);
			ut16 current1;
			if (!rz_buf_read_le16_at(buf, addr + 10, &current1)) {
				free(load_dylib);
				break;
			}
			ut8 current2;
			if (!rz_buf_read8_at(buf, addr + 9, &current2)) {
				free(load_dylib);
				break;
			}
			ut8 current3;
			if (!rz_buf_read8_at(buf, addr + 8, &current3)) {
				free(load_dylib);
				break;
			}
			cb_printf("0x%08" PFMT64x "  current     %d.%d.%d\n", pvaddr + 8, current1, current2, current3);
			ut16 compat1;
			if (!rz_buf_read_le16_at(buf, addr + 14, &compat1)) {
				free(load_dylib);
				break;
			}
			ut8 compat2;
			if (!rz_buf_read8_at(buf, addr + 13, &compat2)) {
				free(load_dylib);
				break;
			}
			ut8 compat3;
			if (!rz_buf_read8_at(buf, addr + 12, &compat3)) {
				free(load_dylib);
				break;
			}
			cb_printf("0x%08" PFMT64x "  compat      %d.%d.%d\n", pvaddr + 12, compat1, compat2, compat3);
			cb_printf("0x%08" PFMT64x "  load_dylib  %s\n",
				pvaddr + str_off - 8, load_dylib ? load_dylib : "");
			free(load_dylib);
			break;
		}
		case LC_RPATH: {
			char *rpath = rz_buf_get_string(buf, addr + 4);
			cb_printf("0x%08" PFMT64x "  rpath       %s\n",
				pvaddr + 4, rpath ? rpath : "");
			free(rpath);
			break;
		}
		case LC_ENCRYPTION_INFO:
		case LC_ENCRYPTION_INFO_64: {
			ut32 word;
			if (!rz_buf_read_le32_at(buf, addr, &word)) {
				break;
			}
			cb_printf("0x%08" PFMT64x "  cryptoff   0x%08x\n", pvaddr, word);

			if (!rz_buf_read_le32_at(buf, addr + 4, &word)) {
				break;
			}
			cb_printf("0x%08" PFMT64x "  cryptsize  %d\n", pvaddr + 4, word);

			if (!rz_buf_read_le32_at(buf, addr + 8, &word)) {
				break;
			}
			cb_printf("0x%08" PFMT64x "  cryptid    %d\n", pvaddr + 8, word);
			break;
		}
		case LC_CODE_SIGNATURE: {
			ut32 words[2];
			rz_buf_read_at(buf, addr, (ut8 *)words, sizeof(words));
			cb_printf("0x%08" PFMT64x "  dataoff     0x%08x\n", pvaddr, words[0]);
			cb_printf("0x%08" PFMT64x "  datasize    %d\n", pvaddr + 4, words[1]);
			cb_printf("# wtf mach0.sign %d @ 0x%x\n", words[1], words[0]);
			break;
		}
		}
		addr += word - 8;
		pvaddr += word - 8;
	}
	free(mh);
}

RzPVector /*<RzBinField *>*/ *MACH0_(mach_fields)(RzBinFile *bf) {
	RzBuffer *buf = bf->buf;
	ut64 length = rz_buf_size(buf);
	struct MACH0_(mach_header) *mh = MACH0_(get_hdr)(buf);
	if (!mh) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_field_free);
	if (!ret) {
		free(mh);
		return NULL;
	}
	ut64 addr = pa2va(bf, 0);
	ut64 paddr = 0;

	rz_pvector_push(ret, rz_bin_field_new(addr, addr, 1, "header", "mach0_header", "mach0_header", true));
	addr += 0x20 - 4;
	paddr += 0x20 - 4;
	bool is64 = mh->cputype >> 16;
	if (is64) {
		addr += 4;
		paddr += 4;
	}

	bool isBe = false;
	switch (mh->cputype) {
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		isBe = true;
		break;
	}

	int n;
	char tmpbuf[128];
	for (n = 0; n < mh->ncmds; n++) {
		ut32 lcType;
		if (!rz_buf_read_ble32_at(buf, paddr, &lcType, isBe)) {
			break;
		}
		ut32 word;
		if (!rz_buf_read_ble32_at(buf, paddr + 4, &word, isBe)) {
			break;
		}
		if (paddr + 8 > length) {
			break;
		}
		ut32 lcSize = word;
		word &= 0xFFFFFF;
		if (lcSize < 1) {
			eprintf("Invalid size for a load command\n");
			break;
		}
		if (word == 0) {
			break;
		}
		const char *pf_definition = cmd_to_pf_definition(lcType);
		if (pf_definition) {
			rz_pvector_push(ret, rz_bin_field_new(addr, addr, 1, rz_strf(tmpbuf, "load_command_%d_%s", n, cmd_to_string(lcType)), pf_definition, pf_definition, true));
		}
		switch (lcType) {
		case LC_BUILD_VERSION: {
			ut32 ntools;
			if (!rz_buf_read_le32_at(buf, paddr + 20, &ntools)) {
				break;
			}
			ut64 off = 24;
			int j = 0;
			while (off < lcSize && ntools--) {
				rz_pvector_push(ret, rz_bin_field_new(addr + off, addr + off, 1, rz_strf(tmpbuf, "tool_%d", j++), "mach0_build_version_tool", "mach0_build_version_tool", true));
				off += 8;
			}
			break;
		}
		case LC_SEGMENT:
		case LC_SEGMENT_64: {
			ut32 nsects;
			if (!rz_buf_read_le32_at(buf, addr + (is64 ? 64 : 48), &nsects)) {
				break;
			}
			ut64 off = is64 ? 72 : 56;
			size_t i, j = 0;
			for (i = 0; i < nsects && (addr + off) < length && off < lcSize; i++) {
				const char *sname = is64 ? "mach0_section64" : "mach0_section";
				RzBinField *f = rz_bin_field_new(addr + off, addr + off, 1,
					rz_strf(tmpbuf, "section_%zu", j++), sname, sname, true);
				rz_pvector_push(ret, f);
				off += is64 ? 80 : 68;
			}
			break;
		default:
			// TODO
			break;
		}
		}
		addr += word;
		paddr += word;
	}
	free(mh);
	return ret;
}

struct MACH0_(mach_header) * MACH0_(get_hdr)(RzBuffer *buf) {
	ut8 magicbytes[sizeof(ut32)] = { 0 };
	ut8 machohdrbytes[sizeof(struct MACH0_(mach_header))] = { 0 };
	int len;
	struct MACH0_(mach_header) *macho_hdr = RZ_NEW0(struct MACH0_(mach_header));
	bool big_endian = false;
	if (!macho_hdr) {
		return NULL;
	}
	if (rz_buf_read_at(buf, 0, magicbytes, 4) < 1) {
		free(macho_hdr);
		return false;
	}

	if (rz_read_le32(magicbytes) == 0xfeedface) {
		big_endian = false;
	} else if (rz_read_be32(magicbytes) == 0xfeedface) {
		big_endian = true;
	} else if (rz_read_le32(magicbytes) == FAT_MAGIC) {
		big_endian = false;
	} else if (rz_read_be32(magicbytes) == FAT_MAGIC) {
		big_endian = true;
	} else if (rz_read_le32(magicbytes) == 0xfeedfacf) {
		big_endian = false;
	} else if (rz_read_be32(magicbytes) == 0xfeedfacf) {
		big_endian = true;
	} else {
		/* also extract non-mach0s */
#if 0
		free (macho_hdr);
		return NULL;
#endif
	}
	len = rz_buf_read_at(buf, 0, machohdrbytes, sizeof(machohdrbytes));
	if (len != sizeof(struct MACH0_(mach_header))) {
		free(macho_hdr);
		return NULL;
	}
	macho_hdr->magic = rz_read_ble(&machohdrbytes[0], big_endian, 32);
	macho_hdr->cputype = rz_read_ble(&machohdrbytes[4], big_endian, 32);
	macho_hdr->cpusubtype = rz_read_ble(&machohdrbytes[8], big_endian, 32);
	macho_hdr->filetype = rz_read_ble(&machohdrbytes[12], big_endian, 32);
	macho_hdr->ncmds = rz_read_ble(&machohdrbytes[16], big_endian, 32);
	macho_hdr->sizeofcmds = rz_read_ble(&machohdrbytes[20], big_endian, 32);
	macho_hdr->flags = rz_read_ble(&machohdrbytes[24], big_endian, 32);
#if RZ_BIN_MACH064
	macho_hdr->reserved = rz_read_ble(&machohdrbytes[28], big_endian, 32);
#endif
	return macho_hdr;
}
