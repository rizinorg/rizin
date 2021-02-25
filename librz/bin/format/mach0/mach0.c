// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_util.h>
#include "mach0.h"
#include <rz_hash.h>

// TODO: deprecate bprintf and use Eprintf (bin->self)
#define bprintf \
	if (bin->verbose) \
	eprintf
#define Eprintf \
	if (mo->verbose) \
	eprintf

typedef struct {
	struct symbol_t *symbols;
	int j;
	int symbols_count;
	HtPP *hash;
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

static ut64 read_uleb128(ut8 **p, ut8 *end) {
	const char *error = NULL;
	ut64 v;
	*p = (ut8 *)rz_uleb128(*p, end - *p, &v, &error);
	if (error) {
		eprintf("%s", error);
		RZ_FREE(error);
		return UT64_MAX;
	}
	return v;
}

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

static ut64 addr_to_offset(struct MACH0_(obj_t) * bin, ut64 addr) {
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

static ut64 offset_to_vaddr(struct MACH0_(obj_t) * bin, ut64 offset) {
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
	return bin ? offset_to_vaddr(bin, offset) : offset;
}

static void init_sdb_formats(struct MACH0_(obj_t) * bin) {
	/*
	 * These definitions are used by rz -nn
	 * must be kept in sync with librz/bin/d/macho
	 */
	sdb_set(bin->kv, "mach0_build_platform.cparse",
		"enum mach0_build_platform"
		"{MACOS=1, IOS=2, TVOS=3, WATCHOS=4, BRIDGEOS=5, IOSMAC=6, IOSSIMULATOR=7, TVOSSIMULATOR=8, WATCHOSSIMULATOR=9};",
		0);
	sdb_set(bin->kv, "mach0_build_tool.cparse",
		"enum mach0_build_tool"
		"{CLANG=1, SWIFT=2, LD=3};",
		0);
	sdb_set(bin->kv, "mach0_load_command_type.cparse",
		"enum mach0_load_command_type"
		"{ LC_SEGMENT=0x00000001ULL, LC_SYMTAB=0x00000002ULL, LC_SYMSEG=0x00000003ULL, LC_THREAD=0x00000004ULL, LC_UNIXTHREAD=0x00000005ULL, LC_LOADFVMLIB=0x00000006ULL, LC_IDFVMLIB=0x00000007ULL, LC_IDENT=0x00000008ULL, LC_FVMFILE=0x00000009ULL, LC_PREPAGE=0x0000000aULL, LC_DYSYMTAB=0x0000000bULL, LC_LOAD_DYLIB=0x0000000cULL, LC_ID_DYLIB=0x0000000dULL, LC_LOAD_DYLINKER=0x0000000eULL, LC_ID_DYLINKER=0x0000000fULL, LC_PREBOUND_DYLIB=0x00000010ULL, LC_ROUTINES=0x00000011ULL, LC_SUB_FRAMEWORK=0x00000012ULL, LC_SUB_UMBRELLA=0x00000013ULL, LC_SUB_CLIENT=0x00000014ULL, LC_SUB_LIBRARY=0x00000015ULL, LC_TWOLEVEL_HINTS=0x00000016ULL, LC_PREBIND_CKSUM=0x00000017ULL, LC_LOAD_WEAK_DYLIB=0x80000018ULL, LC_SEGMENT_64=0x00000019ULL, LC_ROUTINES_64=0x0000001aULL, LC_UUID=0x0000001bULL, LC_RPATH=0x8000001cULL, LC_CODE_SIGNATURE=0x0000001dULL, LC_SEGMENT_SPLIT_INFO=0x0000001eULL, LC_REEXPORT_DYLIB=0x8000001fULL, LC_LAZY_LOAD_DYLIB=0x00000020ULL, LC_ENCRYPTION_INFO=0x00000021ULL, LC_DYLD_INFO=0x00000022ULL, LC_DYLD_INFO_ONLY=0x80000022ULL, LC_LOAD_UPWARD_DYLIB=0x80000023ULL, LC_VERSION_MIN_MACOSX=0x00000024ULL, LC_VERSION_MIN_IPHONEOS=0x00000025ULL, LC_FUNCTION_STARTS=0x00000026ULL, LC_DYLD_ENVIRONMENT=0x00000027ULL, LC_MAIN=0x80000028ULL, LC_DATA_IN_CODE=0x00000029ULL, LC_SOURCE_VERSION=0x0000002aULL, LC_DYLIB_CODE_SIGN_DRS=0x0000002bULL, LC_ENCRYPTION_INFO_64=0x0000002cULL, LC_LINKER_OPTION=0x0000002dULL, LC_LINKER_OPTIMIZATION_HINT=0x0000002eULL, LC_VERSION_MIN_TVOS=0x0000002fULL, LC_VERSION_MIN_WATCHOS=0x00000030ULL, LC_NOTE=0x00000031ULL, LC_BUILD_VERSION=0x00000032ULL };",
		0);
	sdb_set(bin->kv, "mach0_header_filetype.cparse",
		"enum mach0_header_filetype"
		"{MH_OBJECT=1, MH_EXECUTE=2, MH_FVMLIB=3, MH_CORE=4, MH_PRELOAD=5, MH_DYLIB=6, MH_DYLINKER=7, MH_BUNDLE=8, MH_DYLIB_STUB=9, MH_DSYM=10, MH_KEXT_BUNDLE=11};",
		0);
	sdb_set(bin->kv, "mach0_header_flags.cparse",
		"enum mach0_header_flags"
		"{MH_NOUNDEFS=1, MH_INCRLINK=2,MH_DYLDLINK=4,MH_BINDATLOAD=8,MH_PREBOUND=0x10, MH_SPLIT_SEGS=0x20,MH_LAZY_INIT=0x40,MH_TWOLEVEL=0x80, MH_FORCE_FLAT=0x100,MH_NOMULTIDEFS=0x200,MH_NOFIXPREBINDING=0x400, MH_PREBINDABLE=0x800, MH_ALLMODSBOUND=0x1000, MH_SUBSECTIONS_VIA_SYMBOLS=0x2000, MH_CANONICAL=0x4000,MH_WEAK_DEFINES=0x8000, MH_BINDS_TO_WEAK=0x10000,MH_ALLOW_STACK_EXECUTION=0x20000, MH_ROOT_SAFE=0x40000,MH_SETUID_SAFE=0x80000, MH_NO_REEXPORTED_DYLIBS=0x100000,MH_PIE=0x200000, MH_DEAD_STRIPPABLE_DYLIB=0x400000, MH_HAS_TLV_DESCRIPTORS=0x800000, MH_NO_HEAP_EXECUTION=0x1000000};",
		0);
	sdb_set(bin->kv, "mach0_section_types.cparse",
		"enum mach0_section_types"
		"{S_REGULAR=0, S_ZEROFILL=1, S_CSTRING_LITERALS=2, S_4BYTE_LITERALS=3, S_8BYTE_LITERALS=4, S_LITERAL_POINTERS=5, S_NON_LAZY_SYMBOL_POINTERS=6, S_LAZY_SYMBOL_POINTERS=7, S_SYMBOL_STUBS=8, S_MOD_INIT_FUNC_POINTERS=9, S_MOD_TERM_FUNC_POINTERS=0xa, S_COALESCED=0xb, S_GB_ZEROFILL=0xc, S_INTERPOSING=0xd, S_16BYTE_LITERALS=0xe, S_DTRACE_DOF=0xf, S_LAZY_DYLIB_SYMBOL_POINTERS=0x10, S_THREAD_LOCAL_REGULAR=0x11, S_THREAD_LOCAL_ZEROFILL=0x12, S_THREAD_LOCAL_VARIABLES=0x13, S_THREAD_LOCAL_VARIABLE_POINTERS=0x14, S_THREAD_LOCAL_INIT_FUNCTION_POINTERS=0x15, S_INIT_FUNC_OFFSETS=0x16};",
		0);
	sdb_set(bin->kv, "mach0_section_attrs.cparse",
		"enum mach0_section_attrs"
		"{S_ATTR_PURE_INSTRUCTIONS=0x800000ULL, S_ATTR_NO_TOC=0x400000ULL, S_ATTR_STRIP_STATIC_SYMS=0x200000ULL, S_ATTR_NO_DEAD_STRIP=0x100000ULL, S_ATTR_LIVE_SUPPORT=0x080000ULL, S_ATTR_SELF_MODIFYING_CODE=0x040000ULL, S_ATTR_DEBUG=0x020000ULL, S_ATTR_SOME_INSTRUCTIONS=0x000004ULL, S_ATTR_EXT_RELOC=0x000002ULL, S_ATTR_LOC_RELOC=0x000001ULL};",
		0);
	sdb_set(bin->kv, "mach0_header.format",
		"xxx[4]Edd[4]B "
		"magic cputype cpusubtype (mach0_header_filetype)filetype ncmds sizeofcmds (mach0_header_flags)flags",
		0);
	sdb_set(bin->kv, "mach0_segment.format",
		"[4]Ed[16]zxxxxoodx "
		"(mach0_load_command_type)cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags",
		0);
	sdb_set(bin->kv, "mach0_segment64.format",
		"[4]Ed[16]zqqqqoodx "
		"(mach0_load_command_type)cmd cmdsize segname vmaddr vmsize fileoff filesize maxprot initprot nsects flags",
		0);
	sdb_set(bin->kv, "mach0_symtab_command.format",
		"[4]Edxdxd "
		"(mach0_load_command_type)cmd cmdsize symoff nsyms stroff strsize",
		0);
	sdb_set(bin->kv, "mach0_dysymtab_command.format",
		"[4]Edddddddddddxdxdxxxd "
		"(mach0_load_command_type)cmd cmdsize ilocalsym nlocalsym iextdefsym nextdefsym iundefsym nundefsym tocoff ntoc moddtaboff nmodtab extrefsymoff nextrefsyms inddirectsymoff nindirectsyms extreloff nextrel locreloff nlocrel",
		0);
	sdb_set(bin->kv, "mach0_section.format",
		"[16]z[16]zxxxxxx[1]E[3]Bxx "
		"sectname segname addr size offset align reloff nreloc (mach0_section_types)flags_type (mach0_section_attrs)flags_attr reserved1 reserved2",
		0);
	sdb_set(bin->kv, "mach0_section64.format",
		"[16]z[16]zqqxxxx[1]E[3]Bxxx "
		"sectname segname addr size offset align reloff nreloc (mach0_section_types)flags_type (mach0_section_attrs)flags_attr reserved1 reserved2 reserved3",
		0);
	sdb_set(bin->kv, "mach0_dylib.format",
		"xxxxz "
		"name_offset timestamp current_version compatibility_version name",
		0);
	sdb_set(bin->kv, "mach0_dylib_command.format",
		"[4]Ed? "
		"(mach0_load_command_type)cmd cmdsize (mach0_dylib)dylib",
		0);
	sdb_set(bin->kv, "mach0_id_dylib_command.format",
		"[4]Ed? "
		"(mach0_load_command_type)cmd cmdsize (mach0_dylib)dylib",
		0);
	sdb_set(bin->kv, "mach0_uuid_command.format",
		"[4]Ed[16]b "
		"(mach0_load_command_type)cmd cmdsize uuid",
		0);
	sdb_set(bin->kv, "mach0_rpath_command.format",
		"[4]Edxz "
		"(mach0_load_command_type)cmd cmdsize path_offset path",
		0);
	sdb_set(bin->kv, "mach0_entry_point_command.format",
		"[4]Edqq "
		"(mach0_load_command_type)cmd cmdsize entryoff stacksize",
		0);
	sdb_set(bin->kv, "mach0_encryption_info64_command.format",
		"[4]Edxddx "
		"(mach0_load_command_type)cmd cmdsize offset size id padding",
		0);
	sdb_set(bin->kv, "mach0_encryption_info_command.format",
		"[4]Edxdd "
		"(mach0_load_command_type)cmd cmdsize offset size id",
		0);
	sdb_set(bin->kv, "mach0_code_signature_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set(bin->kv, "mach0_dyld_info_only_command.format",
		"[4]Edxdxdxdxdxd "
		"(mach0_load_command_type)cmd cmdsize rebase_off rebase_size bind_off bind_size weak_bind_off weak_bind_size lazy_bind_off lazy_bind_size export_off export_size",
		0);
	sdb_set(bin->kv, "mach0_load_dylinker_command.format",
		"[4]Edxz "
		"(mach0_load_command_type)cmd cmdsize name_offset name",
		0);
	sdb_set(bin->kv, "mach0_id_dylinker_command.format",
		"[4]Edxzi "
		"(mach0_load_command_type)cmd cmdsize name_offset name",
		0);
	sdb_set(bin->kv, "mach0_build_version_command.format",
		"[4]Ed[4]Exxd "
		"(mach0_load_command_type)cmd cmdsize (mach0_build_platform)platform minos sdk ntools",
		0);
	sdb_set(bin->kv, "mach0_build_version_tool.format",
		"[4]Ex "
		"(mach0_build_tool)tool version",
		0);
	sdb_set(bin->kv, "mach0_source_version_command.format",
		"[4]Edq "
		"(mach0_load_command_type)cmd cmdsize version",
		0);
	sdb_set(bin->kv, "mach0_function_starts_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set(bin->kv, "mach0_data_in_code_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set(bin->kv, "mach0_version_min_command.format",
		"[4]Edxx "
		"(mach0_load_command_type)cmd cmdsize version reserved",
		0);
	sdb_set(bin->kv, "mach0_segment_split_info_command.format",
		"[4]Edxd "
		"(mach0_load_command_type)cmd cmdsize offset size",
		0);
	sdb_set(bin->kv, "mach0_unixthread_command.format",
		"[4]Eddd "
		"(mach0_load_command_type)cmd cmdsize flavor count",
		0);
}

static bool init_hdr(struct MACH0_(obj_t) * bin) {
	ut8 magicbytes[4] = { 0 };
	ut8 machohdrbytes[sizeof(struct MACH0_(mach_header))] = { 0 };
	int len;

	if (rz_buf_read_at(bin->b, 0 + bin->header_at, magicbytes, 4) < 1) {
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
	len = rz_buf_read_at(bin->b, 0 + bin->header_at, machohdrbytes, sizeof(machohdrbytes));
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
	sdb_num_set(bin->kv, "mach0_header.offset", 0, 0); // wat about fatmach0?
	return true;
}

static bool parse_segments(struct MACH0_(obj_t) * bin, ut64 off) {
	size_t i, j, k, sect, len;
	ut32 size_sects;
	ut8 segcom[sizeof(struct MACH0_(segment_command))] = { 0 };
	ut8 sec[sizeof(struct MACH0_(section))] = { 0 };

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
	sdb_num_set(bin->kv, sdb_fmt("mach0_segment64_%zu.offset", j), off, 0);
#else
	sdb_num_set(bin->kv, sdb_fmt("mach0_segment_%zu.offset", j), off, 0);
#endif

	sdb_num_set(bin->kv, "mach0_segments.count", 0, 0);

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

			sdb_num_set(bin->kv, sdb_fmt("mach0_section_%.16s_%.16s.offset", bin->sects[k].segname, bin->sects[k].sectname), offset, 0);
#if RZ_BIN_MACH064
			sdb_set(bin->kv, sdb_fmt("mach0_section_%.16s_%.16s.format", bin->sects[k].segname, bin->sects[k].sectname), "mach0_section64", 0);
#else
			sdb_set(bin->kv, sdb_fmt("mach0_section_%.16s_%.16s.format", bin->sects[k].segname, bin->sects[k].sectname), "mach0_section", 0);
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
	st.symoff = rz_read_ble32(symt + 8, be);
	st.nsyms = rz_read_ble32(symt + 12, be);
	st.stroff = rz_read_ble32(symt + 16, be);
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
			//XXX not very safe what if is n_un.n_name instead?
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

static void parseCodeDirectory(RzBuffer *b, int offset, int datasize) {
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

	int hashSize = 20; // SHA1 is default
	int algoType = RZ_HASH_SHA1;
	const char *hashName = "sha1";
	switch (cscd.hashType) {
	case 0: // SHA1 == 20 bytes
	case 1: // SHA1 == 20 bytes
		hashSize = 20;
		hashName = "sha1";
		algoType = RZ_HASH_SHA1;
		break;
	case 2: // SHA256 == 32 bytes
		hashSize = 32;
		algoType = RZ_HASH_SHA256;
		hashName = "sha256";
		break;
	}
	// computed cdhash
	RzHash *ctx = rz_hash_new(true, algoType);
	int fofsz = cscd.length;
	ut8 *fofbuf = calloc(fofsz, 1);
	if (fofbuf) {
		int i;
		if (rz_buf_read_at(b, off, fofbuf, fofsz) != fofsz) {
			eprintf("Invalid cdhash offset/length values\n");
		}
		rz_hash_do_begin(ctx, algoType);
		if (algoType == RZ_HASH_SHA1) {
			rz_hash_do_sha1(ctx, fofbuf, fofsz);
		} else {
			rz_hash_do_sha256(ctx, fofbuf, fofsz);
		}
		rz_hash_do_end(ctx, algoType);
		eprintf("ph %s @ 0x%" PFMT64x "!%d\n", hashName, off, fofsz);
		eprintf("ComputedCDHash: ");
		for (i = 0; i < hashSize; i++) {
			eprintf("%02x", ctx->digest[i]);
		}
		eprintf("\n");
		free(fofbuf);
	}
	// show and check the rest of hashes
	ut8 *hash = p + cscd.hashOffset;
	int j = 0;
	int k = 0;
	eprintf("Hashed region: 0x%08" PFMT64x " - 0x%08" PFMT64x "\n", (ut64)0, (ut64)cscd.codeLimit);
	for (j = 0; j < cscd.nCodeSlots; j++) {
		int fof = 4096 * j;
		int idx = j * hashSize;
		eprintf("0x%08" PFMT64x "  ", off + cscd.hashOffset + idx);
		for (k = 0; k < hashSize; k++) {
			eprintf("%02x", hash[idx + k]);
		}
		ut8 fofbuf[4096];
		int fofsz = RZ_MIN(sizeof(fofbuf), cscd.codeLimit - fof);
		rz_buf_read_at(b, fof, fofbuf, sizeof(fofbuf));
		rz_hash_do_begin(ctx, algoType);
		if (algoType == RZ_HASH_SHA1) {
			rz_hash_do_sha1(ctx, fofbuf, fofsz);
		} else {
			rz_hash_do_sha256(ctx, fofbuf, fofsz);
		}
		rz_hash_do_end(ctx, algoType);
		if (memcmp(hash + idx, ctx->digest, hashSize)) {
			eprintf("  wx ");
			int i;
			for (i = 0; i < hashSize; i++) {
				eprintf("%02x", ctx->digest[i]);
			}
		} else {
			eprintf("  OK");
		}
		eprintf("\n");
	}
	rz_hash_free(ctx);
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
	super.blob.magic = rz_buf_read_ble32_at(bin->b, data, mach0_endian);
	super.blob.length = rz_buf_read_ble32_at(bin->b, data + 4, mach0_endian);
	super.count = rz_buf_read_ble32_at(bin->b, data + 8, mach0_endian);
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
				entitlements.magic = rz_buf_read_ble32_at(bin->b, off, mach0_endian);
				entitlements.length = rz_buf_read_ble32_at(bin->b, off + 4, mach0_endian);
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
				parseCodeDirectory(bin->b, data + idx.offset, link.datasize);
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
					sdb_set(bin->kv, "mach0.ident", ident, 0);
					free(ident);
				}
			} else {
				if (bin->verbose) {
					eprintf("Invalid code slot size\n");
				}
			}
		} break;
		case CSSLOT_INFOSLOT: // 1;
		case CSSLOT_RESOURCEDIR: // 3;
		case CSSLOT_APPLICATION: // 4;
			// TODO: parse those codesign slots
			if (bin->verbose) {
				eprintf("TODO: Some codesign slots are not yet supported\n");
			}
			break;
		default:
			if (bin->verbose) {
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
	if (rz_buf_read_at(bin->b, off + sizeof(struct thread_command), tmp, 4) < 4) {
		goto wrong_read;
	}
	flavor = rz_read_ble32(tmp, bin->big_endian);
	if (len == -1) {
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
				bprintf("Error: read (thread state x86_32)\n");
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
				bprintf("Error: read (thread state x86_64)\n");
				return false;
			}
			pc = bin->thread_state.x86_64.rip;
			pc_offset = ptr_thread + rz_offsetof(struct x86_thread_state64, rip);
			arw_ptr = (ut8 *)&bin->thread_state.x86_64;
			arw_sz = sizeof(struct x86_thread_state64);
			break;
			//default: bprintf ("Unknown type\n");
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
				bprintf("Error: read (thread state ppc_32)\n");
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
				bprintf("Error: read (thread state ppc_64)\n");
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
			bprintf("Error: read (thread state arm)\n");
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
			    (ut8 *)&bin->thread_state.arm_64, bin->big_endian ? "34LI1I" : "34Li1i", 1) == -1) {
			bprintf("Error: read (thread state arm)\n");
			return false;
		}
		pc = rz_read_be64(&bin->thread_state.arm_64.pc);
		pc_offset = ptr_thread + rz_offsetof(struct arm_thread_state64, pc);
		arw_ptr = (ut8 *)&bin->thread_state.arm_64;
		arw_sz = sizeof(struct arm_thread_state64);
		break;
	default:
		bprintf("Error: read (unknown thread state structure)\n");
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
			sdb_num_set(bin->kv, "mach0.entry.offset", pc_offset, 0);
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

static const char *build_version_platform_to_string(ut32 platform) {
	switch (platform) {
	case 1:
		return "macOS";
	case 2:
		return "iOS";
	case 3:
		return "tvOS";
	case 4:
		return "watchOS";
	case 5:
		return "bridgeOS";
	case 6:
		return "iOSmac";
	case 7:
		return "iOS Simulator";
	case 8:
		return "tvOS Simulator";
	case 9:
		return "watchOS Simulator";
	default:
		return "unknown";
	}
}

static const char *build_version_tool_to_string(ut32 tool) {
	switch (tool) {
	case 1:
		return "clang";
	case 2:
		return "swift";
	case 3:
		return "ld";
	default:
		return "unknown";
	}
}

static size_t get_word_size(struct MACH0_(obj_t) * bin) {
	const size_t word_size = MACH0_(get_bits)(bin) / 8;
	return RZ_MAX(word_size, 4);
}

static bool parse_chained_fixups(struct MACH0_(obj_t) * bin, ut32 offset, ut32 size) {
	struct dyld_chained_fixups_header header;
	if (size < sizeof(header)) {
		return false;
	}
	if (rz_buf_fread_at(bin->b, offset, (ut8 *)&header, "7i", 1) != sizeof(header)) {
		return false;
	}
	if (header.fixups_version > 0) {
		eprintf("Unsupported fixups version: %u\n", header.fixups_version);
		return false;
	}
	ut64 starts_at = offset + header.starts_offset;
	if (header.starts_offset > size) {
		return false;
	}
	ut32 segs_count;
	if ((segs_count = rz_buf_read_le32_at(bin->b, starts_at)) == UT32_MAX) {
		return false;
	}
	bin->chained_starts = RZ_NEWS0(struct rz_dyld_chained_starts_in_segment *, segs_count);
	if (!bin->chained_starts) {
		return false;
	}
	size_t i;
	ut64 cursor = starts_at + sizeof(ut32);
	for (i = 0; i < segs_count; i++) {
		ut32 seg_off;
		if ((seg_off = rz_buf_read_le32_at(bin->b, cursor)) == UT32_MAX || !seg_off) {
			cursor += sizeof(ut32);
			continue;
		}
		if (i >= bin->nsegs) {
			break;
		}
		struct rz_dyld_chained_starts_in_segment *cur_seg = RZ_NEW0(struct rz_dyld_chained_starts_in_segment);
		if (!cur_seg) {
			return false;
		}
		bin->chained_starts[i] = cur_seg;
		if (rz_buf_fread_at(bin->b, starts_at + seg_off, (ut8 *)cur_seg, "isslis", 1) != 22) {
			return false;
		}
		if (cur_seg->page_count > 0) {
			ut16 *page_start = malloc(sizeof(ut16) * cur_seg->page_count);
			if (!page_start) {
				return false;
			}
			if (rz_buf_fread_at(bin->b, starts_at + seg_off + 22, (ut8 *)page_start, "s", cur_seg->page_count) != cur_seg->page_count * 2) {
				return false;
			}
			cur_seg->page_start = page_start;
		}
		cursor += sizeof(ut32);
	}
	/* TODO: handle also imports, symbols and multiple starts (32-bit only) */
	return true;
}

static bool reconstruct_chained_fixup(struct MACH0_(obj_t) * bin) {
	if (!bin->dyld_info) {
		return false;
	}
	if (!bin->nsegs) {
		return false;
	}
	bin->chained_starts = RZ_NEWS0(struct rz_dyld_chained_starts_in_segment *, bin->nsegs);
	if (!bin->chained_starts) {
		return false;
	}
	size_t wordsize = get_word_size(bin);
	ut8 *p = NULL;
	size_t j, count, skip, bind_size;
	int seg_idx = 0;
	ut64 seg_off = 0;
	bind_size = bin->dyld_info->bind_size;
	if (!bind_size || bind_size < 1) {
		return false;
	}
	if (bin->dyld_info->bind_off > bin->size) {
		return false;
	}
	if (bin->dyld_info->bind_off + bind_size > bin->size) {
		return false;
	}
	ut8 *opcodes = calloc(1, bind_size + 1);
	if (!opcodes) {
		return false;
	}
	if (rz_buf_read_at(bin->b, bin->dyld_info->bind_off, opcodes, bind_size) != bind_size) {
		bprintf("Error: read (dyld_info bind) at 0x%08" PFMT64x "\n", (ut64)(size_t)bin->dyld_info->bind_off);
		RZ_FREE(opcodes);
		return false;
	}
	struct rz_dyld_chained_starts_in_segment *cur_seg = NULL;
	size_t cur_seg_idx = 0;
	ut8 *end;
	bool done = false;
	for (p = opcodes, end = opcodes + bind_size; !done && p < end;) {
		ut8 imm = *p & BIND_IMMEDIATE_MASK, op = *p & BIND_OPCODE_MASK;
		p++;
		switch (op) {
		case BIND_OPCODE_DONE:
			done = true;
			break;
		case BIND_OPCODE_THREADED: {
			switch (imm) {
			case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: {
				read_uleb128(&p, end);
				break;
			}
			case BIND_SUBOPCODE_THREADED_APPLY: {
				const size_t ps = 0x1000;
				if (!cur_seg || cur_seg_idx != seg_idx) {
					cur_seg_idx = seg_idx;
					cur_seg = bin->chained_starts[seg_idx];
					if (!cur_seg) {
						cur_seg = RZ_NEW0(struct rz_dyld_chained_starts_in_segment);
						if (!cur_seg) {
							break;
						}
						bin->chained_starts[seg_idx] = cur_seg;
						cur_seg->pointer_format = DYLD_CHAINED_PTR_ARM64E;
						cur_seg->page_size = ps;
						cur_seg->page_count = ((bin->segs[seg_idx].vmsize + (ps - 1)) & ~(ps - 1)) / ps;
						if (cur_seg->page_count > 0) {
							cur_seg->page_start = malloc(sizeof(ut16) * cur_seg->page_count);
							if (!cur_seg->page_start) {
								break;
							}
							memset(cur_seg->page_start, 0xff, sizeof(ut16) * cur_seg->page_count);
						}
					}
				}
				if (cur_seg) {
					ut32 page_index = (ut32)(seg_off / ps);
					size_t maxsize = cur_seg->page_count * sizeof(ut16);
					if (page_index < maxsize) {
						cur_seg->page_start[page_index] = seg_off & 0xfff;
					}
				}
				break;
			}
			default:
				bprintf("Error: Unexpected BIND_OPCODE_THREADED sub-opcode: 0x%x\n", imm);
			}
			break;
		}
		case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
		case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
		case BIND_OPCODE_SET_TYPE_IMM:
			break;
		case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
			read_uleb128(&p, end);
			break;
		case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
			while (*p++ && p < end) {
				/* empty loop */
			}
			break;
		case BIND_OPCODE_SET_ADDEND_SLEB:
			rz_sleb128((const ut8 **)&p, end);
			break;
		case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
			seg_idx = imm;
			if (seg_idx >= bin->nsegs) {
				bprintf("Error: BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB"
					" has unexistent segment %d\n",
					seg_idx);
				RZ_FREE(opcodes);
				return false;
			} else {
				seg_off = read_uleb128(&p, end);
			}
			break;
		case BIND_OPCODE_ADD_ADDR_ULEB:
			seg_off += read_uleb128(&p, end);
			break;
		case BIND_OPCODE_DO_BIND:
			break;
		case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
			seg_off += read_uleb128(&p, end) + wordsize;
			break;
		case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
			seg_off += (ut64)imm * (ut64)wordsize + wordsize;
			break;
		case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
			count = read_uleb128(&p, end);
			skip = read_uleb128(&p, end);
			for (j = 0; j < count; j++) {
				seg_off += skip + wordsize;
			}
			break;
		default:
			bprintf("Error: unknown bind opcode 0x%02x in dyld_info\n", *p);
			RZ_FREE(opcodes);
			return false;
		}
	}
	RZ_FREE(opcodes);

	return true;
}

static int init_items(struct MACH0_(obj_t) * bin) {
	struct load_command lc = { 0, 0 };
	ut8 loadc[sizeof(struct load_command)] = { 0 };
	bool is_first_thread = true;
	ut64 off = 0LL;
	int i, len;

	bin->uuidn = 0;
	bin->os = 0;
	bin->has_crypto = 0;
	if (bin->hdr.sizeofcmds > bin->size) {
		bprintf("Warning: chopping hdr.sizeofcmds\n");
		bin->hdr.sizeofcmds = bin->size - 128;
		//return false;
	}
	//bprintf ("Commands: %d\n", bin->hdr.ncmds);
	for (i = 0, off = sizeof(struct MACH0_(mach_header)) + bin->header_at;
		i < bin->hdr.ncmds; i++, off += lc.cmdsize) {
		if (off > bin->size || off + sizeof(struct load_command) > bin->size) {
			bprintf("mach0: out of bounds command\n");
			return false;
		}
		len = rz_buf_read_at(bin->b, off, loadc, sizeof(struct load_command));
		if (len < 1) {
			bprintf("Error: read (lc) at 0x%08" PFMT64x "\n", off);
			return false;
		}
		lc.cmd = rz_read_ble32(&loadc[0], bin->big_endian);
		lc.cmdsize = rz_read_ble32(&loadc[4], bin->big_endian);

		if (lc.cmdsize < 1 || off + lc.cmdsize > bin->size) {
			bprintf("Warning: mach0_header %d = cmdsize<1. (0x%llx vs 0x%llx)\n", i,
				(ut64)(off + lc.cmdsize), (ut64)(bin->size));
			break;
		}

		sdb_num_set(bin->kv, sdb_fmt("mach0_cmd_%d.offset", i), off, 0);
		const char *format_name = cmd_to_pf_definition(lc.cmd);
		if (format_name) {
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.format", i), format_name, 0);
		} else {
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.format", i), "[4]Ed (mach_load_command_type)cmd size", 0);
		}

		switch (lc.cmd) {
		case LC_DATA_IN_CODE:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "data_in_code", 0);
			break;
		case LC_RPATH:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "rpath", 0);
			//bprintf ("--->\n");
			break;
		case LC_SEGMENT_64:
		case LC_SEGMENT:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "segment", 0);
			bin->nsegs++;
			if (!parse_segments(bin, off)) {
				bprintf("error parsing segment\n");
				bin->nsegs--;
				return false;
			}
			break;
		case LC_SYMTAB:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "symtab", 0);
			if (!parse_symtab(bin, off)) {
				bprintf("error parsing symtab\n");
				return false;
			}
			break;
		case LC_DYSYMTAB:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "dysymtab", 0);
			if (!parse_dysymtab(bin, off)) {
				bprintf("error parsing dysymtab\n");
				return false;
			}
			break;
		case LC_DYLIB_CODE_SIGN_DRS:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "dylib_code_sign_drs", 0);
			//bprintf ("[mach0] code is signed\n");
			break;
		case LC_VERSION_MIN_MACOSX:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "version_min_macosx", 0);
			bin->os = 1;
			// set OS = osx
			//bprintf ("[mach0] Requires OSX >= x\n");
			break;
		case LC_VERSION_MIN_IPHONEOS:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "version_min_iphoneos", 0);
			bin->os = 2;
			// set OS = ios
			//bprintf ("[mach0] Requires iOS >= x\n");
			break;
		case LC_VERSION_MIN_TVOS:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "version_min_tvos", 0);
			bin->os = 4;
			break;
		case LC_VERSION_MIN_WATCHOS:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "version_min_watchos", 0);
			bin->os = 3;
			break;
		case LC_UUID:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "uuid", 0);
			{
				struct uuid_command uc = { 0 };
				if (off + sizeof(struct uuid_command) > bin->size) {
					bprintf("UUID out of bounds\n");
					return false;
				}
				if (rz_buf_fread_at(bin->b, off, (ut8 *)&uc, "24c", 1) != -1) {
					char key[128];
					char val[128];
					snprintf(key, sizeof(key) - 1, "uuid.%d", bin->uuidn++);
					rz_hex_bin2str((ut8 *)&uc.uuid, 16, val);
					sdb_set(bin->kv, key, val, 0);
					//for (i=0;i<16; i++) bprintf ("%02x%c", uc.uuid[i], (i==15)?'\n':'-');
				}
			}
			break;
		case LC_ENCRYPTION_INFO_64:
			/* TODO: the struct is probably different here */
		case LC_ENCRYPTION_INFO:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "encryption_info", 0);
			{
				struct MACH0_(encryption_info_command) eic = { 0 };
				ut8 seic[sizeof(struct MACH0_(encryption_info_command))] = { 0 };
				if (off + sizeof(struct MACH0_(encryption_info_command)) > bin->size) {
					bprintf("encryption info out of bounds\n");
					return false;
				}
				if (rz_buf_read_at(bin->b, off, seic, sizeof(struct MACH0_(encryption_info_command))) != -1) {
					eic.cmd = rz_read_ble32(&seic[0], bin->big_endian);
					eic.cmdsize = rz_read_ble32(&seic[4], bin->big_endian);
					eic.cryptoff = rz_read_ble32(&seic[8], bin->big_endian);
					eic.cryptsize = rz_read_ble32(&seic[12], bin->big_endian);
					eic.cryptid = rz_read_ble32(&seic[16], bin->big_endian);

					bin->has_crypto = eic.cryptid;
					sdb_set(bin->kv, "crypto", "true", 0);
					sdb_num_set(bin->kv, "cryptid", eic.cryptid, 0);
					sdb_num_set(bin->kv, "cryptoff", eic.cryptoff, 0);
					sdb_num_set(bin->kv, "cryptsize", eic.cryptsize, 0);
					sdb_num_set(bin->kv, "cryptheader", off, 0);
				}
			}
			break;
		case LC_LOAD_DYLINKER: {
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "dylinker", 0);
			RZ_FREE(bin->intrp);
			//bprintf ("[mach0] load dynamic linker\n");
			struct dylinker_command dy = { 0 };
			ut8 sdy[sizeof(struct dylinker_command)] = { 0 };
			if (off + sizeof(struct dylinker_command) > bin->size) {
				bprintf("Warning: Cannot parse dylinker command\n");
				return false;
			}
			if (rz_buf_read_at(bin->b, off, sdy, sizeof(struct dylinker_command)) == -1) {
				bprintf("Warning: read (LC_DYLD_INFO) at 0x%08" PFMT64x "\n", off);
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
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "main", 0);

			if (!is_first_thread) {
				bprintf("Error: LC_MAIN with other threads\n");
				return false;
			}
			if (off + 8 > bin->size || off + sizeof(ep) > bin->size) {
				bprintf("invalid command size for main\n");
				return false;
			}
			rz_buf_read_at(bin->b, off + 8, sep, 2 * sizeof(ut64));
			ep.eo = rz_read_ble64(&sep[0], bin->big_endian);
			ep.ss = rz_read_ble64(&sep[8], bin->big_endian);

			bin->entry = ep.eo;
			bin->main_cmd = lc;

			sdb_num_set(bin->kv, "mach0.entry.offset", off + 8, 0);
			sdb_num_set(bin->kv, "stacksize", ep.ss, 0);

			is_first_thread = false;
		} break;
		case LC_UNIXTHREAD:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "unixthread", 0);
			if (!is_first_thread) {
				bprintf("Error: LC_UNIXTHREAD with other threads\n");
				return false;
			}
		case LC_THREAD:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "thread", 0);
			if (!parse_thread(bin, &lc, off, is_first_thread)) {
				bprintf("Cannot parse thread\n");
				return false;
			}
			is_first_thread = false;
			break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "load_dylib", 0);
			bin->nlibs++;
			if (!parse_dylib(bin, off)) {
				bprintf("Cannot parse dylib\n");
				bin->nlibs--;
				return false;
			}
			break;
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY: {
			ut8 dyldi[sizeof(struct dyld_info_command)] = { 0 };
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "dyld_info", 0);
			bin->dyld_info = calloc(1, sizeof(struct dyld_info_command));
			if (bin->dyld_info) {
				if (off + sizeof(struct dyld_info_command) > bin->size) {
					bprintf("Cannot parse dyldinfo\n");
					RZ_FREE(bin->dyld_info);
					return false;
				}
				if (rz_buf_read_at(bin->b, off, dyldi, sizeof(struct dyld_info_command)) == -1) {
					RZ_FREE(bin->dyld_info);
					bprintf("Error: read (LC_DYLD_INFO) at 0x%08" PFMT64x "\n", off);
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
					bin->dyld_info->export_off = rz_read_ble32(&dyldi[40], bin->big_endian);
					bin->dyld_info->export_size = rz_read_ble32(&dyldi[44], bin->big_endian);
				}
			}
		} break;
		case LC_CODE_SIGNATURE:
			parse_signature(bin, off);
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "signature", 0);
			/* ut32 dataoff
			// ut32 datasize */
			break;
		case LC_SOURCE_VERSION:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "version", 0);
			/* uint64_t  version;  */
			/* A.B.C.D.E packed as a24.b10.c10.d10.e10 */
			//bprintf ("mach0: TODO: Show source version\n");
			break;
		case LC_SEGMENT_SPLIT_INFO:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "split_info", 0);
			/* TODO */
			break;
		case LC_FUNCTION_STARTS:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "function_starts", 0);
			if (!parse_function_starts(bin, off)) {
				bprintf("Cannot parse LC_FUNCTION_STARTS\n");
			}
			break;
		case LC_REEXPORT_DYLIB:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "dylib", 0);
			/* TODO */
			break;
		default:
			//bprintf ("mach0: Unknown header command %x\n", lc.cmd);
			break;
		}
	}
	bool has_chained_fixups = false;
	for (i = 0, off = sizeof(struct MACH0_(mach_header)) + bin->header_at;
		i < bin->hdr.ncmds; i++, off += lc.cmdsize) {
		len = rz_buf_read_at(bin->b, off, loadc, sizeof(struct load_command));
		if (len < 1) {
			bprintf("Error: read (lc) at 0x%08" PFMT64x "\n", off);
			return false;
		}
		lc.cmd = rz_read_ble32(&loadc[0], bin->big_endian);
		lc.cmdsize = rz_read_ble32(&loadc[4], bin->big_endian);

		if (lc.cmdsize < 1 || off + lc.cmdsize > bin->size) {
			bprintf("Warning: mach0_header %d = cmdsize<1. (0x%llx vs 0x%llx)\n", i,
				(ut64)(off + lc.cmdsize), (ut64)(bin->size));
			break;
		}

		sdb_num_set(bin->kv, sdb_fmt("mach0_cmd_%d.offset", i), off, 0);
		const char *format_name = cmd_to_pf_definition(lc.cmd);
		if (format_name) {
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.format", i), format_name, 0);
		} else {
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.format", i), "[4]Ed (mach_load_command_type)cmd size", 0);
		}

		switch (lc.cmd) {
		case LC_DATA_IN_CODE:
			sdb_set(bin->kv, sdb_fmt("mach0_cmd_%d.cmd", i), "data_in_code", 0);
			if (bin->verbose) {
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
						ut64 va = offset_to_vaddr(bin, dw);
						//	eprintf ("# 0x%d -> 0x%x\n", dw, va);
						//	eprintf ("0x%x kind %d len %d\n", dw, kind, len);
						eprintf("Cd 4 %d @ 0x%" PFMT64x "\n", len / 4, va);
					}
				}
			}
			break;
		case LC_DYLD_EXPORTS_TRIE:
			if (bin->verbose) {
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
				if (bin->verbose) {
					eprintf("chained fixups at 0x%x size %d\n", dataoff, datasize);
				}
				has_chained_fixups = parse_chained_fixups(bin, dataoff, datasize);
			}
		} break;
		}
	}

	if (!has_chained_fixups && bin->hdr.cputype == CPU_TYPE_ARM64 &&
		(bin->hdr.cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
		if (bin->verbose) {
			eprintf("reconstructing chained fixups\n");
		}
		reconstruct_chained_fixup(bin);
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
	free(mo->imports_by_ord);
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
	if (mo->chained_starts) {
		for (i = 0; i < mo->nsegs; i++) {
			if (mo->chained_starts[i]) {
				free(mo->chained_starts[i]->page_start);
				free(mo->chained_starts[i]);
			}
		}
		free(mo->chained_starts);
	}
	rz_buf_free(mo->b);
	free(mo);
	return NULL;
}

void MACH0_(opts_set_default)(struct MACH0_(opts_t) * options, RzBinFile *bf) {
	rz_return_if_fail(options && bf && bf->rbin);
	options->header_at = 0;
	options->verbose = bf->rbin->verbose;
}

static void *duplicate_ptr(void *p) {
	return p;
}

static void free_only_key(HtPPKv *kv) {
	free(kv->key);
}

static size_t ptr_size(void *c) {
	// :D
	return 8;
}

// XXX should be deprecated its never called
struct MACH0_(obj_t) * MACH0_(mach0_new)(const char *file, struct MACH0_(opts_t) * options) {
	struct MACH0_(obj_t) *bin = RZ_NEW0(struct MACH0_(obj_t));
	if (!bin) {
		return NULL;
	}
	if (options) {
		bin->verbose = options->verbose;
		bin->header_at = options->header_at;
	}
	bin->file = file;
	size_t binsz;
	ut8 *buf = (ut8 *)rz_file_slurp(file, &binsz);
	bin->size = binsz;
	if (!buf) {
		return MACH0_(mach0_free)(bin);
	}
	bin->b = rz_buf_new();
	if (!rz_buf_set_bytes(bin->b, buf, bin->size)) {
		free(buf);
		return MACH0_(mach0_free)(bin);
	}
	free(buf);
	bin->dyld_info = NULL;
	if (!init(bin)) {
		return MACH0_(mach0_free)(bin);
	}
	bin->imports_by_ord_size = 0;
	bin->imports_by_ord = NULL;
	bin->imports_by_name = ht_pp_new((HtPPDupValue)duplicate_ptr, free_only_key, (HtPPCalcSizeV)ptr_size);
	return bin;
}

struct MACH0_(obj_t) * MACH0_(new_buf)(RzBuffer *buf, struct MACH0_(opts_t) * options) {
	rz_return_val_if_fail(buf, NULL);
	struct MACH0_(obj_t) *bin = RZ_NEW0(struct MACH0_(obj_t));
	if (bin) {
		bin->b = rz_buf_ref(buf);
		bin->main_addr = UT64_MAX;
		bin->kv = sdb_new(NULL, "bin.mach0", 0);
		bin->size = rz_buf_size(bin->b);
		if (options) {
			bin->verbose = options->verbose;
			bin->header_at = options->header_at;
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

RzList *MACH0_(get_segments)(RzBinFile *bf) {
	struct MACH0_(obj_t) *bin = bf->o->bin_obj;
	RzList *list = rz_list_newf((RzListFree)rz_bin_section_free);
	size_t i, j;

	/* for core files */
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
			//TODO s->flags = seg->flags;
			s->name = rz_str_ndup(seg->segname, 16);
			s->is_segment = true;
			rz_str_filter(s->name, -1);
			s->perm = prot2perm(seg->initprot);
			s->add = true;
			rz_list_append(list, s);
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
			s->is_segment = false;
			s->size = (bin->sects[i].flags == S_ZEROFILL) ? 0 : (ut64)bin->sects[i].size;
			// XXX flags
			s->paddr = (ut64)bin->sects[i].offset;
			int segment_index = 0;
			//s->perm =prot2perm (bin->segs[j].initprot);
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
			rz_list_append(list, s);
			free(segment_name);
			free(section_name);
		}
	}
	return list;
}

// XXX this function is called so many times
struct section_t *MACH0_(get_sections)(struct MACH0_(obj_t) * bin) {
	rz_return_val_if_fail(bin, NULL);
	struct section_t *sections;
	char sectname[64], raw_segname[17];
	size_t i, j, to;

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
			rz_str_ncpy(sectname, seg->segname, 16);
			sectname[16] = 0;
			rz_str_filter(sectname, -1);
			// hack to support multiple sections with same name
			sections[i].perm = prot2perm(seg->initprot);
			sections[i].last = 0;
		}
		sections[i].last = 1;
		return sections;
	}

	if (!bin->sects) {
		return NULL;
	}
	to = RZ_MIN(bin->nsects, 128); // limit number of sections here to avoid fuzzed bins
	if (to < 1) {
		return NULL;
	}
	if (!(sections = calloc(bin->nsects + 1, sizeof(struct section_t)))) {
		return NULL;
	}
	for (i = 0; i < to; i++) {
		sections[i].offset = (ut64)bin->sects[i].offset;
		sections[i].addr = (ut64)bin->sects[i].addr;
		sections[i].size = (bin->sects[i].flags == S_ZEROFILL) ? 0 : (ut64)bin->sects[i].size;
		sections[i].vsize = (ut64)bin->sects[i].size;
		sections[i].align = bin->sects[i].align;
		sections[i].flags = bin->sects[i].flags;
		rz_str_ncpy(sectname, bin->sects[i].sectname, 17);
		rz_str_filter(sectname, -1);
		rz_str_ncpy(raw_segname, bin->sects[i].segname, 16);
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

static int inSymtab(HtPP *hash, const char *name, ut64 addr) {
	bool found = false;
	char *key = rz_str_newf("%" PFMT64x ".%s", addr, name);
	ht_pp_find(hash, key, &found);
	if (found) {
		free(key);
		return true;
	}
	ht_pp_insert(hash, key, "1");
	return false;
}

static char *get_name(struct MACH0_(obj_t) * mo, ut32 stridx, bool filter) {
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
			rz_str_filter(res, -1);
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
	if (!size) {
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
		RTrieState *state = rz_list_get_top(states);
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
				resolver = res + bin->header_at;
			} else if (isReexport) {
				p += strlen((char *)p) + 1;
				// TODO: handle this
			}
			if (!isReexport) {
				offset += bin->header_at;
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
				if (name == NULL) {
					eprintf("malformed export trie\n");
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
			eprintf("malformed export trie\n");
			RZ_FREE(next);
			goto beach;
		}
		ut64 tr = read_uleb128(&p, end);
		if (tr == UT64_MAX) {
			RZ_FREE(next);
			goto beach;
		}
		next->node = tr + trie;
		if (next->node >= end) {
			eprintf("malformed export trie\n");
			RZ_FREE(next);
			goto beach;
		}
		{
			// avoid loops
			RzListIter *it;
			RTrieState *s;
			rz_list_foreach (states, it, s) {
				if (s->node == next->node) {
					eprintf("malformed export trie\n");
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

static void fill_exports_list(struct MACH0_(obj_t) * bin, const char *name, ut64 flags, ut64 offset, void *ctx) {
	RzList *list = (RzList *)ctx;
	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (!sym) {
		return;
	}
	sym->vaddr = offset_to_vaddr(bin, offset);
	sym->paddr = offset;
	sym->type = "EXT";
	sym->name = strdup(name);
	sym->bind = RZ_BIN_BIND_GLOBAL_STR;
	rz_list_append(list, sym);
}

// TODO: Return RzList<RzBinSymbol> // 2x speedup
const RzList *MACH0_(get_symbols_list)(struct MACH0_(obj_t) * bin) {
	static RzList *cache = NULL; // XXX DONT COMMIT WITH THIS
	struct symbol_t *symbols;
	size_t j, s, symbols_size, symbols_count;
	ut32 to, from;
	size_t i;

	rz_return_val_if_fail(bin, NULL);
	if (cache) {
		return cache;
	}
	RzList *list = rz_list_newf((RzListFree)rz_bin_symbol_free);
	cache = list;

	HtPP *hash = ht_pp_new0();
	if (!hash) {
		return NULL;
	}

	walk_exports(bin, fill_exports_list, list);
	if (rz_list_length(list)) {
		RzListIter *it;
		RzBinSymbol *s;
		rz_list_foreach (list, it, s) {
			inSymtab(hash, s->name, s->vaddr);
		}
	}

	if (!bin->symtab || !bin->symstr) {
		return list;
	}
	/* parse dynamic symbol table */
	symbols_count = (bin->dysymtab.nextdefsym +
		bin->dysymtab.nlocalsym +
		bin->dysymtab.nundefsym);
	symbols_count += bin->nsymtab;
	symbols_size = (symbols_count + 1) * 2 * sizeof(struct symbol_t);

	if (symbols_size < 1) {
		return NULL;
	}
	if (!(symbols = calloc(1, symbols_size))) {
		return NULL;
	}
	j = 0; // symbol_idx
	bin->main_addr = 0;
	int bits = MACH0_(get_bits_from_hdr)(&bin->hdr);
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

		from = RZ_MIN(RZ_MAX(0, from), symbols_size / sizeof(struct symbol_t));
		to = RZ_MIN(RZ_MIN(to, bin->nsymtab), symbols_size / sizeof(struct symbol_t));

		ut32 maxsymbols = symbols_size / sizeof(struct symbol_t);
		if (symbols_count >= maxsymbols) {
			symbols_count = maxsymbols - 1;
			eprintf("macho warning: Symbol table truncated\n");
		}
		for (i = from; i < to && j < symbols_count; i++, j++) {
			RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
			sym->vaddr = bin->symtab[i].n_value;
			sym->paddr = addr_to_offset(bin, sym->vaddr);
			symbols[j].size = 0; /* TODO: Is it anywhere? */
			sym->bits = bin->symtab[i].n_desc & N_ARM_THUMB_DEF ? 16 : bits;

			if (bin->symtab[i].n_type & N_EXT) {
				sym->type = "EXT";
			} else {
				sym->type = "LOCAL";
			}
			int stridx = bin->symtab[i].n_strx;
			char *sym_name = get_name(bin, stridx, false);
			if (sym_name) {
				sym->name = sym_name;
				if (!bin->main_addr || bin->main_addr == UT64_MAX) {
					const char *name = sym->name;
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
			} else {
				sym->name = rz_str_newf("unk%zu", i);
			}
			if (!inSymtab(hash, sym->name, sym->vaddr)) {
				rz_list_append(list, sym);
			} else {
				rz_bin_symbol_free(sym);
			}
		}
	}
	to = RZ_MIN((ut32)bin->nsymtab, bin->dysymtab.iundefsym + bin->dysymtab.nundefsym);
	for (i = bin->dysymtab.iundefsym; i < to; i++) {
		struct symbol_t symbol;
		if (j > symbols_count) {
			bprintf("mach0-get-symbols: error\n");
			break;
		}
		if (parse_import_stub(bin, &symbol, i)) {
			j++;
			RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
			sym->vaddr = symbol.addr;
			sym->paddr = symbol.offset;
			sym->name = symbol.name;
			if (!sym->name) {
				sym->name = rz_str_newf("unk%zu", i);
			}
			sym->is_imported = symbol.is_imported;
			rz_list_append(list, sym);
		}
	}

	for (i = 0; i < bin->nsymtab; i++) {
		struct MACH0_(nlist) *st = &bin->symtab[i];
		// 0 is for imports
		// 1 is for symbols
		// 2 is for func.eh (exception handlers?)
		int section = st->n_sect;
		if (section == 1 && j < symbols_count) { // text ??st->n_type == 1) maybe wrong
			RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
			/* is symbol */
			sym->vaddr = st->n_value;
			sym->paddr = addr_to_offset(bin, symbols[j].addr);
			sym->is_imported = symbols[j].is_imported;
			if (st->n_type & N_EXT) {
				sym->type = "EXT";
			} else {
				sym->type = "LOCAL";
			}
			char *sym_name = get_name(bin, st->n_strx, false);
			if (sym_name) {
				sym->name = sym_name;
				if (inSymtab(hash, sym->name, sym->vaddr)) {
					rz_bin_symbol_free(sym);
					continue;
				}
				if (!bin->main_addr || bin->main_addr == UT64_MAX) {
					const char *name = sym->name;
					if (!strcmp(name, "__Dmain")) {
						bin->main_addr = symbols[i].addr;
					} else if (strstr(name, "4main") && !strstr(name, "STATIC")) {
						bin->main_addr = symbols[i].addr;
					} else if (!strcmp(symbols[i].name, "_main")) {
						bin->main_addr = symbols[i].addr;
					}
				}
			} else {
				sym->name = rz_str_newf("unk%zu", i);
			}
			rz_list_append(list, sym);
			j++;
		}
	}
	ht_pp_free(hash);
	free(symbols);
	return list;
}

static void assign_export_symbol_t(struct MACH0_(obj_t) * bin, const char *name, ut64 flags, ut64 offset, void *ctx) {
	RSymCtx *sym_ctx = (RSymCtx *)ctx;
	int j = sym_ctx->j;
	if (j < sym_ctx->symbols_count) {
		sym_ctx->symbols[j].offset = offset;
		sym_ctx->symbols[j].addr = offset_to_vaddr(bin, offset);
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
	int j, s, stridx, symbols_size, symbols_count;
	ut32 to, from, i;

	if (bin->symbols) {
		return bin->symbols;
	}

	HtPP *hash = ht_pp_new0();
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
		symbols_count += bin->nsymtab;
		if (symbols_count < 0 || ((st64)symbols_count * 2) > ST32_MAX) {
			eprintf("Symbols count overflow\n");
			ht_pp_free(hash);
			return NULL;
		}
		symbols_size = (symbols_count + 1) * 2 * sizeof(struct symbol_t);

		if (symbols_size < 1) {
			ht_pp_free(hash);
			return NULL;
		}
		if (!(symbols = calloc(1, symbols_size))) {
			ht_pp_free(hash);
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

			from = RZ_MIN(RZ_MAX(0, from), symbols_size / sizeof(struct symbol_t));
			to = RZ_MIN(RZ_MIN(to, bin->nsymtab), symbols_size / sizeof(struct symbol_t));

			ut32 maxsymbols = symbols_size / sizeof(struct symbol_t);
			if (symbols_count >= maxsymbols) {
				symbols_count = maxsymbols - 1;
				eprintf("macho warning: Symbol table truncated\n");
			}
			for (i = from; i < to && j < symbols_count; i++, j++) {
				symbols[j].offset = addr_to_offset(bin, bin->symtab[i].n_value);
				symbols[j].addr = bin->symtab[i].n_value;
				symbols[j].size = 0; /* TODO: Is it anywhere? */
				symbols[j].bits = bin->symtab[i].n_desc & N_ARM_THUMB_DEF ? 16 : bits;
				symbols[j].is_imported = false;
				symbols[j].type = (bin->symtab[i].n_type & N_EXT)
					? RZ_BIN_MACH0_SYMBOL_TYPE_EXT
					: RZ_BIN_MACH0_SYMBOL_TYPE_LOCAL;
				stridx = bin->symtab[i].n_strx;
				symbols[j].name = get_name(bin, stridx, false);
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

		for (i = 0; i < bin->nsymtab; i++) {
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
				symbols[j].offset = addr_to_offset(bin, symbols[j].addr);
				symbols[j].size = 0; /* find next symbol and crop */
				symbols[j].type = (st->n_type & N_EXT)
					? RZ_BIN_MACH0_SYMBOL_TYPE_EXT
					: RZ_BIN_MACH0_SYMBOL_TYPE_LOCAL;
				char *sym_name = get_name(bin, st->n_strx, false);
				if (sym_name) {
					symbols[j].name = sym_name;
				} else {
					symbols[j].name = rz_str_newf("entry%d", i);
				}
				symbols[j].last = 0;
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
		ht_pp_free(hash);
		return NULL;
	} else {
		symbols_size = (symbols_count + 1) * sizeof(struct symbol_t);
		if (symbols_size < 1) {
			ht_pp_free(hash);
			return NULL;
		}
		if (!(symbols = calloc(1, symbols_size))) {
			ht_pp_free(hash);
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
	ht_pp_free(hash);
	symbols[j].last = true;
	bin->symbols = symbols;
	return symbols;
}

static int parse_import_ptr(struct MACH0_(obj_t) * bin, struct reloc_t *reloc, int idx) {
	int i, j, sym;
	size_t wordsize;
	ut32 stype;
	wordsize = get_word_size(bin);
	if (idx < 0 || idx >= bin->nsymtab) {
		return 0;
	}
	if ((bin->symtab[idx].n_desc & REFERENCE_TYPE) == REFERENCE_FLAG_UNDEFINED_LAZY) {
		stype = S_LAZY_SYMBOL_POINTERS;
	} else {
		stype = S_NON_LAZY_SYMBOL_POINTERS;
	}

	reloc->offset = 0;
	reloc->addr = 0;
	reloc->addend = 0;
#define CASE(T) \
	case ((T) / 8): reloc->type = RZ_BIN_RELOC_##T; break
	switch (wordsize) {
		CASE(8);
		CASE(16);
		CASE(32);
		CASE(64);
	default: return false;
	}
#undef CASE

	for (i = 0; i < bin->nsects; i++) {
		if ((bin->sects[i].flags & SECTION_TYPE) == stype) {
			for (j = 0, sym = -1; bin->sects[i].reserved1 + j < bin->nindirectsyms; j++) {
				int indidx = bin->sects[i].reserved1 + j;
				if (indidx < 0 || indidx >= bin->nindirectsyms) {
					break;
				}
				if (idx == bin->indirectsyms[indidx]) {
					sym = j;
					break;
				}
			}
			reloc->offset = sym == -1 ? 0 : bin->sects[i].offset + sym * wordsize;
			reloc->addr = sym == -1 ? 0 : bin->sects[i].addr + sym * wordsize;
			return true;
		}
	}
	return false;
}

struct import_t *MACH0_(get_imports)(struct MACH0_(obj_t) * bin) {
	rz_return_val_if_fail(bin, NULL);

	int i, j, idx, stridx;
	if (!bin->sects || !bin->symtab || !bin->symstr || !bin->indirectsyms) {
		return NULL;
	}

	if (bin->dysymtab.nundefsym < 1 || bin->dysymtab.nundefsym > 0xfffff) {
		return NULL;
	}

	struct import_t *imports = calloc(bin->dysymtab.nundefsym + 1, sizeof(struct import_t));
	if (!imports) {
		return NULL;
	}
	for (i = j = 0; i < bin->dysymtab.nundefsym; i++) {
		idx = bin->dysymtab.iundefsym + i;
		if (idx < 0 || idx >= bin->nsymtab) {
			bprintf("WARNING: Imports index out of bounds. Ignoring relocs\n");
			free(imports);
			return NULL;
		}
		stridx = bin->symtab[idx].n_strx;
		char *imp_name = get_name(bin, stridx, false);
		if (imp_name) {
			rz_str_ncpy(imports[j].name, imp_name, RZ_BIN_MACH0_STRING_LENGTH);
			free(imp_name);
		} else {
			//imports[j].name[0] = 0;
			continue;
		}
		imports[j].ord = i;
		imports[j++].last = 0;
	}
	imports[j].last = 1;

	if (!bin->imports_by_ord_size) {
		if (j > 0) {
			bin->imports_by_ord_size = j;
			bin->imports_by_ord = (RzBinImport **)calloc(j, sizeof(RzBinImport *));
		} else {
			bin->imports_by_ord_size = 0;
			bin->imports_by_ord = NULL;
		}
	}

	return imports;
}

static int reloc_comparator(struct reloc_t *a, struct reloc_t *b) {
	return a->addr - b->addr;
}

static void parse_relocation_info(struct MACH0_(obj_t) * bin, RzSkipList *relocs, ut32 offset, ut32 num) {
	if (!num || !offset || (st32)num < 0) {
		return;
	}

	ut64 total_size = num * sizeof(struct relocation_info);
	struct relocation_info *info = calloc(num, sizeof(struct relocation_info));
	if (!info) {
		return;
	}

	if (rz_buf_read_at(bin->b, offset, (ut8 *)info, total_size) < total_size) {
		free(info);
		return;
	}

	size_t i;
	for (i = 0; i < num; i++) {
		struct relocation_info a_info = info[i];
		ut32 sym_num = a_info.rz_symbolnum;
		if (sym_num > bin->nsymtab) {
			continue;
		}

		ut32 stridx = bin->symtab[sym_num].n_strx;
		char *sym_name = get_name(bin, stridx, false);
		if (!sym_name) {
			continue;
		}

		struct reloc_t *reloc = RZ_NEW0(struct reloc_t);
		if (!reloc) {
			return;
		}

		reloc->addr = offset_to_vaddr(bin, a_info.rz_address);
		reloc->offset = a_info.rz_address;
		reloc->ord = sym_num;
		reloc->type = a_info.rz_type; // enum RelocationInfoType
		reloc->external = a_info.rz_extern;
		reloc->pc_relative = a_info.rz_pcrel;
		reloc->size = a_info.rz_length;
		rz_str_ncpy(reloc->name, sym_name, sizeof(reloc->name) - 1);
		rz_skiplist_insert(relocs, reloc);
	}
}

static bool is_valid_ordinal_table_size(ut64 size) {
	return size > 0 && size <= UT16_MAX;
}

RzSkipList *MACH0_(get_relocs)(struct MACH0_(obj_t) * bin) {
	RzSkipList *relocs = NULL;
	RzPVector *threaded_binds = NULL;
	size_t wordsize = get_word_size(bin);
	if (bin->dyld_info) {
		ut8 *opcodes, rel_type = 0;
		size_t bind_size, lazy_size, weak_size;

#define CASE(T) \
	case ((T) / 8): rel_type = RZ_BIN_RELOC_##T; break
		switch (wordsize) {
			CASE(8);
			CASE(16);
			CASE(32);
			CASE(64);
		default: return NULL;
		}
#undef CASE
		bind_size = bin->dyld_info->bind_size;
		lazy_size = bin->dyld_info->lazy_bind_size;
		weak_size = bin->dyld_info->weak_bind_size;

		if (!bind_size && !lazy_size) {
			return NULL;
		}

		if ((bind_size + lazy_size) < 1) {
			return NULL;
		}
		if (bin->dyld_info->bind_off > bin->size || bin->dyld_info->bind_off + bind_size > bin->size) {
			return NULL;
		}
		if (bin->dyld_info->lazy_bind_off > bin->size ||
			bin->dyld_info->lazy_bind_off + lazy_size > bin->size) {
			return NULL;
		}
		if (bin->dyld_info->bind_off + bind_size + lazy_size > bin->size) {
			return NULL;
		}
		if (bin->dyld_info->weak_bind_off + weak_size > bin->size) {
			return NULL;
		}
		ut64 amount = bind_size + lazy_size + weak_size;
		if (amount == 0 || amount > UT32_MAX) {
			return NULL;
		}
		if (!bin->segs) {
			return NULL;
		}
		relocs = rz_skiplist_new((RzListFree)&free, (RzListComparator)&reloc_comparator);
		if (!relocs) {
			return NULL;
		}
		opcodes = calloc(1, amount + 1);
		if (!opcodes) {
			rz_skiplist_free(relocs);
			return NULL;
		}

		int len = rz_buf_read_at(bin->b, bin->dyld_info->bind_off, opcodes, bind_size);
		len += rz_buf_read_at(bin->b, bin->dyld_info->lazy_bind_off, opcodes + bind_size, lazy_size);
		len += rz_buf_read_at(bin->b, bin->dyld_info->weak_bind_off, opcodes + bind_size + lazy_size, weak_size);
		if (len < amount) {
			bprintf("Error: read (dyld_info bind) at 0x%08" PFMT64x "\n", (ut64)(size_t)bin->dyld_info->bind_off);
			RZ_FREE(opcodes);
			rz_skiplist_free(relocs);
			return NULL;
		}

		size_t partition_sizes[] = { bind_size, lazy_size, weak_size };
		size_t pidx;
		int opcodes_offset = 0;
		for (pidx = 0; pidx < RZ_ARRAY_SIZE(partition_sizes); pidx++) {
			size_t partition_size = partition_sizes[pidx];

			ut8 type = 0;
			int lib_ord = 0, seg_idx = -1, sym_ord = -1;
			char *sym_name = NULL;
			size_t j, count, skip;
			st64 addend = 0;
			ut64 addr = bin->segs[0].vmaddr;
			ut64 segment_end_addr = addr + bin->segs[0].vmsize;

			ut8 *p = opcodes + opcodes_offset;
			ut8 *end = p + partition_size;
			bool done = false;
			while (!done && p < end) {
				ut8 imm = *p & BIND_IMMEDIATE_MASK;
				ut8 op = *p & BIND_OPCODE_MASK;
				p++;
				switch (op) {
				case BIND_OPCODE_DONE: {
					bool in_lazy_binds = pidx == 1;
					if (!in_lazy_binds) {
						done = true;
					}
					break;
				}
				case BIND_OPCODE_THREADED: {
					switch (imm) {
					case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: {
						ut64 table_size = read_uleb128(&p, end);
						if (!is_valid_ordinal_table_size(table_size)) {
							bprintf("Error: BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB size is wrong\n");
							break;
						}
						if (threaded_binds) {
							rz_pvector_free(threaded_binds);
						}
						threaded_binds = rz_pvector_new_with_len((RzPVectorFree)&free, table_size);
						if (threaded_binds) {
							sym_ord = 0;
						}
						break;
					}
					case BIND_SUBOPCODE_THREADED_APPLY:
						if (threaded_binds) {
							int cur_seg_idx = (seg_idx != -1) ? seg_idx : 0;
							size_t n_threaded_binds = rz_pvector_len(threaded_binds);
							while (addr < segment_end_addr) {
								ut8 tmp[8];
								ut64 paddr = addr - bin->segs[cur_seg_idx].vmaddr + bin->segs[cur_seg_idx].fileoff;
								bin->rebasing_buffer = true;
								if (rz_buf_read_at(bin->b, paddr, tmp, 8) != 8) {
									break;
								}
								bin->rebasing_buffer = false;
								ut64 raw_ptr = rz_read_le64(tmp);
								bool is_auth = (raw_ptr & (1ULL << 63)) != 0;
								bool is_bind = (raw_ptr & (1ULL << 62)) != 0;
								int ordinal = -1;
								int addend = -1;
								ut64 delta;
								if (is_auth && is_bind) {
									struct dyld_chained_ptr_arm64e_auth_bind *p =
										(struct dyld_chained_ptr_arm64e_auth_bind *)&raw_ptr;
									delta = p->next;
									ordinal = p->ordinal;
								} else if (!is_auth && is_bind) {
									struct dyld_chained_ptr_arm64e_bind *p =
										(struct dyld_chained_ptr_arm64e_bind *)&raw_ptr;
									delta = p->next;
									ordinal = p->ordinal;
									addend = p->addend;
								} else if (is_auth && !is_bind) {
									struct dyld_chained_ptr_arm64e_auth_rebase *p =
										(struct dyld_chained_ptr_arm64e_auth_rebase *)&raw_ptr;
									delta = p->next;
								} else {
									struct dyld_chained_ptr_arm64e_rebase *p =
										(struct dyld_chained_ptr_arm64e_rebase *)&raw_ptr;
									delta = p->next;
								}
								if (ordinal != -1) {
									if (ordinal >= n_threaded_binds) {
										bprintf("Error: Malformed bind chain\n");
										break;
									}
									struct reloc_t *ref = rz_pvector_at(threaded_binds, ordinal);
									if (!ref) {
										bprintf("Error: Inconsistent bind opcodes\n");
										break;
									}
									struct reloc_t *reloc = RZ_NEW0(struct reloc_t);
									if (!reloc) {
										break;
									}
									*reloc = *ref;
									reloc->addr = addr;
									reloc->offset = paddr;
									if (addend != -1) {
										reloc->addend = addend;
									}
									rz_skiplist_insert(relocs, reloc);
								}
								addr += delta * wordsize;
								if (!delta) {
									break;
								}
							}
						}
						break;
					default:
						bprintf("Error: Unexpected BIND_OPCODE_THREADED sub-opcode: 0x%x\n", imm);
					}
					break;
				}
				case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
					lib_ord = imm;
					break;
				case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
					lib_ord = read_uleb128(&p, end);
					break;
				case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
					lib_ord = imm ? (st8)(BIND_OPCODE_MASK | imm) : 0;
					break;
				case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
					sym_name = (char *)p;
					while (*p++ && p < end) {
						/* empty loop */
					}
					if (threaded_binds) {
						break;
					}
					sym_ord = -1;
					if (bin->symtab && bin->dysymtab.nundefsym < UT16_MAX) {
						for (j = 0; j < bin->dysymtab.nundefsym; j++) {
							size_t stridx = 0;
							bool found = false;
							int iundefsym = bin->dysymtab.iundefsym;
							if (iundefsym >= 0 && iundefsym < bin->nsymtab) {
								int sidx = iundefsym + j;
								if (sidx < 0 || sidx >= bin->nsymtab) {
									continue;
								}
								stridx = bin->symtab[sidx].n_strx;
								if (stridx >= bin->symstrlen) {
									continue;
								}
								found = true;
							}
							if (found && !strcmp((const char *)bin->symstr + stridx, sym_name)) {
								sym_ord = j;
								break;
							}
						}
					}
					break;
				}
				case BIND_OPCODE_SET_TYPE_IMM:
					type = imm;
					break;
				case BIND_OPCODE_SET_ADDEND_SLEB:
					addend = rz_sleb128((const ut8 **)&p, end);
					break;
				case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
					seg_idx = imm;
					if (seg_idx >= bin->nsegs) {
						bprintf("Error: BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB"
							" has unexistent segment %d\n",
							seg_idx);
						free(opcodes);
						rz_skiplist_free(relocs);
						rz_pvector_free(threaded_binds);
						return NULL; // early exit to avoid future mayhem
					}
					addr = bin->segs[seg_idx].vmaddr + read_uleb128(&p, end);
					segment_end_addr = bin->segs[seg_idx].vmaddr + bin->segs[seg_idx].vmsize;
					break;
				case BIND_OPCODE_ADD_ADDR_ULEB:
					addr += read_uleb128(&p, end);
					break;
#define DO_BIND() \
	do { \
		if (sym_ord < 0 && !sym_name) \
			break; \
		if (!threaded_binds) { \
			if (seg_idx < 0) \
				break; \
			if (!addr) \
				break; \
		} \
		struct reloc_t *reloc = RZ_NEW0(struct reloc_t); \
		reloc->addr = addr; \
		if (seg_idx >= 0) { \
			reloc->offset = addr - bin->segs[seg_idx].vmaddr + bin->segs[seg_idx].fileoff; \
			if (type == BIND_TYPE_TEXT_PCREL32) \
				reloc->addend = addend - (bin->baddr + addr); \
			else \
				reloc->addend = addend; \
		} else { \
			reloc->addend = addend; \
		} \
		/* library ordinal ??? */ \
		reloc->ord = lib_ord; \
		reloc->ord = sym_ord; \
		reloc->type = rel_type; \
		if (sym_name) \
			rz_str_ncpy(reloc->name, sym_name, 256); \
		if (threaded_binds) \
			rz_pvector_set(threaded_binds, sym_ord, reloc); \
		else \
			rz_skiplist_insert(relocs, reloc); \
	} while (0)
				case BIND_OPCODE_DO_BIND:
					if (!threaded_binds && addr >= segment_end_addr) {
						bprintf("Error: Malformed DO bind opcode 0x%" PFMT64x "\n", addr);
						goto beach;
					}
					DO_BIND();
					if (!threaded_binds) {
						addr += wordsize;
					} else {
						sym_ord++;
					}
					break;
				case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
					if (addr >= segment_end_addr) {
						bprintf("Error: Malformed ADDR ULEB bind opcode\n");
						goto beach;
					}
					DO_BIND();
					addr += read_uleb128(&p, end) + wordsize;
					break;
				case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
					if (addr >= segment_end_addr) {
						bprintf("Error: Malformed IMM SCALED bind opcode\n");
						goto beach;
					}
					DO_BIND();
					addr += (ut64)imm * (ut64)wordsize + wordsize;
					break;
				case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
					count = read_uleb128(&p, end);
					skip = read_uleb128(&p, end);
					for (j = 0; j < count; j++) {
						if (addr >= segment_end_addr) {
							bprintf("Error: Malformed ULEB TIMES bind opcode\n");
							goto beach;
						}
						DO_BIND();
						addr += skip + wordsize;
					}
					break;
#undef DO_BIND
				default:
					bprintf("Error: unknown bind opcode 0x%02x in dyld_info\n", *p);
					RZ_FREE(opcodes);
					rz_pvector_free(threaded_binds);
					return relocs;
				}
			}

			opcodes_offset += partition_size;
		}

		RZ_FREE(opcodes);
		rz_pvector_free(threaded_binds);
		threaded_binds = NULL;
	}

	if (bin->symtab && bin->symstr && bin->sects && bin->indirectsyms) {
		int j;
		int amount = bin->dysymtab.nundefsym;
		if (amount < 0) {
			amount = 0;
		}
		if (!relocs) {
			relocs = rz_skiplist_new((RzListFree)&free, (RzListComparator)&reloc_comparator);
			if (!relocs) {
				return NULL;
			}
		}
		for (j = 0; j < amount; j++) {
			struct reloc_t *reloc = RZ_NEW0(struct reloc_t);
			if (!reloc) {
				break;
			}
			if (parse_import_ptr(bin, reloc, bin->dysymtab.iundefsym + j)) {
				reloc->ord = j;
				rz_skiplist_insert(relocs, reloc);
			} else {
				RZ_FREE(reloc);
			}
		}
	}

	if (bin->symtab && bin->dysymtab.extreloff && bin->dysymtab.nextrel) {
		if (!relocs) {
			relocs = rz_skiplist_new((RzListFree)&free, (RzListComparator)&reloc_comparator);
			if (!relocs) {
				return NULL;
			}
		}
		parse_relocation_info(bin, relocs, bin->dysymtab.extreloff, bin->dysymtab.nextrel);
	}
beach:
	rz_pvector_free(threaded_binds);
	return relocs;
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
	entry->offset = addr_to_offset(bin, entry->addr);
	entry->haddr = sdb_num_get(bin->kv, "mach0.entry.offset", 0);
	sdb_num_set(bin->kv, "mach0.entry.vaddr", entry->addr, 0);
	sdb_num_set(bin->kv, "mach0.entry.paddr", bin->entry, 0);

	if (entry->offset == 0 && !bin->sects) {
		int i;
		for (i = 0; i < bin->nsects; i++) {
			// XXX: section name shoudnt matter .. just check for exec flags
			if (!strncmp(bin->sects[i].sectname, "__text", 6)) {
				entry->offset = (ut64)bin->sects[i].offset;
				sdb_num_set(bin->kv, "mach0.entry", entry->offset, 0);
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
	for (i = 0; i < bin->nlibs; i++) {
		sdb_set(bin->kv, sdb_fmt("libs.%d.name", i), bin->libs[i], 0);
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
	for (i = 0; i < bin->nlibs; i++) {
		sdb_set(bin->kv, sdb_fmt("libs.%d.name", i), bin->libs[i], 0);
		strncpy(libs[i].name, bin->libs[i], RZ_BIN_MACH0_STRING_LENGTH);
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
	return rz_str_new("MACH064");
#else
	return rz_str_new("MACH0");
#endif
}

//XXX we are mixing up bits from cpu and opcodes
//since thumb use 16 bits opcode but run in 32 bits
//cpus  so here we should only return 32 or 64
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

const char *MACH0_(get_os)(struct MACH0_(obj_t) * bin) {
	if (bin) {
		switch (bin->os) {
		case 1: return "macos";
		case 2: return "ios";
		case 3: return "watchos";
		case 4: return "tvos";
		}
	}
	return "darwin";
}

const char *MACH0_(get_cputype_from_hdr)(struct MACH0_(mach_header) * hdr) {
	const char *archstr = "unknown";
	switch (hdr->cputype) {
	case CPU_TYPE_VAX:
		archstr = "vax";
		break;
	case CPU_TYPE_MC680x0:
		archstr = "mc680x0";
		break;
	case CPU_TYPE_I386:
	case CPU_TYPE_X86_64:
		archstr = "x86";
		break;
	case CPU_TYPE_MC88000:
		archstr = "mc88000";
		break;
	case CPU_TYPE_MC98000:
		archstr = "mc98000";
		break;
	case CPU_TYPE_HPPA:
		archstr = "hppa";
		break;
	case CPU_TYPE_ARM:
	case CPU_TYPE_ARM64:
	case CPU_TYPE_ARM64_32:
		archstr = "arm";
		break;
	case CPU_TYPE_SPARC:
		archstr = "sparc";
		break;
	case CPU_TYPE_MIPS:
		archstr = "mips";
		break;
	case CPU_TYPE_I860:
		archstr = "i860";
		break;
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		archstr = "ppc";
		break;
	default:
		eprintf("Unknown arch %d\n", hdr->cputype);
		break;
	}
	return archstr;
}

const char *MACH0_(get_cputype)(struct MACH0_(obj_t) * bin) {
	return bin ? MACH0_(get_cputype_from_hdr)(&bin->hdr) : "unknown";
}

static const char *cpusubtype_tostring(ut32 cputype, ut32 cpusubtype) {
	switch (cputype) {
	case CPU_TYPE_VAX:
		switch (cpusubtype) {
		case CPU_SUBTYPE_VAX_ALL: return "all";
		case CPU_SUBTYPE_VAX780: return "vax780";
		case CPU_SUBTYPE_VAX785: return "vax785";
		case CPU_SUBTYPE_VAX750: return "vax750";
		case CPU_SUBTYPE_VAX730: return "vax730";
		case CPU_SUBTYPE_UVAXI: return "uvaxI";
		case CPU_SUBTYPE_UVAXII: return "uvaxII";
		case CPU_SUBTYPE_VAX8200: return "vax8200";
		case CPU_SUBTYPE_VAX8500: return "vax8500";
		case CPU_SUBTYPE_VAX8600: return "vax8600";
		case CPU_SUBTYPE_VAX8650: return "vax8650";
		case CPU_SUBTYPE_VAX8800: return "vax8800";
		case CPU_SUBTYPE_UVAXIII: return "uvaxIII";
		default: return "Unknown vax subtype";
		}
	case CPU_TYPE_MC680x0:
		switch (cpusubtype) {
		case CPU_SUBTYPE_MC68030: return "mc68030";
		case CPU_SUBTYPE_MC68040: return "mc68040";
		case CPU_SUBTYPE_MC68030_ONLY: return "mc68030 only";
		default: return "Unknown mc680x0 subtype";
		}
	case CPU_TYPE_I386:
		switch (cpusubtype) {
		case CPU_SUBTYPE_386: return "386";
		case CPU_SUBTYPE_486: return "486";
		case CPU_SUBTYPE_486SX: return "486sx";
		case CPU_SUBTYPE_PENT: return "Pentium";
		case CPU_SUBTYPE_PENTPRO: return "Pentium Pro";
		case CPU_SUBTYPE_PENTII_M3: return "Pentium 3 M3";
		case CPU_SUBTYPE_PENTII_M5: return "Pentium 3 M5";
		case CPU_SUBTYPE_CELERON: return "Celeron";
		case CPU_SUBTYPE_CELERON_MOBILE: return "Celeron Mobile";
		case CPU_SUBTYPE_PENTIUM_3: return "Pentium 3";
		case CPU_SUBTYPE_PENTIUM_3_M: return "Pentium 3 M";
		case CPU_SUBTYPE_PENTIUM_3_XEON: return "Pentium 3 Xeon";
		case CPU_SUBTYPE_PENTIUM_M: return "Pentium Mobile";
		case CPU_SUBTYPE_PENTIUM_4: return "Pentium 4";
		case CPU_SUBTYPE_PENTIUM_4_M: return "Pentium 4 M";
		case CPU_SUBTYPE_ITANIUM: return "Itanium";
		case CPU_SUBTYPE_ITANIUM_2: return "Itanium 2";
		case CPU_SUBTYPE_XEON: return "Xeon";
		case CPU_SUBTYPE_XEON_MP: return "Xeon MP";
		default: return "Unknown i386 subtype";
		}
	case CPU_TYPE_X86_64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_X86_64_ALL: return "x86 64 all";
		case CPU_SUBTYPE_X86_ARCH1: return "x86 arch 1";
		default: return "Unknown x86 subtype";
		}
	case CPU_TYPE_MC88000:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC88000_ALL: return "all";
		case CPU_SUBTYPE_MC88100: return "mc88100";
		case CPU_SUBTYPE_MC88110: return "mc88110";
		default: return "Unknown mc88000 subtype";
		}
	case CPU_TYPE_MC98000:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MC98000_ALL: return "all";
		case CPU_SUBTYPE_MC98601: return "mc98601";
		default: return "Unknown mc98000 subtype";
		}
	case CPU_TYPE_HPPA:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_HPPA_7100: return "hppa7100";
		case CPU_SUBTYPE_HPPA_7100LC: return "hppa7100LC";
		default: return "Unknown hppa subtype";
		}
	case CPU_TYPE_ARM64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_ARM64_ALL: return "all";
		case CPU_SUBTYPE_ARM64_V8: return "arm64v8";
		case CPU_SUBTYPE_ARM64E: return "arm64e";
		default: return "Unknown arm64 subtype";
		}
		return "v8";
	case CPU_TYPE_ARM:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_ARM_ALL:
			return "all";
		case CPU_SUBTYPE_ARM_V4T:
			return "v4t";
		case CPU_SUBTYPE_ARM_V5:
			return "v5";
		case CPU_SUBTYPE_ARM_V6:
			return "v6";
		case CPU_SUBTYPE_ARM_XSCALE:
			return "xscale";
		case CPU_SUBTYPE_ARM_V7:
			return "v7";
		case CPU_SUBTYPE_ARM_V7F:
			return "v7f";
		case CPU_SUBTYPE_ARM_V7S:
			return "v7s";
		case CPU_SUBTYPE_ARM_V7K:
			return "v7k";
		case CPU_SUBTYPE_ARM_V7M:
			return "v7m";
		case CPU_SUBTYPE_ARM_V7EM:
			return "v7em";
		default:
			eprintf("Unknown arm subtype %d\n", cpusubtype & 0xff);
			return "unknown arm subtype";
		}
	case CPU_TYPE_SPARC:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_SPARC_ALL: return "all";
		default: return "Unknown sparc subtype";
		}
	case CPU_TYPE_MIPS:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_MIPS_ALL: return "all";
		case CPU_SUBTYPE_MIPS_R2300: return "r2300";
		case CPU_SUBTYPE_MIPS_R2600: return "r2600";
		case CPU_SUBTYPE_MIPS_R2800: return "r2800";
		case CPU_SUBTYPE_MIPS_R2000a: return "r2000a";
		case CPU_SUBTYPE_MIPS_R2000: return "r2000";
		case CPU_SUBTYPE_MIPS_R3000a: return "r3000a";
		case CPU_SUBTYPE_MIPS_R3000: return "r3000";
		default: return "Unknown mips subtype";
		}
	case CPU_TYPE_I860:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_I860_ALL: return "all";
		case CPU_SUBTYPE_I860_860: return "860";
		default: return "Unknown i860 subtype";
		}
	case CPU_TYPE_POWERPC:
	case CPU_TYPE_POWERPC64:
		switch (cpusubtype & 0xff) {
		case CPU_SUBTYPE_POWERPC_ALL: return "all";
		case CPU_SUBTYPE_POWERPC_601: return "601";
		case CPU_SUBTYPE_POWERPC_602: return "602";
		case CPU_SUBTYPE_POWERPC_603: return "603";
		case CPU_SUBTYPE_POWERPC_603e: return "603e";
		case CPU_SUBTYPE_POWERPC_603ev: return "603ev";
		case CPU_SUBTYPE_POWERPC_604: return "604";
		case CPU_SUBTYPE_POWERPC_604e: return "604e";
		case CPU_SUBTYPE_POWERPC_620: return "620";
		case CPU_SUBTYPE_POWERPC_750: return "750";
		case CPU_SUBTYPE_POWERPC_7400: return "7400";
		case CPU_SUBTYPE_POWERPC_7450: return "7450";
		case CPU_SUBTYPE_POWERPC_970: return "970";
		default: return "Unknown ppc subtype";
		}
	}
	return "Unknown cputype";
}

char *MACH0_(get_cpusubtype_from_hdr)(struct MACH0_(mach_header) * hdr) {
	rz_return_val_if_fail(hdr, NULL);
	return strdup(cpusubtype_tostring(hdr->cputype, hdr->cpusubtype));
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
#if FEATURE_SYMLIST
		(void)MACH0_(get_symbols_list)(bin);
#else
		(void)MACH0_(get_symbols)(bin);
#endif
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
		ut64 entry = addr_to_offset(bin, bin->entry);
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
			cb_printf("0x%08" PFMT64x "  platform    %s\n",
				pvaddr, build_version_platform_to_string(rz_buf_read_le32_at(buf, addr)));
			cb_printf("0x%08" PFMT64x "  minos       %d.%d.%d\n",
				pvaddr + 4, rz_buf_read_le16_at(buf, addr + 6), rz_buf_read8_at(buf, addr + 5),
				rz_buf_read8_at(buf, addr + 4));
			cb_printf("0x%08" PFMT64x "  sdk         %d.%d.%d\n",
				pvaddr + 8, rz_buf_read_le16_at(buf, addr + 10), rz_buf_read8_at(buf, addr + 9),
				rz_buf_read8_at(buf, addr + 8));
			ut32 ntools = rz_buf_read_le32_at(buf, addr + 12);
			cb_printf("0x%08" PFMT64x "  ntools      %d\n",
				pvaddr + 12, ntools);
			ut64 off = 16;
			while (off < (lcSize - 8) && ntools--) {
				cb_printf("pf.mach0_build_version_tool @ 0x%08" PFMT64x "\n", pvaddr + off);
				cb_printf("0x%08" PFMT64x "  tool        %s\n",
					pvaddr + off, build_version_tool_to_string(rz_buf_read_le32_at(buf, addr + off)));
				off += 4;
				if (off >= (lcSize - 8)) {
					break;
				}
				cb_printf("0x%08" PFMT64x "  version     %d.%d.%d\n",
					pvaddr + off, rz_buf_read_le16_at(buf, addr + off + 2), rz_buf_read8_at(buf, addr + off + 1),
					rz_buf_read8_at(buf, addr + off));
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
			ut32 str_off = rz_buf_read_ble32_at(buf, addr, isBe);
			char *id = rz_buf_get_string(buf, addr + str_off - 8);
			cb_printf("0x%08" PFMT64x "  current     %d.%d.%d\n",
				pvaddr + 8, rz_buf_read_le16_at(buf, addr + 10), rz_buf_read8_at(buf, addr + 9),
				rz_buf_read8_at(buf, addr + 8));
			cb_printf("0x%08" PFMT64x "  compat      %d.%d.%d\n",
				pvaddr + 12, rz_buf_read_le16_at(buf, addr + 14), rz_buf_read8_at(buf, addr + 13),
				rz_buf_read8_at(buf, addr + 12));
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
			ut32 nsects = rz_buf_read_le32_at(buf, addr - 8 + (is64 ? 64 : 48));
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
			ut32 str_off = rz_buf_read_ble32_at(buf, addr, isBe);
			char *load_dylib = rz_buf_get_string(buf, addr + str_off - 8);
			cb_printf("0x%08" PFMT64x "  current     %d.%d.%d\n",
				pvaddr + 8, rz_buf_read_le16_at(buf, addr + 10), rz_buf_read8_at(buf, addr + 9),
				rz_buf_read8_at(buf, addr + 8));
			cb_printf("0x%08" PFMT64x "  compat      %d.%d.%d\n",
				pvaddr + 12, rz_buf_read_le16_at(buf, addr + 14), rz_buf_read8_at(buf, addr + 13),
				rz_buf_read8_at(buf, addr + 12));
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
			ut32 word = rz_buf_read_le32_at(buf, addr);
			cb_printf("0x%08" PFMT64x "  cryptoff   0x%08x\n", pvaddr, word);
			word = rz_buf_read_le32_at(buf, addr + 4);
			cb_printf("0x%08" PFMT64x "  cryptsize  %d\n", pvaddr + 4, word);
			word = rz_buf_read_le32_at(buf, addr + 8);
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

RzList *MACH0_(mach_fields)(RzBinFile *bf) {
	RzBuffer *buf = bf->buf;
	ut64 length = rz_buf_size(buf);
	struct MACH0_(mach_header) *mh = MACH0_(get_hdr)(buf);
	if (!mh) {
		return NULL;
	}
	RzList *ret = rz_list_new();
	if (!ret) {
		free(mh);
		return NULL;
	}
	ret->free = free;
	ut64 addr = pa2va(bf, 0);
	ut64 paddr = 0;

	rz_list_append(ret, rz_bin_field_new(addr, addr, 1, "header", "mach0_header", "mach0_header", true));
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
	for (n = 0; n < mh->ncmds; n++) {
		ut32 lcType = rz_buf_read_ble32_at(buf, paddr, isBe);
		ut32 word = rz_buf_read_ble32_at(buf, paddr + 4, isBe);
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
			rz_list_append(ret, rz_bin_field_new(addr, addr, 1, sdb_fmt("load_command_%d_%s", n, cmd_to_string(lcType)), pf_definition, pf_definition, true));
		}
		switch (lcType) {
		case LC_BUILD_VERSION: {
			ut32 ntools = rz_buf_read_le32_at(buf, paddr + 20);
			ut64 off = 24;
			int j = 0;
			while (off < lcSize && ntools--) {
				rz_list_append(ret, rz_bin_field_new(addr + off, addr + off, 1, sdb_fmt("tool_%d", j++), "mach0_build_version_tool", "mach0_build_version_tool", true));
				off += 8;
			}
			break;
		}
		case LC_SEGMENT:
		case LC_SEGMENT_64: {
			ut32 nsects = rz_buf_read_le32_at(buf, addr + (is64 ? 64 : 48));
			ut64 off = is64 ? 72 : 56;
			size_t i, j = 0;
			for (i = 0; i < nsects && (addr + off) < length && off < lcSize; i++) {
				const char *sname = is64 ? "mach0_section64" : "mach0_section";
				RzBinField *f = rz_bin_field_new(addr + off, addr + off, 1,
					sdb_fmt("section_%zu", j++), sname, sname, true);
				rz_list_append(ret, f);
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
