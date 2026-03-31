// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bin_mach0.inc"

static bool mach0_check_buffer(RzBuffer *b) {
	if (rz_buf_size(b) >= 4) {
		ut8 buf[4] = { 0 };
		if (rz_buf_read_at(b, 0, buf, 4)) {
			if (!memcmp(buf, "\xce\xfa\xed\xfe", 4) ||
				!memcmp(buf, "\xfe\xed\xfa\xce", 4)) {
				return true;
			}
		}
	}
	return false;
}

static RzBuffer *mach0_create(RzBin *bin, const ut8 *code, int clen, const ut8 *data, int dlen, RzBinArchOptions *opt) {
	const bool use_pagezero = true;
	const bool use_main = true;
	const bool use_dylinker = true;
	const bool use_libsystem = true;
	const bool use_linkedit = true;
	ut32 filesize, codeva, datava;
	ut32 ncmds, cmdsize, magiclen;
	ut32 p_codefsz = 0, p_codeva = 0, p_codesz = 0, p_codepa = 0;
	ut32 p_datafsz = 0, p_datava = 0, p_datasz = 0, p_datapa = 0;
	ut32 p_cmdsize = 0, p_entry = 0, p_tmp = 0;
	ut32 baddr = 0x1000;

	rz_return_val_if_fail(bin && opt, NULL);

	bool is_arm = strstr(opt->arch, "arm");
	RzBuffer *buf = rz_buf_new_with_bytes(NULL, 0);
#ifndef RZ_BIN_MACH064
	if (opt->bits == 64) {
		RZ_LOG_ERROR("Please use mach064 instead of mach0\n");
		free(buf);
		return NULL;
	}
#endif

#define B(x, y)    rz_buf_append_bytes(buf, (const ut8 *)(x), y)
#define D(x)       rz_buf_append_ut32(buf, x)
#define Z(x)       rz_buf_append_nbytes(buf, x)
#define W(x, y, z) rz_buf_write_at(buf, x, (const ut8 *)(y), z)
#define WZ(x, y) \
	p_tmp = rz_buf_size(buf); \
	Z(x); \
	W(p_tmp, y, strlen(y))

	/* MACH0 HEADER */
	B("\xce\xfa\xed\xfe", 4); // header
	// 64bit header	B ("\xce\xfa\xed\xfe", 4); // header
	if (is_arm) {
		D(12); // cpu type (arm)
		D(3); // subtype (all?)
	} else {
		/* x86-32 */
		D(7); // cpu type (x86)
		// D(0x1000007); // x86-64
		D(3); // subtype (i386-all)
	}
	D(2); // filetype (executable)

	if (data && dlen > 0) {
		ncmds = 3;
		cmdsize = 0;
	} else {
		ncmds = 2;
		cmdsize = 0;
	}
	if (use_pagezero) {
		ncmds++;
	}
	if (use_dylinker) {
		ncmds++;
		if (use_linkedit) {
			ncmds += 3;
		}
		if (use_libsystem) {
			ncmds++;
		}
	}

	/* COMMANDS */
	D(ncmds); // ncmds
	p_cmdsize = rz_buf_size(buf);
	D(-1); // cmdsize
	D(0); // flags
	// D (0x01200085); // alternative flags found in some a.out..
	magiclen = rz_buf_size(buf);

	if (use_pagezero) {
		/* PAGEZERO */
		D(1); // cmd.LC_SEGMENT
		D(56); // sizeof (cmd)
		WZ(16, "__PAGEZERO");
		D(0); // vmaddr
		D(0x00001000); // vmsize XXX
		D(0); // fileoff
		D(0); // filesize
		D(0); // maxprot
		D(0); // initprot
		D(0); // nsects
		D(0); // flags
	}

	/* TEXT SEGMENT */
	D(1); // cmd.LC_SEGMENT
	D(124); // sizeof (cmd)
	WZ(16, "__TEXT");
	D(baddr); // vmaddr
	D(0x1000); // vmsize XXX
	D(0); // fileoff
	p_codefsz = rz_buf_size(buf);
	D(-1); // filesize
	D(7); // maxprot
	D(5); // initprot
	D(1); // nsects
	D(0); // flags
	WZ(16, "__text");
	WZ(16, "__TEXT");
	p_codeva = rz_buf_size(buf); // virtual address
	D(-1);
	p_codesz = rz_buf_size(buf); // size of code (end-start)
	D(-1);
	p_codepa = rz_buf_size(buf); // code - baddr
	D(-1); //_start-0x1000);
	D(0); // align // should be 2 for 64bit
	D(0); // reloff
	D(0); // nrelocs
	D(0); // flags
	D(0); // reserved
	D(0); // ??

	if (data && dlen > 0) {
		/* DATA SEGMENT */
		D(1); // cmd.LC_SEGMENT
		D(124); // sizeof (cmd)
		p_tmp = rz_buf_size(buf);
		Z(16);
		W(p_tmp, "__TEXT", 6); // segment name
		D(0x2000); // vmaddr
		D(0x1000); // vmsize
		D(0); // fileoff
		p_datafsz = rz_buf_size(buf);
		D(-1); // filesize
		D(6); // maxprot
		D(6); // initprot
		D(1); // nsects
		D(0); // flags

		WZ(16, "__data");
		WZ(16, "__DATA");

		p_datava = rz_buf_size(buf);
		D(-1);
		p_datasz = rz_buf_size(buf);
		D(-1);
		p_datapa = rz_buf_size(buf);
		D(-1); //_start-0x1000);
		D(2); // align
		D(0); // reloff
		D(0); // nrelocs
		D(0); // flags
		D(0); // reserved
		D(0);
	}

	if (use_dylinker) {
		if (use_linkedit) {
			/* LINKEDIT */
			D(1); // cmd.LC_SEGMENT
			D(56); // sizeof (cmd)
			WZ(16, "__LINKEDIT");
			D(0x3000); // vmaddr
			D(0x00001000); // vmsize XXX
			D(0x1000); // fileoff
			D(0); // filesize
			D(7); // maxprot
			D(1); // initprot
			D(0); // nsects
			D(0); // flags

			/* LC_SYMTAB */
			D(2); // cmd.LC_SYMTAB
			D(24); // sizeof (cmd)
			D(0x1000); // symtab offset
			D(0); // symtab size
			D(0x1000); // strtab offset
			D(0); // strtab size

			/* LC_DYSYMTAB */
			D(0xb); // cmd.LC_DYSYMTAB
			D(80); // sizeof (cmd)
			Z(18 * sizeof(ut32)); // empty
		}

		const char *dyld = "/usr/lib/dyld";
		const int dyld_len = strlen(dyld) + 1;
		D(0xe); /* LC_DYLINKER */
		D((4 * 3) + dyld_len);
		D(dyld_len - 2);
		WZ(dyld_len, dyld); // path

		if (use_libsystem) {
			/* add libSystem at least ... */
			const char *lib = "/usr/lib/libSystem.B.dylib";
			const int lib_len = strlen(lib) + 1;
			D(0xc); /* LC_LOAD_DYLIB */
			D(24 + lib_len); // cmdsize
			D(24); // offset where the lib string start
			D(0x2);
			D(0x1);
			D(0x1);
			WZ(lib_len, lib);
		}
	}

	if (use_main) {
		/* LC_MAIN */
		D(0x80000028); // cmd.LC_MAIN
		D(24); // sizeof (cmd)
		D(baddr); // entryoff
		D(0); // stacksize
		D(0); // ???
		D(0); // ???
	} else {
		/* THREAD STATE */
		D(5); // LC_UNIXTHREAD
		D(80); // sizeof (cmd)
		if (is_arm) {
			/* arm */
			D(1); // i386-thread-state
			D(17); // thread-state-count
			p_entry = rz_buf_size(buf) + (16 * sizeof(ut32));
			Z(17 * sizeof(ut32));
			// mach0-arm has one byte more
		} else {
			/* x86-32 */
			D(1); // i386-thread-state
			D(16); // thread-state-count
			p_entry = rz_buf_size(buf) + (10 * sizeof(ut32));
			Z(16 * sizeof(ut32));
		}
	}

	/* padding to make mach_loader checks happy */
	/* binaries must be at least of 4KB :( not tiny anymore */
	WZ(4096 - rz_buf_size(buf), "");

	cmdsize = rz_buf_size(buf) - magiclen;
	codeva = rz_buf_size(buf) + baddr;
	datava = rz_buf_size(buf) + clen + baddr;
	if (p_entry != 0) {
		W(p_entry, &codeva, 4); // set PC
	}

	/* fill header variables */
	W(p_cmdsize, &cmdsize, 4);
	filesize = magiclen + cmdsize + clen + dlen;
	// TEXT SEGMENT should span the whole file //
	W(p_codefsz, &filesize, 4);
	W(p_codefsz - 8, &filesize, 4); // vmsize = filesize
	W(p_codeva, &codeva, 4);
	// clen = 4096;
	W(p_codesz, &clen, 4);
	p_tmp = codeva - baddr;
	W(p_codepa, &p_tmp, 4);

	B(code, clen);

	if (data && dlen > 0) {
		/* append data */
		W(p_datafsz, &filesize, 4);
		W(p_datava, &datava, 4);
		W(p_datasz, &dlen, 4);
		p_tmp = datava - baddr;
		W(p_datapa, &p_tmp, 4);
		B(data, dlen);
	}

	return buf;
}

static RzBinAddr *mach0_binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	ut64 addr;
	RzBinAddr *ret = NULL;
	switch (sym) {
	case RZ_BIN_SPECIAL_SYMBOL_MAIN:
		addr = MACH0_(get_main)(bf->o->bin_obj);
		if (addr == UT64_MAX || !(ret = RZ_NEW0(RzBinAddr))) {
			return NULL;
		}
		// if (bf->o->info && bf->o->info->bits == 16) {
		//  align for thumb
		ret->vaddr = ((addr >> 1) << 1);
		//}
		ret->paddr = ret->vaddr;
		break;
	default:
		break;
	}
	return ret;
}

static ut64 mach0_size(RzBinFile *bf) {
	ut64 off = 0;
	ut64 len = 0;
	if (!bf->o->sections) {
		void **iter;
		RzBinSection *section;
		bf->o->sections = mach0_sections(bf);
		rz_pvector_foreach (bf->o->sections, iter) {
			section = *iter;
			if (section->paddr > off) {
				off = section->paddr;
				len = section->size;
			}
		}
	}
	return off + len;
}

RzBinPlugin rz_bin_plugin_mach0 = {
	.name = "mach0",
	.desc = "Mach-O (Mach Object)",
	.license = "LGPL3",
	.author = "pancake",
	.get_sdb = &mach0_get_sdb,
	.load_buffer = &mach0_load_buffer,
	.destroy = &mach0_destroy,
	.check_buffer = &mach0_check_buffer,
	.baddr = &mach0_baddr,
	.binsym = &mach0_binsym,
	.entries = &mach0_entries,
	.signature = &mach0_entitlements,
	.virtual_files = &mach0_virtual_files,
	.maps = &mach0_maps,
	.sections = &mach0_sections,
	.symbols = &mach0_symbols,
	.imports = &mach0_imports,
	.size = &mach0_size,
	.info = &mach0_info,
	.bin_structure = MACH0_(mach_structure),
	.fields = MACH0_(mach_fields),
	.libs = &mach0_libs,
	.relocs = &mach0_relocs,
	.create = &mach0_create,
	.classes = &mach0_classes,
	.section_type_to_string = &MACH0_(section_type_to_string),
	.section_flag_to_rzlist = &MACH0_(section_flag_to_rzlist)
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_mach0,
	.version = RZ_VERSION
};
#endif
