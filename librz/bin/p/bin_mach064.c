// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#define RZ_BIN_MACH064 1
#include "bin_mach0.c"

#include "objc/mach064_classes.h"
#include "../format/mach0/mach064_is_kernelcache.c"

static bool check_buffer(RzBuffer *b) {
	ut8 buf[4] = { 0 };
	if (rz_buf_size(b) > 4) {
		rz_buf_read_at(b, 0, buf, sizeof(buf));
		if (!memcmp(buf, "\xfe\xed\xfa\xcf", 4)) {
			return true;
		}
		if (!memcmp(buf, "\xcf\xfa\xed\xfe", 4)) {
			return !is_kernelcache_buffer(b);
		}
	}
	return false;
}

static RzBuffer *create(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt) {
	const bool use_pagezero = true;
	const bool use_main = true;
	const bool use_dylinker = true;
	const bool use_libsystem = true;
	const bool use_linkedit = true;
	ut64 filesize, codeva, datava;
	ut32 ncmds, magiclen, headerlen;
	ut64 p_codefsz = 0, p_codeva = 0, p_codesz = 0, p_codepa = 0;
	ut64 p_datafsz = 0, p_datava = 0, p_datasz = 0, p_datapa = 0;
	ut64 p_cmdsize = 0, p_entry = 0, p_tmp = 0;
	ut64 baddr = 0x100001000LL;
	// TODO: baddr must be overriden with -b
	RzBuffer *buf = rz_buf_new();

#define B(x, y)    rz_buf_append_bytes(buf, (const ut8 *)(x), y)
#define D(x)       rz_buf_append_ut32(buf, x)
#define Q(x)       rz_buf_append_ut64(buf, x)
#define Z(x)       rz_buf_append_nbytes(buf, x)
#define W(x, y, z) rz_buf_write_at(buf, x, (const ut8 *)(y), z)
#define WZ(x, y) \
	p_tmp = rz_buf_size(buf); \
	Z(x); \
	W(p_tmp, y, strlen(y))

	/* MACH0 HEADER */
	// 32bit B ("\xce\xfa\xed\xfe", 4); // header
	B("\xcf\xfa\xed\xfe", 4); // header
	D(7 | 0x01000000); // cpu type (x86) | ABI64
	//D (3); // subtype (i386-all)
	D(0x80000003); // x86-64 subtype
	D(2); // filetype (executable)

	ncmds = (data && datalen > 0) ? 3 : 2;
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
	D(-1); // headsize // cmdsize?
	D(0); //0x85); // flags
	D(0); // reserved -- only found in x86-64

	magiclen = rz_buf_size(buf);

	if (use_pagezero) {
		/* PAGEZERO */
		D(0x19); // cmd.LC_SEGMENT
		D(72); // sizeof (cmd)
		WZ(16, "__PAGEZERO");
		Q(0); // vmaddr
		Q(0x1000); // vmsize XXX
		Q(0); // fileoff
		Q(0); // filesize
		D(0); // maxprot
		D(0); // initprot
		D(0); // nsects
		D(0); // flags
	}

	/* TEXT SEGMENT */
	D(0x19); // cmd.LC_SEGMENT_64
	//D (124+16+8); // sizeof (cmd)
	D(124 + 28); // sizeof (cmd)
	WZ(16, "__TEXT");
	Q(baddr); // vmaddr
	Q(0x1000); // vmsize XXX

	Q(0); // fileoff
	p_codefsz = rz_buf_size(buf);
	Q(-1); // filesize
	D(7); // maxprot
	D(5); // initprot
	D(1); // nsects
	D(0); // flags
	// define section
	WZ(16, "__text");
	WZ(16, "__TEXT");
	p_codeva = rz_buf_size(buf); // virtual address
	Q(-1);
	p_codesz = rz_buf_size(buf); // size of code (end-start)
	Q(-1);
	p_codepa = rz_buf_size(buf); // code - baddr
	D(-1); // offset, _start-0x1000);
	D(2); // align
	D(0); // reloff
	D(0); // nrelocs
	D(0); // flags
	D(0); // reserved1
	D(0); // reserved2
	D(0); // reserved3

	if (data && datalen > 0) {
		/* DATA SEGMENT */
		D(0x19); // cmd.LC_SEGMENT_64
		D(124 + 28); // sizeof (cmd)
		p_tmp = rz_buf_size(buf);
		Z(16);
		W(p_tmp, "__TEXT", 6); // segment name
		//XXX must be vmaddr+baddr
		Q(0x2000); // vmaddr
		//XXX must be vmaddr+baddr
		Q(0x1000); // vmsize
		Q(0); // fileoff
		p_datafsz = rz_buf_size(buf);
		Q(-1); // filesize
		D(6); // maxprot
		D(6); // initprot
		D(1); // nsects
		D(0); // flags

		WZ(16, "__data");
		WZ(16, "__DATA");

		p_datava = rz_buf_size(buf);
		Q(-1);
		p_datasz = rz_buf_size(buf);
		Q(-1);
		p_datapa = rz_buf_size(buf);
		D(-1); //_start-0x1000);
		D(2); // align
		D(0); // reloff
		D(0); // nrelocs
		D(0); // flags
		D(0); // reserved1
		D(0); // reserved2
		D(0); // reserved3
	}

	if (use_dylinker) {
		if (use_linkedit) {
			/* LINKEDIT */
			D(0x19); // cmd.LC_SEGMENT
			D(72); // sizeof (cmd)
			WZ(16, "__LINKEDIT");
			Q(0x3000); // vmaddr
			Q(0x00001000); // vmsize XXX
			Q(0x1000); // fileoff
			Q(0); // filesize
			D(7); // maxprot
			D(3); // initprot
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
#define STATESIZE (21 * sizeof(ut64))
		/* THREAD STATE */
		D(5); // LC_UNIXTHREAD
		D(184); // sizeof (cmd)
		D(4); // 1=i386, 4=x86_64
		D(42); // thread-state-count
		p_entry = rz_buf_size(buf) + (16 * sizeof(ut64));
		Z(STATESIZE);
	}

	WZ(4096 - rz_buf_size(buf), "");
	headerlen = rz_buf_size(buf) - magiclen;

	codeva = rz_buf_size(buf) + baddr;
	datava = rz_buf_size(buf) + codelen + baddr;

	if (p_entry != 0) {
		W(p_entry, &codeva, 8); // set PC
	}

	/* fill header variables */
	W(p_cmdsize, &headerlen, 4);
	filesize = magiclen + headerlen + codelen + datalen;
	// TEXT SEGMENT //
	W(p_codefsz, &filesize, 8);
	W(p_codefsz - 16, &filesize, 8); // vmsize = filesize
	W(p_codeva, &codeva, 8);
	{
		ut64 clen = codelen;
		W(p_codesz, &clen, 8);
	}
	p_tmp = codeva - baddr;
	W(p_codepa, &p_tmp, 8);

	B(code, codelen);

	if (data && datalen > 0) {
		/* append data */
		W(p_datafsz, &filesize, 8);
		W(p_datava, &datava, 8);
		W(p_datasz, &datalen, 8);
		p_tmp = datava - baddr;
		W(p_datapa, &p_tmp, 8);
		B(data, datalen);
	}

	return buf;
}

static RzBinAddr *binsym(RzBinFile *bf, int sym) {
	ut64 addr;
	RzBinAddr *ret = NULL;
	switch (sym) {
	case RZ_BIN_SYM_MAIN:
		addr = MACH0_(get_main)(bf->o->bin_obj);
		if (!addr || !(ret = RZ_NEW0(RzBinAddr))) {
			return NULL;
		}
		ret->paddr = ret->vaddr = addr;
		break;
	}
	return ret;
}

RzBinPlugin rz_bin_plugin_mach064 = {
	.name = "mach064",
	.desc = "mach064 bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = binsym,
	.entries = &entries,
	.sections = &sections,
	.signature = &entitlements,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	.header = &MACH0_(mach_headerfields),
	.relocs = &relocs,
	.patch_relocs = &patch_relocs,
	.fields = &MACH0_(mach_fields),
	.create = &create,
	.classes = &MACH0_(parse_classes),
	.write = &rz_bin_write_mach0,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_mach064,
	.version = RZ_VERSION
};
#endif
