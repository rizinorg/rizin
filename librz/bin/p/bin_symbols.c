// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <ht_uu.h>
#include "../i/private.h"
#include "mach0/coresymbolication.h"

// enable debugging messages
#define D              if (0)
#define RZ_UUID_LENGTH 33

typedef struct symbols_header_t {
	ut32 magic;
	ut32 version;
	ut8 uuid[16];
	ut32 unk0;
	ut32 unk1;
	ut32 slotsize;
	ut32 addr;
	bool valid;
	int size;
} SymbolsHeader;

typedef struct symbols_metadata_t { // 0x40
	ut32 cputype;
	ut32 subtype;
	ut32 n_segments;
	ut32 namelen;
	ut32 name;
	bool valid;
	ut32 size;
	//RzList *segments;
	ut32 addr;
	int bits;
	const char *arch;
	const char *cpu;
} SymbolsMetadata;

// header starts at offset 0 and ends at offset 0x40
static SymbolsHeader parseHeader(RzBuffer *buf) {
	ut8 b[64];
	SymbolsHeader sh = { 0 };
	(void)rz_buf_read_at(buf, 0, b, sizeof(b));
	sh.magic = rz_read_le32(b);
	sh.version = rz_read_le32(b + 4);
	sh.valid = sh.magic == 0xff01ff02;
	int i;
	for (i = 0; i < 16; i++) {
		sh.uuid[i] = b[24 + i];
	}
	sh.unk0 = rz_read_le16(b + 0x28);
	sh.unk1 = rz_read_le16(b + 0x2c); // is slotsize + 1 :?
	sh.slotsize = rz_read_le16(b + 0x2e);
	sh.size = 0x40;
	return sh;
}

static const char *typeString(ut32 n, int *bits) {
	*bits = 32;
	if (n == 12) { // CPU_SUBTYPE_ARM_V7) {
		return "arm";
	}
	if (n == 0x0100000c) { // arm64
		*bits = 64;
		return "arm";
	}
	if (n == 0x0200000c) { // arm64-32
		//  TODO: must change bits
		*bits = 64;
		return "arm";
	}
	return "x86";
}

static const char *subtypeString(int n) {
	if (n == 9) { // CPU_SUBTYPE_ARM_V7) {
		return "armv7";
	}
	return "?";
}

// metadata section starts at offset 0x40 and ends around 0xb0 depending on filenamelength
static SymbolsMetadata parseMetadata(RzBuffer *buf, int off) {
	SymbolsMetadata sm = { 0 };
	ut8 b[0x100] = { 0 };
	(void)rz_buf_read_at(buf, off, b, sizeof(b));
	sm.addr = off;
	sm.cputype = rz_read_le32(b);
	sm.arch = typeString(sm.cputype, &sm.bits);
	//  eprintf ("0x%08x  cputype  0x%x -> %s\n", 0x40, sm.cputype, typeString (sm.cputype));
	// bits = (strstr (typeString (sm.cputype, &sm.bits), "64"))? 64: 32;
	sm.subtype = rz_read_le32(b + 4);
	sm.cpu = subtypeString(sm.subtype);
	//  eprintf ("0x%08x  subtype  0x%x -> %s\n", 0x44, sm.subtype, subtypeString (sm.subtype));
	sm.n_segments = rz_read_le32(b + 8);
	// int count = rz_read_le32 (b + 0x48);
	sm.namelen = rz_read_le32(b + 0xc);
	// eprintf ("0x%08x  count    %d\n", 0x48, count);
	// eprintf ("0x%08x  strlen   %d\n", 0x4c, sm.namelen);
	// eprintf ("0x%08x  filename %s\n", 0x50, b + 16);
	int delta = 16;
	//sm.segments = parseSegments (buf, off + sm.namelen + delta, sm.n_segments);
	sm.size = (sm.n_segments * 32) + sm.namelen + delta;

	// hack to detect format
	ut32 nm, nm2, nm3;
	rz_buf_read_at(buf, off + sm.size, (ut8 *)&nm, sizeof(nm));
	rz_buf_read_at(buf, off + sm.size + 4, (ut8 *)&nm2, sizeof(nm2));
	rz_buf_read_at(buf, off + sm.size + 8, (ut8 *)&nm3, sizeof(nm3));
	// eprintf ("0x%x next %x %x %x\n", off + sm.size, nm, nm2, nm3);
	if (rz_read_le32(&nm3) != 0xa1b22b1a) {
		sm.size -= 8;
		//		is64 = true;
	}
	return sm;
}

static void printSymbolsHeader(SymbolsHeader sh) {
	// eprintf ("0x%08x  version  0x%x\n", 4, sh.version);
	eprintf("0x%08x  uuid     ", 24);
	int i;
	for (i = 0; i < 16; i++) {
		eprintf("%02x", sh.uuid[i]);
	}
	eprintf("\n");
	// parse header
	// eprintf ("0x%08x  unknown  0x%x\n", 0x28, sh.unk0); //rz_read_le32 (b+ 0x28));
	// eprintf ("0x%08x  unknown  0x%x\n", 0x2c, sh.unk1); //rz_read_le16 (b+ 0x2c));
	// eprintf ("0x%08x  slotsize %d\n", 0x2e, sh.slotsize); // rz_read_le16 (b+ 0x2e));
}

static RzBinSection *bin_section_from_section(RzCoreSymCacheElementSection *sect) {
	if (!sect->name) {
		return NULL;
	}
	RzBinSection *s = RZ_NEW0(RzBinSection);
	if (!s) {
		return NULL;
	}
	s->name = rz_str_ndup(sect->name, 256);
	s->size = sect->size;
	s->vsize = s->size;
	s->paddr = sect->paddr;
	s->vaddr = sect->vaddr;
	s->add = true;
	s->perm = strstr(s->name, "TEXT") ? 5 : 4;
	s->is_segment = false;
	return s;
}

static RzBinSection *bin_section_from_segment(RzCoreSymCacheElementSegment *seg) {
	if (!seg->name) {
		return NULL;
	}
	RzBinSection *s = RZ_NEW0(RzBinSection);
	if (!s) {
		return NULL;
	}
	s->name = rz_str_ndup(seg->name, 16);
	s->size = seg->size;
	s->vsize = seg->vsize;
	s->paddr = seg->paddr;
	s->vaddr = seg->vaddr;
	s->add = true;
	s->perm = strstr(s->name, "TEXT") ? 5 : 4;
	s->is_segment = true;
	return s;
}

static RzBinSymbol *bin_symbol_from_symbol(RzCoreSymCacheElement *element, RzCoreSymCacheElementSymbol *s) {
	if (!s->name && !s->mangled_name) {
		return NULL;
	}
	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (sym) {
		if (s->name && s->mangled_name) {
			sym->dname = strdup(s->name);
			sym->name = strdup(s->mangled_name);
		} else if (s->name) {
			sym->name = strdup(s->name);
		} else if (s->mangled_name) {
			sym->name = s->mangled_name;
		}
		sym->paddr = s->paddr;
		sym->vaddr = rz_coresym_cache_element_pa2va(element, s->paddr);
		sym->size = s->size;
		sym->type = RZ_BIN_TYPE_FUNC_STR;
		sym->bind = "NONE";
	}
	return sym;
}

static RzCoreSymCacheElement *parseDragons(RzBinFile *bf, RzBuffer *buf, int off, int bits) {
	D eprintf("Dragons at 0x%x\n", off);
	ut64 size = rz_buf_size(buf);
	if (off >= size) {
		return NULL;
	}
	size -= off;
	if (!size) {
		return NULL;
	}
	ut8 *b = malloc(size);
	if (!b) {
		return NULL;
	}
	int available = rz_buf_read_at(buf, off, b, size);
	if (available != size) {
		eprintf("Warning: rz_buf_read_at failed\n");
		return NULL;
	}
#if 0
	// after the list of sections, there's a bunch of unknown
	// data, brobably dwords, and then the same section list again
	// this function aims to parse it.
	0x00000138 |1a2b b2a1 0300 0000 1a2b b2a1 e055 0000| .+.......+...U..
                         n_segments ----.          .--- how many sections ?
	0x00000148 |0100 0000 ca55 0000 0400 0000 1800 0000| .....U..........
	             .---- how many symbols? 0xc7
	0x00000158 |c700 0000 0000 0000 0000 0000 0104 0000| ................
	0x00000168 |250b e803 0000 0100 0000 0000 bd55 0000| %............U..
	0x00000178 |91bb e903 e35a b42c 93a4 340a 8746 9489| .....Z.,..4..F..
	0x00000188 |0cea 4c40 0c00 0000 0900 0000 0000 0000| ..L@............
	0x00000198 |0000 0000 0000 0000 0000 0000 0000 0000| ................
	0x000001a8 |0080 0000 0000 0000 5f5f 5445 5854 0000| ........__TEXT..
	0x000001b8 |0000 0000 0000 0000 0080 0000 0000 0000| ................
	0x000001c8 |0040 0000 0000 0000 5f5f 4441 5441 0000| .@......__DATA..
	0x000001d8 |0000 0000 0000 0000 00c0 0000 0000 0000| ................
	0x000001e8 |0000 0100 0000 0000 5f5f 4c4c 564d 0000| ........__LLVM..
	0x000001f8 |0000 0000 0000 0000 00c0 0100 0000 0000| ................
	0x00000208 |00c0 0000 0000 0000 5f5f 4c49 4e4b 4544| ........__LINKED
	0x00000218 |4954 0000 0000 0000 0000 0000 d069 0000| IT...........i..
#endif
	// eprintf ("Dragon's magic:\n");
	int magicCombo = 0;
	if (!memcmp("\x1a\x2b\xb2\xa1", b, 4)) { // 0x130  ?
		magicCombo++;
	}
	if (!memcmp("\x1a\x2b\xb2\xa1", b + 8, 4)) {
		magicCombo++;
	}
	if (magicCombo != 2) {
		// hack for C22F7494
		available = rz_buf_read_at(buf, off - 8, b, size);
		if (available != size) {
			eprintf("Warning: rz_buf_read_at failed\n");
			return NULL;
		}
		if (!memcmp("\x1a\x2b\xb2\xa1", b, 4)) { // 0x130  ?
			off -= 8;
		} else {
			eprintf("0x%08x  parsing error: invalid magic retry\n", off);
		}
	}
	D eprintf("0x%08x  magic  OK\n", off);
	D {
		const int e0ss = rz_read_le32(b + 12);
		eprintf("0x%08x  eoss   0x%x\n", off + 12, e0ss);
	}
	free(b);
	return rz_coresym_cache_element_new(bf, buf, off + 16, bits);
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
#if 0
	SYMBOLS HEADER

 0	MAGIC	02ff01ff
 4	VERSION 1 (little endian)
 8      ffffffff
16      002b0000 01000000 { 0x2b00, 0x0000 }
24	UUID    16 bytes
40	2621 d85b 2100 2000 0000 0000 0000 0000
56	ffff ffff ffff ff7f 0c00 0000 0900 0000
72	0400 0000 6800 0000 2f76 6172 2f66 6f6c .... 4, 104 /// 104 length string
184
0x000000b8  5f5f 5445 5854 0000 0000 0000 0000 0000 0000 0000 0000 0000 0080 0000 0000 0000  __TEXT..........................
0x000000d8  5f5f 4441 5441 0000 0000 0000 0000 0000 0080 0000 0000 0000 0040 0000 0000 0000  __DATA...................@......
0x000000f8  5f5f 4c4c 564d 0000 0000 0000 0000 0000 00c0 0000 0000 0000 0000 0100 0000 0000  __LLVM..........................
0x00000118  5f5f 4c49 4e4b 4544 4954 0000 0000 0000 00c0 0100 0000 0000 00c0 0000 0000 0000  __LINKEDIT......................

#endif
	// 0 - magic check, version ...
	SymbolsHeader sh = parseHeader(buf);
	if (!sh.valid) {
		eprintf("Invalid headers\n");
		return false;
	}
	printSymbolsHeader(sh);
	SymbolsMetadata sm = parseMetadata(buf, 0x40);
	RzCoreSymCacheElement *element = parseDragons(bf, buf, sm.addr + sm.size, sm.bits);
	if (element) {
		*bin_obj = element;
		return true;
	}
	return false;
}

static RzList *sections(RzBinFile *bf) {
	RzList *res = rz_list_newf((RzListFree)rz_bin_section_free);
	rz_return_val_if_fail(res && bf->o && bf->o->bin_obj, res);
	RzCoreSymCacheElement *element = bf->o->bin_obj;
	size_t i;
	for (i = 0; i < element->hdr->n_segments; i++) {
		RzCoreSymCacheElementSegment *seg = &element->segments[i];
		RzBinSection *s = bin_section_from_segment(seg);
		if (s) {
			rz_list_append(res, s);
		}
	}
	for (i = 0; i < element->hdr->n_sections; i++) {
		RzCoreSymCacheElementSection *sect = &element->sections[i];
		RzBinSection *s = bin_section_from_section(sect);
		if (s) {
			rz_list_append(res, s);
		}
	}
	return res;
}

static ut64 baddr(RzBinFile *bf) {
	return 0LL;
}

static RzBinInfo *info(RzBinFile *bf) {
	SymbolsMetadata sm = parseMetadata(bf->buf, 0x40);
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup(bf->file);
	ret->bclass = strdup("symbols");
	ret->os = strdup("unknown");
	ret->arch = sm.arch ? strdup(sm.arch) : NULL;
	ret->bits = sm.bits;
	ret->type = strdup("Symbols file");
	ret->subsystem = strdup("llvm");
	ret->has_va = true;

	return ret;
}

static bool check_buffer(RzBuffer *b) {
	ut8 buf[4];
	rz_buf_read_at(b, 0, buf, sizeof(buf));
	return !memcmp(buf, "\x02\xff\x01\xff", 4);
}

static RzList *symbols(RzBinFile *bf) {
	RzList *res = rz_list_newf((RzListFree)rz_bin_symbol_free);
	rz_return_val_if_fail(res && bf->o && bf->o->bin_obj, res);
	RzCoreSymCacheElement *element = bf->o->bin_obj;
	size_t i;
	HtUU *hash = ht_uu_new0();
	if (!hash) {
		return res;
	}
	bool found = false;
	for (i = 0; i < element->hdr->n_lined_symbols; i++) {
		RzCoreSymCacheElementSymbol *sym = (RzCoreSymCacheElementSymbol *)&element->lined_symbols[i];
		ht_uu_find(hash, sym->paddr, &found);
		if (found) {
			continue;
		}
		RzBinSymbol *s = bin_symbol_from_symbol(element, sym);
		if (s) {
			rz_list_append(res, s);
			ht_uu_insert(hash, sym->paddr, 1);
		}
	}
	for (i = 0; i < element->hdr->n_symbols; i++) {
		RzCoreSymCacheElementSymbol *sym = &element->symbols[i];
		ht_uu_find(hash, sym->paddr, &found);
		if (found) {
			continue;
		}
		RzBinSymbol *s = bin_symbol_from_symbol(element, sym);
		if (s) {
			rz_list_append(res, s);
		}
	}
	ht_uu_free(hash);
	return res;
}

static ut64 size(RzBinFile *bf) {
	return UT64_MAX;
}

static void destroy(RzBinFile *bf) {
	rz_coresym_cache_element_free(bf->o->bin_obj);
}

static void header(RzBinFile *bf) {
	rz_return_if_fail(bf && bf->o);

	RzCoreSymCacheElement *element = bf->o->bin_obj;
	if (!element) {
		return;
	}

	RzBin *bin = bf->rbin;
	PrintfCallback p = bin->cb_printf;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}

	pj_o(pj);
	pj_kn(pj, "cs_version", element->hdr->version);
	pj_kn(pj, "size", element->hdr->size);
	if (element->file_name) {
		pj_ks(pj, "name", element->file_name);
	}
	if (element->binary_version) {
		pj_ks(pj, "version", element->binary_version);
	}
	char uuidstr[RZ_UUID_LENGTH];
	rz_hex_bin2str(element->hdr->uuid, 16, uuidstr);
	pj_ks(pj, "uuid", uuidstr);
	pj_kn(pj, "segments", element->hdr->n_segments);
	pj_kn(pj, "sections", element->hdr->n_sections);
	pj_kn(pj, "symbols", element->hdr->n_symbols);
	pj_kn(pj, "lined_symbols", element->hdr->n_lined_symbols);
	pj_kn(pj, "line_info", element->hdr->n_line_info);
	pj_end(pj);

	p("%s\n", pj_string(pj));
	pj_free(pj);
}

RzBinPlugin rz_bin_plugin_symbols = {
	.name = "symbols",
	.desc = "Apple Symbols file",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.symbols = &symbols,
	.sections = &sections,
	.size = &size,
	.baddr = &baddr,
	.info = &info,
	.header = &header,
	.destroy = &destroy,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_symbols,
	.version = RZ_VERSION
};
#endif
