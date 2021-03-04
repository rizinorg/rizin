// SPDX-FileCopyrightText: 2016-2020 c0riolis
// SPDX-FileCopyrightText: 2016-2020 x0urc3
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "../format/pyc/pyc.h"

// XXX: to not use globals

static ut64 code_start_offset = 0;
static struct pyc_version version;
/* used from marshall.c */
RzList *interned_table = NULL;
static RzList *sections_cache = NULL;

static bool check_buffer(RzBuffer *b) {
	if (rz_buf_size(b) > 4) {
		ut32 buf;
		rz_buf_read_at(b, 0, (ut8 *)&buf, sizeof(buf));
		version = get_pyc_version(buf);
		return version.magic != -1;
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer(buf);
}

static ut64 get_entrypoint(RzBuffer *buf) {
	ut8 b;
	ut64 result;
	int addr;
	for (addr = 0x8; addr <= 0x10; addr += 0x4) {
		rz_buf_read_at(buf, addr, &b, sizeof(b));
		if (pyc_is_code(b, version.magic)) {
			code_start_offset = addr;
			rz_buf_seek(buf, addr + 1, RZ_BUF_SET);
			if ((result = get_code_object_addr(buf, version.magic)) == 0) {
				return addr;
			}
			return result;
		}
	}
	return 0;
}

static RzBinInfo *info(RzBinFile *arch) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup(arch->file);
	ret->type = rz_str_newf("Python %s byte-compiled file", version.version);
	ret->bclass = strdup("Python byte-compiled file");
	ret->rclass = strdup("pyc");
	ret->arch = strdup("pyc");
	ret->machine = rz_str_newf("Python %s VM (rev %s)", version.version,
		version.revision);
	ret->os = strdup("any");
	ret->bits = version2double(version.version) < 3.6 ? 16 : 8;
	ret->cpu = strdup(version.version); // pass version info in cpu, Asm plugin will get it
	return ret;
}

static RzList *sections(RzBinFile *arch) {
	return sections_cache;
}

static RzList *entries(RzBinFile *arch) {
	RzList *entries = rz_list_newf((RzListFree)free);
	if (!entries) {
		return NULL;
	}
	RzBinAddr *addr = RZ_NEW0(RzBinAddr);
	if (!addr) {
		rz_list_free(entries);
		return NULL;
	}
	ut64 entrypoint = get_entrypoint(arch->buf);
	addr->paddr = entrypoint;
	addr->vaddr = entrypoint;
	rz_buf_seek(arch->buf, entrypoint, RZ_IO_SEEK_SET);
	rz_list_append(entries, addr);
	return entries;
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static RzList *symbols(RzBinFile *arch) {
	RzList *shared = rz_list_newf((RzListFree)rz_list_free);
	if (!shared) {
		return NULL;
	}
	RzList *cobjs = rz_list_newf((RzListFree)free);
	if (!cobjs) {
		rz_list_free(shared);
		return NULL;
	}
	interned_table = rz_list_newf((RzListFree)free);
	if (!interned_table) {
		rz_list_free(shared);
		rz_list_free(cobjs);
		return NULL;
	}
	rz_list_append(shared, cobjs);
	rz_list_append(shared, interned_table);
	arch->o->bin_obj = shared;
	RzList *sections = rz_list_newf((RzListFree)free);
	if (!sections) {
		rz_list_free(shared);
		arch->o->bin_obj = NULL;
		return NULL;
	}
	RzList *symbols = rz_list_newf((RzListFree)free);
	if (!symbols) {
		rz_list_free(shared);
		arch->o->bin_obj = NULL;
		rz_list_free(sections);
		return NULL;
	}
	RzBuffer *buffer = arch->buf;
	rz_buf_seek(buffer, code_start_offset, RZ_BUF_SET);
	pyc_get_sections_symbols(sections, symbols, cobjs, buffer, version.magic);
	sections_cache = sections;
	return symbols;
}

RzBinPlugin rz_bin_plugin_pyc = {
	.name = "pyc",
	.desc = "Python byte-compiled file plugin",
	.license = "LGPL3",
	.info = &info,
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.sections = &sections,
	.baddr = &baddr,
	.symbols = &symbols,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_pyc,
	.version = RZ_VERSION,
};
#endif
