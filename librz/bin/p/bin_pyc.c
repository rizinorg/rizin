// SPDX-FileCopyrightText: 2016-2020 c0riolis
// SPDX-FileCopyrightText: 2016-2020 x0urc3
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "../format/pyc/pyc.h"

static bool check_buffer(RzBuffer *b) {
	if (rz_buf_size(b) > 4) {
		ut32 magic = 0;
		rz_buf_read_le32_at(b, 0, &magic);
		struct pyc_version version = get_pyc_version(magic);
		return version.magic != -1;
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	RzBinPycObj *ctx = RZ_NEW0(RzBinPycObj);
	if (!ctx) {
		return false;
	}
	ut32 magic = 0;
	rz_buf_read_le32_at(buf, 0, &magic);
	ctx->version = get_pyc_version(magic);
	obj->bin_obj = ctx;
	return true;
}

static ut64 get_entrypoint(RzBinFile *arch) {
	RzBinPycObj *pyc = arch->o->bin_obj;
	RzBuffer *buf = arch->buf;
	ut8 b;
	ut64 result;
	int addr;
	for (addr = 0x8; addr <= 0x10; addr += 0x4) {
		rz_buf_read_at(buf, addr, &b, sizeof(b));
		if (pyc_is_code(b, pyc->version.magic)) {
			pyc->code_start_offset = addr;
			rz_buf_seek(buf, addr + 1, RZ_BUF_SET);
			if ((result = get_code_object_addr(pyc, buf, pyc->version.magic)) == 0) {
				return addr;
			}
			return result;
		}
	}
	return 0;
}

static RzBinInfo *info(RzBinFile *arch) {
	RzBinPycObj *ctx = arch->o->bin_obj;
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup(arch->file);
	ret->type = rz_str_newf("Python %s byte-compiled file", ctx->version.version);
	ret->bclass = strdup("Python byte-compiled file");
	ret->rclass = strdup("pyc");
	ret->arch = strdup("pyc");
	ret->machine = rz_str_newf("Python %s VM (rev %s)", ctx->version.version,
		ctx->version.revision);
	ret->os = strdup("any");
	ret->bits = version2double(ctx->version.version) < 3.6 ? 16 : 8;
	ret->cpu = strdup(ctx->version.version); // pass version info in cpu, Asm plugin will get it
	return ret;
}

static RzList /*<RzBinSection *>*/ *sections(RzBinFile *arch) {
	RzBinPycObj *ctx = arch->o->bin_obj;
	return ctx->sections_cache;
}

static RzList /*<RzBinAddr *>*/ *entries(RzBinFile *arch) {
	RzList *entries = rz_list_newf((RzListFree)free);
	if (!entries) {
		return NULL;
	}
	RzBinAddr *addr = RZ_NEW0(RzBinAddr);
	if (!addr) {
		rz_list_free(entries);
		return NULL;
	}
	ut64 entrypoint = get_entrypoint(arch);
	addr->paddr = entrypoint;
	addr->vaddr = entrypoint;
	rz_buf_seek(arch->buf, entrypoint, RZ_IO_SEEK_SET);
	rz_list_append(entries, addr);
	return entries;
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static RzList /*<RzBinSymbol *>*/ *symbols(RzBinFile *arch) {
	RzBinPycObj *pyc = arch->o->bin_obj;
	RzList *shared = rz_list_newf((RzListFree)rz_list_free);
	if (!shared) {
		return NULL;
	}
	RzList *cobjs = rz_list_newf((RzListFree)free);
	if (!cobjs) {
		rz_list_free(shared);
		return NULL;
	}
	pyc->interned_table = rz_list_newf((RzListFree)free);
	if (!pyc->interned_table) {
		rz_list_free(shared);
		rz_list_free(cobjs);
		return NULL;
	}
	rz_list_append(shared, cobjs);
	rz_list_append(shared, pyc->interned_table);
	pyc->shared = shared;
	RzList *sections = rz_list_newf((RzListFree)free);
	if (!sections) {
		rz_list_free(shared);
		return NULL;
	}
	RzList *symbols = rz_list_newf((RzListFree)free);
	if (!symbols) {
		rz_list_free(shared);
		rz_list_free(sections);
		return NULL;
	}
	RzBuffer *buffer = arch->buf;
	rz_buf_seek(buffer, pyc->code_start_offset, RZ_BUF_SET);
	pyc_get_sections_symbols(pyc, sections, symbols, cobjs, buffer, pyc->version.magic);
	pyc->sections_cache = sections;
	return symbols;
}

static void destroy(RzBinFile *bf) {
	RzBinPycObj *pyc = bf->o->bin_obj;
	rz_list_free(pyc->shared);
	RZ_FREE(bf->o->bin_obj);
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
	.populate_symbols = &symbols,
	.destroy = &destroy
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_pyc,
	.version = RZ_VERSION,
};
#endif
