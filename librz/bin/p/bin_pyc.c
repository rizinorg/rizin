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

static bool init_pyc_cache(RzBinPycObj *pyc, RzBuffer *buf) {
	RzList *shared = rz_list_newf((RzListFree)rz_list_free);
	if (!shared) {
		return false;
	}
	RzList *cobjs = rz_list_newf((RzListFree)free);
	if (!cobjs) {
		rz_list_free(shared);
		return false;
	}
	pyc->interned_table = rz_list_newf((RzListFree)free);
	if (!pyc->interned_table) {
		rz_list_free(shared);
		rz_list_free(cobjs);
		return false;
	}
	rz_list_append(shared, cobjs);
	rz_list_append(shared, pyc->interned_table);
	pyc->shared = shared;
	RzPVector *sections = rz_pvector_new((RzPVectorFree)free);
	if (!sections) {
		rz_list_free(shared);
		return false;
	}
	pyc->sections_cache = sections;
	RzPVector *symbols = rz_pvector_new((RzPVectorFree)free);
	if (!symbols) {
		rz_list_free(shared);
		rz_pvector_free(sections);
		return false;
	}
	pyc->symbols_cache = symbols;
	RzPVector *strings = rz_pvector_new((RzPVectorFree)free);
	if (!strings) {
		rz_list_free(shared);
		return false;
	}
	pyc->strings_cache = strings;

	rz_buf_seek(buf, pyc->code_start_offset, RZ_BUF_SET);
	pyc_get_sections_symbols(pyc, sections, symbols, cobjs, buf, pyc->version.magic);
	return true;
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

	bool error = false;
	bool is_before_py_36 = magic_int_within(ctx->version.magic, 0x9494, 0x0d16, &error);
	if (error) {
		return NULL;
	}

	ret->file = rz_str_dup(arch->file);
	ret->type = rz_str_newf("Python %s byte-compiled file", ctx->version.version);
	ret->bclass = rz_str_dup("Python byte-compiled file");
	ret->rclass = rz_str_dup("pyc");
	ret->arch = rz_str_dup("pyc");
	ret->machine = rz_str_newf("Python %s VM (rev %s)", ctx->version.version,
		ctx->version.revision);
	ret->os = rz_str_dup("any");
	ret->bits = is_before_py_36 ? 16 : 8;
	ret->cpu = rz_str_dup(ctx->version.version); // pass version info in cpu, Asm plugin will get it
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *arch) {
	RzBinPycObj *pyc = arch->o->bin_obj;

	RzPVector *entries = rz_pvector_new((RzPVectorFree)free);
	if (!entries) {
		return NULL;
	}
	RzBinAddr *addr = RZ_NEW0(RzBinAddr);
	if (!addr) {
		rz_pvector_free(entries);
		return NULL;
	}
	ut64 entrypoint = get_entrypoint(arch);
	addr->paddr = entrypoint;
	addr->vaddr = entrypoint;
	rz_buf_seek(arch->buf, entrypoint, RZ_IO_SEEK_SET);
	rz_pvector_push(entries, addr);

	if (!init_pyc_cache(pyc, arch->buf)) {
		rz_pvector_free(entries);
		return NULL;
	}
	return entries;
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *arch) {
	RzBinPycObj *ctx = arch->o->bin_obj;
	return ctx->sections_cache;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *arch) {
	RzBinPycObj *pyc = arch->o->bin_obj;
	return pyc->symbols_cache;
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinPycObj *pyc = bf->o->bin_obj;
	return pyc->strings_cache;
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
	.symbols = &symbols,
	.strings = &strings,
	.destroy = &destroy
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_pyc,
	.version = RZ_VERSION,
};
#endif
