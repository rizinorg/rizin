// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	return true;
}

static void destroy(RzBinFile *bf) {
	rz_buf_free(bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static RzList /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	return NULL;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->lang = NULL;
	ret->file = bf->file ? strdup(bf->file) : NULL;
	ret->type = strdup("brainfuck");
	ret->bclass = strdup("1.0");
	ret->rclass = strdup("program");
	ret->os = strdup("any");
	ret->subsystem = strdup("unknown");
	ret->machine = strdup("brainfuck");
	ret->arch = strdup("bf");
	ret->has_va = 1;
	ret->bits = 64; // RzIL emulation of bf uses 64bit values
	ret->big_endian = 0;
	ret->dbg_info = 0;

	RZ_LOG_INFO("Brainfuck debugger setup:\n"
		    "f input 128 @ 0x3000\n"
		    "o malloc://128 0x3000\n"
		    "f screen 80*25 @ 0x4000\n"
		    "o malloc://80*25 0x4000\n"
		    "f stack 0x200 @ 0x5000\n"
		    "o malloc://0x200 0x5000\n"
		    "f data 0x1000 @ 0x6000\n"
		    "o malloc://0x1000 0x6000\n"
		    "ar\n" // hack to init
		    "ar brk=stack\n"
		    "ar scr=screen\n"
		    "ar kbd=input\n"
		    "ar ptr=data\n"
		    "e cmd.vprompt=\"pxa 32@stack;pxa 32@screen;pxa 32@data\"\n"
		    "s 0\n"
		    "e asm.bits=32\n"
		    "dL bf\n");
	return ret;
}

static bool check_buffer(RzBuffer *buf) {
	rz_return_val_if_fail(buf, false);

	ut8 tmp[16];
	int read_length = rz_buf_read_at(buf, 0, tmp, sizeof(tmp));
	if (read_length <= 0) {
		return false;
	}

	const ut8 *p = (const ut8 *)tmp;
	int i;
	for (i = 0; i < read_length; i++) {
		switch (p[i]) {
		case '+':
		case '-':
		case '>':
		case '<':
		case '[':
		case ']':
		case ',':
		case '.':
		case ' ':
		case '\n':
		case '\r':
			break;
		default:
			return false;
		}
	}
	return true;
}

static bool check_filename(const char *filename) {
	return rz_str_endswith_icase(filename, ".bf");
}

static RzList /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzList *ret;
	RzBinAddr *ptr = NULL;

	if (!(ret = rz_list_newf(free))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	ptr->paddr = ptr->vaddr = 0;
	rz_list_append(ret, ptr);
	return ret;
}

static RzList /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	RzList *ret = rz_list_newf((RzListFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzBinMap *map = RZ_NEW0(RzBinMap);
	if (!map) {
		rz_list_free(ret);
		return NULL;
	}
	map->paddr = 0;
	map->vaddr = 0;
	map->psize = bf->size;
	map->vsize = bf->size;
	map->perm = RZ_PERM_RWX;
	map->name = strdup("code");
	rz_list_append(ret, map);

	map = RZ_NEW0(RzBinMap);
	if (!map) {
		rz_list_free(ret);
		return NULL;
	}
	map->paddr = 0;
	map->vaddr = 0x10000;
	map->psize = 0;
	map->vsize = 30000;
	map->perm = RZ_PERM_RW;
	map->name = strdup("mem");
	rz_list_append(ret, map);
	return ret;
}

RzBinPlugin rz_bin_plugin_bf = {
	.name = "bf",
	.desc = "brainfuck",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.check_filename = &check_filename,
	.baddr = &baddr,
	.entries = entries,
	.strings = &strings,
	.maps = &maps,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_bf,
	.version = RZ_VERSION
};
#endif
