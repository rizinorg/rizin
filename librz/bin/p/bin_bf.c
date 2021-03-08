// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return true;
}

static void destroy(RzBinFile *bf) {
	rz_buf_free(bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static RzList *strings(RzBinFile *bf) {
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
	ret->bits = 32; // 16?
	ret->big_endian = 0;
	ret->dbg_info = 0;
	/* TODO: move this somewhere else */
	eprintf("f input 128 0x3000\n");
	eprintf("o malloc://128 0x3000\n");
	eprintf("f screen 80*25 0x4000\n");
	eprintf("o malloc://80*25 0x4000\n");
	eprintf("f stack 0x200 0x5000\n");
	eprintf("o malloc://0x200 0x5000\n");
	eprintf("f data 0x1000 0x6000\n");
	eprintf("o malloc://0x1000 0x6000\n");
	eprintf("ar\n"); // hack to init
	eprintf("ar brk=stack\n");
	eprintf("ar scr=screen\n");
	eprintf("ar kbd=input\n");
	eprintf("ar ptr=data\n");
	eprintf("\"e cmd.vprompt=pxa 32@stack;pxa 32@screen;pxa 32@data\"\n");
	eprintf("s 0\n");
	eprintf("e asm.bits=32\n");
	eprintf("dL bf\n");
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

static RzList *entries(RzBinFile *bf) {
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

RzBinPlugin rz_bin_plugin_bf = {
	.name = "bf",
	.desc = "brainfuck",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = entries,
	.strings = &strings,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_bf,
	.version = RZ_VERSION
};
#endif
