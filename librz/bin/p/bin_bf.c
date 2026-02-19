// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define BF_DATA_AREA_VADDR 0x10000
#define BF_DATA_AREA_SIZE  30000

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	return true;
}

static void destroy(RzBinFile *bf) {
	rz_buf_free(bf->o->bin_obj);
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	return rz_pvector_new((RzPVectorFree)rz_bin_string_free);
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->lang = NULL;
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("brainfuck");
	ret->bclass = rz_str_dup("1.0");
	ret->rclass = rz_str_dup("program");
	ret->os = rz_str_dup("any");
	ret->subsystem = rz_str_dup("unknown");
	ret->machine = rz_str_dup("brainfuck");
	ret->arch = rz_str_dup("bf");
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

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinAddr *ptr = NULL;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	ptr->paddr = ptr->vaddr = 0;
	rz_pvector_push(ret, ptr);
	return ret;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzBinMap *map = RZ_NEW0(RzBinMap);
	if (!map) {
		rz_pvector_free(ret);
		return NULL;
	}
	map->paddr = 0;
	map->vaddr = 0;
	map->psize = bf->size;
	map->vsize = bf->size;
	map->perm = RZ_PERM_RWX;
	map->name = rz_str_dup("code");
	rz_pvector_push(ret, map);

	map = RZ_NEW0(RzBinMap);
	if (!map) {
		rz_pvector_free(ret);
		return NULL;
	}
	map->paddr = 0;
	map->vaddr = BF_DATA_AREA_VADDR;
	map->psize = 0;
	map->vsize = BF_DATA_AREA_SIZE;
	map->perm = RZ_PERM_RW;
	map->name = rz_str_dup("mem");
	rz_pvector_push(ret, map);
	return ret;
}

typedef struct {
	ut64 increment;
	ut64 decrement;
	ut64 move_right;
	ut64 move_left;
	ut64 loop_start;
	ut64 loop_end;
	ut64 input;
	ut64 output;
} BfInstrStats;

static void bf_count_instructions(RzBinFile *bf, BfInstrStats *stats) {
	if (!bf->buf) {
		return;
	}

	ut64 size = rz_buf_size(bf->buf);
	for (ut64 i = 0; i < size; i++) {
		ut8 c;
		if (rz_buf_read_at(bf->buf, i, &c, 1) != 1) {
			break;
		}
		switch (c) {
		case '+': stats->increment++; break;
		case '-': stats->decrement++; break;
		case '>': stats->move_right++; break;
		case '<': stats->move_left++; break;
		case '[': stats->loop_start++; break;
		case ']': stats->loop_end++; break;
		case ',': stats->input++; break;
		case '.': stats->output++; break;
		default: break;
		}
	}
}

static void bf_structure_add_instructions(RzStructuredData *parent, const BfInstrStats *stats) {
	RzStructuredData *instr = rz_structured_data_map_add_map(parent, "instructions");
	if (!instr) {
		return;
	}

	rz_structured_data_map_add_unsigned(instr, "increment", stats->increment, false);
	rz_structured_data_map_add_unsigned(instr, "decrement", stats->decrement, false);
	rz_structured_data_map_add_unsigned(instr, "move_right", stats->move_right, false);
	rz_structured_data_map_add_unsigned(instr, "move_left", stats->move_left, false);
	rz_structured_data_map_add_unsigned(instr, "loop_start", stats->loop_start, false);
	rz_structured_data_map_add_unsigned(instr, "loop_end", stats->loop_end, false);
	rz_structured_data_map_add_unsigned(instr, "input", stats->input, false);
	rz_structured_data_map_add_unsigned(instr, "output", stats->output, false);
}

static void bf_structure_add_memory_layout(RzStructuredData *parent) {
	RzStructuredData *mem = rz_structured_data_map_add_map(parent, "memory");
	if (!mem) {
		return;
	}

	rz_structured_data_map_add_unsigned(mem, "data_area", BF_DATA_AREA_VADDR, true);
	rz_structured_data_map_add_unsigned(mem, "data_size", BF_DATA_AREA_SIZE, false);
}

static RzStructuredData *bf_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_map_add_map(info, "bf");
	if (!root) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(root, "file_size", bf->size, false);
	rz_structured_data_map_add_unsigned(root, "entry_point", 0, true);

	BfInstrStats stats = { 0 };
	bf_count_instructions(bf, &stats);

	ut64 total = stats.increment + stats.decrement + stats.move_right +
		stats.move_left + stats.loop_start + stats.loop_end +
		stats.input + stats.output;
	rz_structured_data_map_add_unsigned(root, "total_instructions", total, false);

	bf_structure_add_instructions(root, &stats);
	bf_structure_add_memory_layout(root);

	return info;
}

RzBinPlugin rz_bin_plugin_bf = {
	.name = "bf",
	.desc = "Brainfuck",
	.license = "LGPL3",
	.author = "pancake",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.check_filename = &check_filename,
	.baddr = &baddr,
	.entries = entries,
	.strings = &strings,
	.maps = &maps,
	.info = &info,
	.bin_structure = &bf_structure,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_bf,
	.version = RZ_VERSION
};
#endif
