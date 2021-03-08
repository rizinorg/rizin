// SPDX-FileCopyrightText: 2016-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_lib.h>

#define CHECK4INSTR(b, instr, size) \
	if (!instr(b, 0) || \
		!instr((b), (size)) || \
		!instr((b), (size)*2) || \
		!instr((b), (size)*3)) { \
		return false; \
	}

#define CHECK3INSTR(b, instr, size) \
	if (!instr((b), (size)) || \
		!instr((b), (size)*2) || \
		!instr((b), (size)*3)) { \
		return false; \
	}

static ut64 tmp_entry = UT64_MAX;

static bool rjmp(RzBuffer *b, ut64 addr) {
	return (rz_buf_read8_at(b, addr + 1) & 0xf0) == 0xc0;
}

static bool jmp(RzBuffer *b, ut64 addr) {
	return (rz_buf_read8_at(b, addr) == 0x0c) && (rz_buf_read8_at(b, addr + 1) == 0x94);
}

static ut64 rjmp_dest(ut64 addr, RzBuffer *b) {
	ut64 dst = 2 + addr + rz_buf_read8_at(b, addr) * 2;
	dst += ((rz_buf_read8_at(b, addr + 1) & 0xf) * 2) << 8;
	return dst;
}

static ut64 jmp_dest(RzBuffer *b, ut64 addr) {
	return (rz_buf_read8_at(b, addr + 2) + (rz_buf_read8_at(b, addr + 3) << 8)) * 2;
}

static bool check_buffer_rjmp(RzBuffer *b) {
	CHECK3INSTR(b, rjmp, 4);
	ut64 dst = rjmp_dest(0, b);
	if (dst < 1 || dst > rz_buf_size(b)) {
		return false;
	}
	tmp_entry = dst;
	return true;
}

static bool check_buffer_jmp(RzBuffer *b) {
	CHECK4INSTR(b, jmp, 4);
	ut64 dst = jmp_dest(b, 0);
	if (dst < 1 || dst > rz_buf_size(b)) {
		return false;
	}
	tmp_entry = dst;
	return true;
}

static bool check_buffer(RzBuffer *buf) {
	if (rz_buf_size(buf) < 32) {
		return false;
	}
	if (!rjmp(buf, 0)) {
		return check_buffer_jmp(buf);
	}
	return check_buffer_rjmp(buf);
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer(buf);
}

static void destroy(RzBinFile *bf) {
	rz_buf_free(bf->o->bin_obj);
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBinInfo *bi = RZ_NEW0(RzBinInfo);
	if (bi) {
		bi->file = strdup(bf->file);
		bi->type = strdup("ROM");
		bi->machine = strdup("ATmel");
		bi->os = strdup("avr");
		bi->has_va = 0; // 1;
		bi->has_lit = false;
		bi->arch = strdup("avr");
		bi->bits = 8;
	}
	return bi;
}

static RzList *entries(RzBinFile *bf) {
	RzList *ret;
	RzBinAddr *ptr = NULL;
	if (tmp_entry == UT64_MAX) {
		return false;
	}
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		ut64 addr = tmp_entry;
		ptr->vaddr = ptr->paddr = addr;
		rz_list_append(ret, ptr);
	}
	return ret;
}

static void addsym(RzList *ret, const char *name, ut64 addr) {
	RzBinSymbol *ptr = RZ_NEW0(RzBinSymbol);
	if (ptr) {
		ptr->name = strdup(name ? name : "");
		ptr->paddr = ptr->vaddr = addr;
		ptr->size = 0;
		ptr->ordinal = 0;
		rz_list_append(ret, ptr);
	}
}

static void addptr(RzList *ret, const char *name, ut64 addr, RzBuffer *b) {
	if (b && rjmp(b, 0)) {
		addsym(ret, sdb_fmt("vector.%s", name), addr);
		ut64 ptr_addr = rjmp_dest(addr, b);
		addsym(ret, sdb_fmt("syscall.%s", name), ptr_addr);
	}
}

static RzList *symbols(RzBinFile *bf) {
	RzList *ret = NULL;
	RzBuffer *obj = bf->o->bin_obj;

	if (!(ret = rz_list_newf(free))) {
		return NULL;
	}
	/* atmega8 */
	addptr(ret, "int0", 2, obj);
	addptr(ret, "int1", 4, obj);
	addptr(ret, "timer2cmp", 6, obj);
	addptr(ret, "timer2ovf", 8, obj);
	addptr(ret, "timer1capt", 10, obj);
	addptr(ret, "timer1cmpa", 12, obj);
	return ret;
}

static RzList *strings(RzBinFile *bf) {
	// we dont want to find strings in avr bins because there are lot of false positives
	return NULL;
}

RzBinPlugin rz_bin_plugin_avr = {
	.name = "avr",
	.desc = "ATmel AVR MCUs",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.entries = &entries,
	.symbols = &symbols,
	.check_buffer = &check_buffer,
	.info = &info,
	.strings = &strings,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_avr,
	.version = RZ_VERSION
};
#endif
