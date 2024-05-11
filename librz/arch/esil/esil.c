// SPDX-FileCopyrightText: 2014-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014-2021 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_bind.h>

#define FLG(x) RZ_ANALYSIS_ESIL_FLAG_##x
#define cpuflag(x, y) \
	if (esil) { \
		if (y) { \
			RZ_BIT_SET(&esil->flags, FLG(x)); \
		} else { \
			RZ_BIT_UNSET(&esil->flags, FLG(x)); \
		} \
	}

/* Returns the number that has bits + 1 least significant bits set. */
static inline ut64 genmask(int bits) {
	ut64 m = UT64_MAX;
	if (bits > 0 && bits < 64) {
		m = (ut64)(((ut64)(2) << bits) - 1);
		if (!m) {
			m = UT64_MAX;
		}
	}
	return m;
}

#define ESIL_LOG(fmtstr, ...) \
	if (esil->verbose) { \
		RZ_LOG_WARN(fmtstr, ##__VA_ARGS__); \
	}

static bool isnum(RzAnalysisEsil *esil, const char *str, ut64 *num) {
	if (!esil || !str) {
		return false;
	}
	if (IS_DIGIT(*str)) {
		if (num) {
			*num = rz_num_get(NULL, str);
		}
		return true;
	}
	if (num) {
		*num = 0;
	}
	return false;
}

static bool ispackedreg(RzAnalysisEsil *esil, const char *str) {
	RzRegItem *ri = rz_reg_get(esil->analysis->reg, str, -1);
	return ri ? ri->packed_size > 0 : false;
}

static bool isregornum(RzAnalysisEsil *esil, const char *str, ut64 *num) {
	if (!rz_analysis_esil_reg_read(esil, str, num, NULL)) {
		if (!isnum(esil, str, num)) {
			return false;
		}
	}
	return true;
}

/* pop Register or Number */
static bool popRN(RzAnalysisEsil *esil, ut64 *n) {
	char *str = rz_analysis_esil_pop(esil);
	if (str) {
		bool ret = isregornum(esil, str, n);
		free(str);
		return ret;
	}
	return false;
}

/* RZ_ANALYSIS_ESIL API */

RZ_API RzAnalysisEsil *rz_analysis_esil_new(int stacksize, int iotrap, unsigned int addrsize) {
	RzAnalysisEsil *esil = RZ_NEW0(RzAnalysisEsil);
	if (!esil) {
		return NULL;
	}
	if (stacksize < 3) {
		free(esil);
		return NULL;
	}
	if (!(esil->stack = calloc(sizeof(char *), stacksize))) {
		free(esil);
		return NULL;
	}
	esil->verbose = false;
	esil->stacksize = stacksize;
	esil->parse_goto_count = RZ_ANALYSIS_ESIL_GOTO_LIMIT;
	esil->ops = ht_sp_new(HT_STR_DUP, NULL, free);
	esil->iotrap = iotrap;
	esil->in_cmd_step = false;
	rz_analysis_esil_sources_init(esil);
	rz_analysis_esil_interrupts_init(esil);
	esil->addrmask = genmask(addrsize - 1);
	rz_strbuf_init(&esil->current_opstr);
	return esil;
}

RZ_API bool rz_analysis_esil_set_op(RzAnalysisEsil *esil, const char *op, RzAnalysisEsilOpCb code, ut32 push, ut32 pop, ut32 type) {
	rz_return_val_if_fail(code && RZ_STR_ISNOTEMPTY(op) && esil && esil->ops, false);
	RzAnalysisEsilOp *eop = ht_sp_find(esil->ops, op, NULL);
	if (!eop) {
		eop = RZ_NEW(RzAnalysisEsilOp);
		if (!eop) {
			RZ_LOG_ERROR("Cannot allocate esil-operation %s\n", op);
			return false;
		}
		if (!ht_sp_insert(esil->ops, op, eop, NULL)) {
			RZ_LOG_ERROR("Cannot set esil-operation %s\n", op);
			free(eop);
			return false;
		}
	}
	eop->push = push;
	eop->pop = pop;
	eop->type = type;
	eop->code = code;
	return true;
}

static bool rz_analysis_esil_fire_trap(RzAnalysisEsil *esil, int trap_type, int trap_code) {
	rz_return_val_if_fail(esil, false);
	if (esil->cmd) {
		if (esil->cmd(esil, esil->cmd_trap, trap_type, trap_code)) {
			return true;
		}
	}
	if (esil->analysis) {
		RzAnalysisPlugin *ap = esil->analysis->cur;
		if (ap && ap->esil_trap) {
			if (ap->esil_trap(esil, trap_type, trap_code)) {
				return true;
			}
		}
	}
	return false;
}

RZ_API bool rz_analysis_esil_set_pc(RzAnalysisEsil *esil, ut64 addr) {
	if (esil) {
		esil->address = addr;
		return true;
	}
	return false;
}

RZ_API void rz_analysis_esil_free(RzAnalysisEsil *esil) {
	if (!esil) {
		return;
	}
	if (esil->analysis && esil == esil->analysis->esil) {
		esil->analysis->esil = NULL;
	}
	ht_sp_free(esil->ops);
	esil->ops = NULL;
	rz_analysis_esil_interrupts_fini(esil);
	rz_analysis_esil_sources_fini(esil);
	sdb_free(esil->stats);
	esil->stats = NULL;
	rz_analysis_esil_stack_free(esil);
	free(esil->stack);
	if (esil->analysis && esil->analysis->cur && esil->analysis->cur->esil_fini) {
		esil->analysis->cur->esil_fini(esil);
	}
	rz_strbuf_fini(&esil->current_opstr);
	rz_analysis_esil_trace_free(esil->trace);
	esil->trace = NULL;
	free(esil->cmd_intr);
	free(esil->cmd_trap);
	free(esil->cmd_mdev);
	free(esil->cmd_todo);
	free(esil->cmd_step);
	free(esil->cmd_step_out);
	free(esil->cmd_ioer);
	free(esil);
}

static ut8 esil_internal_sizeof_reg(RzAnalysisEsil *esil, const char *r) {
	rz_return_val_if_fail(esil && esil->analysis && esil->analysis->reg && r, 0);
	RzRegItem *ri = rz_reg_get(esil->analysis->reg, r, -1);
	return ri ? ri->size : 0;
}

static int internal_esil_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	rz_return_val_if_fail(esil && esil->analysis && esil->analysis->iob.io, 0);

	addr &= esil->addrmask;
	if (esil->cmd_mdev && esil->mdev_range) {
		if (rz_str_range_in(esil->mdev_range, addr)) {
			if (esil->cmd(esil, esil->cmd_mdev, addr, 0)) {
				return true;
			}
		}
	}
	// TODO: Check if error return from read_at.(on previous version of r2 this call always return len)
	(void)esil->analysis->iob.read_at(esil->analysis->iob.io, addr, buf, len);
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, read_at return true/false can't be used to check error vs len
	if (!esil->analysis->iob.is_valid_offset(esil->analysis->iob.io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = RZ_ANALYSIS_TRAP_READ_ERR;
			esil->trap_code = addr;
		}
		if (esil->cmd && esil->cmd_ioer && *esil->cmd_ioer) {
			esil->cmd(esil, esil->cmd_ioer, esil->address, 0);
		}
	}
	return len;
}

static int internal_esil_mem_read_no_null(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	rz_return_val_if_fail(esil && esil->analysis && esil->analysis->iob.io, 0);

	addr &= esil->addrmask;
	// TODO: Check if error return from read_at.(on previous version of r2 this call always return len)
	(void)esil->analysis->iob.read_at(esil->analysis->iob.io, addr, buf, len);
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, read_at return true/false can't be used to check error vs len
	if (!esil->analysis->iob.is_valid_offset(esil->analysis->iob.io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = RZ_ANALYSIS_TRAP_READ_ERR;
			esil->trap_code = addr;
		}
	}
	return len;
}

RZ_API int rz_analysis_esil_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	int ret = 0;
	rz_return_val_if_fail(buf && esil, 0);
	addr &= esil->addrmask;
	if (esil->cb.hook_mem_read) {
		ret = esil->cb.hook_mem_read(esil, addr, buf, len);
	}
	if (!ret && esil->cb.mem_read) {
		ret = esil->cb.mem_read(esil, addr, buf, len);
		if (ret != len) {
			if (esil->iotrap) {
				esil->trap = RZ_ANALYSIS_TRAP_READ_ERR;
				esil->trap_code = addr;
			}
		}
	}
	return ret;
}

static int internal_esil_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int ret = 0;
	if (!esil || !esil->analysis || !esil->analysis->iob.io || esil->nowrite) {
		return 0;
	}
	addr &= esil->addrmask;
	if (esil->cmd_mdev && esil->mdev_range) {
		if (rz_str_range_in(esil->mdev_range, addr)) {
			if (esil->cmd(esil, esil->cmd_mdev, addr, 1)) {
				return true;
			}
		}
	}
	if (esil->analysis->iob.write_at(esil->analysis->iob.io, addr, buf, len)) {
		ret = len;
	}
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, write_at return true/false can't be used to check error vs len
	if (!esil->analysis->iob.is_valid_offset(esil->analysis->iob.io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = RZ_ANALYSIS_TRAP_WRITE_ERR;
			esil->trap_code = addr;
		}
		if (esil->cmd && esil->cmd_ioer && *esil->cmd_ioer) {
			esil->cmd(esil, esil->cmd_ioer, esil->address, 0);
		}
	}
	return ret;
}

static int internal_esil_mem_write_no_null(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int ret = 0;
	if (!esil || !esil->analysis || !esil->analysis->iob.io || !addr) {
		return 0;
	}
	if (esil->nowrite) {
		return 0;
	}
	addr &= esil->addrmask;
	if (esil->analysis->iob.write_at(esil->analysis->iob.io, addr, buf, len)) {
		ret = len;
	}
	// check if request address is mapped , if don't fire trap and esil ioer callback
	// now with siol, write_at return true/false can't be used to check error vs len
	if (!esil->analysis->iob.is_valid_offset(esil->analysis->iob.io, addr, false)) {
		if (esil->iotrap) {
			esil->trap = RZ_ANALYSIS_TRAP_WRITE_ERR;
			esil->trap_code = addr;
		}
	}
	return ret;
}

RZ_API int rz_analysis_esil_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	rz_return_val_if_fail(esil && buf, 0);
	int ret = 0;
	addr &= esil->addrmask;
	if (esil->cb.hook_mem_write) {
		ret = esil->cb.hook_mem_write(esil, addr, buf, len);
	}
	if (!ret && esil->cb.mem_write) {
		ret = esil->cb.mem_write(esil, addr, buf, len);
	}
	return ret;
}

static int internal_esil_reg_read(RzAnalysisEsil *esil, const char *regname, ut64 *num, int *size) {
	RzRegItem *reg = rz_reg_get(esil->analysis->reg, regname, -1);
	if (reg) {
		if (size) {
			*size = reg->size;
		}
		if (num) {
			*num = rz_reg_get_value(esil->analysis->reg, reg);
		}
		return true;
	}
	return false;
}

static int internal_esil_reg_write(RzAnalysisEsil *esil, const char *regname, ut64 num) {
	if (esil && esil->analysis) {
		RzRegItem *reg = rz_reg_get(esil->analysis->reg, regname, -1);
		if (reg) {
			rz_reg_set_value(esil->analysis->reg, reg, num);
			return true;
		}
	}
	return false;
}

static int internal_esil_reg_write_no_null(RzAnalysisEsil *esil, const char *regname, ut64 num) {
	rz_return_val_if_fail(esil && esil->analysis && esil->analysis->reg, false);

	RzRegItem *reg = rz_reg_get(esil->analysis->reg, regname, -1);
	const char *pc = rz_reg_get_name(esil->analysis->reg, RZ_REG_NAME_PC);
	const char *sp = rz_reg_get_name(esil->analysis->reg, RZ_REG_NAME_SP);
	const char *bp = rz_reg_get_name(esil->analysis->reg, RZ_REG_NAME_BP);

	if (!pc) {
		RZ_LOG_WARN("RzReg profile does not contain PC register\n");
		return false;
	}
	if (!sp) {
		RZ_LOG_WARN("RzReg profile does not contain SP register\n");
		return false;
	}
	if (!bp) {
		RZ_LOG_WARN("RzReg profile does not contain BP register\n");
		return false;
	}
	if (reg && reg->name && ((strcmp(reg->name, pc) && strcmp(reg->name, sp) && strcmp(reg->name, bp)) || num)) { // I trust k-maps
		rz_reg_set_value(esil->analysis->reg, reg, num);
		return true;
	}
	return false;
}

RZ_API bool rz_analysis_esil_pushnum(RzAnalysisEsil *esil, ut64 num) {
	char str[64];
	snprintf(str, sizeof(str) - 1, "0x%" PFMT64x, num);
	return rz_analysis_esil_push(esil, str);
}

RZ_API bool rz_analysis_esil_push(RzAnalysisEsil *esil, const char *str) {
	if (!str || !esil || !*str || esil->stackptr > (esil->stacksize - 1)) {
		return false;
	}
	esil->stack[esil->stackptr++] = strdup(str);
	return true;
}

RZ_API char *rz_analysis_esil_pop(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil, NULL);
	if (esil->stackptr < 1) {
		return NULL;
	}
	return esil->stack[--esil->stackptr];
}

RZ_API int rz_analysis_esil_get_parm_type(RzAnalysisEsil *esil, const char *str) {
	int len, i;

	if (!str || !(len = strlen(str))) {
		return RZ_ANALYSIS_ESIL_PARM_INVALID;
	}
	if (!strncmp(str, "0x", 2)) {
		return RZ_ANALYSIS_ESIL_PARM_NUM;
	}
	if (!((IS_DIGIT(str[0])) || str[0] == '-')) {
		goto not_a_number;
	}
	for (i = 1; i < len; i++) {
		if (!(IS_DIGIT(str[i]))) {
			goto not_a_number;
		}
	}
	return RZ_ANALYSIS_ESIL_PARM_NUM;
not_a_number:
	if (rz_reg_get(esil->analysis->reg, str, -1)) {
		return RZ_ANALYSIS_ESIL_PARM_REG;
	}
	return RZ_ANALYSIS_ESIL_PARM_INVALID;
}

RZ_API int rz_analysis_esil_get_parm_size(RzAnalysisEsil *esil, const char *str, ut64 *num, int *size) {
	if (!str || !*str) {
		return false;
	}
	int parm_type = rz_analysis_esil_get_parm_type(esil, str);
	if (!num || !esil) {
		return false;
	}
	switch (parm_type) {
	case RZ_ANALYSIS_ESIL_PARM_NUM:
		*num = rz_num_get(NULL, str);
		if (size) {
			*size = esil->analysis->bits;
		}
		return true;
	case RZ_ANALYSIS_ESIL_PARM_REG:
		if (!rz_analysis_esil_reg_read(esil, str, num, size)) {
			break;
		}
		return true;
	default:
		ESIL_LOG("Invalid arg (%s)\n", str);
		esil->parse_stop = 1;
		break;
	}
	return false;
}

RZ_API int rz_analysis_esil_get_parm(RzAnalysisEsil *esil, const char *str, ut64 *num) {
	return rz_analysis_esil_get_parm_size(esil, str, num, NULL);
}

RZ_API int rz_analysis_esil_reg_write(RzAnalysisEsil *esil, const char *dst, ut64 num) {
	int ret = 0;
	if (esil && esil->cb.hook_reg_write) {
		ret = esil->cb.hook_reg_write(esil, dst, &num);
	}
	if (!ret && esil && esil->cb.reg_write) {
		ret = esil->cb.reg_write(esil, dst, num);
	}
	return ret;
}

RZ_API int rz_analysis_esil_reg_read_nocallback(RzAnalysisEsil *esil, const char *regname, ut64 *num, int *size) {
	int ret;
	void *old_hook_reg_read = (void *)esil->cb.hook_reg_read;
	esil->cb.hook_reg_read = NULL;
	ret = rz_analysis_esil_reg_read(esil, regname, num, size);
	esil->cb.hook_reg_read = old_hook_reg_read;
	return ret;
}

RZ_API int rz_analysis_esil_reg_read(RzAnalysisEsil *esil, const char *regname, ut64 *num, int *size) {
	bool ret = false;
	ut64 localnum; // XXX why is this necessary?
	if (!esil || !regname) {
		return false;
	}
	if (!num) {
		num = &localnum;
	}
	*num = 0LL;
	if (size) {
		*size = esil->analysis->bits;
	}
	if (esil->cb.hook_reg_read) {
		ret = esil->cb.hook_reg_read(esil, regname, num, size);
	}
	if (!ret && esil->cb.reg_read) {
		ret = esil->cb.reg_read(esil, regname, num, size);
	}
	return ret;
}

RZ_API int rz_analysis_esil_signext(RzAnalysisEsil *esil, bool assign) {
	bool ret = false;
	ut64 src, dst;

	char *p_src = rz_analysis_esil_pop(esil);
	if (!p_src) {
		return false;
	}

	if (!rz_analysis_esil_get_parm(esil, p_src, &src)) {
		ESIL_LOG("esil_of: empty stack\n");
		free(p_src);
		return false;
	}

	char *p_dst = rz_analysis_esil_pop(esil);
	if (!p_dst) {
		free(p_src);
		return false;
	}

	if (!rz_analysis_esil_get_parm(esil, p_dst, &dst)) {
		ESIL_LOG("esil_of: empty stack\n");
		free(p_dst);
		free(p_src);
		return false;
	} else {
		free(p_dst);
	}

	// Make sure the other bits are 0
	src &= UT64_MAX >> (64 - dst);

	ut64 m = 0;
	if (dst < 64) {
		m = 1ULL << (dst - 1);
	}

	// dst = (dst & ((1U << src_bit) - 1)); // clear upper bits
	if (assign) {
		ret = rz_analysis_esil_reg_write(esil, p_src, ((src ^ m) - m));
	} else {
		ret = rz_analysis_esil_pushnum(esil, ((src ^ m) - m));
	}

	free(p_src);
	return ret;
}

// sign extension operator for use in idiv, imul, movsx*
// and other instructions involving signed values, extends n bit value to 64 bit value
// example : >"ae 8,0x81,~" ( <src bit width>,<value>,~ )
// output  : 0xffffffffffffff81
static bool esil_signext(RzAnalysisEsil *esil) {
	return rz_analysis_esil_signext(esil, false);
}

// sign extension assignement
// example : > "ae 0x81,a0,="
//           > "ae 8,a0,~="   ( <src bit width>,register,~= )
// output  : > ar a0
//           0xffffff81
static bool esil_signexteq(RzAnalysisEsil *esil) {
	return rz_analysis_esil_signext(esil, true);
}

static bool esil_zf(RzAnalysisEsil *esil) {
	return rz_analysis_esil_pushnum(esil, !(esil->cur & genmask(esil->lastsz - 1)));
}

// checks if there was a carry from bit x (x,$c)
static bool esil_cf(RzAnalysisEsil *esil) {
	char *src = rz_analysis_esil_pop(esil);

	if (!src) {
		return false;
	}

	if (rz_analysis_esil_get_parm_type(esil, src) != RZ_ANALYSIS_ESIL_PARM_NUM) {
		free(src);
		return false;
	}
	ut64 bit;
	rz_analysis_esil_get_parm(esil, src, &bit);
	free(src);
	// carry from bit <src>
	// range of src goes from 0 to 63
	//
	// implements bit mod 64
	const ut64 mask = genmask(bit & 0x3f);
	return rz_analysis_esil_pushnum(esil, (esil->cur & mask) < (esil->old & mask));
}

// checks if there was a borrow from bit x (x,$b)
static bool esil_bf(RzAnalysisEsil *esil) {
	char *src = rz_analysis_esil_pop(esil);

	if (!src) {
		return false;
	}

	if (rz_analysis_esil_get_parm_type(esil, src) != RZ_ANALYSIS_ESIL_PARM_NUM) {
		free(src);
		return false;
	}
	ut64 bit;
	rz_analysis_esil_get_parm(esil, src, &bit);
	free(src);
	// borrow from bit <src>
	// range of src goes from 1 to 64
	//	you cannot borrow from bit 0, bc bit -1 cannot not exist
	//
	// implements (bit - 1) mod 64
	const ut64 mask = genmask((bit + 0x3f) & 0x3f);
	return rz_analysis_esil_pushnum(esil, (esil->old & mask) < (esil->cur & mask));
}

static bool esil_pf(RzAnalysisEsil *esil) {
	// Set if the number of set bits in the least significant _byte_ is a multiple of 2.
	//   - Taken from: https://graphics.stanford.edu/~seander/bithacks.html#ParityWith64Bits
	const ut64 c1 = 0x0101010101010101ULL;
	const ut64 c2 = 0x8040201008040201ULL;
	const ut64 c3 = 0x1FF;
	// Take only the least significant byte.
	ut64 lsb = esil->cur & 0xff;
	return rz_analysis_esil_pushnum(esil, !((((lsb * c1) & c2) % c3) & 1));
}

// like carry
// checks overflow from bit x (x,$o)
//	x,$o ===> x,$c,x-1,$c,^
static bool esil_of(RzAnalysisEsil *esil) {
	char *p_bit = rz_analysis_esil_pop(esil);

	if (!p_bit) {
		return false;
	}

	if (rz_analysis_esil_get_parm_type(esil, p_bit) != RZ_ANALYSIS_ESIL_PARM_NUM) {
		free(p_bit);
		return false;
	}
	ut64 bit;

	if (!rz_analysis_esil_get_parm(esil, p_bit, &bit)) {
		ESIL_LOG("esil_of: empty stack\n");
		free(p_bit);
		return false;
	}
	free(p_bit);

	const ut64 m[2] = { genmask(bit & 0x3f), genmask((bit + 0x3f) & 0x3f) };
	const ut64 result = ((esil->cur & m[0]) < (esil->old & m[0])) ^ ((esil->cur & m[1]) < (esil->old & m[1]));
	ut64 res = rz_analysis_esil_pushnum(esil, result);
	return res;
}

// checks sign bit at x (x,$s)
static bool esil_sf(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil, false);

	char *p_size = rz_analysis_esil_pop(esil);
	rz_return_val_if_fail(p_size, false);

	if (rz_analysis_esil_get_parm_type(esil, p_size) != RZ_ANALYSIS_ESIL_PARM_NUM) {
		free(p_size);
		return false;
	}
	ut64 size, num;
	rz_analysis_esil_get_parm(esil, p_size, &size);
	free(p_size);

	if (size > 63) {
		num = 0;
	} else {
		num = (esil->cur >> size) & 1;
	}
	ut64 res = rz_analysis_esil_pushnum(esil, num);
	return res;
}

static bool esil_ds(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil, false);
	return rz_analysis_esil_pushnum(esil, esil->delay);
}

static bool esil_jt(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil, false);
	return rz_analysis_esil_pushnum(esil, esil->jump_target);
}

static bool esil_js(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil, false);
	return rz_analysis_esil_pushnum(esil, esil->jump_target_set);
}

// TODO: this should be deprecated because it is not accurate
static bool esil_rs(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil && esil->analysis, false);
	return rz_analysis_esil_pushnum(esil, esil->analysis->bits >> 3);
}

// TODO: this should be deprecated because plugins should know their current address
static bool esil_address(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil, false);
	return rz_analysis_esil_pushnum(esil, esil->address);
}

static bool esil_weak_eq(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil && esil->analysis, false);
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);

	if (!(dst && src && (rz_analysis_esil_get_parm_type(esil, dst) == RZ_ANALYSIS_ESIL_PARM_REG))) {
		free(dst);
		free(src);
		return false;
	}

	ut64 src_num;
	if (rz_analysis_esil_get_parm(esil, src, &src_num)) {
		(void)rz_analysis_esil_reg_write(esil, dst, src_num);
		free(src);
		free(dst);
		return true;
	}

	free(src);
	free(dst);
	return false;
}

static bool esil_eq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (!src || !dst) {
		ESIL_LOG("Missing elements in the esil stack for '=' at 0x%08" PFMT64x "\n", esil->address);
		free(src);
		free(dst);
		return false;
	}
	if (ispackedreg(esil, dst)) {
		char *src2 = rz_analysis_esil_pop(esil);
		char *newreg = rz_str_newf("%sl", dst);
		if (rz_analysis_esil_get_parm(esil, src2, &num2)) {
			ret = rz_analysis_esil_reg_write(esil, newreg, num2);
		}
		free(newreg);
		free(src2);
		goto beach;
	}

	if (src && dst && rz_analysis_esil_reg_read_nocallback(esil, dst, &num, NULL)) {
		if (rz_analysis_esil_get_parm(esil, src, &num2)) {
			ret = rz_analysis_esil_reg_write(esil, dst, num2);
			esil->cur = num2;
			esil->old = num;
			esil->lastsz = esil_internal_sizeof_reg(esil, dst);
		} else {
			ESIL_LOG("esil_eq: invalid src\n");
		}
	} else {
		ESIL_LOG("esil_eq: invalid parameters\n");
	}

beach:
	free(src);
	free(dst);
	return ret;
}

static bool esil_neg(RzAnalysisEsil *esil) {
	bool ret = false;
	char *src = rz_analysis_esil_pop(esil);
	if (src) {
		ut64 num;
		if (rz_analysis_esil_get_parm(esil, src, &num)) {
			rz_analysis_esil_pushnum(esil, !num);
			ret = true;
		} else {
			if (isregornum(esil, src, &num)) {
				ret = true;
				rz_analysis_esil_pushnum(esil, !num);
			} else {
				RZ_LOG_ERROR("0x%08" PFMT64x " esil_neg: unknown reg %s\n", esil->address, src);
			}
		}
	} else {
		ESIL_LOG("esil_neg: empty stack\n");
	}
	free(src);
	return ret;
}

static bool esil_negeq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num;
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_reg_read(esil, src, &num, NULL)) {
		num = !num;
		rz_analysis_esil_reg_write(esil, src, num);
		ret = true;
	} else {
		ESIL_LOG("esil_negeq: empty stack\n");
	}
	free(src);
	// rz_analysis_esil_pushnum (esil, ret);
	return ret;
}

static bool esil_nop(RzAnalysisEsil *esil) {
	return true;
}

static bool esil_andeq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_reg_read(esil, dst, &num, NULL)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			esil->old = num;
			esil->cur = num & num2;
			esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			rz_analysis_esil_reg_write(esil, dst, num & num2);
			ret = true;
		} else {
			ESIL_LOG("esil_andeq: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_oreq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_reg_read(esil, dst, &num, NULL)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			esil->old = num;
			esil->cur = num | num2;
			esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			ret = rz_analysis_esil_reg_write(esil, dst, num | num2);
		} else {
			ESIL_LOG("esil_ordeq: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_xoreq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_reg_read(esil, dst, &num, NULL)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			esil->old = num;
			esil->cur = num ^ num2;
			esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			ret = rz_analysis_esil_reg_write(esil, dst, num ^ num2);
		} else {
			ESIL_LOG("esil_xoreq: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

#if 0
static int esil_interrupt_linux_i386(RzAnalysisEsil *esil) { 		//move this into a plugin
	ut32 sn, ret = 0;
	char *usn = rz_analysis_esil_pop (esil);
	if (usn) {
		sn = (ut32) rz_num_get (NULL, usn);
	} else sn = 0x80;

	if (sn == 3) {
		// trap
		esil->trap = RZ_ANALYSIS_TRAP_BREAKPOINT;
		esil->trap_code = 3;
		return -1;
	}

	if (sn != 0x80) {
		RZ_LOG_ERROR("Interrupt 0x%x not handled.\n", sn);
		esil->trap = RZ_ANALYSIS_TRAP_UNHANDLED;
		esil->trap_code = sn;
		return -1;
	}
#undef r
#define r(x) rz_reg_getv(esil->analysis->reg, "##x##")
#undef rs
#define rs(x, y) rz_reg_setv(esil->analysis->reg, "##x##", y)
	switch (r(eax)) {
	case 1:
		printf ("exit(%d)\n", (int)r(ebx));
		rs(eax, -1);
		// never return. stop execution somehow, throw an exception
		break;
	case 3:
		ret = r(edx);
		printf ("ret:%d = read(fd:%"PFMT64d", ptr:0x%08"PFMT64x", len:%"PFMT64d")\n",
			(int)ret, r(ebx), r(ecx), r(edx));
		rs(eax, ret);
		break;
	case 4:
		ret = r(edx);
		printf ("ret:%d = write(fd:%"PFMT64d", ptr:0x%08"PFMT64x", len:%"PFMT64d")\n",
			(int)ret, r(ebx), r(ecx), r(edx));
		rs(eax, ret);
		break;
	case 5:
		ret = -1;
		printf ("fd:%d = open(file:0x%08"PFMT64x", mode:%"PFMT64d", perm:%"PFMT64d")\n",
			(int)ret, r(ebx), r(ecx), r(edx));
		rs(eax, ret);
		break;
	}
#undef r
#undef rs
	return 0;
}
#endif

static bool esil_trap(RzAnalysisEsil *esil) {
	ut64 s, d;
	if (popRN(esil, &s) && popRN(esil, &d)) {
		esil->trap = s;
		esil->trap_code = d;
		return rz_analysis_esil_fire_trap(esil, (int)s, (int)d);
	}
	ESIL_LOG("esil_trap: missing parameters in stack\n");
	return false;
}

static bool esil_bits(RzAnalysisEsil *esil) {
	ut64 s;
	if (popRN(esil, &s)) {
		if (esil->analysis && esil->analysis->coreb.setab) {
			esil->analysis->coreb.setab(esil->analysis->coreb.core, NULL, s);
		}
		return true;
	}
	ESIL_LOG("esil_bits: missing parameters in stack\n");
	return false;
}

static bool esil_interrupt(RzAnalysisEsil *esil) {
	ut64 interrupt;
	if (popRN(esil, &interrupt)) {
		return rz_analysis_esil_fire_interrupt(esil, (ut32)interrupt);
	}
	return false;
}

// This function also sets internal vars which is used in flag calculations.
static bool esil_cmp(RzAnalysisEsil *esil) {
	ut64 num, num2;
	bool ret = false;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm(esil, dst, &num)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = true;
			if (rz_reg_get(esil->analysis->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			} else if (rz_reg_get(esil->analysis->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg(esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
		}
	}
	free(dst);
	free(src);
	return ret;
}

#if 0
x86 documentation:
CF - carry flag -- Set on high-order bit carry or borrow; cleared otherwise
	num>>63
PF - parity flag
	(num&0xff)
    Set if low-order eight bits of result contain an even number of "1" bits; cleared otherwise
ZF - zero flags
    Set if result is zero; cleared otherwise
	zf = num?0:1;
SF - sign flag
    Set equal to high-order bit of result (0 if positive 1 if negative)
	sf = ((st64)num)<0)?1:0;
OF - overflow flag
	if (a>0&&b>0 && (a+b)<0)
    Set if result is too large a positive number or too small a negative number (excluding sign bit) to fit in destination operand; cleared otherwise

JBE: CF = 1 || ZF = 1

#endif

/*
 * Expects a string in the stack. Each char of the string represents a CPU flag.
 * Those relations are associated by the CPU itself and are used to move values
 * from the internal ESIL into the RzReg instance.
 *
 * For example:
 *   zco,?=     # update zf, cf and of
 *
 * If we want to update the esil value of a specific flag we use the =? command
 *
 *    zf,z,=?    # esil[zf] = rz_reg[zf]
 *
 * Defining new cpu flags
 */
#if 0
static int esil_ifset(RzAnalysisEsil *esil) {
	char *s, *src = rz_analysis_esil_pop (esil);
	for (s=src; *s; s++) {
		switch (*s) {
		case 'z':
			rz_analysis_esil_reg_write (esil, "zf", RZ_BIT_CHK(&esil->flags, FLG(ZERO)));
			break;
		case 'c':
			rz_analysis_esil_reg_write (esil, "cf", RZ_BIT_CHK(&esil->flags, FLG(CARRY)));
			break;
		case 'o':
			rz_analysis_esil_reg_write (esil, "of", RZ_BIT_CHK(&esil->flags, FLG(OVERFLOW)));
			break;
		case 'p':
			rz_analysis_esil_reg_write (esil, "pf", RZ_BIT_CHK(&esil->flags, FLG(PARITY)));
			break;
		}
	}
	free (src);
	return 0;
}
#endif

static bool esil_if(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num = 0LL;
	if (esil->skip) {
		esil->skip++;
		return true;
	}
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &num)) {
		// condition not matching, skipping until
		if (!num) {
			esil->skip++;
		}
		ret = true;
	}
	free(src);
	return ret;
}

static bool esil_lsl(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm(esil, dst, &num)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			if (num2 > sizeof(ut64) * 8) {
				ESIL_LOG("esil_lsl: shift is too big\n");
			} else {
				if (num2 > 63) {
					rz_analysis_esil_pushnum(esil, 0);
				} else {
					rz_analysis_esil_pushnum(esil, num << num2);
				}
				ret = true;
			}
		} else {
			ESIL_LOG("esil_lsl: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_lsleq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_reg_read(esil, dst, &num, NULL)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			if (num2 > sizeof(ut64) * 8) {
				ESIL_LOG("esil_lsleq: shift is too big\n");
			} else {
				esil->old = num;
				if (num2 > 63) {
					num = 0;
				} else {
					num <<= num2;
				}
				esil->cur = num;
				esil->lastsz = esil_internal_sizeof_reg(esil, dst);
				rz_analysis_esil_reg_write(esil, dst, num);
				ret = true;
			}
		} else {
			ESIL_LOG("esil_lsleq: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_lsr(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm(esil, dst, &num)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			ut64 res = num >> RZ_MIN(num2, 63);
			rz_analysis_esil_pushnum(esil, res);
			ret = true;
		} else {
			ESIL_LOG("esil_lsr: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_lsreq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_reg_read(esil, dst, &num, NULL)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			if (num2 > 63) {
				ESIL_LOG("Invalid shift at 0x%08" PFMT64x "\n", esil->address);
				num2 = 63;
			}
			esil->old = num;
			num >>= num2;
			esil->cur = num;
			esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			rz_analysis_esil_reg_write(esil, dst, num);
			ret = true;
		} else {
			ESIL_LOG("esil_lsreq: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_asreq(RzAnalysisEsil *esil) {
	bool ret = false;
	int regsize = 0;
	ut64 op_num, param_num;
	char *op = rz_analysis_esil_pop(esil);
	char *param = rz_analysis_esil_pop(esil);
	if (op && rz_analysis_esil_get_parm_size(esil, op, &op_num, &regsize)) {
		if (param && rz_analysis_esil_get_parm(esil, param, &param_num)) {
			ut64 mask = (regsize - 1);
			param_num &= mask;
			bool isNegative;
			if (regsize == 32) {
				isNegative = ((st32)op_num) < 0;
				st32 snum = op_num;
				op_num = snum;
			} else {
				isNegative = ((st64)op_num) < 0;
			}
			if (isNegative) {
				if (regsize == 32) {
					op_num = -(st64)op_num;
					if (op_num >> param_num) {
						op_num >>= param_num;
						op_num = -(st64)op_num;
					} else {
						op_num = -1;
					}
				} else {
					ut64 mask = (regsize - 1);
					param_num &= mask;
					ut64 left_bits = 0;
					int shift = regsize - 1;
					if (shift < 0 || shift > regsize - 1) {
						ESIL_LOG("Invalid asreq shift of %d at 0x%" PFMT64x "\n", shift, esil->address);
						shift = 0;
					}
					if (param_num > regsize - 1) {
						// capstone bug?
						ESIL_LOG("Invalid asreq shift of %" PFMT64d " at 0x%" PFMT64x "\n", param_num, esil->address);
						param_num = 30;
					}
					if (shift >= 63) {
						// LL can't handle LShift of 63 or more
						ESIL_LOG("Invalid asreq shift of %d at 0x%08" PFMT64x "\n", shift, esil->address);
					} else if (op_num & (1LL << shift)) {
						left_bits = (1 << param_num) - 1;
						left_bits <<= regsize - param_num;
					}
					op_num = left_bits | (op_num >> param_num);
				}
			} else {
				op_num >>= param_num;
			}
			ut64 res = op_num;
			esil->cur = res;
			esil->lastsz = esil_internal_sizeof_reg(esil, op);
			rz_analysis_esil_reg_write(esil, op, res);
			// rz_analysis_esil_pushnum (esil, res);
			ret = true;
		} else {
			ESIL_LOG("esil_asr: empty stack\n");
		}
	}
	free(param);
	free(op);
	return ret;
}

static bool esil_asr(RzAnalysisEsil *esil) {
	bool ret = false;
	int regsize = 0;
	ut64 op_num = 0, param_num = 0;
	char *op = rz_analysis_esil_pop(esil);
	char *param = rz_analysis_esil_pop(esil);
	if (op && rz_analysis_esil_get_parm_size(esil, op, &op_num, &regsize)) {
		if (param && rz_analysis_esil_get_parm(esil, param, &param_num)) {
			if (param_num > regsize - 1) {
				// capstone bug?
				ESIL_LOG("Invalid asr shift of %" PFMT64d " at 0x%" PFMT64x "\n", param_num, esil->address);
				param_num = 30;
			}
			bool isNegative;
			if (regsize == 32) {
				isNegative = ((st32)op_num) < 0;
				st32 snum = op_num;
				op_num = snum;
			} else {
				isNegative = ((st64)op_num) < 0;
			}
			if (isNegative) {
				ut64 mask = (regsize - 1);
				param_num &= mask;
				ut64 left_bits = 0;
				if (op_num & (1ULL << (regsize - 1))) {
					left_bits = (1ULL << param_num) - 1;
					left_bits <<= regsize - param_num;
				}
				op_num = left_bits | (op_num >> param_num);
			} else {
				op_num >>= param_num;
			}
			ut64 res = op_num;
			rz_analysis_esil_pushnum(esil, res);
			ret = true;
		} else {
			ESIL_LOG("esil_asr: empty stack\n");
		}
	}
	free(param);
	free(op);
	return ret;
}

static bool esil_ror(RzAnalysisEsil *esil) {
	bool ret = 0;
	int regsize;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm_size(esil, dst, &num, &regsize)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			ut64 mask = (regsize - 1);
			num2 &= mask;
			ut64 res = (num >> num2) | (num << ((-(st64)num2) & mask));
			rz_analysis_esil_pushnum(esil, res);
			ret = true;
		} else {
			ESIL_LOG("esil_ror: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_rol(RzAnalysisEsil *esil) {
	bool ret = 0;
	int regsize;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm_size(esil, dst, &num, &regsize)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			ut64 mask = (regsize - 1);
			num2 &= mask;
			ut64 res = (num << num2) | (num >> ((-(st64)num2) & mask));
			rz_analysis_esil_pushnum(esil, res);
			ret = true;
		} else {
			ESIL_LOG("esil_rol: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_and(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm(esil, dst, &num)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			num &= num2;
			rz_analysis_esil_pushnum(esil, num);
			ret = true;
		} else {
			ESIL_LOG("esil_and: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_xor(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm(esil, dst, &num)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			num ^= num2;
			rz_analysis_esil_pushnum(esil, num);
			ret = true;
		} else {
			ESIL_LOG("esil_xor: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_or(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 num, num2;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm(esil, dst, &num)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			num |= num2;
			rz_analysis_esil_pushnum(esil, num);
			ret = true;
		} else {
			ESIL_LOG("esil_xor: empty stack\n");
		}
	}
	free(src);
	free(dst);
	return ret;
}

RZ_API const char *rz_analysis_esil_trapstr(int type) {
	switch (type) {
	case RZ_ANALYSIS_TRAP_READ_ERR:
		return "read-err";
	case RZ_ANALYSIS_TRAP_WRITE_ERR:
		return "write-err";
	case RZ_ANALYSIS_TRAP_BREAKPOINT:
		return "breakpoint";
	case RZ_ANALYSIS_TRAP_UNHANDLED:
		return "unhandled";
	case RZ_ANALYSIS_TRAP_DIVBYZERO:
		return "divbyzero";
	case RZ_ANALYSIS_TRAP_INVALID:
		return "invalid";
	case RZ_ANALYSIS_TRAP_UNALIGNED:
		return "unaligned";
	case RZ_ANALYSIS_TRAP_TODO:
		return "todo";
	default:
		return "unknown";
	}
}

static bool esil_break(RzAnalysisEsil *esil) {
	esil->parse_stop = 1;
	return 1;
}

static bool esil_clear(RzAnalysisEsil *esil) {
	char *r;
	while ((r = rz_analysis_esil_pop(esil))) {
		free(r);
	}
	return 1;
}

static bool esil_todo(RzAnalysisEsil *esil) {
	esil->parse_stop = 2;
	return 1;
}

static bool esil_goto(RzAnalysisEsil *esil) {
	ut64 num = 0;
	char *src = rz_analysis_esil_pop(esil);
	if (src && *src && rz_analysis_esil_get_parm(esil, src, &num)) {
		esil->parse_goto = num;
	}
	free(src);
	return 1;
}

static bool esil_repeat(RzAnalysisEsil *esil) {
	char *dst = rz_analysis_esil_pop(esil); // destaintion of the goto
	char *src = rz_analysis_esil_pop(esil); // value of the counter
	ut64 n, num = 0;
	if (rz_analysis_esil_get_parm(esil, src, &n) && rz_analysis_esil_get_parm(esil, dst, &num)) {
		if (n > 1) {
			esil->parse_goto = num;
			rz_analysis_esil_pushnum(esil, n - 1);
		}
	}
	free(dst);
	free(src);
	return 1;
}

static bool esil_pop(RzAnalysisEsil *esil) {
	char *dst = rz_analysis_esil_pop(esil);
	free(dst);
	return 1;
}

static bool esil_mod(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		if (dst && rz_analysis_esil_get_parm(esil, dst, &d)) {
			if (s == 0) {
				ESIL_LOG("0x%08" PFMT64x " esil_mod: Division by zero!\n", esil->address);
				esil->trap = RZ_ANALYSIS_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				rz_analysis_esil_pushnum(esil, d % s);
			}
			ret = true;
		}
	} else {
		ESIL_LOG("esil_mod: invalid parameters\n");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_signed_mod(RzAnalysisEsil *esil) {
	bool ret = false;
	st64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, (ut64 *)&s)) {
		if (dst && rz_analysis_esil_get_parm(esil, dst, (ut64 *)&d)) {
			if (ST64_DIV_OVFCHK(d, s)) {
				ESIL_LOG("0x%08" PFMT64x " esil_mod: Division by zero!\n", esil->address);
				esil->trap = RZ_ANALYSIS_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				rz_analysis_esil_pushnum(esil, d % s);
			}
			ret = true;
		}
	} else {
		ESIL_LOG("esil_mod: invalid parameters\n");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_modeq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		if (dst && rz_analysis_esil_reg_read(esil, dst, &d, NULL)) {
			if (s) {
				esil->old = d;
				esil->cur = d % s;
				esil->lastsz = esil_internal_sizeof_reg(esil, dst);
				rz_analysis_esil_reg_write(esil, dst, d % s);
			} else {
				ESIL_LOG("esil_modeq: Division by zero!\n");
				esil->trap = RZ_ANALYSIS_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			}
			ret = true;
		} else {
			ESIL_LOG("esil_modeq: empty stack\n");
		}
	} else {
		ESIL_LOG("esil_modeq: invalid parameters\n");
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_div(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		if (dst && rz_analysis_esil_get_parm(esil, dst, &d)) {
			if (s == 0) {
				ESIL_LOG("esil_div: Division by zero!\n");
				esil->trap = RZ_ANALYSIS_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				rz_analysis_esil_pushnum(esil, d / s);
			}
			ret = true;
		}
	} else {
		ESIL_LOG("esil_div: invalid parameters\n");
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_signed_div(RzAnalysisEsil *esil) {
	bool ret = false;
	st64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, (ut64 *)&s)) {
		if (dst && rz_analysis_esil_get_parm(esil, dst, (ut64 *)&d)) {
			if (ST64_DIV_OVFCHK(d, s)) {
				ESIL_LOG("esil_div: Division by zero!\n");
				esil->trap = RZ_ANALYSIS_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			} else {
				rz_analysis_esil_pushnum(esil, d / s);
			}
			ret = true;
		}
	} else {
		ESIL_LOG("esil_div: invalid parameters\n");
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_diveq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		if (dst && rz_analysis_esil_reg_read(esil, dst, &d, NULL)) {
			if (s) {
				esil->old = d;
				esil->cur = d / s;
				esil->lastsz = esil_internal_sizeof_reg(esil, dst);
				rz_analysis_esil_reg_write(esil, dst, d / s);
			} else {
				// RZ_LOG_ERROR("0x%08"PFMT64x" esil_diveq: Division by zero!\n", esil->address);
				esil->trap = RZ_ANALYSIS_TRAP_DIVBYZERO;
				esil->trap_code = 0;
			}
			ret = true;
		} else {
			ESIL_LOG("esil_diveq: empty stack\n");
		}
	} else {
		ESIL_LOG("esil_diveq: invalid parameters\n");
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_mul(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		if (dst && rz_analysis_esil_get_parm(esil, dst, &d)) {
			rz_analysis_esil_pushnum(esil, d * s);
			ret = true;
		} else {
			ESIL_LOG("esil_mul: empty stack\n");
		}
	} else {
		ESIL_LOG("esil_mul: invalid parameters\n");
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_muleq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		if (dst && rz_analysis_esil_reg_read(esil, dst, &d, NULL)) {
			esil->old = d;
			esil->cur = d * s;
			esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			ret = rz_analysis_esil_reg_write(esil, dst, s * d);
		} else {
			ESIL_LOG("esil_muleq: empty stack\n");
		}
	} else {
		ESIL_LOG("esil_muleq: invalid parameters\n");
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_add(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if ((src && rz_analysis_esil_get_parm(esil, src, &s)) && (dst && rz_analysis_esil_get_parm(esil, dst, &d))) {
		rz_analysis_esil_pushnum(esil, s + d);
		ret = true;
	} else {
		ESIL_LOG("esil_add: invalid parameters\n");
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_addeq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		if (dst && rz_analysis_esil_reg_read(esil, dst, &d, NULL)) {
			esil->old = d;
			esil->cur = d + s;
			esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			ret = rz_analysis_esil_reg_write(esil, dst, s + d);
		}
	} else {
		ESIL_LOG("esil_addeq: invalid parameters\n");
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_inc(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		s++;
		ret = rz_analysis_esil_pushnum(esil, s);
	} else {
		ESIL_LOG("esil_inc: invalid parameters\n");
	}
	free(src);
	return ret;
}

static bool esil_inceq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 sd;
	char *src_dst = rz_analysis_esil_pop(esil);
	if (src_dst && (rz_analysis_esil_get_parm_type(esil, src_dst) == RZ_ANALYSIS_ESIL_PARM_REG) && rz_analysis_esil_get_parm(esil, src_dst, &sd)) {
		// inc rax
		esil->old = sd++;
		esil->cur = sd;
		rz_analysis_esil_reg_write(esil, src_dst, sd);
		esil->lastsz = esil_internal_sizeof_reg(esil, src_dst);
		ret = true;
	} else {
		ESIL_LOG("esil_inceq: invalid parameters\n");
	}
	free(src_dst);
	return ret;
}

static bool esil_sub(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if ((src && rz_analysis_esil_get_parm(esil, src, &s)) && (dst && rz_analysis_esil_get_parm(esil, dst, &d))) {
		ret = rz_analysis_esil_pushnum(esil, d - s);
	} else {
		ESIL_LOG("esil_sub: invalid parameters\n");
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_subeq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		if (dst && rz_analysis_esil_reg_read(esil, dst, &d, NULL)) {
			esil->old = d;
			esil->cur = d - s;
			esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			ret = rz_analysis_esil_reg_write(esil, dst, d - s);
		}
	} else {
		ESIL_LOG("esil_subeq: invalid parameters\n");
	}
	free(src);
	free(dst);
	return ret;
}

static bool esil_dec(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		s--;
		ret = rz_analysis_esil_pushnum(esil, s);
	} else {
		ESIL_LOG("esil_dec: invalid parameters\n");
	}
	free(src);
	return ret;
}

static bool esil_deceq(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 sd;
	char *src_dst = rz_analysis_esil_pop(esil);
	if (src_dst && (rz_analysis_esil_get_parm_type(esil, src_dst) == RZ_ANALYSIS_ESIL_PARM_REG) && rz_analysis_esil_get_parm(esil, src_dst, &sd)) {
		esil->old = sd;
		sd--;
		esil->cur = sd;
		rz_analysis_esil_reg_write(esil, src_dst, sd);
		esil->lastsz = esil_internal_sizeof_reg(esil, src_dst);
		ret = true;
	} else {
		ESIL_LOG("esil_deceq: invalid parameters\n");
	}
	free(src_dst);
	return ret;
}

/* POKE */
static bool esil_poke_n(RzAnalysisEsil *esil, int bits) {
	ut64 bitmask = genmask(bits - 1);
	ut64 num, num2, addr;
	ut8 b[8] = { 0 };
	ut64 n;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	int bytes = RZ_MIN(sizeof(b), bits / 8);
	if (bits % 8) {
		free(src);
		free(dst);
		return false;
	}
	bool ret = false;
	char *src2 = NULL;
	if (src && rz_analysis_esil_get_parm(esil, src, &num)) {
		if (dst && rz_analysis_esil_get_parm(esil, dst, &addr)) {
			if (bits == 128) {
				src2 = rz_analysis_esil_pop(esil);
				if (src2 && rz_analysis_esil_get_parm(esil, src2, &num2)) {
					rz_write_ble(b, num, esil->analysis->big_endian, 64);
					rz_analysis_esil_mem_write(esil, addr, b, bytes);
					rz_write_ble(b, num2, esil->analysis->big_endian, 64);
					rz_analysis_esil_mem_write(esil, addr + 8, b, bytes);
					ret = true;
					goto out;
				}
				ret = false;
				goto out;
			}
			// this is a internal peek performed before a poke
			// we disable hooks to avoid run hooks on internal peeks
			void *oldhook = (void *)esil->cb.hook_mem_read;
			esil->cb.hook_mem_read = NULL;
			rz_analysis_esil_mem_read(esil, addr, b, bytes);
			esil->cb.hook_mem_read = oldhook;
			n = rz_read_ble64(b, esil->analysis->big_endian);
			esil->old = n;
			esil->cur = num;
			esil->lastsz = bits;
			num = num & bitmask;
			rz_write_ble(b, num, esil->analysis->big_endian, bits);
			rz_analysis_esil_mem_write(esil, addr, b, bytes);
			ret = true;
		}
	}
out:
	free(src2);
	free(src);
	free(dst);
	return ret;
}

static bool esil_poke1(RzAnalysisEsil *esil) {
	return esil_poke_n(esil, 8);
}

static bool esil_poke2(RzAnalysisEsil *esil) {
	return esil_poke_n(esil, 16);
}

static bool esil_poke3(RzAnalysisEsil *esil) {
	return esil_poke_n(esil, 24);
}

static bool esil_poke4(RzAnalysisEsil *esil) {
	return esil_poke_n(esil, 32);
}

static bool esil_poke8(RzAnalysisEsil *esil) {
	return esil_poke_n(esil, 64);
}

static bool esil_poke16(RzAnalysisEsil *esil) {
	return esil_poke_n(esil, 128);
}

static bool esil_poke(RzAnalysisEsil *esil) {
	return esil_poke_n(esil, esil->analysis->bits);
}

static bool esil_poke_some(RzAnalysisEsil *esil) {
	bool ret = false;
	int i, regsize;
	ut64 ptr, regs = 0, tmp;
	char *count, *dst = rz_analysis_esil_pop(esil);

	if (dst && rz_analysis_esil_get_parm_size(esil, dst, &tmp, &regsize)) {
		// reg
		isregornum(esil, dst, &ptr);
		count = rz_analysis_esil_pop(esil);
		if (count) {
			isregornum(esil, count, &regs);
			if (regs > 0) {
				ut8 b[8] = { 0 };
				ut64 num64;
				for (i = 0; i < regs; i++) {
					char *foo = rz_analysis_esil_pop(esil);
					if (!foo) {
						// avoid looping out of stack
						free(dst);
						free(count);
						return true;
					}
					rz_analysis_esil_get_parm_size(esil, foo, &tmp, &regsize);
					isregornum(esil, foo, &num64);
					rz_write_ble(b, num64, esil->analysis->big_endian, regsize);
					const int size_bytes = regsize / 8;
					const ut32 written = rz_analysis_esil_mem_write(esil, ptr, b, size_bytes);
					if (written != size_bytes) {
						esil->trap = 1;
					}
					ptr += size_bytes;
					free(foo);
				}
			}
			free(dst);
			free(count);
			return ret;
		}
		free(dst);
	}
	return false;
}

/* PEEK */

static bool esil_peek_n(RzAnalysisEsil *esil, int bits) {
	if (bits & 7) {
		return false;
	}
	bool ret = false;
	char res[32];
	ut64 addr;
	ut32 bytes = bits / 8;
	char *dst = rz_analysis_esil_pop(esil);
	if (!dst) {
		RZ_LOG_ERROR("Cannot peek memory without specifying an address (esil address: 0x%08" PFMT64x ")\n", esil->address);
		return false;
	}
	if (dst && isregornum(esil, dst, &addr)) {
		if (bits == 128) {
			ut8 a[sizeof(ut64) * 2] = { 0 };
			rz_analysis_esil_mem_read(esil, addr, a, bytes);
			ut64 b = rz_read_ble(a, esil->analysis->big_endian, bits);
			ut64 c = rz_read_ble(a + 8, esil->analysis->big_endian, bits);
			rz_strf(res, "0x%" PFMT64x, b);
			rz_analysis_esil_push(esil, res);
			rz_strf(res, "0x%" PFMT64x, c);
			rz_analysis_esil_push(esil, res);
			free(dst);
			return true;
		}
		ut64 bitmask = genmask(bits - 1);
		ut8 a[sizeof(ut64)] = { 0 };
		rz_analysis_esil_mem_read(esil, addr, a, bytes);
		ut64 b = rz_read_ble(a, esil->analysis->big_endian, bits);
		rz_strf(res, "0x%" PFMT64x, b & bitmask);
		rz_analysis_esil_push(esil, res);
		esil->lastsz = bits;
		ret = true;
	}
	free(dst);
	return ret;
}

static bool esil_peek1(RzAnalysisEsil *esil) {
	return esil_peek_n(esil, 8);
}

static bool esil_peek2(RzAnalysisEsil *esil) {
	return esil_peek_n(esil, 16);
}

static bool esil_peek3(RzAnalysisEsil *esil) {
	return esil_peek_n(esil, 24);
}

static bool esil_peek4(RzAnalysisEsil *esil) {
	return esil_peek_n(esil, 32);
}

static bool esil_peek8(RzAnalysisEsil *esil) {
	return esil_peek_n(esil, 64);
}

static bool esil_peek16(RzAnalysisEsil *esil) {
	// packed only
	return esil_peek_n(esil, 128);
}

static bool esil_stack(RzAnalysisEsil *esil) {
	return esil->stackptr >= 1;
}

static bool esil_peek(RzAnalysisEsil *esil) {
	return esil_peek_n(esil, esil->analysis->bits);
};

static bool esil_peek_some(RzAnalysisEsil *esil) {
	int i;
	ut64 ptr, regs;
	// pop ptr
	char *count, *dst = rz_analysis_esil_pop(esil);
	if (dst) {
		// reg
		isregornum(esil, dst, &ptr);
		count = rz_analysis_esil_pop(esil);
		if (count) {
			isregornum(esil, count, &regs);
			if (regs > 0) {
				ut32 num32;
				ut8 a[4];
				for (i = 0; i < regs; i++) {
					char *foo = rz_analysis_esil_pop(esil);
					if (!foo) {
						ESIL_LOG("Cannot pop in peek\n");
						free(dst);
						free(count);
						return 0;
					}
					const ut32 read = rz_analysis_esil_mem_read(esil, ptr, a, 4);
					if (read == 4) { // this is highly questionabla
						num32 = rz_read_ble32(a, esil->analysis->big_endian);
						rz_analysis_esil_reg_write(esil, foo, num32);
					} else {
						ESIL_LOG("Cannot peek from 0x%08" PFMT64x "\n", ptr);
					}
					ptr += 4;
					free(foo);
				}
			}
			free(dst);
			free(count);
			return 1;
		}
		free(dst);
	}
	return 0;
}

/* OREQ */

static bool esil_mem_oreq_n(RzAnalysisEsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil); // save the dst-addr
	char *src0 = rz_analysis_esil_pop(esil); // get the src
	char *src1 = NULL;
	if (src0 && rz_analysis_esil_get_parm(esil, src0, &s)) { // get the src
		rz_analysis_esil_push(esil, dst); // push the dst-addr
		ret = (!!esil_peek_n(esil, bits)); // read
		src1 = rz_analysis_esil_pop(esil); // get the old dst-value
		if (src1 && rz_analysis_esil_get_parm(esil, src1, &d)) { // get the old dst-value
			d |= s; // calculate the new dst-value
			rz_analysis_esil_pushnum(esil, d); // push the new dst-value
			rz_analysis_esil_push(esil, dst); // push the dst-addr
			ret &= (!!esil_poke_n(esil, bits)); // write
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_oreq_n: invalid parameters\n");
	}
	free(dst);
	free(src0);
	free(src1);
	return ret;
}

static bool esil_mem_oreq1(RzAnalysisEsil *esil) {
	return esil_mem_oreq_n(esil, 8);
}
static bool esil_mem_oreq2(RzAnalysisEsil *esil) {
	return esil_mem_oreq_n(esil, 16);
}
static bool esil_mem_oreq4(RzAnalysisEsil *esil) {
	return esil_mem_oreq_n(esil, 32);
}
static bool esil_mem_oreq8(RzAnalysisEsil *esil) {
	return esil_mem_oreq_n(esil, 64);
}
static bool esil_mem_oreq(RzAnalysisEsil *esil) {
	return esil_mem_oreq_n(esil, esil->analysis->bits);
}

/* XOREQ */

static bool esil_mem_xoreq_n(RzAnalysisEsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src0 = rz_analysis_esil_pop(esil);
	char *src1 = NULL;
	if (src0 && rz_analysis_esil_get_parm(esil, src0, &s)) {
		rz_analysis_esil_push(esil, dst);
		ret = (!!esil_peek_n(esil, bits));
		src1 = rz_analysis_esil_pop(esil);
		if (src1 && rz_analysis_esil_get_parm(esil, src1, &d)) {
			d ^= s;
			rz_analysis_esil_pushnum(esil, d);
			rz_analysis_esil_push(esil, dst);
			ret &= (!!esil_poke_n(esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_xoreq_n: invalid parameters\n");
	}
	free(dst);
	free(src0);
	free(src1);
	return ret;
}

static bool esil_mem_xoreq1(RzAnalysisEsil *esil) {
	return esil_mem_xoreq_n(esil, 8);
}
static bool esil_mem_xoreq2(RzAnalysisEsil *esil) {
	return esil_mem_xoreq_n(esil, 16);
}
static bool esil_mem_xoreq4(RzAnalysisEsil *esil) {
	return esil_mem_xoreq_n(esil, 32);
}
static bool esil_mem_xoreq8(RzAnalysisEsil *esil) {
	return esil_mem_xoreq_n(esil, 64);
}
static bool esil_mem_xoreq(RzAnalysisEsil *esil) {
	return esil_mem_xoreq_n(esil, esil->analysis->bits);
}

/* ANDEQ */

static bool esil_mem_andeq_n(RzAnalysisEsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src0 = rz_analysis_esil_pop(esil);
	char *src1 = NULL;
	if (src0 && rz_analysis_esil_get_parm(esil, src0, &s)) {
		rz_analysis_esil_push(esil, dst);
		ret = (!!esil_peek_n(esil, bits));
		src1 = rz_analysis_esil_pop(esil);
		if (src1 && rz_analysis_esil_get_parm(esil, src1, &d)) {
			d &= s;
			rz_analysis_esil_pushnum(esil, d);
			rz_analysis_esil_push(esil, dst);
			ret &= (!!esil_poke_n(esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_andeq_n: invalid parameters\n");
	}
	free(dst);
	free(src0);
	free(src1);
	return ret;
}

static bool esil_mem_andeq1(RzAnalysisEsil *esil) {
	return esil_mem_andeq_n(esil, 8);
}
static bool esil_mem_andeq2(RzAnalysisEsil *esil) {
	return esil_mem_andeq_n(esil, 16);
}
static bool esil_mem_andeq4(RzAnalysisEsil *esil) {
	return esil_mem_andeq_n(esil, 32);
}
static bool esil_mem_andeq8(RzAnalysisEsil *esil) {
	return esil_mem_andeq_n(esil, 64);
}
static bool esil_mem_andeq(RzAnalysisEsil *esil) {
	return esil_mem_andeq_n(esil, esil->analysis->bits);
}

/* ADDEQ */

static bool esil_mem_addeq_n(RzAnalysisEsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src0 = rz_analysis_esil_pop(esil);
	char *src1 = NULL;
	if (src0 && rz_analysis_esil_get_parm(esil, src0, &s)) {
		rz_analysis_esil_push(esil, dst);
		ret = (!!esil_peek_n(esil, bits));
		src1 = rz_analysis_esil_pop(esil);
		if (src1 && rz_analysis_esil_get_parm(esil, src1, &d)) {
			d += s;
			rz_analysis_esil_pushnum(esil, d);
			rz_analysis_esil_push(esil, dst);
			ret &= (!!esil_poke_n(esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_addeq_n: invalid parameters\n");
	}
	free(dst);
	free(src0);
	free(src1);
	return ret;
}

static bool esil_mem_addeq1(RzAnalysisEsil *esil) {
	return esil_mem_addeq_n(esil, 8);
}
static bool esil_mem_addeq2(RzAnalysisEsil *esil) {
	return esil_mem_addeq_n(esil, 16);
}
static bool esil_mem_addeq4(RzAnalysisEsil *esil) {
	return esil_mem_addeq_n(esil, 32);
}
static bool esil_mem_addeq8(RzAnalysisEsil *esil) {
	return esil_mem_addeq_n(esil, 64);
}
static bool esil_mem_addeq(RzAnalysisEsil *esil) {
	return esil_mem_addeq_n(esil, esil->analysis->bits);
}

/* SUBEQ */

static bool esil_mem_subeq_n(RzAnalysisEsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src0 = rz_analysis_esil_pop(esil);
	char *src1 = NULL;
	if (src0 && rz_analysis_esil_get_parm(esil, src0, &s)) {
		rz_analysis_esil_push(esil, dst);
		ret = (!!esil_peek_n(esil, bits));
		src1 = rz_analysis_esil_pop(esil);
		if (src1 && rz_analysis_esil_get_parm(esil, src1, &d)) {
			d -= s;
			rz_analysis_esil_pushnum(esil, d);
			rz_analysis_esil_push(esil, dst);
			ret &= (!!esil_poke_n(esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_subeq_n: invalid parameters\n");
	}
	free(dst);
	free(src0);
	free(src1);
	return ret;
}

static bool esil_mem_subeq1(RzAnalysisEsil *esil) {
	return esil_mem_subeq_n(esil, 8);
}
static bool esil_mem_subeq2(RzAnalysisEsil *esil) {
	return esil_mem_subeq_n(esil, 16);
}
static bool esil_mem_subeq4(RzAnalysisEsil *esil) {
	return esil_mem_subeq_n(esil, 32);
}
static bool esil_mem_subeq8(RzAnalysisEsil *esil) {
	return esil_mem_subeq_n(esil, 64);
}
static bool esil_mem_subeq(RzAnalysisEsil *esil) {
	return esil_mem_subeq_n(esil, esil->analysis->bits);
}

/* MODEQ */

static bool esil_mem_modeq_n(RzAnalysisEsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src0 = rz_analysis_esil_pop(esil);
	char *src1 = NULL;
	if (src0 && rz_analysis_esil_get_parm(esil, src0, &s)) {
		if (s == 0) {
			ESIL_LOG("esil_mem_modeq4: Division by zero!\n");
			esil->trap = RZ_ANALYSIS_TRAP_DIVBYZERO;
			esil->trap_code = 0;
		} else {
			rz_analysis_esil_push(esil, dst);
			ret = (!!esil_peek_n(esil, bits));
			src1 = rz_analysis_esil_pop(esil);
			if (src1 && rz_analysis_esil_get_parm(esil, src1, &d) && s >= 1) {
				rz_analysis_esil_pushnum(esil, d % s);
				d = d % s;
				rz_analysis_esil_pushnum(esil, d);
				rz_analysis_esil_push(esil, dst);
				ret &= (!!esil_poke_n(esil, bits));
			} else {
				ret = false;
			}
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_modeq_n: invalid parameters\n");
	}
	free(dst);
	free(src0);
	free(src1);
	return ret;
}

static bool esil_mem_modeq1(RzAnalysisEsil *esil) {
	return esil_mem_modeq_n(esil, 8);
}
static bool esil_mem_modeq2(RzAnalysisEsil *esil) {
	return esil_mem_modeq_n(esil, 16);
}
static bool esil_mem_modeq4(RzAnalysisEsil *esil) {
	return esil_mem_modeq_n(esil, 32);
}
static bool esil_mem_modeq8(RzAnalysisEsil *esil) {
	return esil_mem_modeq_n(esil, 64);
}
static bool esil_mem_modeq(RzAnalysisEsil *esil) {
	return esil_mem_modeq_n(esil, esil->analysis->bits);
}

/* DIVEQ */

static bool esil_mem_diveq_n(RzAnalysisEsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src0 = rz_analysis_esil_pop(esil);
	char *src1 = NULL;
	if (src0 && rz_analysis_esil_get_parm(esil, src0, &s)) {
		if (s == 0) {
			ESIL_LOG("esil_mem_diveq8: Division by zero!\n");
			esil->trap = RZ_ANALYSIS_TRAP_DIVBYZERO;
			esil->trap_code = 0;
		} else {
			rz_analysis_esil_push(esil, dst);
			ret = (!!esil_peek_n(esil, bits));
			src1 = rz_analysis_esil_pop(esil);
			if (src1 && rz_analysis_esil_get_parm(esil, src1, &d)) {
				d = d / s;
				rz_analysis_esil_pushnum(esil, d);
				rz_analysis_esil_push(esil, dst);
				ret &= (!!esil_poke_n(esil, bits));
			} else {
				ret = false;
			}
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_diveq_n: invalid parameters\n");
	}
	free(dst);
	free(src0);
	free(src1);
	return ret;
}

static bool esil_mem_diveq1(RzAnalysisEsil *esil) {
	return esil_mem_diveq_n(esil, 8);
}
static bool esil_mem_diveq2(RzAnalysisEsil *esil) {
	return esil_mem_diveq_n(esil, 16);
}
static bool esil_mem_diveq4(RzAnalysisEsil *esil) {
	return esil_mem_diveq_n(esil, 32);
}
static bool esil_mem_diveq8(RzAnalysisEsil *esil) {
	return esil_mem_diveq_n(esil, 64);
}
static bool esil_mem_diveq(RzAnalysisEsil *esil) {
	return esil_mem_diveq_n(esil, esil->analysis->bits);
}

/* MULEQ */

static bool esil_mem_muleq_n(RzAnalysisEsil *esil, int bits, ut64 bitmask) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src0 = rz_analysis_esil_pop(esil);
	char *src1 = NULL;
	if (src0 && rz_analysis_esil_get_parm(esil, src0, &s)) {
		rz_analysis_esil_push(esil, dst);
		ret = (!!esil_peek_n(esil, bits));
		src1 = rz_analysis_esil_pop(esil);
		if (src1 && rz_analysis_esil_get_parm(esil, src1, &d)) {
			d *= s;
			rz_analysis_esil_pushnum(esil, d);
			rz_analysis_esil_push(esil, dst);
			ret &= (!!esil_poke_n(esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_muleq_n: invalid parameters\n");
	}
	free(dst);
	free(src0);
	free(src1);
	return ret;
}

static bool esil_mem_muleq1(RzAnalysisEsil *esil) {
	return esil_mem_muleq_n(esil, 8, UT8_MAX);
}
static bool esil_mem_muleq2(RzAnalysisEsil *esil) {
	return esil_mem_muleq_n(esil, 16, UT16_MAX);
}
static bool esil_mem_muleq4(RzAnalysisEsil *esil) {
	return esil_mem_muleq_n(esil, 32, UT32_MAX);
}
static bool esil_mem_muleq8(RzAnalysisEsil *esil) {
	return esil_mem_muleq_n(esil, 64, UT64_MAX);
}

static bool esil_mem_muleq(RzAnalysisEsil *esil) {
	switch (esil->analysis->bits) {
	case 64: return esil_mem_muleq8(esil);
	case 32: return esil_mem_muleq4(esil);
	case 16: return esil_mem_muleq2(esil);
	case 8: return esil_mem_muleq1(esil);
	}
	return 0;
}

/* INCEQ */

static bool esil_mem_inceq_n(RzAnalysisEsil *esil, int bits) {
	bool ret = false;
	ut64 s;
	char *off = rz_analysis_esil_pop(esil);
	char *src = NULL;
	if (off) {
		rz_analysis_esil_push(esil, off);
		ret = (!!esil_peek_n(esil, bits));
		src = rz_analysis_esil_pop(esil);
		if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
			esil->old = s;
			s++;
			esil->cur = s;
			esil->lastsz = bits;
			rz_analysis_esil_pushnum(esil, s);
			rz_analysis_esil_push(esil, off);
			ret &= (!!esil_poke_n(esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_inceq_n: invalid parameters\n");
	}
	free(src);
	free(off);
	return ret;
}

static bool esil_mem_inceq1(RzAnalysisEsil *esil) {
	return esil_mem_inceq_n(esil, 8);
}
static bool esil_mem_inceq2(RzAnalysisEsil *esil) {
	return esil_mem_inceq_n(esil, 16);
}
static bool esil_mem_inceq4(RzAnalysisEsil *esil) {
	return esil_mem_inceq_n(esil, 32);
}
static bool esil_mem_inceq8(RzAnalysisEsil *esil) {
	return esil_mem_inceq_n(esil, 64);
}
static bool esil_mem_inceq(RzAnalysisEsil *esil) {
	return esil_mem_inceq_n(esil, esil->analysis->bits);
}

/* DECEQ */

static bool esil_mem_deceq_n(RzAnalysisEsil *esil, int bits) {
	bool ret = false;
	ut64 s;
	char *off = rz_analysis_esil_pop(esil);
	char *src = NULL;
	if (off) {
		rz_analysis_esil_push(esil, off);
		ret = (!!esil_peek_n(esil, bits));
		src = rz_analysis_esil_pop(esil);
		if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
			s--;
			rz_analysis_esil_pushnum(esil, s);
			rz_analysis_esil_push(esil, off);
			ret &= (!!esil_poke_n(esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_deceq_n: invalid parameters\n");
	}
	free(src);
	free(off);
	return ret;
}

static bool esil_mem_deceq1(RzAnalysisEsil *esil) {
	return esil_mem_deceq_n(esil, 8);
}
static bool esil_mem_deceq2(RzAnalysisEsil *esil) {
	return esil_mem_deceq_n(esil, 16);
}
static bool esil_mem_deceq4(RzAnalysisEsil *esil) {
	return esil_mem_deceq_n(esil, 32);
}
static bool esil_mem_deceq8(RzAnalysisEsil *esil) {
	return esil_mem_deceq_n(esil, 64);
}
static bool esil_mem_deceq(RzAnalysisEsil *esil) {
	return esil_mem_deceq_n(esil, esil->analysis->bits);
}

/* LSLEQ */

static bool esil_mem_lsleq_n(RzAnalysisEsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src0 = rz_analysis_esil_pop(esil);
	char *src1 = NULL;
	if (src0 && rz_analysis_esil_get_parm(esil, src0, &s)) {
		if (s > sizeof(ut64) * 8) {
			ESIL_LOG("esil_mem_lsleq_n: shift is too big\n");
		} else {
			rz_analysis_esil_push(esil, dst);
			ret = (!!esil_peek_n(esil, bits));
			src1 = rz_analysis_esil_pop(esil);
			if (src1 && rz_analysis_esil_get_parm(esil, src1, &d)) {
				if (s > 63) {
					d = 0;
				} else {
					d <<= s;
				}
				rz_analysis_esil_pushnum(esil, d);
				rz_analysis_esil_push(esil, dst);
				ret &= (!!esil_poke_n(esil, bits));
			} else {
				ret = false;
			}
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_lsleq_n: invalid parameters\n");
	}
	free(dst);
	free(src0);
	free(src1);
	return ret;
}

static bool esil_mem_lsleq1(RzAnalysisEsil *esil) {
	return esil_mem_lsleq_n(esil, 8);
}
static bool esil_mem_lsleq2(RzAnalysisEsil *esil) {
	return esil_mem_lsleq_n(esil, 16);
}
static bool esil_mem_lsleq4(RzAnalysisEsil *esil) {
	return esil_mem_lsleq_n(esil, 32);
}
static bool esil_mem_lsleq8(RzAnalysisEsil *esil) {
	return esil_mem_lsleq_n(esil, 64);
}
static bool esil_mem_lsleq(RzAnalysisEsil *esil) {
	return esil_mem_lsleq_n(esil, esil->analysis->bits);
}

/* LSREQ */

static bool esil_mem_lsreq_n(RzAnalysisEsil *esil, int bits) {
	bool ret = false;
	ut64 s, d;
	char *dst = rz_analysis_esil_pop(esil);
	char *src0 = rz_analysis_esil_pop(esil);
	char *src1 = NULL;
	if (src0 && rz_analysis_esil_get_parm(esil, src0, &s)) {
		rz_analysis_esil_push(esil, dst);
		ret = (!!esil_peek_n(esil, bits));
		src1 = rz_analysis_esil_pop(esil);
		if (src1 && rz_analysis_esil_get_parm(esil, src1, &d)) {
			d >>= s;
			rz_analysis_esil_pushnum(esil, d);
			rz_analysis_esil_push(esil, dst);
			ret &= (!!esil_poke_n(esil, bits));
		} else {
			ret = false;
		}
	}
	if (!ret) {
		ESIL_LOG("esil_mem_lsreq_n: invalid parameters\n");
	}
	free(dst);
	free(src0);
	free(src1);
	return ret;
}

static bool esil_mem_lsreq1(RzAnalysisEsil *esil) {
	return esil_mem_lsreq_n(esil, 8);
}
static bool esil_mem_lsreq2(RzAnalysisEsil *esil) {
	return esil_mem_lsreq_n(esil, 16);
}
static bool esil_mem_lsreq4(RzAnalysisEsil *esil) {
	return esil_mem_lsreq_n(esil, 32);
}
static bool esil_mem_lsreq8(RzAnalysisEsil *esil) {
	return esil_mem_lsreq_n(esil, 64);
}
static bool esil_mem_lsreq(RzAnalysisEsil *esil) {
	return esil_mem_lsreq_n(esil, esil->analysis->bits);
}

/* get value of register or memory reference and push the value */
static bool esil_num(RzAnalysisEsil *esil) {
	char *dup_me;
	ut64 dup;
	if (!esil) {
		return false;
	}
	if (!(dup_me = rz_analysis_esil_pop(esil))) {
		return false;
	}
	if (!rz_analysis_esil_get_parm(esil, dup_me, &dup)) {
		free(dup_me);
		return false;
	}
	free(dup_me);
	return rz_analysis_esil_pushnum(esil, dup);
}

/* duplicate the last element in the stack */
static bool esil_dup(RzAnalysisEsil *esil) {
	if (!esil || !esil->stack || esil->stackptr < 1 || esil->stackptr > (esil->stacksize - 1)) {
		return false;
	}
	return rz_analysis_esil_push(esil, esil->stack[esil->stackptr - 1]);
}

static bool esil_swap(RzAnalysisEsil *esil) {
	char *tmp;
	if (!esil || !esil->stack || esil->stackptr < 2) {
		return false;
	}
	if (!esil->stack[esil->stackptr - 1] || !esil->stack[esil->stackptr - 2]) {
		return false;
	}
	tmp = esil->stack[esil->stackptr - 1];
	esil->stack[esil->stackptr - 1] = esil->stack[esil->stackptr - 2];
	esil->stack[esil->stackptr - 2] = tmp;
	return true;
}

// NOTE on following comparison functions:
// The push to top of the stack is based on a
// signed compare (as this causes least surprise to the users).
// If an unsigned comparison is necessary, one must not use the
// result pushed onto the top of the stack, but rather test the flags which
// are set as a result of the compare.

static int signed_compare_gt(ut64 a, ut64 b, ut64 size) {
	int result;
	switch (size) {
	case 1:
		result = (a & 1) > (b & 1);
		break;
	case 8:
		result = (st8)a > (st8)b;
		break;
	case 16:
		result = (st16)a > (st16)b;
		break;
	case 32:
		result = (st32)a > (st32)b;
		break;
	case 64:
	default:
		result = (st64)a > (st64)b;
		break;
	}
	return result;
}

static bool esil_smaller(RzAnalysisEsil *esil) { // 'dst < src' => 'src,dst,<'
	ut64 num, num2;
	bool ret = false;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm(esil, dst, &num)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = true;
			if (rz_reg_get(esil->analysis->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			} else if (rz_reg_get(esil->analysis->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg(esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			rz_analysis_esil_pushnum(esil, (num != num2) & !signed_compare_gt(num, num2, esil->lastsz));
		}
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_bigger(RzAnalysisEsil *esil) { // 'dst > src' => 'src,dst,>'
	ut64 num, num2;
	bool ret = false;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm(esil, dst, &num)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = true;
			if (rz_reg_get(esil->analysis->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			} else if (rz_reg_get(esil->analysis->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg(esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			rz_analysis_esil_pushnum(esil, signed_compare_gt(num, num2, esil->lastsz));
		}
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_smaller_equal(RzAnalysisEsil *esil) { // 'dst <= src' => 'src,dst,<='
	ut64 num, num2;
	bool ret = false;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm(esil, dst, &num)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = true;
			if (rz_reg_get(esil->analysis->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			} else if (rz_reg_get(esil->analysis->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg(esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			rz_analysis_esil_pushnum(esil, !signed_compare_gt(num, num2, esil->lastsz));
		}
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_bigger_equal(RzAnalysisEsil *esil) { // 'dst >= src' => 'src,dst,>='
	ut64 num, num2;
	bool ret = false;
	char *dst = rz_analysis_esil_pop(esil);
	char *src = rz_analysis_esil_pop(esil);
	if (dst && rz_analysis_esil_get_parm(esil, dst, &num)) {
		if (src && rz_analysis_esil_get_parm(esil, src, &num2)) {
			esil->old = num;
			esil->cur = num - num2;
			ret = true;
			if (rz_reg_get(esil->analysis->reg, dst, -1)) {
				esil->lastsz = esil_internal_sizeof_reg(esil, dst);
			} else if (rz_reg_get(esil->analysis->reg, src, -1)) {
				esil->lastsz = esil_internal_sizeof_reg(esil, src);
			} else {
				// default size is set to 64 as internally operands are ut64
				esil->lastsz = 64;
			}
			rz_analysis_esil_pushnum(esil, (num == num2) | signed_compare_gt(num, num2, esil->lastsz));
		}
	}
	free(dst);
	free(src);
	return ret;
}

static bool esil_set_jump_target(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		esil->jump_target = s;
		esil->jump_target_set = 1;
		ret = true;
	} else {
		RZ_FREE(src);
		ESIL_LOG("esil_set_jump_target: empty stack\n");
	}
	free(src);
	return ret;
}

static bool esil_set_jump_target_set(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		esil->jump_target_set = s;
		ret = true;
	} else {
		RZ_FREE(src);
		ESIL_LOG("esil_set_jump_target_set: empty stack\n");
	}
	free(src);
	return ret;
}

static bool esil_set_delay_slot(RzAnalysisEsil *esil) {
	bool ret = false;
	ut64 s;
	char *src = rz_analysis_esil_pop(esil);
	if (src && rz_analysis_esil_get_parm(esil, src, &s)) {
		esil->delay = s;
		ret = true;
	} else {
		RZ_FREE(src);
		ESIL_LOG("esil_set_delay_slot: empty stack\n");
	}
	free(src);
	return ret;
}

static bool iscommand(RzAnalysisEsil *esil, const char *word, RzAnalysisEsilOp **op) {
	RzAnalysisEsilOp *eop = ht_sp_find(esil->ops, word, NULL);
	if (eop) {
		*op = eop;
		return true;
	}
	return false;
}

static bool runword(RzAnalysisEsil *esil, const char *word) {
	RzAnalysisEsilOp *op = NULL;
	if (!word) {
		return false;
	}
	esil->parse_goto_count--;
	if (esil->parse_goto_count < 1) {
		ESIL_LOG("ESIL infinite loop detected\n");
		esil->trap = 1; // INTERNAL ERROR
		esil->parse_stop = 1; // INTERNAL ERROR
		return false;
	}

	if (!strcmp(word, "}{")) {
		if (esil->skip == 1) {
			esil->skip = 0;
		} else if (esil->skip == 0) { // this isn't perfect, but should work for valid esil
			esil->skip = 1;
		}
		return true;
	}
	if (!strcmp(word, "}")) {
		if (esil->skip) {
			esil->skip--;
		}
		return true;
	}
	if (esil->skip && strcmp(word, "?{")) {
		return true;
	}

	if (iscommand(esil, word, &op)) {
		// run action
		if (op) {
			if (esil->cb.hook_command) {
				if (esil->cb.hook_command(esil, word)) {
					return 1; // XXX cannot return != 1
				}
			}
			rz_strbuf_set(&esil->current_opstr, word);
			// so this is basically just sharing what's the operation with the operation
			// useful for wrappers
			const bool ret = op->code(esil);
			rz_strbuf_fini(&esil->current_opstr);
			if (!ret) {
				ESIL_LOG("%s returned 0\n", word);
			}
			return ret;
		}
	}
	if (!*word || *word == ',') {
		// skip empty words
		return true;
	}

	// push value
	if (!rz_analysis_esil_push(esil, word)) {
		ESIL_LOG("ESIL stack is full\n");
		esil->trap = 1;
		esil->trap_code = 1;
	}
	return true;
}

static const char *gotoWord(const char *str, int n) {
	const char *ostr = str;
	int count = 0;
	while (*str) {
		if (count == n) {
			return ostr;
		}
		str++;
		if (*str == ',') {
			ostr = str + 1;
			count++;
		}
	}
	return NULL;
}

/** evaluate an esil word and return the action to perform
 * TODO: Use `enum` here
 * 0: continue running the
 * 1: stop execution
 * 2: continue in loop
 * 3: normal continuation
 */
static int evalWord(RzAnalysisEsil *esil, const char *ostr, const char **str) {
	rz_return_val_if_fail(esil && str, 0);
	if (!*str) {
		return 0;
	}
	if ((*str)[0] && (*str)[1] == ',') {
		return 2;
	}
	if (esil->repeat) {
		return 0;
	}
	if (esil->parse_goto != -1) {
		// TODO: detect infinite loop??? how??
		*str = gotoWord(ostr, esil->parse_goto);
		if (*str) {
			esil->parse_goto = -1;
			return 2;
		}
		ESIL_LOG("Cannot find word %d\n", esil->parse_goto);
		return 1;
	}
	if (esil->parse_stop) {
		if (esil->parse_stop == 2) {
			RZ_LOG_DEBUG("[esil at 0x%08" PFMT64x "] TODO: %s\n", esil->address, *str + 1);
		}
		return 1;
	}
	return 3;
}

static bool __stepOut(RzAnalysisEsil *esil, const char *cmd) {
	bool ret = false;
	if (cmd && esil && esil->cmd && !esil->in_cmd_step) {
		esil->in_cmd_step = true;
		ret = esil->cmd(esil, cmd, esil->address, 0);
		esil->in_cmd_step = false;
	}
	return ret;
}

RZ_API bool rz_analysis_esil_parse(RzAnalysisEsil *esil, const char *str) {
	int wordi = 0;
	int dorunword;
	char word[64];
	const char *ostr = str;
	rz_return_val_if_fail(esil && RZ_STR_ISNOTEMPTY(str), 0);

	if (__stepOut(esil, esil->cmd_step)) {
		(void)__stepOut(esil, esil->cmd_step_out);
		return true;
	}
	const char *hashbang = strstr(str, "#!");
	esil->trap = 0;
	if (esil->cmd && esil->cmd_todo) {
		if (!strncmp(str, "TODO", 4)) {
			esil->cmd(esil, esil->cmd_todo, esil->address, 0);
		}
	}
loop:
	esil->repeat = 0;
	esil->skip = 0;
	esil->parse_goto = -1;
	esil->parse_stop = 0;
	// memleak or failing aetr test. wat du
	//	rz_analysis_esil_stack_free (esil);
	esil->parse_goto_count = esil->analysis ? esil->analysis->esil_goto_limit : RZ_ANALYSIS_ESIL_GOTO_LIMIT;
	str = ostr;
repeat:
	wordi = 0;
	while (*str) {
		if (str == hashbang) {
			if (esil->analysis && esil->analysis->coreb.setab) {
				esil->analysis->coreb.cmd(esil->analysis->coreb.core, str + 2);
			}
			break;
		}
		if (wordi > 62) {
			ESIL_LOG("Invalid esil string\n");
			__stepOut(esil, esil->cmd_step_out);
			return -1;
		}
		dorunword = 0;
		if (*str == ';') {
			word[wordi] = 0;
			dorunword = 1;
		}
		if (*str == ',') {
			word[wordi] = 0;
			dorunword = 2;
		}
		if (dorunword) {
			if (*word) {
				if (!runword(esil, word)) {
					__stepOut(esil, esil->cmd_step_out);
					return 0;
				}
				word[wordi] = ',';
				wordi = 0;
				switch (evalWord(esil, ostr, &str)) {
				case 0: goto loop;
				case 1:
					__stepOut(esil, esil->cmd_step_out);
					return 0;
				case 2: continue;
				}
				if (dorunword == 1) {
					__stepOut(esil, esil->cmd_step_out);
					return 0;
				}
			}
			str++;
		}
		word[wordi++] = *str;
		// is *str is '\0' in the next iteration the condition will be true
		// reading beyond the boundaries
		if (*str) {
			str++;
		}
	}
	word[wordi] = 0;
	if (*word) {
		if (!runword(esil, word)) {
			__stepOut(esil, esil->cmd_step_out);
			return 0;
		}
		switch (evalWord(esil, ostr, &str)) {
		case 0: goto loop;
		case 1:
			__stepOut(esil, esil->cmd_step_out);
			return 0;
		case 2: goto repeat;
		}
	}
	__stepOut(esil, esil->cmd_step_out);
	return 1;
}

RZ_API bool rz_analysis_esil_runword(RzAnalysisEsil *esil, const char *word) {
	(void)runword(esil, word);
	// for some reasons this is called twice in the original code from condret.
	return runword(esil, word);
}

// frees all elements from the stack, not the stack itself
// rename to stack_empty() ?
RZ_API void rz_analysis_esil_stack_free(RzAnalysisEsil *esil) {
	int i;
	if (esil) {
		for (i = 0; i < esil->stackptr; i++) {
			RZ_FREE(esil->stack[i]);
		}
		esil->stackptr = 0;
	}
}

RZ_API int rz_analysis_esil_condition(RzAnalysisEsil *esil, const char *str) {
	char *popped;
	int ret;
	if (!esil) {
		return false;
	}
	while (*str == ' ') {
		str++; // use proper string chop?
	}
	(void)rz_analysis_esil_parse(esil, str);
	popped = rz_analysis_esil_pop(esil);
	if (popped) {
		ut64 num;
		if (isregornum(esil, popped, &num)) {
			ret = !!num;
		} else {
			ret = 0;
		}
		free(popped);
	} else {
		RZ_LOG_ERROR("Cannot pop because The ESIL stack is empty\n");
		return -1;
	}
	return ret;
}

static void rz_analysis_esil_setup_ops(RzAnalysisEsil *esil) {
#define OP(v, w, x, y, z) rz_analysis_esil_set_op(esil, v, w, x, y, z)
#define OT_UNK            RZ_ANALYSIS_ESIL_OP_TYPE_UNKNOWN
#define OT_CTR            RZ_ANALYSIS_ESIL_OP_TYPE_CONTROL_FLOW
#define OT_MATH           RZ_ANALYSIS_ESIL_OP_TYPE_MATH
#define OT_REGW           RZ_ANALYSIS_ESIL_OP_TYPE_REG_WRITE
#define OT_MEMW           RZ_ANALYSIS_ESIL_OP_TYPE_MEM_WRITE
#define OT_MEMR           RZ_ANALYSIS_ESIL_OP_TYPE_MEM_READ

	OP("$", esil_interrupt, 0, 1, OT_UNK); // hm, type seems a bit wrong
	OP("$z", esil_zf, 1, 0, OT_UNK);
	OP("$c", esil_cf, 1, 1, OT_UNK);
	OP("$b", esil_bf, 1, 1, OT_UNK);
	OP("$p", esil_pf, 1, 0, OT_UNK);
	OP("$s", esil_sf, 1, 1, OT_UNK);
	OP("$o", esil_of, 1, 1, OT_UNK);
	OP("$ds", esil_ds, 1, 0, OT_UNK);
	OP("$jt", esil_jt, 1, 0, OT_UNK);
	OP("$js", esil_js, 1, 0, OT_UNK);
	OP("$r", esil_rs, 1, 0, OT_UNK);
	OP("$$", esil_address, 1, 0, OT_UNK);
	OP("~", esil_signext, 1, 2, OT_MATH);
	OP("~=", esil_signexteq, 0, 2, OT_MATH);
	OP("==", esil_cmp, 0, 2, OT_MATH);
	OP("<", esil_smaller, 1, 2, OT_MATH);
	OP(">", esil_bigger, 1, 2, OT_MATH);
	OP("<=", esil_smaller_equal, 1, 2, OT_MATH);
	OP(">=", esil_bigger_equal, 1, 2, OT_MATH);
	OP("?{", esil_if, 0, 1, OT_CTR);
	OP("<<", esil_lsl, 1, 2, OT_MATH);
	OP("<<=", esil_lsleq, 0, 2, OT_MATH | OT_REGW);
	OP(">>", esil_lsr, 1, 2, OT_MATH);
	OP(">>=", esil_lsreq, 0, 2, OT_MATH | OT_REGW);
	OP(">>>>", esil_asr, 1, 2, OT_MATH);
	OP(">>>>=", esil_asreq, 0, 2, OT_MATH | OT_REGW);
	OP(">>>", esil_ror, 1, 2, OT_MATH);
	OP("<<<", esil_rol, 1, 2, OT_MATH);
	OP("&", esil_and, 1, 2, OT_MATH);
	OP("&=", esil_andeq, 0, 2, OT_MATH | OT_REGW);
	OP("}", esil_nop, 0, 0, OT_CTR); // just to avoid push
	OP("}{", esil_nop, 0, 0, OT_CTR);
	OP("|", esil_or, 1, 2, OT_MATH);
	OP("|=", esil_oreq, 0, 2, OT_MATH | OT_REGW);
	OP("!", esil_neg, 1, 1, OT_MATH);
	OP("!=", esil_negeq, 0, 1, OT_MATH | OT_REGW);
	OP("=", esil_eq, 0, 2, OT_REGW);
	OP(":=", esil_weak_eq, 0, 2, OT_REGW);
	OP("*", esil_mul, 1, 2, OT_MATH);
	OP("*=", esil_muleq, 0, 2, OT_MATH | OT_REGW);
	OP("^", esil_xor, 1, 2, OT_MATH);
	OP("^=", esil_xoreq, 0, 2, OT_MATH | OT_REGW);
	OP("+", esil_add, 1, 2, OT_MATH);
	OP("+=", esil_addeq, 0, 2, OT_MATH | OT_REGW);
	OP("++", esil_inc, 1, 1, OT_MATH);
	OP("++=", esil_inceq, 0, 1, OT_MATH | OT_REGW);
	OP("-", esil_sub, 1, 2, OT_MATH);
	OP("-=", esil_subeq, 0, 2, OT_MATH | OT_REGW);
	OP("--", esil_dec, 1, 1, OT_MATH);
	OP("--=", esil_deceq, 0, 1, OT_MATH | OT_REGW);
	OP("/", esil_div, 1, 2, OT_MATH);
	OP("~/", esil_signed_div, 1, 2, OT_MATH);
	OP("/=", esil_diveq, 0, 2, OT_MATH | OT_REGW);
	OP("%", esil_mod, 1, 2, OT_MATH);
	OP("~%", esil_signed_mod, 1, 2, OT_MATH);
	OP("%=", esil_modeq, 0, 2, OT_MATH | OT_REGW);
	OP("=[]", esil_poke, 0, 2, OT_MEMW);
	OP("=[1]", esil_poke1, 0, 2, OT_MEMW);
	OP("=[2]", esil_poke2, 0, 2, OT_MEMW);
	OP("=[3]", esil_poke3, 0, 2, OT_MEMW);
	OP("=[4]", esil_poke4, 0, 2, OT_MEMW);
	OP("=[8]", esil_poke8, 0, 2, OT_MEMW);
	OP("=[16]", esil_poke16, 0, 2, OT_MEMW);
	OP("|=[]", esil_mem_oreq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("|=[1]", esil_mem_oreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("|=[2]", esil_mem_oreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("|=[4]", esil_mem_oreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("|=[8]", esil_mem_oreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("^=[]", esil_mem_xoreq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("^=[1]", esil_mem_xoreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("^=[2]", esil_mem_xoreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("^=[4]", esil_mem_xoreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("^=[8]", esil_mem_xoreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("&=[]", esil_mem_andeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("&=[1]", esil_mem_andeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("&=[2]", esil_mem_andeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("&=[4]", esil_mem_andeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("&=[8]", esil_mem_andeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("+=[]", esil_mem_addeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("+=[1]", esil_mem_addeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("+=[2]", esil_mem_addeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("+=[4]", esil_mem_addeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("+=[8]", esil_mem_addeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("-=[]", esil_mem_subeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("-=[1]", esil_mem_subeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("-=[2]", esil_mem_subeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("-=[4]", esil_mem_subeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("-=[8]", esil_mem_subeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("%=[]", esil_mem_modeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("%=[1]", esil_mem_modeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("%=[2]", esil_mem_modeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("%=[4]", esil_mem_modeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("%=[8]", esil_mem_modeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("/=[]", esil_mem_diveq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("/=[1]", esil_mem_diveq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("/=[2]", esil_mem_diveq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("/=[4]", esil_mem_diveq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("/=[8]", esil_mem_diveq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("*=[]", esil_mem_muleq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("*=[1]", esil_mem_muleq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("*=[2]", esil_mem_muleq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("*=[4]", esil_mem_muleq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("*=[8]", esil_mem_muleq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("++=[]", esil_mem_inceq, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP("++=[1]", esil_mem_inceq1, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP("++=[2]", esil_mem_inceq2, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP("++=[4]", esil_mem_inceq4, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP("++=[8]", esil_mem_inceq8, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP("--=[]", esil_mem_deceq, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP("--=[1]", esil_mem_deceq1, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP("--=[2]", esil_mem_deceq2, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP("--=[4]", esil_mem_deceq4, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP("--=[8]", esil_mem_deceq8, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	OP("<<=[]", esil_mem_lsleq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("<<=[1]", esil_mem_lsleq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("<<=[2]", esil_mem_lsleq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("<<=[4]", esil_mem_lsleq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("<<=[8]", esil_mem_lsleq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP(">>=[]", esil_mem_lsreq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP(">>=[1]", esil_mem_lsreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP(">>=[2]", esil_mem_lsreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP(">>=[4]", esil_mem_lsreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP(">>=[8]", esil_mem_lsreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	OP("[]", esil_peek, 1, 1, OT_MEMR);
	OP("[*]", esil_peek_some, 0, 0, OT_MEMR);
	OP("=[*]", esil_poke_some, 0, 0, OT_MEMW);
	OP("[1]", esil_peek1, 1, 1, OT_MEMR);
	OP("[2]", esil_peek2, 1, 1, OT_MEMR);
	OP("[3]", esil_peek3, 1, 1, OT_MEMR);
	OP("[4]", esil_peek4, 1, 1, OT_MEMR);
	OP("[8]", esil_peek8, 1, 1, OT_MEMR);
	OP("[16]", esil_peek16, 1, 1, OT_MEMR);
	OP("STACK", esil_stack, 0, 0, OT_UNK);
	OP("REPEAT", esil_repeat, 0, 2, OT_CTR);
	OP("POP", esil_pop, 0, 1, OT_UNK);
	OP("TODO", esil_todo, 0, 0, OT_UNK);
	OP("GOTO", esil_goto, 0, 1, OT_CTR);
	OP("BREAK", esil_break, 0, 0, OT_CTR);
	OP("CLEAR", esil_clear, 0, 0, OT_UNK);
	OP("DUP", esil_dup, 1, 0, OT_UNK);
	OP("NUM", esil_num, 1, 1, OT_UNK);
	OP("SWAP", esil_swap, 2, 2, OT_UNK);
	OP("TRAP", esil_trap, 0, 0, OT_UNK);
	OP("BITS", esil_bits, 1, 0, OT_UNK);
	OP("SETJT", esil_set_jump_target, 0, 1, OT_UNK);
	OP("SETJTS", esil_set_jump_target_set, 0, 1, OT_UNK);
	OP("SETD", esil_set_delay_slot, 0, 1, OT_UNK);
}

/* register callbacks using this analysis module. */
RZ_API bool rz_analysis_esil_setup(RzAnalysisEsil *esil, RzAnalysis *analysis, int romem, int stats, int nonull) {
	rz_return_val_if_fail(esil, false);
	// esil->debug = 0;
	esil->analysis = analysis;
	esil->parse_goto_count = analysis->esil_goto_limit;
	esil->trap = 0;
	esil->trap_code = 0;
	// esil->user = NULL;
	esil->cb.reg_read = internal_esil_reg_read;
	esil->cb.mem_read = internal_esil_mem_read;

	if (nonull) {
		// this is very questionable, most platforms allow accessing NULL
		// never writes zero to PC, BP, SP, why? because writing
		// zeros to these registers is equivalent to accessing NULL
		// pointer somehow
		esil->cb.reg_write = internal_esil_reg_write_no_null;
		esil->cb.mem_read = internal_esil_mem_read_no_null;
		esil->cb.mem_write = internal_esil_mem_write_no_null;
	} else {
		esil->cb.reg_write = internal_esil_reg_write;
		esil->cb.mem_read = internal_esil_mem_read;
		esil->cb.mem_write = internal_esil_mem_write;
	}
	rz_analysis_esil_mem_ro(esil, romem);
	rz_analysis_esil_stats(esil, stats);
	rz_analysis_esil_setup_ops(esil);

	return (analysis->cur && analysis->cur->esil_init)
		? analysis->cur->esil_init(esil)
		: true;
}
