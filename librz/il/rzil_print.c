// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_vm.h>

typedef void (*dump_op_t)(RzILOp *op, RzStrBuf *sb, PJ *pj);

static void il_opdmp_var(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_unk(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_ite(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_b0(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_b1(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_inv(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_and(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_or(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_int(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_msb(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_lsb(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_neg(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_not(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_add(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_sub(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_mul(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_div(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_sdiv(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_mod(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_smod(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_logand(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_logor(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_logxor(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_shiftr(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_shiftl(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_sle(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_ule(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_cast(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_concat(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_append(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_load(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_store(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_perform(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_set(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_jmp(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_goto(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_seq(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_blk(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_repeat(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_branch(RzILOp *op, RzStrBuf *sb, PJ *pj);
static void il_opdmp_invalid(RzILOp *op, RzStrBuf *sb, PJ *pj);

static dump_op_t il_opdmp[RZIL_OP_MAX] = {
	&il_opdmp_var, &il_opdmp_unk, &il_opdmp_ite, &il_opdmp_b0, &il_opdmp_b1, &il_opdmp_inv, &il_opdmp_and, &il_opdmp_or,
	&il_opdmp_int, &il_opdmp_msb, &il_opdmp_lsb, &il_opdmp_neg, &il_opdmp_not, &il_opdmp_add, &il_opdmp_sub, &il_opdmp_mul,
	&il_opdmp_div, &il_opdmp_sdiv, &il_opdmp_mod, &il_opdmp_smod, &il_opdmp_logand, &il_opdmp_logor, &il_opdmp_logxor,
	&il_opdmp_shiftr, &il_opdmp_shiftl, &il_opdmp_sle, &il_opdmp_ule, &il_opdmp_cast, &il_opdmp_concat,
	&il_opdmp_append, &il_opdmp_load, &il_opdmp_store, &il_opdmp_perform, &il_opdmp_set, &il_opdmp_jmp, &il_opdmp_goto,
	&il_opdmp_seq, &il_opdmp_blk, &il_opdmp_repeat, &il_opdmp_branch, &il_opdmp_invalid
};

#define il_op_unimplemented(name) \
	do { \
		if (sb) { \
			rz_strbuf_append(sb, name "(unimplemented)"); \
		} else { \
			pj_o(pj); \
			pj_ks(pj, "opcode", name); \
			pj_kb(pj, "missing", true); \
			pj_end(pj); \
		} \
	} while (0)

#define il_op_param_1(name, opx, v0) \
	do { \
		if (sb) { \
			rz_strbuf_append(sb, name "("); \
			il_op_resolve(opx->v0, sb, pj); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			pj_o(pj); \
			pj_ks(pj, "opcode", name); \
			pj_ka(pj, "params"); \
			il_op_resolve(opx->v0, sb, pj); \
			pj_end(pj); \
			pj_end(pj); \
		} \
	} while (0)

#define il_op_param_2(name, opx, v0, v1) \
	do { \
		if (sb) { \
			rz_strbuf_append(sb, name "("); \
			il_op_resolve(opx->v0, sb, pj); \
			rz_strbuf_append(sb, ", "); \
			il_op_resolve(opx->v1, sb, pj); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			pj_o(pj); \
			pj_ks(pj, "opcode", name); \
			pj_ka(pj, "params"); \
			il_op_resolve(opx->v0, sb, pj); \
			il_op_resolve(opx->v1, sb, pj); \
			pj_end(pj); \
			pj_end(pj); \
		} \
	} while (0)

#define il_op_param_3(name, opx, v0, v1, v2) \
	do { \
		if (sb) { \
			rz_strbuf_append(sb, name "("); \
			il_op_resolve(opx->v0, sb, pj); \
			rz_strbuf_append(sb, ", "); \
			il_op_resolve(opx->v1, sb, pj); \
			rz_strbuf_append(sb, ", "); \
			il_op_resolve(opx->v2, sb, pj); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			pj_o(pj); \
			pj_ks(pj, "opcode", name); \
			pj_ka(pj, "params"); \
			il_op_resolve(opx->v0, sb, pj); \
			il_op_resolve(opx->v1, sb, pj); \
			il_op_resolve(opx->v2, sb, pj); \
			pj_end(pj); \
			pj_end(pj); \
		} \
	} while (0)

static inline void il_op_resolve(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	if (op && op->code < RZIL_OP_MAX) {
		il_opdmp[op->code](op, sb, pj);
	} else if (sb && op) {
		rz_strbuf_appendf(sb, "unk_%u", op->code);
	} else if (pj && op) {
		char tmp[64];
		rz_strf(tmp, "unk_%u", op->code);
		pj_o(pj);
		pj_ks(pj, "opcode", tmp);
		pj_end(pj);
	} else if (sb) {
		rz_strbuf_append(sb, "null");
	} else {
		pj_null(pj);
	}
}

static void il_opdmp_var(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	RzILOpVar *opx = op->op.var;
	if (sb) {
		rz_strbuf_appendf(sb, "var(%s)", opx->v);
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "var");
		pj_ks(pj, "value", opx->v);
		pj_end(pj);
	}
}

static void il_opdmp_unk(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	if (sb) {
		rz_strbuf_append(sb, "unk");
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "unk");
		pj_end(pj);
	}
}

static void il_opdmp_ite(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_3("ite", op->op.ite, condition, x, y);
}

static void il_opdmp_b0(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	if (sb) {
		rz_strbuf_append(sb, "bool(false)");
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "bool");
		pj_kb(pj, "value", false);
		pj_end(pj);
	}
}

static void il_opdmp_b1(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	if (sb) {
		rz_strbuf_append(sb, "bool(true)");
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "bool");
		pj_kb(pj, "value", true);
		pj_end(pj);
	}
}

static void il_opdmp_inv(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("inv", op->op.inv, x, ret);
}

static void il_opdmp_and(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("and", op->op.and_, x, y);
}

static void il_opdmp_or(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("or", op->op.or_, x, y);
}

static void il_opdmp_int(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	RzILOpInt *opx = op->op.int_;
	if (sb) {
		rz_strbuf_appendf(sb, "int(n:%d, l:%u)", opx->value, opx->length);
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "int");
		pj_kn(pj, "length", opx->length);
		pj_kN(pj, "value", opx->value);
		pj_end(pj);
	}
}

static void il_opdmp_msb(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_1("msb", op->op.msb, bv);
}

static void il_opdmp_lsb(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_1("lsb", op->op.lsb, bv);
}

static void il_opdmp_neg(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_1("neg", op->op.neg, bv);
}

static void il_opdmp_not(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_1("not", op->op.not_, bv);
}

static void il_opdmp_add(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("add", op->op.add, x, y);
}

static void il_opdmp_sub(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("sub", op->op.sub, x, y);
}

static void il_opdmp_mul(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("mul", op->op.mul, x, y);
}

static void il_opdmp_div(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("div", op->op.div, x, y);
}

static void il_opdmp_sdiv(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("sdiv", op->op.sdiv, x, y);
}

static void il_opdmp_mod(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("mod", op->op.mod, x, y);
}

static void il_opdmp_smod(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("smod", op->op.smod, x, y);
}

static void il_opdmp_logand(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("logand", op->op.logand, x, y);
}

static void il_opdmp_logor(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("logor", op->op.logor, x, y);
}

static void il_opdmp_logxor(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("logxor", op->op.logxor, x, y);
}

static void il_opdmp_shiftr(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_3("shiftr", op->op.shiftr, x, y, fill_bit);
}

static void il_opdmp_shiftl(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_3("shiftl", op->op.shiftl, x, y, fill_bit);
}

static void il_opdmp_sle(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("sle", op->op.sle, x, y);
}

static void il_opdmp_ule(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("ule", op->op.ule, x, y);
}

static void il_opdmp_cast(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	RzILOpCast *opx = op->op.cast;
	if (sb) {
		rz_strbuf_append(sb, "cast(");
		il_op_resolve(opx->val, sb, pj);
		rz_strbuf_appendf(sb, ", l:%u, s:%d)", opx->length, opx->shift);
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "cast");
		pj_k(pj, "value");
		il_op_resolve(opx->val, sb, pj);
		pj_kn(pj, "length", opx->length);
		pj_kN(pj, "shift", opx->shift);
		pj_end(pj);
	}
}

static void il_opdmp_concat(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_unimplemented("concat");
}

static void il_opdmp_append(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_unimplemented("append");
}

static void il_opdmp_load(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	RzILOpLoad *opx = op->op.load;
	if (sb) {
		rz_strbuf_append(sb, "load(k:");
		il_op_resolve(opx->key, sb, pj);
		rz_strbuf_appendf(sb, ", m:%d)", opx->mem);
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "load");
		pj_k(pj, "key");
		il_op_resolve(opx->key, sb, pj);
		pj_kN(pj, "mem", opx->mem);
		pj_end(pj);
	}
}

static void il_opdmp_store(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	RzILOpStore *opx = op->op.store;

	if (sb) {
		rz_strbuf_append(sb, "store(k:");
		il_op_resolve(opx->key, sb, pj);
		rz_strbuf_append(sb, ", v:");
		il_op_resolve(opx->value, sb, pj);
		rz_strbuf_appendf(sb, ", m:%d)", opx->mem);
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "store");
		pj_k(pj, "key");
		il_op_resolve(opx->key, sb, pj);
		pj_k(pj, "value");
		il_op_resolve(opx->value, sb, pj);
		pj_kN(pj, "mem", opx->mem);
		pj_end(pj);
	}
}

static void il_opdmp_perform(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_1("perform", op->op.perform, eff);
}

static void il_opdmp_set(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	RzILOpSet *opx = op->op.set;
	if (sb) {
		rz_strbuf_appendf(sb, "set(d:%s, s:", opx->v);
		il_op_resolve(opx->x, sb, pj);
		rz_strbuf_append(sb, ")");
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "set");
		pj_ks(pj, "dst", opx->v);
		pj_k(pj, "src");
		il_op_resolve(opx->x, sb, pj);
		pj_end(pj);
	}
}

static void il_opdmp_jmp(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_1("jmp", op->op.jmp, dst);
}

static void il_opdmp_goto(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	RzILOpGoto *opx = op->op.goto_;
	if (sb) {
		rz_strbuf_appendf(sb, "goto(%s)", opx->lbl);
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "goto");
		pj_ks(pj, "label", opx->lbl);
		pj_end(pj);
	}
}

static void il_opdmp_seq(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("seq", op->op.seq, x, y);
}

static void il_opdmp_blk(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_unimplemented("blk");
}

static void il_opdmp_repeat(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_unimplemented("repeat");
}

static void il_opdmp_branch(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_3("branch", op->op.branch, condition, true_eff, false_eff);
}

static void il_opdmp_invalid(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	if (sb) {
		rz_strbuf_append(sb, "invalid");
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "invalid");
		pj_end(pj);
	}
}

RZ_API void rz_il_dump_list(RZ_NONNULL RzPVector *op_list, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(sb);
	if (!op_list) {
		rz_strbuf_append(sb, "[]");
		return;
	}

	ut32 i = 0;
	void **iter;
	rz_strbuf_append(sb, "[");
	rz_pvector_foreach (op_list, iter) {
		RzILOp *ilop = *iter;
		if (i > 0) {
			rz_strbuf_append(sb, ", ");
		}
		il_op_resolve(ilop, sb, NULL);
		i++;
	}
	rz_strbuf_append(sb, "]");
}

RZ_API void rz_il_json_list(RZ_NONNULL RzPVector *op_list, RZ_NONNULL PJ *pj) {
	rz_return_if_fail(pj);
	if (!op_list) {
		pj_null(pj);
		return;
	}

	pj_a(pj);
	void **iter;
	rz_pvector_foreach (op_list, iter) {
		RzILOp *ilop = *iter;
		il_op_resolve(ilop, NULL, pj);
	}
	pj_end(pj);
}