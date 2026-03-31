// SPDX-FileCopyrightText: 2021-2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file il_export_json.c
 * Outputs the IL statements & events in JSON format.
 * The string format of a statement is composed simply of s-expressions and looks like below:
 *    (store 0 (var ptr) (+ (load 0 (var ptr)) (bv 8 0x1)))
 * which can be deconstructed like below:
 * [
 *     {
 *         "opcode": "store",
 *         "key": {
 *             "opcode": "var",
 *             "value": "ptr"
 *         },
 *         "value": {
 *             "opcode": "add",
 *             "x": {
 *                 "opcode": "load",
 *                 "key": {
 *                     "opcode": "var",
 *                     "value": "ptr"
 *                 },
 *                 "mem": 0
 *             },
 *             "y": {
 *                 "opcode": "int",
 *                 "length": 8,
 *                 "value": 1
 *             }
 *         },
 *         "mem": 0
 *     }
 * ]
 *
 * The json format of an event looks like below:
 * {
 *     "event": "mem_write",
 *     "addr": "0x0000000000000000",
 *     "old": "0x00",
 *     "new": "0x01"
 * }
 */

#include <rz_il/rz_il_vm.h>

static void il_op_pure_json_resolve(RzILOpPure *op, PJ *pj);
static void il_op_effect_json_resolve(RzILOpEffect *op, PJ *pj);

#define il_op_param_0(name) \
	do { \
		pj_o(pj); \
		pj_ks(pj, "opcode", name); \
		pj_end(pj); \
	} while (0)

#define il_op_param_1(name, opx, v0) \
	do { \
		pj_o(pj); \
		pj_ks(pj, "opcode", name); \
		pj_k(pj, #v0); \
		il_op_pure_json_resolve(opx.v0, pj); \
		pj_end(pj); \
	} while (0)

#define il_op_param_2(name, opx, sort0, v0, sort1, v1) \
	do { \
		pj_o(pj); \
		pj_ks(pj, "opcode", name); \
		pj_k(pj, #v0); \
		il_op_##sort0##_json_resolve(opx.v0, pj); \
		pj_k(pj, #v1); \
		il_op_##sort1##_json_resolve(opx.v1, pj); \
		pj_end(pj); \
	} while (0)

#define il_op_param_3(name, opx, sort0, v0, sort1, v1, sort2, v2) \
	do { \
		pj_o(pj); \
		pj_ks(pj, "opcode", name); \
		pj_k(pj, #v0); \
		il_op_##sort0##_json_resolve(opx.v0, pj); \
		pj_k(pj, #v1); \
		il_op_##sort1##_json_resolve(opx.v1, pj); \
		pj_k(pj, #v2); \
		il_op_##sort2##_json_resolve(opx.v2, pj); \
		pj_end(pj); \
	} while (0)

#define il_op_param_1_with_rmode(name, opx, v0, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		pj_o(pj); \
		pj_ks(pj, "opcode", name); \
		pj_ks(pj, "rmode", rmode_str); \
		pj_k(pj, #v0); \
		il_op_pure_json_resolve(opx.v0, pj); \
		pj_end(pj); \
	} while (0)

#define il_op_param_2_with_rmode(name, opx, sort0, v0, sort1, v1, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		pj_o(pj); \
		pj_ks(pj, "opcode", name); \
		pj_ks(pj, "rmode", rmode_str); \
		pj_k(pj, #v0); \
		il_op_##sort0##_json_resolve(opx.v0, pj); \
		pj_k(pj, #v1); \
		il_op_##sort1##_json_resolve(opx.v1, pj); \
		pj_end(pj); \
	} while (0)

#define il_op_param_3_with_rmode(name, opx, sort0, v0, sort1, v1, sort2, v2, vr) \
	do { \
		const char *rmode_str = rz_il_float_stringify_rmode(opx.vr); \
		pj_o(pj); \
		pj_ks(pj, "opcode", name); \
		pj_ks(pj, "rmode", rmode_str); \
		pj_k(pj, #v0); \
		il_op_##sort0##_json_resolve(opx.v0, pj); \
		pj_k(pj, #v1); \
		il_op_##sort1##_json_resolve(opx.v1, pj); \
		pj_k(pj, #v2); \
		il_op_##sort2##_json_resolve(opx.v2, pj); \
		pj_end(pj); \
	} while (0)

static void il_opdmp_var(RzILOpPure *op, PJ *pj) {
	RzILOpArgsVar *opx = &op->op.var;
	pj_o(pj);
	pj_ks(pj, "opcode", "var");
	pj_ks(pj, "value", opx->v);
	pj_end(pj);
}

static void il_opdmp_ite(RzILOpPure *op, PJ *pj) {
	il_op_param_3("ite", op->op.ite, pure, condition, pure, x, pure, y);
}

static void il_opdmp_let(RzILOpPure *op, PJ *pj) {
	RzILOpArgsLet *opx = &op->op.let;
	pj_o(pj);
	pj_ks(pj, "opcode", "let");
	pj_ks(pj, "dst", opx->name);
	pj_k(pj, "exp");
	il_op_pure_json_resolve(opx->exp, pj);
	pj_k(pj, "body");
	il_op_pure_json_resolve(opx->body, pj);
	pj_end(pj);
}

static void il_opdmp_bool_false(RzILOpPure *op, PJ *pj) {
	pj_o(pj);
	pj_ks(pj, "opcode", "bool");
	pj_kb(pj, "value", false);
	pj_end(pj);
}

static void il_opdmp_bool_true(RzILOpPure *op, PJ *pj) {
	pj_o(pj);
	pj_ks(pj, "opcode", "bool");
	pj_kb(pj, "value", true);
	pj_end(pj);
}

static void il_opdmp_bool_inv(RzILOpPure *op, PJ *pj) {
	il_op_param_1("!", op->op.boolinv, x);
}

static void il_opdmp_bool_and(RzILOpPure *op, PJ *pj) {
	il_op_param_2("&&", op->op.booland, pure, x, pure, y);
}

static void il_opdmp_bool_or(RzILOpPure *op, PJ *pj) {
	il_op_param_2("||", op->op.boolor, pure, x, pure, y);
}

static void il_opdmp_bool_xor(RzILOpPure *op, PJ *pj) {
	il_op_param_2("^^", op->op.boolxor, pure, x, pure, y);
}

static void il_opdmp_bitv(RzILOpPure *op, PJ *pj) {
	RzILOpArgsBv *opx = &op->op.bitv;
	char *num = rz_bv_as_hex_string(opx->value, false);
	pj_o(pj);
	pj_ks(pj, "opcode", "bitv");
	pj_ks(pj, "bits", num);
	pj_kn(pj, "len", opx->value->len);
	pj_end(pj);
	free(num);
}

static void il_opdmp_msb(RzILOpPure *op, PJ *pj) {
	il_op_param_1("msb", op->op.msb, bv);
}

static void il_opdmp_lsb(RzILOpPure *op, PJ *pj) {
	il_op_param_1("lsb", op->op.lsb, bv);
}

static void il_opdmp_is_zero(RzILOpPure *op, PJ *pj) {
	il_op_param_1("is_zero", op->op.lsb, bv);
}

static void il_opdmp_neg(RzILOpPure *op, PJ *pj) {
	il_op_param_1("~-", op->op.neg, bv);
}

static void il_opdmp_lognot(RzILOpPure *op, PJ *pj) {
	il_op_param_1("~", op->op.lognot, bv);
}

static void il_opdmp_add(RzILOpPure *op, PJ *pj) {
	il_op_param_2("+", op->op.add, pure, x, pure, y);
}

static void il_opdmp_sub(RzILOpPure *op, PJ *pj) {
	il_op_param_2("-", op->op.sub, pure, x, pure, y);
}

static void il_opdmp_mul(RzILOpPure *op, PJ *pj) {
	il_op_param_2("*", op->op.mul, pure, x, pure, y);
}

static void il_opdmp_div(RzILOpPure *op, PJ *pj) {
	il_op_param_2("div", op->op.div, pure, x, pure, y);
}

static void il_opdmp_sdiv(RzILOpPure *op, PJ *pj) {
	il_op_param_2("sdiv", op->op.sdiv, pure, x, pure, y);
}

static void il_opdmp_mod(RzILOpPure *op, PJ *pj) {
	il_op_param_2("mod", op->op.mod, pure, x, pure, y);
}

static void il_opdmp_smod(RzILOpPure *op, PJ *pj) {
	il_op_param_2("smod", op->op.smod, pure, x, pure, y);
}

static void il_opdmp_logand(RzILOpPure *op, PJ *pj) {
	il_op_param_2("&", op->op.logand, pure, x, pure, y);
}

static void il_opdmp_logor(RzILOpPure *op, PJ *pj) {
	il_op_param_2("|", op->op.logor, pure, x, pure, y);
}

static void il_opdmp_logxor(RzILOpPure *op, PJ *pj) {
	il_op_param_2("^", op->op.logxor, pure, x, pure, y);
}

static void il_opdmp_shiftr(RzILOpPure *op, PJ *pj) {
	il_op_param_3(">>", op->op.shiftr, pure, x, pure, y, pure, fill_bit);
}

static void il_opdmp_shiftl(RzILOpPure *op, PJ *pj) {
	il_op_param_3("<<", op->op.shiftl, pure, x, pure, y, pure, fill_bit);
}

static void il_opdmp_eq(RzILOpPure *op, PJ *pj) {
	il_op_param_2("==", op->op.ule, pure, x, pure, y);
}

static void il_opdmp_sle(RzILOpPure *op, PJ *pj) {
	il_op_param_2("sle", op->op.sle, pure, x, pure, y);
}

static void il_opdmp_ule(RzILOpPure *op, PJ *pj) {
	il_op_param_2("ule", op->op.ule, pure, x, pure, y);
}

static void il_opdmp_cast(RzILOpPure *op, PJ *pj) {
	RzILOpArgsCast *opx = &op->op.cast;
	pj_o(pj);
	pj_ks(pj, "opcode", "cast");
	pj_k(pj, "value");
	il_op_pure_json_resolve(opx->val, pj);
	pj_kn(pj, "length", opx->length);
	pj_k(pj, "fill");
	il_op_pure_json_resolve(opx->fill, pj);
	pj_end(pj);
}

static void il_opdmp_append(RzILOpPure *op, PJ *pj) {
	il_op_param_2("append", op->op.append, pure, high, pure, low);
}

static void il_opdmp_float(RzILOpPure *op, PJ *pj) {
	RzILOpArgsFloat *opx = &op->op.float_;
	pj_o(pj);
	pj_ks(pj, "opcode", "float");
	pj_kn(pj, "format", opx->r);
	pj_k(pj, "bv");
	il_op_pure_json_resolve(opx->bv, pj);
	pj_end(pj);
}

static void il_opdmp_fbits(RzILOpPure *op, PJ *pj) {
	il_op_param_1("fbits", op->op.fbits, f);
}

static void il_opdmp_is_finite(RzILOpPure *op, PJ *pj) {
	il_op_param_1("is_finite", op->op.is_finite, f);
}

static void il_opdmp_is_nan(RzILOpPure *op, PJ *pj) {
	il_op_param_1("is_nan", op->op.is_nan, f);
}

static void il_opdmp_is_inf(RzILOpPure *op, PJ *pj) {
	il_op_param_1("is_inf", op->op.is_inf, f);
}

static void il_opdmp_is_fzero(RzILOpPure *op, PJ *pj) {
	il_op_param_1("is_fzero", op->op.is_fzero, f);
}

static void il_opdmp_is_fneg(RzILOpPure *op, PJ *pj) {
	il_op_param_1("is_fneg", op->op.is_fneg, f);
}

static void il_opdmp_is_fpos(RzILOpPure *op, PJ *pj) {
	il_op_param_1("is_fpos", op->op.is_fpos, f);
}

static void il_opdmp_fneg(RzILOpPure *op, PJ *pj) {
	il_op_param_1("fneg", op->op.fneg, f);
}

static void il_opdmp_fabs(RzILOpPure *op, PJ *pj) {
	il_op_param_1("fpos", op->op.fabs, f);
}

static void il_opdmp_fcast_int(RzILOpPure *op, PJ *pj) {
	RzILOpArgsFCastint *opx = &op->op.fcast_int;
	pj_o(pj);
	pj_ks(pj, "opcode", "fcast_int");
	pj_kn(pj, "length", opx->length);
	pj_ks(pj, "rmode", rz_il_float_stringify_rmode(opx->mode));
	pj_k(pj, "value");
	il_op_pure_json_resolve(opx->f, pj);
	pj_end(pj);
}

static void il_opdmp_fcast_sint(RzILOpPure *op, PJ *pj) {
	RzILOpArgsFCastsint *opx = &op->op.fcast_sint;
	pj_o(pj);
	pj_ks(pj, "opcode", "fcast_sint");
	pj_kn(pj, "length", opx->length);
	pj_ks(pj, "rmode", rz_il_float_stringify_rmode(opx->mode));
	pj_k(pj, "value");
	il_op_pure_json_resolve(opx->f, pj);
	pj_end(pj);
}

static void il_opdmp_fcast_float(RzILOpPure *op, PJ *pj) {
	RzILOpArgsFCastfloat *opx = &op->op.fcast_float;
	pj_o(pj);
	pj_ks(pj, "opcode", "fcast_float");
	pj_ks(pj, "format", rz_il_float_stringify_format(opx->format));
	pj_ks(pj, "rmode", rz_il_float_stringify_rmode(opx->mode));
	pj_k(pj, "value");
	il_op_pure_json_resolve(opx->bv, pj);
	pj_end(pj);
}

static void il_opdmp_fcast_sfloat(RzILOpPure *op, PJ *pj) {
	RzILOpArgsFCastsfloat *opx = &op->op.fcast_sfloat;
	pj_o(pj);
	pj_ks(pj, "opcode", "fcast_sfloat");
	pj_ks(pj, "format", rz_il_float_stringify_format(opx->format));
	pj_ks(pj, "rmode", rz_il_float_stringify_rmode(opx->mode));
	pj_k(pj, "value");
	il_op_pure_json_resolve(opx->bv, pj);
	pj_end(pj);
}

static void il_opdmp_fconvert(RzILOpPure *op, PJ *pj) {
	RzILOpArgsFconvert *opx = &op->op.fconvert;
	pj_o(pj);
	pj_ks(pj, "opcode", "fconvert");
	pj_ks(pj, "format", rz_il_float_stringify_format(opx->format));
	pj_ks(pj, "rmode", rz_il_float_stringify_rmode(opx->mode));
	pj_k(pj, "value");
	il_op_pure_json_resolve(opx->f, pj);
	pj_end(pj);
}

static void il_opdmp_fround(RzILOpPure *op, PJ *pj) {
	RzILOpArgsFround *opx = &op->op.fround;
	pj_o(pj);
	pj_ks(pj, "opcode", "fround");
	pj_ks(pj, "rmode", rz_il_float_stringify_rmode(opx->rmode));
	pj_k(pj, "value");
	il_op_pure_json_resolve(opx->f, pj);
	pj_end(pj);
}

static void il_opdmp_frequal(RzILOpPure *op, PJ *pj) {
	RzILOpArgsFrequal *opx = &op->op.frequal;
	pj_o(pj);
	pj_ks(pj, "opcode", "frequal");
	pj_ks(pj, "rmode_x", rz_il_float_stringify_rmode(opx->x));
	pj_ks(pj, "rmode_y", rz_il_float_stringify_rmode(opx->y));
	pj_end(pj);
}

static void il_opdmp_fsucc(RzILOpPure *op, PJ *pj) {
	il_op_param_1("fsucc", op->op.fsucc, f);
}
static void il_opdmp_fpred(RzILOpPure *op, PJ *pj) {
	il_op_param_1("fpred", op->op.fpred, f);
}

static void il_opdmp_forder(RzILOpPure *op, PJ *pj) {
	il_op_param_2("<.", op->op.forder, pure, x, pure, y);
}

static void il_opdmp_fsqrt(RzILOpPure *op, PJ *pj) {
	il_op_param_1_with_rmode("fsqrt", op->op.fsqrt, f, rmode);
}

static void il_opdmp_frsqrt(RzILOpPure *op, PJ *pj) {
	il_op_param_1_with_rmode("frsqrt", op->op.frsqrt, f, rmode);
}

static void il_opdmp_fadd(RzILOpPure *op, PJ *pj) {
	il_op_param_2_with_rmode("+.", op->op.fadd, pure, x, pure, y, rmode);
}

static void il_opdmp_fsub(RzILOpPure *op, PJ *pj) {
	il_op_param_2_with_rmode("-.", op->op.fsub, pure, x, pure, y, rmode);
}

static void il_opdmp_fmul(RzILOpPure *op, PJ *pj) {
	il_op_param_2_with_rmode("*.", op->op.fmul, pure, x, pure, y, rmode);
}

static void il_opdmp_fdiv(RzILOpPure *op, PJ *pj) {
	il_op_param_2_with_rmode("/.", op->op.fdiv, pure, x, pure, y, rmode);
}

static void il_opdmp_fmod(RzILOpPure *op, PJ *pj) {
	il_op_param_2_with_rmode("%.", op->op.fmod, pure, x, pure, y, rmode);
}

static void il_opdmp_fhypot(RzILOpPure *op, PJ *pj) {
	il_op_param_2_with_rmode("hypot", op->op.fhypot, pure, x, pure, y, rmode);
}

static void il_opdmp_fpow(RzILOpPure *op, PJ *pj) {
	il_op_param_2_with_rmode("pow", op->op.fpow, pure, x, pure, y, rmode);
}

static void il_opdmp_fmad(RzILOpPure *op, PJ *pj) {
	il_op_param_3_with_rmode("fmad", op->op.fmad, pure, x, pure, y, pure, z, rmode);
}

static void il_opdmp_fpown(RzILOpPure *op, PJ *pj) {
	il_op_param_2_with_rmode("fpown", op->op.fpown, pure, f, pure, n, rmode);
}

static void il_opdmp_frootn(RzILOpPure *op, PJ *pj) {
	il_op_param_2_with_rmode("frootn", op->op.frootn, pure, f, pure, n, rmode);
}

static void il_opdmp_fcompound(RzILOpPure *op, PJ *pj) {
	il_op_param_2_with_rmode("fcompound", op->op.fcompound, pure, f, pure, n, rmode);
}

static void il_opdmp_load(RzILOpPure *op, PJ *pj) {
	RzILOpArgsLoad *opx = &op->op.load;
	pj_o(pj);
	pj_ks(pj, "opcode", "load");
	pj_kn(pj, "mem", opx->mem);
	pj_k(pj, "key");
	il_op_pure_json_resolve(opx->key, pj);
	pj_end(pj);
}

static void il_opdmp_loadw(RzILOpPure *op, PJ *pj) {
	RzILOpArgsLoadW *opx = &op->op.loadw;
	pj_o(pj);
	pj_ks(pj, "opcode", "loadw");
	pj_kn(pj, "mem", opx->mem);
	pj_k(pj, "key");
	il_op_pure_json_resolve(opx->key, pj);
	pj_kn(pj, "bits", opx->n_bits);
	pj_end(pj);
}

static void il_opdmp_store(RzILOpEffect *op, PJ *pj) {
	RzILOpArgsStore *opx = &op->op.store;
	pj_o(pj);
	pj_ks(pj, "opcode", "store");
	pj_kn(pj, "mem", opx->mem);
	pj_k(pj, "key");
	il_op_pure_json_resolve(opx->key, pj);
	pj_k(pj, "value");
	il_op_pure_json_resolve(opx->value, pj);
	pj_end(pj);
}

static void il_opdmp_storew(RzILOpEffect *op, PJ *pj) {
	RzILOpArgsStore *opx = &op->op.store;
	pj_o(pj);
	pj_ks(pj, "opcode", "storew");
	pj_kn(pj, "mem", opx->mem);
	pj_k(pj, "key");
	il_op_pure_json_resolve(opx->key, pj);
	pj_k(pj, "value");
	il_op_pure_json_resolve(opx->value, pj);
	pj_end(pj);
}

static void il_opdmp_nop(RzILOpEffect *op, PJ *pj) {
	il_op_param_0("nop");
}

static void il_opdmp_empty(RzILOpEffect *op, PJ *pj) {
	il_op_param_0("empty");
}

static void il_opdmp_set(RzILOpEffect *op, PJ *pj) {
	RzILOpArgsSet *opx = &op->op.set;
	pj_o(pj);
	pj_ks(pj, "opcode", "set");
	pj_ks(pj, "dst", opx->v);
	pj_k(pj, "src");
	il_op_pure_json_resolve(opx->x, pj);
	pj_end(pj);
}

static void il_opdmp_jmp(RzILOpEffect *op, PJ *pj) {
	il_op_param_1("jmp", op->op.jmp, dst);
}

static void il_opdmp_goto(RzILOpEffect *op, PJ *pj) {
	RzILOpArgsGoto *opx = &op->op.goto_;
	pj_o(pj);
	pj_ks(pj, "opcode", "goto");
	pj_ks(pj, "label", opx->lbl);
	pj_end(pj);
}

static void il_opdmp_seq(RzILOpEffect *op, PJ *pj) {
	il_op_param_2("seq", op->op.seq, effect, x, effect, y);
}

static void il_opdmp_blk(RzILOpEffect *op, PJ *pj) {
	RzILOpArgsBlk *opx = &op->op.blk;
	pj_o(pj);
	pj_ks(pj, "label", opx->label);
	pj_k(pj, "data");
	il_op_effect_json_resolve(opx->data_eff, pj);
	pj_k(pj, "ctrl");
	il_op_effect_json_resolve(opx->ctrl_eff, pj);
	pj_end(pj);
}

static void il_opdmp_repeat(RzILOpEffect *op, PJ *pj) {
	il_op_param_2("repeat", op->op.repeat, pure, condition, effect, data_eff);
}

static void il_opdmp_branch(RzILOpEffect *op, PJ *pj) {
	il_op_param_3("branch", op->op.branch, pure, condition, effect, true_eff, effect, false_eff);
}

static void il_op_pure_json_resolve(RzILOpPure *op, PJ *pj) {
	if (!op) {
		if (pj) {
			pj_o(pj);
			pj_knull(pj, "opcode");
			pj_end(pj);
		}
		return;
	}
	switch (op->code) {
	case RZ_IL_OP_VAR:
		il_opdmp_var(op, pj);
		return;
	case RZ_IL_OP_ITE:
		il_opdmp_ite(op, pj);
		return;
	case RZ_IL_OP_LET:
		il_opdmp_let(op, pj);
		return;
	case RZ_IL_OP_B0:
		il_opdmp_bool_false(op, pj);
		return;
	case RZ_IL_OP_B1:
		il_opdmp_bool_true(op, pj);
		return;
	case RZ_IL_OP_INV:
		il_opdmp_bool_inv(op, pj);
		return;
	case RZ_IL_OP_AND:
		il_opdmp_bool_and(op, pj);
		return;
	case RZ_IL_OP_OR:
		il_opdmp_bool_or(op, pj);
		return;
	case RZ_IL_OP_XOR:
		il_opdmp_bool_xor(op, pj);
		return;
	case RZ_IL_OP_BITV:
		il_opdmp_bitv(op, pj);
		return;
	case RZ_IL_OP_MSB:
		il_opdmp_msb(op, pj);
		return;
	case RZ_IL_OP_LSB:
		il_opdmp_lsb(op, pj);
		return;
	case RZ_IL_OP_IS_ZERO:
		il_opdmp_is_zero(op, pj);
		return;
	case RZ_IL_OP_NEG:
		il_opdmp_neg(op, pj);
		return;
	case RZ_IL_OP_LOGNOT:
		il_opdmp_lognot(op, pj);
		return;
	case RZ_IL_OP_ADD:
		il_opdmp_add(op, pj);
		return;
	case RZ_IL_OP_SUB:
		il_opdmp_sub(op, pj);
		return;
	case RZ_IL_OP_MUL:
		il_opdmp_mul(op, pj);
		return;
	case RZ_IL_OP_DIV:
		il_opdmp_div(op, pj);
		return;
	case RZ_IL_OP_SDIV:
		il_opdmp_sdiv(op, pj);
		return;
	case RZ_IL_OP_MOD:
		il_opdmp_mod(op, pj);
		return;
	case RZ_IL_OP_SMOD:
		il_opdmp_smod(op, pj);
		return;
	case RZ_IL_OP_LOGAND:
		il_opdmp_logand(op, pj);
		return;
	case RZ_IL_OP_LOGOR:
		il_opdmp_logor(op, pj);
		return;
	case RZ_IL_OP_LOGXOR:
		il_opdmp_logxor(op, pj);
		return;
	case RZ_IL_OP_SHIFTR:
		il_opdmp_shiftr(op, pj);
		return;
	case RZ_IL_OP_SHIFTL:
		il_opdmp_shiftl(op, pj);
		return;
	case RZ_IL_OP_EQ:
		il_opdmp_eq(op, pj);
		return;
	case RZ_IL_OP_SLE:
		il_opdmp_sle(op, pj);
		return;
	case RZ_IL_OP_ULE:
		il_opdmp_ule(op, pj);
		return;
	case RZ_IL_OP_CAST:
		il_opdmp_cast(op, pj);
		return;
	case RZ_IL_OP_APPEND:
		il_opdmp_append(op, pj);
		return;
	case RZ_IL_OP_LOAD:
		il_opdmp_load(op, pj);
		return;
	case RZ_IL_OP_LOADW:
		il_opdmp_loadw(op, pj);
		return;
	case RZ_IL_OP_FLOAT:
		il_opdmp_float(op, pj);
		return;
	case RZ_IL_OP_FBITS:
		il_opdmp_fbits(op, pj);
		return;
	case RZ_IL_OP_IS_FINITE:
		il_opdmp_is_finite(op, pj);
		return;
	case RZ_IL_OP_IS_NAN:
		il_opdmp_is_nan(op, pj);
		return;
	case RZ_IL_OP_IS_INF:
		il_opdmp_is_inf(op, pj);
		return;
	case RZ_IL_OP_IS_FZERO:
		il_opdmp_is_fzero(op, pj);
		return;
	case RZ_IL_OP_IS_FNEG:
		il_opdmp_is_fneg(op, pj);
		return;
	case RZ_IL_OP_IS_FPOS:
		il_opdmp_is_fpos(op, pj);
		return;
	case RZ_IL_OP_FNEG:
		il_opdmp_fneg(op, pj);
		return;
	case RZ_IL_OP_FABS:
		il_opdmp_fabs(op, pj);
		return;
	case RZ_IL_OP_FCAST_INT:
		il_opdmp_fcast_int(op, pj);
		return;
	case RZ_IL_OP_FCAST_SINT:
		il_opdmp_fcast_sint(op, pj);
		return;
	case RZ_IL_OP_FCAST_FLOAT:
		il_opdmp_fcast_float(op, pj);
		return;
	case RZ_IL_OP_FCAST_SFLOAT:
		il_opdmp_fcast_sfloat(op, pj);
		return;
	case RZ_IL_OP_FCONVERT:
		il_opdmp_fconvert(op, pj);
		return;
	case RZ_IL_OP_FREQUAL:
		il_opdmp_frequal(op, pj);
		return;
	case RZ_IL_OP_FSUCC:
		il_opdmp_fsucc(op, pj);
		return;
	case RZ_IL_OP_FPRED:
		il_opdmp_fpred(op, pj);
		return;
	case RZ_IL_OP_FORDER:
		il_opdmp_forder(op, pj);
		return;
	case RZ_IL_OP_FROUND:
		il_opdmp_fround(op, pj);
		return;
	case RZ_IL_OP_FSQRT:
		il_opdmp_fsqrt(op, pj);
		return;
	case RZ_IL_OP_FRSQRT:
		il_opdmp_frsqrt(op, pj);
		return;
	case RZ_IL_OP_FADD:
		il_opdmp_fadd(op, pj);
		return;
	case RZ_IL_OP_FSUB:
		il_opdmp_fsub(op, pj);
		return;
	case RZ_IL_OP_FMUL:
		il_opdmp_fmul(op, pj);
		return;
	case RZ_IL_OP_FDIV:
		il_opdmp_fdiv(op, pj);
		return;
	case RZ_IL_OP_FMOD:
		il_opdmp_fmod(op, pj);
		return;
	case RZ_IL_OP_FHYPOT:
		il_opdmp_fhypot(op, pj);
		return;
	case RZ_IL_OP_FPOW:
		il_opdmp_fpow(op, pj);
		return;
	case RZ_IL_OP_FMAD:
		il_opdmp_fmad(op, pj);
		return;
	case RZ_IL_OP_FPOWN:
		il_opdmp_fpown(op, pj);
		return;
	case RZ_IL_OP_FROOTN:
		il_opdmp_frootn(op, pj);
		return;
	case RZ_IL_OP_FCOMPOUND:
		il_opdmp_fcompound(op, pj);
		return;

	default: {
		rz_warn_if_reached();
		char tmp[64];
		rz_strf(tmp, "unk_%u", op->code);
		pj_o(pj);
		pj_ks(pj, "opcode", tmp);
		pj_end(pj);
	} break;
	}
}

static void il_op_effect_json_resolve(RzILOpEffect *op, PJ *pj) {
	if (!op) {
		pj_o(pj);
		pj_ks(pj, "opcode", "nop");
		pj_end(pj);
		return;
	}
	switch (op->code) {
	case RZ_IL_OP_EMPTY:
		il_opdmp_empty(op, pj);
		break;
	case RZ_IL_OP_STORE:
		il_opdmp_store(op, pj);
		return;
	case RZ_IL_OP_STOREW:
		il_opdmp_storew(op, pj);
		return;
	case RZ_IL_OP_NOP:
		il_opdmp_nop(op, pj);
		return;
	case RZ_IL_OP_SET:
		il_opdmp_set(op, pj);
		return;
	case RZ_IL_OP_JMP:
		il_opdmp_jmp(op, pj);
		return;
	case RZ_IL_OP_GOTO:
		il_opdmp_goto(op, pj);
		return;
	case RZ_IL_OP_SEQ:
		il_opdmp_seq(op, pj);
		return;
	case RZ_IL_OP_BLK:
		il_opdmp_blk(op, pj);
		return;
	case RZ_IL_OP_REPEAT:
		il_opdmp_repeat(op, pj);
		return;
	case RZ_IL_OP_BRANCH:
		il_opdmp_branch(op, pj);
		return;
	default: {
		rz_warn_if_reached();
		char tmp[64];
		rz_strf(tmp, "unk_%u", op->code);
		pj_o(pj);
		pj_ks(pj, "opcode", tmp);
		pj_end(pj);
	} break;
	}
}

/**
 * Generates the JSON representation of the IL statement
 * \param op IL statement
 * \param pj PJ*, a pointer to the JSON buffer
 */
RZ_API void rz_il_op_pure_json(RZ_NONNULL RzILOpPure *op, RZ_NONNULL PJ *pj) {
	rz_return_if_fail(op && pj);
	il_op_pure_json_resolve(op, pj);
}

/**
 * Generates the JSON representation of the IL statement
 * \param op IL statement
 * \param pj PJ*, a pointer to the JSON buffer
 */
RZ_API void rz_il_op_effect_json(RZ_NONNULL RzILOpEffect *op, RZ_NONNULL PJ *pj) {
	rz_return_if_fail(op && pj);
	il_op_effect_json_resolve(op, pj);
}

RZ_API void rz_il_event_json(RZ_NONNULL RzILEvent *evt, RZ_NONNULL PJ *pj) {
	rz_return_if_fail(evt && pj);
	char *tmp0 = NULL, *tmp1 = NULL, *tmp2 = NULL;

	switch (evt->type) {
	case RZ_IL_EVENT_EXCEPTION:
		pj_o(pj);
		pj_ks(pj, "type", "exception");
		pj_ks(pj, "exception", rz_il_event_exception_msg(evt->data.exception));
		pj_end(pj);
		break;
	case RZ_IL_EVENT_PC_WRITE:
		tmp0 = rz_bv_as_hex_string(evt->data.pc_write.old_pc, false);
		tmp1 = rz_bv_as_hex_string(evt->data.pc_write.new_pc, false);
		pj_o(pj);
		pj_ks(pj, "type", "pc_write");
		pj_ks(pj, "old", tmp0);
		pj_ks(pj, "new", tmp1);
		pj_end(pj);
		break;
	case RZ_IL_EVENT_MEM_READ:
		tmp0 = rz_bv_as_hex_string(evt->data.mem_read.address, false);
		tmp1 = rz_bv_as_hex_string(evt->data.mem_read.value, false);
		pj_o(pj);
		pj_ks(pj, "type", "mem_read");
		pj_ks(pj, "address", tmp0);
		pj_ks(pj, "value", tmp1);
		pj_end(pj);
		break;
	case RZ_IL_EVENT_VAR_READ:
		tmp1 = rz_il_value_stringify(evt->data.var_read.value);
		pj_o(pj);
		pj_ks(pj, "type", "var_read");
		pj_ks(pj, "name", evt->data.var_read.variable);
		pj_ks(pj, "value", tmp1 ? tmp1 : "uninitialized variable");
		pj_end(pj);
		break;
	case RZ_IL_EVENT_MEM_WRITE:
		tmp0 = rz_bv_as_hex_string(evt->data.mem_write.address, false);
		tmp1 = evt->data.mem_write.old_value ? rz_bv_as_hex_string(evt->data.mem_write.old_value, false) : NULL;
		tmp2 = rz_bv_as_hex_string(evt->data.mem_write.new_value, false);
		pj_o(pj);
		pj_ks(pj, "type", "mem_write");
		pj_ks(pj, "address", tmp0);
		pj_ks(pj, "old", tmp1 ? tmp1 : "uninitialized memory");
		pj_ks(pj, "new", tmp2);
		pj_end(pj);
		break;
	case RZ_IL_EVENT_VAR_WRITE:
		tmp1 = rz_il_value_stringify(evt->data.var_write.old_value);
		tmp2 = rz_il_value_stringify(evt->data.var_write.new_value);
		pj_o(pj);
		pj_ks(pj, "type", "var_write");
		pj_ks(pj, "name", evt->data.var_write.variable);
		pj_ks(pj, "old", tmp1 ? tmp1 : "uninitialized variable");
		pj_ks(pj, "new", tmp2);
		pj_end(pj);
		break;
	default:
		rz_warn_if_reached();
		pj_o(pj);
		pj_ks(pj, "type", "unknown");
		pj_end(pj);
		break;
	}

	free(tmp0);
	free(tmp1);
	free(tmp2);
}
