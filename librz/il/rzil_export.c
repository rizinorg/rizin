// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file rzil_export.c
 * Outputs the IL statements & events in JSON or string format.
 * The string format of a statement looks like below:
 *    [store(key:var(v:ptr), value:add(x:load(key:var(v:ptr), mem:0), y:int(value:1, length:8)), mem:0)]
 * which can be deconstructed like below
 * [
 *     store(
 *         key:var(
 *             v:ptr
 *         ),
 *         value:add(
 *             x:load(
 *                 key:var(
 *                     v:ptr
 *                 ),
 *                 mem:0
 *             ),
 *             y:int(
 *                 value:1,
 *                 length:8
 *             )
 *         ),
 *         mem:0
 *     )
 * ]
 *
 * The json format of a statement looks like below:
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
 * The string format of an event looks like below:
 *    mem_write(addr: 0x0000000000000000, old: 0x00, new: 0x01)
 *
 * The json format of an event looks like below:
 * {
 *     "event": "mem_write",
 *     "old": "0x00",
 *     "new": "0x01"
 * }
 */

#include <rz_il/rzil_vm.h>

static void il_op_resolve(RzILOp *op, RzStrBuf *sb, PJ *pj);

#define il_op_unimplemented(name) \
	do { \
		if (sb) { \
			rz_strbuf_append(sb, name "(unimplemented)"); \
		} else { \
			pj_o(pj); \
			pj_ks(pj, "opcode", name); \
			pj_kb(pj, "unimplemented", true); \
			pj_end(pj); \
		} \
	} while (0)

#define il_op_param_1(name, opx, v0) \
	do { \
		if (sb) { \
			rz_strbuf_append(sb, name "(" #v0 ":"); \
			il_op_resolve(opx->v0, sb, pj); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			pj_o(pj); \
			pj_ks(pj, "opcode", name); \
			pj_k(pj, #v0); \
			il_op_resolve(opx->v0, sb, pj); \
			pj_end(pj); \
		} \
	} while (0)

#define il_op_param_2(name, opx, v0, v1) \
	do { \
		if (sb) { \
			rz_strbuf_append(sb, name "(" #v0 ":"); \
			il_op_resolve(opx->v0, sb, pj); \
			rz_strbuf_append(sb, ", " #v1 ":"); \
			il_op_resolve(opx->v1, sb, pj); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			pj_o(pj); \
			pj_ks(pj, "opcode", name); \
			pj_k(pj, #v0); \
			il_op_resolve(opx->v0, sb, pj); \
			pj_k(pj, #v1); \
			il_op_resolve(opx->v1, sb, pj); \
			pj_end(pj); \
		} \
	} while (0)

#define il_op_param_3(name, opx, v0, v1, v2) \
	do { \
		if (sb) { \
			rz_strbuf_append(sb, name "(" #v0 ":"); \
			il_op_resolve(opx->v0, sb, pj); \
			rz_strbuf_append(sb, ", " #v1 ":"); \
			il_op_resolve(opx->v1, sb, pj); \
			rz_strbuf_append(sb, ", " #v2 ":"); \
			il_op_resolve(opx->v2, sb, pj); \
			rz_strbuf_append(sb, ")"); \
		} else { \
			pj_o(pj); \
			pj_ks(pj, "opcode", name); \
			pj_k(pj, #v0); \
			il_op_resolve(opx->v0, sb, pj); \
			pj_k(pj, #v1); \
			il_op_resolve(opx->v1, sb, pj); \
			pj_k(pj, #v2); \
			il_op_resolve(opx->v2, sb, pj); \
			pj_end(pj); \
		} \
	} while (0)

static void il_opdmp_var(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	RzILOpVar *opx = op->op.var;
	if (sb) {
		rz_strbuf_appendf(sb, "var(v:%s)", opx->v);
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

static void il_opdmp_bool_false(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	if (sb) {
		rz_strbuf_append(sb, "bool(false)");
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "bool");
		pj_kb(pj, "value", false);
		pj_end(pj);
	}
}

static void il_opdmp_bool_true(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	if (sb) {
		rz_strbuf_append(sb, "bool(true)");
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "bool");
		pj_kb(pj, "value", true);
		pj_end(pj);
	}
}

static void il_opdmp_bool_inv(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("inv", op->op.boolinv, x, ret);
}

static void il_opdmp_bool_and(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("booland", op->op.booland, x, y);
}

static void il_opdmp_bool_or(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("boolor", op->op.boolor, x, y);
}

static void il_opdmp_bool_xor(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_2("boolxor", op->op.boolxor, x, y);
}

static void il_opdmp_bitv(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	RzILOpBv *opx = op->op.bitv;
	char *num = rz_il_bv_as_hex_string(opx->value);
	if (sb) {
		rz_strbuf_appendf(sb, "bitv(bits:%s, len:%u)", num, opx->value->len);
	} else {
		pj_o(pj);
		pj_ks(pj, "opcode", "bitv");
		pj_ks(pj, "bits", num);
		pj_kn(pj, "len", opx->value->len);
		pj_end(pj);
	}
	free(num);
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

static void il_opdmp_lognot(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	il_op_param_1("lognot", op->op.lognot, bv);
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
		rz_strbuf_append(sb, "cast(val:");
		il_op_resolve(opx->val, sb, pj);
		rz_strbuf_appendf(sb, ", length:%u, shift:%d)", opx->length, opx->shift);
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
		rz_strbuf_append(sb, "load(key:");
		il_op_resolve(opx->key, sb, pj);
		rz_strbuf_appendf(sb, ", mem:%d)", opx->mem);
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
		rz_strbuf_append(sb, "store(key:");
		il_op_resolve(opx->key, sb, pj);
		rz_strbuf_append(sb, ", value:");
		il_op_resolve(opx->value, sb, pj);
		rz_strbuf_appendf(sb, ", mem:%d)", opx->mem);
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
		rz_strbuf_appendf(sb, "set(v:%s, x:", opx->v);
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
		rz_strbuf_appendf(sb, "goto(lbl:%s)", opx->lbl);
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

static void il_op_resolve(RzILOp *op, RzStrBuf *sb, PJ *pj) {
	if (!op && sb) {
		rz_strbuf_append(sb, "nop");
		return;
	} else if (!op && pj) {
		pj_o(pj);
		pj_ks(pj, "opcode", "nop");
		pj_end(pj);
		return;
	}
	switch (op->code) {
	case RZIL_OP_VAR:
		return il_opdmp_var(op, sb, pj);
	case RZIL_OP_UNK:
		return il_opdmp_unk(op, sb, pj);
	case RZIL_OP_ITE:
		return il_opdmp_ite(op, sb, pj);
	case RZIL_OP_B0:
		return il_opdmp_bool_false(op, sb, pj);
	case RZIL_OP_B1:
		return il_opdmp_bool_true(op, sb, pj);
	case RZIL_OP_INV:
		return il_opdmp_bool_inv(op, sb, pj);
	case RZIL_OP_AND:
		return il_opdmp_bool_and(op, sb, pj);
	case RZIL_OP_OR:
		return il_opdmp_bool_or(op, sb, pj);
	case RZIL_OP_XOR:
		return il_opdmp_bool_xor(op, sb, pj);
	case RZIL_OP_BITV:
		return il_opdmp_bitv(op, sb, pj);
	case RZIL_OP_MSB:
		return il_opdmp_msb(op, sb, pj);
	case RZIL_OP_LSB:
		return il_opdmp_lsb(op, sb, pj);
	case RZIL_OP_NEG:
		return il_opdmp_neg(op, sb, pj);
	case RZIL_OP_LOGNOT:
		return il_opdmp_lognot(op, sb, pj);
	case RZIL_OP_ADD:
		return il_opdmp_add(op, sb, pj);
	case RZIL_OP_SUB:
		return il_opdmp_sub(op, sb, pj);
	case RZIL_OP_MUL:
		return il_opdmp_mul(op, sb, pj);
	case RZIL_OP_DIV:
		return il_opdmp_div(op, sb, pj);
	case RZIL_OP_SDIV:
		return il_opdmp_sdiv(op, sb, pj);
	case RZIL_OP_MOD:
		return il_opdmp_mod(op, sb, pj);
	case RZIL_OP_SMOD:
		return il_opdmp_smod(op, sb, pj);
	case RZIL_OP_LOGAND:
		return il_opdmp_logand(op, sb, pj);
	case RZIL_OP_LOGOR:
		return il_opdmp_logor(op, sb, pj);
	case RZIL_OP_LOGXOR:
		return il_opdmp_logxor(op, sb, pj);
	case RZIL_OP_SHIFTR:
		return il_opdmp_shiftr(op, sb, pj);
	case RZIL_OP_SHIFTL:
		return il_opdmp_shiftl(op, sb, pj);
	case RZIL_OP_SLE:
		return il_opdmp_sle(op, sb, pj);
	case RZIL_OP_ULE:
		return il_opdmp_ule(op, sb, pj);
	case RZIL_OP_CAST:
		return il_opdmp_cast(op, sb, pj);
	case RZIL_OP_CONCAT:
		return il_opdmp_concat(op, sb, pj);
	case RZIL_OP_APPEND:
		return il_opdmp_append(op, sb, pj);
	case RZIL_OP_LOAD:
		return il_opdmp_load(op, sb, pj);
	case RZIL_OP_STORE:
		return il_opdmp_store(op, sb, pj);
	case RZIL_OP_PERFORM:
		return il_opdmp_perform(op, sb, pj);
	case RZIL_OP_SET:
		return il_opdmp_set(op, sb, pj);
	case RZIL_OP_JMP:
		return il_opdmp_jmp(op, sb, pj);
	case RZIL_OP_GOTO:
		return il_opdmp_goto(op, sb, pj);
	case RZIL_OP_SEQ:
		return il_opdmp_seq(op, sb, pj);
	case RZIL_OP_BLK:
		return il_opdmp_blk(op, sb, pj);
	case RZIL_OP_REPEAT:
		return il_opdmp_repeat(op, sb, pj);
	case RZIL_OP_BRANCH:
		return il_opdmp_branch(op, sb, pj);
	case RZIL_OP_INVALID:
		return il_opdmp_invalid(op, sb, pj);
	default:
		rz_warn_if_reached();
		if (sb) {
			rz_strbuf_appendf(sb, "unk_%u", op->code);
		} else {
			char tmp[64];
			rz_strf(tmp, "unk_%u", op->code);
			pj_o(pj);
			pj_ks(pj, "opcode", tmp);
			pj_end(pj);
		}
		return;
	}
}

/**
 * Generates the string representation of the IL statement
 * \param op RzILOp*, IL statement
 * \param sb RzStrBuf*, a pointer to the string buffer
 */
RZ_API void rz_il_op_stringify(RZ_NONNULL RzILOp *op, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(op && sb);
	il_op_resolve(op, sb, NULL);
}

/**
 * Generates the JSON representation of the IL statement
 * \param op RzILOp*, IL statement
 * \param pj PJ*, a pointer to the JSON buffer
 */
RZ_API void rz_il_op_json(RZ_NONNULL RzILOp *op, RZ_NONNULL PJ *pj) {
	rz_return_if_fail(op && pj);
	il_op_resolve(op, NULL, pj);
}

/**
 * Generates the string representation of the IL statements
 * \param op_list RzPVector*, array of IL statements
 * \param sb RzStrBuf*, a pointer to the string buffer
 */
RZ_API void rz_il_oplist_stringify(RZ_NONNULL RzPVector *op_list, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(op_list && sb);

	ut32 i = 0;
	void **iter;
	rz_strbuf_append(sb, "[");
	rz_pvector_foreach (op_list, iter) {
		RzILOp *ilop = *iter;
		if (i > 0) {
			rz_strbuf_append(sb, ", ");
		}
		rz_il_op_stringify(ilop, sb);
		i++;
	}
	rz_strbuf_append(sb, "]");
}

/**
 * Generates the JSON representation of the IL statements
 * \param code RzPVector*, array of IL statements
 * \param pj PJ*, a pointer to the JSON buffer
 */
RZ_API void rz_il_oplist_json(RZ_NONNULL RzPVector *op_list, RZ_NONNULL PJ *pj) {
	rz_return_if_fail(op_list && pj);

	pj_a(pj);
	void **iter;
	rz_pvector_foreach (op_list, iter) {
		RzILOp *ilop = *iter;
		rz_il_op_json(ilop, pj);
	}
	pj_end(pj);
}

RZ_API void rz_il_event_stringify(RZ_NONNULL RzILEvent *evt, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(evt && sb);
	char *tmp0 = NULL, *tmp1 = NULL, *tmp2 = NULL;

	switch (evt->type) {
	case RZIL_EVENT_EXCEPTION:
		rz_strbuf_appendf(sb, "exception(%s)", evt->data.exception);
		break;
	case RZIL_EVENT_PC_WRITE:
		tmp0 = rz_il_bv_as_hex_string(evt->data.pc_write.old_pc);
		tmp1 = rz_il_bv_as_hex_string(evt->data.pc_write.new_pc);
		rz_strbuf_appendf(sb, "pc_write(old: %s, new: %s)", tmp0, tmp1);
		break;
	case RZIL_EVENT_MEM_READ:
		tmp0 = rz_il_bv_as_hex_string(evt->data.mem_read.address);
		tmp1 = evt->data.mem_read.value ? rz_il_bv_as_hex_string(evt->data.mem_read.value) : NULL;
		rz_strbuf_appendf(sb, "mem_read(addr: %s, value: %s)", tmp0, tmp1 ? tmp1 : "uninitialized memory");
		break;
	case RZIL_EVENT_VAR_READ:
		tmp1 = evt->data.var_read.value ? rz_il_bv_as_hex_string(evt->data.var_read.value) : NULL;
		rz_strbuf_appendf(sb, "var_read(name: %s, value: %s)", evt->data.var_write.variable, tmp1 ? tmp1 : "uninitialized variable");
		break;
	case RZIL_EVENT_MEM_WRITE:
		tmp0 = rz_il_bv_as_hex_string(evt->data.mem_write.address);
		tmp1 = evt->data.mem_write.old_value ? rz_il_bv_as_hex_string(evt->data.mem_write.old_value) : NULL;
		tmp2 = rz_il_bv_as_hex_string(evt->data.mem_write.new_value);
		rz_strbuf_appendf(sb, "mem_write(addr: %s, old: %s, new: %s)", tmp0, tmp1 ? tmp1 : "uninitialized memory", tmp2);
		break;
	case RZIL_EVENT_VAR_WRITE:
		tmp1 = evt->data.var_write.old_value ? rz_il_bv_as_hex_string(evt->data.var_write.old_value) : NULL;
		tmp2 = rz_il_bv_as_hex_string(evt->data.var_write.new_value);
		rz_strbuf_appendf(sb, "var_write(name: %s, old: %s, new: %s)", evt->data.var_write.variable, tmp1 ? tmp1 : "uninitialized variable", tmp2);
		break;
	default:
		rz_warn_if_reached();
		rz_strbuf_append(sb, "unknown(?)");
		break;
	}

	free(tmp0);
	free(tmp1);
	free(tmp2);
}

RZ_API void rz_il_event_json(RZ_NONNULL RzILEvent *evt, RZ_NONNULL PJ *pj) {
	rz_return_if_fail(evt && pj);
	char *tmp0 = NULL, *tmp1 = NULL, *tmp2 = NULL;

	switch (evt->type) {
	case RZIL_EVENT_EXCEPTION:
		pj_o(pj);
		pj_ks(pj, "type", "exception");
		pj_ks(pj, "exception", evt->data.exception);
		pj_end(pj);
		break;
	case RZIL_EVENT_PC_WRITE:
		tmp0 = rz_il_bv_as_hex_string(evt->data.pc_write.old_pc);
		tmp1 = rz_il_bv_as_hex_string(evt->data.pc_write.new_pc);
		pj_o(pj);
		pj_ks(pj, "type", "pc_write");
		pj_ks(pj, "old", tmp0);
		pj_ks(pj, "new", tmp1);
		pj_end(pj);
		break;
	case RZIL_EVENT_MEM_READ:
		tmp0 = rz_il_bv_as_hex_string(evt->data.mem_read.address);
		tmp1 = evt->data.mem_read.value ? rz_il_bv_as_hex_string(evt->data.mem_read.value) : NULL;
		pj_o(pj);
		pj_ks(pj, "type", "mem_read");
		pj_ks(pj, "address", tmp0);
		pj_ks(pj, "value", tmp1 ? tmp1 : "uninitialized memory");
		pj_end(pj);
		break;
	case RZIL_EVENT_VAR_READ:
		tmp1 = evt->data.var_read.value ? rz_il_bv_as_hex_string(evt->data.var_read.value) : NULL;
		pj_o(pj);
		pj_ks(pj, "type", "var_read");
		pj_ks(pj, "name", evt->data.var_read.variable);
		pj_ks(pj, "value", tmp1 ? tmp1 : "uninitialized variable");
		pj_end(pj);
		break;
	case RZIL_EVENT_MEM_WRITE:
		tmp0 = rz_il_bv_as_hex_string(evt->data.mem_write.address);
		tmp1 = evt->data.mem_write.old_value ? rz_il_bv_as_hex_string(evt->data.mem_write.old_value) : NULL;
		tmp2 = rz_il_bv_as_hex_string(evt->data.mem_write.new_value);
		pj_o(pj);
		pj_ks(pj, "type", "mem_write");
		pj_ks(pj, "address", tmp0);
		pj_ks(pj, "old", tmp1 ? tmp1 : "uninitialized memory");
		pj_ks(pj, "new", tmp2);
		pj_end(pj);
		break;
	case RZIL_EVENT_VAR_WRITE:
		tmp1 = evt->data.var_write.old_value ? rz_il_bv_as_hex_string(evt->data.var_write.old_value) : NULL;
		tmp2 = rz_il_bv_as_hex_string(evt->data.var_write.new_value);
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
