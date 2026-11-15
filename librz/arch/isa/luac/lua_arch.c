// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "lua_arch.h"
#include "v54/arch_54.h"
#include <luac/luac_common.h>

RZ_IPI char *fmt_str(size_t len, char *buffer, const char *fmt, ...) {
	assert(buffer);
	assert(fmt);
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buffer, len, fmt, ap);
	va_end(ap);
	return buffer;
}

RZ_IPI RzAnalysisValue *new_reg_item(RzAnalysis *analysis, ut8 index) {
	RzAnalysisValue *x = rz_analysis_value_new();
	rz_return_val_if_fail(x, NULL);
	if (!x) {
		return NULL;
	}
	char tmp[32] = { 0 };
	RzReg *areg = rz_analysis_get_reg(analysis);
	x->reg = rz_reg_get(areg, rz_strf(tmp, "r%d", index), RZ_REG_TYPE_GPR);
	return x;
}

RzAnalysisValue *new_imm_item(st64 value) {
	RzAnalysisValue *x = rz_analysis_value_new();
	if (!x) {
		return NULL;
	}
	x->imm = value;
	return x;
}

static LuaConstEntry *get_const_entry(const LuacBinInfo *lbi, ut64 addr, ut32 index) {
	if (!lbi) {
		return NULL;
	}

	const ut64 proto_base = PROTO_INDEX(addr);
	const LuaProto *proto = (LuaProto *)rz_pvector_at(lbi->protos_vec, proto_base);
	if (!proto || !proto->const_entries) {
		return NULL;
	}
	LuaConstEntry *const_entrie = (LuaConstEntry *)rz_pvector_at(proto->const_entries, index);
	if (!const_entrie) {
		RZ_LOG_DEBUG("const_entrie is null, addr: 0x%" PFMT64x ", index: %d, proto_base: 0x%" PFMT64x "\n", addr, index, proto_base);
		return NULL;
	}
	return const_entrie;
}

static LuaUpvalueEntry *get_upvalue_entry(const LuacBinInfo *lbi, ut64 addr, ut32 index) {
	if (!lbi) {
		return NULL;
	}

	const ut64 proto_base = PROTO_INDEX(addr);
	const LuaProto *proto = (LuaProto *)rz_pvector_at(lbi->protos_vec, proto_base);
	if (!proto || !proto->upvalue_entries) {
		return NULL;
	}
	LuaUpvalueEntry *upvalue_entrie = (LuaUpvalueEntry *)rz_pvector_at(proto->upvalue_entries, index);
	if (!upvalue_entrie) {
		RZ_LOG_DEBUG("upvalue_entrie is null, addr: 0x%" PFMT64x ", index: %d\n", addr, index);
		return NULL;
	}
	return upvalue_entrie;
}

static const LuacBinInfo *get_luac_bin_info(const RzAnalysis *analysis) {
	RzBinBind *binb = rz_analysis_get_bin_bind((RzAnalysis *)analysis);
	const RzBinObject *bobj = binb->get_bin_object(binb->bin);
	if (!bobj) {
		return NULL;
	}
	return bobj->bin_obj;
}

static char *get_const_string_b(const LuacBinInfo *lbi, ut64 addr, ut32 index, st32 *data_len, char *out_buffer) {
	LuaConstEntry *const_entrie = get_const_entry(lbi, addr, index);
	if (!const_entrie) {
		RZ_LOG_DEBUG("const_entrie is null, addr: 0x%" PFMT64x ", index: %d\n", addr, index);
		*data_len = 0;
		return NULL;
	}
	*data_len = const_entrie->data_len;
	switch (const_entrie->tag) {
	case LUA_VNUMINT:
		sprintf(out_buffer, "%" PFMT64u, *(ut64 *)const_entrie->data);
		return out_buffer;
	case LUA_VNUMFLT: {
		const double r = *(double *)const_entrie->data;
		sprintf(out_buffer, "%f", r);
		return out_buffer;
	}
	case LUA_TSTRING:
		sprintf(out_buffer, "%s", (char *)const_entrie->data);
		return out_buffer;
	case LUA_TBOOLEAN:
		sprintf(out_buffer, "%s", const_entrie->data ? "true" : "false");
		return out_buffer;
	case LUA_TNIL:
	default:
		return NULL;
	}
}

RZ_IPI char *get_const_string(const RzAnalysis *analysis, ut64 addr, ut32 index, st32 *data_len, char *out_buffer) {
	const LuacBinInfo *lbi = get_luac_bin_info(analysis);
	if (!lbi) {
		RZ_LOG_DEBUG("LuacBinInfo is null, addr: 0x%" PFMT64x ", index: %d\n", addr, index);
		return NULL;
	}
	return get_const_string_b(lbi, addr, index, data_len, out_buffer);
}

RZ_IPI char *get_k(const RzAnalysis *analysis, ut64 addr, ut32 index, char *out_buffer) {
	st32 data_len = 0;
	get_const_string(analysis, addr, index, &data_len, out_buffer);
	return out_buffer;
}

RZ_IPI ut64 get_const_address_b(const LuacBinInfo *lbi, ut64 addr, ut32 index) {
	LuaConstEntry *const_entrie = get_const_entry(lbi, addr, index);
	if (!const_entrie) {
		RZ_LOG_DEBUG("const_entrie is null, addr: 0x%" PFMT64x ", index: %d\n", addr, index);
		return UT64_MAX;
	}
	return const_entrie->voffset + 2;
}

static ut64 get_upvalue_address_b(const LuacBinInfo *lbi, ut64 addr, ut32 index) {
	LuaUpvalueEntry *upvalue_entrie = get_upvalue_entry(lbi, addr, index);
	if (!upvalue_entrie) {
		RZ_LOG_DEBUG("upvalue_entrie is null, addr: 0x%" PFMT64x ", index: %d\n", addr, index);
		return UT64_MAX;
	}
	return upvalue_entrie->voffset;
}

RZ_IPI ut64 get_metamethod_address(const ut32 index) {
	return METATABLES_VOFFSET + index * 4;
}

RZ_IPI const char *get_metamethod_name(const ut8 minor, const ut32 index) {
	switch (minor) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
		return get_lua_tagnames(index);
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

RZ_IPI ut64 get_const_address(const RzAnalysis *analysis, ut64 addr, ut32 index) {
	const LuacBinInfo *lbi = get_luac_bin_info(analysis);
	if (!lbi) {
		RZ_LOG_DEBUG("LuacBinInfo is null, addr: 0x%" PFMT64x ", index: %d\n", addr, index);
		return UT64_MAX;
	}
	return get_const_address_b(lbi, addr, index);
}

RZ_IPI ut64 get_upvalue_address(const RzAnalysis *analysis, ut64 addr, ut32 index) {
	const LuacBinInfo *lbi = get_luac_bin_info(analysis);
	if (!lbi) {
		RZ_LOG_DEBUG("LuacBinInfo is null, addr: 0x%" PFMT64x ", index: %d\n", addr, index);
		return UT64_MAX;
	}
	return get_upvalue_address_b(lbi, addr, index);
}

RZ_IPI LuaInstruction lua_build_instruction(const ut8 *buf) {
	LuaInstruction ret = 0;
	ret |= buf[3] << 24;
	ret |= buf[2] << 16;
	ret |= buf[1] << 8;
	ret |= buf[0];
	return ret;
}

RZ_IPI void lua_set_instruction(const LuaInstruction instruction, ut8 *data) {
	data[3] = instruction >> 24;
	data[2] = instruction >> 16;
	data[1] = instruction >> 8;
	data[0] = instruction >> 0;
}

RZ_IPI bool free_lua_opnames(LuaOpNameList list) {
	if (list != NULL) {
		RZ_FREE(list);
		return true;
	}
	return false;
}

RZ_IPI int lua_load_next_arg_start(const char *raw_string, char *recv_buf) {
	if (!raw_string) {
		return 0;
	}

	const char *arg_start = NULL;
	const char *arg_end = NULL;
	int arg_len = 0;

	/* locate the start point */
	arg_start = rz_str_trim_head_ro(raw_string);
	if (strlen(arg_start) == 0) {
		return 0;
	}

	if (arg_start[0] == 'r') {
		arg_start++;
	}
	arg_end = strchr(arg_start, ' ');
	if (arg_end == NULL) {
		/* is last arg */
		arg_len = (int)strlen(arg_start);
	} else {
		arg_len = arg_end - arg_start;
	}

	/* Set NUL */
	memcpy(recv_buf, arg_start, arg_len);
	recv_buf[arg_len] = 0x00;

	/* Calculate offset */
	return arg_start - raw_string + arg_len;
}

RZ_IPI bool lua_is_valid_num_value_string(const char *str) {
	if (!rz_is_valid_input_num_value(NULL, str)) {
		RZ_LOG_ERROR("assembler: lua: %s is not a valid number argument\n", str);
		return false;
	}
	return true;
}

RZ_IPI bool load_args_asm(const char *arg_start, int *args) {
	const char *pattern = "(?:[r-]?[0-9]+)";
	RzRegex *rx = rz_regex_new(pattern, RZ_REGEX_EXTENDED, 0, NULL);
	if (!rx) {
		return false;
	}

	const RzPVector *matches = rz_regex_match_all_not_grouped(
		rx, arg_start, strlen(arg_start), 0, 0);

	int count = 0;
	if (matches) {
		const size_t matches_count = rz_pvector_len(matches);
		for (size_t i = 0; i < matches_count; i++) {
			const RzRegexMatch *m = (RzRegexMatch *)rz_pvector_at(matches, i);
			const char *p_start = (char *)(arg_start + m->start);
			const int p_len = (int)m->len + 1;
			if (arg_start[m->start] == 'r') {
				p_start++;
			}

			char val_str[8] = { 0 };
			rz_str_ncpy(val_str, p_start, p_len);
			args[count++] = (int)strtol(val_str, NULL, 0);
		}
		rz_pvector_free((RzPVector *)matches);
	}

	rz_regex_free(rx);
	return count;
}

RZ_IPI bool analysis_op_4_5(RzAnalysis *analysis, RzAnalysisOp *op, AnalysisLuacContext *ctx, ut16 opcode, ut8 minor) {
	const LuaInstruction instruction = ctx->instruction;
	const ut64 addr = ctx->addr;
	const int a = GETARG_A4(instruction);
	const int b = GETARG_B4(instruction);
	const int c = GETARG_C4(instruction);
	const int ax = GETARG_Ax4(instruction);
	const int bx = GETARG_Bx4(instruction);
	const int sb = GETARG_sB(instruction);
	const int sc = GETARG_sC(instruction);
	const int sbx = GETARG_sBx4(instruction);
	const int sj = GETARG_sJ(instruction);
	const int k = GETARG_k4(instruction);

	char comment[128] = { 0 };

	switch (opcode) {
	case OP_MOVE: /*	A B	R[A] := R[B]					*/
		TYPE_CFMT_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_MOV, "r%d = r%d", a, b);
	case OP_GETUPVAL: /*	A B	R[A] := UpValue[B]				*/ {
		const st64 target_upv = VADDRESS_PROTO_BASE(addr) + UPVALUE_OFFSET + (b * 2);
		op->ptr = (st64)target_upv;
		TYPE_CFMT_DST_REG_SRC0_IMM(RZ_ANALYSIS_OP_TYPE_LOAD, "r%d = upvalue[%d]", a, b);
	}
	case OP_SETUPVAL: /*	A B	UpValue[B] := R[A]				*/
		TYPE_DST_IMM_SRC0_REG(RZ_ANALYSIS_OP_TYPE_STORE, "upvalue[%d] = r%d", b, a);
	case OP_UNM: /*	A B	R[A] := -R[B]					*/
		TYPE_CFMT_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_UNK, "r%d = -r%d", a, b);
	case OP_NOT: /*		A B	R[A] := not R[B]				*/
		TYPE_CFMT_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_NOT, "r%d = not r%d", a, b);
	case OP_LOADK: /*	A Bx	R[A] := K[Bx]					*/ {
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		rz_strf(comment, "r%d = %s", a, Kst(bx));
		break;
	}
	case OP_LOADNIL: /*	A B	R[A], R[A+1], ..., R[A+B] := nil		*/
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		op->val = (ut64)0;
		break;
	case OP_CLOSURE: /*	A Bx	R[A] := closure(KPROTO[Bx])			*/ {
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		const ut64 child_vaddr = CHILD_VADDRESS(addr, (bx + 1));
		op->ptr = (st64)child_vaddr;
		RzAnalysisFunction *fc = rz_analysis_get_function_at(analysis, child_vaddr);
		if (!fc) {
			break;
		}
		const char *fcn_name = fc->name;
		if (fcn_name) {
			rz_strf(comment, "instantiate proto %d `%s` at 0x%" PFMT64x, bx + 1, fcn_name, child_vaddr);
		} else {
			rz_strf(comment, "instantiate proto%d at 0x%" PFMT64x, bx + 1, child_vaddr);
		}
		rz_meta_set(analysis, RZ_META_TYPE_DATA, child_vaddr, 0, "fcn_ptr");
		break;
	}
	case OP_RETURN: /*	A B C k	return R[A], ... ,R[A+B-2]	(see note)	*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->src[0] = new_reg_item(analysis, a);
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		if (b == 0) {
			rz_strf(comment, "%s", "return all (top of stack)");
		} else {
			rz_strf(comment, "%d out", b - 1);
		}
		break;
	}
	case OP_TAILCALL: /*	A B C k	return R[A](R[A+1], ... ,R[A+B-1])		*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_TAIL;
		op->type2 = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		op->jump = 0;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		op->src[0] = new_reg_item(analysis, a);
		if (b > 0) {
			rz_strf(comment, "return r%d(args: %d)", a, b - 1);
		} else {
			rz_strf(comment, "return r%d(all varargs)", a);
		}
		break;
	}
	case OP_TEST: /*	A k	if (not R[A] == k) then pc++			*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		JUMP_FAIL_OFFSET(8, 4);
		break;
	case OP_SETLIST: /*	A B C k	R[A][C+i] := R[A+i], 1 <= i <= B		*/
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_STORE, a);
		break;
	case OP_CALL: /*	A B C	R[A], ... ,R[A+C-2] := R[A](R[A+1], ... ,R[A+B-1]) */
		OP_CALL();
	case OP_GETTABLE: /*  A B C   R[A] := R[B][R[C]]                              */ {
		TYPE_DST_SRC_ABC_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a, b, c);
		rz_strf(comment, "r%d = r%d[r%d]", a, b, c);
		break;
	}
	case OP_SETTABLE: /*  A B C   R[A][R[B]] := RK(C)                             */
		RKC_REG_OR_IMM(c, 1);
		rz_strf(comment, "r%d[r%d] = %s", a, b, RKC);
		TYPE_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_STORE, a, b);
	case OP_NEWTABLE: /*	A B C k	R[A] := {}					*/
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		const int array_size = (b > 0) ? (1 << (b - 1)) : 0;
		const int hash_size = (c > 0) ? (1 << (c - 1)) : 0;
		op->val = array_size + hash_size;
		rz_strf(comment, "r%d = {}; array: %d, hash: %d%s",
			a, array_size, hash_size, k ? " (extra)" : "");
		break;
	case OP_ADD: /*		A B C	R[A] := R[B] + R[C]				*/
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_ADD, "r%d = r%d + r%d", a, b, c);
		break;
	case OP_SUB: /*       A B C   R[A] := R[B] - R[C]                             */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_SUB, "r%d = r%d - r%d", a, b, c);
		break;
	case OP_MUL: /*       A B C   R[A] := R[B] * R[C]                             */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_MUL, "r%d = r%d * r%d", a, b, c);
		break;
	case OP_DIV: /*       A B C   R[A] := R[B] / R[C]                             */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_DIV, "r%d = r%d / r%d", a, b, c);
		break;
	case OP_POW: /*       A B C   R[A] := R[B] ^ R[C]                             */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_MUL, "r%d = r%d ^ r%d", a, b, c);
		break;
	case OP_EQI: /*       A sB k  if ((R[A] == sB) ~= k) then pc++                */
	case OP_LTI: /*       A sB k  if ((R[A] < sB) ~= k) then pc++                 */
	case OP_GTI: /*       A sB k  if ((R[A] > sB) ~= k) then pc++                 */
	case OP_GEI: /*       A sB k  if ((R[A] >= sB) ~= k) then pc++                */
	case OP_LEI: /*       A sB k  if ((R[A] <= sB) ~= k) then pc++                */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->src[0] = new_reg_item(analysis, a);
		op->src[1] = new_imm_item(sb);
		JUMP_FAIL_OFFSET(8, 4);
		if (opcode == OP_EQI) {
			op->cond = RZ_TYPE_COND_EQ;
		} else if (opcode == OP_LTI) {
			op->cond = RZ_TYPE_COND_LT;
		} else if (opcode == OP_GTI) {
			op->cond = RZ_TYPE_COND_GT;
		} else if (opcode == OP_GEI) {
			op->cond = RZ_TYPE_COND_GE;
		} else {
			op->cond = RZ_TYPE_COND_LE;
		}
		break;
	case OP_EQ: /*	A B k	if ((R[A] == R[B]) ~= k) then pc++		*/
	case OP_EQK: /*       A B k   if ((R[A] == K[B]) ~= k) then pc++              */
	case OP_LT: /*	A B k	if ((R[A] <  R[B]) ~= k) then pc++		*/
	case OP_LE: /*	A B k	if ((R[A] <= R[B]) ~= k) then pc++		*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->src[0] = new_reg_item(analysis, a);
		op->src[1] = new_reg_item(analysis, b);
		JUMP_FAIL_OFFSET(8, 4);
		if (opcode == OP_EQ) {
			op->cond = RZ_TYPE_COND_EQ;
		} else if (opcode == OP_LT) {
			op->cond = RZ_TYPE_COND_LT;
		} else {
			op->cond = RZ_TYPE_COND_LE;
		}
		break;
	}
	case OP_JMP: /*	sJ	pc += sJ					*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		const ut64 offset = (sj + 1) * 4;
		const ut64 target = addr + offset;
		JUMP_FAIL_ABS(target, addr + 4);
		op->eob = true;
		rz_strf(comment, "jump to 0x%" PFMT64x, target);
		break;
	}
	case OP_CONCAT: /*    A B     R[A] := R[A].. ... ..R[A + B - 1]               */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_UNK, a);
		break;
	case OP_LOADI: /*     A sBx   R[A] := sBx                                     */
		op->val = (ut64)sbx;
		rz_strf(comment, "r%d = %" PFMT64d, a, (st64)sbx);
		TYPE_DST_REG_SRC0_IMM(RZ_ANALYSIS_OP_TYPE_LOAD, a, sbx);
	case OP_SETI: /*      A B C   R[A][B] := RK(C)                                */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		RKC_REG_OR_IMM(c, 0);
		op->src[1] = new_imm_item((st64)b);
		rz_strf(comment, "r%d[%d] = %s", a, b, RKC);
		break;
	case OP_SETFIELD: /*  A B C   R[A][K[B]:shortstring] := RK(C)                 */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		RKC_REG_OR_IMM(c, 0);
		rz_strf(comment, "table r%d['%s'] = %s", a, Kst(b), RKC);
		break;
	case OP_ADDI: /*      A B sC  R[A] := R[B] + sC                               */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_ADD, "r%d := r%d + (sC=%d)", a, b, sc);
		break;
	case OP_SHRI: /*      A B sC  R[A] := R[B] >> sC                              */
		if (minor == 4) {
			ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_SHR, "r%d := r%d >> (sC=%d)", a, b, sc);
		} else { ///< if minor = 5
			ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_SHL, "r%d := (sC=%d) >> r%d", a, sc, b);
		}
		break;
	case OP_SHLI: /*      A B sC  R[A] := sC << R[B]                              */
		if (minor == 4) {
			ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_SHL, "r%d := (sC=%d) >> r%d", a, sc, b);
		} else { ///< if minor = 5
			ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_SHR, "r%d := r%d >> (sC=%d)", a, b, sc);
		}
		break;
	case OP_MOD: /*       A B C   R[A] := R[B] % R[C]                             */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_MOD, "r%d = r%d MOD r%d", a, b, c);
		break;
	case OP_IDIV: /*      A B C   R[A] := R[B] // R[C]                            */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_DIV, "r%d = r%d // r%d", a, b, c);
		break;
	case OP_BAND: /*      A B C   R[A] := R[B] & R[C]                             */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_AND, "r%d = r%d & r%d", a, b, c);
		break;
	case OP_BOR: /*       A B C   R[A] := R[B] | R[C]                             */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_OR, "r%d = r%d | r%d", a, b, c);
		break;
	case OP_BXOR: /*      A B C   R[A] := R[B] ~ R[C]                             */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_XOR, "r%d = r%d ~ r%d", a, b, c);
		break;
	case OP_SHL: /*       A B C   R[A] := R[B] << R[C]                            */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_SHL, "r%d = r%d << r%d", a, b, c);
		break;
	case OP_SHR: /*       A B C   R[A] := R[B] >> R[C]                            */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_SHR, "r%d = r%d >> r%d", a, b, c);
		break;
	case OP_ADDK: /*      A B C   R[A] := R[B] + K[C]:number                      */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_ADD, "r%d = r%d + K[%d]:number", a, b, c);
		break;
	case OP_SUBK: /*      A B C   R[A] := R[B] - K[C]:number                      */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_SUB, "r%d = r%d - K[%d]:number", a, b, c);
		break;
	case OP_MULK: /*      A B C   R[A] := R[B] * K[C]:number                      */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_MUL, "r%d = r%d * K[%d]:number", a, b, c);
		break;
	case OP_MODK: /*      A B C   R[A] := R[B] % K[C]:number                      */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_MOD, "r%d = r%d MOD K[%d]:number", a, b, c);
		break;
	case OP_POWK: /*      A B C   R[A] := R[B] ^ K[C]:number                      */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_MUL, "r%d = r%d ^ K[%d]:number", a, b, c);
		break;
	case OP_DIVK: /*      A B C   R[A] := R[B] / K[C]:number                      */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_DIV, "r%d = r%d / K[%d]:number", a, b, c);
		break;
	case OP_IDIVK: /*     A B C   R[A] := R[B] // K[C]:number                     */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_DIV, "r%d = r%d // K[%d]:number", a, b, c);
		break;
	case OP_BANDK: /*     A B C   R[A] := R[B] & K[C]:integer                     */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_AND, "r%d = r%d & K[%d]:number", a, b, c);
		break;
	case OP_BORK: /*      A B C   R[A] := R[B] | K[C]:integer                     */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_OR, "r%d = r%d | K[%d]:number", a, b, c);
		break;
	case OP_BXORK: /*     A B C   R[A] := R[B] ~ K[C]:integer                     */
		ARITHMETIC_OP_4_5(RZ_ANALYSIS_OP_TYPE_OR, "r%d = r%d ~ K[%d]:number", a, b, c);
		break;
	case OP_MMBIN: /*     A B C   call C metamethod over R[A] and R[B]            */ {
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		const ut64 meta_addr = get_metamethod_address(c);
		JUMP_FAIL_ABS(meta_addr, addr + 4);
		op->ptr = (st64)meta_addr;
		op->src[0] = new_reg_item(analysis, a);
		op->src[1] = new_reg_item(analysis, b);
		if (c >= 0 && c < 15) {
			rz_strf(comment, "call metamethod %s(r%d, r%d)", get_lua_tagnames(c), a, b);
		}
		break;
	}
	case OP_MMBINI: /*    A sB C k        call C metamethod over R[A] and sB      */ {
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		const ut64 meta_addr = get_metamethod_address(c);
		JUMP_FAIL_ABS(meta_addr, addr + 4);
		op->ptr = (st64)meta_addr;
		op->src[0] = new_reg_item(analysis, a);
		op->src[1] = new_imm_item((st64)sb);
		op->val = (ut64)c;
		if (c >= 0 && c < 15) {
			rz_strf(comment, "call metamethod %s(r%d, %d)", get_lua_tagnames(c), a, sb);
		}
		break;
	}
	case OP_MMBINK: /*    A B C k         call C metamethod over R[A] and K[B]    */
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		const ut64 meta_addr = get_metamethod_address(c);
		JUMP_FAIL_ABS(meta_addr, addr + 4);
		op->ptr = (st64)meta_addr;
		op->src[0] = new_reg_item(analysis, a);
		op->src[1] = new_imm_item((st64)b);
		op->val = (ut64)b;
		if (c >= 0 && c < 15) {
			rz_strf(comment, "call metamethod %s(r%d, K[%d]", get_lua_tagnames(c), a, b);
		}
		break;
	case OP_BNOT: /*      A B     R[A] := ~R[B]                                   */
		TYPE_DST_SRC_AB_REG(RZ_ANALYSIS_OP_TYPE_NOT, "r%d = ~r%d", a, b);
	case OP_TBC: /*       A       mark variable A "to be closed"                  */
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case OP_LOADF: /*     A sBx   R[A] := (lua_Number)sBx                         */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		op->val = (ut64)sbx;
		break;
	case OP_LOADFALSE: /* A       R[A] := false                                   */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		op->val = (ut64)0;
		break;
	case OP_LFALSESKIP: /*A       R[A] := false; pc++     (*)                     */ {
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		JUMP_FAIL_ABS(addr + 8, UT64_MAX);
		op->val = 0;
		rz_strf(comment, "r%d = false, skip next", a);
		break;
	}
	case OP_LOADTRUE: /*  A       R[A] := true                                    */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		op->val = (ut64)1;
		break;
	case OP_GETI: /*      A B C   R[A] := R[B][C]                                 */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		op->src[0] = new_reg_item(analysis, b);
		break;
	case OP_GETFIELD: /*  A B C   R[A] := R[B][K[C]:shortstring]                  */
		rz_strf(comment, "r%d = r%d['%s']", a, b, Kst(c));
		TYPE_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a, b);
	case OP_RETURN0: /*           return                                          */ {
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		op->jump = UT64_MAX;
		rz_strf(comment, "%s", "empty return");
		break;
	}
	case OP_RETURN1: /*   A       return R[A]                                     */ {
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		op->src[0] = new_reg_item(analysis, a);
		rz_strf(comment, "return r%d", a);
		break;
	}
	case OP_TESTSET: /*	A B k	if (not R[B] == k) then pc++ else R[A] := R[B]	*/
		JUMP_FAIL_OFFSET(8, 4);
		TYPE_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_CMOV, a, b);
	case OP_LEN: /*	A B	R[A] := #R[B] (length operator)			*/
		TYPE_CFMT_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_LENGTH, "r%d = #r%d", a, b);
	case OP_LOADKX: /*	A	R[A] := K[extra arg]				*/ {
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		const ut32 next_inst = ctx->next_inst;
		const int ax_next = GETARG_Ax4(next_inst);
		op->size = 8; /* 2 instructions (4+4 bytes) */
		op->ptr = (st64)CONST_VADDRESS(addr, ax_next);
		rz_strf(comment, "r%d = constants[%d]", a, ax_next);
		break;
	}
	case OP_GETTABUP: /*	A B C	R[A] := UpValue[B][K[C]:string]			*/ {
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		op->src[0] = new_imm_item((st64)b);
		op->ptr = (st64)CONST_VADDRESS(addr, c);
		rz_strf(comment, "r%d = %s['%s']", a, SCOPE(b), Kst(c));
		break;
	}
	case OP_SETTABUP: /*	A B C	UpValue[A][K[B]:string] := RK(C)		*/ {
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_STORE, a);
		op->ptr = (st64)CONST_VADDRESS(addr, b);
		RKC_REG_OR_IMM(c, 0);
		rz_strf(comment, "%s['%s'] = %s", SCOPE(a), Kst(b), RKC);
		break;
	}
	case OP_TFORPREP: /*	A Bx	create upvalue for R[A + 3]; pc+=Bx		*/
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + 4 + (bx * 4);
		op->val = (ut64)a;
		rz_strf(comment, "to 0x%" PFMT64x, op->jump);
		break;
	case OP_TFORLOOP: /*	A Bx	if R[A+2] ~= nil then { R[A]=R[A+2]; pc -= Bx }	*/
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_CJMP, a);
		op->jump = addr + 4 - ((bx * 4));
		rz_strf(comment, "to 0x%" PFMT64x, op->jump);
		break;
	case OP_SELF: /*	A B C	R[A+1] := R[B]; R[A] := R[B][RK(C):string]	*/ {
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		op->src[0] = new_reg_item(analysis, b);
		op->val = get_const_address(analysis, addr, c);
		RKC_REG_OR_IMM(c, 1);
		rz_strf(comment, "r%d=r%d (self), r%d=r%d[%s] self.%s()", a + 1, b, a, b, RKC, Kst(c));
		break;
	}
	case OP_CLOSE: /*	A	close all upvalues >= R[A]			*/
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case OP_TFORCALL: /*	A C	R[A+4], ... ,R[A+3+C] := R[A](R[A+1], R[A+2]);	*/
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_CALL, a);
		op->val = (ut64)c;
		break;
	case OP_FORLOOP: /*	A Bx	update counters; if loop continues then pc-=Bx; */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		JUMP_FAIL_ABS(addr + 4 - 4 * bx, addr + 4);
		break;
	case OP_FORPREP: /*	A Bx	<check values and prepare counters>;
	      if not to run then pc+=Bx+1;			*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		JUMP_FAIL_ABS(addr + 4 + 4 * (bx + 1), addr + 4);
		rz_strf(comment, "to 0x%" PFMT64x, op->jump);
		break;
	case OP_VARARG: /*	A C	R[A], R[A+1], ..., R[A+C-2] = vararg		*/ {
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		if (c == 0) {
			rz_strf(comment, "r%d... = varargs (all)", a);
		} else {
			rz_strf(comment, "r%d...r%d = varargs", a, a + c - 2);
		}
		break;
	}
	case OP_EXTRAARG: /*	Ax	extra (larger) argument for previous opcode	*/
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->val = ax;
		rz_strf(comment, "extension for previous opcode");
		break;
	default:
		return false;
	}
	if (strlen(comment) > 0) {
		rz_meta_set(analysis, RZ_META_TYPE_COMMENT, addr, 4, comment);
	}
	return true;
}
