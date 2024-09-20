// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2010-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_set.h>
#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_list.h>

RZ_API RzAnalysisOp *rz_analysis_op_new(void) {
	RzAnalysisOp *op = RZ_NEW(RzAnalysisOp);
	rz_analysis_op_init(op);
	return op;
}

RZ_API RzList /*<RzAnalysisOp *>*/ *rz_analysis_op_list_new(void) {
	RzList *list = rz_list_new();
	if (list) {
		list->free = &rz_analysis_op_free;
	}
	return list;
}

RZ_API void rz_analysis_op_init(RzAnalysisOp *op) {
	if (op) {
		memset(op, 0, sizeof(*op));
		op->addr = UT64_MAX;
		op->jump = UT64_MAX;
		op->fail = UT64_MAX;
		op->ptr = UT64_MAX;
		op->refptr = 0;
		op->val = UT64_MAX;
		op->disp = UT64_MAX;
		op->mmio_address = UT64_MAX;
		op->stackptr = RZ_ANALYSIS_OP_INVALID_STACKPTR;
	}
}

RZ_API bool rz_analysis_op_fini(RzAnalysisOp *op) {
	if (!op) {
		return false;
	}
	rz_analysis_value_free(op->src[0]);
	rz_analysis_value_free(op->src[1]);
	rz_analysis_value_free(op->src[2]);
	op->src[0] = NULL;
	op->src[1] = NULL;
	op->src[2] = NULL;
	rz_analysis_value_free(op->dst);
	op->dst = NULL;
	rz_list_free(op->access);
	op->access = NULL;
	rz_strbuf_fini(&op->opex);
	rz_strbuf_fini(&op->esil);
	rz_analysis_switch_op_free(op->switch_op);
	op->switch_op = NULL;
	RZ_FREE(op->mnemonic);
	rz_il_op_effect_free(op->il_op);
	op->il_op = NULL;
	return true;
}

RZ_API void rz_analysis_op_free(void *op) {
	if (!op) {
		return;
	}
	rz_analysis_op_fini(op);
	memset(op, 0, sizeof(RzAnalysisOp));
	free(op);
}

static int defaultCycles(RzAnalysisOp *op) {
	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_PUSH:
	case RZ_ANALYSIS_OP_TYPE_POP:
	case RZ_ANALYSIS_OP_TYPE_STORE:
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		return 2;
	case RZ_ANALYSIS_OP_TYPE_LEA:
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_NOP:
		return 1;
	case RZ_ANALYSIS_OP_TYPE_TRAP:
	case RZ_ANALYSIS_OP_TYPE_SWI:
		return 4;
	case RZ_ANALYSIS_OP_TYPE_SYNC:
		return 4;
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
		return 4;
	default:
		return 1;
	}
}

/**
 * \brief Disassemble the given \p data at \p addr to an RzAnalysisOp.
 * Note: \p op will be set to an invalid operation in case of failure.
 *
 * \param analysis The RzAnalysis to use.
 * \param op An _uninitialized_ RzAnalysisOp to save the result into.
 * \param addr The address the data is located.
 * \param data The buffer with the bytes to disassemble.
 * \param len Length of the \p data in bytes.
 * \param mask The which analysis details should be disassembled.
 *
 * \return The number of bytes which were disassembled. -1 in case of failure.
 */
RZ_API int rz_analysis_op(RZ_NONNULL RzAnalysis *analysis, RZ_OUT RzAnalysisOp *op, ut64 addr, const ut8 *data, ut64 len, RzAnalysisOpMask mask) {
	rz_return_val_if_fail(analysis && op && len > 0, -1);

	rz_analysis_op_init(op);
	int ret = RZ_MIN(2, len);
	if (len > 0 && analysis->cur && analysis->cur->op) {
		// use core binding to set asm.bits correctly based on the addr
		// this is because of the hassle of arm/thumb
		if (analysis && analysis->coreb.archbits) {
			analysis->coreb.archbits(analysis->coreb.core, addr);
		}
		if (analysis->pcalign && addr % analysis->pcalign) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			op->addr = addr;
			// RZ_LOG_DEBUG("Unaligned instruction for %d bits at 0x%"PFMT64x"\n", analysis->bits, addr);
			op->size = 1;
			return -1;
		}
		ret = analysis->cur->op(analysis, op, addr, data, len, mask);
		if (ret < 1) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		}
		op->addr = addr;
		/* consider at least 1 byte to be part of the opcode */
		if (op->nopcode < 1) {
			op->nopcode = 1;
		}
	} else if (!memcmp(data, "\xff\xff\xff\xff", RZ_MIN(4, len))) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		if (op->cycles == 0) {
			op->cycles = defaultCycles(op);
		}
	}
	if (!op->mnemonic && (mask & RZ_ANALYSIS_OP_MASK_DISASM)) {
		RZ_LOG_DEBUG("Warning: unhandled RZ_ANALYSIS_OP_MASK_DISASM in rz_analysis_op\n");
	}
	if (mask & RZ_ANALYSIS_OP_MASK_HINT) {
		RzAnalysisHint *hint = rz_analysis_hint_get(analysis, addr);
		if (hint) {
			rz_analysis_op_hint(op, hint);
			rz_analysis_hint_free(hint);
		}
	}
	return ret;
}

RZ_API RzAnalysisOp *rz_analysis_op_copy(RzAnalysisOp *op) {
	RzAnalysisOp *nop = RZ_NEW0(RzAnalysisOp);
	if (!nop) {
		return NULL;
	}
	*nop = *op;
	if (op->mnemonic) {
		nop->mnemonic = rz_str_dup(op->mnemonic);
		if (!nop->mnemonic) {
			free(nop);
			return NULL;
		}
	} else {
		nop->mnemonic = NULL;
	}
	nop->src[0] = rz_analysis_value_copy(op->src[0]);
	nop->src[1] = rz_analysis_value_copy(op->src[1]);
	nop->src[2] = rz_analysis_value_copy(op->src[2]);
	nop->dst = rz_analysis_value_copy(op->dst);
	if (op->access) {
		RzListIter *it;
		RzAnalysisValue *val;
		RzList *naccess = rz_list_newf((RzListFree)rz_analysis_value_free);
		rz_list_foreach (op->access, it, val) {
			rz_list_append(naccess, rz_analysis_value_copy(val));
		}
		nop->access = naccess;
	}
	rz_strbuf_init(&nop->esil);
	rz_strbuf_copy(&nop->esil, &op->esil);
	return nop;
}

RZ_API bool rz_analysis_op_nonlinear(int t) {
	t &= RZ_ANALYSIS_OP_TYPE_MASK;
	switch (t) {
	// call
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
	case RZ_ANALYSIS_OP_TYPE_UCCALL:
	// jmp
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_MJMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_UCJMP:
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_IJMP:
	case RZ_ANALYSIS_OP_TYPE_IRJMP:
	// trap| ill| unk
	case RZ_ANALYSIS_OP_TYPE_TRAP:
	case RZ_ANALYSIS_OP_TYPE_ILL:
	case RZ_ANALYSIS_OP_TYPE_UNK:
	case RZ_ANALYSIS_OP_TYPE_SWI:
	case RZ_ANALYSIS_OP_TYPE_RET:
		return true;
	default:
		return false;
	}
}

RZ_API bool rz_analysis_op_ismemref(int t) {
	t &= RZ_ANALYSIS_OP_TYPE_MASK;
	switch (t) {
	case RZ_ANALYSIS_OP_TYPE_LOAD:
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_STORE:
	case RZ_ANALYSIS_OP_TYPE_LEA:
	case RZ_ANALYSIS_OP_TYPE_CMP:
	case RZ_ANALYSIS_OP_TYPE_POP:
	case RZ_ANALYSIS_OP_TYPE_PUSH:
		return true;
	default:
		return false;
	}
}

static struct optype {
	int type;
	const char *name;
} optypes[] = {
	{ RZ_ANALYSIS_OP_TYPE_IO, "io" },
	{ RZ_ANALYSIS_OP_TYPE_ACMP, "acmp" },
	{ RZ_ANALYSIS_OP_TYPE_ADD, "add" },
	{ RZ_ANALYSIS_OP_TYPE_SYNC, "sync" },
	{ RZ_ANALYSIS_OP_TYPE_AND, "and" },
	{ RZ_ANALYSIS_OP_TYPE_CALL, "call" },
	{ RZ_ANALYSIS_OP_TYPE_CCALL, "ccall" },
	{ RZ_ANALYSIS_OP_TYPE_CJMP, "cjmp" },
	{ RZ_ANALYSIS_OP_TYPE_MJMP, "mjmp" },
	{ RZ_ANALYSIS_OP_TYPE_CMP, "cmp" },
	{ RZ_ANALYSIS_OP_TYPE_CRET, "cret" },
	{ RZ_ANALYSIS_OP_TYPE_ILL, "ill" },
	{ RZ_ANALYSIS_OP_TYPE_JMP, "jmp" },
	{ RZ_ANALYSIS_OP_TYPE_LEA, "lea" },
	{ RZ_ANALYSIS_OP_TYPE_LEAVE, "leave" },
	{ RZ_ANALYSIS_OP_TYPE_LOAD, "load" },
	{ RZ_ANALYSIS_OP_TYPE_NEW, "new" },
	{ RZ_ANALYSIS_OP_TYPE_MOD, "mod" },
	{ RZ_ANALYSIS_OP_TYPE_CMOV, "cmov" },
	{ RZ_ANALYSIS_OP_TYPE_MOV, "mov" },
	{ RZ_ANALYSIS_OP_TYPE_CAST, "cast" },
	{ RZ_ANALYSIS_OP_TYPE_MUL, "mul" },
	{ RZ_ANALYSIS_OP_TYPE_DIV, "div" },
	{ RZ_ANALYSIS_OP_TYPE_NOP, "nop" },
	{ RZ_ANALYSIS_OP_TYPE_NOT, "not" },
	{ RZ_ANALYSIS_OP_TYPE_NULL, "null" },
	{ RZ_ANALYSIS_OP_TYPE_OR, "or" },
	{ RZ_ANALYSIS_OP_TYPE_POP, "pop" },
	{ RZ_ANALYSIS_OP_TYPE_PUSH, "push" },
	{ RZ_ANALYSIS_OP_TYPE_REP, "rep" },
	{ RZ_ANALYSIS_OP_TYPE_RET, "ret" },
	{ RZ_ANALYSIS_OP_TYPE_ROL, "rol" },
	{ RZ_ANALYSIS_OP_TYPE_ROR, "ror" },
	{ RZ_ANALYSIS_OP_TYPE_SAL, "sal" },
	{ RZ_ANALYSIS_OP_TYPE_SAR, "sar" },
	{ RZ_ANALYSIS_OP_TYPE_SHL, "shl" },
	{ RZ_ANALYSIS_OP_TYPE_SHR, "shr" },
	{ RZ_ANALYSIS_OP_TYPE_STORE, "store" },
	{ RZ_ANALYSIS_OP_TYPE_SUB, "sub" },
	{ RZ_ANALYSIS_OP_TYPE_SWI, "swi" },
	{ RZ_ANALYSIS_OP_TYPE_CSWI, "cswi" },
	{ RZ_ANALYSIS_OP_TYPE_SWITCH, "switch" },
	{ RZ_ANALYSIS_OP_TYPE_TRAP, "trap" },
	{ RZ_ANALYSIS_OP_TYPE_UCALL, "ucall" },
	{ RZ_ANALYSIS_OP_TYPE_RCALL, "rcall" },
	{ RZ_ANALYSIS_OP_TYPE_ICALL, "icall" },
	{ RZ_ANALYSIS_OP_TYPE_IRCALL, "ircall" },
	{ RZ_ANALYSIS_OP_TYPE_UCCALL, "uccall" },
	{ RZ_ANALYSIS_OP_TYPE_UCJMP, "ucjmp" },
	{ RZ_ANALYSIS_OP_TYPE_UJMP, "ujmp" },
	{ RZ_ANALYSIS_OP_TYPE_RJMP, "rjmp" },
	{ RZ_ANALYSIS_OP_TYPE_IJMP, "ijmp" },
	{ RZ_ANALYSIS_OP_TYPE_IRJMP, "irjmp" },
	{ RZ_ANALYSIS_OP_TYPE_UNK, "unk" },
	{ RZ_ANALYSIS_OP_TYPE_UPUSH, "upush" },
	{ RZ_ANALYSIS_OP_TYPE_RPUSH, "rpush" },
	{ RZ_ANALYSIS_OP_TYPE_XCHG, "xchg" },
	{ RZ_ANALYSIS_OP_TYPE_XOR, "xor" },
	{ RZ_ANALYSIS_OP_TYPE_CASE, "case" },
	{ RZ_ANALYSIS_OP_TYPE_CPL, "cpl" },
	{ RZ_ANALYSIS_OP_TYPE_CRYPTO, "crypto" },
	{ RZ_ANALYSIS_OP_TYPE_SIMD, "simd" }
};

/**
 * Return the op type corresponding the given name
 * \param  name       string, name of the optype
 * \return type       int, id of the op type (one of \link _RzAnalysisOpType \endlink)
 */
RZ_API int rz_analysis_optype_from_string(RZ_NONNULL const char *name) {
	rz_return_val_if_fail(name, -1);
	int i;
	for (i = 0; i < RZ_ARRAY_SIZE(optypes); i++) {
		if (!strcmp(optypes[i].name, name)) {
			return optypes[i].type;
		}
	}
	return -1;
}

/**
 * Return the name of the given op type
 * \param  type       int, id of the op type (one of \link _RzAnalysisOpType \endlink)
 * \return name       string, string, name of the optype
 */
RZ_API const char *rz_analysis_optype_to_string(int type) {
	int i;

	for (i = 0; i < RZ_ARRAY_SIZE(optypes); i++) {
		if (optypes[i].type == type) {
			return optypes[i].name;
		}
	}

	type &= RZ_ANALYSIS_OP_TYPE_MASK;

	for (i = 0; i < RZ_ARRAY_SIZE(optypes); i++) {
		if (optypes[i].type == type) {
			return optypes[i].name;
		}
	}
	return "undefined";
}

RZ_API const char *rz_analysis_op_to_esil_string(RzAnalysis *analysis, RzAnalysisOp *op) {
	return rz_strbuf_get(&op->esil);
}

// TODO: use esil here?
RZ_API char *rz_analysis_op_to_string(RzAnalysis *analysis, RzAnalysisOp *op) {
	RzAnalysisBlock *bb;
	RzAnalysisFunction *f;
	char *cstr, ret[128];
	char *r0 = rz_analysis_value_to_string(op->dst);
	char *a0 = rz_analysis_value_to_string(op->src[0]);
	char *a1 = rz_analysis_value_to_string(op->src[1]);
	if (!r0) {
		r0 = rz_str_dup("?");
	}
	if (!a0) {
		a0 = rz_str_dup("?");
	}
	if (!a1) {
		a1 = rz_str_dup("?");
	}

	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_MOV:
		snprintf(ret, sizeof(ret), "%s = %s", r0, a0);
		break;
	case RZ_ANALYSIS_OP_TYPE_CJMP:
		if ((bb = rz_analysis_find_most_relevant_block_in(analysis, op->addr))) {
			cstr = rz_analysis_cond_to_string(bb->cond);
			snprintf(ret, sizeof(ret), "if (%s) goto 0x%" PFMT64x, cstr, op->jump);
			free(cstr);
		} else {
			snprintf(ret, sizeof(ret), "if (%s) goto 0x%" PFMT64x, "?", op->jump);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_JMP:
		snprintf(ret, sizeof(ret), "goto 0x%" PFMT64x, op->jump);
		break;
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_IJMP:
	case RZ_ANALYSIS_OP_TYPE_IRJMP:
		snprintf(ret, sizeof(ret), "goto %s", r0);
		break;
	case RZ_ANALYSIS_OP_TYPE_PUSH:
	case RZ_ANALYSIS_OP_TYPE_UPUSH:
	case RZ_ANALYSIS_OP_TYPE_RPUSH:
		snprintf(ret, sizeof(ret), "push %s", a0);
		break;
	case RZ_ANALYSIS_OP_TYPE_POP:
		snprintf(ret, sizeof(ret), "pop %s", r0);
		break;
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
		snprintf(ret, sizeof(ret), "%s()", r0);
		break;
	case RZ_ANALYSIS_OP_TYPE_CALL:
		f = rz_analysis_get_fcn_in(analysis, op->jump, RZ_ANALYSIS_FCN_TYPE_NULL);
		if (f) {
			snprintf(ret, sizeof(ret), "%s()", f->name);
		} else {
			snprintf(ret, sizeof(ret), "0x%" PFMT64x "()", op->jump);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_CCALL:
		f = rz_analysis_get_fcn_in(analysis, op->jump, RZ_ANALYSIS_FCN_TYPE_NULL);
		if ((bb = rz_analysis_find_most_relevant_block_in(analysis, op->addr))) {
			cstr = rz_analysis_cond_to_string(bb->cond);
			if (f) {
				snprintf(ret, sizeof(ret), "if (%s) %s()", cstr, f->name);
			} else {
				snprintf(ret, sizeof(ret), "if (%s) 0x%" PFMT64x "()", cstr, op->jump);
			}
			free(cstr);
		} else {
			if (f) {
				snprintf(ret, sizeof(ret), "if (unk) %s()", f->name);
			} else {
				snprintf(ret, sizeof(ret), "if (unk) 0x%" PFMT64x "()", op->jump);
			}
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_ADD:
		if (!a1 || !strcmp(a0, a1)) {
			snprintf(ret, sizeof(ret), "%s += %s", r0, a0);
		} else {
			snprintf(ret, sizeof(ret), "%s = %s + %s", r0, a0, a1);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_SUB:
		if (!a1 || !strcmp(a0, a1)) {
			snprintf(ret, sizeof(ret), "%s -= %s", r0, a0);
		} else {
			snprintf(ret, sizeof(ret), "%s = %s - %s", r0, a0, a1);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_MUL:
		if (!a1 || !strcmp(a0, a1)) {
			snprintf(ret, sizeof(ret), "%s *= %s", r0, a0);
		} else {
			snprintf(ret, sizeof(ret), "%s = %s * %s", r0, a0, a1);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_DIV:
		if (!a1 || !strcmp(a0, a1)) {
			snprintf(ret, sizeof(ret), "%s /= %s", r0, a0);
		} else {
			snprintf(ret, sizeof(ret), "%s = %s / %s", r0, a0, a1);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_AND:
		if (!a1 || !strcmp(a0, a1)) {
			snprintf(ret, sizeof(ret), "%s &= %s", r0, a0);
		} else {
			snprintf(ret, sizeof(ret), "%s = %s & %s", r0, a0, a1);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_OR:
		if (!a1 || !strcmp(a0, a1)) {
			snprintf(ret, sizeof(ret), "%s |= %s", r0, a0);
		} else {
			snprintf(ret, sizeof(ret), "%s = %s | %s", r0, a0, a1);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_XOR:
		if (!a1 || !strcmp(a0, a1)) {
			snprintf(ret, sizeof(ret), "%s ^= %s", r0, a0);
		} else {
			snprintf(ret, sizeof(ret), "%s = %s ^ %s", r0, a0, a1);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_LEA:
		snprintf(ret, sizeof(ret), "%s -> %s", r0, a0);
		break;
	case RZ_ANALYSIS_OP_TYPE_CMP:
		memcpy(ret, ";", 2);
		break;
	case RZ_ANALYSIS_OP_TYPE_NOP:
		memcpy(ret, "nop", 4);
		break;
	case RZ_ANALYSIS_OP_TYPE_RET:
		memcpy(ret, "ret", 4);
		break;
	case RZ_ANALYSIS_OP_TYPE_CRET:
		if ((bb = rz_analysis_find_most_relevant_block_in(analysis, op->addr))) {
			cstr = rz_analysis_cond_to_string(bb->cond);
			snprintf(ret, sizeof(ret), "if (%s) ret", cstr);
			free(cstr);
		} else {
			strcpy(ret, "if (unk) ret");
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_LEAVE:
		memcpy(ret, "leave", 6);
		break;
	case RZ_ANALYSIS_OP_TYPE_MOD:
		if (!a1 || !strcmp(a0, a1)) {
			snprintf(ret, sizeof(ret), "%s %%= %s", r0, a0);
		} else {
			snprintf(ret, sizeof(ret), "%s = %s %% %s", r0, a0, a1);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_XCHG:
		if (!a1 || !strcmp(a0, a1)) {
			snprintf(ret, sizeof(ret), "tmp = %s; %s = %s; %s = tmp", r0, r0, a0, a0);
		} else {
			snprintf(ret, sizeof(ret), "%s = %s ^ %s", r0, a0, a1);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_ROL:
	case RZ_ANALYSIS_OP_TYPE_ROR:
	case RZ_ANALYSIS_OP_TYPE_SWITCH:
	case RZ_ANALYSIS_OP_TYPE_CASE:
		RZ_LOG_DEBUG("Command not implemented.\n");
		free(r0);
		free(a0);
		free(a1);
		return NULL;
	default:
		free(r0);
		free(a0);
		free(a1);
		return NULL;
	}
	free(r0);
	free(a0);
	free(a1);
	return rz_str_dup(ret);
}

RZ_API const char *rz_analysis_stackop_tostring(int s) {
	switch (s) {
	case RZ_ANALYSIS_STACK_NULL:
		return "null";
	case RZ_ANALYSIS_STACK_NOP:
		return "nop";
	case RZ_ANALYSIS_STACK_INC:
		return "inc";
	case RZ_ANALYSIS_STACK_GET:
		return "get";
	case RZ_ANALYSIS_STACK_SET:
		return "set";
	case RZ_ANALYSIS_STACK_RESET:
		return "reset";
	}
	return "unk";
}

/**
 * Modify the given stack pointer value as the instruction \p op would when being executed.
 */
RZ_API RzStackAddr rz_analysis_op_apply_sp_effect(RzAnalysisOp *op, RzStackAddr sp) {
	rz_return_val_if_fail(op, sp);
	// When changing something here, also update rz_analysis_op_describe_sp_effect() to describe
	// the same effect in a textual form.
	switch (op->stackop) {
	case RZ_ANALYSIS_STACK_INC:
		return sp - op->stackptr;
	case RZ_ANALYSIS_STACK_RESET:
		return 0;
	default:
		return sp;
	}
}

/**
 * Generate a textual description of the effect on the stack pointer that \p op has.
 * \return a description like "-= 8" or NULL if the op has no effect on the stack pointer
 */
RZ_API RZ_NULLABLE RZ_OWN char *rz_analysis_op_describe_sp_effect(RzAnalysisOp *op) {
	rz_return_val_if_fail(op, NULL);
	// Keep this in sync with what rz_analysis_op_apply_sp_effect() does!
	switch (op->stackop) {
	case RZ_ANALYSIS_STACK_INC:
		return rz_str_newf("%c= %" PFMT64d, op->stackptr > 0 ? '-' : '+', RZ_ABS(op->stackptr));
	case RZ_ANALYSIS_STACK_RESET:
		return rz_str_dup(":= 0");
	default:
		return NULL;
	}
}

static const struct {
	int id;
	const char *name;
} op_families[] = {
	{ RZ_ANALYSIS_OP_FAMILY_CPU, "cpu" },
	{ RZ_ANALYSIS_OP_FAMILY_FPU, "fpu" },
	{ RZ_ANALYSIS_OP_FAMILY_MMX, "mmx" },
	{ RZ_ANALYSIS_OP_FAMILY_SSE, "sse" },
	{ RZ_ANALYSIS_OP_FAMILY_PRIV, "priv" },
	{ RZ_ANALYSIS_OP_FAMILY_VIRT, "virt" },
	{ RZ_ANALYSIS_OP_FAMILY_CRYPTO, "crpt" },
	{ RZ_ANALYSIS_OP_FAMILY_IO, "io" },
	{ RZ_ANALYSIS_OP_FAMILY_SECURITY, "sec" },
	{ RZ_ANALYSIS_OP_FAMILY_THREAD, "thread" },
};

/**
 * Return the name of the given op family
 * \param  id       int, id of the operation family (one of \link RzAnalysisOpFamily \endlink)
 * \return name     string, name of the op family
 */
RZ_API const char *rz_analysis_op_family_to_string(int id) {
	int i;

	for (i = 0; i < RZ_ARRAY_SIZE(op_families); i++) {
		if (op_families[i].id == id) {
			return op_families[i].name;
		}
	}
	return NULL;
}

/**
 * Return the op family id given its name
 * \param  name     string, name of the op family
 * \return id       int, id of the operation family (one of \link RzAnalysisOpFamily \endlink)
 */
RZ_API int rz_analysis_op_family_from_string(RZ_NONNULL const char *name) {
	int i;
	rz_return_val_if_fail(name, RZ_ANALYSIS_OP_FAMILY_UNKNOWN);
	for (i = 0; i < RZ_ARRAY_SIZE(op_families); i++) {
		if (!strcmp(name, op_families[i].name)) {
			return op_families[i].id;
		}
	}
	return RZ_ANALYSIS_OP_FAMILY_UNKNOWN;
}

/* apply hint to op, return the number of hints applied */
RZ_API int rz_analysis_op_hint(RzAnalysisOp *op, RzAnalysisHint *hint) {
	int changes = 0;
	if (hint) {
		if (hint->val != UT64_MAX) {
			op->val = hint->val;
			changes++;
		}
		if (hint->type > 0) {
			op->type = hint->type;
			changes++;
		}
		if (hint->jump != UT64_MAX) {
			op->jump = hint->jump;
			changes++;
		}
		if (hint->fail != UT64_MAX) {
			op->fail = hint->fail;
			changes++;
		}
		if (hint->opcode) {
			/* XXX: this is not correct */
			free(op->mnemonic);
			op->mnemonic = rz_str_dup(hint->opcode);
			changes++;
		}
		if (hint->esil) {
			rz_strbuf_set(&op->esil, hint->esil);
			changes++;
		}
		if (hint->size) {
			op->size = hint->size;
			changes++;
		}
	}
	return changes;
}

// returns the '33' in 'rax + 33'
// returns value for the given register name in specific address / range
RZ_API int rz_analysis_op_reg_delta(RzAnalysis *analysis, ut64 addr, const char *name) {
	int delta = 0;
	ut8 buf[32];
	analysis->iob.read_at(analysis->iob.io, addr, buf, sizeof(buf));
	RzAnalysisOp op = { 0 };
	rz_analysis_op_init(&op);
	if (rz_analysis_op(analysis, &op, addr, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_ALL) > 0) {
		if (op.dst && op.dst->reg && op.dst->reg->name && (!name || !strcmp(op.dst->reg->name, name))) {
			if (op.src[0]) {
				delta = op.src[0]->delta;
			}
		}
	}
	rz_analysis_op_fini(&op);
	return delta;
}

RZ_API RZ_OWN RzAnalysisInsnWord *rz_analysis_insn_word_new() {
	RzAnalysisInsnWord *iword = RZ_NEW0(RzAnalysisInsnWord);
	if (!iword) {
		return NULL;
	}
	iword->asm_str = rz_strbuf_new("");
	iword->insns = rz_pvector_new(rz_analysis_op_free);
	iword->jump_targets = rz_set_u_new();
	iword->call_targets = rz_set_u_new();
	if (!iword->asm_str || !iword->insns || !iword->jump_targets) {
		rz_analysis_insn_word_free(iword);
		return NULL;
	}
	return iword;
}

RZ_API void rz_analysis_insn_word_free(RZ_OWN RZ_NULLABLE RzAnalysisInsnWord *iword) {
	if (!iword) {
		return;
	}
	rz_analysis_insn_word_fini(iword);
	free(iword);
}

RZ_API void rz_analysis_insn_word_setup(RZ_BORROW RZ_NONNULL RzAnalysisInsnWord *iword) {
	rz_return_if_fail(iword);
	rz_analysis_insn_word_fini(iword);
	iword->asm_str = rz_strbuf_new("");
	iword->insns = rz_pvector_new(rz_analysis_op_free);
	iword->jump_targets = rz_set_u_new();
	iword->call_targets = rz_set_u_new();
	if (!iword->asm_str || !iword->insns || !iword->jump_targets) {
		rz_analysis_insn_word_fini(iword);
	}
}

RZ_API void rz_analysis_insn_word_fini(RZ_OWN RZ_NULLABLE RzAnalysisInsnWord *iword) {
	if (!iword) {
		return;
	}
	rz_strbuf_free(iword->asm_str);
	rz_pvector_free(iword->insns);
	rz_set_u_free(iword->jump_targets);
	rz_set_u_free(iword->call_targets);
	rz_il_op_effect_free(iword->il_op);
	rz_mem_memzero(iword, sizeof(RzAnalysisInsnWord));
}
