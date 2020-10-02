/* radare - LGPL - Copyright 2010-2020 - pancake, nibble */

#include <rz_anal.h>
#include <rz_util.h>
#include <rz_list.h>

RZ_API RzAnalOp *rz_anal_op_new(void) {
	RzAnalOp *op = RZ_NEW (RzAnalOp);
	rz_anal_op_init (op);
	return op;
}

RZ_API RzList *rz_anal_op_list_new(void) {
	RzList *list = rz_list_new ();
	if (list) {
		list->free = &rz_anal_op_free;
	}
	return list;
}

RZ_API void rz_anal_op_init(RzAnalOp *op) {
	if (op) {
		memset (op, 0, sizeof (*op));
		op->addr = UT64_MAX;
		op->jump = UT64_MAX;
		op->fail = UT64_MAX;
		op->ptr = UT64_MAX;
		op->refptr = 0;
		op->val = UT64_MAX;
		op->disp = UT64_MAX;
	}
}

RZ_API bool rz_anal_op_fini(RzAnalOp *op) {
	if (!op) {
		return false;
	}
	rz_anal_value_free (op->src[0]);
	rz_anal_value_free (op->src[1]);
	rz_anal_value_free (op->src[2]);
	op->src[0] = NULL;
	op->src[1] = NULL;
	op->src[2] = NULL;
	rz_anal_value_free (op->dst);
	op->dst = NULL;
	rz_list_free (op->access);
	op->access = NULL;
	rz_strbuf_fini (&op->opex);
	rz_strbuf_fini (&op->esil);
	rz_anal_switch_op_free (op->switch_op);
	op->switch_op = NULL;
	RZ_FREE (op->mnemonic);
	return true;
}

RZ_API void rz_anal_op_free(void *_op) {
	if (!_op) {
		return;
	}
	rz_anal_op_fini (_op);
	memset (_op, 0, sizeof (RzAnalOp));
	free (_op);
}

static int defaultCycles(RzAnalOp *op) {
	switch (op->type) {
	case RZ_ANAL_OP_TYPE_PUSH:
	case RZ_ANAL_OP_TYPE_POP:
	case RZ_ANAL_OP_TYPE_STORE:
	case RZ_ANAL_OP_TYPE_LOAD:
		return 2;
	case RZ_ANAL_OP_TYPE_LEA:
	case RZ_ANAL_OP_TYPE_MOV:
	case RZ_ANAL_OP_TYPE_NOP:
		return 1;
	case RZ_ANAL_OP_TYPE_TRAP:
	case RZ_ANAL_OP_TYPE_SWI:
		return 4;
	case RZ_ANAL_OP_TYPE_SYNC:
		return 4;
	case RZ_ANAL_OP_TYPE_RET:
	case RZ_ANAL_OP_TYPE_JMP:
	case RZ_ANAL_OP_TYPE_RJMP:
	case RZ_ANAL_OP_TYPE_CALL:
		return 4;
	default:
		return 1;
	}
}

RZ_API int rz_anal_op(RzAnal *anal, RzAnalOp *op, ut64 addr, const ut8 *data, int len, RzAnalOpMask mask) {
	rz_anal_op_init (op);
	rz_return_val_if_fail (anal && op && len > 0, -1);

	int ret = RZ_MIN (2, len);
	if (len > 0 && anal->cur && anal->cur->op) {
		//use core binding to set asm.bits correctly based on the addr
		//this is because of the hassle of arm/thumb
		if (anal && anal->coreb.archbits) {
			anal->coreb.archbits (anal->coreb.core, addr);
		}
		if (anal->pcalign && addr % anal->pcalign) {
			op->type = RZ_ANAL_OP_TYPE_ILL;
			op->addr = addr;
			// eprintf ("Unaligned instruction for %d bits at 0x%"PFMT64x"\n", anal->bits, addr);
			op->size = 1;
			return -1;
		}
		ret = anal->cur->op (anal, op, addr, data, len, mask);
		if (ret < 1) {
			op->type = RZ_ANAL_OP_TYPE_ILL;
		}
		op->addr = addr;
		/* consider at least 1 byte to be part of the opcode */
		if (op->nopcode < 1) {
			op->nopcode = 1;
		}
	} else if (!memcmp (data, "\xff\xff\xff\xff", RZ_MIN (4, len))) {
		op->type = RZ_ANAL_OP_TYPE_ILL;
	} else {
		op->type = RZ_ANAL_OP_TYPE_MOV;
		if (op->cycles == 0) {
			op->cycles = defaultCycles (op);
		}
	}
	if (!op->mnemonic && (mask & RZ_ANAL_OP_MASK_DISASM)) {
		if (anal->verbose) {
			eprintf ("Warning: unhandled RZ_ANAL_OP_MASK_DISASM in rz_anal_op\n");
		}
        }
	if (mask & RZ_ANAL_OP_MASK_HINT) {
		RzAnalHint *hint = rz_anal_hint_get (anal, addr);
		if (hint) {
			rz_anal_op_hint (op, hint);
			rz_anal_hint_free (hint);
		}
	}
	return ret;
}

RZ_API RzAnalOp *rz_anal_op_copy(RzAnalOp *op) {
	RzAnalOp *nop = RZ_NEW0 (RzAnalOp);
	if (!nop) {
		return NULL;
	}
	*nop = *op;
	if (op->mnemonic) {
		nop->mnemonic = strdup (op->mnemonic);
		if (!nop->mnemonic) {
			free (nop);
			return NULL;
		}
	} else {
		nop->mnemonic = NULL;
	}
	nop->src[0] = rz_anal_value_copy (op->src[0]);
	nop->src[1] = rz_anal_value_copy (op->src[1]);
	nop->src[2] = rz_anal_value_copy (op->src[2]);
	nop->dst = rz_anal_value_copy (op->dst);
	if (op->access) {
		RzListIter *it;
		RzAnalValue *val;
		RzList *naccess = rz_list_newf ((RzListFree)rz_anal_value_free);
		rz_list_foreach (op->access, it, val) {
			rz_list_append (naccess, rz_anal_value_copy (val));
		}
		nop->access = naccess;
	}
	rz_strbuf_init (&nop->esil);
	rz_strbuf_copy (&nop->esil, &op->esil);
	return nop;
}

RZ_API bool rz_anal_op_nonlinear(int t) {
	t &= RZ_ANAL_OP_TYPE_MASK;
	switch (t) {
	//call
	case RZ_ANAL_OP_TYPE_CALL:
	case RZ_ANAL_OP_TYPE_RCALL:
	case RZ_ANAL_OP_TYPE_ICALL:
	case RZ_ANAL_OP_TYPE_UCALL:
	case RZ_ANAL_OP_TYPE_IRCALL:
	case RZ_ANAL_OP_TYPE_UCCALL:
	// jmp
	case RZ_ANAL_OP_TYPE_JMP:
	case RZ_ANAL_OP_TYPE_MJMP:
	case RZ_ANAL_OP_TYPE_UJMP:
	case RZ_ANAL_OP_TYPE_CJMP:
	case RZ_ANAL_OP_TYPE_UCJMP:
	case RZ_ANAL_OP_TYPE_RJMP:
	case RZ_ANAL_OP_TYPE_IJMP:
	case RZ_ANAL_OP_TYPE_IRJMP:
	// trap| ill| unk
	case RZ_ANAL_OP_TYPE_TRAP:
	case RZ_ANAL_OP_TYPE_ILL:
	case RZ_ANAL_OP_TYPE_UNK:
	case RZ_ANAL_OP_TYPE_SWI:
	case RZ_ANAL_OP_TYPE_RET:
		return true;
	default:
		return false;
	}
}

RZ_API bool rz_anal_op_ismemref(int t) {
	t &= RZ_ANAL_OP_TYPE_MASK;
	switch (t) {
	case RZ_ANAL_OP_TYPE_LOAD:
	case RZ_ANAL_OP_TYPE_MOV:
	case RZ_ANAL_OP_TYPE_STORE:
	case RZ_ANAL_OP_TYPE_LEA:
	case RZ_ANAL_OP_TYPE_CMP:
		return true;
	default:
		return false;
	}
}

static struct optype {
	int type;
	const char *name;
} optypes[] = {
	{ RZ_ANAL_OP_TYPE_IO, "io" },
	{ RZ_ANAL_OP_TYPE_ACMP, "acmp" },
	{ RZ_ANAL_OP_TYPE_ADD, "add" },
	{ RZ_ANAL_OP_TYPE_SYNC, "sync" },
	{ RZ_ANAL_OP_TYPE_AND, "and" },
	{ RZ_ANAL_OP_TYPE_CALL, "call" },
	{ RZ_ANAL_OP_TYPE_CCALL, "ccall" },
	{ RZ_ANAL_OP_TYPE_CJMP, "cjmp" },
	{ RZ_ANAL_OP_TYPE_MJMP, "mjmp" },
	{ RZ_ANAL_OP_TYPE_CMP, "cmp" },
	{ RZ_ANAL_OP_TYPE_IO, "cret" },
	{ RZ_ANAL_OP_TYPE_ILL, "ill" },
	{ RZ_ANAL_OP_TYPE_JMP, "jmp" },
	{ RZ_ANAL_OP_TYPE_LEA, "lea" },
	{ RZ_ANAL_OP_TYPE_LEAVE, "leave" },
	{ RZ_ANAL_OP_TYPE_LOAD, "load" },
	{ RZ_ANAL_OP_TYPE_NEW, "new" },
	{ RZ_ANAL_OP_TYPE_MOD, "mod" },
	{ RZ_ANAL_OP_TYPE_CMOV, "cmov" },
	{ RZ_ANAL_OP_TYPE_MOV, "mov" },
	{ RZ_ANAL_OP_TYPE_CAST, "cast" },
	{ RZ_ANAL_OP_TYPE_MUL, "mul" },
	{ RZ_ANAL_OP_TYPE_DIV, "div" },
	{ RZ_ANAL_OP_TYPE_NOP, "nop" },
	{ RZ_ANAL_OP_TYPE_NOT, "not" },
	{ RZ_ANAL_OP_TYPE_NULL  , "null" },
	{ RZ_ANAL_OP_TYPE_OR    , "or" },
	{ RZ_ANAL_OP_TYPE_POP   , "pop" },
	{ RZ_ANAL_OP_TYPE_PUSH  , "push" },
	{ RZ_ANAL_OP_TYPE_REP   , "rep" },
	{ RZ_ANAL_OP_TYPE_RET   , "ret" },
	{ RZ_ANAL_OP_TYPE_ROL   , "rol" },
	{ RZ_ANAL_OP_TYPE_ROR   , "ror" },
	{ RZ_ANAL_OP_TYPE_SAL   , "sal" },
	{ RZ_ANAL_OP_TYPE_SAR   , "sar" },
	{ RZ_ANAL_OP_TYPE_SHL   , "shl" },
	{ RZ_ANAL_OP_TYPE_SHR   , "shr" },
	{ RZ_ANAL_OP_TYPE_STORE , "store" },
	{ RZ_ANAL_OP_TYPE_SUB   , "sub" },
	{ RZ_ANAL_OP_TYPE_SWI   , "swi" },
	{ RZ_ANAL_OP_TYPE_CSWI  , "cswi" },
	{ RZ_ANAL_OP_TYPE_SWITCH, "switch" },
	{ RZ_ANAL_OP_TYPE_TRAP  , "trap" },
	{ RZ_ANAL_OP_TYPE_UCALL , "ucall" },
	{ RZ_ANAL_OP_TYPE_RCALL , "rcall" }, // needs to be changed
	{ RZ_ANAL_OP_TYPE_ICALL , "ucall" }, // needs to be changed
	{ RZ_ANAL_OP_TYPE_IRCALL, "ucall" }, // needs to be changed
	{ RZ_ANAL_OP_TYPE_UCCALL, "uccall" },
	{ RZ_ANAL_OP_TYPE_UCJMP , "ucjmp" },
	{ RZ_ANAL_OP_TYPE_UJMP  , "ujmp" },
	{ RZ_ANAL_OP_TYPE_RJMP  , "rjmp" }, // needs to be changed
	{ RZ_ANAL_OP_TYPE_IJMP  , "ujmp" }, // needs to be changed
	{ RZ_ANAL_OP_TYPE_IRJMP , "ujmp" }, // needs to be changed
	{ RZ_ANAL_OP_TYPE_UNK   , "unk" },
	{ RZ_ANAL_OP_TYPE_UPUSH , "upush" },
	{ RZ_ANAL_OP_TYPE_RPUSH , "rpush" },
	{ RZ_ANAL_OP_TYPE_XCHG  , "xchg" },
	{ RZ_ANAL_OP_TYPE_XOR   , "xor" },
	{ RZ_ANAL_OP_TYPE_CASE  , "case" },
	{ RZ_ANAL_OP_TYPE_CPL   , "cpl" },
	{ RZ_ANAL_OP_TYPE_CRYPTO, "crypto" },
	{0,NULL}
};

RZ_API int rz_anal_optype_from_string(const char *type) {
	int i;
	for  (i = 0; optypes[i].name;i++) {
		if (!strcmp (optypes[i].name, type)) {
			return optypes[i].type;
		}
	}
	return -1;
}

RZ_API const char *rz_anal_optype_to_string(int t) {
	bool once = true;
repeat:
	// TODO: delete
	switch (t) {
	case RZ_ANAL_OP_TYPE_IO    : return "io";
	case RZ_ANAL_OP_TYPE_ACMP  : return "acmp";
	case RZ_ANAL_OP_TYPE_ADD   : return "add";
	case RZ_ANAL_OP_TYPE_SYNC  : return "sync";
	case RZ_ANAL_OP_TYPE_AND   : return "and";
	case RZ_ANAL_OP_TYPE_CALL  : return "call";
	case RZ_ANAL_OP_TYPE_CCALL : return "ccall";
	case RZ_ANAL_OP_TYPE_CJMP  : return "cjmp";
	case RZ_ANAL_OP_TYPE_MJMP  : return "mjmp";
	case RZ_ANAL_OP_TYPE_CMP   : return "cmp";
	case RZ_ANAL_OP_TYPE_CRET  : return "cret";
	case RZ_ANAL_OP_TYPE_DIV   : return "div";
	case RZ_ANAL_OP_TYPE_ILL   : return "ill";
	case RZ_ANAL_OP_TYPE_JMP   : return "jmp";
	case RZ_ANAL_OP_TYPE_LEA   : return "lea";
	case RZ_ANAL_OP_TYPE_LEAVE : return "leave";
	case RZ_ANAL_OP_TYPE_LOAD  : return "load";
	case RZ_ANAL_OP_TYPE_NEW   : return "new";
	case RZ_ANAL_OP_TYPE_MOD   : return "mod";
	case RZ_ANAL_OP_TYPE_CMOV  : return "cmov";
	case RZ_ANAL_OP_TYPE_MOV   : return "mov";
	case RZ_ANAL_OP_TYPE_CAST  : return "cast";
	case RZ_ANAL_OP_TYPE_MUL   : return "mul";
	case RZ_ANAL_OP_TYPE_NOP   : return "nop";
	case RZ_ANAL_OP_TYPE_NOT   : return "not";
	case RZ_ANAL_OP_TYPE_NULL  : return "null";
	case RZ_ANAL_OP_TYPE_OR    : return "or";
	case RZ_ANAL_OP_TYPE_POP   : return "pop";
	case RZ_ANAL_OP_TYPE_PUSH  : return "push";
	case RZ_ANAL_OP_TYPE_RPUSH : return "rpush";
	case RZ_ANAL_OP_TYPE_REP   : return "rep";
	case RZ_ANAL_OP_TYPE_RET   : return "ret";
	case RZ_ANAL_OP_TYPE_ROL   : return "rol";
	case RZ_ANAL_OP_TYPE_ROR   : return "ror";
	case RZ_ANAL_OP_TYPE_SAL   : return "sal";
	case RZ_ANAL_OP_TYPE_SAR   : return "sar";
	case RZ_ANAL_OP_TYPE_SHL   : return "shl";
	case RZ_ANAL_OP_TYPE_SHR   : return "shr";
	case RZ_ANAL_OP_TYPE_STORE : return "store";
	case RZ_ANAL_OP_TYPE_SUB   : return "sub";
	case RZ_ANAL_OP_TYPE_SWI   : return "swi";
	case RZ_ANAL_OP_TYPE_CSWI  : return "cswi";
	case RZ_ANAL_OP_TYPE_SWITCH: return "switch";
	case RZ_ANAL_OP_TYPE_TRAP  : return "trap";
	case RZ_ANAL_OP_TYPE_UCALL : return "ucall";
	case RZ_ANAL_OP_TYPE_RCALL : return "rcall"; // needs to be changed
	case RZ_ANAL_OP_TYPE_ICALL : return "ucall"; // needs to be changed
	case RZ_ANAL_OP_TYPE_IRCALL: return "ucall"; // needs to be changed
	case RZ_ANAL_OP_TYPE_UCCALL: return "uccall";
	case RZ_ANAL_OP_TYPE_UCJMP : return "ucjmp";
	case RZ_ANAL_OP_TYPE_UJMP  : return "ujmp";
	case RZ_ANAL_OP_TYPE_RJMP  : return "rjmp"; // needs to be changed
	case RZ_ANAL_OP_TYPE_IJMP  : return "ujmp"; // needs to be changed
	case RZ_ANAL_OP_TYPE_IRJMP : return "ujmp"; // needs to be changed
	case RZ_ANAL_OP_TYPE_UNK   : return "unk";
	case RZ_ANAL_OP_TYPE_UPUSH : return "upush";
	case RZ_ANAL_OP_TYPE_XCHG  : return "xchg";
	case RZ_ANAL_OP_TYPE_XOR   : return "xor";
	case RZ_ANAL_OP_TYPE_CASE  : return "case";
	case RZ_ANAL_OP_TYPE_CPL   : return "cpl";
	case RZ_ANAL_OP_TYPE_CRYPTO: return "crypto";
	}
	if (once) {
		once = false;
		t &= RZ_ANAL_OP_TYPE_MASK; // ignore the modifier bits... we don't want this!
		goto repeat;
	}
	return "undefined";
}

RZ_API const char *rz_anal_op_to_esil_string(RzAnal *anal, RzAnalOp *op) {
	return rz_strbuf_get (&op->esil);
}

// TODO: use esil here?
RZ_API char *rz_anal_op_to_string(RzAnal *anal, RzAnalOp *op) {
	RzAnalBlock *bb;
	RzAnalFunction *f;
	char *cstr, ret[128];
	char *r0 = rz_anal_value_to_string (op->dst);
	char *a0 = rz_anal_value_to_string (op->src[0]);
	char *a1 = rz_anal_value_to_string (op->src[1]);
	if (!r0) {
		r0 = strdup ("?");
	}
	if (!a0) {
		a0 = strdup ("?");
	}
	if (!a1) {
		a1 = strdup ("?");
	}

	switch (op->type) {
	case RZ_ANAL_OP_TYPE_MOV:
		snprintf (ret, sizeof (ret), "%s = %s", r0, a0);
		break;
	case RZ_ANAL_OP_TYPE_CJMP:
		if ((bb = rz_anal_bb_from_offset (anal, op->addr))) {
			cstr = rz_anal_cond_to_string (bb->cond);
			snprintf (ret, sizeof (ret), "if (%s) goto 0x%"PFMT64x, cstr, op->jump);
			free (cstr);
		} else {
			snprintf (ret, sizeof (ret), "if (%s) goto 0x%"PFMT64x, "?", op->jump);
		}
		break;
	case RZ_ANAL_OP_TYPE_JMP:
		snprintf (ret, sizeof (ret), "goto 0x%"PFMT64x, op->jump);
		break;
	case RZ_ANAL_OP_TYPE_UJMP:
	case RZ_ANAL_OP_TYPE_RJMP:
	case RZ_ANAL_OP_TYPE_IJMP:
	case RZ_ANAL_OP_TYPE_IRJMP:
		snprintf (ret, sizeof (ret), "goto %s", r0);
		break;
	case RZ_ANAL_OP_TYPE_PUSH:
	case RZ_ANAL_OP_TYPE_UPUSH:
	case RZ_ANAL_OP_TYPE_RPUSH:
		snprintf (ret, sizeof (ret), "push %s", a0);
		break;
	case RZ_ANAL_OP_TYPE_POP:
		snprintf (ret, sizeof (ret), "pop %s", r0);
		break;
	case RZ_ANAL_OP_TYPE_UCALL:
	case RZ_ANAL_OP_TYPE_RCALL:
	case RZ_ANAL_OP_TYPE_ICALL:
	case RZ_ANAL_OP_TYPE_IRCALL:
		snprintf (ret, sizeof (ret), "%s()", r0);
		break;
	case RZ_ANAL_OP_TYPE_CALL:
		f = rz_anal_get_fcn_in (anal, op->jump, RZ_ANAL_FCN_TYPE_NULL);
		if (f) {
			snprintf (ret, sizeof (ret), "%s()", f->name);
		} else {
			snprintf (ret, sizeof (ret), "0x%"PFMT64x"()", op->jump);
		}
		break;
	case RZ_ANAL_OP_TYPE_CCALL:
		f = rz_anal_get_fcn_in (anal, op->jump, RZ_ANAL_FCN_TYPE_NULL);
		if ((bb = rz_anal_bb_from_offset (anal, op->addr))) {
			cstr = rz_anal_cond_to_string (bb->cond);
			if (f) {
				snprintf (ret, sizeof (ret), "if (%s) %s()", cstr, f->name);
			} else {
				snprintf (ret, sizeof (ret), "if (%s) 0x%" PFMT64x "()", cstr, op->jump);
			}
			free (cstr);
		} else {
			if (f) {
				snprintf (ret, sizeof (ret), "if (unk) %s()", f->name);
			} else {
				snprintf (ret, sizeof (ret), "if (unk) 0x%" PFMT64x "()", op->jump);
			}
		}
		break;
	case RZ_ANAL_OP_TYPE_ADD:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s += %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s + %s", r0, a0, a1);
		}
		break;
	case RZ_ANAL_OP_TYPE_SUB:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s -= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s - %s", r0, a0, a1);
		}
		break;
	case RZ_ANAL_OP_TYPE_MUL:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s *= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s * %s", r0, a0, a1);
		}
		break;
	case RZ_ANAL_OP_TYPE_DIV:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s /= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s / %s", r0, a0, a1);
		}
		break;
	case RZ_ANAL_OP_TYPE_AND:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s &= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s & %s", r0, a0, a1);
		}
		break;
	case RZ_ANAL_OP_TYPE_OR:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s |= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s | %s", r0, a0, a1);
		}
		break;
	case RZ_ANAL_OP_TYPE_XOR:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s ^= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s ^ %s", r0, a0, a1);
		}
		break;
	case RZ_ANAL_OP_TYPE_LEA:
		snprintf (ret, sizeof (ret), "%s -> %s", r0, a0);
		break;
	case RZ_ANAL_OP_TYPE_CMP:
		memcpy (ret, ";", 2);
		break;
	case RZ_ANAL_OP_TYPE_NOP:
		memcpy (ret, "nop", 4);
		break;
	case RZ_ANAL_OP_TYPE_RET:
		memcpy (ret, "ret", 4);
		break;
	case RZ_ANAL_OP_TYPE_CRET:
		if ((bb = rz_anal_bb_from_offset (anal, op->addr))) {
			cstr = rz_anal_cond_to_string (bb->cond);
			snprintf (ret, sizeof (ret), "if (%s) ret", cstr);
			free (cstr);
		} else {
			strcpy (ret, "if (unk) ret");
		}
		break;
	case RZ_ANAL_OP_TYPE_LEAVE:
		memcpy (ret, "leave", 6);
		break;
	case RZ_ANAL_OP_TYPE_MOD:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s %%= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s %% %s", r0, a0, a1);
		}
		break;
	case RZ_ANAL_OP_TYPE_XCHG:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "tmp = %s; %s = %s; %s = tmp", r0, r0, a0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s ^ %s", r0, a0, a1);
		}
		break;
	case RZ_ANAL_OP_TYPE_ROL:
	case RZ_ANAL_OP_TYPE_ROR:
	case RZ_ANAL_OP_TYPE_SWITCH:
	case RZ_ANAL_OP_TYPE_CASE:
		eprintf ("Command not implemented.\n");
		free (r0);
		free (a0);
		free (a1);
		return NULL;
	default:
		free (r0);
		free (a0);
		free (a1);
		return NULL;
	}
	free (r0);
	free (a0);
	free (a1);
	return strdup (ret);
}

RZ_API const char *rz_anal_stackop_tostring(int s) {
	switch (s) {
	case RZ_ANAL_STACK_NULL:
		return "null";
	case RZ_ANAL_STACK_NOP:
		return "nop";
	case RZ_ANAL_STACK_INC:
		return "inc";
	case RZ_ANAL_STACK_GET:
		return "get";
	case RZ_ANAL_STACK_SET:
		return "set";
	case RZ_ANAL_STACK_RESET:
		return "reset";
	}
	return "unk";
}

RZ_API const char *rz_anal_op_family_to_string(int n) {
	switch (n) {
	case RZ_ANAL_OP_FAMILY_UNKNOWN: return "unk";
	case RZ_ANAL_OP_FAMILY_CPU: return "cpu";
	case RZ_ANAL_OP_FAMILY_SECURITY: return "sec";
	case RZ_ANAL_OP_FAMILY_FPU: return "fpu";
	case RZ_ANAL_OP_FAMILY_MMX: return "mmx";
	case RZ_ANAL_OP_FAMILY_SSE: return "sse";
	case RZ_ANAL_OP_FAMILY_PRIV: return "priv";
	case RZ_ANAL_OP_FAMILY_THREAD: return "thrd";
	case RZ_ANAL_OP_FAMILY_CRYPTO: return "crpt";
	case RZ_ANAL_OP_FAMILY_IO: return "io";
	case RZ_ANAL_OP_FAMILY_VIRT: return "virt";
	}
	return NULL;
}

RZ_API int rz_anal_op_family_from_string(const char *f) {
	struct op_family {
		const char *name;
		int id;
	};
	static const struct op_family of[] = {
		{"cpu", RZ_ANAL_OP_FAMILY_CPU},
		{"fpu", RZ_ANAL_OP_FAMILY_FPU},
		{"mmx", RZ_ANAL_OP_FAMILY_MMX},
		{"sse", RZ_ANAL_OP_FAMILY_SSE},
		{"priv", RZ_ANAL_OP_FAMILY_PRIV},
		{"virt", RZ_ANAL_OP_FAMILY_VIRT},
		{"crpt", RZ_ANAL_OP_FAMILY_CRYPTO},
		{"io", RZ_ANAL_OP_FAMILY_IO},
		{"sec", RZ_ANAL_OP_FAMILY_SECURITY},
		{"thread", RZ_ANAL_OP_FAMILY_THREAD},
	};

	int i;
	for (i = 0; i < sizeof (of) / sizeof (of[0]); i ++) {
		if (!strcmp (f, of[i].name)) {
			return of[i].id;
		}
	}
	return RZ_ANAL_OP_FAMILY_UNKNOWN;
}

/* apply hint to op, return the number of hints applied */
RZ_API int rz_anal_op_hint(RzAnalOp *op, RzAnalHint *hint) {
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
			free (op->mnemonic);
			op->mnemonic = strdup (hint->opcode);
			changes++;
		}
		if (hint->esil) {
			rz_strbuf_set (&op->esil, hint->esil);
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
// imho this should not iterate, should be just a helper to get that value
RZ_API int rz_anal_op_reg_delta(RzAnal *anal, ut64 addr, const char *name) {
	ut8 buf[32];
	anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf));
	RzAnalOp op = { 0 };
	if (rz_anal_op (anal, &op, addr, buf, sizeof (buf), RZ_ANAL_OP_MASK_ALL) > 0) {
		if (op.dst && op.dst->reg && op.dst->reg->name && (!name || !strcmp (op.dst->reg->name, name))) {
			if (op.src[0]) {
				return op.src[0]->delta;
			}
		}
	}
	return 0;
}
