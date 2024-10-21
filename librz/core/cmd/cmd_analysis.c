// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util/rz_graph_drawable.h>

#include "../core_private.h"

#define MAX_SCAN_SIZE 0x7ffffff

#define ESILISTATE core->analysis->esilinterstate

HEAPTYPE(ut64);

static const char *help_msg_a[] = {
	"Usage:", "a", "[abdefFghoprxstc] [...]",
	"a*", "", "same as afl*;ah*;ax*",
	"aa", "[?]", "analyze all (fcns + bbs) (aa0 to avoid sub renaming)",
	"a8", " [hexpairs]", "analyze bytes",
	"ab", "[?] [addr]", "analyze block",
	"ad", "[?]", "analyze data trampoline (wip)",
	"ad", " [from] [to]", "analyze data pointers to (from-to)",
	"ae", "[?] [expr]", "analyze opcode eval expression (see ao)",
	"af", "[?]", "analyze Functions",
	"aF", "", "same as above, but using analysis.depth=1",
	"ag", "[?] [options]", "draw graphs in various formats",
	"ah", "[?]", "analysis hints (force opcode size, ...)",
	"ai", " [addr]", "address information (show perms, stack, heap, ...)",
	"aj", "", "same as a* but in json (aflj)",
	"aL", "", "list all asm/analysis plugins (e asm.arch=?)",
	"an", " [name] [@addr]", "show/rename/create whatever flag/function is used at addr",
	"ao", "[?] [len]", "analyze Opcodes (or emulate it)",
	"aO", "[?] [len]", "Analyze N instructions in M bytes",
	"ap", "", "find prelude for current offset",
	"ar", "[?]", "like 'dr' but for the esil vm. (registers)",
	"as", "[?] [num]", "analyze syscall using dbg.reg",
	"av", "[?] [.]", "show vtables",
	"ax", "[?]", "manage refs/xrefs (see also afx?)",
	NULL
};

static const char *help_msg_ae[] = {
	"Usage:", "ae[idesr?] [arg]", "ESIL code emulation",
	"ae", " [expr]", "evaluate ESIL expression",
	"ae?", "", "show this help",
	"ae??", "", "show ESIL help",
	"ae[aA]", "[f] [count]", "analyse esil accesses (regs, mem..)",
	"aeC", "[arg0 arg1..] @ addr", "appcall in esil",
	"aec", "[?]", "continue until ^C",
	"aecb", "", "continue back until breakpoint",
	"aecs", "", "continue until syscall",
	"aecc", "", "continue until call",
	"aecu", " [addr]", "continue until address",
	"aecue", " [esil]", "continue until esil expression match",
	"aef", " [addr]", "emulate function",
	"aefa", " [addr]", "emulate function to find out args in given or current offset",
	"aei", "", "initialize ESIL VM state (aei- to deinitialize)",
	"aeim", " [addr] [size] [name]", "initialize ESIL VM stack (aeim- remove)",
	"aeip", "", "initialize ESIL program counter to curseek",
	"aek", " [query]", "perform sdb query on ESIL.info",
	"aek-", "", "resets the ESIL.info sdb instance",
	"aeli", "", "list loaded ESIL interrupts",
	"aeli", " [file]", "load ESIL interrupts from shared object",
	"aelir", " [interrupt number]", "remove ESIL interrupt and free it if needed",
	"aepc", " [addr]", "change esil PC to this address",
	"aes", "", "perform emulated debugger step",
	"aesp", " [X] [N]", "evaluate N instr from offset X",
	"aesb", "", "step back",
	"aeso", " ", "step over",
	"aesou", " [addr]", "step over until given address",
	"aess", " ", "step skip (in case of CALL, just skip, instead of step into)",
	"aesu", " [addr]", "step until given address",
	"aesue", " [esil]", "step until esil expression match",
	"aesuo", " [optype]", "step until given opcode type",
	"aets", "[?]", "ESIL Trace session",
	"aex", " [hex]", "evaluate opcode expression",
	"aez", "[?]", "RzIL Emulation",
	NULL
};

static const char *help_detail_ae[] = {
	"Examples:", "ESIL", " examples and documentation",
	"=", "", "assign updating internal flags",
	":=", "", "assign without updating internal flags",
	"+=", "", "A+=B => B,A,+=",
	"+", "", "A=A+B => B,A,+,A,=",
	"++", "", "increment, 2,A,++ == 3 (see rsi,--=[1], ... )",
	"--", "", "decrement, 2,A,-- == 1",
	"*=", "", "A*=B => B,A,*=",
	"/=", "", "A/=B => B,A,/=",
	"%=", "", "A%=B => B,A,%=",
	"&=", "", "and ax, bx => bx,ax,&=",
	"|", "", "or r0, r1, r2 => r2,r1,|,r0,=",
	"!=", "", "negate all bits",
	"^=", "", "xor ax, bx => bx,ax,^=",
	"", "[]", "mov eax,[eax] => eax,[],eax,=",
	"=", "[]", "mov [eax+3], 1 => 1,3,eax,+,=[]",
	"=", "[1]", "mov byte[eax],1 => 1,eax,=[1]",
	"=", "[8]", "mov [rax],1 => 1,rax,=[8]",
	"[]", "", "peek from random position",
	"[N]", "", "peek word of N bytes from popped address",
	"[*]", "", "peek some from random position",
	"=", "[*]", "poke some at random position",
	"$", "", "int 0x80 => 0x80,$",
	"$$", "", "simulate a hardware trap",
	"==", "", "pops twice, compare and update esil flags",
	"<", "", "compare for smaller",
	"<=", "", "compare for smaller or equal",
	">", "", "compare for bigger",
	">=", "", "compare bigger for or equal",
	">>=", "", "shr ax, bx => bx,ax,>>=  # shift right",
	"<<=", "", "shl ax, bx => bx,ax,<<=  # shift left",
	">>>=", "", "ror ax, bx => bx,ax,>>>=  # rotate right",
	"<<<=", "", "rol ax, bx => bx,ax,<<<=  # rotate left",
	"?{", "", "if popped value != 0 run the block until }",
	"POP", "", "drops last element in the esil stack",
	"DUP", "", "duplicate last value in stack",
	"NUM", "", "evaluate last item in stack to number",
	"SWAP", "", "swap last two values in stack",
	"TRAP", "", "stop execution",
	"BITS", "", "16,BITS  # change bits, useful for arm/thumb",
	"TODO", "", "the instruction is not yet esilized",
	"STACK", "", "show contents of stack",
	"CLEAR", "", "clears the esil stack",
	"REPEAT", "", "repeat n times",
	"BREAK", "", "terminates the string parsing",
	"SETJT", "", "set jump target",
	"SETJTS", "", "set jump target set",
	"SETD", "", "set delay slot",
	"GOTO", "", "jump to the Nth word popped from the stack",
	"$", "", "esil interrupt",
	"$z", "", "internal flag: zero",
	"$c", "", "internal flag: carry",
	"$b", "", "internal flag: borrow",
	"$p", "", "internal flag: parity",
	"$s", "", "internal flag: sign",
	"$o", "", "internal flag: overflow",
	"$ds", "", "internal flag: delay-slot",
	"$jt", "", "internal flag: jump-target",
	"$js", "", "internal flag: jump-target-set",
	// DEPRECATED "$r", "", "internal flag: jump-sign",
	"$$", "", "internal flag: pc address",
	NULL
};

static const char *help_msg_aea[] = {
	"Examples:", "aea", " show regs and memory accesses used in a range",
	"aea", "  [ops]", "Show regs/memory accesses used in N instructions ",
	"aea*", " [ops]", "Create mem.* flags for memory accesses",
	"aeab", "", "Show regs used in current basic block",
	"aeaf", "", "Show regs used in current function",
	"aear", " [ops]", "Show regs read in N instructions",
	"aeaw", " [ops]", "Show regs written in N instructions",
	"aean", " [ops]", "Show regs not written in N instructions",
	"aeaj", " [ops]", "Show aea output in JSON format",
	"aeA", "  [len]", "Show regs used in N bytes (subcommands are the same)",
	"Legend:", "", "",
	"I", "", "input registers (read before being set)",
	"A", "", "all regs accessed",
	"R", "", "register values read",
	"W", "", "registers written",
	"N", "", "read but never written",
	"V", "", "values",
	"@R", "", "memreads",
	"@W", "", "memwrites",
	"NOTE:", "", "mem{reads,writes} with PIC only fetch the offset",
	NULL
};

/**
 * \brief Helper to get function in \p offset
 *
 * Case of overlapped functions is treated as an error
 * if \p offset is not an entry point.
 */
static RzAnalysisFunction *analysis_get_function_in(RzAnalysis *analysis, ut64 offset) {
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(analysis, offset);
	if (fcn) {
		return fcn;
	}
	RzList *list = rz_analysis_get_functions_in(analysis, offset);
	if (rz_list_empty(list)) {
		RZ_LOG_ERROR("No function found in 0x%08" PFMT64x ".\n", offset);
		goto exit;
	}
	if (rz_list_length(list) > 1) {
		RZ_LOG_ERROR("Multiple overlapping functions found at 0x%08" PFMT64x ". "
			     "Re-run this command at the entrypoint of one of them to disambiguate.\n",
			offset);
		goto exit;
	}
	fcn = rz_list_first(list);
	if (!fcn) {
		rz_warn_if_reached();
	}
exit:
	rz_list_free(list);
	return fcn;
}

static int cmpaddr(const void *_a, const void *_b, void *user) {
	const RzAnalysisFunction *a = _a, *b = _b;
	return (a->addr > b->addr) ? 1 : (a->addr < b->addr) ? -1
							     : 0;
}

static bool listOpDescriptions(void *_core, const SdbKv *kv) {
	rz_cons_printf("%s=%s\n", sdbkv_key(kv), sdbkv_value(kv));
	return true;
}

static void var_accesses_list(RzAnalysisFunction *fcn, RzAnalysisVar *var, PJ *pj, int access_type, const char *name) {
	RzAnalysisVarAccess *acc;
	bool first = true;
	if (pj) {
		pj_o(pj);
		pj_ks(pj, "name", name);
		pj_ka(pj, "addrs");
	} else {
		rz_cons_printf("%10s", name);
	}
	rz_vector_foreach (&var->accesses, acc) {
		if (!(acc->type & access_type)) {
			continue;
		}
		ut64 addr = fcn->addr + acc->offset;
		if (pj) {
			pj_n(pj, addr);
		} else {
			rz_cons_printf("%s0x%" PFMT64x, first ? "  " : ",", addr);
		}
		first = false;
	}
	if (pj) {
		pj_end(pj);
		pj_end(pj);
	} else {
		rz_cons_newline();
	}
}

typedef enum {
	IS_VAR = 0,
	IS_ARG,
	IS_ARG_AND_VAR
} RzVarListType;

static void list_vars(RzCore *core, RzAnalysisFunction *fcn, PJ *pj, int type, const char *name, RzVarListType vlt) {
	void **it;
	if (type == '=') {
		ut64 oaddr = core->offset;
		rz_pvector_foreach (&fcn->vars, it) {
			RzAnalysisVar *var = *it;
			rz_cons_printf("* %s\n", var->name);
			RzAnalysisVarAccess *acc;
			rz_vector_foreach (&var->accesses, acc) {
				if (!(acc->type & RZ_ANALYSIS_VAR_ACCESS_TYPE_READ)) {
					continue;
				}
				rz_cons_printf("R 0x%" PFMT64x "  ", fcn->addr + acc->offset);
				rz_core_seek(core, fcn->addr + acc->offset, 1);
				rz_core_print_disasm_instructions(core, 0, 1);
			}
			rz_vector_foreach (&var->accesses, acc) {
				if (!(acc->type & RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE)) {
					continue;
				}
				rz_cons_printf("W 0x%" PFMT64x "  ", fcn->addr + acc->offset);
				rz_core_seek(core, fcn->addr + acc->offset, 1);
				rz_core_print_disasm_instructions(core, 0, 1);
			}
		}
		rz_core_seek(core, oaddr, 0);
		return;
	}
	if (type == '*') {
		const char *bp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_BP);
		rz_cons_printf("f- fcnvar*\n");
		rz_pvector_foreach (&fcn->vars, it) {
			RzAnalysisVar *var = *it;
			if (var->storage.type != RZ_ANALYSIS_VAR_STORAGE_STACK) {
				continue;
			}
			st64 off = var->storage.stack_off;
			rz_cons_printf("f fcnvar.%s @ %s%s%" PFMT64x "\n", var->name, bp,
				off >= 0 ? "+" : "", off);
		}
		return;
	}
	if (type != 'W' && type != 'R') {
		return;
	}
	int access_type = type == 'R' ? RZ_ANALYSIS_VAR_ACCESS_TYPE_READ : RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE;
	if (pj) {
		pj_a(pj);
	}
	if (name && *name) {
		RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, name);
		if (var) {
			if (vlt == IS_ARG_AND_VAR || rz_analysis_var_is_arg(var) == (vlt == IS_ARG)) {
				var_accesses_list(fcn, var, pj, access_type, var->name);
			}
		}
	} else {
		rz_pvector_foreach (&fcn->vars, it) {
			RzAnalysisVar *var = *it;
			if (vlt == IS_ARG_AND_VAR || rz_analysis_var_is_arg(var) == (vlt == IS_ARG)) {
				var_accesses_list(fcn, var, pj, access_type, var->name);
			}
		}
	}
	if (pj) {
		pj_end(pj);
	}
}

#define PJ_KS(pj, key, value) \
	{ \
		const char *value_tmp = (value); \
		if (RZ_STR_ISNOTEMPTY(value_tmp)) { \
			pj_ks(pj, key, value_tmp); \
		} \
	}
#define PJ_KN(pj, key, value) \
	{ \
		const ut64 value_tmp = (value); \
		if (value_tmp != UT64_MAX) { \
			pj_kn(pj, key, value_tmp); \
		} \
	}

static bool core_analysis_name_print(RzCore *core, RzCmdStateOutput *state) {
	RzCoreAnalysisName *p = rz_core_analysis_name(core, core->offset);
	if (!p) {
		return false;
	}
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON: {
		pj_a(pj);

		pj_o(pj);
		PJ_KS(pj, "name", p->name);
		PJ_KS(pj, "realname", p->realname);
		pj_ks(pj, "type", rz_core_analysis_name_type_to_str(p->type));
		pj_kn(pj, "offset", p->offset);
		pj_end(pj);

		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		if (p->type == RZ_CORE_ANALYSIS_NAME_TYPE_ADDRESS) {
			rz_cons_printf("0x%" PFMT64x "\n", p->offset);
		} else {
			rz_cons_println(p->name);
		}
		break;
	}
	default:
		rz_warn_if_reached();
		rz_core_analysis_name_free(p);
		return false;
	}

	rz_core_analysis_name_free(p);
	return true;
}

static void print_trampolines(RzCore *core, ut64 minimum, ut64 maximum,
	size_t element_size) {
	bool big_endian = rz_config_get_b(core->config, "cfg.big_endian");
	for (int i = 0; i < core->blocksize; i += element_size) {
		ut32 n = rz_read_ble32(core->block + i, big_endian);
		if (n < minimum || n > maximum) {
			continue;
		}
		rz_cons_printf("f trampoline.%" PFMT32x " @ 0x%" PFMT64x "\n", n, core->offset + i);
		rz_cons_printf("Cd %zu @ 0x%" PFMT64x ":%zu\n", element_size, core->offset + i, element_size);
		// TODO: add data xrefs
	}
}

static int mw(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	int *ec = (int *)esil->user;
	*ec += (len * 2);
	return 1;
}

static int mr(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	int *ec = (int *)esil->user;
	*ec += len;
	return 1;
}

static int esil_cost(RzCore *core, ut64 addr, const char *expr) {
	if (RZ_STR_ISEMPTY(expr)) {
		return 0;
	}
	int ec = 0;
	RzAnalysisEsil *e = rz_analysis_esil_new(256, 0, 0);
	rz_analysis_esil_setup(e, core->analysis, false, false, false);
	e->user = &ec;
	e->cb.mem_read = mr;
	e->cb.mem_write = mw;
	rz_analysis_esil_parse(e, expr);
	rz_analysis_esil_free(e);
	return ec;
}

static void core_analysis_bytes_size(RzCore *core, const ut8 *buf, int len, int nops) {
	core->parser->subrel = rz_config_get_i(core->config, "asm.sub.rel");
	int ret, i, idx;
	RzAnalysisOp op = { 0 };
	ut64 addr;
	int totalsize = 0;

	for (i = idx = 0; idx < len && (!nops || (nops && i < nops)); i++, idx += ret) {
		addr = core->offset + idx;
		rz_asm_set_pc(core->rasm, addr);
		rz_analysis_op_init(&op);
		ret = rz_analysis_op(core->analysis, &op, addr, buf + idx, len - idx,
			RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_OPEX | RZ_ANALYSIS_OP_MASK_HINT);

		if (ret < 1) {
			RZ_LOG_ERROR("Invalid instruction at 0x%08" PFMT64x "...\n", core->offset + idx);
			break;
		}
		totalsize += op.size;
		rz_analysis_op_fini(&op);
	}
	rz_analysis_op_fini(&op);
	rz_cons_printf("%d\n", totalsize);
}

static void core_analysis_bytes_desc(RzCore *core, const ut8 *buf, int len, int nops) {
	core->parser->subrel = rz_config_get_i(core->config, "asm.sub.rel");
	int ret, i, idx;
	RzAsmOp asmop;
	RzAnalysisOp op = { 0 };
	ut64 addr;

	for (i = idx = 0; idx < len && (!nops || (nops && i < nops)); i++, idx += ret) {
		addr = core->offset + idx;
		rz_asm_set_pc(core->rasm, addr);
		rz_analysis_op_init(&op);
		ret = rz_analysis_op(core->analysis, &op, addr, buf + idx, len - idx,
			RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_OPEX | RZ_ANALYSIS_OP_MASK_HINT);
		(void)rz_asm_disassemble(core->rasm, &asmop, buf + idx, len - idx);

		if (ret < 1) {
			RZ_LOG_ERROR("Invalid instruction at 0x%08" PFMT64x "...\n", core->offset + idx);
			break;
		}

		char *opname = rz_str_dup(rz_asm_op_get_asm(&asmop));
		if (opname) {
			rz_str_split(opname, ' ');
			char *d = rz_asm_describe(core->rasm, opname);
			if (d && *d) {
				rz_cons_printf("%s: %s\n", opname, d);
				free(d);
			} else {
				RZ_LOG_ERROR("mnemonic %s has no description\n", opname);
			}
			free(opname);
		}
		rz_analysis_op_fini(&op);
	}
	rz_analysis_op_fini(&op);
}

static void core_analysis_bytes_esil(RzCore *core, const ut8 *buf, int len, int nops) {
	bool use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	core->parser->subrel = rz_config_get_i(core->config, "asm.sub.rel");
	int ret, i, idx;
	const char *color = "";
	const char *esilstr;
	RzAnalysisEsil *esil = NULL;
	RzAnalysisOp op = { 0 };
	ut64 addr;

	if (use_color) {
		color = core->cons->context->pal.label;
	}
	for (i = idx = 0; idx < len && (!nops || (nops && i < nops)); i++, idx += ret) {
		addr = core->offset + idx;
		rz_asm_set_pc(core->rasm, addr);
		rz_analysis_op_init(&op);
		ret = rz_analysis_op(core->analysis, &op, addr, buf + idx, len - idx,
			RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_OPEX | RZ_ANALYSIS_OP_MASK_HINT);
		esilstr = RZ_STRBUF_SAFEGET(&op.esil);

		if (ret < 1) {
			RZ_LOG_ERROR("Invalid instruction at 0x%08" PFMT64x "...\n", core->offset + idx);
			break;
		}

		if (RZ_STR_ISNOTEMPTY(esilstr)) {
			if (use_color) {
				rz_cons_printf("%s0x%" PFMT64x Color_RESET " %s\n", color, core->offset + idx, esilstr);
			} else {
				rz_cons_printf("0x%" PFMT64x " %s\n", core->offset + idx, esilstr);
			}
		}
		rz_analysis_op_fini(&op);
	}
	rz_analysis_op_fini(&op);
	rz_analysis_esil_free(esil);
}

static void core_analysis_bytes_json(RzCore *core, const ut8 *buf, int len, int nops, PJ *pj) {
	RzIterator *iter = rz_core_analysis_bytes(core, core->offset, buf, len, nops);
	if (!iter) {
		return;
	}

	RzAnalysisBytes *ab;

	pj_a(pj);
	rz_iterator_foreach(iter, ab) {
		if (!ab || !ab->op) {
			break;
		}
		RzAnalysisOp *op = ab->op;
		const char *esilstr = RZ_STRBUF_SAFEGET(&op->esil);
		const char *opexstr = RZ_STRBUF_SAFEGET(&op->opex);
		RzAnalysisHint *hint = ab->hint;

		pj_o(pj);
		PJ_KS(pj, "opcode", ab->opcode);
		PJ_KS(pj, "disasm", ab->disasm);
		PJ_KS(pj, "pseudo", ab->pseudo);
		PJ_KS(pj, "description", ab->description);
		PJ_KS(pj, "mnemonic", op->mnemonic);
		PJ_KS(pj, "mask", ab->mask);

		if (hint) {
			PJ_KS(pj, "ophint", hint->opcode);
		}
		PJ_KN(pj, "jump", op->jump);
		PJ_KN(pj, "fail", op->fail);
		PJ_KS(pj, "esil", (hint && hint->esil) ? hint->esil : esilstr);

		if (op->il_op) {
			pj_k(pj, "rzil");
			rz_il_op_effect_json(op->il_op, pj);
		}
		pj_kb(pj, "sign", op->sign);
		pj_kn(pj, "prefix", op->prefix);
		pj_ki(pj, "id", op->id);
		if (RZ_STR_ISNOTEMPTY(opexstr)) {
			pj_k(pj, "opex");
			pj_j(pj, opexstr);
		}
		PJ_KN(pj, "addr", op->addr);
		PJ_KS(pj, "bytes", ab->bytes);
		PJ_KN(pj, "val", op->val);
		PJ_KN(pj, "disp", op->disp);
		PJ_KN(pj, "ptr", op->ptr);
		pj_ki(pj, "size", op->size);
		PJ_KS(pj, "type", rz_analysis_optype_to_string((int)op->type));
		PJ_KS(pj, "datatype", rz_analysis_datatype_to_string(op->datatype));
		if (esilstr) {
			pj_ki(pj, "esilcost", esil_cost(core, op->addr, esilstr));
		}
		PJ_KS(pj, "reg", op->reg);
		PJ_KS(pj, "ireg", op->ireg);
		pj_ki(pj, "scale", op->scale);
		if (op->refptr != -1) {
			pj_ki(pj, "refptr", op->refptr);
		}
		pj_ki(pj, "cycles", op->cycles);
		pj_ki(pj, "failcycles", op->failcycles);
		pj_ki(pj, "delay", op->delay);
		const char *p1 = rz_analysis_stackop_tostring(op->stackop);
		if (strcmp(p1, "null") != 0) {
			PJ_KS(pj, "stack", p1);
		}
		pj_kn(pj, "stackptr", op->stackptr);
		PJ_KS(pj, "cond", (op->type & RZ_ANALYSIS_OP_TYPE_COND) ? rz_type_cond_tostring(op->cond) : NULL);
		PJ_KS(pj, "family", rz_analysis_op_family_to_string(op->family));
		pj_end(pj);
	}

	pj_end(pj);
	rz_iterator_free(iter);
}

#define PRINTF_LN(k, fmt, arg) \
	{ \
		if (use_color) \
			rz_cons_printf("%s%s: " Color_RESET, color, k); \
		else \
			rz_cons_printf("%s: ", k); \
		if (fmt) \
			rz_cons_printf(fmt, arg); \
	}

#define PRINTF_LN_NOT(k, fmt, arg, notv) \
	if ((arg) != (notv)) { \
		PRINTF_LN(k, fmt, arg) \
	}

#define PRINTF_LN_STR(k, arg) \
	{ \
		const char *value = (arg); \
		if (RZ_STR_ISNOTEMPTY(value)) { \
			if (use_color) \
				rz_cons_printf("%s%s: %s\n" Color_RESET, color, k, value); \
			else \
				rz_cons_printf("%s: %s\n", k, value); \
		} \
	}

static void core_analysis_bytes_standard(RzCore *core, const ut8 *buf, int len, int nops) {
	RzIterator *iter = rz_core_analysis_bytes(core, core->offset, buf, len, nops);
	if (!iter) {
		return;
	}

	bool use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	const char *color = use_color ? core->cons->context->pal.label : "";

	RzAnalysisBytes *ab;
	rz_iterator_foreach(iter, ab) {
		if (!ab->op) {
			break;
		}
		RzAnalysisOp *op = ab->op;
		const char *esilstr = RZ_STRBUF_SAFEGET(&op->esil);
		RzAnalysisHint *hint = ab->hint;

		PRINTF_LN("address", "0x%" PFMT64x "\n", op->addr);
		PRINTF_LN("opcode", "%s\n", ab->opcode);
		if (esilstr) {
			PRINTF_LN("esilcost", "%d\n", esil_cost(core, op->addr, esilstr));
		}
		PRINTF_LN("disasm", "%s\n", ab->disasm);
		PRINTF_LN_STR("pseudo", ab->pseudo);
		PRINTF_LN("mnemonic", "%s\n", op->mnemonic);
		PRINTF_LN_STR("description", ab->description);
		PRINTF_LN("mask", "%s\n", ab->mask);
		PRINTF_LN_STR("ophint", hint ? hint->opcode : NULL);
		PRINTF_LN("prefix", "%u\n", op->prefix);
		PRINTF_LN("id", "%d\n", op->id);
		PRINTF_LN_STR("bytes", ab->bytes);
		PRINTF_LN_NOT("val", "0x%08" PFMT64x "\n", op->val, UT64_MAX);
		PRINTF_LN_NOT("ptr", "0x%08" PFMT64x "\n", op->ptr, UT64_MAX);
		PRINTF_LN_NOT("disp", "0x%08" PFMT64x "\n", op->disp, UT64_MAX);
		PRINTF_LN_NOT("refptr", "%d\n", op->refptr, -1);
		PRINTF_LN("size", "%d\n", op->size);
		PRINTF_LN_STR("sign", rz_str_bool(op->sign));
		PRINTF_LN_STR("type", rz_analysis_optype_to_string(op->type));
		PRINTF_LN_STR("datatype", rz_analysis_datatype_to_string(op->datatype));
		PRINTF_LN("cycles", "%d\n", op->cycles);
		PRINTF_LN_NOT("failcycles", "%d\n", op->failcycles, 0);
		PRINTF_LN_NOT("type2", "0x%x\n", op->type2, 0);
		PRINTF_LN_STR("reg", op->reg);
		PRINTF_LN_STR("ireg", op->ireg);
		PRINTF_LN_NOT("scale", "%d\n", op->scale, 0);
		PRINTF_LN_STR("esil", hint && hint->esil ? hint->esil : esilstr);
		if (op->il_op) {
			RzStrBuf *sbil = rz_strbuf_new("");
			rz_il_op_effect_stringify(op->il_op, sbil, false);
			PRINTF_LN_STR("rzil", rz_strbuf_get(sbil));
			rz_strbuf_free(sbil);
		}
		PRINTF_LN_NOT("jump", "0x%08" PFMT64x "\n", op->jump, UT64_MAX);
		if (op->direction != 0) {
			const char *dir = op->direction == 1 ? "read"
				: op->direction == 2         ? "write"
				: op->direction == 4         ? "exec"
				: op->direction == 8         ? "ref"
							     : "none";
			PRINTF_LN("direction", "%s\n", dir);
		}
		PRINTF_LN_NOT("fail", "0x%08" PFMT64x "\n", op->fail, UT64_MAX);
		PRINTF_LN_NOT("delay", "%d\n", op->delay, 0);
		{
			const char *arg = (op->type & RZ_ANALYSIS_OP_TYPE_COND) ? rz_type_cond_tostring(op->cond) : NULL;
			PRINTF_LN_STR("cond", arg);
		}
		PRINTF_LN("family", "%s\n", rz_analysis_op_family_to_string(op->family));
		PRINTF_LN_STR("stackop", op->stackop != RZ_ANALYSIS_STACK_NULL ? rz_analysis_stackop_tostring(op->stackop) : NULL);
		PRINTF_LN_NOT("stackptr", "%" PFMT64u "\n", op->stackptr, 0);
	}
	rz_iterator_free(iter);
}

#undef PJ_KS
#undef PJ_KN
#undef PRINTF_LN
#undef PRINTF_LN_NOT
#undef PRINTF_LN_STR

static char *fcnjoin(RzList /*<RzAnalysisFunction *>*/ *list) {
	RzAnalysisFunction *n;
	RzListIter *iter;
	RzStrBuf buf;
	rz_strbuf_init(&buf);
	rz_list_foreach (list, iter, n) {
		rz_strbuf_appendf(&buf, " 0x%08" PFMT64x, n->addr);
	}
	char *s = rz_str_dup(rz_strbuf_get(&buf));
	rz_strbuf_fini(&buf);
	return s;
}

static char *ut64join(RzList /*<ut64 *>*/ *list) {
	ut64 *n;
	RzListIter *iter;
	RzStrBuf buf;
	rz_strbuf_init(&buf);
	rz_list_foreach (list, iter, n) {
		rz_strbuf_appendf(&buf, " 0x%08" PFMT64x, *n);
	}
	char *s = rz_str_dup(rz_strbuf_get(&buf));
	rz_strbuf_fini(&buf);
	return s;
}

static void cmd_address_info(RzCore *core, const ut64 addr, RzCmdStateOutput *state) {
	ut64 type;
	PJ *pj;
	type = rz_core_analysis_address(core, addr);
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj = state->d.pj;
		pj_o(pj);
		if (type & RZ_ANALYSIS_ADDR_TYPE_PROGRAM)
			pj_ks(pj, "program", "true");
		if (type & RZ_ANALYSIS_ADDR_TYPE_LIBRARY)
			pj_ks(pj, "library", "true");
		if (type & RZ_ANALYSIS_ADDR_TYPE_EXEC)
			pj_ks(pj, "exec", "true");
		if (type & RZ_ANALYSIS_ADDR_TYPE_READ)
			pj_ks(pj, "read", "true");
		if (type & RZ_ANALYSIS_ADDR_TYPE_WRITE)
			pj_ks(pj, "write", "true");
		if (type & RZ_ANALYSIS_ADDR_TYPE_FLAG)
			pj_ks(pj, "flag", "true");
		if (type & RZ_ANALYSIS_ADDR_TYPE_FUNC)
			pj_ks(pj, "func", "true");
		if (type & RZ_ANALYSIS_ADDR_TYPE_STACK)
			pj_ks(pj, "stack", "true");
		if (type & RZ_ANALYSIS_ADDR_TYPE_HEAP)
			pj_ks(pj, "heap", "true");
		if (type & RZ_ANALYSIS_ADDR_TYPE_REG)
			pj_ks(pj, "reg", "true");
		if (type & RZ_ANALYSIS_ADDR_TYPE_ASCII)
			pj_ks(pj, "ascii", "true");
		if (type & RZ_ANALYSIS_ADDR_TYPE_SEQUENCE)
			pj_ks(pj, "sequence", "true");
		pj_end(pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		if (type & RZ_ANALYSIS_ADDR_TYPE_PROGRAM)
			rz_cons_printf("program\n");
		if (type & RZ_ANALYSIS_ADDR_TYPE_LIBRARY)
			rz_cons_printf("library\n");
		if (type & RZ_ANALYSIS_ADDR_TYPE_EXEC)
			rz_cons_printf("exec\n");
		if (type & RZ_ANALYSIS_ADDR_TYPE_READ)
			rz_cons_printf("read\n");
		if (type & RZ_ANALYSIS_ADDR_TYPE_WRITE)
			rz_cons_printf("write\n");
		if (type & RZ_ANALYSIS_ADDR_TYPE_FLAG)
			rz_cons_printf("flag\n");
		if (type & RZ_ANALYSIS_ADDR_TYPE_FUNC)
			rz_cons_printf("func\n");
		if (type & RZ_ANALYSIS_ADDR_TYPE_STACK)
			rz_cons_printf("stack\n");
		if (type & RZ_ANALYSIS_ADDR_TYPE_HEAP)
			rz_cons_printf("heap\n");
		if (type & RZ_ANALYSIS_ADDR_TYPE_REG)
			rz_cons_printf("reg\n");
		if (type & RZ_ANALYSIS_ADDR_TYPE_ASCII)
			rz_cons_printf("ascii\n");
		if (type & RZ_ANALYSIS_ADDR_TYPE_SEQUENCE)
			rz_cons_printf("sequence\n");
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

typedef struct {
	RzList /*<char *>*/ *regs;
	RzList /*<char *>*/ *regread;
	RzList /*<char *>*/ *regwrite;
	RzList /*<char *>*/ *regvalues;
	RzList /*<char *>*/ *inputregs;
} AeaStats;

static void aea_stats_init(AeaStats *stats) {
	stats->regs = rz_list_newf(free);
	stats->regread = rz_list_newf(free);
	stats->regwrite = rz_list_newf(free);
	stats->regvalues = rz_list_newf(free);
	stats->inputregs = rz_list_newf(free);
}

static void aea_stats_fini(AeaStats *stats) {
	RZ_FREE(stats->regs);
	RZ_FREE(stats->regread);
	RZ_FREE(stats->regwrite);
	RZ_FREE(stats->inputregs);
}

static bool contains(RzList /*<char *>*/ *list, const char *name) {
	RzListIter *iter;
	const char *n;
	rz_list_foreach (list, iter, n) {
		if (!strcmp(name, n))
			return true;
	}
	return false;
}

static int mymemwrite(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	RzListIter *iter;
	RzAnalysisEsilMemoryRegion *n;
	RzList *memwrites = esil->analysis->esilinterstate->memwrites;
	rz_list_foreach (memwrites, iter, n) {
		if (addr == n->addr) {
			return len;
		}
	}
	if (!rz_io_is_valid_offset(esil->analysis->iob.io, addr, 0)) {
		return false;
	}
	n = RZ_NEW(RzAnalysisEsilMemoryRegion);
	if (n) {
		n->addr = addr;
		n->size = len;
		rz_list_push(memwrites, n);
	}
	return len;
}

static int mymemread(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	RzListIter *iter;
	RzAnalysisEsilMemoryRegion *n;
	RzList *memreads = esil->analysis->esilinterstate->memreads;
	rz_list_foreach (memreads, iter, n) {
		if (addr == n->addr) {
			return len;
		}
	}
	if (!rz_io_is_valid_offset(esil->analysis->iob.io, addr, 0)) {
		return false;
	}
	n = RZ_NEW(RzAnalysisEsilMemoryRegion);
	if (n) {
		n->addr = addr;
		n->size = len;
		rz_list_push(memreads, n);
	}
	return len;
}

static int myregwrite(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	AeaStats *stats = esil->user;
	if (!IS_DIGIT(*name)) {
		if (!contains(stats->regs, name)) {
			rz_list_push(stats->regs, rz_str_dup(name));
		}
		if (!contains(stats->regwrite, name)) {
			rz_list_push(stats->regwrite, rz_str_dup(name));
		}
		char *v = rz_str_newf("%" PFMT64d, *val);
		if (!contains(stats->regvalues, v)) {
			rz_list_push(stats->regvalues, rz_str_dup(v));
		}
		free(v);
	}
	return 0;
}

static int myregread(RzAnalysisEsil *esil, const char *name, ut64 *val, int *len) {
	AeaStats *stats = esil->user;
	if (!IS_DIGIT(*name)) {
		if (!contains(stats->inputregs, name)) {
			if (!contains(stats->regwrite, name)) {
				rz_list_push(stats->inputregs, rz_str_dup(name));
			}
		}
		if (!contains(stats->regs, name)) {
			rz_list_push(stats->regs, rz_str_dup(name));
		}
		if (!contains(stats->regread, name)) {
			rz_list_push(stats->regread, rz_str_dup(name));
		}
	}
	return 0;
}

static void showregs(RzList /*<char *>*/ *list) {
	if (!rz_list_empty(list)) {
		char *reg;
		RzListIter *iter;
		rz_list_foreach (list, iter, reg) {
			rz_cons_print(reg);
			if (rz_list_iter_has_next(iter)) {
				rz_cons_printf(" ");
			}
		}
	}
	rz_cons_newline();
}

static void showmem(RzList /*<RzAnalysisEsilMemoryRegion *>*/ *list) {
	if (!rz_list_empty(list)) {
		RzAnalysisEsilMemoryRegion *item;
		RzListIter *iter;
		rz_list_foreach (list, iter, item) {
			rz_cons_printf(" 0x%08" PFMT64x, item->addr);
		}
	}
	rz_cons_newline();
}

static void showregs_json(RzList /*<char *>*/ *list, PJ *pj) {
	pj_a(pj);
	if (!rz_list_empty(list)) {
		char *reg;
		RzListIter *iter;

		rz_list_foreach (list, iter, reg) {
			pj_s(pj, reg);
		}
	}
	pj_end(pj);
}

static void showmem_json(RzList /*<RzAnalysisEsilMemoryRegion *>*/ *list, PJ *pj) {
	pj_a(pj);
	if (!rz_list_empty(list)) {
		RzListIter *iter;
		RzAnalysisEsilMemoryRegion *item;
		rz_list_foreach (list, iter, item) {
			pj_n(pj, item->addr);
		}
	}

	pj_end(pj);
}

static bool cmd_aea(RzCore *core, int mode, ut64 addr, int length) {
	RzAnalysisEsil *esil;
	int ptr, ops, ops_end = 0, len, buf_sz, maxopsize;
	ut64 addr_end;
	AeaStats stats;
	const char *esilstr;
	RzAnalysisOp aop = RZ_EMPTY;
	ut8 *buf;
	RzList *regnow;
	PJ *pj = NULL;
	if (!core) {
		return false;
	}
	maxopsize = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
	if (maxopsize < 1) {
		maxopsize = 16;
	}
	if (mode & 1) {
		// number of bytes / length
		buf_sz = length;
	} else {
		// number of instructions / opcodes
		ops_end = length;
		if (ops_end < 1) {
			ops_end = 1;
		}
		buf_sz = ops_end * maxopsize;
	}
	if (buf_sz < 1) {
		buf_sz = maxopsize;
	}
	addr_end = addr + buf_sz;
	buf = malloc(buf_sz);
	if (!buf) {
		return false;
	}
	(void)rz_io_read_at(core->io, addr, (ut8 *)buf, buf_sz);
	aea_stats_init(&stats);

	// esil_init (core);
	// esil = core->analysis->esil;
	rz_reg_arena_push(core->analysis->reg);
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	bool iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int romem = rz_config_get_i(core->config, "esil.romem");
	int stats1 = rz_config_get_i(core->config, "esil.stats");
	int noNULL = rz_config_get_i(core->config, "esil.noNULL");
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");
	esil = rz_analysis_esil_new(stacksize, iotrap, addrsize);
	rz_analysis_esil_setup(esil, core->analysis, romem, stats1, noNULL); // setup io
#define hasNext(x) (x & 1) ? (addr < addr_end) : (ops < ops_end)

	ESILISTATE->memreads = rz_list_new();
	ESILISTATE->memwrites = rz_list_new();
	esil->user = &stats;
	esil->cb.hook_reg_write = myregwrite;
	esil->cb.hook_reg_read = myregread;
	esil->cb.hook_mem_write = mymemwrite;
	esil->cb.hook_mem_read = mymemread;
	esil->nowrite = true;
	for (ops = ptr = 0; ptr < buf_sz && hasNext(mode); ops++, ptr += len) {
		rz_analysis_op_init(&aop);
		len = rz_analysis_op(core->analysis, &aop, addr + ptr, buf + ptr, buf_sz - ptr, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_HINT);
		if (len < 1) {
			RZ_LOG_ERROR("core: Invalid 0x%08" PFMT64x " instruction %02x %02x\n",
				addr + ptr, buf[ptr], buf[ptr + 1]);
			break;
		}
		esilstr = RZ_STRBUF_SAFEGET(&aop.esil);
		if (RZ_STR_ISNOTEMPTY(esilstr)) {
			rz_analysis_esil_parse(esil, esilstr);
			rz_analysis_esil_stack_free(esil);
		}
		rz_analysis_op_fini(&aop);
	}
	esil->nowrite = false;
	esil->cb.hook_reg_write = NULL;
	esil->cb.hook_reg_read = NULL;
	// esil_fini (core);
	rz_analysis_esil_free(esil);
	rz_reg_arena_pop(core->analysis->reg);
	regnow = rz_list_newf(free);
	{
		RzListIter *iter;
		char *reg;
		rz_list_foreach (stats.regs, iter, reg) {
			if (!contains(stats.regwrite, reg)) {
				rz_list_push(regnow, rz_str_dup(reg));
			}
		}
	}
	if ((mode >> 5) & 1) {
		RzListIter *iter;
		RzAnalysisEsilMemoryRegion *n;
		int c = 0;
		rz_cons_printf("f-mem.*\n");
		rz_list_foreach (ESILISTATE->memreads, iter, n) {
			rz_cons_printf("f mem.read.%d 0x%08zu @ 0x%08" PFMT64x "\n", c++, n->size, n->addr);
		}
		c = 0;
		rz_list_foreach (ESILISTATE->memwrites, iter, n) {
			rz_cons_printf("f mem.write.%d 0x%08zu @ 0x%08" PFMT64x "\n", c++, n->size, n->addr);
		}
	}

	/* show registers used */
	if ((mode >> 1) & 1) {
		showregs(stats.regread);
	} else if ((mode >> 2) & 1) {
		showregs(stats.regwrite);
	} else if ((mode >> 3) & 1) {
		showregs(regnow);
	} else if ((mode >> 4) & 1) {
		pj = pj_new();
		if (!pj) {
			return false;
		}
		pj_o(pj);
		pj_k(pj, "A");
		showregs_json(stats.regs, pj);
		pj_k(pj, "I");
		showregs_json(stats.inputregs, pj);
		pj_k(pj, "R");
		showregs_json(stats.regread, pj);
		pj_k(pj, "W");
		showregs_json(stats.regwrite, pj);
		if (!rz_list_empty(stats.regvalues)) {
			pj_k(pj, "V");
			showregs_json(stats.regvalues, pj);
		}
		if (!rz_list_empty(regnow)) {
			pj_k(pj, "N");
			showregs_json(regnow, pj);
		}
		if (!rz_list_empty(ESILISTATE->memreads)) {
			pj_k(pj, "@R");
			showmem_json(ESILISTATE->memreads, pj);
		}
		if (!rz_list_empty(ESILISTATE->memwrites)) {
			pj_k(pj, "@W");
			showmem_json(ESILISTATE->memwrites, pj);
		}

		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	} else if ((mode >> 5) & 1) {
		// nothing
	} else {
		if (!rz_list_empty(stats.inputregs)) {
			rz_cons_printf(" I: ");
			showregs(stats.inputregs);
		}
		if (!rz_list_empty(stats.regs)) {
			rz_cons_printf(" A: ");
			showregs(stats.regs);
		}
		if (!rz_list_empty(stats.regread)) {
			rz_cons_printf(" R: ");
			showregs(stats.regread);
		}
		if (!rz_list_empty(stats.regwrite)) {
			rz_cons_printf(" W: ");
			showregs(stats.regwrite);
		}
		if (!rz_list_empty(stats.regvalues)) {
			rz_cons_printf(" V: ");
			showregs(stats.regvalues);
		}
		if (!rz_list_empty(regnow)) {
			rz_cons_printf(" N: ");
			showregs(regnow);
		}
		if (!rz_list_empty(ESILISTATE->memreads)) {
			rz_cons_printf("@R:");
			showmem(ESILISTATE->memreads);
		}
		if (!rz_list_empty(ESILISTATE->memwrites)) {
			rz_cons_printf("@W:");
			showmem(ESILISTATE->memwrites);
		}
	}

	rz_list_free(ESILISTATE->memreads);
	rz_list_free(ESILISTATE->memwrites);
	ESILISTATE->memreads = NULL;
	ESILISTATE->memwrites = NULL;
	aea_stats_fini(&stats);
	free(buf);
	RZ_FREE(regnow);
	return true;
}

// aeC
RZ_IPI RzCmdStatus rz_analysis_appcall_handler(RzCore *core, int argc, const char **argv) {
	for (int i = 1; i < argc; ++i) {
		const char *alias = rz_str_newf("A%d", i - 1);
		rz_reg_setv(core->analysis->reg, alias, rz_num_math(core->num, argv[i]));
	}

	ut64 sp = rz_reg_getv(core->analysis->reg, "SP");
	rz_reg_setv(core->analysis->reg, "SP", 0);

	rz_reg_setv(core->analysis->reg, "PC", core->offset);
	rz_core_esil_step(core, 0, NULL, NULL, false);
	rz_core_reg_update_flags(core);

	rz_reg_setv(core->analysis->reg, "SP", sp);
	return RZ_CMD_STATUS_OK;
}

// aec
RZ_IPI RzCmdStatus rz_analysis_continue_until_except_handler(RzCore *core, int argc, const char **argv) {
	rz_core_esil_step(core, UT64_MAX, "0", NULL, false);
	rz_core_reg_update_flags(core);
	return RZ_CMD_STATUS_OK;
}

// aecb
RZ_IPI RzCmdStatus rz_analysis_continue_until_breakpoint_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_core_esil_continue_back(core)) {
		RZ_LOG_ERROR("cannot continue back\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_reg_update_flags(core);
	return RZ_CMD_STATUS_OK;
}

// aecs
RZ_IPI RzCmdStatus rz_analysis_continue_until_syscall_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_analysis_continue_until_syscall(core));
}

// aecc
RZ_IPI RzCmdStatus rz_analysis_continue_until_call_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_analysis_continue_until_call(core));
}

// aecu
RZ_IPI RzCmdStatus rz_analysis_continue_until_addr_handler(RzCore *core, int argc, const char **argv) {
	rz_core_esil_step(core, rz_num_math(core->num, argv[1]), NULL, NULL, false);
	rz_core_reg_update_flags(core);
	return RZ_CMD_STATUS_OK;
}

// aecue
RZ_IPI RzCmdStatus rz_analysis_continue_until_esil_handler(RzCore *core, int argc, const char **argv) {
	rz_core_esil_step(core, UT64_MAX, argv[1], NULL, false);
	rz_core_reg_update_flags(core);
	return RZ_CMD_STATUS_OK;
}

// aei
RZ_IPI RzCmdStatus rz_analysis_esil_init_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_esil_reinit(core);
	return RZ_CMD_STATUS_OK;
}

// aei-
RZ_IPI RzCmdStatus rz_analysis_esil_deinit_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_esil_deinit(core);
	return RZ_CMD_STATUS_OK;
}

// aeip
RZ_IPI RzCmdStatus rz_analysis_esil_init_p_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_set_reg(core, "PC", core->offset);
	return RZ_CMD_STATUS_OK;
}

// aeim
RZ_IPI RzCmdStatus rz_analysis_esil_init_mem_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = argc > 1 ? rz_num_math(core->num, argv[1]) : UT64_MAX;
	ut32 size = argc > 2 ? (ut32)rz_num_math(core->num, argv[2]) : UT32_MAX;
	const char *name = argc > 3 ? argv[3] : NULL;
	rz_core_analysis_esil_init_mem(core, name, addr, size);
	return RZ_CMD_STATUS_OK;
}

// aeim-
RZ_IPI RzCmdStatus rz_analysis_esil_init_mem_remove_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = argc > 1 ? rz_num_math(core->num, argv[1]) : UT64_MAX;
	ut32 size = argc > 2 ? (ut32)rz_num_math(core->num, argv[2]) : UT32_MAX;
	const char *name = argc > 3 ? argv[3] : NULL;
	rz_core_analysis_esil_init_mem_del(core, name, addr, size);
	return RZ_CMD_STATUS_OK;
}

// aeimp
RZ_IPI RzCmdStatus rz_analysis_esil_init_mem_p_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_esil_init_mem_p(core);
	return RZ_CMD_STATUS_OK;
}

// aes
RZ_IPI RzCmdStatus rz_il_step_handler(RzCore *core, int argc, const char **argv) {
	if (argc <= 1) {
		rz_core_esil_step(core, UT64_MAX, NULL, NULL, false);
		rz_core_reg_update_flags(core);
	} else if (argc == 2) {
		int n = (int)rz_num_math(core->num, argv[1]);
		rz_core_analysis_esil_emulate(core, -1, -1, n);
	}
	return RZ_CMD_STATUS_OK;
}

// aesp
RZ_IPI RzCmdStatus rz_il_step_evaluate_handler(RzCore *core, int argc, const char **argv) {
	int n = (int)rz_num_math(core->num, argv[1]);
	rz_core_analysis_esil_emulate(core, core->offset, -1, n);
	return RZ_CMD_STATUS_OK;
}

// aesb
RZ_IPI RzCmdStatus rz_il_step_back_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_core_esil_step_back(core)) {
		RZ_LOG_ERROR("cannot step back\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_reg_update_flags(core);
	return RZ_CMD_STATUS_OK;
}

// aeso
RZ_IPI RzCmdStatus rz_il_step_over_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_esil_step_over(core);
	return RZ_CMD_STATUS_OK;
}

// aesou
RZ_IPI RzCmdStatus rz_il_step_over_until_addr_handler(RzCore *core, int argc, const char **argv) {
	ut64 until_addr = rz_num_math(core->num, argv[1]);
	rz_core_analysis_esil_step_over_until(core, until_addr);
	return RZ_CMD_STATUS_OK;
}

// aess
RZ_IPI RzCmdStatus rz_il_step_skip_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_esil_step_over_until(core, UT64_MAX);
	return RZ_CMD_STATUS_OK;
}

// aessu
RZ_IPI RzCmdStatus rz_il_step_skip_until_addr_handler(RzCore *core, int argc, const char **argv) {
	ut64 until_addr = rz_num_math(core->num, argv[1]);
	rz_core_analysis_esil_step_over_until(core, until_addr);
	return RZ_CMD_STATUS_OK;
}

// aessue
RZ_IPI RzCmdStatus rz_il_step_skip_until_expr_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_esil_step_over_untilexpr(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

// aesu
RZ_IPI RzCmdStatus rz_il_step_until_addr_handler(RzCore *core, int argc, const char **argv) {
	ut64 until_addr = rz_num_math(core->num, argv[1]);
	rz_core_esil_step(core, until_addr, NULL, NULL, false);
	rz_core_reg_update_flags(core);
	return RZ_CMD_STATUS_OK;
}

// aesue
RZ_IPI RzCmdStatus rz_il_step_until_expr_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_esil_step_over_untilexpr(core, argv[1]);
	rz_core_reg_update_flags(core);
	return RZ_CMD_STATUS_OK;
}

// aesuo
RZ_IPI RzCmdStatus rz_il_step_until_opt_handler(RzCore *core, int argc, const char **argv) {
	RzList *optypes_list = rz_list_new_from_array((const void **)&argv[1], argc - 1);
	step_until_optype(core, optypes_list);
	rz_list_free(optypes_list);
	rz_core_reg_update_flags(core);
	return RZ_CMD_STATUS_OK;
}

// aets+
RZ_IPI RzCmdStatus rz_il_trace_start_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_analysis_esil_trace_start(core) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// aets-
RZ_IPI RzCmdStatus rz_il_trace_stop_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_analysis_esil_trace_stop(core) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static const char _handler_no_name[] = "<no name>";
static bool _aeli_iter(void *user, const ut64 key, const void *value) {
	const RzAnalysisEsilInterrupt *interrupt = value;
	rz_cons_printf("%3" PFMT64x ": %s\n", key, interrupt->handler->name ? interrupt->handler->name : _handler_no_name);
	return true;
}

static void rz_analysis_aefa(RzCore *core, const char *arg) {
	ut64 to = rz_num_math(core->num, arg);
	ut64 at, from = core->offset;
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, to, -1);
	if (!from || from == UT64_MAX) {
		if (fcn) {
			from = fcn->addr;
		} else {
			RZ_LOG_ERROR("core: Usage: aefa [from] # if no from address is given, uses fcn.addr\n");
			return;
		}
	}
	RZ_LOG_ERROR("core: Emulate from 0x%08" PFMT64x " to 0x%08" PFMT64x "\n", from, to);
	RZ_LOG_ERROR("core: Resolve call args for 0x%08" PFMT64x "\n", to);

	// emulate
	rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
	ut64 off = core->offset;
	for (at = from; at < to; at++) {
		rz_core_analysis_set_reg(core, "PC", at);
		rz_core_analysis_esil_step_over(core);
		rz_core_seek(core, at, true);
		int delta = rz_num_get(core->num, "$l");
		if (delta < 1) {
			break;
		}
		at += delta - 1;
	}
	rz_core_seek(core, off, true);

	// the logic of identifying args by function types and
	// show json format and arg name goes into arA
	rz_core_cmd0(core, "arA");
}

static void __analysis_esil_function(RzCore *core, ut64 addr) {
	void **iter;
	RzAnalysisBlock *bb;
	if (!core->analysis->esil) {
		rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
	}
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis,
		addr, RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
	if (fcn) {
		// emulate every instruction in the function recursively across all the basic blocks
		rz_pvector_foreach (fcn->bbs, iter) {
			bb = (RzAnalysisBlock *)*iter;
			ut64 pc = bb->addr;
			ut64 end = bb->addr + bb->size;
			RzAnalysisOp op = { 0 };
			int ret, bbs = end - pc;
			if (bbs < 1 || bbs > 0xfffff || pc >= end) {
				RZ_LOG_ERROR("core: Invalid block size\n");
				continue;
			}
			// eprintf ("[*] Emulating 0x%08"PFMT64x" basic block 0x%08" PFMT64x " - 0x%08" PFMT64x "\r[", fcn->addr, pc, end);
			ut8 *buf = calloc(1, bbs + 1);
			if (!buf) {
				break;
			}
			rz_io_read_at(core->io, pc, buf, bbs);
			int left;
			bool opskip;
			while (pc < end) {
				left = RZ_MIN(end - pc, 32);
				// rz_asm_set_pc (core->rasm, pc);
				rz_analysis_op_init(&op);
				ret = rz_analysis_op(core->analysis, &op, pc, buf + pc - bb->addr, left, RZ_ANALYSIS_OP_MASK_HINT | RZ_ANALYSIS_OP_MASK_ESIL); // read overflow
				opskip = false;
				switch (op.type) {
				case RZ_ANALYSIS_OP_TYPE_CALL:
				case RZ_ANALYSIS_OP_TYPE_RET:
					opskip = true;
					break;
				}
				if (ret > 0) {
					if (opskip) {
						rz_reg_set_value_by_role(core->analysis->reg, RZ_REG_NAME_PC, pc);
						rz_analysis_esil_parse(core->analysis->esil, RZ_STRBUF_SAFEGET(&op.esil));
						rz_core_esil_dumpstack(core->analysis->esil);
						rz_analysis_esil_stack_free(core->analysis->esil);
					}
					pc += op.size;
				} else {
					pc += 4; // XXX
				}
				rz_analysis_op_fini(&op);
			}
			free(buf);
		}
	} else {
		RZ_LOG_ERROR("core: Cannot find function at 0x%08" PFMT64x "\n", addr);
	}
	rz_analysis_esil_free(core->analysis->esil);
}

static void cmd_analysis_esil(RzCore *core, const char *input) {
	RzAnalysisEsil *esil = core->analysis->esil;
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int romem = rz_config_get_i(core->config, "esil.romem");
	int stats = rz_config_get_i(core->config, "esil.stats");
	int noNULL = rz_config_get_i(core->config, "esil.noNULL");
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");

	switch (input[0]) {
	case 'p':
		switch (input[1]) {
		case 'c': // "aepc"
			if (input[2] == ' ' || input[2] == '=') {
				// seek to this address
				ut64 pc_val = rz_num_math(core->num, rz_str_trim_head_ro(input + 3));
				rz_core_analysis_set_reg(core, "PC", pc_val);
			} else {
				RZ_LOG_ERROR("core: Missing argument\n");
			}
			break;
		default:
			rz_core_cmd_help(core, help_msg_ae);
			break;
		}
		break;
	case '*': // "ae*"
		// XXX: this is wip, not working atm
		if (core->analysis->esil) {
			rz_cons_printf("trap: %d\n", core->analysis->esil->trap);
			rz_cons_printf("trap-code: %d\n", core->analysis->esil->trap_code);
		} else {
			RZ_LOG_ERROR("core: esil vm not initialized. run `aei`\n");
		}
		break;
	case ' ': // "ae "
		// rz_analysis_esil_eval (core->analysis, input+1);
		if (!esil && !(core->analysis->esil = esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
			return;
		}
		rz_analysis_esil_setup(esil, core->analysis, romem, stats, noNULL); // setup io
		rz_analysis_esil_set_pc(esil, core->offset);
		rz_analysis_esil_parse(esil, input + 1);
		rz_core_esil_dumpstack(esil);
		rz_analysis_esil_stack_free(esil);
		break;
	case 'k': // "aek"
		switch (input[1]) {
		case '\0': // "aek"
			input = "123*";
			/* fall through */
		case ' ': // "aek "
			if (esil && esil->stats) {
				char *out = sdb_querys(esil->stats, NULL, 0, input + 2);
				if (out) {
					rz_cons_println(out);
					free(out);
				}
			} else {
				RZ_LOG_ERROR("core: esil.stats is empty. Run 'aei'\n");
			}
			break;
		case '-': // "aek-"
			if (esil) {
				sdb_reset(esil->stats);
			}
			break;
		}
		break;
	case 'l': // ael commands
		switch (input[1]) {
		case 'i': // aeli interrupts
			switch (input[2]) {
			case ' ': // "aeli" with arguments
				if (!rz_analysis_esil_load_interrupts_from_lib(esil, input + 3)) {
					RZ_LOG_ERROR("core: Failed to load interrupts from '%s'.\n", input + 3);
				}
				break;
			case 0: // "aeli" with no args
				if (esil && esil->interrupts) {
					ht_up_foreach(esil->interrupts, _aeli_iter, NULL);
				}
				break;
			case 'r': // "aelir"
				if (esil && esil->interrupts) {
					ht_up_delete(esil->interrupts, rz_num_math(core->num, input + 3));
				}
				break;
			}
		}
		break;
	case 'b': // "aeb"
		rz_core_analysis_esil_emulate_bb(core);
		break;
	case 'f': // "aef"
		if (input[1] == 'a') { // "aefa"
			rz_analysis_aefa(core, rz_str_trim_head_ro(input + 2));
		} else { // This should be aefb -> because its emulating all the bbs
			__analysis_esil_function(core, core->offset);
		}
		break;
	case 'A': // "aeA"
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_aea);
		} else if (input[1] == 'r') {
			cmd_aea(core, 1 + (1 << 1), core->offset, rz_num_math(core->num, input + 2));
		} else if (input[1] == 'w') {
			cmd_aea(core, 1 + (1 << 2), core->offset, rz_num_math(core->num, input + 2));
		} else if (input[1] == 'n') {
			cmd_aea(core, 1 + (1 << 3), core->offset, rz_num_math(core->num, input + 2));
		} else if (input[1] == 'j') {
			cmd_aea(core, 1 + (1 << 4), core->offset, rz_num_math(core->num, input + 2));
		} else if (input[1] == '*') {
			cmd_aea(core, 1 + (1 << 5), core->offset, rz_num_math(core->num, input + 2));
		} else if (input[1] == 'f') {
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, -1);
			if (fcn) {
				cmd_aea(core, 1, rz_analysis_function_min_addr(fcn), rz_analysis_function_linear_size(fcn));
			}
		} else {
			cmd_aea(core, 1, core->offset, (int)rz_num_math(core->num, input + 2));
		}
		break;
	case 'a': // "aea"
	{
		RzReg *reg = core->analysis->reg;
		ut64 pc = rz_reg_getv(reg, "PC");
		RzAnalysisOp *op = rz_core_analysis_op(core, pc, 0);
		if (!op) {
			break;
		}
		ut64 newPC = core->offset + op->size;
		rz_reg_setv(reg, "PC", newPC);
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_aea);
		} else if (input[1] == 'r') {
			cmd_aea(core, 1 << 1, core->offset, rz_num_math(core->num, input + 2));
		} else if (input[1] == 'w') {
			cmd_aea(core, 1 << 2, core->offset, rz_num_math(core->num, input + 2));
		} else if (input[1] == 'n') {
			cmd_aea(core, 1 << 3, core->offset, rz_num_math(core->num, input + 2));
		} else if (input[1] == 'j') {
			cmd_aea(core, 1 << 4, core->offset, rz_num_math(core->num, input + 2));
		} else if (input[1] == '*') {
			cmd_aea(core, 1 << 5, core->offset, rz_num_math(core->num, input + 2));
		} else if (input[1] == 'b') { // "aeab"
			bool json = input[2] == 'j';
			int a = json ? 3 : 2;
			ut64 addr = (input[a] == ' ') ? rz_num_math(core->num, input + a) : core->offset;
			RzList *l = rz_analysis_get_blocks_in(core->analysis, addr);
			RzAnalysisBlock *b;
			RzListIter *iter;
			rz_list_foreach (l, iter, b) {
				int mode = json ? (1 << 4) : 1;
				cmd_aea(core, mode, b->addr, b->size);
				break;
			}
		} else if (input[1] == 'f') {
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, -1);
			// "aeafj"
			if (fcn) {
				switch (input[2]) {
				case 'j': // "aeafj"
					cmd_aea(core, 1 << 4, rz_analysis_function_min_addr(fcn), rz_analysis_function_linear_size(fcn));
					break;
				default:
					cmd_aea(core, 1, rz_analysis_function_min_addr(fcn), rz_analysis_function_linear_size(fcn));
					break;
				}
				break;
			}
		} else if (input[1] == 'b') { // "aeab"
			RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
			if (bb) {
				switch (input[2]) {
				case 'j': // "aeabj"
					cmd_aea(core, 1 << 4, bb->addr, bb->size);
					break;
				default:
					cmd_aea(core, 1, bb->addr, bb->size);
					break;
				}
			}
		} else {
			const char *arg = input[1] ? input + 2 : "";
			ut64 len = rz_num_math(core->num, arg);
			cmd_aea(core, 0, core->offset, len);
		}
		rz_reg_setv(reg, "PC", pc);
	} break;
	case 'x': { // "aex"
		char *hex;
		int ret, bufsz;

		input = rz_str_trim_head_ro(input + 1);
		hex = rz_str_dup(input);
		if (!hex) {
			break;
		}

		RzAnalysisOp aop = RZ_EMPTY;
		bufsz = rz_hex_str2bin(hex, (ut8 *)hex);
		rz_analysis_op_init(&aop);
		ret = rz_analysis_op(core->analysis, &aop, core->offset,
			(const ut8 *)hex, bufsz, RZ_ANALYSIS_OP_MASK_ESIL);
		if (ret > 0) {
			const char *str = RZ_STRBUF_SAFEGET(&aop.esil);
			char *str2 = rz_str_newf(" %s", str);
			cmd_analysis_esil(core, str2);
			free(str2);
		}
		rz_analysis_op_fini(&aop);
		break;
	}
	case '?': // "ae?"
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_detail_ae);
			break;
		}
		/* fallthrough */
	default:
		rz_core_cmd_help(core, help_msg_ae);
		break;
	}
}

static bool print_cmd_analysis_after_traps_print(RZ_NONNULL RzCore *core, ut64 n_bytes) {
	int bufi = 0, minop = 1; // 4
	ut8 *buf = NULL;
	RzAnalysisOp op = { 0 };
	ut64 addr = core->offset, addr_end = 0;

	if (n_bytes > 0xffffff) {
		RZ_LOG_ERROR("number of bytes is too big (> 0xffffff)\n");
		return false;
	}

	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf) {
		return false;
	}

	if (!n_bytes) {
		// ignore search.in to avoid problems. analysis != search
		RzIOMap *map = rz_io_map_get(core->io, addr);
		if (map && (map->perm & RZ_PERM_X)) {
			// search in current section
			if (map->itv.size > bf->size) {
				addr = map->itv.addr;
				if (bf->size > map->delta) {
					n_bytes = bf->size - map->delta;
				} else {
					RZ_LOG_ERROR("aaT: binary size is smaller than map delta\n");
					return false;
				}
			} else {
				addr = map->itv.addr;
				n_bytes = map->itv.size;
			}
		} else {
			if (map && map->itv.addr != map->delta && bf->size > (core->offset - map->itv.addr + map->delta)) {
				n_bytes = bf->size - (core->offset - map->itv.addr + map->delta);
			} else {
				if (bf->size > core->offset) {
					n_bytes = bf->size - core->offset;
				} else {
					RZ_LOG_ERROR("aaT: found an invalid range where binary size > current offset\n");
					return false;
				}
			}
		}
	}

	addr_end = addr + n_bytes;
	if (!(buf = malloc(4096))) {
		RZ_LOG_ERROR("aaT: cannot allocate buffer\n");
		return false;
	}

	bufi = 0;
	int trapcount = 0;
	int nopcount = 0;
	rz_cons_break_push(NULL, NULL);
	while (addr < addr_end) {
		if (rz_cons_is_breaked()) {
			break;
		}
		// TODO: too many ioreads here
		if (bufi > 4000) {
			bufi = 0;
		}
		if (!bufi) {
			rz_io_read_at(core->io, addr, buf, 4096);
		}
		rz_analysis_op_init(&op);
		if (rz_analysis_op(core->analysis, &op, addr, buf + bufi, 4096 - bufi, RZ_ANALYSIS_OP_MASK_BASIC) > 0) {
			if (op.size < 1) {
				// XXX must be +4 on arm/mips/.. like we do in disasm.c
				op.size = minop;
			}
			if (op.type == RZ_ANALYSIS_OP_TYPE_TRAP) {
				trapcount++;
			} else if (op.type == RZ_ANALYSIS_OP_TYPE_NOP) {
				nopcount++;
			} else {
				if (nopcount > 1) {
					rz_cons_printf("af @ 0x%08" PFMT64x "\n", addr);
					nopcount = 0;
				}
				if (trapcount > 0) {
					rz_cons_printf("af @ 0x%08" PFMT64x "\n", addr);
					trapcount = 0;
				}
			}
		} else {
			op.size = minop;
		}
		addr += (op.size > 0) ? op.size : 1;
		bufi += (op.size > 0) ? op.size : 1;
		rz_analysis_op_fini(&op);
	}
	rz_cons_break_pop();
	free(buf);
	return true;
}

RZ_IPI RzCmdStatus rz_analysis_syscall_show_handler(RzCore *core, int argc, const char **argv) {
	st64 n = argc > 1 ? rz_num_math(core->num, argv[1]) : -1;
	char *sysc = rz_core_syscall_as_string(core, n, core->offset);
	if (!sysc) {
		RZ_LOG_ERROR("Cannot resolve syscall: %" PFMT64d "\n", n);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(sysc);
	free(sysc);
	return RZ_CMD_STATUS_OK;
}

#define SYSCALL_HEX_LIMIT 1000

RZ_IPI RzCmdStatus rz_analysis_syscall_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzListIter *iter;
	RzSyscallItem *si;
	RzList *list = rz_syscall_list(core->analysis->syscall);
	rz_cmd_state_output_array_start(state);
	rz_list_foreach (list, iter, si) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD: {
			if (si->num > SYSCALL_HEX_LIMIT) {
				rz_cons_printf("%s = 0x%02x.%x\n", si->name, si->swi, si->num);
			} else {
				rz_cons_printf("%s = 0x%02x.%d\n", si->name, si->swi, si->num);
			}
			break;
		}
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_ks(state->d.pj, "name", si->name);
			pj_ki(state->d.pj, "swi", si->swi);
			pj_ki(state->d.pj, "num", si->num);
			pj_end(state->d.pj);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_syscall_name_handler(RzCore *core, int argc, const char **argv) {
	int num = rz_syscall_get_num(core->analysis->syscall, argv[1]);
	if (num < 1) {
		RZ_LOG_ERROR("Cannot resolve syscall: %s\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	if (num > SYSCALL_HEX_LIMIT) {
		rz_cons_printf("%x\n", num);
	} else {
		rz_cons_printf("%d\n", num);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_syscall_number_handler(RzCore *core, int argc, const char **argv) {
	st64 num = rz_num_math(NULL, argv[1]);
	if (num < 1) {
		RZ_LOG_ERROR("Cannot resolve syscall: %s\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	RzSyscallItem *si = rz_syscall_get(core->analysis->syscall, num, -1);
	if (!si) {
		RZ_LOG_ERROR("Cannot resolve syscall: %" PFMT64d "\n", num);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(si->name);
	return RZ_CMD_STATUS_OK;
}

static void syscall_dump(RzSyscallItem *si, bool is_c) {
	if (is_c) {
		if (si->num > SYSCALL_HEX_LIMIT) {
			rz_cons_printf("#define SYS_%s %x\n", si->name, si->num);
		} else {
			rz_cons_printf("#define SYS_%s %d\n", si->name, si->num);
		}
	} else {
		if (si->num > SYSCALL_HEX_LIMIT) {
			rz_cons_printf(".equ SYS_%s %x\n", si->name, si->num);
		} else {
			rz_cons_printf(".equ SYS_%s %d\n", si->name, si->num);
		}
	}
}

static RzCmdStatus syscalls_dump(RzCore *core, int argc, const char **argv, bool is_c) {
	if (argc > 1) {
		st64 n = rz_num_math(core->num, argv[1]);
		if (n < 1) {
			n = rz_syscall_get_num(core->analysis->syscall, argv[1]);
			if (n == -1) {
				RZ_LOG_ERROR("Cannot resolve syscall: %s\n", argv[1]);
				return RZ_CMD_STATUS_ERROR;
			}
			if (n > SYSCALL_HEX_LIMIT) {
				rz_cons_printf(".equ SYS_%s %" PFMT64x "\n", argv[1], n);
			} else {
				rz_cons_printf(".equ SYS_%s %" PFMT64d "\n", argv[1], n);
			}
			return RZ_CMD_STATUS_OK;
		}
		RzSyscallItem *si = rz_syscall_get(core->analysis->syscall, n, -1);
		if (!si) {
			RZ_LOG_ERROR("Cannot resolve syscall: %" PFMT64d "\n", n);
			return RZ_CMD_STATUS_ERROR;
		}
		// Workaround until syscalls searching code is fixed
		si->num = n;
		syscall_dump(si, is_c);
		rz_syscall_item_free(si);
	} else {
		RzListIter *iter;
		RzSyscallItem *si;
		RzList *list = rz_syscall_list(core->analysis->syscall);
		rz_list_foreach (list, iter, si) {
			syscall_dump(si, is_c);
		}
		rz_list_free(list);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_syscall_dump_assembly_handler(RzCore *core, int argc, const char **argv) {
	return syscalls_dump(core, argc, argv, false);
}

RZ_IPI RzCmdStatus rz_analysis_syscall_dump_c_handler(RzCore *core, int argc, const char **argv) {
	return syscalls_dump(core, argc, argv, true);
}

static void cmd_analysis_ucall_ref(RzCore *core, ut64 addr) {
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, addr);
	if (fcn) {
		rz_cons_printf(" ; %s", fcn->name);
	} else {
		rz_cons_printf(" ; 0x%" PFMT64x, addr);
	}
}

static inline RzFlagItem *core_flag_get_at_as_ref_type(RzCore *core, RzAnalysisXRef *xrefi) {
	switch (xrefi->type) {
	case RZ_ANALYSIS_XREF_TYPE_CALL:
		return rz_flag_get_by_spaces(core->flags, xrefi->to, RZ_FLAGS_FS_SYMBOLS, RZ_FLAGS_FS_CLASSES, RZ_FLAGS_FS_FUNCTIONS, NULL);
	case RZ_ANALYSIS_XREF_TYPE_DATA:
		return rz_flag_get_by_spaces(core->flags, xrefi->to, RZ_FLAGS_FS_STRINGS, RZ_FLAGS_FS_SYMBOLS, RZ_FLAGS_FS_IMPORTS, NULL);
	case RZ_ANALYSIS_XREF_TYPE_STRING:
		return rz_flag_get_by_spaces(core->flags, xrefi->to, RZ_FLAGS_FS_STRINGS, NULL);
	default:
		return rz_flag_get_at(core->flags, xrefi->to, true);
	}
}

RZ_IPI RzCmdStatus rz_analysis_list_vtables_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	rz_analysis_list_vtables(core->analysis, mode);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_print_rtti_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	rz_analysis_rtti_print_at_vtable(core->analysis, core->offset, mode);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_print_rtti_all_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	rz_analysis_rtti_print_all(core->analysis, mode);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_recover_all_classes_from_bin_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_class_recover_from_rzbin(core->analysis);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_recover_rtti_all_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_rtti_recover_all(core->analysis);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_rtti_demangle_class_name_handler(RzCore *core, int argc, const char **argv) {
	if (argc == 2) {
		char *classname = (char *)argv[1];
		char *demangled = rz_analysis_rtti_demangle_class_name(core->analysis, classname);
		if (demangled) {
			rz_cons_println(demangled);
			free(demangled);
		}
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_analysis_print_global_variable_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (!rz_analysis_var_global_list_show(core->analysis, state, argv[1])) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_global_variable_add_handler(RzCore *core, int argc, const char **argv) {
	const char *var_name = argv[1];
	const char *type = argv[2];
	ut64 addr = core->offset;

	char *errmsg = NULL;
	RzType *typ = rz_type_parse_string_single(core->analysis->typedb->parser, type, &errmsg);
	if (errmsg) {
		RZ_LOG_ERROR("%s : Error parsing type: \"%s\" message:\n%s\n", __FUNCTION__, type, errmsg);
		free(errmsg);
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_new(var_name, addr);
	if (!glob) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_analysis_var_global_set_type(glob, typ);

	if (!rz_analysis_var_global_add(core->analysis, glob)) {
		rz_analysis_var_global_free(glob);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_global_variable_delete_byaddr_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = rz_num_math(core->num, argv[1]);

	if (!rz_analysis_var_global_delete_byaddr_in(core->analysis, addr)) {
		return RZ_CMD_STATUS_ERROR;
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_global_variable_delete_byname_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_analysis_var_global_delete_byname(core->analysis, argv[1])) {
		return RZ_CMD_STATUS_ERROR;
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_global_variable_rename_handler(RzCore *core, int argc, const char **argv) {
	const char *oldname = argv[1];
	const char *newname = argv[2];
	if (!rz_analysis_var_global_rename(core->analysis, oldname, newname)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_global_variable_print_handler(RzCore *core, int argc, const char **argv) {
	const char *name = argv[1];
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(core->analysis, name);
	if (!glob) {
		RZ_LOG_ERROR("Global variable '%s' does not exist!\n", name);
		return RZ_CMD_STATUS_ERROR;
	}
	char *fmt = rz_type_as_format_pair(core->analysis->typedb, glob->type);
	if (RZ_STR_ISEMPTY(fmt)) {
		free(fmt);
		return RZ_CMD_STATUS_ERROR;
	}
	char *r = rz_core_print_format(core, fmt, RZ_PRINT_MUSTSEE, glob->addr);
	if (r) {
		rz_cons_print(r);
	}
	free(r);
	free(fmt);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_global_variable_retype_handler(RzCore *core, int argc, const char **argv) {
	const char *name = argv[1];
	const char *type = argv[2];
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(core->analysis, name);
	if (!glob) {
		RZ_LOG_ERROR("Global variable '%s' does not exist!\n", name);
		return RZ_CMD_STATUS_ERROR;
	}
	char *errmsg = NULL;
	RzType *typ = rz_type_parse_string_single(core->analysis->typedb->parser, type, &errmsg);
	if (errmsg) {
		RZ_LOG_ERROR("%s : Error parsing type: \"%s\" message:\n%s\n", __FUNCTION__, type, errmsg);
		free(errmsg);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_analysis_var_global_set_type(glob, typ);
	return RZ_CMD_STATUS_OK;
}

RZ_API void rz_core_cmd_show_analysis_help(RZ_NONNULL RzCore *core) {
	rz_return_if_fail(core);
	rz_core_cmd_help(core, help_msg_a);
}

RZ_IPI int rz_cmd_analysis(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	ut32 tbs = core->blocksize;
	switch (input[0]) {
	case 'e': cmd_analysis_esil(core, input + 1); break; // "ae"
	case '*': // "a*"
		rz_core_cmd0_rzshell(core, "afl*");
		rz_core_cmd0_rzshell(core, "ah*");
		rz_core_cmd0_rzshell(core, "ax*");
		break;
	default:
		rz_core_cmd_help(core, help_msg_a);
		break;
	}
	if (tbs != core->blocksize) {
		rz_core_block_size(core, tbs);
	}
	if (rz_cons_is_breaked()) {
		rz_cons_clear_line(1);
	}
	return 0;
}

RZ_IPI RzCmdStatus rz_analysis_function_blocks_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	char *info = rz_core_analysis_bbs_as_string(core, fcn, state);
	if (info) {
		rz_cons_println(info);
		RZ_FREE(info);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_blocks_del_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisBlock *b = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	if (!b) {
		RZ_LOG_ERROR("core: Cannot find basic block\n");
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisFunction *fcn = rz_list_first(b->fcns);
	rz_analysis_function_remove_block(fcn, b);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_blocks_del_all_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	while (!rz_pvector_len(fcn->bbs)) {
		rz_analysis_function_remove_block(fcn, rz_pvector_head(fcn->bbs));
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_blocks_edge_handler(RzCore *core, int argc, const char **argv) {
	ut64 switch_addr = rz_num_math(core->num, argv[1]);
	ut64 case_addr = rz_num_math(core->num, argv[2]);
	RzList *blocks = rz_analysis_get_blocks_in(core->analysis, switch_addr);
	if (!rz_list_empty(blocks)) {
		rz_list_free(blocks);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_analysis_block_add_switch_case(rz_list_first(blocks), switch_addr, 0, case_addr);
	rz_list_free(blocks);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_blocks_switch_type_handler(RzCore *core, int argc, const char **argv) {
	ut64 switch_addr = rz_num_math(core->num, argv[1]);
	RzList *blocks = rz_analysis_get_blocks_in(core->analysis, switch_addr);
	if (rz_list_empty(blocks)) {
		RZ_LOG_ERROR("No basic block exists at '%s' (0x%" PFMT64x ")\n", argv[1], switch_addr);
		rz_list_free(blocks);
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisBlock *b = rz_list_first(blocks);
	if (!b->switch_op) {
		RZ_LOG_ERROR("Block does not have a switch case\n");
		return RZ_CMD_STATUS_INVALID;
	}
	RzBaseType *e = rz_type_db_get_enum(core->analysis->typedb, argv[2]);
	if (!e) {
		RZ_LOG_ERROR("Enum '%s' does not exist\n", argv[2]);
		return RZ_CMD_STATUS_INVALID;
	}
	rz_type_free(b->switch_op->enum_type);
	b->switch_op->enum_type = rz_type_identifier_of_base_type(core->analysis->typedb, e, true);
	rz_list_free(blocks);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_returns_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_analysis_fcn_returns(core, fcn);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_blocks_asciiart_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_analysis_bbs_asciiart(core, fcn);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_blocks_info_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	if (!bb) {
		RZ_LOG_ERROR("core: No basic block at 0x%" PFMT64x, core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_analysis_bb_info_print(core, bb, core->offset, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_blocks_add_handler(RzCore *core, int argc, const char **argv) {
	RzCmdStatus res = RZ_CMD_STATUS_ERROR;
	ut64 fcn_addr = rz_num_math(core->num, argv[1]);
	ut64 addr = rz_num_math(core->num, argv[2]);
	ut64 size = rz_num_math(core->num, argv[3]);
	ut64 jump = argc > 4 ? rz_num_math(core->num, argv[4]) : UT64_MAX;
	ut64 fail = argc > 5 ? rz_num_math(core->num, argv[5]) : UT64_MAX;
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, fcn_addr);
	if (!fcn) {
		RZ_LOG_ERROR("core: Cannot find function at 0x%" PFMT64x "\n", fcn_addr);
		goto err;
	}
	if (!rz_analysis_fcn_add_bb(core->analysis, fcn, addr, size, jump, fail)) {
		RZ_LOG_ERROR("core: Cannot add basic block at 0x%" PFMT64x " to fcn at 0x%" PFMT64x "\n", addr, fcn_addr);
		goto err;
	}
	res = RZ_CMD_STATUS_OK;
err:
	return res;
}

RZ_IPI RzCmdStatus rz_analysis_function_blocks_color_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = rz_num_math(core->num, argv[1]);
	ut32 color = (ut32)rz_num_math(core->num, argv[2]);
	RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in(core->analysis, addr);
	if (!block) {
		RZ_LOG_ERROR("core: No basic block at 0x%08" PFMT64x "\n", addr);
		return RZ_CMD_STATUS_ERROR;
	}
	block->colorize = color;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_setbits_handler(RzCore *core, int argc, const char **argv) {
	int bits = atoi(argv[1]);
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	void **iter;
	RzAnalysisBlock *bb;
	rz_pvector_foreach (fcn->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
		rz_analysis_hint_set_bits(core->analysis, bb->addr, bits);
		rz_analysis_hint_set_bits(core->analysis, bb->addr + bb->size, core->analysis->bits);
	}
	fcn->bits = bits;
	return RZ_CMD_STATUS_OK;
}

static bool function_byte_signature(RzCore *core, RzAnalysisFunction *fcn, ut8 **buffer, ut32 *buf_sz) {
	size_t size = 0, current = 0;
	ut8 *data = NULL;
	RzAnalysisBlock *bb;
	void **iter;

	rz_pvector_foreach (fcn->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
		size += bb->size;
	}

	if (size < 1 || !(data = malloc(size))) {
		RZ_LOG_ERROR("core: failed to allocate pattern bytes for function '%s'\n", fcn->name);
		goto fail;
	}

	current = 0;
	rz_pvector_foreach (fcn->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
		if (bb->size > 0 && !rz_io_read_at(core->io, bb->addr, data + current, bb->size)) {
			RZ_LOG_ERROR("core: failed to read at %" PFMT64x "\n", bb->addr);
			goto fail;
		}
		current += bb->size;
	}

	*buf_sz = size;
	*buffer = data;
	return true;

fail:
	free(data);
	return false;
}

RZ_IPI RzCmdStatus rz_analysis_function_signature_bytes_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *f = analysis_get_function_in(core->analysis, core->offset);
	if (!f) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzCmdStatus status = RZ_CMD_STATUS_OK;
	ut32 size = 0;
	char *s_pattern = NULL, *s_mask = NULL, *s_search = NULL;
	ut8 *pattern = NULL, *mask = NULL;

	if (!function_byte_signature(core, f, &pattern, &size)) {
		return RZ_CMD_STATUS_ERROR;
	}

	mask = rz_analysis_mask(core->analysis, size, pattern, f->addr);
	if (!mask) {
		RZ_LOG_ERROR("core: failed to create mask of function '%s'\n", f->name);
		status = RZ_CMD_STATUS_ERROR;
		goto fail;
	}

	if (!(s_pattern = rz_hex_bin2strdup(pattern, size)) ||
		!(s_mask = rz_hex_bin2strdup(mask, size)) ||
		!(s_search = rz_str_dup(s_pattern))) {
		RZ_LOG_ERROR("core: failed to convert pattern & mask to string\n");
		status = RZ_CMD_STATUS_ERROR;
		goto fail;
	}

	for (ut32 i = 0, j = 0; i < size; ++i, j += 2) {
		if (mask[i] == 0xFF) {
			continue;
		}
		s_search[j] = '.';
		s_search[j + 1] = '.';
	}

	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_cons_printf("pattern %s\n", s_pattern);
		rz_cons_printf("mask %s\n", s_mask);
		rz_cons_printf("search %s\n", s_search);
		break;
	}
	case RZ_OUTPUT_MODE_JSON: {
		pj_o(state->d.pj);
		pj_ks(state->d.pj, "pattern", s_pattern);
		pj_ks(state->d.pj, "mask", s_mask);
		pj_ks(state->d.pj, "search", s_search);
		pj_end(state->d.pj);
		break;
	}
	default:
		rz_warn_if_reached();
		status = RZ_CMD_STATUS_ERROR;
		goto fail;
	}

fail:
	free(s_pattern);
	free(s_mask);
	free(s_search);
	free(mask);
	free(pattern);
	return status;
}

RZ_IPI RzCmdStatus rz_analysis_function_signature_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzAnalysisFunction *f = analysis_get_function_in(core->analysis, core->offset);
	if (!f) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (argc > 1) {
		// set signature
		rz_core_analysis_function_set_signature(core, f, argv[1]);
	} else {
		// get signature
		char *str = NULL;
		switch (mode) {
		case RZ_OUTPUT_MODE_STANDARD: {
			str = rz_analysis_function_get_signature(f);
			break;
		}
		case RZ_OUTPUT_MODE_JSON: {
			str = rz_analysis_function_get_json(f);
			break;
		}
		default:
			rz_warn_if_reached();
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_println(str);
		free(str);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_signature_editor_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_function_signature_editor(core, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_signature_type_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	char *error_msg = NULL;
	RzType *ret_type = rz_type_parse_string_single(core->analysis->typedb->parser, argv[1], &error_msg);
	if (!ret_type || error_msg) {
		RZ_LOG_ERROR("core: Cannot parse type \"%s\":\n%s\n", argv[1], error_msg);
		free(error_msg);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_type_func_ret_set(core->analysis->typedb, fcn->name, ret_type)) {
		RZ_LOG_ERROR("core: Cannot find type %s\n", argv[1]);
		rz_type_free(ret_type);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_type_free(fcn->ret_type);
	fcn->ret_type = ret_type;
	return RZ_CMD_STATUS_OK;
}

static void xref_print_to_json(RZ_UNUSED RzCore *core, RzAnalysisXRef *xref, PJ *pj) {
	pj_o(pj);
	pj_kn(pj, "from", xref->from);
	pj_kn(pj, "to", xref->to);
	pj_ks(pj, "type", rz_analysis_xrefs_type_tostring(xref->type));
	pj_end(pj);
}

static void xref_list_print_to_json(RZ_UNUSED RzCore *core, RzList /*<RzAnalysisXRef *>*/ *list, PJ *pj) {
	RzAnalysisXRef *xref;
	RzListIter *iter;
	pj_a(pj);
	rz_list_foreach (list, iter, xref) {
		xref_print_to_json(core, xref, pj);
	}
	pj_end(pj);
}

RZ_IPI RzCmdStatus rz_analysis_function_xrefs_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 oaddr = core->offset;
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	rz_cmd_state_output_array_start(state);

	RzAnalysisXRef *xref;
	RzListIter *iter;
	rz_list_foreach (xrefs, iter, xref) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("%c 0x%08" PFMT64x " -> ", xref->type, xref->from);
			switch (xref->type) {
			case RZ_ANALYSIS_XREF_TYPE_NULL:
				rz_cons_printf("0x%08" PFMT64x " ", xref->to);
				break;
			case RZ_ANALYSIS_XREF_TYPE_CODE:
			case RZ_ANALYSIS_XREF_TYPE_CALL:
			case RZ_ANALYSIS_XREF_TYPE_DATA:
				rz_cons_printf("0x%08" PFMT64x " ", xref->to);
				rz_core_seek(core, xref->from, 1);
				rz_core_print_disasm_instructions(core, 0, 1);
				break;
			case RZ_ANALYSIS_XREF_TYPE_STRING: {
				char *s = rz_core_cmd_strf(core, "pxr 8 @ 0x%08" PFMT64x, xref->to);
				char *nl = strchr(s, '\n');
				if (nl) {
					*nl = 0;
				}
				rz_cons_printf("%s\n", s);
				free(s);
				break;
			}
			}
			break;
		case RZ_OUTPUT_MODE_JSON:
			xref_print_to_json(core, xref, state->d.pj);
			break;
		default:
			rz_warn_if_reached();
			status = RZ_CMD_STATUS_WRONG_ARGS;
			goto exit;
		}
	}
	rz_core_seek(core, oaddr, 1);
exit:
	rz_list_free(xrefs);
	rz_cmd_state_output_array_end(state);
	return status;
}

RZ_IPI RzCmdStatus rz_analysis_function_stacksz_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	fcn->maxstack = rz_num_math(core->num, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_address_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	PJ *pj = NULL;
	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("0x%08" PFMT64x "\n", fcn->addr);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj = pj_new();
		if (!pj) {
			return RZ_CMD_STATUS_ERROR;
		}
		pj_o(pj);
		if (fcn) {
			pj_ki(pj, "address", fcn->addr);
		}
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
		break;
	default:
		rz_return_val_if_reached(RZ_CMD_STATUS_ERROR);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_until_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr_end = rz_num_math(core->num, argv[1]);
	if (addr_end < core->offset) {
		RZ_LOG_ERROR("core: Invalid address ranges\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_analysis_function_until(core, addr_end);
	return RZ_CMD_STATUS_OK;
}

static int var_comparator(const RzAnalysisVar *a, const RzAnalysisVar *b, void *user) {
	if (!a || !b) {
		return 0;
	}
	return rz_analysis_var_storage_cmp(&a->storage, &b->storage);
}

typedef struct {
	const char *func_var;
	const char *func_var_type;
	const char *func_var_addr;
	const char *color_reset;
	RzCore *core;
	RzCmdStateOutput *out;
} VarShowContext;

static void var_show(
	RZ_NONNULL VarShowContext *ctx,
	RZ_NONNULL RzAnalysisFunction *fcn,
	RZ_NONNULL RzAnalysisVar *var) {
	char *constr = rz_analysis_var_get_constraints_readable(var);
	char *var_type_string = rz_type_as_string(ctx->core->analysis->typedb, var->type);
	char *storage_string = rz_analysis_var_storage_to_string(ctx->core->analysis, var, &var->storage);
	RzBinDWARFDumpOption dump_opt = {
		.dwarf_register_mapping = ctx->core->analysis->debug_info->dwarf_register_mapping,
		.loclist_sep = ",\t",
		.loclist_indent = "",
		.loclist_breaklines = false,
		.expr_sep = ",\t",
		.expr_indent = "",
		.expr_breaklines = false,
		.composite_sep = ",\t",
		.composite_indent = "",
		.compose_breaklines = false,
	};
	char *loc_string = var->origin.kind == RZ_ANALYSIS_VAR_ORIGIN_DWARF ? rz_bin_dwarf_location_to_string(var->origin.dw_var->location, &dump_opt)
									    : NULL;
	switch (ctx->out->mode) {
	case RZ_OUTPUT_MODE_RIZIN: {
		// we can't express all type info here :(
		switch (var->storage.type) {
		case RZ_ANALYSIS_VAR_STORAGE_REG:
			rz_cons_printf("afvr %s %s %s @ 0x%" PFMT64x "\n",
				var->storage.reg, var->name, var_type_string, fcn->addr);
			break;
		case RZ_ANALYSIS_VAR_STORAGE_STACK:
			rz_cons_printf("afvs %" PFMT64d " %s %s @ 0x%" PFMT64x "\n",
				var->storage.stack_off, var->name, var_type_string,
				fcn->addr);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		break;
	}
	case RZ_OUTPUT_MODE_JSON: {
		pj_o(ctx->out->d.pj);
		pj_ks(ctx->out->d.pj, "name", var->name);
		pj_kb(ctx->out->d.pj, "arg", rz_analysis_var_is_arg(var));
		pj_ks(ctx->out->d.pj, "type", var_type_string);
		rz_analysis_var_storage_dump_pj(ctx->out->d.pj, var, &var->storage);
		pj_end(ctx->out->d.pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD:
	case RZ_OUTPUT_MODE_LONG: {
		const char *pfx = rz_analysis_var_is_arg(var) ? "arg" : "var";
		rz_cons_printf("%s%s %s%s%s%s",
			ctx->func_var, pfx,
			ctx->func_var_type, var_type_string,
			rz_str_endswith(var_type_string, "*") ? "" : " ",
			var->name);

		rz_cons_printf(" %s%s%s%s",
			ctx->func_var_addr,
			constr ? " { " : "",
			constr ? constr : "",
			constr ? "} " : "");

		if (ctx->out->mode == RZ_OUTPUT_MODE_LONG && var->origin.kind == RZ_ANALYSIS_VAR_ORIGIN_DWARF) {
			rz_cons_printf("%sorigin=DWARF @ %s\n", ctx->color_reset, loc_string);
		} else {
			rz_cons_printf("@ %s\n", storage_string);
		}
		break;
	}
	case RZ_OUTPUT_MODE_TABLE: {
		rz_table_add_rowf(ctx->out->d.t, "bsssss",
			rz_analysis_var_is_arg(var),
			var->name,
			var_type_string,
			constr,
			var->origin.kind == RZ_ANALYSIS_VAR_ORIGIN_DWARF ? "DWARF" : "rizin",
			var->origin.kind == RZ_ANALYSIS_VAR_ORIGIN_DWARF ? loc_string : storage_string);
		break;
	}
	default: break;
	}

	free(var_type_string);
	free(constr);
	free(storage_string);
	free(loc_string);
}

static void var_list_show(
	RzCore *core,
	RzAnalysisFunction *fcn,
	RzCmdStateOutput *state,
	RzList /*<RzAnalysisVar *>*/ *list) {
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "bsssss",
		"is_arg", "name", "type", "constraints", "origin", "addr");

	if (!(list && rz_list_length(list) > 0)) {
		goto fail;
	}
	rz_list_sort(list, (RzListComparator)var_comparator, NULL);

	bool color_arg = (rz_config_get_b(core->config, "scr.color") && rz_config_get_b(core->config, "scr.color.args"));
	VarShowContext ctx = {
		.core = core,
		.out = state,
		.func_var = color_arg
			? core->cons->context->pal.func_var
			: "",
		.func_var_type = color_arg
			? core->cons->context->pal.func_var_type
			: "",
		.func_var_addr = color_arg
			? core->cons->context->pal.func_var_addr
			: "",
		.color_reset = color_arg
			? Color_RESET
			: "",
	};

	RzAnalysisVar *var;
	RzListIter *iter;
	rz_list_foreach (list, iter, var) {
		var_show(&ctx, fcn, var);
	}
fail:
	rz_cmd_state_output_array_end(state);
}

static void core_analysis_var_list_show(
	RzCore *core,
	RzAnalysisFunction *fcn,
	RzAnalysisVarStorageType kind,
	RzCmdStateOutput *state) {
	RzList *list = rz_analysis_var_list(fcn, kind);
	if (!list) {
		return;
	}
	var_list_show(core, fcn, state, list);
	rz_list_free(list);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	switch (state->mode) {
	case RZ_OUTPUT_MODE_RIZIN:
	case RZ_OUTPUT_MODE_STANDARD:
	case RZ_OUTPUT_MODE_LONG:
	case RZ_OUTPUT_MODE_TABLE:
		for (int i = 0; i <= RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING; ++i) {
			core_analysis_var_list_show(core, fcn, i, state);
		}
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		for (int i = 0; i <= RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING; ++i) {
			RzList *list = rz_analysis_var_list(fcn, i);
			if (!(list && !rz_list_empty(list))) {
				continue;
			}
			pj_k(state->d.pj, rz_analysis_var_storage_type_to_string(i));
			var_list_show(core, fcn, state, list);
		};
		pj_end(state->d.pj);
		break;
	default:
		rz_return_val_if_reached(RZ_CMD_STATUS_ERROR);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_dis_refs_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 oaddr = core->offset;
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		rz_cons_printf("* %s\n", var->name);
		RzAnalysisVarAccess *acc;
		rz_vector_foreach (&var->accesses, acc) {
			if (!(acc->type & RZ_ANALYSIS_VAR_ACCESS_TYPE_READ)) {
				continue;
			}
			rz_cons_printf("R 0x%" PFMT64x "  ", fcn->addr + acc->offset);
			rz_core_seek(core, fcn->addr + acc->offset, 1);
			rz_core_print_disasm_instructions(core, 0, 1);
		}
		rz_vector_foreach (&var->accesses, acc) {
			if (!(acc->type & RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE)) {
				continue;
			}
			rz_cons_printf("W 0x%" PFMT64x "  ", fcn->addr + acc->offset);
			rz_core_seek(core, fcn->addr + acc->offset, 1);
			rz_core_print_disasm_instructions(core, 0, 1);
		}
	}
	rz_core_seek(core, oaddr, 0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_del_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	const char *varname = argv[1];
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, varname);
	if (!var) {
		RZ_LOG_ERROR("Variable \"%s\" not found.\n", varname);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_analysis_var_delete(var);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_detect_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	rz_analysis_function_delete_all_vars(fcn);
	rz_core_recover_vars(core, fcn, false);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_display_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzAnalysisVar *v;
	char *r = NULL;
	switch (argc) {
	case 1:
		r = rz_core_analysis_all_vars_display(core, fcn, true);
		break;
	case 2:
		v = rz_analysis_function_get_var_byname(fcn, argv[1]);
		if (!v) {
			RZ_LOG_ERROR("core: Cannot find variable '%s' in current function\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		r = rz_core_analysis_var_display(core, v, true);
		break;
	default:
		rz_return_val_if_reached(RZ_CMD_STATUS_ERROR);
	}
	rz_cons_print(r);
	free(r);
	return RZ_CMD_STATUS_OK;
}

static int delta_cmp(const void *a, const void *b, void *user) {
	const RzAnalysisVar *va = a;
	const RzAnalysisVar *vb = b;
	if (va->storage.type != vb->storage.type) {
		return va->storage.type - vb->storage.type;
	}
	if (va->storage.type == RZ_ANALYSIS_VAR_STORAGE_STACK) {
		return vb->storage.stack_off - va->storage.stack_off;
	}
	return 0;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_stackframe_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzPVector *vars = rz_pvector_clone(&fcn->vars);
	if (!vars) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_pvector_sort(vars, delta_cmp, NULL);
	void **it;
	rz_pvector_foreach (vars, it) {
		RzAnalysisVar *p = *it;
		if (p->storage.type != RZ_ANALYSIS_VAR_STORAGE_STACK) {
			continue;
		}
		char *pad = rz_str_pad(' ', 10 - strlen(p->name));
		char *ptype = rz_type_as_string(core->analysis->typedb, p->type);
		st64 off = p->storage.stack_off;
		char sign = off < 0 ? '-' : '+';
		rz_cons_printf("%c0x%08" PFMT64x "  %s:%s%s\n", sign, RZ_ABS(off), p->name, pad, ptype);
		free(ptype);
		free(pad);
	}
	rz_pvector_free(vars);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_rename_handler(RzCore *core, int argc, const char **argv) {
	const char *newname = argv[1];
	const char *oldname = argv[2];
	bool result = rz_core_analysis_var_rename(core, oldname, newname);
	return result ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_OK;
}

static RzCmdStatus analysis_function_vars_accesses(RzCore *core, int access_type, const char *varname) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (!varname) {
		void **it;
		rz_pvector_foreach (&fcn->vars, it) {
			RzAnalysisVar *var = *it;
			var_accesses_list(fcn, var, NULL, access_type, var->name);
		}
	} else {
		RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, varname);
		if (!var) {
			RZ_LOG_ERROR("core: Cannot find variable %s\n", varname);
			return RZ_CMD_STATUS_ERROR;
		}
		var_accesses_list(fcn, var, NULL, access_type, var->name);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_reads_handler(RzCore *core, int argc, const char **argv) {
	return analysis_function_vars_accesses(core, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, argv[1]);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_writes_handler(RzCore *core, int argc, const char **argv) {
	return analysis_function_vars_accesses(core, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, argv[1]);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_type_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzAnalysisVar *v = rz_analysis_function_get_var_byname(fcn, argv[1]);
	if (!v) {
		RZ_LOG_ERROR("core: Cannot find variable %s\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	char *error_msg = NULL;
	RzType *v_type = rz_type_parse_string_single(core->analysis->typedb->parser, argv[2], &error_msg);
	if (!v_type || error_msg) {
		RZ_LOG_ERROR("core: Cannot parse type \"%s\":\n%s\n", argv[2], error_msg);
		free(error_msg);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_analysis_var_set_type(v, v_type, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_args_and_vars_xrefs_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode, bool use_args, bool use_vars) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	PJ *pj = NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj = pj_new();
		pj_o(pj);
		pj_k(pj, "reads");
	} else {
		rz_cons_printf("afvR\n");
	}
	if (use_args) {
		list_vars(core, fcn, pj, 'R', argv[1], IS_ARG);
	}
	if (use_vars) {
		list_vars(core, fcn, pj, 'R', argv[1], IS_VAR);
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_k(pj, "writes");
	} else {
		rz_cons_printf("afvW\n");
	}
	if (use_args) {
		list_vars(core, fcn, pj, 'W', argv[1], IS_ARG);
	}
	if (use_vars) {
		list_vars(core, fcn, pj, 'W', argv[1], IS_VAR);
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		char *j = pj_drain(pj);
		rz_cons_printf("%s\n", j);
		free(j);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_xrefs_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return rz_analysis_function_args_and_vars_xrefs_handler(core, argc, argv, mode, true, true);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_xrefs_args_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return rz_analysis_function_args_and_vars_xrefs_handler(core, argc, argv, mode, true, false);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_xrefs_vars_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return rz_analysis_function_args_and_vars_xrefs_handler(core, argc, argv, mode, false, true);
}

static RzCmdStatus analysis_function_vars_kind_list(RzCore *core, RzAnalysisFunction *fcn, RzAnalysisVarStorageType kind, RzCmdStateOutput *state) {
	core_analysis_var_list_show(core, fcn, kind, state);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus analysis_function_vars_del(RzCore *core, RzAnalysisVarStorageType kind, const char *varname) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_analysis_function_delete_var(core, fcn, kind, varname);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus analysis_function_vars_del_all(RzCore *core, RzAnalysisVarStorageType kind) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_analysis_function_delete_vars_by_storage_type(fcn, kind);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus analysis_function_vars_getsetref(RzCore *core, RzAnalysisVarStorage *stor, ut64 addr, RzAnalysisVarAccessType access_type) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzAnalysisVar *var = rz_analysis_function_get_var_at(fcn, stor);
	if (!var) {
		char *stor_str = rz_analysis_var_storage_to_string(core->analysis, NULL, stor);
		RZ_LOG_ERROR("core: Cannot find variable with %s\n", stor_str);
		free(stor_str);
		return RZ_CMD_STATUS_ERROR;
	}

	RzAnalysisOp *op = rz_core_analysis_op(core, addr, 0);
	const char *ireg = op ? op->ireg : NULL;
	st64 addend = 0;
	if (stor->type == RZ_ANALYSIS_VAR_STORAGE_STACK) {
		// TODO: this is wrong. What we need is not the address on the stack, but
		// the exact value added to the register during the access.
		addend = stor->stack_off;
	}
	rz_analysis_var_set_access(var, ireg, addr, access_type, addend);
	rz_analysis_op_free(op);
	return RZ_CMD_STATUS_OK;
}

/// --------- Stack-based variable handlers -------------

RZ_IPI RzCmdStatus rz_analysis_function_vars_stack_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (argc == 1) {
		return analysis_function_vars_kind_list(core, fcn, RZ_ANALYSIS_VAR_STORAGE_STACK, state);
	} else {
		const char *varname = argv[2];
		const char *vartype = argc > 3 ? argv[3] : "int";
		st64 delta = (int)rz_num_math(core->num, argv[1]);
		char *error_msg = NULL;
		RzType *var_type = rz_type_parse_string_single(core->analysis->typedb->parser, vartype, &error_msg);
		if (!var_type || error_msg) {
			RZ_LOG_ERROR("core: Cannot parse type \"%s\":\n%s\n", vartype, error_msg);
			free(error_msg);
			return RZ_CMD_STATUS_ERROR;
		}
		RzAnalysisVarStorage stor;
		rz_analysis_var_storage_init_stack(&stor, delta);
		rz_analysis_function_set_var(fcn, &stor, var_type, 4, varname);
		rz_type_free(var_type);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_stack_del_handler(RzCore *core, int argc, const char **argv) {
	return analysis_function_vars_del(core, RZ_ANALYSIS_VAR_STORAGE_STACK, argv[1]);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_stack_del_all_handler(RzCore *core, int argc, const char **argv) {
	return analysis_function_vars_del_all(core, RZ_ANALYSIS_VAR_STORAGE_STACK);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_stack_getref_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisVarStorage stor;
	rz_analysis_var_storage_init_stack(&stor, (st64)rz_num_math(core->num, argv[1]));
	ut64 addr = rz_num_math(core->num, argv[2]);
	return analysis_function_vars_getsetref(core, &stor, addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_stack_setref_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisVarStorage stor;
	rz_analysis_var_storage_init_stack(&stor, (st64)rz_num_math(core->num, argv[1]));
	ut64 addr = rz_num_math(core->num, argv[2]);
	return analysis_function_vars_getsetref(core, &stor, addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE);
}

/// --------- Register-based variable handlers -------------

RZ_IPI RzCmdStatus rz_analysis_function_vars_regs_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (argc == 1) {
		return analysis_function_vars_kind_list(core, fcn, RZ_ANALYSIS_VAR_STORAGE_REG, state);
	} else {
		const char *varname = argv[2];
		const char *vartype = argc > 3 ? argv[3] : "int";
		RzRegItem *i = rz_reg_get(core->analysis->reg, argv[1], -1);
		if (!i) {
			RZ_LOG_ERROR("core: Register not found\n");
			return RZ_CMD_STATUS_ERROR;
		}
		char *error_msg = NULL;
		RzType *var_type = rz_type_parse_string_single(core->analysis->typedb->parser, vartype, &error_msg);
		if (!var_type || error_msg) {
			RZ_LOG_ERROR("core: Cannot parse type \"%s\":\n%s\n", vartype, error_msg);
			free(error_msg);
			return RZ_CMD_STATUS_ERROR;
		}
		RzAnalysisVarStorage stor;
		rz_analysis_var_storage_init_reg(&stor, i->name);
		rz_analysis_function_set_var(fcn, &stor, var_type, 4, varname);
		rz_type_free(var_type);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_regs_del_handler(RzCore *core, int argc, const char **argv) {
	return analysis_function_vars_del(core, RZ_ANALYSIS_VAR_STORAGE_REG, argv[1]);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_regs_del_all_handler(RzCore *core, int argc, const char **argv) {
	return analysis_function_vars_del_all(core, RZ_ANALYSIS_VAR_STORAGE_REG);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_regs_getref_handler(RzCore *core, int argc, const char **argv) {
	RzRegItem *i = rz_reg_get(core->analysis->reg, argv[1], -1);
	if (!i) {
		RZ_LOG_ERROR("core: Register not found\n");
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisVarStorage stor;
	rz_analysis_var_storage_init_reg(&stor, i->name);
	ut64 addr = rz_num_math(core->num, argv[2]);
	return analysis_function_vars_getsetref(core, &stor, addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_regs_setref_handler(RzCore *core, int argc, const char **argv) {
	RzRegItem *i = rz_reg_get(core->analysis->reg, argv[1], -1);
	if (!i) {
		RZ_LOG_ERROR("core: Register not found\n");
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisVarStorage stor;
	rz_analysis_var_storage_init_reg(&stor, i->name);
	ut64 addr = rz_num_math(core->num, argv[2]);
	return analysis_function_vars_getsetref(core, &stor, addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE);
}

/// ---------

static RzCmdStatus xrefs_set(RzCore *core, int argc, const char **argv, RzAnalysisXRefType type) {
	ut64 from = core->offset;
	ut64 to = rz_num_math(core->num, argv[1]);
	return rz_analysis_xrefs_set(core->analysis, from, to, type) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_set_0_handler(RzCore *core, int argc, const char **argv) {
	return xrefs_set(core, argc, argv, RZ_ANALYSIS_XREF_TYPE_NULL);
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_set_c_handler(RzCore *core, int argc, const char **argv) {
	return xrefs_set(core, argc, argv, RZ_ANALYSIS_XREF_TYPE_CODE);
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_set_C_handler(RzCore *core, int argc, const char **argv) {
	return xrefs_set(core, argc, argv, RZ_ANALYSIS_XREF_TYPE_CALL);
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_set_d_handler(RzCore *core, int argc, const char **argv) {
	return xrefs_set(core, argc, argv, RZ_ANALYSIS_XREF_TYPE_DATA);
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_set_s_handler(RzCore *core, int argc, const char **argv) {
	return xrefs_set(core, argc, argv, RZ_ANALYSIS_XREF_TYPE_STRING);
}

static void xrefs_list_print(RzCore *core, RzList /*<RzAnalysisXRef *>*/ *list) {
	RzListIter *iter;
	RzAnalysisXRef *xref;

	rz_list_foreach (list, iter, xref) {
		char *name = core->analysis->coreb.getNameDelta(core->analysis->coreb.core, xref->from);
		if (name) {
			rz_str_replace_ch(name, ' ', 0, true);
			rz_cons_printf("%40s", name);
			free(name);
		} else {
			rz_cons_printf("%40s", "?");
		}
		rz_cons_printf(" 0x%" PFMT64x " -> %9s -> 0x%" PFMT64x, xref->from, rz_analysis_xrefs_type_tostring(xref->type), xref->to);
		name = core->analysis->coreb.getNameDelta(core->analysis->coreb.core, xref->to);
		if (name) {
			rz_str_replace_ch(name, ' ', 0, true);
			rz_cons_printf(" %s\n", name);
			free(name);
		} else {
			rz_cons_printf("\n");
		}
	}
}

static const char *xref_type2cmd(RzAnalysisXRefType type) {
	switch (type) {
	case RZ_ANALYSIS_XREF_TYPE_CODE:
		return "axc";
	case RZ_ANALYSIS_XREF_TYPE_CALL:
		return "axC";
	case RZ_ANALYSIS_XREF_TYPE_DATA:
		return "axd";
	case RZ_ANALYSIS_XREF_TYPE_STRING:
		return "axs";
	case RZ_ANALYSIS_XREF_TYPE_NULL:
		return "ax";
	}
	return "ax";
}

static void xref_list_print_as_cmd(RZ_UNUSED RzCore *core, RzList /*<RzAnalysisXRef *>*/ *list) {
	RzListIter *iter;
	RzAnalysisXRef *xref;
	rz_list_foreach (list, iter, xref) {
		rz_cons_printf("%s 0x%" PFMT64x " @ 0x%" PFMT64x "\n", xref_type2cmd(xref->type), xref->to, xref->from);
	}
}

static void xrefs_list_handler(RzCore *core, RzList /*<RzAnalysisXRef *>*/ *list, RzCmdStateOutput *state) {
	RzAnalysisXRef *xref;
	RzListIter *iter;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		xrefs_list_print(core, list);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_list_foreach (list, iter, xref) {
			rz_cons_printf("0x%08" PFMT64x " -> 0x%08" PFMT64x "  %s\n", xref->from, xref->to, rz_analysis_xrefs_type_tostring(xref->type));
		}
		break;
	case RZ_OUTPUT_MODE_JSON:
		xref_list_print_to_json(core, list, state->d.pj);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		xref_list_print_as_cmd(core, list);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RzList *list = rz_analysis_xrefs_list(core->analysis);
	xrefs_list_handler(core, list, state);
	rz_list_free(list);
	return status;
}

static void xrefs_to_list_handler(RzCore *core, RzList /*<RzAnalysisXRef *>*/ *list, RzCmdStateOutput *state) {
	RzAnalysisXRef *xref;
	RzListIter *iter;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_list_foreach (list, iter, xref) {
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, xref->from, 0);
			char *buf_asm = rz_core_disasm_instruction(core, xref->from, core->offset, fcn, true);
			const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, xref->from);
			char *print_comment = NULL;
			const char *nl = comment ? strchr(comment, '\n') : NULL;
			if (nl) { // display only until the first newline
				comment = print_comment = rz_str_ndup(comment, nl - comment);
			}
			char *buf_fcn = comment
				? rz_str_newf("%s; %s", fcn ? fcn->name : "(nofunc)", comment)
				: rz_str_newf("%s", fcn ? fcn->name : "(nofunc)");
			free(print_comment);
			rz_cons_printf("%s 0x%" PFMT64x " [%s] %s\n",
				buf_fcn, xref->from, rz_analysis_xrefs_type_tostring(xref->type), buf_asm);
			free(buf_asm);
			free(buf_fcn);
		}
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_list_foreach (list, iter, xref) {
			rz_cons_printf("0x%08" PFMT64x "\n", xref->from);
		}
		break;
	case RZ_OUTPUT_MODE_JSON:
		xref_list_print_to_json(core, list, state->d.pj);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		xref_list_print_as_cmd(core, list);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_to_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RzList *list = rz_analysis_xrefs_get_to(core->analysis, core->offset);
	xrefs_to_list_handler(core, list, state);
	rz_list_free(list);
	return status;
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_from_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisXRef *xref;
	RzListIter *iter;
	char str[512];
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RzList *list = rz_analysis_xrefs_get_from(core->analysis, core->offset);
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_list_foreach (list, iter, xref) {
			ut8 buf[16];
			char *desc;
			RzAsmOp asmop;
			RzFlagItem *flag = rz_flag_get_at(core->flags, xref->to, false);
			if (flag) {
				desc = flag->name;
			} else {
				rz_io_read_at(core->io, xref->to, buf, sizeof(buf));
				rz_asm_set_pc(core->rasm, xref->to);
				rz_asm_disassemble(core->rasm, &asmop, buf, sizeof(buf));
				RzAnalysisHint *hint = rz_analysis_hint_get(core->analysis, xref->to);
				rz_parse_filter(core->parser, xref->from, core->flags, hint, rz_asm_op_get_asm(&asmop),
					str, sizeof(str), core->print->big_endian);
				rz_analysis_hint_free(hint);
				desc = str;
			}
			rz_cons_printf("%c 0x%" PFMT64x " %s",
				xref->type ? xref->type : ' ', xref->to, desc);

			if (xref->type == RZ_ANALYSIS_XREF_TYPE_CALL) {
				RzAnalysisOp aop = { 0 };
				rz_analysis_op_init(&aop);
				rz_analysis_op(core->analysis, &aop, xref->to, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
				if (aop.type == RZ_ANALYSIS_OP_TYPE_UCALL) {
					cmd_analysis_ucall_ref(core, xref->to);
				}
				rz_analysis_op_fini(&aop);
			}
			rz_cons_newline();
		}
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_list_foreach (list, iter, xref) {
			rz_cons_printf("0x%08" PFMT64x "\n", xref->to);
		}
		break;
	case RZ_OUTPUT_MODE_JSON:
		xref_list_print_to_json(core, list, state->d.pj);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		xref_list_print_as_cmd(core, list);
		break;
	default:
		rz_warn_if_reached();
		status = RZ_CMD_STATUS_WRONG_ARGS;
		break;
	}
	rz_list_free(list);
	return status;
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_to_graph_cmd_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisXRef *xref;
	RzListIter *iter;
	ut64 addr = core->offset;
	RzList *list = rz_analysis_xrefs_get_to(core->analysis, addr);
	rz_list_foreach (list, iter, xref) {
		char *str = rz_core_cmd_strf(core, "fd @ 0x%" PFMT64x, xref->from);
		if (!str) {
			str = rz_str_dup("?\n");
		}
		rz_str_trim_tail(str);
		rz_cons_printf("agn 0x%" PFMT64x " \"%s\"\n", xref->from, str);
		free(str);
	}
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
	rz_cons_printf("agn 0x%" PFMT64x " \"%s\"\n", addr, fcn ? fcn->name : "$$");
	rz_list_foreach (list, iter, xref) {
		rz_cons_printf("age 0x%" PFMT64x " 0x%" PFMT64x "\n", xref->from, addr);
	}
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_del_handler(RzCore *core, int argc, const char **argv) {
	bool all = true;
	ut64 from = 0;
	ut64 to = rz_num_math(core->num, argv[1]);
	if (argc == 3) {
		from = rz_num_math(core->num, argv[2]);
		all = false;
	}
	RzAnalysisXRef *xref;
	RzListIter *iter;
	RzList *list = rz_analysis_xrefs_get_to(core->analysis, to);
	rz_list_foreach (list, iter, xref) {
		if (all || from == xref->from) {
			rz_analysis_xref_del(core->analysis, xref->from, xref->to);
		}
	}
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_del_all_handler(RzCore *core, int argc, const char **argv) {
	return rz_analysis_xrefs_init(core->analysis) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_copy_handler(RzCore *core, int argc, const char **argv) {
	ut64 src = rz_num_math(core->num, argv[1]);
	RzAnalysisXRef *xref;
	RzListIter *iter;
	RzList *list = rz_analysis_xrefs_get_to(core->analysis, src);
	rz_list_foreach (list, iter, xref) {
		rz_cons_printf("0x%08" PFMT64x " %s\n", xref->from, rz_analysis_xrefs_type_tostring(xref->type));
		rz_analysis_xrefs_set(core->analysis, xref->from, core->offset, xref->type);
	}
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

static void xrefs_graph_fcn_start_json(PJ *pj, RzAnalysisFunction *fcn, ut64 addr) {
	char taddr[64];
	pj_o(pj);
	pj_k(pj, rz_strf(taddr, "%" PFMT64u, addr));
	pj_o(pj);
	pj_ks(pj, "type", "fcn");
	pj_kn(pj, "fcn_addr", fcn->addr);
	pj_ks(pj, "name", fcn->name);
	pj_k(pj, "refs");
	pj_a(pj);
}

static void xrefs_graph(RzCore *core, ut64 addr, int level, HtUU *ht, RzOutputMode mode, PJ *pj) {
	char pre[128];
	RzListIter *iter;
	RzAnalysisXRef *xref;
	bool is_json = mode == RZ_OUTPUT_MODE_JSON;
	bool is_rz = mode == RZ_OUTPUT_MODE_RIZIN;
	int spaces = (level + 1) * 2;
	if (spaces > sizeof(pre) - 4) {
		spaces = sizeof(pre) - 4;
	}
	memset(pre, ' ', sizeof(pre));
	strcpy(pre + spaces, "- ");

	RzList *xrefs = rz_analysis_xrefs_get_to(core->analysis, addr);
	bool open_object = false;
	if (!rz_list_empty(xrefs)) {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in_bounds(core->analysis, addr, -1);
		if (fcn) {
			if (is_rz) {
				rz_cons_printf("agn 0x%08" PFMT64x " %s\n", fcn->addr, fcn->name);
			} else if (is_json) {
				xrefs_graph_fcn_start_json(pj, fcn, addr);
				open_object = true;
			} else {
				rz_cons_printf("%s0x%08" PFMT64x " fcn 0x%08" PFMT64x " %s\n",
					pre + 2, addr, fcn->addr, fcn->name);
			}
		} else {
			if (is_rz) {
				rz_cons_printf("age 0x%08" PFMT64x "\n", addr);
			} else if (is_json) {
				char taddr[64];
				pj_o(pj);
				pj_k(pj, sdb_itoa(addr, taddr, 10));
				pj_o(pj);
				pj_k(pj, "refs");
				pj_a(pj);
				open_object = true;
			} else {
				rz_cons_printf("%s0x%08" PFMT64x "\n", pre + 2, addr);
			}
		}
	}
	rz_list_foreach (xrefs, iter, xref) {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in_bounds(core->analysis, xref->from, -1);
		if (fcn) {
			if (is_rz) {
				rz_cons_printf("agn 0x%08" PFMT64x " %s\n", fcn->addr, fcn->name);
				rz_cons_printf("age 0x%08" PFMT64x " 0x%08" PFMT64x "\n", fcn->addr, addr);
			} else if (is_json) {
				xrefs_graph_fcn_start_json(pj, fcn, xref->from);
			} else {
				rz_cons_printf("%s0x%08" PFMT64x " fcn 0x%08" PFMT64x " %s\n", pre, xref->from, fcn->addr, fcn->name);
			}
			if (ht_uu_insert(ht, fcn->addr, 1)) {
				xrefs_graph(core, fcn->addr, level + 1, ht, mode, pj);
			}
			if (is_json) {
				pj_end(pj);
				pj_end(pj);
				pj_end(pj);
			}
		} else {
			if (is_rz) {
				rz_cons_printf("agn 0x%08" PFMT64x " ???\n", xref->from);
				rz_cons_printf("age 0x%08" PFMT64x " 0x%08" PFMT64x "\n", xref->from, addr);
			} else if (is_json) {
				char taddr[64];
				pj_o(pj);
				pj_k(pj, sdb_itoa(xref->from, taddr, 10));
				pj_o(pj);
				pj_ks(pj, "type", "???");
				pj_k(pj, "refs");
				pj_a(pj);
			} else {
				rz_cons_printf("%s0x%08" PFMT64x " ???\n", pre, xref->from);
			}
			if (ht_uu_insert(ht, xref->from, 1)) {
				xrefs_graph(core, xref->from, level + 1, ht, mode, pj);
			}
			if (is_json) {
				pj_end(pj);
				pj_end(pj);
				pj_end(pj);
			}
		}
	}
	if (is_json) {
		if (open_object) {
			pj_end(pj);
			pj_end(pj);
			pj_end(pj);
		}
	}
	rz_list_free(xrefs);
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_graph_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	HtUU *ht = ht_uu_new();
	if (!ht) {
		return RZ_CMD_STATUS_ERROR;
	}
	PJ *pj = state->mode == RZ_OUTPUT_MODE_JSON ? state->d.pj : NULL;
	xrefs_graph(core, core->offset, 0, ht, state->mode, pj);
	ht_uu_free(ht);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_global_variable_xrefs_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(core->analysis, argv[1]);
	if (!glob) {
		RZ_LOG_ERROR("Global variable '%s' does not exist!\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RzList *list = rz_analysis_var_global_xrefs(core->analysis, glob);
	xrefs_to_list_handler(core, list, state);
	rz_list_free(list);
	return status;
}

#define CMD_REGS_PREFIX   analysis
#define CMD_REGS_REG_PATH analysis->reg
#define CMD_REGS_SYNC     NULL
#include "cmd_regs_meta.inc"
#undef CMD_REGS_PREFIX
#undef CMD_REGS_REG_PATH
#undef CMD_REGS_SYNC

static int RzAnalysisRef_cmp(const RzAnalysisXRef *xref1, const RzAnalysisXRef *xref2, void *user) {
	return xref1->to != xref2->to;
}

static void function_list_print_to_table(RzCore *core, RzList /*<RzAnalysisFunction *>*/ *list, RzTable *t, bool verbose) {
	RzTableColumnType *typeString = rz_table_type("string");
	RzTableColumnType *typeNumber = rz_table_type("number");
	rz_table_add_column(t, typeNumber, "addr", 0);
	rz_table_add_column(t, typeString, "name", 0);
	rz_table_add_column(t, typeNumber, "size", 0);
	rz_table_add_column(t, typeNumber, "xrefsTo", 0);
	rz_table_add_column(t, typeNumber, "xrefsFrom", 0);
	rz_table_add_column(t, typeNumber, "calls", 0);
	rz_table_add_column(t, typeNumber, "nbbs", 0);
	rz_table_add_column(t, typeNumber, "edges", 0);
	rz_table_add_column(t, typeNumber, "cc", 0);
	rz_table_add_column(t, typeNumber, "cost", 0);
	rz_table_add_column(t, rz_table_type("boolean"), "noreturn", 0);
	if (verbose) {
		rz_table_add_column(t, typeNumber, "min bound", 0);
		rz_table_add_column(t, typeNumber, "range", 0);
		rz_table_add_column(t, typeNumber, "max bound", 0);
		rz_table_add_column(t, typeNumber, "locals", 0);
		rz_table_add_column(t, typeNumber, "args", 0);
		rz_table_add_column(t, typeNumber, "frame", 0);
		rz_table_add_column(t, typeNumber, "loops", 0);
	}

	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (list, iter, fcn) {
		RzList *xrefs_to = rz_analysis_function_get_xrefs_to(fcn);
		ut32 xref_to_num = rz_list_length(xrefs_to);
		rz_list_free(xrefs_to);

		RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
		ut32 xref_from_num = rz_list_length(xrefs);
		rz_list_free(xrefs);

		RzList *calls = rz_core_analysis_fcn_get_calls(core, fcn);
		// Uniquify the list by ref->addr
		RzList *uniq_calls = rz_list_uniq(calls, (RzListComparator)RzAnalysisRef_cmp, NULL);
		ut32 calls_num = rz_list_length(uniq_calls);
		rz_list_free(uniq_calls);
		rz_list_free(calls);

		if (verbose) {
			ut32 locals = rz_analysis_var_local_count(fcn);
			ut32 args = rz_analysis_arg_count(fcn);

			rz_table_add_rowf(t, "XsndddddddbXnXdddd", fcn->addr,
				fcn->name, rz_analysis_function_realsize(fcn),
				xref_to_num, xref_from_num, calls_num,
				rz_pvector_len(fcn->bbs), rz_analysis_function_count_edges(fcn, NULL),
				rz_analysis_function_complexity(fcn), rz_analysis_function_cost(fcn),
				fcn->is_noreturn, rz_analysis_function_min_addr(fcn),
				rz_analysis_function_linear_size(fcn), rz_analysis_function_max_addr(fcn),
				locals, args, fcn->maxstack, rz_analysis_function_loops(fcn), NULL);
		} else {
			rz_table_add_rowf(t, "Xsndddddddb", fcn->addr,
				fcn->name, rz_analysis_function_realsize(fcn),
				xref_to_num, xref_from_num, calls_num,
				rz_pvector_len(fcn->bbs), rz_analysis_function_count_edges(fcn, NULL),
				rz_analysis_function_complexity(fcn), rz_analysis_function_cost(fcn),
				fcn->is_noreturn, NULL);
		}
	}
}

static void function_list_print(RzCore *core, RzList /*<RzAnalysisFunction *>*/ *list) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (list, it, fcn) {
		char *msg = NULL;
		ut64 realsize = rz_analysis_function_realsize(fcn);
		ut64 size = rz_analysis_function_linear_size(fcn);
		if (realsize == size) {
			msg = rz_str_newf("%-12" PFMT64u, size);
		} else {
			msg = rz_str_newf("%-4" PFMT64u " -> %-4" PFMT64u, size, realsize);
		}
		rz_cons_printf("0x%08" PFMT64x " %4" PFMTSZu " %4s %s\n",
			fcn->addr, rz_pvector_len(fcn->bbs), msg, fcn->name);
		free(msg);
	}
}

static void function_list_print_quiet(RZ_UNUSED RzCore *core, RzList /*<RzAnalysisFunction *>*/ *list) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (list, it, fcn) {
		rz_cons_printf("0x%08" PFMT64x " %s\n", fcn->addr, fcn->name);
	}
}

static char function_type_to_char(RzAnalysisFunction *fcn) {
	switch (fcn->type) {
	case RZ_ANALYSIS_FCN_TYPE_LOC:
		return 'l';
	case RZ_ANALYSIS_FCN_TYPE_SYM:
		return 's';
	case RZ_ANALYSIS_FCN_TYPE_IMP:
		return 'i';
	default:
		break;
	}
	return 'f';
}

static void fcn_list_bbs(RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bbi;
	void **iter;

	rz_pvector_foreach (fcn->bbs, iter) {
		bbi = (RzAnalysisBlock *)*iter;
		rz_cons_printf("afb+ 0x%08" PFMT64x " 0x%08" PFMT64x " %" PFMT64u " ",
			fcn->addr, bbi->addr, bbi->size);
		rz_cons_printf("0x%08" PFMT64x " ", bbi->jump);
		rz_cons_printf("0x%08" PFMT64x, bbi->fail);
		rz_cons_printf("\n");
	}
}

static void function_list_print_as_cmd(RzCore *core, RzList /*<RzAnalysisFunction *>*/ *list, RzCmdStateOutput *state) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (list, it, fcn) {
		const char *defaultCC = rz_analysis_cc_default(core->analysis);
		rz_cons_printf("\"f %s %" PFMT64u " @ 0x%08" PFMT64x "\"\n", fcn->name, rz_analysis_function_linear_size(fcn), fcn->addr);
		rz_cons_printf("\"af+ %s %c @ 0x%08" PFMT64x "\"\n",
			fcn->name, // rz_analysis_fcn_size (fcn), fcn->name,
			function_type_to_char(fcn),
			fcn->addr);
		// FIXME: this command prints something annoying. Does it have important side-effects?
		fcn_list_bbs(fcn);
		if (fcn->bits != 0) {
			rz_cons_printf("afB %d @ 0x%08" PFMT64x "\n", fcn->bits, fcn->addr);
		}
		// FIXME command injection vuln here
		if (fcn->cc || defaultCC) {
			rz_cons_printf("afc %s @ 0x%08" PFMT64x "\n", fcn->cc ? fcn->cc : defaultCC, fcn->addr);
		}
		/* show variables  and arguments */
		core_analysis_var_list_show(core, fcn, RZ_ANALYSIS_VAR_STORAGE_STACK, state);
		core_analysis_var_list_show(core, fcn, RZ_ANALYSIS_VAR_STORAGE_REG, state);
		/* Show references */
		RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
		xref_list_print_as_cmd(core, xrefs);
		rz_list_free(xrefs);
		/*Saving Function stack frame*/
		rz_cons_printf("afS %d @ 0x%" PFMT64x "\n", fcn->maxstack, fcn->addr);
	}
}

static void function_print_to_json(RzCore *core, RzAnalysisFunction *fcn, RzCmdStateOutput *state) {
	int ebbs = 0;
	pj_o(state->d.pj);
	pj_kn(state->d.pj, "offset", fcn->addr);
	if (fcn->name) {
		pj_ks(state->d.pj, "name", fcn->name);
	}
	pj_kn(state->d.pj, "size", rz_analysis_function_linear_size(fcn));
	pj_kb(state->d.pj, "is-pure", rz_analysis_function_purity(fcn));
	pj_kn(state->d.pj, "realsz", rz_analysis_function_realsize(fcn));
	pj_kb(state->d.pj, "noreturn", fcn->is_noreturn);
	pj_ki(state->d.pj, "stackframe", fcn->maxstack);
	if (fcn->cc) {
		pj_ks(state->d.pj, "calltype", fcn->cc); // calling conventions
	}
	pj_ki(state->d.pj, "cost", rz_analysis_function_cost(fcn)); // execution cost
	pj_ki(state->d.pj, "cc", rz_analysis_function_complexity(fcn)); // cyclic cost
	pj_ki(state->d.pj, "loops", rz_analysis_function_loops(fcn));
	pj_ki(state->d.pj, "bits", fcn->bits);
	pj_ks(state->d.pj, "type", rz_analysis_fcntype_tostring(fcn->type));
	pj_ki(state->d.pj, "nbbs", rz_pvector_len(fcn->bbs));
	pj_ki(state->d.pj, "edges", rz_analysis_function_count_edges(fcn, &ebbs));
	pj_ki(state->d.pj, "ebbs", ebbs);
	{
		char *sig = rz_core_analysis_function_signature(core, RZ_OUTPUT_MODE_STANDARD, fcn->name);
		if (sig) {
			rz_str_trim(sig);
			pj_ks(state->d.pj, "signature", sig);
			free(sig);
		}
	}
	pj_kn(state->d.pj, "minbound", rz_analysis_function_min_addr(fcn));
	pj_kn(state->d.pj, "maxbound", rz_analysis_function_max_addr(fcn));

	int outdegree = 0;
	RzListIter *iter;
	RzAnalysisXRef *xrefi;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	if (!rz_list_empty(xrefs)) {
		pj_k(state->d.pj, "callrefs");
		pj_a(state->d.pj);
		rz_list_foreach (xrefs, iter, xrefi) {
			if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_CALL) {
				outdegree++;
			}
			if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_CODE ||
				xrefi->type == RZ_ANALYSIS_XREF_TYPE_CALL) {
				xref_print_to_json(core, xrefi, state->d.pj);
			}
		}
		pj_end(state->d.pj);

		pj_k(state->d.pj, "datarefs");
		pj_a(state->d.pj);
		rz_list_foreach (xrefs, iter, xrefi) {
			if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_DATA ||
				xrefi->type == RZ_ANALYSIS_XREF_TYPE_STRING) {
				xref_print_to_json(core, xrefi, state->d.pj);
			}
		}
		pj_end(state->d.pj);
	}
	rz_list_free(xrefs);

	int indegree = 0;
	xrefs = rz_analysis_function_get_xrefs_to(fcn);
	if (!rz_list_empty(xrefs)) {
		pj_k(state->d.pj, "codexrefs");
		pj_a(state->d.pj);
		rz_list_foreach (xrefs, iter, xrefi) {
			if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_CODE ||
				xrefi->type == RZ_ANALYSIS_XREF_TYPE_CALL) {
				indegree++;
				xref_print_to_json(core, xrefi, state->d.pj);
			}
		}

		pj_end(state->d.pj);
		pj_k(state->d.pj, "dataxrefs");
		pj_a(state->d.pj);

		rz_list_foreach (xrefs, iter, xrefi) {
			if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_DATA) {
				xref_print_to_json(core, xrefi, state->d.pj);
			}
		}
		pj_end(state->d.pj);
	}
	rz_list_free(xrefs);

	pj_ki(state->d.pj, "indegree", indegree);
	pj_ki(state->d.pj, "outdegree", outdegree);

	if (fcn->type == RZ_ANALYSIS_FCN_TYPE_FCN || fcn->type == RZ_ANALYSIS_FCN_TYPE_SYM) {
		pj_kn(state->d.pj, "nlocals", rz_analysis_var_local_count(fcn));
		pj_kn(state->d.pj, "nargs", rz_analysis_arg_count(fcn));

		pj_k(state->d.pj, "stackvars");
		core_analysis_var_list_show(core, fcn, RZ_ANALYSIS_VAR_STORAGE_STACK, state);
		pj_k(state->d.pj, "regvars");
		core_analysis_var_list_show(core, fcn, RZ_ANALYSIS_VAR_STORAGE_REG, state);
	}
	pj_end(state->d.pj);
}

static void function_list_print_to_json(RzCore *core, RzList /*<RzAnalysisFunction *>*/ *list, RzCmdStateOutput *state) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	pj_a(state->d.pj);
	rz_list_foreach (list, it, fcn) {
		function_print_to_json(core, fcn, state);
	}
	pj_end(state->d.pj);
}

static int fcn_cmp_addr(const void *a, const void *b, void *user) {
	const RzAnalysisFunction *fa = a;
	const RzAnalysisFunction *fb = b;
	if (fa->addr > fb->addr) {
		return 1;
	} else if (fa->addr == fb->addr) {
		return 0;
	}
	return -1;
}

static RzList /*<RzAnalysisFunction *>*/ *functions_sorted_by_addr(RzAnalysis *analysis) {
	RzList *list = rz_analysis_function_list(analysis);
	if (!list) {
		return NULL;
	}
	RzList *sorted = rz_list_clone(list);
	if (!sorted) {
		return NULL;
	}
	rz_list_sort(sorted, fcn_cmp_addr, NULL);
	return sorted;
}

RZ_IPI RzCmdStatus rz_analysis_function_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	RzList *list = functions_sorted_by_addr(core->analysis);
	if (!list) {
		return RZ_CMD_STATUS_ERROR;
	}
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		function_list_print(core, list);
		break;
	case RZ_OUTPUT_MODE_LONG:
		rz_cmd_state_output_fini(state);
		if (rz_cmd_state_output_init(state, RZ_OUTPUT_MODE_TABLE)) {
			function_list_print_to_table(core, list, state->d.t, true);
		} else {
			res = RZ_CMD_STATUS_ERROR;
		}
		break;
	case RZ_OUTPUT_MODE_QUIET:
		function_list_print_quiet(core, list);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		function_list_print_as_cmd(core, list, state);
		break;
	case RZ_OUTPUT_MODE_JSON:
		function_list_print_to_json(core, list, state);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		function_list_print_to_table(core, list, state->d.t, false);
		break;
	default:
		rz_warn_if_reached();
		res = RZ_CMD_STATUS_WRONG_ARGS;
		break;
	}
	rz_list_free(list);
	return res;
}

RZ_IPI RzCmdStatus rz_analysis_function_list_in_handler(RzCore *core, int argc, const char **argv) {
	RzList *list = rz_analysis_get_functions_in(core->analysis, core->offset);
	function_list_print_quiet(core, list);
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_count_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", rz_list_length(core->analysis->fcns));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_size_sum_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn;
	RzListIter *iter;
	ut64 total = 0;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		total += rz_analysis_function_realsize(fcn);
	}
	rz_cons_printf("%" PFMT64u "\n", total);
	return RZ_CMD_STATUS_OK;
}

// Lists function names and their calls (uniqified)
static void function_print_calls(RzCore *core, RzList /*<RzAnalysisFunction *>*/ *fcns, RzCmdStateOutput *state) {
	PJ *pj = state->d.pj;
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}

	RzListIter *fcniter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (fcns, fcniter, fcn) {
		// Get all refs for a function
		RzList *xrefs = rz_core_analysis_fcn_get_calls(core, fcn);
		// Uniquify the list by ref->addr
		RzList *uniq_xrefs = rz_list_uniq(xrefs, (RzListComparator)RzAnalysisRef_cmp, NULL);

		// don't enter for functions with 0 refs
		if (!rz_list_empty(uniq_xrefs)) {
			if (state->mode == RZ_OUTPUT_MODE_JSON) { // begin json output of function
				pj_o(pj);
				pj_ks(pj, "name", fcn->name);
				pj_kn(pj, "addr", fcn->addr);
				pj_k(pj, "calls");
				pj_a(pj);
			} else {
				rz_cons_printf("%s", fcn->name);
			}

			if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
				rz_cons_printf(":\n");
			} else if (state->mode == RZ_OUTPUT_MODE_QUIET) {
				rz_cons_printf(" -> ");
			}

			RzListIter *refiter;
			RzAnalysisXRef *xrefi;
			rz_list_foreach (uniq_xrefs, refiter, xrefi) {
				RzFlagItem *f = rz_flag_get_i(core->flags, xrefi->to);
				char *dst = rz_str_newf((f ? f->name : "0x%08" PFMT64x), xrefi->to);
				if (state->mode == RZ_OUTPUT_MODE_JSON) { // Append calee json item
					pj_o(pj);
					pj_ks(pj, "name", dst);
					pj_kn(pj, "addr", xrefi->from);
					pj_end(pj); // close referenced item
				} else if (state->mode == RZ_OUTPUT_MODE_QUIET) {
					rz_cons_printf("%s ", dst);
				} else {
					rz_cons_printf("    %s\n", dst);
				}
				free(dst);
			}
			if (state->mode == RZ_OUTPUT_MODE_JSON) {
				pj_end(pj); // close list of calls
				pj_end(pj); // close function item
			} else {
				rz_cons_newline();
			}
		}
		rz_list_free(xrefs);
		rz_list_free(uniq_xrefs);
	}

	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
	}
}

RZ_IPI RzCmdStatus rz_analysis_function_list_calls_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	RzList *list = functions_sorted_by_addr(core->analysis);
	if (!list) {
		return RZ_CMD_STATUS_ERROR;
	}
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
	case RZ_OUTPUT_MODE_QUIET:
	case RZ_OUTPUT_MODE_JSON:
		function_print_calls(core, list, state);
		break;
	default:
		rz_warn_if_reached();
		res = RZ_CMD_STATUS_WRONG_ARGS;
		break;
	}
	rz_list_free(list);
	return res;
}

RZ_IPI RzCmdStatus rz_analysis_function_list_ascii_handler(RzCore *core, int argc, const char **argv) {
	RzList *fcns = functions_sorted_by_addr(core->analysis);
	if (!fcns) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzList *flist = rz_list_newf((RzListFree)rz_listinfo_free);
	if (!flist) {
		rz_list_free(fcns);
		return RZ_CMD_STATUS_ERROR;
	}
	char temp[32];
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (fcns, iter, fcn) {
		RzInterval inter = { rz_analysis_function_min_addr(fcn), rz_analysis_function_linear_size(fcn) };
		RzListInfo *info = rz_listinfo_new(fcn->name, inter, inter, -1, rz_strf(temp, "%d", fcn->bits));
		if (!info) {
			break;
		}
		rz_list_append(flist, info);
	}
	RzTable *table = rz_core_table(core);
	rz_table_visual_list(table, flist, core->offset, core->blocksize,
		rz_cons_get_size(NULL), rz_config_get_i(core->config, "scr.color"));
	char *tablestr = rz_table_tostring(table);
	rz_cons_printf("\n%s\n", tablestr);
	free(tablestr);
	rz_table_free(table);
	rz_list_free(flist);
	rz_list_free(fcns);
	return RZ_CMD_STATUS_OK;
}

static void fcn_print_trace_info(RzDebugTrace *traced, RzAnalysisFunction *fcn) {
	int tag = traced->tag;
	RzListIter *iter;
	RzDebugTracepoint *trace;

	rz_list_foreach (traced->traces, iter, trace) {
		if (!trace->tag || (tag & trace->tag)) {
			if (rz_analysis_function_contains(fcn, trace->addr)) {
				rz_cons_printf("traced: %d\n", trace->times);
				return;
			}
		}
	}
}

static void fcn_print_info(RzCore *core, RzAnalysisFunction *fcn, RzCmdStateOutput *state) {
	RzListIter *iter;
	RzAnalysisXRef *xrefi;
	int ebbs = 0;

	rz_cons_printf("offset: 0x%08" PFMT64x "\nname: %s\nsize: %" PFMT64u "\n",
		fcn->addr, fcn->name, rz_analysis_function_linear_size(fcn));
	rz_cons_printf("is-pure: %s\n", rz_str_bool(rz_analysis_function_purity(fcn)));
	rz_cons_printf("realsz: %" PFMT64d "\n", rz_analysis_function_realsize(fcn));
	rz_cons_printf("stackframe: %d\n", fcn->maxstack);
	if (fcn->cc) {
		rz_cons_printf("call-convention: %s\n", fcn->cc);
	}
	rz_cons_printf("cyclomatic-cost: %d\n", rz_analysis_function_cost(fcn));
	rz_cons_printf("cyclomatic-complexity: %d\n", rz_analysis_function_complexity(fcn));
	rz_cons_printf("loops: %d\n", rz_analysis_function_loops(fcn));
	rz_cons_printf("bits: %d\n", fcn->bits);
	rz_cons_printf("type: %s\n", rz_analysis_fcntype_tostring(fcn->type));
	rz_cons_printf("num-bbs: %" PFMTSZu "\n", rz_pvector_len(fcn->bbs));
	rz_cons_printf("edges: %d\n", rz_analysis_function_count_edges(fcn, &ebbs));
	rz_cons_printf("end-bbs: %d\n", ebbs);
	rz_cons_printf("call-refs:");
	int outdegree = 0;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	rz_list_foreach (xrefs, iter, xrefi) {
		if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_CALL) {
			outdegree++;
		}
		if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_CODE || xrefi->type == RZ_ANALYSIS_XREF_TYPE_CALL) {
			rz_cons_printf(" 0x%08" PFMT64x " %c", xrefi->to,
				xrefi->type == RZ_ANALYSIS_XREF_TYPE_CALL ? 'C' : 'J');
		}
	}
	rz_cons_printf("\ndata-refs:");
	rz_list_foreach (xrefs, iter, xrefi) {
		// global or local?
		if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_DATA) {
			rz_cons_printf(" 0x%08" PFMT64x, xrefi->to);
		}
	}
	rz_list_free(xrefs);

	int indegree = 0;
	rz_cons_printf("\ncode-xrefs:");
	xrefs = rz_analysis_function_get_xrefs_to(fcn);
	rz_list_foreach (xrefs, iter, xrefi) {
		if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_CODE || xrefi->type == RZ_ANALYSIS_XREF_TYPE_CALL) {
			indegree++;
			rz_cons_printf(" 0x%08" PFMT64x " %c", xrefi->from,
				xrefi->type == RZ_ANALYSIS_XREF_TYPE_CALL ? 'C' : 'J');
		}
	}
	rz_cons_printf("\nnoreturn: %s\n", rz_str_bool(fcn->is_noreturn));
	rz_cons_printf("in-degree: %d\n", indegree);
	rz_cons_printf("out-degree: %d\n", outdegree);
	rz_cons_printf("data-xrefs:");
	rz_list_foreach (xrefs, iter, xrefi) {
		if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_DATA) {
			rz_cons_printf(" 0x%08" PFMT64x, xrefi->from);
		}
	}
	rz_list_free(xrefs);
	rz_cons_printf("\n");

	if (fcn->type == RZ_ANALYSIS_FCN_TYPE_FCN || fcn->type == RZ_ANALYSIS_FCN_TYPE_SYM) {
		ut32 args_count = rz_analysis_arg_count(fcn);
		ut32 var_count = rz_analysis_var_local_count(fcn);

		rz_cons_printf("locals: %u\nargs: %u\n", var_count, args_count);
		core_analysis_var_list_show(core, fcn, RZ_ANALYSIS_VAR_STORAGE_REG, state);
		core_analysis_var_list_show(core, fcn, RZ_ANALYSIS_VAR_STORAGE_STACK, state);
	}

	// traced
	if (core->dbg->trace->enabled) {
		fcn_print_trace_info(core->dbg->trace, fcn);
	}
}

static void fcn_list_print_info(RzCore *core, RzList /*<RzAnalysisFunction *>*/ *fcns, RzCmdStateOutput *state) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	bool next = false;
	rz_list_foreach (fcns, iter, fcn) {
		if (next) {
			rz_cons_printf("#\n");
		}
		fcn_print_info(core, fcn, state);
		next = true;
	}
}

RZ_IPI RzCmdStatus rz_analysis_function_info_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	RzList *list = rz_analysis_get_functions_in(core->analysis, core->offset);
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		fcn_list_print_info(core, list, state);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		function_list_print_as_cmd(core, list, state);
		break;
	case RZ_OUTPUT_MODE_JSON:
		function_list_print_to_json(core, list, state);
		break;
	default:
		rz_warn_if_reached();
		res = RZ_CMD_STATUS_WRONG_ARGS;
		break;
	}
	rz_list_free(list);
	return res;
}

RZ_IPI RzCmdStatus rz_analysis_function_import_list_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc == 2) {
		if (!fcn->imports) {
			fcn->imports = rz_list_newf((RzListFree)free);
			if (!fcn->imports) {
				return RZ_CMD_STATUS_ERROR;
			}
		}
		char *import = rz_str_dup(argv[1]);
		if (!import || !rz_list_append(fcn->imports, import)) {
			free(import);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		char *imp;
		RzListIter *iter;
		rz_list_foreach (fcn->imports, iter, imp) {
			rz_cons_printf("%s\n", imp);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_import_list_del_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_list_free(fcn->imports);
	fcn->imports = NULL;
	return RZ_CMD_STATUS_OK;
}

static void ht_inc(HtSU *ht, const char *key) {
	bool found;
	HtSUKv *kv = ht_su_find_kv(ht, key, &found);
	if (kv) {
		kv->value++;
	} else {
		ht_su_insert(ht, key, 1);
	}
}

enum STATS_MODE {
	STATS_MODE_DEF,
	STATS_MODE_FML,
	STATS_MODE_TYPE
};

static void update_stat_for_op(RzCore *core, HtSU *ht, ut64 addr, int mode) {
	RzAnalysisOp *op = rz_core_analysis_op(core, addr, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT | RZ_ANALYSIS_OP_MASK_DISASM);
	if (!op) {
		return;
	}
	RzStrBuf buf;
	const char *key;
	rz_strbuf_init(&buf);
	if (mode == STATS_MODE_FML) {
		key = rz_analysis_op_family_to_string(op->family);
	} else if (mode == STATS_MODE_TYPE) {
		key = rz_analysis_optype_to_string(op->type);
	} else {
		char *sp = strchr(op->mnemonic, ' ');
		if (sp) {
			rz_strbuf_setbin(&buf, (ut8 *)op->mnemonic, sp - op->mnemonic);
		} else {
			rz_strbuf_set(&buf, op->mnemonic);
		}
		key = rz_strbuf_get(&buf);
	}
	ht_inc(ht, key);
	rz_strbuf_fini(&buf);
	rz_analysis_op_free(op);
}

static void gather_opcode_stat_for_fcn(RzCore *core, HtSU *ht, RzAnalysisFunction *fcn, int mode) {
	void **iter;
	RzAnalysisBlock *bb;
	rz_pvector_foreach (fcn->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
		update_stat_for_op(core, ht, bb->addr, mode);
		for (int i = 0; i < bb->op_pos_size; i++) {
			ut16 op_pos = bb->op_pos[i];
			update_stat_for_op(core, ht, bb->addr + op_pos, mode);
		}
	}
}

static bool list_keys_cb(RzList /*<char *>*/ *list, char *k, RZ_UNUSED ut64 v) {
	rz_list_push(list, k);
	return true;
}

static void print_stats(RzCore *core, HtSU *ht, RzAnalysisFunction *fcn, RzCmdStateOutput *state) {
	const char *name;
	RzListIter *iter;
	RzList *list = rz_list_newf(NULL);
	ht_su_foreach(ht, (HtSUForeachCallback)list_keys_cb, list);
	rz_list_sort(list, (RzListComparator)strcmp, NULL);
	if (state->mode == RZ_OUTPUT_MODE_TABLE) {
		RzTable *t = state->d.t;
		RzTableColumnType *typeString = rz_table_type("string");
		RzTableColumnType *typeNumber = rz_table_type("number");
		rz_table_add_column(t, typeString, "name", 0);
		rz_list_foreach (list, iter, name) {
			rz_table_add_column(t, typeNumber, name, 0);
		}
		RzPVector *items = rz_pvector_new(free);
		if (!items) {
			RZ_LOG_ERROR("Failed to allocate memory.\n");
			rz_list_free(list);
			return;
		}
		rz_pvector_push(items, rz_str_dup(fcn->name));
		rz_list_foreach (list, iter, name) {
			int nv = (int)ht_su_find(ht, name, NULL);
			rz_pvector_push(items, rz_str_newf("%d", nv));
		}
		rz_table_add_row_vec(t, items);
	} else {
		rz_list_foreach (list, iter, name) {
			ut32 nv = (ut32)ht_su_find(ht, name, NULL);
			rz_cons_printf("%4u %s\n", nv, name);
		}
	}
	rz_list_free(list);
}

RZ_IPI RzCmdStatus rz_analysis_function_opcode_stat_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int mode = STATS_MODE_DEF;
	if (argc > 1) {
		mode = !strcmp(argv[1], "family") ? STATS_MODE_FML : STATS_MODE_TYPE;
	}
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	HtSU *ht = ht_su_new(HT_STR_DUP);
	if (!ht) {
		return RZ_CMD_STATUS_ERROR;
	}
	gather_opcode_stat_for_fcn(core, ht, fcn, mode);
	print_stats(core, ht, fcn, state);
	ht_su_free(ht);
	return RZ_CMD_STATUS_OK;
}

static bool add_keys_to_set_cb(HtSU *ht, const char *k, RZ_UNUSED const ut64 v) {
	if (strcmp(k, ".addr")) {
		ht_su_insert(ht, k, 1);
	}
	return true;
}

RZ_IPI RzCmdStatus rz_analysis_function_all_opcode_stat_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (state->mode != RZ_OUTPUT_MODE_TABLE) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzCmdStatus res = RZ_CMD_STATUS_ERROR;
	int mode = STATS_MODE_DEF;
	if (argc > 1) {
		mode = !strcmp(argv[1], "family") ? STATS_MODE_FML : STATS_MODE_TYPE;
	}
	RzList *keys = rz_list_newf(NULL);
	HtSU *keys_set = ht_su_new(HT_STR_DUP);
	RzList *dbs = rz_list_newf((RzListFree)ht_pu_free);
	if (!keys || !keys_set || !dbs) {
		goto exit;
	}

	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		HtSU *db = ht_su_new(HT_STR_DUP);
		if (!db) {
			break;
		}
		gather_opcode_stat_for_fcn(core, db, fcn, mode);
		ht_su_insert(db, ".addr", fcn->addr);
		rz_list_append(dbs, db);
	}

	HtSU *db;
	rz_list_foreach (dbs, iter, db) {
		ht_su_foreach(db, (HtSUForeachCallback)add_keys_to_set_cb, keys_set);
	}

	ht_su_foreach(keys_set, (HtSUForeachCallback)list_keys_cb, keys);
	rz_list_sort(keys, (RzListComparator)strcmp, NULL);

	RzTable *t = state->d.t;
	RzTableColumnType *typeString = rz_table_type("string");
	RzTableColumnType *typeNumber = rz_table_type("number");
	rz_table_add_column(t, typeString, "name", 0);
	rz_table_add_column(t, typeNumber, "addr", 0);

	char *key;
	rz_list_foreach (keys, iter, key) {
		rz_table_add_column(t, typeNumber, key, 0);
	}

	RzListIter *iter2;
	rz_list_foreach (dbs, iter2, db) {
		RzPVector *items = rz_pvector_new(free);
		if (!items) {
			break;
		}
		ut64 fcnAddr = ht_su_find(db, ".addr", NULL);
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, fcnAddr);
		rz_pvector_push(items, fcn ? rz_str_dup(fcn->name) : rz_str_dup(""));
		rz_pvector_push(items, fcn ? rz_str_newf("0x%08" PFMT64x, fcnAddr) : rz_str_dup("0"));
		rz_list_foreach (keys, iter, key) {
			ut32 n = (ut32)ht_su_find(db, key, NULL);
			rz_pvector_push(items, rz_str_newf("%u", n));
		}
		rz_table_add_row_vec(t, items);
	}
	res = RZ_CMD_STATUS_OK;
exit:
	rz_list_free(keys);
	rz_list_free(dbs);
	ht_su_free(keys_set);
	return res;
}

RZ_IPI RzCmdStatus rz_analysis_function_rename_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_analysis_function_rename(core, core->offset, argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_analysis_function_autoname_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	char *name = rz_core_analysis_function_autoname(core, fcn);
	if (!name) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%s\n", name);
	free(name);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_strings_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	PJ *pj = state->mode == RZ_OUTPUT_MODE_JSON ? state->d.pj : NULL;
	rz_core_analysis_function_strings_print(core, fcn, pj);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_type_matching_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 seek = core->offset;
	rz_analysis_esil_set_pc(core->analysis->esil, fcn->addr);
	rz_core_analysis_type_match(core, fcn, NULL);
	rz_core_seek(core, seek, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_functions_map_handler(RzCore *core, int argc, const char **argv) {
	int show_color = rz_config_get_i(core->config, "scr.color");
	int cols = rz_config_get_i(core->config, "hex.cols") * 4;
	ut64 code_size = rz_num_get(core->num, "$SS");
	ut64 base_addr = rz_num_get(core->num, "$S");

	if (code_size < 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	char *bitmap = calloc(1, code_size + 64);
	if (!bitmap) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzListIter *iter;
	void **vit;
	RzAnalysisFunction *fcn;
	RzAnalysisBlock *b;
	// for each function
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		// for each basic block in the function
		rz_pvector_foreach (fcn->bbs, vit) {
			b = (RzAnalysisBlock *)*vit;
			// if it is not within range, continue
			if ((fcn->addr < base_addr) || (fcn->addr >= base_addr + code_size)) {
				continue;
			}
			// otherwise mark each byte in the BB in the bitmap
			int counter = 1;
			for (counter = 0; counter < b->size; counter++) {
				bitmap[b->addr + counter - base_addr] = '=';
			}
			bitmap[fcn->addr - base_addr] = 'F';
		}
	}
	// print the bitmap
	int assigned = 0;
	if (cols < 1) {
		cols = 1;
	}
	for (ut64 i = 0; i < code_size; i += 1) {
		if (!(i % cols)) {
			rz_cons_printf("\n0x%08" PFMT64x "  ", base_addr + i);
		}
		if (bitmap[i]) {
			assigned++;
		}
		if (show_color) {
			if (bitmap[i]) {
				rz_cons_printf("%s%c\x1b[0m", Color_GREEN, bitmap[i]);
			} else {
				rz_cons_printf(".");
			}
		} else {
			rz_cons_printf("%c", bitmap[i] ? bitmap[i] : '.');
		}
	}
	rz_cons_printf("\n%d / %" PFMT64u " (%.2lf%%) bytes assigned to a function\n", assigned, code_size, 100.0 * ((float)assigned) / code_size);
	free(bitmap);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_functions_merge_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = rz_num_math(core->num, argv[1]);
	rz_core_analysis_fcn_merge(core, core->offset, addr);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_cc_set_get_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc == 1) {
		rz_cons_println(fcn->cc);
		return RZ_CMD_STATUS_OK;
	}
	if (!rz_analysis_cc_exist(core->analysis, argv[1])) {
		RZ_LOG_ERROR("Unknown calling convention. See `afcl` for available ones.\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	fcn->cc = rz_str_constpool_get(&core->analysis->constpool, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_cc_list_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	rz_core_types_calling_conventions_print(core, mode);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_cc_load_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_file_exists(argv[1])) {
		RZ_LOG_ERROR("File \"%s\" does not exist\n", argv[1]);
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	Sdb *db = sdb_new(0, argv[1], 0);
	if (!db) {
		return RZ_CMD_STATUS_ERROR;
	}
	sdb_merge(core->analysis->sdb_cc, db);
	sdb_close(db);
	sdb_free(db);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_cc_reg_usage_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	PJ *pj = state->mode == RZ_OUTPUT_MODE_JSON ? state->d.pj : NULL;
	rz_core_analysis_cc_print(core, fcn->cc, pj);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_describe_offset_handler(RzCore *core, int argc, const char **argv) {
	RzList *list = rz_analysis_get_functions_in(core->analysis, core->offset);
	if (rz_list_empty(list)) {
		RZ_LOG_ERROR("No function found in 0x%08" PFMT64x ".\n", core->offset);
		rz_list_free(list);
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (list, it, fcn) {
		st64 delta = core->offset - fcn->addr;
		if (delta > 0) {
			rz_cons_printf("%s + %" PFMT64d "\n", fcn->name, delta);
		} else if (delta < 0) {
			rz_cons_printf("%s - %" PFMT64d "\n", fcn->name, -delta);
		} else {
			rz_cons_printf("%s\n", fcn->name);
		}
	}
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_add_nodepth_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_fcn(core, core->offset, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_add_recu_handler(RzCore *core, int argc, const char **argv) {
	const char *name = argc == 2 ? argv[1] : NULL;
	bool analyze_recursively = true;
	if (!strcmp(argv[0], "af")) {
		analyze_recursively = rz_config_get_b(core->config, "analysis.calls");
	}
	return bool2status(rz_core_analysis_function_add(core, name, core->offset, analyze_recursively));
}

RZ_IPI RzCmdStatus rz_analysis_function_create_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFcnType type = RZ_ANALYSIS_FCN_TYPE_FCN;
	if (argc >= 3) {
		switch (argv[2][0]) {
		case 'l':
			type = RZ_ANALYSIS_FCN_TYPE_LOC;
			break;
		case 'i':
			type = RZ_ANALYSIS_FCN_TYPE_IMP;
			break;
		case 's':
			type = RZ_ANALYSIS_FCN_TYPE_SYM;
			break;
		default:
			break;
		}
	}
	RzAnalysisFunction *fcn = rz_analysis_create_function(core->analysis, argv[1], core->offset, type);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot add function (duplicated)\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_del_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *f = analysis_get_function_in(core->analysis, core->offset);
	if (!f) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 addr = f->addr;
	rz_core_analysis_undefine(core, addr);
	rz_analysis_fcn_del_locs(core->analysis, addr);
	rz_analysis_fcn_del(core->analysis, addr);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_del_all_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *f;
	RzListIter *iter, *iter_tmp;
	rz_list_foreach_safe (core->analysis->fcns, iter, iter_tmp, f) {
		rz_analysis_del_jmprefs(core->analysis, f);
		rz_core_analysis_undefine(core, f->addr);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_analyze_jmptable_handler(RzCore *core, int argc, const char **argv) {
	RzList *blocks = rz_analysis_get_blocks_in(core->analysis, core->offset);
	if (!blocks) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisBlock *block = rz_list_first(blocks);
	if (block && !rz_list_empty(block->fcns)) {
		ut64 table = rz_num_math(core->num, argv[1]);
		ut64 elements = rz_num_math(core->num, argv[2]);
		RzStackAddr sp = rz_analysis_block_get_sp_at(block, core->offset);
		rz_analysis_jmptbl(core->analysis, rz_list_first(block->fcns), block, core->offset, table, elements, UT64_MAX, sp);
	} else {
		RZ_LOG_ERROR("No function defined here\n");
	}
	rz_list_free(blocks);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_analyze_args_handler(RzCore *core, int argc, const char **argv) {
	if (!strcmp(argv[0], "afa") || rz_config_get_b(core->config, "dbg.funcarg")) {
		rz_core_print_func_args(core);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_il_vm_initialize_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_il_reinit(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_il_vm_step_handler(RzCore *core, int argc, const char **argv) {
	ut64 repeat_times = argc == 1 ? 1 : rz_num_math(NULL, argv[1]);
	rz_core_il_step(core, repeat_times);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_il_vm_step_with_events_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut64 repeat_times = argc == 1 ? 1 : rz_num_math(NULL, argv[1]);
	PJ *pj = NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj = pj_new();
		if (!pj) {
			RZ_LOG_ERROR("cannot allocate PJ.\n");
			return RZ_CMD_STATUS_ERROR;
		}
		pj_a(pj);
	}
	for (ut64 i = 0; i < repeat_times; ++i) {
		if (!rz_core_analysis_il_step_with_events(core, pj)) {
			break;
		}
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_il_vm_step_until_addr_handler(RzCore *core, int argc, const char **argv) {
	ut64 address = rz_num_math(core->num, argv[1]);
	rz_core_il_step_until(core, address);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_il_vm_step_until_addr_with_events_handler(RzCore *core, int argc, const char **argv) {
	ut64 address = rz_num_math(core->num, argv[1]);
	rz_core_il_step_until_with_events(core, address);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_il_vm_status_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc == 3) {
		ut64 value = rz_num_math(core->num, argv[2]);
		if (rz_core_analysis_il_vm_set(core, argv[1], value)) {
			rz_cons_printf("%s = 0x%" PFMT64x "\n", argv[1], value);
		}
	} else {
		// print variable or all variables
		rz_core_analysis_il_vm_status(core, argc == 2 ? argv[1] : NULL, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI char **rz_analysis_graph_format_choices(RzCore *core) {
	static const char *formats[] = {
		"ascii", "cmd", "dot", "gml", "json", "json_disasm", "sdb", "interactive", NULL
	};
	const ut8 sz = RZ_ARRAY_SIZE(formats);
	char **res = malloc(sizeof(char *) * sz);
	if (!res) {
		return NULL;
	}
	for (ut8 i = 0; i < sz - 1; ++i) {
		res[i] = rz_str_dup(formats[i]);
	}
	res[sz - 1] = NULL;
	return res;
}

RZ_IPI RzCmdStatus rz_analysis_graph_dataref_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, core->offset, RZ_CORE_GRAPH_TYPE_DATAREF, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_dataref_global_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, UT64_MAX, RZ_CORE_GRAPH_TYPE_DATAREF, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_callgraph_function_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, core->offset, RZ_CORE_GRAPH_TYPE_FUNCALL, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_callgraph_global_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, UT64_MAX, RZ_CORE_GRAPH_TYPE_FUNCALL, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_bb_function_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, core->offset, RZ_CORE_GRAPH_TYPE_BLOCK_FUN, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_imports_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, UT64_MAX, RZ_CORE_GRAPH_TYPE_IMPORT, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_refs_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, core->offset, RZ_CORE_GRAPH_TYPE_REF, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_refs_global_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, UT64_MAX, RZ_CORE_GRAPH_TYPE_REF, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_normal_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, core->offset, RZ_CORE_GRAPH_TYPE_NORMAL, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_line_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, core->offset, RZ_CORE_GRAPH_TYPE_LINE, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_xrefs_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, core->offset, RZ_CORE_GRAPH_TYPE_XREF, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_il_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, core->offset, RZ_CORE_GRAPH_TYPE_IL, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_icfg_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, core->offset, RZ_CORE_GRAPH_TYPE_ICFG, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_cfg_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_graph_print(core, core->offset, RZ_CORE_GRAPH_TYPE_CFG, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_custom_handler(RzCore *core, int argc, const char **argv) {
	const RzCoreGraphFormat format = rz_core_graph_format_from_string(argv[1]);
	return bool2status(rz_core_agraph_print(core, format));
}

RZ_IPI RzCmdStatus rz_analysis_graph_write_handler(RzCore *core, int argc, const char **argv) {
	if (RZ_STR_ISEMPTY(argv[1]) || RZ_STR_ISEMPTY(argv[2])) {
		return RZ_CMD_STATUS_ERROR;
	}
	const RzCoreGraphType graph_type = rz_core_graph_type_from_string(argv[1]);
	const char *path = argv[2];
	const bool global = argc > 3 ? strcmp(argv[3], "-global") == 0 || strcmp(argv[3], "-g") == 0 : false;
	return bool2status(rz_core_graph_write(core, global ? UT64_MAX : core->offset, graph_type, path));
}

RZ_IPI RzCmdStatus rz_analysis_graph_custom_clear_handler(RzCore *core, int argc, const char **argv) {
	rz_core_agraph_reset(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_graph_custom_node_add_handler(RzCore *core, int argc, const char **argv) {
	const char *body = argc > 2 ? argv[2] : "";
	rz_core_agraph_add_node(core, argv[1], body);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_graph_custom_node_remove_handler(RzCore *core, int argc, const char **argv) {
	rz_core_agraph_del_node(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_graph_custom_edge_add_handler(RzCore *core, int argc, const char **argv) {
	rz_core_agraph_add_edge(core, argv[1], argv[2]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_graph_custom_edge_remove_handler(RzCore *core, int argc, const char **argv) {
	rz_core_agraph_del_edge(core, argv[1], argv[2]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_analysis_hint_list_print(core->analysis, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_list_at_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_analysis_hint_print(core->analysis, core->offset, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = 1;
	if (argc == 2) {
		size = rz_num_math(core->num, argv[1]);
	}
	rz_analysis_hint_del(core->analysis, core->offset, size);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_all_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_clear(core->analysis);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_arch_handler(RzCore *core, int argc, const char **argv) {
	const char *arch = !strcmp(argv[1], "0") ? NULL : argv[1];
	rz_analysis_hint_set_arch(core->analysis, core->offset, arch);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_arch_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_arch(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_bits_handler(RzCore *core, int argc, const char **argv) {
	ut64 bits = rz_num_math(core->num, argv[1]);
	rz_analysis_hint_set_bits(core->analysis, core->offset, bits);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_bits_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_bits(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_high_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_set_high(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_high_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_high(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_jump_handler(RzCore *core, int argc, const char **argv) {
	ut64 jump = rz_num_math(core->num, argv[1]);
	rz_analysis_hint_set_jump(core->analysis, core->offset, jump);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_jump_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_jump(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_esil_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_set_esil(core->analysis, core->offset, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_esil_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_esil(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_opcode_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_set_opcode(core->analysis, core->offset, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_opcode_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_opcode(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_size_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = rz_num_math(core->num, argv[1]);
	rz_analysis_hint_set_size(core->analysis, core->offset, size);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_size_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_size(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_fail_handler(RzCore *core, int argc, const char **argv) {
	ut64 fail = rz_num_math(core->num, argv[1]);
	rz_analysis_hint_set_fail(core->analysis, core->offset, fail);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_fail_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_fail(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_stackframe_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = rz_num_math(core->num, argv[1]);
	rz_analysis_hint_set_stackframe(core->analysis, core->offset, size);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_stackframe_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_stackframe(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_syntax_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_set_syntax(core->analysis, core->offset, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_syntax_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_syntax(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_ptr_handler(RzCore *core, int argc, const char **argv) {
	ut64 ptr = rz_num_math(core->num, argv[1]);
	rz_analysis_hint_set_pointer(core->analysis, core->offset, ptr);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_ptr_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_pointer(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_ret_handler(RzCore *core, int argc, const char **argv) {
	ut64 ret = rz_num_math(core->num, argv[1]);
	rz_analysis_hint_set_ret(core->analysis, core->offset, ret);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_ret_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_ret(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_val_handler(RzCore *core, int argc, const char **argv) {
	ut64 val = rz_num_math(core->num, argv[1]);
	rz_analysis_hint_set_val(core->analysis, core->offset, val);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_val_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_val(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_optype_handler(RzCore *core, int argc, const char **argv) {
	int type = rz_analysis_optype_from_string(argv[1]);
	if (type < 0) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	rz_analysis_hint_set_type(core->analysis, core->offset, type);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_optype_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_type(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_immbase_handler(RzCore *core, int argc, const char **argv) {
	int base = rz_num_base_of_string(core->num, argv[1]);
	if (argc == 3) {
		ut64 nword = rz_num_math(core->num, argv[2]);
		rz_analysis_hint_set_nword(core->analysis, core->offset, (int)(nword));
	}
	rz_analysis_hint_set_immbase(core->analysis, core->offset, base);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_immbase_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_immbase(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_hint_set_offset_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_analysis_hint_set_offset(core, argv[1]));
}

RZ_IPI RzCmdStatus rz_analysis_hint_del_offset_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_hint_unset_offset(core->analysis, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_list_struct_offsets_handler(RzCore *core, int argc, const char **argv) {
	ut64 toff = rz_num_math(core->num, argv[1]);
	if (!toff) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	RzList *typeoffs = rz_type_db_get_by_offset(core->analysis->typedb, toff);
	RzListIter *iter;
	RzTypePath *ty;
	// We only print type paths here
	rz_list_foreach (typeoffs, iter, ty) {
		rz_cons_printf("%s\n", ty->path);
	}
	rz_list_free(typeoffs);
	return RZ_CMD_STATUS_OK;
}

static void analysis_class_print(RzAnalysis *analysis, const char *class_name, bool detailed) {
	rz_cons_printf("[%s", class_name);

	RzVector *bases = rz_analysis_class_base_get_all(analysis, class_name);
	if (bases) {
		RzAnalysisBaseClass *base;
		bool first = true;
		rz_vector_foreach (bases, base) {
			if (first) {
				rz_cons_print(": ");
				first = false;
			} else {
				rz_cons_print(", ");
			}
			rz_cons_print(base->class_name);
		}
		rz_vector_free(bases);
	}

	rz_cons_print("]\n");

	if (detailed) {
		RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);
		if (vtables) {
			RzAnalysisVTable *vtable;
			rz_vector_foreach (vtables, vtable) {
				rz_cons_printf("  (vtable at 0x%" PFMT64x, vtable->addr);
				if (vtable->offset > 0) {
					rz_cons_printf(" in class at +0x%" PFMT64x ")\n", vtable->offset);
				} else {
					rz_cons_print(")\n");
				}
			}
			rz_vector_free(vtables);
		}

		RzVector *methods = rz_analysis_class_method_get_all(analysis, class_name);
		if (methods && rz_vector_len(methods) > 0) {
			RzTable *table = rz_table_new();
			rz_table_set_columnsf(table, "dXXss", "nth", "addr", "vt_offset", "type", "name");
			rz_table_align(table, 2, RZ_TABLE_ALIGN_RIGHT);
			char *method_type[] = { "DEFAULT", "VIRTUAL", "V_DESTRUCTOR", "DESTRUCTOR", "CONSTRUCTOR" };
			RzAnalysisMethod *meth;
			int i = 1;
			rz_vector_foreach (methods, meth) {
				ut64 vtable = meth->vtable_offset >= 0 ? meth->vtable_offset : UT64_MAX;
				rz_table_add_rowf(table, "dXXss", i, meth->addr, vtable, method_type[meth->method_type], meth->real_name);
				i++;
			}
			char *s = rz_table_tostring(table);
			rz_cons_printf("%s\n", s);
			free(s);
			rz_table_free(table);
		}
		rz_vector_free(methods);
	}
}

static void analysis_class_print_to_json(RzAnalysis *analysis, PJ *pj, const char *class_name) {
	pj_o(pj);
	pj_ks(pj, "name", class_name);

	pj_k(pj, "bases");
	pj_a(pj);
	RzVector *bases = rz_analysis_class_base_get_all(analysis, class_name);
	if (bases) {
		RzAnalysisBaseClass *base;
		rz_vector_foreach (bases, base) {
			pj_o(pj);
			pj_ks(pj, "id", base->id);
			pj_ks(pj, "name", base->class_name);
			pj_kn(pj, "offset", base->offset);
			pj_end(pj);
		}
		rz_vector_free(bases);
	}
	pj_end(pj);

	pj_k(pj, "vtables");
	pj_a(pj);
	RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);
	if (vtables) {
		RzAnalysisVTable *vtable;
		rz_vector_foreach (vtables, vtable) {
			pj_o(pj);
			pj_ks(pj, "id", vtable->id);
			pj_kn(pj, "addr", vtable->addr);
			pj_kn(pj, "offset", vtable->offset);
			pj_end(pj);
		}
	}
	pj_end(pj);

	pj_k(pj, "methods");
	pj_a(pj);
	RzVector *methods = rz_analysis_class_method_get_all(analysis, class_name);
	if (methods) {
		char *method_type[] = { "DEFAULT", "VIRTUAL", "V_DESTRUCTOR", "DESTRUCTOR", "CONSTRUCTOR" };
		RzAnalysisMethod *meth;
		rz_vector_foreach (methods, meth) {
			pj_o(pj);
			pj_ks(pj, "name", meth->real_name);
			pj_kn(pj, "addr", meth->addr);
			pj_ks(pj, "type", method_type[meth->method_type]);
			if (meth->vtable_offset >= 0) {
				pj_kn(pj, "vtable_offset", (ut64)meth->vtable_offset);
			}
			pj_end(pj);
		}
		rz_vector_free(methods);
	}
	pj_end(pj);

	pj_end(pj);
}

typedef struct {
	RzAnalysis *analysis;
	PJ *pj;
} ListJsonCtx;

static bool analysis_class_print_to_json_cb(void *user, const SdbKv *kv) {
	ListJsonCtx *ctx = user;
	analysis_class_print_to_json(ctx->analysis, ctx->pj, sdbkv_key(kv));
	return true;
}

static void analysis_class_list_print_to_json(RzAnalysis *analysis, PJ *pj) {
	ListJsonCtx ctx;
	ctx.analysis = analysis;
	ctx.pj = pj;
	pj_a(pj);
	rz_analysis_class_foreach(analysis, analysis_class_print_to_json_cb, &ctx);
	pj_end(pj);
	return;
}

static void analysis_class_print_as_cmd(RzAnalysis *analysis, const char *class_name) {
	RzVector *bases = rz_analysis_class_base_get_all(analysis, class_name);
	if (bases) {
		RzAnalysisBaseClass *base;
		rz_vector_foreach (bases, base) {
			rz_cons_printf("acb %s %s %" PFMT64u "\n", class_name, base->class_name, base->offset);
		}
		rz_vector_free(bases);
	}

	RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);
	if (vtables) {
		RzAnalysisVTable *vtable;
		rz_vector_foreach (vtables, vtable) {
			rz_cons_printf("acv %s 0x%" PFMT64x " %" PFMT64u "\n", class_name, vtable->addr, vtable->offset);
		}
		rz_vector_free(vtables);
	}

	RzVector *methods = rz_analysis_class_method_get_all(analysis, class_name);
	if (methods) {
		RzAnalysisMethod *meth;
		rz_vector_foreach (methods, meth) {
			rz_cons_printf("acm %s %s 0x%" PFMT64x " %" PFMT64d "\n", class_name, meth->name, meth->addr, meth->vtable_offset);
		}
		rz_vector_free(methods);
	}
}

RZ_IPI RzCmdStatus rz_analysis_class_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		analysis_class_list_print_to_json(core->analysis, state->d.pj);
		return RZ_CMD_STATUS_OK;
	}

	RzPVector *classes = rz_analysis_class_get_all(core->analysis, state->mode != RZ_OUTPUT_MODE_RIZIN);
	void **iter;
	if (state->mode == RZ_OUTPUT_MODE_RIZIN) {
		rz_pvector_foreach (classes, iter) {
			SdbKv *kv = *iter;
			// need to create all classes first, so they can be referenced
			rz_cons_printf("ac %s\n", sdbkv_key(kv));
		}
		rz_pvector_foreach (classes, iter) {
			SdbKv *kv = *iter;
			analysis_class_print_as_cmd(core->analysis, sdbkv_key(kv));
		}
	} else {
		rz_pvector_foreach (classes, iter) {
			SdbKv *kv = *iter;
			analysis_class_print(core->analysis, sdbkv_key(kv), state->mode == RZ_OUTPUT_MODE_LONG);
		}
	}
	rz_pvector_free(classes);
	return RZ_CMD_STATUS_OK;
}

static inline void log_err_nonexist_class() {
	RZ_LOG_ERROR("Class does not exist.\n");
}

RZ_IPI RzCmdStatus rz_analysis_class_info_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *class_name = argv[1];
	if (!rz_analysis_class_exists(core->analysis, class_name)) {
		log_err_nonexist_class();
		return RZ_CMD_STATUS_ERROR;
	}
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
	case RZ_OUTPUT_MODE_LONG:
		analysis_class_print(core->analysis, class_name, state->mode == RZ_OUTPUT_MODE_LONG);
		break;
	case RZ_OUTPUT_MODE_JSON:
		analysis_class_print_to_json(core->analysis, state->d.pj, class_name);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus class_error(RzAnalysisClassErr err) {
	RzCmdStatus status = RZ_CMD_STATUS_ERROR;
	switch (err) {
	case RZ_ANALYSIS_CLASS_ERR_SUCCESS:
		status = RZ_CMD_STATUS_OK;
		break;
	case RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_CLASS:
		log_err_nonexist_class();
		break;
	case RZ_ANALYSIS_CLASS_ERR_CLASH:
		RZ_LOG_ERROR("A class with this name already exists.\n");
		break;
	default:
		break;
	}
	return status;
}

RZ_IPI RzCmdStatus rz_analysis_class_add_handler(RzCore *core, int argc, const char **argv) {
	const char *class_name = argv[1];
	if (strchr(class_name, ' ')) {
		RZ_LOG_ERROR("Invalid class name.\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	RzAnalysisClassErr err = rz_analysis_class_create(core->analysis, class_name);
	return class_error(err);
}

RZ_IPI RzCmdStatus rz_analysis_class_del_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_class_delete(core->analysis, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_class_rename_handler(RzCore *core, int argc, const char **argv) {
	const char *old_name = argv[1];
	const char *new_name = argv[2];
	if (strchr(new_name, ' ')) {
		RZ_LOG_ERROR("Invalid class name.\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	RzAnalysisClassErr err = rz_analysis_class_rename(core->analysis, old_name, new_name);
	return class_error(err);
}

RZ_IPI RzCmdStatus rz_analysis_class_graph_handler(RzCore *core, int argc, const char **argv) {
	RzGraph *graph = rz_analysis_class_get_inheritance_graph(core->analysis);
	if (!graph) {
		RZ_LOG_ERROR("Couldn't create graph.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	core->graph->is_callgraph = false;
	rz_core_graph_print_graph(core, graph, RZ_CORE_GRAPH_FORMAT_ASCII_ART, false);
	rz_graph_free(graph);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus class_method_error(RzAnalysisClassErr err) {
	RzCmdStatus status = RZ_CMD_STATUS_ERROR;
	switch (err) {
	case RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_ATTR:
		RZ_LOG_ERROR("Method does not exist.\n");
		break;
	case RZ_ANALYSIS_CLASS_ERR_CLASH:
		RZ_LOG_ERROR("Method already exists.\n");
		break;
	default:
		status = class_error(err);
		break;
	}
	return status;
}

RZ_IPI RzCmdStatus rz_analysis_class_method_add_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisMethod meth;
	meth.name = rz_str_dup(argv[2]);
	meth.real_name = rz_str_dup(argv[2]);
	meth.method_type = RZ_ANALYSIS_CLASS_METHOD_DEFAULT;
	meth.addr = rz_num_math(core->num, argv[3]);
	meth.vtable_offset = -1;
	if (argc == 5) {
		meth.vtable_offset = (st64)rz_num_math(core->num, argv[4]);
	}
	RzAnalysisClassErr err = rz_analysis_class_method_set(core->analysis, argv[1], &meth);
	rz_analysis_class_method_fini(&meth);
	return class_method_error(err);
}

RZ_IPI RzCmdStatus rz_analysis_class_method_del_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisClassErr err = rz_analysis_class_method_delete(core->analysis, argv[1], argv[2]);
	return class_method_error(err);
}

RZ_IPI RzCmdStatus rz_analysis_class_method_rename_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisClassErr err = rz_analysis_class_method_rename(core->analysis, argv[1], argv[2], argv[3]);
	return class_method_error(err);
}

static RzCmdStatus class_base_error(RzAnalysisClassErr err) {
	RzCmdStatus status = RZ_CMD_STATUS_ERROR;
	switch (err) {
	case RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_ATTR:
		RZ_LOG_ERROR("Base class does not exist.\n");
		break;
	case RZ_ANALYSIS_CLASS_ERR_CLASH:
		RZ_LOG_ERROR("Base class already exists.\n");
		break;
	default:
		status = class_error(err);
		break;
	}
	return status;
}

RZ_IPI RzCmdStatus rz_analysis_class_base_add_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisBaseClass base;
	base.id = NULL;
	base.offset = 0;
	base.class_name = rz_str_dup(argv[2]);
	if (argc == 4) {
		base.offset = rz_num_math(core->num, argv[3]);
	}
	RzAnalysisClassErr err = rz_analysis_class_base_set(core->analysis, argv[1], &base);
	rz_analysis_class_base_fini(&base);
	return class_base_error(err);
}

RZ_IPI RzCmdStatus rz_analysis_class_base_del_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisClassErr err = rz_analysis_class_base_delete(core->analysis, argv[1], argv[2]);
	return class_base_error(err);
}

RZ_IPI RzCmdStatus rz_analysis_class_base_list_handler(RzCore *core, int argc, const char **argv) {
	const char *class_name = argv[1];
	if (!rz_analysis_class_exists(core->analysis, class_name)) {
		log_err_nonexist_class();
		return RZ_CMD_STATUS_ERROR;
	}
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%s:\n", class_name_sanitized);
	free(class_name_sanitized);

	RzVector *bases = rz_analysis_class_base_get_all(core->analysis, class_name);
	RzAnalysisBaseClass *base;
	rz_vector_foreach (bases, base) {
		rz_cons_printf("  %4s %s @ +0x%" PFMT64x "\n", base->id, base->class_name, base->offset);
	}
	rz_vector_free(bases);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus class_vtable_error(RzAnalysisClassErr err) {
	RzCmdStatus status = RZ_CMD_STATUS_ERROR;
	switch (err) {
	case RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_ATTR:
		RZ_LOG_ERROR("Vtable does not exist.\n");
		break;
	case RZ_ANALYSIS_CLASS_ERR_CLASH:
		RZ_LOG_ERROR("Vtable already exists.\n");
		break;
	default:
		status = class_error(err);
		break;
	}
	return status;
}

RZ_IPI RzCmdStatus rz_analysis_class_vtable_add_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisVTable vtable;
	vtable.id = NULL;
	vtable.addr = rz_num_math(core->num, argv[2]);
	vtable.offset = 0;
	vtable.size = 0;
	if (argc >= 4) {
		vtable.offset = rz_num_math(core->num, argv[3]);
	}
	if (argc == 5) {
		vtable.size = rz_num_math(core->num, argv[4]);
	}
	RzAnalysisClassErr err = rz_analysis_class_vtable_set(core->analysis, argv[1], &vtable);
	rz_analysis_class_vtable_fini(&vtable);
	return class_vtable_error(err);
}

RZ_IPI RzCmdStatus rz_analysis_class_vtable_del_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisClassErr err = rz_analysis_class_vtable_delete(core->analysis, argv[1], argv[2]);
	return class_vtable_error(err);
}

RZ_IPI RzCmdStatus rz_analysis_class_vtable_list_handler(RzCore *core, int argc, const char **argv) {
	const char *class_name = argv[1];
	if (!rz_analysis_class_exists(core->analysis, class_name)) {
		log_err_nonexist_class();
		return RZ_CMD_STATUS_ERROR;
	}
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%s:\n", class_name_sanitized);
	free(class_name_sanitized);

	RzVector *vtables = rz_analysis_class_vtable_get_all(core->analysis, class_name);
	if (vtables) {
		RzAnalysisVTable *vtable;
		rz_vector_foreach (vtables, vtable) {
			rz_cons_printf("  %4s vtable 0x%" PFMT64x " @ +0x%" PFMT64x " size:+0x%" PFMT64x "\n", vtable->id, vtable->addr, vtable->offset, vtable->size);
		}
		rz_vector_free(vtables);
	}
	return RZ_CMD_STATUS_OK;
}

static void list_all_functions_at_vtable_offset(RzAnalysis *analysis, const char *class_name, ut64 offset) {
	RVTableContext vtableContext;
	rz_analysis_vtable_begin(analysis, &vtableContext);
	ut8 function_ptr_size = vtableContext.word_size;
	RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);

	if (!vtables) {
		return;
	}

	RzAnalysisVTable *vtable;
	rz_vector_foreach (vtables, vtable) {
		if (vtable->size < offset + function_ptr_size || offset % function_ptr_size) {
			continue;
		}
		ut64 func_address;
		if (vtableContext.read_addr(analysis, vtable->addr + offset, &func_address)) {
			rz_cons_printf("Function address: 0x%08" PFMT64x ", in %s vtable %s\n", func_address, class_name, vtable->id);
		}
	}
	rz_vector_free(vtables);
}

RZ_IPI RzCmdStatus rz_analysis_class_vtable_lookup_handler(RzCore *core, int argc, const char **argv) {
	ut64 offset = rz_num_math(core->num, argv[1]);
	const char *class_name = argc == 3 ? argv[2] : NULL;
	if (class_name && !rz_analysis_class_exists(core->analysis, class_name)) {
		log_err_nonexist_class();
		return RZ_CMD_STATUS_ERROR;
	}

	if (class_name) {
		list_all_functions_at_vtable_offset(core->analysis, class_name, offset);
		return RZ_CMD_STATUS_OK;
	}
	RzPVector *classes = rz_analysis_class_get_all(core->analysis, true);
	void **iter;
	rz_pvector_foreach (classes, iter) {
		SdbKv *kv = *iter;
		const char *name = sdbkv_key(kv);
		list_all_functions_at_vtable_offset(core->analysis, name, offset);
	}
	rz_pvector_free(classes);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_bytes_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut8 *buf;
	st32 len;

	if (!(buf = malloc(strlen(argv[1]) + 1))) {
		return RZ_CMD_STATUS_ERROR;
	}

	len = rz_hex_str2bin(argv[1], buf);
	if (len <= 0) {
		free(buf);
		return RZ_CMD_STATUS_ERROR;
	}

	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		core_analysis_bytes_json(core, buf, len, 0, state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		core_analysis_bytes_standard(core, buf, len, 0);
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_n_bytes_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		core_analysis_bytes_json(core, core->block, core->blocksize, 0, state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		core_analysis_bytes_standard(core, core->block, core->blocksize, 0);
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_n_bytes_esil_handler(RzCore *core, int argc, const char **argv) {
	core_analysis_bytes_esil(core, core->block, core->blocksize, 0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_n_bytes_desc_handler(RzCore *core, int argc, const char **argv) {
	core_analysis_bytes_desc(core, core->block, core->blocksize, 0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_n_bytes_size_handler(RzCore *core, int argc, const char **argv) {
	core_analysis_bytes_size(core, core->block, core->blocksize, 0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_n_ins_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	st32 l;
	ut32 count = 1, obs = core->blocksize;

	if (argc > 1) {
		l = (st32)rz_num_math(core->num, argv[1]);
		if (l <= 0) {
			RZ_LOG_ERROR("Invalid zero or negative arguments.\n");
			return RZ_CMD_STATUS_ERROR;
		}

		count = l;
		l *= 8;
		if (l > obs) {
			rz_core_block_size(core, l);
		}
	}

	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		core_analysis_bytes_json(core, core->block, core->blocksize, count, state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		core_analysis_bytes_standard(core, core->block, core->blocksize, count);
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	if (obs != core->blocksize) {
		rz_core_block_size(core, obs);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_n_ins_size_handler(RzCore *core, int argc, const char **argv) {
	ut32 count = 1, obs = core->blocksize;
	st32 l;

	if (argc > 1) {
		l = (st32)rz_num_math(core->num, argv[1]);
		if (l <= 0) {
			RZ_LOG_ERROR("Invalid zero or negative arguments.\n");
			return RZ_CMD_STATUS_ERROR;
		}
		count = l;
		l *= 8;
		if (l > obs) {
			rz_core_block_size(core, l);
		}
	}

	core_analysis_bytes_size(core, core->block, core->blocksize, count);

	if (obs != core->blocksize) {
		rz_core_block_size(core, obs);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_n_ins_esil_handler(RzCore *core, int argc, const char **argv) {
	ut32 count = 1, obs = core->blocksize;
	st32 l;

	if (argc > 1) {
		l = (st32)rz_num_math(core->num, argv[1]);
		if (l <= 0) {
			RZ_LOG_ERROR("Invalid zero or negative arguments.\n");
			return RZ_CMD_STATUS_ERROR;
		}
		count = l;
		l *= 8;
		if (l > obs) {
			rz_core_block_size(core, l);
		}
	}

	core_analysis_bytes_esil(core, core->block, core->blocksize, count);

	if (obs != core->blocksize) {
		rz_core_block_size(core, obs);
	}
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief Analyzes a block of bytes in Intermediate Language (IL)
 *
 * This function is used to analyze a given block of bytes in Intermediate Language (IL)
 * using length, and number of operations as parameters, restricted by \p len and \p num_ops
 * at the same time. The analysis result is the pretty-printed if the 'pretty' parameter is true.
 *
 * \param core   The main Rizin object
 * \param len    The length of bytes to analyze, set to 0 to disable it.
 * \param num_ops The number of operations to analyze from the beginning of the block, set to 0 to disable it.
 * \param pretty If true, the output will be in a pretty format.
 */
RZ_API void rz_core_analysis_bytes_il(RZ_NONNULL RzCore *core, ut64 len, ut64 num_ops, bool pretty) {
	rz_return_if_fail(core);
	RzIterator *iter = rz_core_analysis_op_chunk_iter(core, core->offset, len, num_ops, RZ_ANALYSIS_OP_MASK_IL);
	if (!iter) {
		return;
	}

	rz_core_il_cons_print(core, iter, pretty);
	rz_iterator_free(iter);
}

RZ_IPI RzCmdStatus rz_analyze_n_ins_il_handler(RzCore *core, int argc, const char **argv) {
	ut32 count = 1;
	if (argc > 1) {
		st32 l = (st32)rz_num_math(core->num, argv[1]);
		if (l <= 0) {
			RZ_LOG_ERROR("Invalid zero or negative arguments.\n");
			return RZ_CMD_STATUS_ERROR;
		}
		count = l;
	}

	rz_core_analysis_bytes_il(core, 0, count, false);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_n_ins_il_pretty_handler(RzCore *core, int argc, const char **argv) {
	ut32 count = 1;
	if (argc > 1) {
		st32 l = (st32)rz_num_math(core->num, argv[1]);
		if (l <= 0) {
			RZ_LOG_ERROR("Invalid zero or negative arguments.\n");
			return RZ_CMD_STATUS_ERROR;
		}
		count = l;
	}

	rz_core_analysis_bytes_il(core, 0, count, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_opcode_handler(RzCore *core, int argc, const char **argv) {
	int cur;
	char *d;

	if (argc < 2) {
		cur = RZ_MAX(core->print->cur, 0);
		core_analysis_bytes_desc(core, core->block + cur, core->blocksize, 1);
	} else {
		d = rz_asm_describe(core->rasm, argv[1]);
		if (RZ_STR_ISEMPTY(d)) {
			RZ_LOG_ERROR("Unknown mnemonic\n");
			free(d);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_println(d);
		free(d);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_display_opcode_handler(RzCore *core, int argc, const char **argv) {
	sdb_foreach(core->rasm->pair, listOpDescriptions, core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_cycles_handler(RzCore *core, int argc, const char **argv) {
	RzList *hooks;
	RzListIter *iter;
	RzAnalysisCycleHook *hook;
	char *instr_tmp = NULL;
	st32 ccl = 0;
	RzConfigHold *hc = rz_config_hold_new(core->config);

	rz_config_hold_i(hc, "asm.cmt.right", "asm.functions", "asm.lines", "asm.xrefs", NULL);

	if (argc > 1) {
		ccl = (st32)rz_num_get(core->num, argv[1]);
		if (ccl < 0) {
			RZ_LOG_ERROR("Invalid negative arguments.\n");
			return RZ_CMD_STATUS_ERROR;
		}
	}

	rz_config_set_i(core->config, "asm.cmt.right", true);
	rz_config_set_i(core->config, "asm.functions", false);
	rz_config_set_i(core->config, "asm.lines", false);
	rz_config_set_i(core->config, "asm.xrefs", false);

	hooks = rz_core_analysis_cycles(core, ccl); // analysisyse
	rz_cons_clear_line(1);
	rz_list_foreach (hooks, iter, hook) {
		instr_tmp = rz_core_disassemble_instr(core, hook->addr, 1);
		rz_cons_printf("After %4i cycles:\t%s", (ccl - hook->cycles), instr_tmp);
		rz_cons_flush();
		free(instr_tmp);
	}
	rz_list_free(hooks);

	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_convert_mne_handler(RzCore *core, int argc, const char **argv) {
	st32 id;

	if (rz_str_isnumber(argv[1])) {
		id = (st32)rz_num_math(core->num, argv[1]);
		// id starts from 1
		if (id <= 0) {
			RZ_LOG_ERROR("Invalid negative or zero arguments.\n");
			return RZ_CMD_STATUS_ERROR;
		}

		char *ops = rz_asm_mnemonics(core->rasm, id, false);
		if (!ops) {
			RZ_LOG_ERROR("Can not find mnemonic by id.\n");
			return RZ_CMD_STATUS_ERROR;
		}

		rz_cons_println(ops);
		free(ops);
	} else {
		id = rz_asm_mnemonics_byname(core->rasm, argv[1]);
		if (id <= 0) {
			RZ_LOG_ERROR("Can not find id by mnemonic.\n");
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_printf("%d\n", id);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_list_mne_handler(RzCore *core, int argc, const char **argv) {
	char *nl, *ptr, *ops = rz_asm_mnemonics(core->rasm, -1, false);

	if (!ops) {
		return RZ_CMD_STATUS_ERROR;
	}
	ptr = ops;
	nl = strchr(ptr, '\n');
	while (nl) {
		*nl = 0;
		char *desc = rz_asm_describe(core->rasm, ptr);
		if (desc) {
			char *pad = rz_str_pad(' ', 16 - strlen(ptr));
			rz_cons_printf("%s%s%s\n", ptr, pad, desc);
			free(pad);
			free(desc);
		} else {
			rz_cons_printf("%s\n", ptr);
		}
		ptr = nl + 1;
		nl = strchr(ptr, '\n');
	}
	free(ops);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_list_plugins_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_core_asm_plugins_print(core, NULL, state);
}

RZ_IPI RzCmdStatus rz_analyse_name_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc > 1) {
		bool ret = rz_core_analysis_rename(core, argv[1], core->offset);
		if (!ret) {
			// name exists when error happens
			RZ_LOG_ERROR("Error happens while handling name: %s\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		return RZ_CMD_STATUS_OK;
	}

	return bool2status(core_analysis_name_print(core, state));
}

RZ_IPI RzCmdStatus rz_analysis_all_esil_handler(RzCore *core, int argc, const char **argv) {
	bool reg_flags_defined = rz_flag_space_count(core->flags, RZ_FLAGS_FS_REGISTERS) != 0;
	if (argc > 1) {
		rz_core_analysis_esil(core, core->offset, rz_num_get(core->num, argv[1]), NULL);
	} else {
		rz_core_analysis_esil_default(core);
	}
	if (!reg_flags_defined) {
		// hack to not leak flags if not wanted
		rz_flag_unset_all_in_space(core->flags, RZ_FLAGS_FS_REGISTERS);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_all_esil_functions_handler(RzCore *core, int argc, const char **argv) {
	bool reg_flags_defined = rz_flag_space_count(core->flags, RZ_FLAGS_FS_REGISTERS) != 0;
	rz_core_analysis_esil_references_all_functions(core);
	if (!reg_flags_defined) {
		// hack to not leak flags if not wanted
		rz_flag_unset_all_in_space(core->flags, RZ_FLAGS_FS_REGISTERS);
	}
	return RZ_CMD_STATUS_OK;
}

static RzList /*<ut64 *>*/ *get_xrefs(RzAnalysisBlock *block) {
	RzListIter *iter;
	RzAnalysisXRef *xref;
	RzList *list = NULL;
	size_t i;
	for (i = 0; i < block->ninstr; i++) {
		ut64 ia = block->addr + block->op_pos[i];
		RzList *xrefs = rz_analysis_xrefs_get_to(block->analysis, ia);
		rz_list_foreach (xrefs, iter, xref) {
			if (!list) {
				list = rz_list_newf(free);
			}
			rz_list_push(list, ut64_new(xref->from));
		}
	}
	return list;
}

static RzList /*<ut64 *>*/ *get_calls(RzAnalysisBlock *block) {
	ut8 *data = malloc(block->size);
	if (!data) {
		return NULL;
	}
	RzList *list = NULL;
	RzAnalysisOp op = { 0 };
	block->analysis->iob.read_at(block->analysis->iob.io, block->addr, data, block->size);
	for (size_t i = 0; i < block->size; i++) {
		rz_analysis_op_init(&op);
		int ret = rz_analysis_op(block->analysis, &op, block->addr + i, data + i, block->size - i, RZ_ANALYSIS_OP_MASK_HINT);
		if (ret < 1) {
			continue;
		}
		if (op.type == RZ_ANALYSIS_OP_TYPE_CALL) {
			if (!list) {
				list = rz_list_newf(free);
			}
			rz_list_push(list, ut64_new(op.jump));
		}
		rz_analysis_op_fini(&op);
		if (op.size > 0) {
			i += op.size - 1;
		}
	}
	return list;
}

RZ_IPI RzCmdStatus rz_analysis_basic_block_info_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	if (!bb) {
		RZ_LOG_ERROR("No basic block at 0x%" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_analysis_bb_info_print(core, bb, core->offset, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_basic_block_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	PJ *pj = state->mode == RZ_OUTPUT_MODE_JSON ? state->d.pj : NULL;
	RzTable *table = state->mode == RZ_OUTPUT_MODE_TABLE ? state->d.t : NULL;

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "xnddsssss", "addr", "size",
		"traced", "ninstr", "jump", "fail", "fcns", "calls", "xrefs");
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RBIter iter;
	RzAnalysisBlock *block;
	rz_rbtree_foreach (core->analysis->bb_tree, iter, block, RzAnalysisBlock, _rb) {
		RzList *xrefs = get_xrefs(block);
		RzList *calls = get_calls(block);
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_kn(pj, "addr", block->addr);
			pj_kb(pj, "traced", block->traced);
			pj_kn(pj, "ninstr", block->ninstr);
			pj_kn(pj, "size", block->size);
			if (block->jump != UT64_MAX) {
				pj_kn(pj, "jump", block->jump);
			}
			if (block->fail != UT64_MAX) {
				pj_kn(pj, "fail", block->fail);
			}
			if (xrefs) {
				pj_ka(pj, "xrefs");
				RzListIter *iter2;
				ut64 *addr;
				rz_list_foreach (xrefs, iter2, addr) {
					pj_n(pj, *addr);
				}
				pj_end(pj);
			}
			if (calls) {
				pj_ka(pj, "calls");
				RzListIter *iter2;
				ut64 *addr;
				rz_list_foreach (calls, iter2, addr) {
					pj_n(pj, *addr);
				}
				pj_end(pj);
			}
			pj_ka(pj, "fcns");
			RzListIter *iter2;
			RzAnalysisFunction *fcn;
			rz_list_foreach (block->fcns, iter2, fcn) {
				pj_n(pj, fcn->addr);
			}
			pj_end(pj);
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_TABLE: {
			char *jump = block->jump != UT64_MAX ? rz_str_newf("0x%08" PFMT64x, block->jump) : rz_str_dup("");
			char *fail = block->fail != UT64_MAX ? rz_str_newf("0x%08" PFMT64x, block->fail) : rz_str_dup("");
			char *call = ut64join(calls);
			char *xref = ut64join(calls);
			char *fcns = fcnjoin(block->fcns);
			rz_table_add_rowf(table, "xnddsssss",
				block->addr,
				block->size,
				block->traced,
				block->ninstr,
				jump,
				fail,
				fcns,
				call,
				xref);
			free(jump);
			free(fail);
			free(call);
			free(xref);
			free(fcns);
		} break;
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("0x%08" PFMT64x "\n", block->addr);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("0x%08" PFMT64x, block->addr);
			if (block->jump != UT64_MAX) {
				rz_cons_printf(" .j 0x%08" PFMT64x, block->jump);
			}
			if (block->fail != UT64_MAX) {
				rz_cons_printf(" .f 0x%08" PFMT64x, block->fail);
			}
			if (xrefs) {
				RzListIter *iter2;
				rz_cons_printf(" .x");
				ut64 *addr;
				rz_list_foreach (xrefs, iter2, addr) {
					rz_cons_printf(" 0x%08" PFMT64x, *addr);
				}
			}
			if (calls) {
				rz_cons_printf(" .c");
				RzListIter *iter2;
				ut64 *addr;
				rz_list_foreach (calls, iter2, addr) {
					rz_cons_printf(" 0x%08" PFMT64x, *addr);
				}
			}
			if (block->fcns) {
				RzListIter *iter2;
				RzAnalysisFunction *fcn;
				rz_list_foreach (block->fcns, iter2, fcn) {
					rz_cons_printf(" .u 0x%" PFMT64x, fcn->addr);
				}
			}
			rz_cons_printf(" .s %" PFMT64d "\n", block->size);
			break;
		default:
			rz_warn_if_reached();
			status = RZ_CMD_STATUS_WRONG_ARGS;
			iter.len = 0;
		}
		rz_list_free(xrefs);
		rz_list_free(calls);
	}
	rz_cmd_state_output_array_end(state);
	return status;
}

RZ_IPI RzCmdStatus rz_analysis_basic_block_find_paths_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 addr = rz_num_math(core->num, argv[1]);
	RzAnalysisBlock *block = rz_analysis_get_block_at(core->analysis, core->offset);
	if (!block) {
		RZ_LOG_ERROR("No basic block at 0x%" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	RzList *path = rz_analysis_block_shortest_path(block, addr);
	if (!path) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	rz_cmd_state_output_array_start(state);
	RzListIter *it;
	rz_list_foreach (path, it, block) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_n(state->d.pj, block->addr);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("0x%08" PFMT64x "\n", block->addr);
			break;
		default:
			rz_warn_if_reached();
			status = RZ_CMD_STATUS_WRONG_ARGS;
			it = NULL;
		}
	}
	rz_cmd_state_output_array_end(state);
	rz_list_free(path);
	return status;
}

RZ_IPI RzCmdStatus rz_analyze_simple_handler(RzCore *core, int argc, const char **argv) {
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_SIMPLE);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_everything_handler(RzCore *core, int argc, const char **argv) {
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_DEEP);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_everything_experimental_handler(RzCore *core, int argc, const char **argv) {
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_all_function_calls_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_calls(core, false);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_all_function_calls_to_imports_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_calls(core, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_all_data_references_to_code_handler(RzCore *core, int argc, const char **argv) {
	RzListIter *iter;
	RzAnalysisXRef *xref;
	RzList *list = rz_analysis_xrefs_get_from(core->analysis, UT64_MAX);
	rz_list_foreach (list, iter, xref) {
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_DATA && rz_io_is_valid_offset(core->io, xref->to, false)) {
			rz_core_analysis_fcn(core, xref->from, xref->to, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
		}
	}
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_all_functions_handler(RzCore *core, int argc, const char **argv) {
	const bool old_hasnext = rz_config_get_b(core->config, "analysis.hasnext");
	rz_config_set_b(core->config, "analysis.hasnext", true);
	rz_core_cmd0(core, "afr @@c:isq"); // TODO: replace with C apis.
	rz_config_set_b(core->config, "analysis.hasnext", old_hasnext);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_all_functions_esil_handler(RzCore *core, int argc, const char **argv) {
	rz_core_cmd0(core, "aef @@F"); // TODO: replace with C apis.
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_all_consecutive_functions_in_section_handler(RzCore *core, int argc, const char **argv) {
	ut64 old_offset = core->offset;
	RzListIter *iter;
	RzIOMap *map;
	RzList *list = rz_core_get_boundaries_prot(core, RZ_PERM_X, NULL, "analysis");
	if (!list) {
		RZ_LOG_ERROR("Cannot find maps with exec permisions.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	const bool hasnext = rz_config_get_b(core->config, "analysis.hasnext");
	rz_list_foreach (list, iter, map) {
		rz_core_seek(core, map->itv.addr, true);
		rz_config_set_b(core->config, "analysis.hasnext", true);
		rz_core_analysis_function_add(core, NULL, core->offset, true);
		rz_config_set_b(core->config, "analysis.hasnext", hasnext);
	}

	rz_list_free(list);
	rz_core_seek(core, old_offset, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_recursively_all_function_types_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_analysis_types_propagation(core));
}

RZ_IPI RzCmdStatus rz_apply_signatures_from_sigdb_handler(RzCore *core, int argc, const char **argv) {
	const char *filter = argc == 2 ? argv[1] : NULL;
	return bool2status(rz_core_analysis_sigdb_apply(core, NULL, filter));
}

RZ_IPI RzCmdStatus rz_list_signatures_in_sigdb_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_analysis_sigdb_print(core, state->d.t);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_analysis_details_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	st64 fcns = rz_list_length(core->analysis->fcns);
	st64 strs = rz_flag_count(core->flags, "str.*");
	st64 syms = rz_flag_count(core->flags, "sym.*");
	st64 imps = rz_flag_count(core->flags, "sym.imp.*");
	st64 sigs = rz_flag_count(core->flags, "flirt.*");
	st64 code = rz_core_analysis_code_count(core);
	st64 covr = rz_core_analysis_coverage_count(core);
	st64 call = rz_core_analysis_calls_count(core);
	st64 xrfs = rz_analysis_xrefs_count(core->analysis);
	double precentage = (code > 0) ? (covr * 100.0 / code) : 0;

	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("functions:   %" PFMT64d "\n", fcns);
		rz_cons_printf("xrefs:       %" PFMT64d "\n", xrfs);
		rz_cons_printf("calls:       %" PFMT64d "\n", call);
		rz_cons_printf("strings:     %" PFMT64d "\n", strs);
		rz_cons_printf("symbols:     %" PFMT64d "\n", syms);
		rz_cons_printf("imports:     %" PFMT64d "\n", imps);
		rz_cons_printf("signatures:  %" PFMT64d "\n", sigs);
		rz_cons_printf("coverage:    %" PFMT64d "\n", covr);
		rz_cons_printf("code size:   %" PFMT64d "\n", code);
		rz_cons_printf("percentage: %.2f%% (coverage on code size)\n", precentage);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_ki(state->d.pj, "fcns", fcns);
		pj_ki(state->d.pj, "xrefs", xrfs);
		pj_ki(state->d.pj, "calls", call);
		pj_ki(state->d.pj, "strings", strs);
		pj_ki(state->d.pj, "symbols", syms);
		pj_ki(state->d.pj, "imports", imps);
		pj_ki(state->d.pj, "signatures", sigs);
		pj_ki(state->d.pj, "covrage", covr);
		pj_ki(state->d.pj, "codesz", code);
		pj_ki(state->d.pj, "percent", precentage);
		pj_end(state->d.pj);
		break;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_all_unresolved_jumps_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_resolve_jumps(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_recover_all_golang_functions_strings_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_core_analysis_recover_golang_functions(core)) {
		RZ_LOG_ERROR("cannot recover golang functions.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_analysis_resolve_golang_strings(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_all_objc_references_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_analysis_objc_refs(core, false));
}

RZ_IPI RzCmdStatus rz_analyze_all_objc_stubs_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_objc_stubs(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_autoname_all_functions_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_autoname_all_fcns(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_autoname_all_functions_noreturn_handler(RzCore *core, int argc, const char **argv) {
	rz_core_analysis_propagate_noreturn(core, UT64_MAX);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_all_preludes_handler(RzCore *core, int argc, const char **argv) {
	rz_core_search_preludes(core, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_xrefs_section_bytes_handler(RzCore *core, int argc, const char **argv) {
	size_t n_bytes = argc == 2 ? rz_num_math(core->num, argv[1]) : 0;
	return bool2status(rz_core_analysis_refs(core, n_bytes));
}

static bool analyze_function_at_flag(RzFlagItem *fi, RzCore *core) {
	bool analyze_recursively = rz_config_get_b(core->config, "analysis.calls");
	rz_core_analysis_function_add(core, NULL, fi->offset, analyze_recursively);
	return true;
}

RZ_IPI RzCmdStatus rz_analyze_symbols_entries_handler(RzCore *core, int argc, const char **argv) {
	bool analyze_recursively = rz_config_get_b(core->config, "analysis.calls");
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	if (!obj) {
		RZ_LOG_ERROR("Cannot get current bin object\n");
		return RZ_CMD_STATUS_ERROR;
	}

	const RzPVector *symbols = rz_bin_object_get_symbols(obj);
	void **it;
	RzBinSymbol *symbol;

	rz_pvector_foreach (symbols, it) {
		symbol = *it;
		rz_core_analysis_function_add(core, NULL, symbol->vaddr, analyze_recursively);
	}

	rz_flag_foreach_glob(core->flags, "entry", (RzFlagItemCb)analyze_function_at_flag, core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_symbols_entries_flags_handler(RzCore *core, int argc, const char **argv) {
	rz_flag_foreach_glob(core->flags, "sym.", (RzFlagItemCb)analyze_function_at_flag, core);
	rz_flag_foreach_glob(core->flags, "entry", (RzFlagItemCb)analyze_function_at_flag, core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_function_linked_offsets_handler(RzCore *core, int argc, const char **argv) {
	ut64 func_offset = argc == 2 ? rz_num_math(core->num, argv[1]) : UT64_MAX;
	RzAnalysisFunction *fcn;

	if (func_offset != UT64_MAX) {
		fcn = rz_analysis_get_function_at(core->analysis, func_offset);
		if (!fcn) {
			RZ_LOG_ERROR("Cannot find function '%s'\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_core_global_vars_propagate_types(core, fcn);
		return RZ_CMD_STATUS_OK;
	} else if (rz_list_empty(core->analysis->fcns)) {
		RZ_LOG_ERROR("Couldn't find any functions\n");
		return RZ_CMD_STATUS_ERROR;
	}

	RzListIter *it;
	rz_list_foreach (core->analysis->fcns, it, fcn) {
		if (rz_cons_is_breaked()) {
			break;
		}
		rz_core_global_vars_propagate_types(core, fcn);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_commands_after_traps_handler(RzCore *core, int argc, const char **argv) {
	ut64 n_bytes = argc == 2 ? rz_num_math(core->num, argv[1]) : 0;
	return bool2status(print_cmd_analysis_after_traps_print(core, n_bytes));
}

RZ_IPI RzCmdStatus rz_print_areas_no_functions_handler(RzCore *core, int argc, const char **argv) {
	size_t min_len = argc == 2 ? rz_num_math(core->num, argv[1]) : 16;
	if (min_len < 1) {
		min_len = 1;
	}

	ut64 code_size = rz_num_get(core->num, "$SS");
	ut64 base_addr = rz_num_get(core->num, "$S");
	ut64 chunk_size, chunk_offset, i;
	RzListIter *iter;
	void **iter2;
	RzAnalysisFunction *fcn;
	RzAnalysisBlock *b;
	char *bitmap;
	int counter;

	if (code_size < 1) {
		RZ_LOG_ERROR("Invalid code size (size < 1)\n");
		return RZ_CMD_STATUS_ERROR;
	}

	bitmap = calloc(1, code_size + 64);
	if (!bitmap) {
		RZ_LOG_ERROR("Cannot allocate bitmap buffer\n");
		return RZ_CMD_STATUS_ERROR;
	}

	// for each function
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		// for each basic block in the function
		rz_pvector_foreach (fcn->bbs, iter2) {
			b = (RzAnalysisBlock *)*iter2;
			// if it is not withing range, continue
			if ((fcn->addr < base_addr) || (fcn->addr >= base_addr + code_size))
				continue;
			// otherwise mark each byte in the BB in the bitmap
			for (counter = 0; counter < b->size; counter++) {
				bitmap[b->addr + counter - base_addr] = '=';
			}
			// finally, add a special marker to show the beginning of a
			// function
			bitmap[fcn->addr - base_addr] = 'F';
		}
	}

	// Now we print the list of memory regions that are not assigned to a function
	chunk_size = 0;
	chunk_offset = 0;
	for (i = 0; i < code_size; i++) {
		if (bitmap[i]) {
			// We only print a region is its size is bigger than 15 bytes
			if (chunk_size >= min_len) {
				fcn = rz_analysis_get_fcn_in(core->analysis, base_addr + chunk_offset, RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
				if (fcn) {
					rz_cons_printf("0x%08" PFMT64x "  %6" PFMT64u "   %s\n", base_addr + chunk_offset, chunk_size, fcn->name);
				} else {
					rz_cons_printf("0x%08" PFMT64x "  %6" PFMT64u "\n", base_addr + chunk_offset, chunk_size);
				}
			}
			chunk_size = 0;
			chunk_offset = i + 1;
			continue;
		}
		chunk_size += 1;
	}
	if (chunk_size >= 16) {
		fcn = rz_analysis_get_fcn_in(core->analysis, base_addr + chunk_offset, RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
		if (fcn) {
			rz_cons_printf("0x%08" PFMT64x "  %6" PFMT64u "   %s\n", base_addr + chunk_offset, chunk_size, fcn->name);
		} else {
			rz_cons_printf("0x%08" PFMT64x "  %6" PFMT64u "\n", base_addr + chunk_offset, chunk_size);
		}
	}
	free(bitmap);

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_value_to_maps_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_analysis_value_pointers(core, state->mode);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_info_show_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	cmd_address_info(core, core->offset, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_global_imports_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	char *imp;
	RzListIter *iter;

	if (RZ_STR_ISNOTEMPTY(argv[1])) {
		rz_analysis_add_import(core->analysis, argv[1]);
		return RZ_CMD_STATUS_OK;
	}
	rz_list_foreach (core->analysis->imports, iter, imp) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("%s\n", imp);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_delete_global_imports_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_analysis_purge_imports(core->analysis);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_data_handler(RzCore *core, int argc, const char **argv) {
	int count = argc > 1 ? rz_num_math(core->num, argv[1]) : 2 + (core->blocksize / 4);
	if (count < 1) {
		RZ_LOG_ERROR("Count could not be negative or zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	int depth = argc > 2 ? rz_num_math(core->num, argv[2]) : 1;
	if (depth < 1) {
		RZ_LOG_ERROR("Depth could not be negative or zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	int wordsize = argc > 3 ? rz_num_math(core->num, argv[3]) : 0;
	rz_core_analysis_data(core, core->offset, count, depth, wordsize);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_data_function_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_ANY);
	if (!fcn) {
		RZ_LOG_ERROR("Function not found at the 0x%08" PFMT64x " offset\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	int i;
	bool gap = false;
	ut64 gap_addr = UT64_MAX;
	ut32 fcn_size = rz_analysis_function_size_from_entry(fcn);
	char *bitmap = calloc(1, fcn_size);
	if (bitmap) {
		RzAnalysisBlock *b;
		void **iter;
		rz_pvector_foreach (fcn->bbs, iter) {
			b = (RzAnalysisBlock *)*iter;
			int f = b->addr - fcn->addr;
			int t = RZ_MIN(f + b->size, fcn_size);
			if (f >= 0) {
				while (f < t) {
					bitmap[f++] = 1;
				}
			}
		}
	}
	for (i = 0; i < fcn_size; i++) {
		ut64 here = fcn->addr + i;
		if (bitmap && bitmap[i]) {
			if (gap) {
				rz_cons_printf("Cd %" PFMT64u " @ 0x%08" PFMT64x "\n", here - gap_addr, gap_addr);
				gap = false;
			}
			gap_addr = UT64_MAX;
		} else {
			if (!gap) {
				gap = true;
				gap_addr = here;
			}
		}
	}
	if (gap) {
		rz_cons_printf("Cd %" PFMT64u " @ 0x%08" PFMT64x "\n", fcn->addr + fcn_size - gap_addr, gap_addr);
	}
	free(bitmap);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_data_function_gaps_handler(RzCore *core, int argc, const char **argv) {
	ut64 end = UT64_MAX;
	RzAnalysisFunction *fcn;
	RzListIter *iter;
	int i, wordsize = core->rasm->bits / 8;
	rz_list_sort(core->analysis->fcns, cmpaddr, NULL);
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		if (end != UT64_MAX) {
			int range = fcn->addr - end;
			if (range > 0) {
				for (i = 0; i + wordsize < range; i += wordsize) {
					rz_cons_printf("Cd %d @ 0x%08" PFMT64x "\n", wordsize, end + i);
				}
				rz_cons_printf("Cd %d @ 0x%08" PFMT64x "\n", range - i, end + i);
			}
		}
		end = fcn->addr + rz_analysis_function_size_from_entry(fcn);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_data_kind_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisDataKind kind = rz_analysis_data_kind(core->analysis,
		core->offset, core->block, core->blocksize);
	switch (kind) {
	case RZ_ANALYSIS_DATA_KIND_INVALID:
		rz_cons_println("invalid");
		break;
	case RZ_ANALYSIS_DATA_KIND_CODE:
		rz_cons_println("code");
		break;
	case RZ_ANALYSIS_DATA_KIND_STRING:
		rz_cons_println("text");
		break;
	case RZ_ANALYSIS_DATA_KIND_DATA:
		rz_cons_println("data");
		break;
	default:
		rz_cons_println("unknown");
		break;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_data_trampoline_handler(RzCore *core, int argc, const char **argv) {
	ut64 minimum = rz_num_math(core->num, argv[1]);
	ut64 maximum = rz_num_math(core->num, argv[2]);

	int bits = rz_config_get_i(core->config, "asm.bits");
	print_trampolines(core, minimum, maximum, bits / 8);
	return RZ_CMD_STATUS_OK;
}
