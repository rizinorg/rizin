// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util/rz_graph_drawable.h>

#include "../core_private.h"

#define MAX_SCAN_SIZE 0x7ffffff

HEAPTYPE(ut64);

static const char *help_msg_a[] = {
	"Usage:", "a", "[abdefFghoprxstc] [...]",
	"a*", "", "same as afl*;ah*;ax*",
	"aa", "[?]", "analyze all (fcns + bbs) (aa0 to avoid sub renaming)",
	"a8", " [hexpairs]", "analyze bytes",
	"ab", "[?] [addr]", "analyze block",
	"aC", "[?]", "analyze function call",
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

static const char *help_msg_ai[] = {
	"Usage:", "ai", "[j*] [sz] # analysis/address information/imports",
	"ai", " @addr", "show address information",
	"aii", " [namespace]", "global import (like afii, but global)",
	"aii", "-", "delete all global imports",
	"aij", " @addr", "show address information in JSON format",
	NULL
};

static const char *help_msg_ad[] = {
	"Usage:", "ad", "[kt] [...]",
	"ad", " [N] [D]", "analyze N data words at D depth",
	"ad4", " [N] [D]", "analyze N data words at D depth (asm.bits=32)",
	"ad8", " [N] [D]", "analyze N data words at D depth (asm.bits=64)",
	"adf", "", "analyze data in function (use like .adf @@=`afl~[0]`",
	"adfg", "", "analyze data in function gaps",
	"adt", "", "analyze data trampolines (wip)",
	"adk", "", "analyze data kind (code, text, data, invalid, ...)",
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

static const char *help_msg_ag[] = {
	"Usage:", "ag<graphtype><format> [addr]", "",
	"Graph commands:", "", "",
	"aga", "[format]", "Data references graph",
	"agA", "[format]", "Global data references graph",
	"agc", "[format]", "Function callgraph",
	"agC", "[format]", "Global callgraph",
	"agd", "[format] [fcn addr]", "Diff graph",
	"agf", "[format]", "Basic blocks function graph",
	"agi", "[format]", "Imports graph",
	"agr", "[format]", "References graph",
	"agR", "[format]", "Global references graph",
	"agx", "[format]", "Cross references graph",
	"agg", "[format]", "Custom graph",
	"ag-", "", "Clear the custom graph",
	"agn", "[?] title body", "Add a node to the custom graph",
	"age", "[?] title1 title2", "Add an edge to the custom graph",
	"", "", "",
	"Output formats:", "", "",
	"<blank>", "", "Ascii art",
	"*", "", "rizin commands",
	"d", "", "Graphviz dot",
	"g", "", "Graph Modelling Language (gml)",
	"j", "", "json ('J' for formatted disassembly)",
	"k", "", "SDB key-value",
	"t", "", "Tiny ascii art",
	"v", "", "Interactive ascii art",
	"w", " [path]", "Write to path or display graph image (see graph.gv.format)",
	NULL
};

static const char *help_msg_age[] = {
	"Usage:", "age [title1] [title2]", "",
	"Examples:", "", "",
	"age", " title1 title2", "Add an edge from the node with \"title1\" as title to the one with title \"title2\"",
	"age", " \"title1 with spaces\" title2", "Add an edge from node \"title1 with spaces\" to node \"title2\"",
	"age-", " title1 title2", "Remove an edge from the node with \"title1\" as title to the one with title \"title2\"",
	"age?", "", "Show this help",
	NULL
};

static const char *help_msg_agn[] = {
	"Usage:", "agn [title] [body]", "",
	"Examples:", "", "",
	"agn", " title1 body1", "Add a node with title \"title1\" and body \"body1\"",
	"agn", " \"title with space\" \"body with space\"", "Add a node with spaces in the title and in the body",
	"agn", " title1 base64:Ym9keTE=", "Add a node with the body specified as base64",
	"agn-", " title1", "Remove a node with title \"title1\"",
	"agn?", "", "Show this help",
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

static int cmpaddr(const void *_a, const void *_b) {
	const RzAnalysisFunction *a = _a, *b = _b;
	return (a->addr > b->addr) ? 1 : (a->addr < b->addr) ? -1
							     : 0;
}

static bool listOpDescriptions(void *_core, const char *k, const char *v) {
	rz_cons_printf("%s=%s\n", k, v);
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
	rz_vector_foreach(&var->accesses, acc) {
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
	RzAnalysisVar *var = NULL;
	RzListIter *iter;
	RzList *list = rz_analysis_var_all_list(core->analysis, fcn);
	if (type == '=') {
		ut64 oaddr = core->offset;
		rz_list_foreach (list, iter, var) {
			rz_cons_printf("* %s\n", var->name);
			RzAnalysisVarAccess *acc;
			rz_vector_foreach(&var->accesses, acc) {
				if (!(acc->type & RZ_ANALYSIS_VAR_ACCESS_TYPE_READ)) {
					continue;
				}
				rz_cons_printf("R 0x%" PFMT64x "  ", fcn->addr + acc->offset);
				rz_core_seek(core, fcn->addr + acc->offset, 1);
				rz_core_print_disasm_instructions(core, 0, 1);
			}
			rz_vector_foreach(&var->accesses, acc) {
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
		rz_cons_printf("f-fcnvar*\n");
		rz_list_foreach (list, iter, var) {
			rz_cons_printf("f fcnvar.%s @ %s%s%d\n", var->name, bp,
				var->delta >= 0 ? "+" : "", var->delta);
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
		var = rz_analysis_function_get_var_byname(fcn, name);
		if (var) {
			if (var->isarg == vlt || vlt == IS_ARG_AND_VAR) {
				var_accesses_list(fcn, var, pj, access_type, var->name);
			}
		}
	} else {
		rz_list_foreach (list, iter, var) {
			if (var->isarg == vlt || vlt == IS_ARG_AND_VAR) {
				var_accesses_list(fcn, var, pj, access_type, var->name);
			}
		}
	}
	if (pj) {
		pj_end(pj);
	}
}

static bool core_analysis_name(RzCore *core, const char *name, PJ *pj) {
	bool ret = true;
	ut64 off = core->offset;
	RzAnalysisOp op;
	ut64 tgt_addr = UT64_MAX;

	if (pj) {
		pj_a(pj);
	}

	rz_analysis_op(core->analysis, &op, off,
		core->block + off - core->offset, 32, RZ_ANALYSIS_OP_MASK_BASIC);
	RzAnalysisVar *var = rz_analysis_get_used_function_var(core->analysis, op.addr);

	tgt_addr = op.jump != UT64_MAX ? op.jump : op.ptr;
	if (var) {
		if (name) {
			ret = rz_analysis_var_rename(var, name, true)
				? true
				: false;
		} else {
			if (pj) {
				pj_o(pj);
				pj_ks(pj, "name", var->name);
				pj_ks(pj, "type", "var");
				pj_kn(pj, "offset", tgt_addr);
				pj_end(pj);
			} else {
				rz_cons_println(var->name);
			}
		}
	} else if (tgt_addr != UT64_MAX) {
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, tgt_addr);
		RzFlagItem *f = rz_flag_get_i(core->flags, tgt_addr);
		if (fcn) {
			if (name) {
				ret = rz_analysis_function_rename(fcn, name) ? true : false;
			} else {
				if (!pj) {
					rz_cons_println(fcn->name);
				} else {
					pj_o(pj);
					pj_ks(pj, "name", fcn->name);
					pj_ks(pj, "type", "function");
					pj_kn(pj, "offset", tgt_addr);
					pj_end(pj);
				}
			}
		} else if (f) {
			if (name) {
				ret = rz_flag_rename(core->flags, f, name) ? true : false;
			} else {
				if (!pj) {
					rz_cons_println(f->name);
				} else {
					pj_o(pj);
					if (name) {
						pj_ks(pj, "old_name", f->name);
						pj_ks(pj, "name", name);
					} else {
						pj_ks(pj, "name", f->name);
					}
					if (f->realname) {
						pj_ks(pj, "realname", f->realname);
					}
					pj_ks(pj, "type", "flag");
					pj_kn(pj, "offset", tgt_addr);
					pj_end(pj);
				}
			}
		} else {
			if (name) {
				ret = rz_flag_set(core->flags, name, tgt_addr, 1) ? true : false;
			} else {
				if (!pj) {
					rz_cons_printf("0x%" PFMT64x "\n", tgt_addr);
				} else {
					pj_o(pj);
					pj_ks(pj, "type", "address");
					pj_kn(pj, "offset", tgt_addr);
					pj_end(pj);
				}
			}
		}
	}

	if (pj) {
		pj_end(pj);
	}

	rz_analysis_op_fini(&op);
	return ret;
}

static void print_trampolines(RzCore *core, ut64 a, ut64 b, size_t element_size) {
	int i;
	for (i = 0; i < core->blocksize; i += element_size) {
		ut32 n;
		memcpy(&n, core->block + i, sizeof(ut32));
		if (n >= a && n <= b) {
			if (element_size == 4) {
				rz_cons_printf("f trampoline.%x @ 0x%" PFMT64x "\n", n, core->offset + i);
			} else {
				rz_cons_printf("f trampoline.%" PFMT32x " @ 0x%" PFMT64x "\n", n, core->offset + i);
			}
			rz_cons_printf("Cd %zu @ 0x%" PFMT64x ":%zu\n", element_size, core->offset + i, element_size);
			// TODO: add data xrefs
		}
	}
}

static void cmd_analysis_trampoline(RzCore *core, const char *input) {
	int bits = rz_config_get_i(core->config, "asm.bits");
	char *p, *inp = strdup(input);
	p = strchr(inp, ' ');
	if (p) {
		*p = 0;
	}
	ut64 a = rz_num_math(core->num, inp);
	ut64 b = p ? rz_num_math(core->num, p + 1) : 0;
	free(inp);

	switch (bits) {
	case 32:
		print_trampolines(core, a, b, 4);
		break;
	case 64:
		print_trampolines(core, a, b, 8);
		break;
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

#define printline(k, fmt, arg) \
	{ \
		if (use_color) \
			rz_cons_printf("%s%s: " Color_RESET, color, k); \
		else \
			rz_cons_printf("%s: ", k); \
		if (fmt) \
			rz_cons_printf(fmt, arg); \
	}
#define printline_noarg(k, msg) \
	{ \
		if (use_color) \
			rz_cons_printf("%s%s: " Color_RESET, color, k); \
		else \
			rz_cons_printf("%s: ", k); \
		if (msg) \
			rz_cons_println(msg); \
	}

#define PJ_KS(pj, key, value) \
	if (RZ_STR_ISNOTEMPTY(value)) { \
		pj_ks(pj, key, value); \
	}
#define PJ_KN(pj, key, value) \
	if (value != UT64_MAX) { \
		pj_kn(pj, key, value); \
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
		ret = rz_analysis_op(core->analysis, &op, addr, buf + idx, len - idx,
			RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_OPEX | RZ_ANALYSIS_OP_MASK_HINT);
		(void)rz_asm_disassemble(core->rasm, &asmop, buf + idx, len - idx);

		if (ret < 1) {
			RZ_LOG_ERROR("Invalid instruction at 0x%08" PFMT64x "...\n", core->offset + idx);
			break;
		}

		char *opname = strdup(rz_asm_op_get_asm(&asmop));
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
	RzPVector *vec = rz_core_analysis_bytes(core, buf, len, nops);
	if (!vec) {
		return;
	}

	void **iter;
	RzAnalysisBytes *ab;

	pj_a(pj);
	rz_pvector_foreach (vec, iter) {
		if (!iter) {
			break;
		}
		ab = *iter;
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
	rz_pvector_free(vec);
}

static void core_analysis_bytes_standard(RzCore *core, const ut8 *buf, int len, int nops) {
	bool be = core->print->big_endian;
	bool use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	core->parser->subrel = rz_config_get_i(core->config, "asm.sub.rel");
	int ret, i, j, idx, size;
	const char *color = "";
	const char *esilstr;
	RzAnalysisHint *hint;
	RzAnalysisEsil *esil = NULL;
	RzAsmOp asmop;
	RzAnalysisOp op = { 0 };
	ut64 addr;

	if (use_color) {
		color = core->cons->context->pal.label;
	}

	for (i = idx = 0; idx < len && (!nops || (nops && i < nops)); i++, idx += ret) {
		addr = core->offset + idx;
		rz_asm_set_pc(core->rasm, addr);
		hint = rz_analysis_hint_get(core->analysis, addr);
		ret = rz_analysis_op(core->analysis, &op, addr, buf + idx, len - idx,
			RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_OPEX | RZ_ANALYSIS_OP_MASK_HINT);
		(void)rz_asm_disassemble(core->rasm, &asmop, buf + idx, len - idx);
		esilstr = RZ_STRBUF_SAFEGET(&op.esil);
		char *mnem = strdup(rz_asm_op_get_asm(&asmop));
		char *sp = strchr(mnem, ' ');
		if (sp) {
			*sp = 0;
			if (op.prefix) {
				char *arg = strdup(sp + 1);
				char *sp = strchr(arg, ' ');
				if (sp) {
					*sp = 0;
				}
				free(mnem);
				mnem = arg;
			}
		}
		if (ret < 1) {
			RZ_LOG_ERROR("Invalid instruction at 0x%08" PFMT64x "...\n", core->offset + idx);
			free(mnem);
			break;
		}
		size = op.size;

		char disasm[128] = { 0 };
		rz_parse_subvar(core->parser, NULL,
			&op, rz_asm_op_get_asm(&asmop),
			disasm, sizeof(disasm));
		ut64 killme = UT64_MAX;
		if (rz_io_read_i(core->io, op.ptr, &killme, op.refptr, be)) {
			core->parser->subrel_addr = killme;
		}
		char *p = strdup(disasm);
		if (p) {
			rz_parse_filter(core->parser, addr, core->flags, hint, p,
				disasm, sizeof(disasm), be);
			free(p);
		}

		printline("address", "0x%" PFMT64x "\n", core->offset + idx);
		printline("opcode", "%s\n", rz_asm_op_get_asm(&asmop));
		if (!*disasm) {
			rz_str_ncpy(disasm, rz_asm_op_get_asm(&asmop), sizeof(disasm) - 1);
		}
		{
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
			if (fcn) {
				rz_parse_subvar(core->parser, fcn, &op,
					disasm, disasm, sizeof(disasm));
			}
		}
		if (esilstr) {
			int ec = esil_cost(core, addr, esilstr);
			printline("esilcost", "%d\n", ec);
		}
		printline("disasm", "%s\n", disasm);
		{
			char *pseudo = rz_parse_pseudocode(core->parser, disasm);
			if (RZ_STR_ISNOTEMPTY(pseudo)) {
				printline("pseudo", "%s\n", pseudo);
			}
			free(pseudo);
		}
		printline("mnemonic", "%s\n", mnem);
		{
			char *opname = strdup(disasm);
			char *sp = strchr(opname, ' ');
			if (sp) {
				*sp = 0;
			}
			char *d = rz_asm_describe(core->rasm, opname);
			if (d && *d) {
				printline("description", "%s\n", d);
			}
			free(d);
			free(opname);
		}
		{
			ut8 *mask = rz_analysis_mask(core->analysis, len - idx, buf + idx, core->offset + idx);
			char *maskstr = rz_hex_bin2strdup(mask, size);
			printline("mask", "%s\n", maskstr);
			free(mask);
			free(maskstr);
		}
		if (hint) {
			if (hint->opcode) {
				printline("ophint", "%s\n", hint->opcode);
			}
		}
		printline("prefix", "%u\n", op.prefix);
		printline("id", "%d\n", op.id);
		printline("bytes", "%s", "");
		int minsz = RZ_MIN(len, size);
		minsz = RZ_MAX(minsz, 0);
		for (j = 0; j < minsz; j++) {
			rz_cons_printf("%02x", buf[idx + j]);
		}
		rz_cons_newline();
		if (op.val != UT64_MAX) {
			printline("val", "0x%08" PFMT64x "\n", op.val);
		}
		if (op.ptr != UT64_MAX) {
			printline("ptr", "0x%08" PFMT64x "\n", op.ptr);
		}
		if (op.disp && op.disp != UT64_MAX) {
			printline("disp", "0x%08" PFMT64x "\n", op.disp);
		}
		if (op.refptr != -1) {
			printline("refptr", "%d\n", op.refptr);
		}
		printline("size", "%d\n", size);
		printline("sign", "%s\n", rz_str_bool(op.sign));
		printline("type", "%s\n", rz_analysis_optype_to_string(op.type));
		const char *datatype = rz_analysis_datatype_to_string(op.datatype);
		if (datatype) {
			printline("datatype", "%s\n", datatype);
		}
		printline("cycles", "%d\n", op.cycles);
		if (op.failcycles) {
			printline("failcycles", "%d\n", op.failcycles);
		}
		if (op.type2) {
			printline("type2", "0x%x\n", op.type2);
		}
		if (op.reg) {
			printline("reg", "%s\n", op.reg);
		}
		if (op.ireg) {
			printline("ireg", "%s\n", op.ireg);
		}
		if (op.scale) {
			printline("scale", "%d\n", op.scale);
		}
		if (hint && hint->esil) {
			printline("esil", "%s\n", hint->esil);
		} else if (RZ_STR_ISNOTEMPTY(esilstr)) {
			printline("esil", "%s\n", esilstr);
		}
		if (op.il_op) {
			RzStrBuf *sbil = rz_strbuf_new("");
			rz_il_op_effect_stringify(op.il_op, sbil);
			printline("rzil", "%s\n", rz_strbuf_get(sbil));
			rz_strbuf_free(sbil);
		}
		if (hint && hint->jump != UT64_MAX) {
			op.jump = hint->jump;
		}
		if (op.jump != UT64_MAX) {
			printline("jump", "0x%08" PFMT64x "\n", op.jump);
		}
		if (op.direction != 0) {
			const char *dir = op.direction == 1 ? "read"
				: op.direction == 2         ? "write"
				: op.direction == 4         ? "exec"
				: op.direction == 8         ? "ref"
							    : "none";
			printline("direction", "%s\n", dir);
		}
		if (hint && hint->fail != UT64_MAX) {
			op.fail = hint->fail;
		}
		if (op.fail != UT64_MAX) {
			printline("fail", "0x%08" PFMT64x "\n", op.fail);
		}
		if (op.delay) {
			printline("delay", "%d\n", op.delay);
		}
		{
			const char *arg = (op.type & RZ_ANALYSIS_OP_TYPE_COND) ? rz_type_cond_tostring(op.cond) : NULL;
			if (arg) {
				printline("cond", "%s\n", arg);
			}
		}
		printline("family", "%s\n", rz_analysis_op_family_to_string(op.family));
		if (op.stackop != RZ_ANALYSIS_STACK_NULL) {
			printline("stackop", "%s\n", rz_analysis_stackop_tostring(op.stackop));
		}
		if (op.stackptr) {
			printline("stackptr", "%" PFMT64u "\n", op.stackptr);
		}

		// rz_cons_printf ("false: 0x%08"PFMT64x"\n", core->offset+idx);
		// free (hint);
		free(mnem);
		rz_analysis_hint_free(hint);
		rz_analysis_op_fini(&op);
	}

	rz_analysis_op_fini(&op);
	rz_analysis_esil_free(esil);
}

#undef PJ_KS
#undef PJ_KN
#undef printline
#undef printline_noarg

static char *fcnjoin(RzList *list) {
	RzAnalysisFunction *n;
	RzListIter *iter;
	RzStrBuf buf;
	rz_strbuf_init(&buf);
	rz_list_foreach (list, iter, n) {
		rz_strbuf_appendf(&buf, " 0x%08" PFMT64x, n->addr);
	}
	char *s = strdup(rz_strbuf_get(&buf));
	rz_strbuf_fini(&buf);
	return s;
}

static char *ut64join(RzList *list) {
	ut64 *n;
	RzListIter *iter;
	RzStrBuf buf;
	rz_strbuf_init(&buf);
	rz_list_foreach (list, iter, n) {
		rz_strbuf_appendf(&buf, " 0x%08" PFMT64x, *n);
	}
	char *s = strdup(rz_strbuf_get(&buf));
	rz_strbuf_fini(&buf);
	return s;
}

static ut64 initializeEsil(RzCore *core) {
	int romem = rz_config_get_i(core->config, "esil.romem");
	int stats = rz_config_get_i(core->config, "esil.stats");
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int exectrap = rz_config_get_i(core->config, "esil.exectrap");
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	int noNULL = rz_config_get_i(core->config, "esil.noNULL");
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");
	if (!(core->analysis->esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
		return UT64_MAX;
	}
	ut64 addr;
	RzAnalysisEsil *esil = core->analysis->esil;
	esil->verbose = rz_config_get_i(core->config, "esil.verbose");
	esil->cmd = rz_core_esil_cmd;
	rz_analysis_esil_setup(esil, core->analysis, romem, stats, noNULL); // setup io
	{
		const char *cmd_esil_step = rz_config_get(core->config, "cmd.esil.step");
		if (cmd_esil_step && *cmd_esil_step) {
			esil->cmd_step = strdup(cmd_esil_step);
		}
		const char *cmd_esil_step_out = rz_config_get(core->config, "cmd.esil.stepout");
		if (cmd_esil_step_out && *cmd_esil_step_out) {
			esil->cmd_step_out = strdup(cmd_esil_step_out);
		}
		{
			const char *s = rz_config_get(core->config, "cmd.esil.intr");
			if (s) {
				char *my = strdup(s);
				if (my) {
					rz_config_set(core->config, "cmd.esil.intr", my);
					free(my);
				}
			}
		}
	}
	esil->exectrap = exectrap;
	RzList *entries = rz_bin_get_entries(core->bin);
	RzBinAddr *entry = NULL;
	RzBinInfo *info = NULL;
	if (entries && !rz_list_empty(entries)) {
		entry = (RzBinAddr *)rz_list_pop_head(entries);
		info = rz_bin_get_info(core->bin);
		addr = info->has_va ? entry->vaddr : entry->paddr;
		rz_list_push(entries, entry);
	} else {
		addr = core->offset;
	}
	// set memory read only
	return addr;
}

RZ_API int rz_core_esil_step(RzCore *core, ut64 until_addr, const char *until_expr, ut64 *prev_addr, bool stepOver) {
#define return_tail(x) \
	{ \
		tail_return_value = x; \
		goto tail_return; \
	}
	int tail_return_value = 0;
	int ret;
	ut8 code[32];
	RzAnalysisOp op = { 0 };
	RzAnalysisEsil *esil = core->analysis->esil;
	const char *name = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	ut64 addr = 0;
	bool breakoninvalid = rz_config_get_i(core->config, "esil.breakoninvalid");
	int esiltimeout = rz_config_get_i(core->config, "esil.timeout");
	ut64 startTime;

	if (esiltimeout > 0) {
		startTime = rz_time_now_mono();
	}
	rz_cons_break_push(NULL, NULL);
repeat:
	if (rz_cons_is_breaked()) {
		eprintf("[+] ESIL emulation interrupted at 0x%08" PFMT64x "\n", addr);
		return_tail(0);
	}
	// Break if we have exceeded esil.timeout
	if (esiltimeout > 0) {
		ut64 elapsedTime = rz_time_now_mono() - startTime;
		elapsedTime >>= 20;
		if (elapsedTime >= esiltimeout) {
			eprintf("[ESIL] Timeout exceeded.\n");
			return_tail(0);
		}
	}
	if (!esil) {
		addr = initializeEsil(core);
		esil = core->analysis->esil;
		if (!esil) {
			return_tail(0);
		}
	} else {
		esil->trap = 0;
		addr = rz_reg_getv(core->analysis->reg, name);
		// eprintf ("PC=0x%"PFMT64x"\n", (ut64)addr);
	}
	if (prev_addr) {
		*prev_addr = addr;
	}
	if (esil->exectrap) {
		if (!rz_io_is_valid_offset(core->io, addr, RZ_PERM_X)) {
			esil->trap = RZ_ANALYSIS_TRAP_EXEC_ERR;
			esil->trap_code = addr;
			eprintf("[ESIL] Trap, trying to execute on non-executable memory\n");
			return_tail(1);
		}
	}
	rz_asm_set_pc(core->rasm, addr);
	// run esil pin command here
	int dataAlign = rz_analysis_archinfo(esil->analysis, RZ_ANALYSIS_ARCHINFO_DATA_ALIGN);
	if (dataAlign > 1) {
		if (addr % dataAlign) {
			if (esil->cmd && esil->cmd_trap) {
				esil->cmd(esil, esil->cmd_trap, addr, RZ_ANALYSIS_TRAP_UNALIGNED);
			}
			if (breakoninvalid) {
				rz_cons_printf("[ESIL] Stopped execution in an unaligned instruction (see e??esil.breakoninvalid)\n");
				return_tail(0);
			}
		}
	}
	(void)rz_io_read_at_mapped(core->io, addr, code, sizeof(code));
	// TODO: sometimes this is dupe
	ret = rz_analysis_op(core->analysis, &op, addr, code, sizeof(code), RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_HINT);
	// if type is JMP then we execute the next N instructions
	// update the esil pointer because RzAnalysis.op() can change it
	esil = core->analysis->esil;
	if (op.size < 1 || ret < 1) {
		if (esil->cmd && esil->cmd_trap) {
			esil->cmd(esil, esil->cmd_trap, addr, RZ_ANALYSIS_TRAP_INVALID);
		}
		if (breakoninvalid) {
			eprintf("[ESIL] Stopped execution in an invalid instruction (see e??esil.breakoninvalid)\n");
			return_tail(0);
		}
		op.size = 1; // avoid inverted stepping
	}
	if (stepOver) {
		switch (op.type) {
		case RZ_ANALYSIS_OP_TYPE_SWI:
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_CALL:
		case RZ_ANALYSIS_OP_TYPE_JMP:
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_RJMP:
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_RET:
		case RZ_ANALYSIS_OP_TYPE_CRET:
		case RZ_ANALYSIS_OP_TYPE_UJMP:
			if (addr == until_addr) {
				return_tail(0);
			} else {
				rz_reg_setv(core->analysis->reg, "PC", op.addr + op.size);
			}
			return 1;
		}
	}
	rz_reg_setv(core->analysis->reg, name, addr + op.size);
	if (ret) {
		rz_analysis_esil_set_pc(esil, addr);
		const char *e = RZ_STRBUF_SAFEGET(&op.esil);
		if (core->dbg->trace->enabled) {
			RzReg *reg = core->dbg->reg;
			core->dbg->reg = core->analysis->reg;
			rz_debug_trace_op(core->dbg, &op);
			core->dbg->reg = reg;
		} else if (RZ_STR_ISNOTEMPTY(e)) {
			rz_analysis_esil_parse(esil, e);
			if (core->analysis->cur && core->analysis->cur->esil_post_loop) {
				core->analysis->cur->esil_post_loop(esil, &op);
			}
			rz_analysis_esil_stack_free(esil);
		}
		bool isNextFall = false;
		if (op.type == RZ_ANALYSIS_OP_TYPE_CJMP) {
			ut64 pc = rz_reg_getv(core->analysis->reg, name);
			if (pc == addr + op.size) {
				// do not opdelay here
				isNextFall = true;
			}
		}
		// only support 1 slot for now
		if (op.delay && !isNextFall) {
			ut8 code2[32];
			ut64 naddr = addr + op.size;
			RzAnalysisOp op2 = { 0 };
			// emulate only 1 instruction
			rz_analysis_esil_set_pc(esil, naddr);
			(void)rz_io_read_at(core->io, naddr, code2, sizeof(code2));
			// TODO: sometimes this is dupe
			ret = rz_analysis_op(core->analysis, &op2, naddr, code2, sizeof(code2), RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_HINT);
			if (ret > 0) {
				switch (op2.type) {
				case RZ_ANALYSIS_OP_TYPE_CJMP:
				case RZ_ANALYSIS_OP_TYPE_JMP:
				case RZ_ANALYSIS_OP_TYPE_CRET:
				case RZ_ANALYSIS_OP_TYPE_RET:
					// branches are illegal in a delay slot
					esil->trap = RZ_ANALYSIS_TRAP_EXEC_ERR;
					esil->trap_code = addr;
					eprintf("[ESIL] Trap, trying to execute a branch in a delay slot\n");
					return_tail(1);
					break;
				}
				const char *e = RZ_STRBUF_SAFEGET(&op2.esil);
				if (RZ_STR_ISNOTEMPTY(e)) {
					rz_analysis_esil_parse(esil, e);
				}
			} else {
				eprintf("Invalid instruction at 0x%08" PFMT64x "\n", naddr);
			}
			rz_analysis_op_fini(&op2);
		}
		tail_return_value = 1;
	}
	// esil->verbose ?
	// eprintf ("REPE 0x%llx %s => 0x%llx\n", addr, RZ_STRBUF_SAFEGET (&op.esil), rz_reg_getv (core->analysis->reg, "PC"));

	ut64 pc = rz_reg_getv(core->analysis->reg, name);
	if (core->analysis->pcalign > 0) {
		pc -= (pc % core->analysis->pcalign);
		rz_reg_setv(core->analysis->reg, name, pc);
	}

	st64 follow = (st64)rz_config_get_i(core->config, "dbg.follow");
	if (follow > 0) {
		ut64 pc = rz_reg_getv(core->analysis->reg, name);
		if ((pc < core->offset) || (pc > (core->offset + follow))) {
			rz_core_seek_to_register(core, "PC", false);
		}
	}
	// check breakpoints
	if (rz_bp_get_at(core->dbg->bp, pc)) {
		rz_cons_printf("[ESIL] hit breakpoint at 0x%" PFMT64x "\n", pc);
		return_tail(0);
	}
	// check addr
	if (until_addr != UT64_MAX) {
		if (pc == until_addr) {
			return_tail(0);
		}
		goto repeat;
	}
	// check esil
	if (esil && esil->trap) {
		if (core->analysis->esil->verbose) {
			eprintf("TRAP\n");
		}
		return_tail(0);
	}
	if (until_expr) {
		if (rz_analysis_esil_condition(core->analysis->esil, until_expr)) {
			if (core->analysis->esil->verbose) {
				eprintf("ESIL BREAK!\n");
			}
			return_tail(0);
		}
		goto repeat;
	}
tail_return:
	rz_analysis_op_fini(&op);
	rz_cons_break_pop();
	return tail_return_value;
}

RZ_API int rz_core_esil_step_back(RzCore *core) {
	rz_return_val_if_fail(core->analysis->esil && core->analysis->esil->trace, -1);
	RzAnalysisEsil *esil = core->analysis->esil;
	if (esil->trace->idx > 0) {
		rz_analysis_esil_trace_restore(esil, esil->trace->idx - 1);
		rz_core_reg_update_flags(core);
		return 1;
	}
	return 0;
}

RZ_API bool rz_core_esil_continue_back(RzCore *core) {
	rz_return_val_if_fail(core->analysis->esil && core->analysis->esil->trace, false);
	RzAnalysisEsil *esil = core->analysis->esil;
	if (esil->trace->idx == 0) {
		return true;
	}

	RzRegItem *ripc = rz_reg_get(esil->analysis->reg, "PC", -1);
	RzVector *vreg = ht_up_find(esil->trace->registers, ripc->offset | (ripc->arena << 16), NULL);
	if (!vreg) {
		RZ_LOG_ERROR("failed to find PC change vector\n");
		return false;
	}

	// Search for the nearest breakpoint in the tracepoints before the current position
	bool bp_found = false;
	int idx = 0;
	RzAnalysisEsilRegChange *reg;
	rz_vector_foreach_prev(vreg, reg) {
		if (reg->idx >= esil->trace->idx) {
			continue;
		}
		bp_found = rz_bp_get_in(core->dbg->bp, reg->data, RZ_PERM_X) != NULL;
		if (bp_found) {
			idx = reg->idx;
			eprintf("hit breakpoint at: 0x%" PFMT64x " idx: %d\n", reg->data, reg->idx);
			break;
		}
	}

	// Return to the nearest breakpoint or jump back to the first index if a breakpoint wasn't found
	rz_analysis_esil_trace_restore(esil, idx);

	rz_core_reg_update_flags(core);

	return true;
}

static void cmd_address_info(RzCore *core, const char *addrstr, int fmt) {
	ut64 addr, type;
	if (!addrstr || !*addrstr) {
		addr = core->offset;
	} else {
		addr = rz_num_math(core->num, addrstr);
	}
	type = rz_core_analysis_address(core, addr);
	switch (fmt) {
	case 'j': {
		PJ *pj = pj_new();
		if (!pj) {
			return;
		}
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
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	} break;
	default:
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
	}
}

static void cmd_analysis_info(RzCore *core, const char *input) {
	switch (input[0]) {
	case '?': // "ai?""
		rz_core_cmd_help(core, help_msg_ai);
		break;
	case ' ': // "ai "
		cmd_address_info(core, input, 0);
		break;
	case 'i': // "aii"
		// global imports
		if (input[1]) {
			if (input[1] == ' ') {
				char *s = rz_str_trim_dup(input + 1);
				if (s) {
					rz_analysis_add_import(core->analysis, s);
					free(s);
				}
			} else if (input[1] == '-') {
				rz_analysis_purge_imports(core->analysis);
			} else {
				eprintf("Usagae: aii [namespace] # see afii - imports\n");
			}
		} else {
			if (core->analysis->imports) {
				char *imp;
				RzListIter *iter;
				rz_list_foreach (core->analysis->imports, iter, imp) {
					rz_cons_printf("%s\n", imp);
				}
			}
		}
		break;
	case 'j': // "aij"
		cmd_address_info(core, input + 1, 'j');
		break;
	default:
		cmd_address_info(core, NULL, 0);
		break;
	}
}

typedef struct {
	RzList *regs;
	RzList *regread;
	RzList *regwrite;
	RzList *regvalues;
	RzList *inputregs;
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

static bool contains(RzList *list, const char *name) {
	RzListIter *iter;
	const char *n;
	rz_list_foreach (list, iter, n) {
		if (!strcmp(name, n))
			return true;
	}
	return false;
}

static char *oldregread = NULL;
static RzList *mymemxsr = NULL;
static RzList *mymemxsw = NULL;

#define RZ_NEW_DUP(x) memcpy((void *)malloc(sizeof(x)), &(x), sizeof(x))
typedef struct {
	ut64 addr;
	int size;
} AeaMemItem;

static int mymemwrite(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	RzListIter *iter;
	AeaMemItem *n;
	rz_list_foreach (mymemxsw, iter, n) {
		if (addr == n->addr) {
			return len;
		}
	}
	if (!rz_io_is_valid_offset(esil->analysis->iob.io, addr, 0)) {
		return false;
	}
	n = RZ_NEW(AeaMemItem);
	if (n) {
		n->addr = addr;
		n->size = len;
		rz_list_push(mymemxsw, n);
	}
	return len;
}

static int mymemread(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	RzListIter *iter;
	AeaMemItem *n;
	rz_list_foreach (mymemxsr, iter, n) {
		if (addr == n->addr) {
			return len;
		}
	}
	if (!rz_io_is_valid_offset(esil->analysis->iob.io, addr, 0)) {
		return false;
	}
	n = RZ_NEW(AeaMemItem);
	if (n) {
		n->addr = addr;
		n->size = len;
		rz_list_push(mymemxsr, n);
	}
	return len;
}

static int myregwrite(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	AeaStats *stats = esil->user;
	if (oldregread && !strcmp(name, oldregread)) {
		rz_list_pop(stats->regread);
		RZ_FREE(oldregread)
	}
	if (!IS_DIGIT(*name)) {
		if (!contains(stats->regs, name)) {
			rz_list_push(stats->regs, strdup(name));
		}
		if (!contains(stats->regwrite, name)) {
			rz_list_push(stats->regwrite, strdup(name));
		}
		char *v = rz_str_newf("%" PFMT64d, *val);
		if (!contains(stats->regvalues, v)) {
			rz_list_push(stats->regvalues, strdup(v));
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
				rz_list_push(stats->inputregs, strdup(name));
			}
		}
		if (!contains(stats->regs, name)) {
			rz_list_push(stats->regs, strdup(name));
		}
		if (!contains(stats->regread, name)) {
			rz_list_push(stats->regread, strdup(name));
		}
	}
	return 0;
}

static void showregs(RzList *list) {
	if (!rz_list_empty(list)) {
		char *reg;
		RzListIter *iter;
		rz_list_foreach (list, iter, reg) {
			rz_cons_print(reg);
			if (iter->n) {
				rz_cons_printf(" ");
			}
		}
	}
	rz_cons_newline();
}

static void showmem(RzList *list) {
	if (!rz_list_empty(list)) {
		AeaMemItem *item;
		RzListIter *iter;
		rz_list_foreach (list, iter, item) {
			rz_cons_printf(" 0x%08" PFMT64x, item->addr);
		}
	}
	rz_cons_newline();
}

static void showregs_json(RzList *list, PJ *pj) {
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

static void showmem_json(RzList *list, PJ *pj) {
	pj_a(pj);
	if (!rz_list_empty(list)) {
		RzListIter *iter;
		AeaMemItem *item;
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

	mymemxsr = rz_list_new();
	mymemxsw = rz_list_new();
	esil->user = &stats;
	esil->cb.hook_reg_write = myregwrite;
	esil->cb.hook_reg_read = myregread;
	esil->cb.hook_mem_write = mymemwrite;
	esil->cb.hook_mem_read = mymemread;
	esil->nowrite = true;
	for (ops = ptr = 0; ptr < buf_sz && hasNext(mode); ops++, ptr += len) {
		len = rz_analysis_op(core->analysis, &aop, addr + ptr, buf + ptr, buf_sz - ptr, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_HINT);
		esilstr = RZ_STRBUF_SAFEGET(&aop.esil);
		if (RZ_STR_ISNOTEMPTY(esilstr)) {
			if (len < 1) {
				eprintf("Invalid 0x%08" PFMT64x " instruction %02x %02x\n",
					addr + ptr, buf[ptr], buf[ptr + 1]);
				break;
			}
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
				rz_list_push(regnow, strdup(reg));
			}
		}
	}
	if ((mode >> 5) & 1) {
		RzListIter *iter;
		AeaMemItem *n;
		int c = 0;
		rz_cons_printf("f-mem.*\n");
		rz_list_foreach (mymemxsr, iter, n) {
			rz_cons_printf("f mem.read.%d 0x%08x @ 0x%08" PFMT64x "\n", c++, n->size, n->addr);
		}
		c = 0;
		rz_list_foreach (mymemxsw, iter, n) {
			rz_cons_printf("f mem.write.%d 0x%08x @ 0x%08" PFMT64x "\n", c++, n->size, n->addr);
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
		if (!rz_list_empty(mymemxsr)) {
			pj_k(pj, "@R");
			showmem_json(mymemxsr, pj);
		}
		if (!rz_list_empty(mymemxsw)) {
			pj_k(pj, "@W");
			showmem_json(mymemxsw, pj);
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
		if (!rz_list_empty(mymemxsr)) {
			rz_cons_printf("@R:");
			showmem(mymemxsr);
		}
		if (!rz_list_empty(mymemxsw)) {
			rz_cons_printf("@W:");
			showmem(mymemxsw);
		}
	}

	rz_list_free(mymemxsr);
	rz_list_free(mymemxsw);
	mymemxsr = NULL;
	mymemxsw = NULL;
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
	RzAnalysisEsil *esil = core->analysis->esil;
	if (esil) {
		sdb_reset(esil->stats);
	}
	rz_analysis_esil_free(esil);
	core->analysis->esil = NULL;
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
			eprintf("Usage: aefa [from] # if no from address is given, uses fcn.addr\n");
			return;
		}
	}
	eprintf("Emulate from 0x%08" PFMT64x " to 0x%08" PFMT64x "\n", from, to);
	eprintf("Resolve call args for 0x%08" PFMT64x "\n", to);

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

RZ_API bool rz_core_esil_dumpstack(RzAnalysisEsil *esil) {
	rz_return_val_if_fail(esil, false);
	int i;
	if (esil->trap) {
		rz_cons_printf("ESIL TRAP type %d code 0x%08x %s\n",
			esil->trap, esil->trap_code,
			rz_analysis_esil_trapstr(esil->trap));
	}
	if (esil->stackptr < 1) {
		return false;
	}
	for (i = esil->stackptr - 1; i >= 0; i--) {
		rz_cons_printf("%s\n", esil->stack[i]);
	}
	return true;
}

static void __analysis_esil_function(RzCore *core, ut64 addr) {
	RzListIter *iter;
	RzAnalysisBlock *bb;
	if (!core->analysis->esil) {
		rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
	}
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis,
		addr, RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
	if (fcn) {
		// emulate every instruction in the function recursively across all the basic blocks
		rz_list_foreach (fcn->bbs, iter, bb) {
			ut64 pc = bb->addr;
			ut64 end = bb->addr + bb->size;
			RzAnalysisOp op;
			int ret, bbs = end - pc;
			if (bbs < 1 || bbs > 0xfffff || pc >= end) {
				eprintf("Invalid block size\n");
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
				ret = rz_analysis_op(core->analysis, &op, pc, buf + pc - bb->addr, left, RZ_ANALYSIS_OP_MASK_HINT | RZ_ANALYSIS_OP_MASK_ESIL); // read overflow
				opskip = false;
				switch (op.type) {
				case RZ_ANALYSIS_OP_TYPE_CALL:
				case RZ_ANALYSIS_OP_TYPE_RET:
					opskip = true;
					break;
				}
				if (ret) {
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
		eprintf("Cannot find function at 0x%08" PFMT64x "\n", addr);
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
				eprintf("Missing argument\n");
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
			eprintf("esil vm not initialized. run `aei`\n");
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
				eprintf("esil.stats is empty. Run 'aei'\n");
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
					eprintf("Failed to load interrupts from '%s'.", input + 3);
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
		hex = strdup(input);
		if (!hex) {
			break;
		}

		RzAnalysisOp aop = RZ_EMPTY;
		bufsz = rz_hex_str2bin(hex, (ut8 *)hex);
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
		if (rz_analysis_op(core->analysis, &op, addr, buf + bufi, 4096 - bufi, RZ_ANALYSIS_OP_MASK_BASIC)) {
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

static void _analysis_calls(RzCore *core, ut64 addr, ut64 addr_end, bool importsOnly) {
	RzAnalysisOp op;
	int depth = rz_config_get_i(core->config, "analysis.depth");
	const int addrbytes = core->io->addrbytes;
	const int bsz = 4096;
	int bufi = 0;
	int bufi_max = bsz - 16;
	if (addr_end - addr > UT32_MAX) {
		return;
	}
	ut8 *buf = malloc(bsz);
	ut8 *block0 = calloc(1, bsz);
	ut8 *block1 = malloc(bsz);
	if (!buf || !block0 || !block1) {
		eprintf("Error: cannot allocate buf or block\n");
		free(buf);
		free(block0);
		free(block1);
		return;
	}
	memset(block1, -1, bsz);
	int minop = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	if (minop < 1) {
		minop = 1;
	}
	int setBits = rz_config_get_i(core->config, "asm.bits");
	rz_cons_break_push(NULL, NULL);
	while (addr < addr_end && !rz_cons_is_breaked()) {
		// TODO: too many ioreads here
		if (bufi > bufi_max) {
			bufi = 0;
		}
		if (!bufi) {
			(void)rz_io_read_at(core->io, addr, buf, bsz);
		}
		if (!memcmp(buf, block0, bsz) || !memcmp(buf, block1, bsz)) {
			// eprintf ("Error: skipping uninitialized block \n");
			addr += bsz;
			continue;
		}
		RzAnalysisHint *hint = rz_analysis_hint_get(core->analysis, addr);
		if (hint && hint->bits) {
			setBits = hint->bits;
		}
		rz_analysis_hint_free(hint);
		if (setBits != core->rasm->bits) {
			rz_config_set_i(core->config, "asm.bits", setBits);
		}
		if (rz_analysis_op(core->analysis, &op, addr, buf + bufi, bsz - bufi, 0) > 0) {
			if (op.size < 1) {
				op.size = minop;
			}
			if (op.type == RZ_ANALYSIS_OP_TYPE_CALL) {
				bool isValidCall = true;
				if (importsOnly) {
					RzFlagItem *f = rz_flag_get_i(core->flags, op.jump);
					if (!f || !strstr(f->name, "imp.")) {
						isValidCall = false;
					}
				}
				RzBinReloc *rel = rz_core_getreloc(core, addr, op.size);
				if (rel && (rel->import || rel->symbol)) {
					isValidCall = false;
				}
				if (isValidCall) {
					ut8 buf[4];
					rz_io_read_at(core->io, op.jump, buf, 4);
					isValidCall = memcmp(buf, "\x00\x00\x00\x00", 4);
				}
				if (isValidCall) {
					// add xref here
					rz_analysis_xrefs_set(core->analysis, addr, op.jump, RZ_ANALYSIS_XREF_TYPE_CALL);
					if (rz_io_is_valid_offset(core->io, op.jump, 1)) {
						rz_core_analysis_fcn(core, op.jump, addr, RZ_ANALYSIS_XREF_TYPE_CALL, depth);
					}
				}
			}
		} else {
			op.size = minop;
		}
		if ((int)op.size < 1) {
			op.size = minop;
		}
		addr += op.size;
		bufi += addrbytes * op.size;
		rz_analysis_op_fini(&op);
	}
	rz_cons_break_pop();
	free(buf);
	free(block0);
	free(block1);
}

RZ_API void rz_core_analysis_calls(RZ_NONNULL RzCore *core, bool imports_only) {
	rz_return_if_fail(core);

	RzList *ranges = NULL;
	RzIOMap *r;
	ut64 addr;
	RzBinFile *binfile = rz_bin_cur(core->bin);
	addr = core->offset;
	if (binfile) {
		ranges = rz_core_get_boundaries_prot(core, RZ_PERM_X, NULL, "analysis");
	}
	rz_cons_break_push(NULL, NULL);
	if (!binfile || rz_list_length(ranges) < 1) {
		RzListIter *iter;
		RzIOMap *map;
		rz_list_free(ranges);
		ranges = rz_core_get_boundaries_prot(core, 0, NULL, "analysis");
		if (ranges) {
			rz_list_foreach (ranges, iter, map) {
				ut64 addr = map->itv.addr;
				_analysis_calls(core, addr, rz_itv_end(map->itv), imports_only);
			}
		}
	} else {
		RzListIter *iter;
		if (binfile) {
			rz_list_foreach (ranges, iter, r) {
				addr = r->itv.addr;
				// this normally will happen on fuzzed binaries, dunno if with huge
				// binaries as well
				if (rz_cons_is_breaked()) {
					break;
				}
				_analysis_calls(core, addr, rz_itv_end(r->itv), imports_only);
			}
		}
	}
	rz_cons_break_pop();
	rz_list_free(ranges);
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

static const char *syscallNumber(int n) {
	return sdb_fmt(n > 1000 ? "0x%x" : "%d", n);
}

RZ_IPI RzCmdStatus rz_analysis_syscall_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzListIter *iter;
	RzSyscallItem *si;
	RzList *list = rz_syscall_list(core->analysis->syscall);
	rz_cmd_state_output_array_start(state);
	rz_list_foreach (list, iter, si) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("%s = 0x%02x.%s\n",
				si->name, si->swi, syscallNumber(si->num));
			break;
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
	st64 num = rz_syscall_get_num(core->analysis->syscall, argv[1]);
	if (num < 1) {
		RZ_LOG_ERROR("Cannot resolve syscall: %s\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(syscallNumber(num));
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
		rz_cons_printf("#define SYS_%s %s\n", si->name, syscallNumber(si->num));
	} else {
		rz_cons_printf(".equ SYS_%s %s\n", si->name, syscallNumber(si->num));
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
			rz_cons_printf(".equ SYS_%s %s\n", argv[1], syscallNumber(n));
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

#define var_ref_list(a, d, t) sdb_fmt("var.0x%" PFMT64x ".%d.%d.%s", \
	a, 1, d, (t == 'R') ? "reads" : "writes");

static char *getViewerPath(void) {
	int i;
	const char *viewers[] = {
#if __WINDOWS__
		"explorer",
#else
		"open",
		"geeqie",
		"gqview",
		"eog",
		"xdg-open",
#endif
		NULL
	};
	for (i = 0; viewers[i]; i++) {
		char *viewerPath = rz_file_path(viewers[i]);
		if (viewerPath && strcmp(viewerPath, viewers[i])) {
			return viewerPath;
		}
		free(viewerPath);
	}
	return NULL;
}

static char *dot_executable_path(void) {
	const char *dot = "dot";
	char *dotPath = rz_file_path(dot);
	if (!strcmp(dotPath, dot)) {
		free(dotPath);
		dot = "xdot";
		dotPath = rz_file_path(dot);
		if (!strcmp(dotPath, dot)) {
			free(dotPath);
			return NULL;
		}
	}
	return dotPath;
}

static bool convert_dot_to_image(RzCore *core, const char *dot_file, const char *save_path) {
	char *dot = dot_executable_path();
	bool result = false;
	if (!dot) {
		eprintf("Graphviz not found\n");
		return false;
	}
	const char *ext = rz_config_get(core->config, "graph.gv.format");

	char *cmd = NULL;
	if (save_path && *save_path) {
		cmd = rz_str_newf("!%s -T%s -o%s a.dot;", dot, ext, save_path);
	} else {
		char *viewer = getViewerPath();
		if (viewer) {
			cmd = rz_str_newf("!%s -T%s -oa.%s a.dot;!%s a.%s",
				dot, ext, ext, viewer, ext);
			free(viewer);
		} else {
			eprintf("Cannot find a valid picture viewer\n");
			goto end;
		}
	}
	rz_core_cmd0(core, cmd);
	result = true;
end:
	free(cmd);
	free(dot);
	return result;
}

static bool convert_dotcmd_to_image(RzCore *core, char *rz_cmd, const char *save_path) {
	if (save_path && *save_path) {
		rz_cons_printf("Saving to file '%s'...\n", save_path);
		rz_cons_flush();
	}
	rz_core_cmdf(core, "%s > a.dot", rz_cmd); // TODO: check error here
	return convert_dot_to_image(core, "a.dot", save_path);
}

static bool convert_dot_str_to_image(RzCore *core, char *str, const char *save_path) {
	if (save_path && *save_path) {
		rz_cons_printf("Saving to file '%s'...\n", save_path);
		rz_cons_flush();
	}
	if (!rz_file_dump("a.dot", (const unsigned char *)str, -1, false)) {
		return false;
	}
	return convert_dot_to_image(core, "a.dot", save_path);
}

RZ_IPI void rz_core_agraph_print_write(RzCore *core, const char *filename) {
	convert_dotcmd_to_image(core, "aggd", filename);
}

static void cmd_agraph_node(RzCore *core, const char *input) {
	switch (*input) {
	case ' ': { // "agn"
		int n_args = 0;
		char **args = rz_str_argv(input, &n_args);
		if (n_args < 1 || n_args > 3) {
			rz_cons_printf("Wrong arguments\n");
			rz_str_argv_free(args);
			break;
		}
		const char *title = args[0];
		const char *body = n_args > 1 ? args[1] : "";
		int color = n_args > 2 ? atoi(args[2]) : -1;
		rz_core_agraph_add_node(core, title, body, color);
		rz_str_argv_free(args);
		break;
	}
	case '-': { // "agn-"
		char **args;
		int n_args;

		input++;
		args = rz_str_argv(input, &n_args);
		if (n_args != 1) {
			rz_cons_printf("Wrong arguments\n");
			rz_str_argv_free(args);
			break;
		}
		rz_core_agraph_del_node(core, args[0]);
		rz_str_argv_free(args);
		break;
	}
	case '?': // "agn?"
	default:
		rz_core_cmd_help(core, help_msg_agn);
		break;
	}
}

static void cmd_agraph_edge(RzCore *core, const char *input) {
	char **args;
	int n_args;

	switch (*input) {
	case ' ': // "age"
		args = rz_str_argv(input + 1, &n_args);
		if (n_args != 2) {
			rz_cons_printf("Wrong arguments\n");
			rz_str_argv_free(args);
			break;
		}

		rz_core_agraph_add_edge(core, args[0], args[1]);
		rz_str_argv_free(args);
		break;
	case '-': // "age-"
		args = rz_str_argv(input + 1, &n_args);
		if (n_args != 2) {
			rz_cons_printf("Wrong arguments\n");
			rz_str_argv_free(args);
			break;
		}

		rz_core_agraph_del_edge(core, args[0], args[1]);
		rz_str_argv_free(args);
		break;
	case '?': // "age?"
	default:
		rz_core_cmd_help(core, help_msg_age);
		break;
	}
}

RZ_API void rz_core_agraph_print(RzCore *core, int use_utf, const char *input) {
	if (use_utf != -1) {
		rz_config_set_i(core->config, "scr.utf8", use_utf);
	}
	switch (*input) {
	case 0:
		rz_core_agraph_print_ascii(core);
		break;
	case 't': // "aggt" - tiny graph
		rz_core_agraph_print_tiny(core);
		break;
	case 'k': // "aggk"
		rz_core_agraph_print_sdb(core);
		break;
	case 'v': // "aggv"
	case 'i': // "aggi" - open current core->graph in interactive mode
		rz_core_agraph_print_interactive(core);
		break;
	case 'd': // "aggd" - dot format
		rz_core_agraph_print_dot(core);
		break;
	case '*': // "agg*" -
		rz_core_agraph_print_rizin(core);
		break;
	case 'J': // "aggJ"
	case 'j': // "aggj"
		rz_core_agraph_print_json(core);
		break;
	case 'g': // "aggg"
		rz_core_agraph_print_gml(core);
		break;
	case 'w': { // "aggw"
		const char *filename = rz_str_trim_head_ro(input + 1);
		rz_core_agraph_print_write(core, filename);
		break;
	}
	default:
		eprintf("Usage: see ag?\n");
	}
}

static void print_graph_agg(RzGraph /*RzGraphNodeInfo*/ *graph) {
	RzGraphNodeInfo *print_node;
	RzGraphNode *node, *target;
	RzListIter *it, *edge_it;
	rz_list_foreach (graph->nodes, it, node) {
		char *encbody;
		int len;
		print_node = node->data;
		if (RZ_STR_ISNOTEMPTY(print_node->body)) {
			len = strlen(print_node->body);
			if (len > 0 && print_node->body[len - 1] == '\n') {
				len--;
			}
			encbody = rz_base64_encode_dyn((const ut8 *)print_node->body, len);
			rz_cons_printf("agn \"%s\" base64:%s\n", print_node->title, encbody);
			free(encbody);
		} else {
			rz_cons_printf("agn \"%s\"\n", print_node->title);
		}
	}
	rz_list_foreach (graph->nodes, it, node) {
		print_node = node->data;
		rz_list_foreach (node->out_nodes, edge_it, target) {
			RzGraphNodeInfo *to = target->data;
			rz_cons_printf("age \"%s\" \"%s\"\n", print_node->title, to->title);
		}
	}
}

static char *print_graph_dot(RzCore *core, RzGraph /*<RzGraphNodeInfo>*/ *graph) {
	const char *font = rz_config_get(core->config, "graph.font");
	char *node_properties = rz_str_newf("fontname=\"%s\"", font);
	char *result = rz_graph_drawable_to_dot(graph, node_properties, NULL);
	free(node_properties);
	return result;
}

static void rz_core_graph_print(RzCore *core, RzGraph /*<RzGraphNodeInfo>*/ *graph, int use_utf, bool use_offset, const char *input) {
	RzAGraph *agraph = NULL;
	RzListIter *it;
	RzListIter *edge_it;
	RzGraphNode *graphNode, *target;
	RzGraphNodeInfo *print_node;
	if (use_utf != -1) {
		rz_config_set_i(core->config, "scr.utf8", use_utf);
	}
	switch (*input) {
	case 0:
	case 't':
	case 'k':
	case 'v':
	case 'i': {
		agraph = create_agraph_from_graph(graph);
		switch (*input) {
		case 0:
			agraph->can->linemode = rz_config_get_i(core->config, "graph.linemode");
			agraph->can->color = rz_config_get_i(core->config, "scr.color");
			rz_agraph_set_title(agraph,
				rz_config_get(core->config, "graph.title"));
			rz_agraph_print(agraph);
			break;
		case 't': { // "ag_t" - tiny graph
			agraph->is_tiny = true;
			int e = rz_config_get_i(core->config, "graph.edges");
			rz_config_set_i(core->config, "graph.edges", 0);
			rz_core_visual_graph(core, agraph, NULL, false);
			rz_config_set_i(core->config, "graph.edges", e);
			break;
		}
		case 'k': // "ag_k"
		{
			Sdb *db = rz_agraph_get_sdb(agraph);
			char *o = sdb_querys(db, "null", 0, "*");
			rz_cons_print(o);
			free(o);
			break;
		}
		case 'v': // "ag_v"
		case 'i': // "ag_i" - open current core->graph in interactive mode
		{
			RzANode *ran = rz_agraph_get_first_node(agraph);
			if (ran) {
				ut64 oseek = core->offset;
				rz_agraph_set_title(agraph, rz_config_get(core->config, "graph.title"));
				rz_agraph_set_curnode(agraph, ran);
				agraph->force_update_seek = true;
				agraph->need_set_layout = true;
				agraph->layout = rz_config_get_i(core->config, "graph.layout");
				bool ov = rz_cons_is_interactive();
				agraph->need_update_dim = true;
				int update_seek = rz_core_visual_graph(core, agraph, NULL, true);
				rz_config_set_i(core->config, "scr.interactive", ov);
				rz_cons_show_cursor(true);
				rz_cons_enable_mouse(false);
				if (update_seek != -1) {
					rz_core_seek(core, oseek, false);
				}
			} else {
				eprintf("This graph contains no nodes\n");
			}
			break;
		}
		}
		break;
	}
	case 'd': { // "ag_d" - dot format
		char *dot_text = print_graph_dot(core, graph);
		if (dot_text) {
			rz_cons_print(dot_text);
			free(dot_text);
		}
		break;
	}
	case '*': // "ag_*" -
		print_graph_agg(graph);
		break;
	case 'J': // "ag_J"
	case 'j': { // "ag_j"
		PJ *pj = pj_new();
		if (pj) {
			rz_graph_drawable_to_json(graph, pj, use_offset);
			rz_cons_println(pj_string(pj));
			pj_free(pj);
		}
	} break;
	case 'g': // "ag_g"
		rz_cons_printf("graph\n[\n"
			       "hierarchic 1\n"
			       "label \"\"\n"
			       "directed 1\n");
		rz_list_foreach (graph->nodes, it, graphNode) {
			print_node = graphNode->data;
			rz_cons_printf("  node [\n"
				       "    id  %d\n"
				       "    label  \"%s\"\n"
				       "  ]\n",
				graphNode->idx, print_node->title);
		}
		rz_list_foreach (graph->nodes, it, graphNode) {
			rz_list_foreach (graphNode->out_nodes, edge_it, target) {
				rz_cons_printf("  edge [\n"
					       "    source  %d\n"
					       "    target  %d\n"
					       "  ]\n",
					graphNode->idx, target->idx);
			}
		}
		rz_cons_print("]\n");
		break;
	case 'w': { // "ag_w"
		const char *filename = rz_str_trim_head_ro(input + 1);
		char *dot_text = print_graph_dot(core, graph);
		if (dot_text) {
			convert_dot_str_to_image(core, dot_text, filename);
			free(dot_text);
		}
		break;
	}
	default:
		eprintf("Usage: see ag?\n");
	}
}

static void cmd_analysis_graph(RzCore *core, const char *input) {
	core->graph->show_node_titles = rz_config_get_i(core->config, "graph.ntitles");
	rz_cons_enable_highlight(false);
	switch (input[0]) {
	case 'f': // "agf"
		switch (input[1]) {
		case 0: // "agf"
			rz_core_visual_graph(core, NULL, NULL, false);
			break;
		case ' ': { // "agf "
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
			rz_core_visual_graph(core, NULL, fcn, false);
			break;
		}
		case 'v': // "agfv"
			eprintf("\rRendering graph...\n");
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_ROOT);
			if (fcn) {
				rz_core_visual_graph(core, NULL, fcn, 1);
			}
			rz_cons_enable_mouse(false);
			rz_cons_show_cursor(true);
			break;
		case 't': { // "agft" - tiny graph
			int e = rz_config_get_i(core->config, "graph.edges");
			rz_config_set_i(core->config, "graph.edges", 0);
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
			rz_core_visual_graph(core, NULL, fcn, 2);
			rz_config_set_i(core->config, "graph.edges", e);
			break;
		}
		case 'd': // "agfd"
			if (input[2] == 'm') {
				rz_core_analysis_graph(core, rz_num_math(core->num, input + 3),
					RZ_CORE_ANALYSIS_GRAPHLINES);
			} else {
				rz_core_analysis_graph(core, rz_num_math(core->num, input + 2),
					RZ_CORE_ANALYSIS_GRAPHBODY);
			}
			break;
		case 'j': // "agfj"
			rz_core_analysis_graph(core, rz_num_math(core->num, input + 2), RZ_CORE_ANALYSIS_JSON);
			break;
		case 'J': { // "agfJ"
			// Honor asm.graph=false in json as well
			RzConfigHold *hc = rz_config_hold_new(core->config);
			rz_config_hold_i(hc, "asm.offset", NULL);
			const bool o_graph_offset = rz_config_get_i(core->config, "graph.offset");
			rz_config_set_i(core->config, "asm.offset", o_graph_offset);
			rz_core_analysis_graph(core, rz_num_math(core->num, input + 2),
				RZ_CORE_ANALYSIS_JSON | RZ_CORE_ANALYSIS_JSON_FORMAT_DISASM);
			rz_config_hold_restore(hc);
			rz_config_hold_free(hc);
			break;
		}
		case 'g': { // "agfg"
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
			rz_core_print_bb_gml(core, fcn);
			break;
		}
		case 'k': // "agfk"
			rz_core_agraph_reset(core);
			rz_core_cmdf(core, ".agf* @ %" PFMT64u "", core->offset);
			rz_core_agraph_print_sdb(core);
			break;
		case '*': { // "agf*"
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
			rz_core_print_bb_custom(core, fcn);
			break;
		}
		case 'w': { // "agfw"
			char *cmdargs = rz_str_newf("agfd @ 0x%" PFMT64x, core->offset);
			convert_dotcmd_to_image(core, cmdargs, input + 2);
			free(cmdargs);
			break;
		}
		default:
			eprintf("Usage: see ag?\n");
			break;
		}
		break;
	case '-': // "ag-"
		rz_core_agraph_reset(core);
		break;
	case 'n': // "agn"
		cmd_agraph_node(core, input + 1);
		break;
	case 'e': // "age"
		cmd_agraph_edge(core, input + 1);
		break;
	case 'g': // "agg"
		rz_core_agraph_print(core, -1, input + 1);
		break;
	case 's': // "ags"
		rz_core_analysis_graph(core, rz_num_math(core->num, input + 1), 0);
		break;
	case 'C': // "agC"
		switch (input[1]) {
		case 'v': // "agCv"
		case 't': // "agCt"
		case 'k': // "agCk"
		case 'w': // "agCw"
		case ' ': // "agC "
		case 0: {
			core->graph->is_callgraph = true;
			rz_core_agraph_reset(core);
			rz_core_cmdf(core, ".agC*;");
			rz_core_agraph_print(core, -1, input + 1);
			core->graph->is_callgraph = false;
			break;
		}
		case 'J': // "agCJ"
		case 'j': // "agCj"
			rz_core_analysis_callgraph(core, UT64_MAX, RZ_GRAPH_FORMAT_JSON);
			break;
		case 'g': // "agCg"
			rz_core_analysis_callgraph(core, UT64_MAX, RZ_GRAPH_FORMAT_GML);
			break;
		case 'd': // "agCd"
			rz_core_analysis_callgraph(core, UT64_MAX, RZ_GRAPH_FORMAT_DOT);
			break;
		case '*': // "agC*"
			rz_core_analysis_callgraph(core, UT64_MAX, RZ_GRAPH_FORMAT_CMD);
			break;
		default:
			eprintf("Usage: see ag?\n");
			break;
		}
		break;
	case 'r': // "agr" references graph
		switch (input[1]) {
		case '*': { // "agr*"
			rz_core_analysis_coderefs(core, core->offset);
		} break;
		default: {
			core->graph->is_callgraph = true;
			rz_core_agraph_reset(core);
			rz_core_cmdf(core, ".agr* @ %" PFMT64u ";", core->offset);
			rz_core_agraph_print(core, -1, input + 1);
			core->graph->is_callgraph = false;
			break;
		}
		}
		break;
	case 'R': // "agR" global refs
		switch (input[1]) {
		case '*': { // "agR*"
			ut64 from = rz_config_get_i(core->config, "graph.from");
			ut64 to = rz_config_get_i(core->config, "graph.to");
			RzListIter *it;
			RzAnalysisFunction *fcn;
			rz_list_foreach (core->analysis->fcns, it, fcn) {
				if ((from == UT64_MAX && to == UT64_MAX) || RZ_BETWEEN(from, fcn->addr, to)) {
					rz_core_analysis_coderefs(core, fcn->addr);
				}
			}
			break;
		}
		default: {
			core->graph->is_callgraph = true;
			rz_core_agraph_reset(core);
			rz_core_cmdf(core, ".agR*;");
			rz_core_agraph_print(core, -1, input + 1);
			core->graph->is_callgraph = false;
			break;
		}
		}
		break;
	case 'x': { // "agx" cross refs
		RzGraph *graph = rz_core_analysis_codexrefs(core, core->offset);
		if (!graph) {
			eprintf("Couldn't create graph");
			break;
		}
		rz_core_graph_print(core, graph, -1, true, input + 1);
		rz_graph_free(graph);
		break;
	}
	case 'i': { // "agi" import graph
		RzGraph *graph = rz_core_analysis_importxrefs(core);
		if (!graph) {
			eprintf("Couldn't create graph");
			break;
		}
		rz_core_graph_print(core, graph, -1, true, input + 1);
		rz_graph_free(graph);
		break;
	}
	case 'c': // "agc"
		switch (input[1]) {
		case 'v': // "agcv"
		case 't': // "agct"
		case 'k': // "agck"
		case 'w': // "agcw"
		case ' ': { // "agc "
			core->graph->is_callgraph = true;
			rz_core_agraph_reset(core);
			rz_core_cmdf(core, ".agc* @ %" PFMT64u "; agg%s;", core->offset, input + 1);
			core->graph->is_callgraph = false;
			break;
		}
		case 0: // "agc "
			core->graph->is_callgraph = true;
			rz_core_agraph_reset(core);
			rz_core_cmd0(core, ".agc* $$");
			rz_core_agraph_print_ascii(core);
			core->graph->is_callgraph = false;
			break;
		case 'g': { // "agg"
			rz_core_analysis_callgraph(core, core->offset, RZ_GRAPH_FORMAT_GMLFCN);
			break;
		}
		case 'd': { // "aggd"
			rz_core_analysis_callgraph(core, core->offset, RZ_GRAPH_FORMAT_DOT);
			break;
		}
		case 'J': // "aggJ"
		case 'j': { // "aggj"
			rz_core_analysis_callgraph(core, core->offset, RZ_GRAPH_FORMAT_JSON);
			break;
		}
		case '*': { // "agg*"
			rz_core_analysis_callgraph(core, core->offset, RZ_GRAPH_FORMAT_CMD);
			break;
		}
		default:
			eprintf("Usage: see ag?\n");
			break;
		}
		break;
	case 'j': // "agj" alias for agfj
		rz_core_cmdf(core, "agfj%s", input + 1);
		break;
	case 'J': // "agJ" alias for agfJ
		rz_core_cmdf(core, "agfJ%s", input + 1);
		break;
	case 'k': // "agk" alias for agfk
		rz_core_cmdf(core, "agfk%s", input + 1);
		break;
	case 'l': // "agl"
		rz_core_analysis_graph(core, rz_num_math(core->num, input + 1), RZ_CORE_ANALYSIS_GRAPHLINES);
		break;
	case 'a': // "aga"
		switch (input[1]) {
		case '*': {
			rz_core_analysis_datarefs(core, core->offset);
			break;
		}
		default:
			rz_core_agraph_reset(core);
			rz_core_cmdf(core, ".aga* @ %" PFMT64u ";", core->offset);
			rz_core_agraph_print(core, -1, input + 1);
			break;
		}
		break;
	case 'A': // "agA" global data refs
		switch (input[1]) {
		case '*': {
			ut64 from = rz_config_get_i(core->config, "graph.from");
			ut64 to = rz_config_get_i(core->config, "graph.to");
			RzListIter *it;
			RzAnalysisFunction *fcn;
			rz_list_foreach (core->analysis->fcns, it, fcn) {
				if ((from == UT64_MAX && to == UT64_MAX) || RZ_BETWEEN(from, fcn->addr, to)) {
					rz_core_analysis_datarefs(core, fcn->addr);
				}
			}
			break;
		}
		default:
			rz_core_agraph_reset(core);
			rz_core_cmdf(core, ".agA*;");
			rz_core_agraph_print(core, -1, input + 1);
			break;
		}
		break;
	case 'd': { // "agd"
		int diff_opt = RZ_CORE_ANALYSIS_GRAPHBODY | RZ_CORE_ANALYSIS_GRAPHDIFF;
		switch (input[1]) {
		case 'j': { // "agdj"
			ut64 addr = input[2] ? rz_num_math(core->num, input + 2) : core->offset;
			rz_core_gdiff_function_1_file(core, addr, core->offset);
			rz_core_analysis_graph(core, addr, diff_opt | RZ_CORE_ANALYSIS_JSON);
			break;
		}
		case 'J': { // "agdJ"
			ut64 addr = input[2] ? rz_num_math(core->num, input + 2) : core->offset;
			rz_core_gdiff_function_1_file(core, addr, core->offset);
			rz_core_analysis_graph(core, addr, diff_opt | RZ_CORE_ANALYSIS_JSON | RZ_CORE_ANALYSIS_JSON_FORMAT_DISASM);
			break;
		}
		case '*': { // "agd*"
			ut64 addr = input[2] ? rz_num_math(core->num, input + 2) : core->offset;
			rz_core_gdiff_function_1_file(core, addr, core->offset);
			rz_core_analysis_graph(core, addr, diff_opt | RZ_CORE_ANALYSIS_STAR);
			break;
		}
		case ' ': // "agd "
		case 0:
		case 't': // "agdt"
		case 'k': // "agdk"
		case 'v': // "agdv"
		case 'g': { // "agdg"
			ut64 addr = input[2] ? rz_num_math(core->num, input + 2) : core->offset;
			rz_core_agraph_reset(core);
			rz_core_cmdf(core, ".agd* @ %" PFMT64u "; agg%s;", addr, input + 1);
			break;
		}
		case 'd': { // "agdd"
			ut64 addr = input[2] ? rz_num_math(core->num, input + 2) : core->offset;
			rz_core_gdiff_function_1_file(core, addr, core->offset);
			rz_core_analysis_graph(core, addr, diff_opt);
			break;
		}
		case 'w': { // "agdw"
			char *cmdargs = rz_str_newf("agdd 0x%" PFMT64x, core->offset);
			convert_dotcmd_to_image(core, cmdargs, input + 2);
			free(cmdargs);
			break;
		}
		}
		break;
	}
	case 'v': // "agv" alias for "agfv"
		rz_core_cmdf(core, "agfv%s", input + 1);
		break;
	case 'w': { // "agw"
		char *cmdargs = rz_str_newf("agfd @ 0x%" PFMT64x, core->offset);
		convert_dotcmd_to_image(core, cmdargs, input + 1);
		free(cmdargs);
		break;
	}
	default:
		rz_core_cmd_help(core, help_msg_ag);
		break;
	}
}

static st64 compute_coverage(RzCore *core) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	st64 cov = 0;
	cov += rz_meta_get_size(core->analysis, RZ_META_TYPE_DATA);
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		void **it;
		RzPVector *maps = rz_io_maps(core->io);
		rz_pvector_foreach (maps, it) {
			RzIOMap *map = *it;
			if (map->perm & RZ_PERM_X) {
				ut64 section_end = map->itv.addr + map->itv.size;
				ut64 s = rz_analysis_function_realsize(fcn);
				if (fcn->addr >= map->itv.addr && (fcn->addr + s) < section_end) {
					cov += s;
				}
			}
		}
	}
	return cov;
}

static st64 compute_code(RzCore *core) {
	st64 code = 0;
	void **it;
	RzPVector *maps = rz_io_maps(core->io);
	rz_pvector_foreach (maps, it) {
		RzIOMap *map = *it;
		if (map->perm & RZ_PERM_X) {
			code += map->itv.size;
		}
	}
	return code;
}

static st64 compute_calls(RzCore *core) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	RzList *xrefs;
	st64 cov = 0;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		xrefs = rz_analysis_function_get_xrefs_from(fcn);
		if (xrefs) {
			cov += rz_list_length(xrefs);
			rz_list_free(xrefs);
			xrefs = NULL;
		}
	}
	return cov;
}

static bool analysis_fcn_data(RzCore *core, const char *input) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_ANY);
	if (fcn) {
		int i;
		bool gap = false;
		ut64 gap_addr = UT64_MAX;
		ut32 fcn_size = rz_analysis_function_size_from_entry(fcn);
		char *bitmap = calloc(1, fcn_size);
		if (bitmap) {
			RzAnalysisBlock *b;
			RzListIter *iter;
			rz_list_foreach (fcn->bbs, iter, b) {
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
		return true;
	}
	return false;
}

static bool analysis_fcn_data_gaps(RzCore *core, const char *input) {
	ut64 end = UT64_MAX;
	RzAnalysisFunction *fcn;
	RzListIter *iter;
	int i, wordsize = (core->rasm->bits == 64) ? 8 : 4;
	rz_list_sort(core->analysis->fcns, cmpaddr);
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		if (end != UT64_MAX) {
			int range = fcn->addr - end;
			if (range > 0) {
				for (i = 0; i + wordsize < range; i += wordsize) {
					rz_cons_printf("Cd %d @ 0x%08" PFMT64x "\n", wordsize, end + i);
				}
				rz_cons_printf("Cd %d @ 0x%08" PFMT64x "\n", range - i, end + i);
				// rz_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", range, end);
			}
		}
		end = fcn->addr + rz_analysis_function_size_from_entry(fcn);
	}
	return true;
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
	ut64 addr = rz_num_math(core->num, argv[2]);
	const char *type = argv[3];

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

static void show_reg_args(RzCore *core, int nargs, RzStrBuf *sb) {
	int i;
	char regname[8];
	if (nargs < 0) {
		nargs = 4; // default args if not defined
	}
	for (i = 0; i < nargs; i++) {
		snprintf(regname, sizeof(regname), "A%d", i);
		ut64 v = rz_reg_getv(core->analysis->reg, regname);
		if (sb) {
			rz_strbuf_appendf(sb, "%s0x%08" PFMT64x, i ? ", " : "", v);
		} else {
			rz_cons_printf("A%d 0x%08" PFMT64x "\n", i, v);
		}
	}
}

// ripped from disasm.c: dupe code from there
// TODO: Implement aC* and aCj
static void cmd_analysis_aC(RzCore *core, const char *input) {
	const char *cc = rz_analysis_cc_default(core->analysis);
	RzAnalysisFuncArg *arg;
	RzListIter *iter;
	RzListIter *nextele;
	const char *iarg = strchr(input, ' ');
	if (iarg) {
		iarg++;
	}
	if (!iarg) {
		eprintf("Usage: aC [addr-of-call] # analyze call args\n");
		return;
	}
	RzStrBuf *sb = rz_strbuf_new("");
	ut64 pcv = rz_num_math(core->num, iarg);
	RzAnalysisOp *op = rz_core_analysis_op(core, pcv, -1);
	if (!op) {
		rz_strbuf_free(sb);
		return;
	}
	bool go_on = true;
	if (op->type != RZ_ANALYSIS_OP_TYPE_CALL) {
		show_reg_args(core, -1, sb);
		go_on = false;
	}
	const char *fcn_name = NULL;
	RzAnalysisFunction *fcn;
	if (go_on) {
		fcn = rz_analysis_get_function_at(core->analysis, pcv);
		if (fcn) {
			fcn_name = fcn->name;
		} else {
			RzFlagItem *item = rz_flag_get_i(core->flags, op->jump);
			if (item) {
				fcn_name = item->name;
			}
		}
		char *key = (fcn_name) ? resolve_fcn_name(core->analysis, fcn_name) : NULL;
		if (key) {
			RzType *fcn_type = rz_type_func_ret(core->analysis->typedb, key);
			int nargs = rz_type_func_args_count(core->analysis->typedb, key);
			// remove other comments
			char *fcn_type_str = NULL;
			if (fcn_type) {
				fcn_type_str = rz_type_as_string(core->analysis->typedb, fcn_type);
			}
			const char *sp = fcn_type && fcn_type->kind == RZ_TYPE_KIND_POINTER ? "" : " ";
			rz_strbuf_appendf(sb, "%s%s%s(",
				fcn_type_str ? fcn_type_str : "", sp,
				rz_str_get_null(key));
			if (!nargs) {
				rz_strbuf_appendf(sb, "void)\n");
			}
			free(fcn_type_str);
		} else {
			show_reg_args(core, -1, NULL);
			go_on = false;
		}
	}
	if (go_on) {
		ut64 s_width = (core->analysis->bits == 64) ? 8 : 4;
		const char *sp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
		ut64 spv = rz_reg_getv(core->analysis->reg, sp);
		rz_reg_setv(core->analysis->reg, sp, spv + s_width); // temporarily set stack ptr to sync with carg.c
		RzList *list = rz_core_get_func_args(core, fcn_name);
		if (!rz_list_empty(list)) {
			rz_list_foreach (list, iter, arg) {
				nextele = rz_list_iter_get_next(iter);
				if (!arg->fmt) {
					rz_strbuf_appendf(sb, "?%s", nextele ? ", " : "");
				} else {
					// print_fcn_arg (core, arg->orig_c_type, arg->name, arg->fmt, arg->src, on_stack, 0);
					// const char *fmt = arg->orig_c_type;
					ut64 addr = arg->src;
					char *res = rz_core_cmd_strf(core, "pfq %s @ 0x%08" PFMT64x, arg->fmt, addr);
					// rz_cons_printf ("pfq *%s @ 0x%08" PFMT64x"\n", arg->fmt, addr);
					rz_str_trim(res);
					rz_strbuf_appendf(sb, "%s", res);
					free(res);
				}
			}
			rz_strbuf_appendf(sb, ")");
		} else {
			// function name not resolved
			int i, nargs = 4; // DEFAULT_NARGS;
			if (fcn) {
				// @TODO: fcn->nargs should be updated somewhere and used here instead
				nargs = rz_analysis_var_count(core->analysis, fcn, 's', 1) +
					rz_analysis_var_count(core->analysis, fcn, 'b', 1) +
					rz_analysis_var_count(core->analysis, fcn, 'r', 1);
			}
			if (nargs > 0) {
				if (fcn_name) {
					rz_strbuf_appendf(sb, "; %s(", fcn_name);
				} else {
					rz_strbuf_appendf(sb, "; 0x%" PFMT64x "(", pcv);
				}
				for (i = 0; i < nargs; i++) {
					ut64 v = rz_core_arg_get(core, cc, i);
					rz_strbuf_appendf(sb, "%s0x%" PFMT64x, i ? ", " : "", v);
				}
				rz_strbuf_appendf(sb, ")");
			}
		}
		rz_reg_setv(core->analysis->reg, sp, spv); // reset stack ptr
		rz_list_free(list);
	}
	char *s = rz_strbuf_drain(sb);
	rz_cons_printf("%s\n", s);
	free(s);
}

RZ_IPI int rz_cmd_analysis(void *data, const char *input) {
	const char *r;
	RzCore *core = (RzCore *)data;
	ut32 tbs = core->blocksize;
	switch (input[0]) {
	case 'p': // "ap"
	{
		const ut8 *prelude = (const ut8 *)"\xe9\x2d"; //: fffff000";
		const int prelude_sz = 2;
		const int bufsz = 4096;
		ut8 *buf = calloc(1, bufsz);
		ut64 off = core->offset;
		if (input[1] == ' ') {
			off = rz_num_math(core->num, input + 1);
			rz_io_read_at(core->io, off - bufsz + prelude_sz, buf, bufsz);
		} else {
			rz_io_read_at(core->io, off - bufsz + prelude_sz, buf, bufsz);
		}
		// const char *prelude = "\x2d\xe9\xf0\x47"; //:fffff000";
		rz_mem_reverse(buf, bufsz);
		// rz_print_hexdump (NULL, off, buf, bufsz, 16, -16);
		const ut8 *pos = rz_mem_mem(buf, bufsz, prelude, prelude_sz);
		if (pos) {
			int delta = (size_t)(pos - buf);
			eprintf("POS = %d\n", delta);
			eprintf("HIT = 0x%" PFMT64x "\n", off - delta);
			rz_cons_printf("0x%08" PFMT64x "\n", off - delta);
		} else {
			eprintf("Cannot find prelude\n");
		}
		free(buf);
	} break;
	case 'C': // "aC"
		cmd_analysis_aC(core, input + 1);
		break;
	case 'i': cmd_analysis_info(core, input + 1); break; // "ai"
	case 'e': cmd_analysis_esil(core, input + 1); break; // "ae"
	case 'L': { // aL
		RzCmdStateOutput state = { 0 };
		switch (input[1]) {
		case 'j':
			rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_JSON);
			break;
		case 'q':
			rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_JSON);
			break;
		default:
			rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STANDARD);
			break;
		}
		rz_core_asm_plugins_print(core, NULL, &state);
		rz_cmd_state_output_print(&state);
		rz_cmd_state_output_fini(&state);
		rz_cons_flush();
		break;
	}
	case 'F': // "aF"
		rz_core_analysis_fcn(core, core->offset, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
		break;
	case 'g': // "ag"
		cmd_analysis_graph(core, input + 1);
		break;
	case '*': // "a*"
		rz_core_cmd0_rzshell(core, "afl*");
		rz_core_cmd0_rzshell(core, "ah*");
		rz_core_cmd0_rzshell(core, "ax*");
		break;
	case 'd': // "ad"
		switch (input[1]) {
		case 'f': // "adf"
			if (input[2] == 'g') {
				analysis_fcn_data_gaps(core, rz_str_trim_head_ro(input + 1));
			} else {
				analysis_fcn_data(core, input + 1);
			}
			break;
		case 't': // "adt"
			cmd_analysis_trampoline(core, input + 2);
			break;
		case ' ': { // "ad"
			const int default_depth = 1;
			const char *p;
			int a, b;
			a = rz_num_math(core->num, input + 2);
			p = strchr(input + 2, ' ');
			b = p ? rz_num_math(core->num, p + 1) : default_depth;
			if (a < 1) {
				a = 1;
			}
			if (b < 1) {
				b = 1;
			}
			rz_core_analysis_data(core, core->offset, a, b, 0);
		} break;
		case 'k': // "adk"
			r = rz_analysis_data_kind(core->analysis,
				core->offset, core->block, core->blocksize);
			rz_cons_println(r);
			break;
		case '\0': // "ad"
			rz_core_analysis_data(core, core->offset, 2 + (core->blocksize / 4), 1, 0);
			break;
		case '4': // "ad4"
			rz_core_analysis_data(core, core->offset, 2 + (core->blocksize / 4), 1, 4);
			break;
		case '8': // "ad8"
			rz_core_analysis_data(core, core->offset, 2 + (core->blocksize / 4), 1, 8);
			break;
		default:
			rz_core_cmd_help(core, help_msg_ad);
			break;
		}
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
	rz_core_analysis_bbs_info_print(core, fcn, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_blocks_del_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisBlock *b = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	if (!b) {
		eprintf("Cannot find basic block\n");
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
	while (!rz_list_empty(fcn->bbs)) {
		rz_analysis_function_remove_block(fcn, rz_list_first(fcn->bbs));
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
		eprintf("No basic block at 0x%" PFMT64x, core->offset);
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
	RzAnalysisDiff *diff = NULL;
	if (argc > 6) {
		diff = rz_analysis_diff_new();
		diff->type = argv[6][0] == 'm' ? RZ_ANALYSIS_DIFF_TYPE_MATCH : RZ_ANALYSIS_DIFF_TYPE_UNMATCH;
	}
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, fcn_addr);
	if (!fcn) {
		eprintf("Cannot find function at 0x%" PFMT64x "\n", fcn_addr);
		goto err;
	}
	if (!rz_analysis_fcn_add_bb(core->analysis, fcn, addr, size, jump, fail, diff)) {
		eprintf("Cannot add basic block at 0x%" PFMT64x " to fcn at 0x%" PFMT64x "\n", addr, fcn_addr);
		goto err;
	}
	res = RZ_CMD_STATUS_OK;
err:
	rz_analysis_diff_free(diff);
	return res;
}

RZ_IPI RzCmdStatus rz_analysis_function_blocks_color_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = rz_num_math(core->num, argv[1]);
	ut32 color = (ut32)rz_num_math(core->num, argv[2]);
	RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in(core->analysis, addr);
	if (!block) {
		eprintf("No basic block at 0x%08" PFMT64x "\n", addr);
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
	RzListIter *iter;
	RzAnalysisBlock *bb;
	rz_list_foreach (fcn->bbs, iter, bb) {
		rz_analysis_hint_set_bits(core->analysis, bb->addr, bits);
		rz_analysis_hint_set_bits(core->analysis, bb->addr + bb->size, core->analysis->bits);
	}
	fcn->bits = bits;
	return RZ_CMD_STATUS_OK;
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
		eprintf("Cannot parse type \"%s\":\n%s\n", argv[1], error_msg);
		free(error_msg);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_type_func_ret_set(core->analysis->typedb, fcn->name, ret_type)) {
		eprintf("Cannot find type %s\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
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

static void xref_list_print_to_json(RZ_UNUSED RzCore *core, RzList *list, PJ *pj) {
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
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		xref_list_print_to_json(core, xrefs, state->d.pj);
		status = RZ_CMD_STATUS_WRONG_ARGS;
		goto exit;
	}
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
		default:
			rz_warn_if_reached();
			status = RZ_CMD_STATUS_WRONG_ARGS;
			goto exit;
		}
	}
	rz_core_seek(core, oaddr, 1);
exit:
	rz_list_free(xrefs);
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
		eprintf("Invalid address ranges\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_analysis_function_until(core, addr_end);
	return RZ_CMD_STATUS_OK;
}

static int var_comparator(const RzAnalysisVar *a, const RzAnalysisVar *b) {
	return (a && b) ? (a->delta > b->delta) - (a->delta < b->delta) : 0;
}

static void core_analysis_var_list_show(RzAnalysis *analysis, RzAnalysisFunction *fcn, int kind, RzCmdStateOutput *state) {
	RzAnalysisVar *var;
	RzListIter *iter;
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(state->d.pj);
	}
	RzList *list = rz_analysis_var_list(analysis, fcn, kind);
	if (!list) {
		goto fail;
	}
	rz_list_sort(list, (RzListComparator)var_comparator);
	rz_list_foreach (list, iter, var) {
		if (var->kind != kind) {
			continue;
		}
		switch (state->mode) {
		case RZ_OUTPUT_MODE_RIZIN: {
			// we can't express all type info here :(
			char *vartype = rz_type_as_string(analysis->typedb, var->type);
			if (kind == RZ_ANALYSIS_VAR_KIND_REG) { // registers
				RzRegItem *i = rz_reg_index_get(analysis->reg, var->delta);
				if (!i) {
					RZ_LOG_ERROR("Register not found");
					free(vartype);
					break;
				}
				rz_cons_printf("afv%c %s %s %s @ 0x%" PFMT64x "\n",
					kind, i->name, var->name, vartype, fcn->addr);
			} else {
				int delta = kind == RZ_ANALYSIS_VAR_KIND_BPV
					? var->delta + fcn->bp_off
					: var->delta;
				rz_cons_printf("afv%c %d %s %s @ 0x%" PFMT64x "\n",
					kind, delta, var->name, vartype,
					fcn->addr);
			}
			free(vartype);
			break;
		}
		case RZ_OUTPUT_MODE_JSON:
			switch (var->kind) {
			case RZ_ANALYSIS_VAR_KIND_BPV: {
				char *vartype = rz_type_as_string(analysis->typedb, var->type);
				st64 delta = (st64)var->delta + fcn->bp_off;
				pj_o(state->d.pj);
				pj_ks(state->d.pj, "name", var->name);
				pj_ks(state->d.pj, "kind", var->isarg ? "arg" : "var");
				pj_ks(state->d.pj, "type", vartype);
				pj_k(state->d.pj, "ref");
				pj_o(state->d.pj);
				pj_ks(state->d.pj, "base", analysis->reg->name[RZ_REG_NAME_BP]);
				pj_kN(state->d.pj, "offset", delta);
				pj_end(state->d.pj);
				pj_end(state->d.pj);
				free(vartype);
			} break;
			case RZ_ANALYSIS_VAR_KIND_REG: {
				RzRegItem *i = rz_reg_index_get(analysis->reg, var->delta);
				if (!i) {
					RZ_LOG_ERROR("Register not found");
					break;
				}
				char *vartype = rz_type_as_string(analysis->typedb, var->type);
				pj_o(state->d.pj);
				pj_ks(state->d.pj, "name", var->name);
				pj_ks(state->d.pj, "kind", "reg");
				pj_ks(state->d.pj, "type", vartype);
				pj_ks(state->d.pj, "ref", i->name);
				pj_end(state->d.pj);
				free(vartype);
			} break;
			case RZ_ANALYSIS_VAR_KIND_SPV: {
				st64 delta = (st64)var->delta + fcn->maxstack;
				pj_o(state->d.pj);
				pj_ks(state->d.pj, "name", var->name);
				pj_ks(state->d.pj, "kind", var->isarg ? "arg" : "var");
				char *vartype = rz_type_as_string(analysis->typedb, var->type);
				pj_ks(state->d.pj, "type", vartype);
				pj_k(state->d.pj, "ref");
				pj_o(state->d.pj);
				pj_ks(state->d.pj, "base", analysis->reg->name[RZ_REG_NAME_SP]);
				pj_kN(state->d.pj, "offset", delta);
				pj_end(state->d.pj);
				pj_end(state->d.pj);
				free(vartype);
			} break;
			}
			break;
		default:
			switch (kind) {
			case RZ_ANALYSIS_VAR_KIND_BPV: {
				int delta = var->delta + fcn->bp_off;
				char *vartype = rz_type_as_string(analysis->typedb, var->type);
				if (var->isarg) {
					rz_cons_printf("arg %s %s @ %s+0x%x\n",
						vartype, var->name,
						analysis->reg->name[RZ_REG_NAME_BP],
						delta);
				} else {
					char sign = (-var->delta <= fcn->bp_off) ? '+' : '-';
					rz_cons_printf("var %s %s @ %s%c0x%x\n",
						vartype, var->name,
						analysis->reg->name[RZ_REG_NAME_BP],
						sign, RZ_ABS(delta));
				}
				free(vartype);
			} break;
			case RZ_ANALYSIS_VAR_KIND_REG: {
				RzRegItem *i = rz_reg_index_get(analysis->reg, var->delta);
				if (!i) {
					RZ_LOG_ERROR("Register not found");
					break;
				}
				char *vartype = rz_type_as_string(analysis->typedb, var->type);
				rz_cons_printf("arg %s %s @ %s\n", vartype, var->name, i->name);
				free(vartype);
			} break;
			case RZ_ANALYSIS_VAR_KIND_SPV: {
				int delta = fcn->maxstack + var->delta;
				char *vartype = rz_type_as_string(analysis->typedb, var->type);
				if (!var->isarg) {
					char sign = (-var->delta <= fcn->maxstack) ? '+' : '-';
					rz_cons_printf("var %s %s @ %s%c0x%x\n",
						vartype, var->name,
						analysis->reg->name[RZ_REG_NAME_SP],
						sign, RZ_ABS(delta));
				} else {
					rz_cons_printf("arg %s %s @ %s+0x%x\n",
						vartype, var->name,
						analysis->reg->name[RZ_REG_NAME_SP],
						delta);
				}
				free(vartype);
			} break;
			}
		}
	}
fail:
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(state->d.pj);
	}
	rz_list_free(list);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	const char *bp = NULL;
	RzList *list;
	RzListIter *iter;
	RzAnalysisVar *var;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		core_analysis_var_list_show(core->analysis, fcn, RZ_ANALYSIS_VAR_KIND_SPV, state);
		core_analysis_var_list_show(core->analysis, fcn, RZ_ANALYSIS_VAR_KIND_BPV, state);
		core_analysis_var_list_show(core->analysis, fcn, RZ_ANALYSIS_VAR_KIND_REG, state);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		bp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_BP);
		rz_cons_printf("f-fcnvar*\n");
		list = rz_analysis_var_all_list(core->analysis, fcn);
		rz_list_foreach (list, iter, var) {
			rz_cons_printf("f fcnvar.%s @ %s%s%d\n", var->name, bp,
				var->delta >= 0 ? "+" : "", var->delta);
		}
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_k(state->d.pj, "sp");
		core_analysis_var_list_show(core->analysis, fcn, RZ_ANALYSIS_VAR_KIND_SPV, state);
		pj_k(state->d.pj, "bp");
		core_analysis_var_list_show(core->analysis, fcn, RZ_ANALYSIS_VAR_KIND_BPV, state);
		pj_k(state->d.pj, "reg");
		core_analysis_var_list_show(core->analysis, fcn, RZ_ANALYSIS_VAR_KIND_REG, state);
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
	RzListIter *iter;
	RzAnalysisVar *var;
	RzList *list = rz_analysis_var_all_list(core->analysis, fcn);
	rz_list_foreach (list, iter, var) {
		rz_cons_printf("* %s\n", var->name);
		RzAnalysisVarAccess *acc;
		rz_vector_foreach(&var->accesses, acc) {
			if (!(acc->type & RZ_ANALYSIS_VAR_ACCESS_TYPE_READ)) {
				continue;
			}
			rz_cons_printf("R 0x%" PFMT64x "  ", fcn->addr + acc->offset);
			rz_core_seek(core, fcn->addr + acc->offset, 1);
			rz_core_print_disasm_instructions(core, 0, 1);
		}
		rz_vector_foreach(&var->accesses, acc) {
			if (!(acc->type & RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE)) {
				continue;
			}
			rz_cons_printf("W 0x%" PFMT64x "  ", fcn->addr + acc->offset);
			rz_core_seek(core, fcn->addr + acc->offset, 1);
			rz_core_print_disasm_instructions(core, 0, 1);
		}
	}
	rz_core_seek(core, oaddr, 0);
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_del_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	rz_core_analysis_function_delete_var(core, fcn, RZ_ANALYSIS_VAR_KIND_SPV, argv[1]);
	rz_core_analysis_function_delete_var(core, fcn, RZ_ANALYSIS_VAR_KIND_BPV, argv[1]);
	rz_core_analysis_function_delete_var(core, fcn, RZ_ANALYSIS_VAR_KIND_REG, argv[1]);
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
			eprintf("Cannot find variable '%s' in current function\n", argv[1]);
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

// EBP BASED
static int delta_cmp(const void *a, const void *b) {
	const RzAnalysisVar *va = a;
	const RzAnalysisVar *vb = b;
	return vb->delta - va->delta;
}

static int delta_cmp2(const void *a, const void *b) {
	const RzAnalysisVar *va = a;
	const RzAnalysisVar *vb = b;
	return va->delta - vb->delta;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_stackframe_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *iter;
	RzAnalysisVar *p;
	RzList *list = rz_analysis_var_all_list(core->analysis, fcn);
	rz_list_sort(list, delta_cmp2);
	rz_list_foreach (list, iter, p) {
		if (p->isarg || p->delta > 0) {
			continue;
		}
		const char *pad = rz_str_pad(' ', 10 - strlen(p->name));
		char *ptype = rz_type_as_string(core->analysis->typedb, p->type);
		rz_cons_printf("0x%08" PFMT64x "  %s:%s%s\n", (ut64)-p->delta, p->name, pad, ptype);
		free(ptype);
	}
	rz_list_sort(list, delta_cmp);
	rz_list_foreach (list, iter, p) {
		if (!p->isarg && p->delta < 0) {
			continue;
		}
		// TODO: only stack vars if (p->kind == 's') { }
		const char *pad = rz_str_pad(' ', 10 - strlen(p->name));
		char *ptype = rz_type_as_string(core->analysis->typedb, p->type);
		// XXX this 0x6a is a hack
		rz_cons_printf("0x%08" PFMT64x "  %s:%s%s\n", ((ut64)p->delta) - 0x6a, p->name, pad, ptype);
		free(ptype);
	}
	rz_list_free(list);
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
		RzList *list = rz_analysis_var_all_list(core->analysis, fcn);
		RzListIter *iter;
		RzAnalysisVar *var;
		rz_list_foreach (list, iter, var) {
			var_accesses_list(fcn, var, NULL, access_type, var->name);
		}
		rz_list_free(list);
	} else {
		RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, varname);
		if (!var) {
			eprintf("Cannot find variable %s\n", varname);
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
		eprintf("Cannot find variable %s\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	char *error_msg = NULL;
	RzType *v_type = rz_type_parse_string_single(core->analysis->typedb->parser, argv[2], &error_msg);
	if (!v_type || error_msg) {
		eprintf("Cannot parse type \"%s\":\n%s\n", argv[2], error_msg);
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

static RzCmdStatus analysis_function_vars_kind_list(RzCore *core, RzAnalysisFunction *fcn, RzAnalysisVarKind kind, RzCmdStateOutput *state) {
	core_analysis_var_list_show(core->analysis, fcn, kind, state);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus analysis_function_vars_del(RzCore *core, RzAnalysisVarKind kind, const char *varname) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_analysis_function_delete_var(core, fcn, kind, varname);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus analysis_function_vars_del_all(RzCore *core, RzAnalysisVarKind kind) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_analysis_function_delete_vars_by_kind(fcn, kind);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus analysis_function_vars_getsetref(RzCore *core, int delta, ut64 addr, RzAnalysisVarKind kind, RzAnalysisVarAccessType access_type) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzAnalysisVar *var = rz_analysis_function_get_var(fcn, kind, delta);
	if (!var) {
		eprintf("Cannot find variable with delta %d\n", delta);
		return RZ_CMD_STATUS_ERROR;
	}

	RzAnalysisOp *op = rz_core_analysis_op(core, addr, 0);
	const char *ireg = op ? op->ireg : NULL;
	if (kind == RZ_ANALYSIS_VAR_KIND_SPV) {
		delta -= fcn->maxstack;
	}
	rz_analysis_var_set_access(var, ireg, addr, access_type, delta);
	rz_analysis_op_free(op);
	return RZ_CMD_STATUS_OK;
}

/// --------- Base pointer based variable handlers -------------

RZ_IPI RzCmdStatus rz_analysis_function_vars_bp_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (argc == 1) {
		return analysis_function_vars_kind_list(core, fcn, RZ_ANALYSIS_VAR_KIND_BPV, state);
	} else {
		const char *varname = argv[2];
		const char *vartype = argc > 3 ? argv[3] : "int";
		int delta = (int)rz_num_math(core->num, argv[1]) - fcn->bp_off;
		bool isarg = delta > 0;
		char *error_msg = NULL;
		RzType *var_type = rz_type_parse_string_single(core->analysis->typedb->parser, vartype, &error_msg);
		if (!var_type || error_msg) {
			eprintf("Cannot parse type \"%s\":\n%s\n", vartype, error_msg);
			free(error_msg);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_analysis_function_set_var(fcn, delta, RZ_ANALYSIS_VAR_KIND_BPV, var_type, 4, isarg, varname);
		rz_type_free(var_type);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_bp_del_handler(RzCore *core, int argc, const char **argv) {
	return analysis_function_vars_del(core, RZ_ANALYSIS_VAR_KIND_BPV, argv[1]);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_bp_del_all_handler(RzCore *core, int argc, const char **argv) {
	return analysis_function_vars_del_all(core, RZ_ANALYSIS_VAR_KIND_BPV);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_bp_getref_handler(RzCore *core, int argc, const char **argv) {
	int delta = (int)rz_num_math(core->num, argv[1]);
	ut64 addr = rz_num_math(core->num, argv[2]);
	return analysis_function_vars_getsetref(core, delta, addr, RZ_ANALYSIS_VAR_KIND_BPV, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_bp_setref_handler(RzCore *core, int argc, const char **argv) {
	int delta = (int)rz_num_math(core->num, argv[1]);
	ut64 addr = rz_num_math(core->num, argv[2]);
	return analysis_function_vars_getsetref(core, delta, addr, RZ_ANALYSIS_VAR_KIND_BPV, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE);
}

/// --------- Register-based variable handlers -------------

RZ_IPI RzCmdStatus rz_analysis_function_vars_regs_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (argc == 1) {
		return analysis_function_vars_kind_list(core, fcn, RZ_ANALYSIS_VAR_KIND_REG, state);
	} else {
		const char *varname = argv[2];
		const char *vartype = argc > 3 ? argv[3] : "int";
		RzRegItem *i = rz_reg_get(core->analysis->reg, argv[1], -1);
		if (!i) {
			eprintf("Register not found");
			return RZ_CMD_STATUS_ERROR;
		}
		int delta = i->index;
		bool isarg = true;
		char *error_msg = NULL;
		RzType *var_type = rz_type_parse_string_single(core->analysis->typedb->parser, vartype, &error_msg);
		if (!var_type || error_msg) {
			eprintf("Cannot parse type \"%s\":\n%s\n", vartype, error_msg);
			free(error_msg);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_analysis_function_set_var(fcn, delta, RZ_ANALYSIS_VAR_KIND_REG, var_type, 4, isarg, varname);
		rz_type_free(var_type);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_regs_del_handler(RzCore *core, int argc, const char **argv) {
	return analysis_function_vars_del(core, RZ_ANALYSIS_VAR_KIND_REG, argv[1]);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_regs_del_all_handler(RzCore *core, int argc, const char **argv) {
	return analysis_function_vars_del_all(core, RZ_ANALYSIS_VAR_KIND_REG);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_regs_getref_handler(RzCore *core, int argc, const char **argv) {
	RzRegItem *i = rz_reg_get(core->analysis->reg, argv[1], -1);
	if (!i) {
		eprintf("Register not found");
		return RZ_CMD_STATUS_ERROR;
	}
	int delta = i->index;
	ut64 addr = rz_num_math(core->num, argv[2]);
	return analysis_function_vars_getsetref(core, delta, addr, RZ_ANALYSIS_VAR_KIND_REG, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_regs_setref_handler(RzCore *core, int argc, const char **argv) {
	RzRegItem *i = rz_reg_get(core->analysis->reg, argv[1], -1);
	if (!i) {
		eprintf("Register not found");
		return RZ_CMD_STATUS_ERROR;
	}
	int delta = i->index;
	ut64 addr = rz_num_math(core->num, argv[2]);
	return analysis_function_vars_getsetref(core, delta, addr, RZ_ANALYSIS_VAR_KIND_REG, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE);
}

/// --------- Stack-based variable handlers -------------

RZ_IPI RzCmdStatus rz_analysis_function_vars_sp_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = analysis_get_function_in(core->analysis, core->offset);
	if (!fcn) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (argc == 1) {
		return analysis_function_vars_kind_list(core, fcn, RZ_ANALYSIS_VAR_KIND_SPV, state);
	} else {
		const char *varname = argv[2];
		const char *vartype = argc > 3 ? argv[3] : "int";
		int delta = (int)rz_num_math(core->num, argv[1]);
		bool isarg = delta > fcn->maxstack;
		char *error_msg = NULL;
		RzType *var_type = rz_type_parse_string_single(core->analysis->typedb->parser, vartype, &error_msg);
		if (!var_type || error_msg) {
			eprintf("Cannot parse type \"%s\":\n%s\n", vartype, error_msg);
			free(error_msg);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_analysis_function_set_var(fcn, delta, RZ_ANALYSIS_VAR_KIND_SPV, var_type, 4, isarg, varname);
		rz_type_free(var_type);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_sp_del_handler(RzCore *core, int argc, const char **argv) {
	return analysis_function_vars_del(core, RZ_ANALYSIS_VAR_KIND_SPV, argv[1]);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_sp_getref_handler(RzCore *core, int argc, const char **argv) {
	int delta = (int)rz_num_math(core->num, argv[1]);
	ut64 addr = rz_num_math(core->num, argv[2]);
	return analysis_function_vars_getsetref(core, delta, addr, RZ_ANALYSIS_VAR_KIND_SPV, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ);
}

RZ_IPI RzCmdStatus rz_analysis_function_vars_sp_setref_handler(RzCore *core, int argc, const char **argv) {
	int delta = (int)rz_num_math(core->num, argv[1]);
	ut64 addr = rz_num_math(core->num, argv[2]);
	return analysis_function_vars_getsetref(core, delta, addr, RZ_ANALYSIS_VAR_KIND_SPV, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE);
}

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

static void xrefs_list_print(RzCore *core, RzList *list) {
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

static void xref_list_print_as_cmd(RZ_UNUSED RzCore *core, RzList *list) {
	RzListIter *iter;
	RzAnalysisXRef *xref;
	rz_list_foreach (list, iter, xref) {
		rz_cons_printf("%s 0x%" PFMT64x " @ 0x%" PFMT64x "\n", xref_type2cmd(xref->type), xref->to, xref->from);
	}
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzListIter *iter;
	RzAnalysisXRef *xref;
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RzList *list = rz_analysis_xrefs_list(core->analysis);
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
		status = RZ_CMD_STATUS_WRONG_ARGS;
		break;
	}
	rz_list_free(list);
	return status;
}

RZ_IPI RzCmdStatus rz_analysis_xrefs_to_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisXRef *xref;
	RzListIter *iter;
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RzList *list = rz_analysis_xrefs_get_to(core->analysis, core->offset);
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
		status = RZ_CMD_STATUS_WRONG_ARGS;
		break;
	}
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
				rz_analysis_op(core->analysis, &aop, xref->to, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
				if (aop.type == RZ_ANALYSIS_OP_TYPE_UCALL) {
					cmd_analysis_ucall_ref(core, xref->to);
				}
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
		char *str = rz_core_cmd_strf(core, "fd 0x%" PFMT64x, xref->from);
		if (!str) {
			str = strdup("?\n");
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
	HtUU *ht = ht_uu_new0();
	if (!ht) {
		return RZ_CMD_STATUS_ERROR;
	}
	PJ *pj = state->mode == RZ_OUTPUT_MODE_JSON ? state->d.pj : NULL;
	xrefs_graph(core, core->offset, 0, ht, state->mode, pj);
	ht_uu_free(ht);
	return RZ_CMD_STATUS_OK;
}

#define CMD_REGS_PREFIX   analysis
#define CMD_REGS_REG_PATH analysis->reg
#define CMD_REGS_SYNC     NULL
#include "cmd_regs_meta.inc"
#undef CMD_REGS_PREFIX
#undef CMD_REGS_REG_PATH
#undef CMD_REGS_SYNC

static int RzAnalysisRef_cmp(const RzAnalysisXRef *xref1, const RzAnalysisXRef *xref2) {
	return xref1->to != xref2->to;
}

static void function_list_print_to_table(RzCore *core, RzList *list, RzTable *t, bool verbose) {
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
		RzList *uniq_calls = rz_list_uniq(calls, (RzListComparator)RzAnalysisRef_cmp);
		ut32 calls_num = rz_list_length(uniq_calls);
		rz_list_free(uniq_calls);
		rz_list_free(calls);

		if (verbose) {
			int locals = rz_analysis_var_count(core->analysis, fcn, 's', 0);
			locals += rz_analysis_var_count(core->analysis, fcn, 'b', 0);
			locals += rz_analysis_var_count(core->analysis, fcn, 'r', 0);

			int args = rz_analysis_var_count(core->analysis, fcn, 's', 1);
			args += rz_analysis_var_count(core->analysis, fcn, 'b', 1);
			args += rz_analysis_var_count(core->analysis, fcn, 'r', 1);

			rz_table_add_rowf(t, "XsndddddddbXnXdddd", fcn->addr,
				fcn->name, rz_analysis_function_realsize(fcn),
				xref_to_num, xref_from_num, calls_num,
				rz_list_length(fcn->bbs), rz_analysis_function_count_edges(fcn, NULL),
				rz_analysis_function_complexity(fcn), rz_analysis_function_cost(fcn),
				fcn->is_noreturn, rz_analysis_function_min_addr(fcn),
				rz_analysis_function_linear_size(fcn), rz_analysis_function_max_addr(fcn),
				locals, args, fcn->maxstack, rz_analysis_function_loops(fcn), NULL);
		} else {
			rz_table_add_rowf(t, "Xsndddddddb", fcn->addr,
				fcn->name, rz_analysis_function_realsize(fcn),
				xref_to_num, xref_from_num, calls_num,
				rz_list_length(fcn->bbs), rz_analysis_function_count_edges(fcn, NULL),
				rz_analysis_function_complexity(fcn), rz_analysis_function_cost(fcn),
				fcn->is_noreturn, NULL);
		}
	}
}

static void function_list_print(RzCore *core, RzList *list) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (list, it, fcn) {
		char *msg, *name = rz_core_analysis_fcn_name(core, fcn);
		ut64 realsize = rz_analysis_function_realsize(fcn);
		ut64 size = rz_analysis_function_linear_size(fcn);
		if (realsize == size) {
			msg = rz_str_newf("%-12" PFMT64u, size);
		} else {
			msg = rz_str_newf("%-4" PFMT64u " -> %-4" PFMT64u, size, realsize);
		}
		rz_cons_printf("0x%08" PFMT64x " %4d %4s %s\n",
			fcn->addr, rz_list_length(fcn->bbs), msg, name);
		free(name);
		free(msg);
	}
}

static void function_list_print_quiet(RZ_UNUSED RzCore *core, RzList *list) {
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

static const char *diff_type_to_str(RzAnalysisDiff *diff) {
	if (diff->type == RZ_ANALYSIS_DIFF_TYPE_NULL) {
		return "new";
	}
	return diff->type == RZ_ANALYSIS_DIFF_TYPE_MATCH ? "match" : "unmatch";
}

static char diff_type_to_char(RzAnalysisDiff *diff) {
	return diff->type == RZ_ANALYSIS_DIFF_TYPE_NULL ? 'n' : diff->type;
}

static void fcn_list_bbs(RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bbi;
	RzListIter *iter;

	rz_list_foreach (fcn->bbs, iter, bbi) {
		rz_cons_printf("afb+ 0x%08" PFMT64x " 0x%08" PFMT64x " %" PFMT64u " ",
			fcn->addr, bbi->addr, bbi->size);
		rz_cons_printf("0x%08" PFMT64x " ", bbi->jump);
		rz_cons_printf("0x%08" PFMT64x, bbi->fail);
		if (bbi->diff) {
			rz_cons_printf(" %c", diff_type_to_char(bbi->diff));
		}
		rz_cons_printf("\n");
	}
}

static void function_list_print_as_cmd(RzCore *core, RzList *list, RzCmdStateOutput *state) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (list, it, fcn) {
		const char *defaultCC = rz_analysis_cc_default(core->analysis);
		char *name = rz_core_analysis_fcn_name(core, fcn);
		rz_cons_printf("\"f %s %" PFMT64u " @ 0x%08" PFMT64x "\"\n", name, rz_analysis_function_linear_size(fcn), fcn->addr);
		rz_cons_printf("\"af+ %s %c %c @ 0x%08" PFMT64x "\"\n",
			name, // rz_analysis_fcn_size (fcn), name,
			function_type_to_char(fcn),
			diff_type_to_char(fcn->diff),
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
		core_analysis_var_list_show(core->analysis, fcn, 'b', state);
		core_analysis_var_list_show(core->analysis, fcn, 'r', state);
		core_analysis_var_list_show(core->analysis, fcn, 's', state);
		/* Show references */
		RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
		xref_list_print_as_cmd(core, xrefs);
		rz_list_free(xrefs);
		/*Saving Function stack frame*/
		rz_cons_printf("afS %d @ 0x%" PFMT64x "\n", fcn->maxstack, fcn->addr);
		free(name);
	}
}

static void function_print_to_json(RzCore *core, RzAnalysisFunction *fcn, RzCmdStateOutput *state) {
	int ebbs = 0;
	pj_o(state->d.pj);
	pj_kn(state->d.pj, "offset", fcn->addr);
	char *name = rz_core_analysis_fcn_name(core, fcn);
	if (name) {
		pj_ks(state->d.pj, "name", name);
	}
	free(name);
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
	pj_ki(state->d.pj, "nbbs", rz_list_length(fcn->bbs));
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
		pj_ki(state->d.pj, "nlocals", rz_analysis_var_count(core->analysis, fcn, 'b', 0) + rz_analysis_var_count(core->analysis, fcn, 'r', 0) + rz_analysis_var_count(core->analysis, fcn, 's', 0));
		pj_ki(state->d.pj, "nargs", rz_analysis_var_count(core->analysis, fcn, 'b', 1) + rz_analysis_var_count(core->analysis, fcn, 'r', 1) + rz_analysis_var_count(core->analysis, fcn, 's', 1));

		pj_k(state->d.pj, "bpvars");
		core_analysis_var_list_show(core->analysis, fcn, 'b', state);
		pj_k(state->d.pj, "spvars");
		core_analysis_var_list_show(core->analysis, fcn, 's', state);
		pj_k(state->d.pj, "regvars");
		core_analysis_var_list_show(core->analysis, fcn, 'r', state);

		pj_ks(state->d.pj, "difftype", diff_type_to_str(fcn->diff));
		if (fcn->diff->addr != -1) {
			pj_kn(state->d.pj, "diffaddr", fcn->diff->addr);
		}
		if (fcn->diff->name) {
			pj_ks(state->d.pj, "diffname", fcn->diff->name);
		}
	}
	pj_end(state->d.pj);
}

static void function_list_print_to_json(RzCore *core, RzList *list, RzCmdStateOutput *state) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	pj_a(state->d.pj);
	rz_list_foreach (list, it, fcn) {
		function_print_to_json(core, fcn, state);
	}
	pj_end(state->d.pj);
}

RZ_IPI RzCmdStatus rz_analysis_function_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	RzList *list = rz_analysis_function_list(core->analysis);
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
static void function_print_calls(RzCore *core, RzList *fcns, RzCmdStateOutput *state) {
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
		RzList *uniq_xrefs = rz_list_uniq(xrefs, (RzListComparator)RzAnalysisRef_cmp);

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
	RzList *list = rz_analysis_function_list(core->analysis);
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
	return res;
}

RZ_IPI RzCmdStatus rz_analysis_function_list_ascii_handler(RzCore *core, int argc, const char **argv) {
	RzList *fcns = rz_list_clone(rz_analysis_function_list(core->analysis));
	if (!fcns) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_list_sort(fcns, fcn_cmpaddr);
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
		char *fcn_name = rz_core_analysis_fcn_name(core, fcn);
		RzListInfo *info = rz_listinfo_new(fcn_name, inter, inter, -1, rz_strf(temp, "%d", fcn->bits));
		free(fcn_name);
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
				rz_cons_printf("\ntraced: %d\n", trace->times);
				return;
			}
		}
	}
}

static void fcn_print_info(RzCore *core, RzAnalysisFunction *fcn, RzCmdStateOutput *state) {
	RzListIter *iter;
	RzAnalysisXRef *xrefi;
	int ebbs = 0;
	char *name = rz_core_analysis_fcn_name(core, fcn);

	rz_cons_printf("#\noffset: 0x%08" PFMT64x "\nname: %s\nsize: %" PFMT64u,
		fcn->addr, name, rz_analysis_function_linear_size(fcn));
	rz_cons_printf("\nis-pure: %s", rz_str_bool(rz_analysis_function_purity(fcn)));
	rz_cons_printf("\nrealsz: %" PFMT64d, rz_analysis_function_realsize(fcn));
	rz_cons_printf("\nstackframe: %d", fcn->maxstack);
	if (fcn->cc) {
		rz_cons_printf("\ncall-convention: %s", fcn->cc);
	}
	rz_cons_printf("\ncyclomatic-cost: %d", rz_analysis_function_cost(fcn));
	rz_cons_printf("\ncyclomatic-complexity: %d", rz_analysis_function_complexity(fcn));
	rz_cons_printf("\nloops: %d", rz_analysis_function_loops(fcn));
	rz_cons_printf("\nbits: %d", fcn->bits);
	rz_cons_printf("\ntype: %s", rz_analysis_fcntype_tostring(fcn->type));
	if (fcn->type == RZ_ANALYSIS_FCN_TYPE_FCN || fcn->type == RZ_ANALYSIS_FCN_TYPE_SYM) {
		rz_cons_printf(" [%s]", diff_type_to_str(fcn->diff));
	}
	rz_cons_printf("\nnum-bbs: %d", rz_list_length(fcn->bbs));
	rz_cons_printf("\nedges: %d", rz_analysis_function_count_edges(fcn, &ebbs));
	rz_cons_printf("\nend-bbs: %d", ebbs);
	rz_cons_printf("\ncall-refs:");
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
	rz_cons_printf("\nnoreturn: %s", rz_str_bool(fcn->is_noreturn));
	rz_cons_printf("\nin-degree: %d", indegree);
	rz_cons_printf("\nout-degree: %d", outdegree);
	rz_cons_printf("\ndata-xrefs:");
	rz_list_foreach (xrefs, iter, xrefi) {
		if (xrefi->type == RZ_ANALYSIS_XREF_TYPE_DATA) {
			rz_cons_printf(" 0x%08" PFMT64x, xrefi->from);
		}
	}
	rz_list_free(xrefs);

	if (fcn->type == RZ_ANALYSIS_FCN_TYPE_FCN || fcn->type == RZ_ANALYSIS_FCN_TYPE_SYM) {
		int args_count = rz_analysis_var_count(core->analysis, fcn, 'b', 1);
		args_count += rz_analysis_var_count(core->analysis, fcn, 's', 1);
		args_count += rz_analysis_var_count(core->analysis, fcn, 'r', 1);
		int var_count = rz_analysis_var_count(core->analysis, fcn, 'b', 0);
		var_count += rz_analysis_var_count(core->analysis, fcn, 's', 0);
		var_count += rz_analysis_var_count(core->analysis, fcn, 'r', 0);

		rz_cons_printf("\nlocals: %d\nargs: %d\n", var_count, args_count);
		core_analysis_var_list_show(core->analysis, fcn, 'b', state);
		core_analysis_var_list_show(core->analysis, fcn, 's', state);
		core_analysis_var_list_show(core->analysis, fcn, 'r', state);
		rz_cons_printf("diff: type: %s", diff_type_to_str(fcn->diff));
		if (fcn->diff->addr != -1) {
			rz_cons_printf("addr: 0x%" PFMT64x, fcn->diff->addr);
		}
		if (fcn->diff->name) {
			rz_cons_printf("function: %s", fcn->diff->name);
		}
	}
	free(name);

	// traced
	if (core->dbg->trace->enabled) {
		fcn_print_trace_info(core->dbg->trace, fcn);
	}
}

static void fcn_list_print_info(RzCore *core, RzList *fcns, RzCmdStateOutput *state) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (fcns, iter, fcn) {
		fcn_print_info(core, fcn, state);
	}
	rz_cons_newline();
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
		char *import = strdup(argv[1]);
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

static void ht_inc(HtPU *ht, const char *key) {
	bool found;
	HtPUKv *kv = ht_pu_find_kv(ht, key, &found);
	if (kv) {
		kv->value++;
	} else {
		ht_pu_insert(ht, key, 1);
	}
}

enum STATS_MODE {
	STATS_MODE_DEF,
	STATS_MODE_FML,
	STATS_MODE_TYPE
};

static void update_stat_for_op(RzCore *core, HtPU *ht, ut64 addr, int mode) {
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

static void gather_opcode_stat_for_fcn(RzCore *core, HtPU *ht, RzAnalysisFunction *fcn, int mode) {
	RzAnalysisBlock *bb;
	RzListIter *iter;
	rz_list_foreach (fcn->bbs, iter, bb) {
		update_stat_for_op(core, ht, bb->addr, mode);
		for (int i = 0; i < bb->op_pos_size; i++) {
			ut16 op_pos = bb->op_pos[i];
			update_stat_for_op(core, ht, bb->addr + op_pos, mode);
		}
	}
}

static bool list_keys_cb(RzList *list, char *k, RZ_UNUSED ut64 v) {
	rz_list_push(list, k);
	return true;
}

static void print_stats(RzCore *core, HtPU *ht, RzAnalysisFunction *fcn, RzCmdStateOutput *state) {
	const char *name;
	RzListIter *iter;
	RzList *list = rz_list_newf(NULL);
	ht_pu_foreach(ht, (HtPUForeachCallback)list_keys_cb, list);
	rz_list_sort(list, (RzListComparator)strcmp);
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
		rz_pvector_push(items, strdup(fcn->name));
		rz_list_foreach (list, iter, name) {
			int nv = (int)ht_pu_find(ht, name, NULL);
			rz_pvector_push(items, rz_str_newf("%d", nv));
		}
		rz_table_add_row_vec(t, items);
	} else {
		rz_list_foreach (list, iter, name) {
			ut32 nv = (ut32)ht_pu_find(ht, name, NULL);
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
	HtPU *ht = ht_pu_new0();
	if (!ht) {
		return RZ_CMD_STATUS_ERROR;
	}
	gather_opcode_stat_for_fcn(core, ht, fcn, mode);
	print_stats(core, ht, fcn, state);
	ht_pu_free(ht);
	return RZ_CMD_STATUS_OK;
}

static bool add_keys_to_set_cb(HtPU *ht, const char *k, RZ_UNUSED const ut64 v) {
	if (strcmp(k, ".addr")) {
		ht_pu_insert(ht, k, 1);
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
	HtPU *keys_set = ht_pu_new0();
	RzList *dbs = rz_list_newf((RzListFree)ht_pu_free);
	if (!keys || !keys_set || !dbs) {
		goto exit;
	}

	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		HtPU *db = ht_pu_new0();
		if (!db) {
			break;
		}
		gather_opcode_stat_for_fcn(core, db, fcn, mode);
		ht_pu_insert(db, ".addr", fcn->addr);
		rz_list_append(dbs, db);
	}

	HtPU *db;
	rz_list_foreach (dbs, iter, db) {
		ht_pu_foreach(db, (HtPUForeachCallback)add_keys_to_set_cb, keys_set);
	}

	ht_pu_foreach(keys_set, (HtPUForeachCallback)list_keys_cb, keys);
	rz_list_sort(keys, (RzListComparator)strcmp);

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
		ut64 fcnAddr = ht_pu_find(db, ".addr", NULL);
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, fcnAddr);
		rz_pvector_push(items, fcn ? strdup(fcn->name) : strdup(""));
		rz_pvector_push(items, fcn ? rz_str_newf("0x%08" PFMT64x, fcnAddr) : strdup("0"));
		rz_list_foreach (keys, iter, key) {
			ut32 n = (ut32)ht_pu_find(db, key, NULL);
			rz_pvector_push(items, rz_str_newf("%u", n));
		}
		rz_table_add_row_vec(t, items);
	}
	res = RZ_CMD_STATUS_OK;
exit:
	rz_list_free(keys);
	rz_list_free(dbs);
	ht_pu_free(keys_set);
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

	RzListIter *iter, *iter2;
	RzAnalysisFunction *fcn;
	RzAnalysisBlock *b;
	// for each function
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		// for each basic block in the function
		rz_list_foreach (fcn->bbs, iter2, b) {
			// if it is not within range, continue
			if ((fcn->addr < base_addr) || (fcn->addr >= base_addr + code_size))
				continue;
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

RZ_IPI RzCmdStatus rz_analysis_function_add_recu_handler(RzCore *core, int argc, const char **argv) {
	const char *name = argc == 2 ? argv[1] : NULL;
	bool analyze_recursively = true;
	if (!strcmp(argv[0], "af")) {
		analyze_recursively = rz_config_get_b(core->config, "analysis.calls");
	}
	return bool2status(rz_core_analysis_function_add(core, name, core->offset, analyze_recursively));
}

RZ_IPI RzCmdStatus rz_analysis_function_create_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisDiff *diff = rz_analysis_diff_new();
	if (!diff) {
		RZ_LOG_ERROR("Cannot init RzAnalysisDiff\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc == 4) {
		switch (argv[3][0]) {
		case 'm':
			diff->type = RZ_ANALYSIS_DIFF_TYPE_MATCH;
			break;
		case 'u':
			diff->type = RZ_ANALYSIS_DIFF_TYPE_UNMATCH;
			break;
		default:
			break;
		}
	}
	int type = RZ_ANALYSIS_FCN_TYPE_FCN;
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
	RzAnalysisFunction *fcn = rz_analysis_create_function(core->analysis, argv[1], core->offset, type, diff);
	if (!fcn) {
		rz_analysis_diff_free(diff);
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
		rz_analysis_jmptbl(core->analysis, rz_list_first(block->fcns), block, core->offset, table, elements, UT64_MAX);
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
	for (ut64 i = 0; i < repeat_times; ++i) {
		if (!rz_core_il_step(core)) {
			break;
		}
	}
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

	if (!core->analysis->il_vm) {
		RZ_LOG_ERROR("RzIL: the VM is not initialized.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	while (1) {
		ut64 pc = rz_reg_get_value_by_role(core->analysis->reg, RZ_REG_NAME_PC);
		if (pc == address) {
			break;
		}
		if (rz_cons_is_breaked()) {
			rz_cons_printf("CTRL+C was pressed.\n");
			break;
		}
		if (!rz_core_il_step(core)) {
			break;
		}
	}
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
		rz_vector_foreach(bases, base) {
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
			rz_vector_foreach(vtables, vtable) {
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
			rz_table_set_columnsf(table, "dsxxs", "nth", "name", "addr", "vt_offset", "type");
			rz_table_align(table, 2, RZ_TABLE_ALIGN_RIGHT);
			char *method_type[] = { "DEFAULT", "VIRTUAL", "V_DESTRUCTOR", "DESTRUCTOR", "CONSTRUCTOR" };
			RzAnalysisMethod *meth;
			int i = 1;
			rz_vector_foreach(methods, meth) {
				RzPVector *row_vec = rz_pvector_new(free);
				if (!row_vec) {
					RZ_LOG_ERROR("Failed to allocate memory.\n");
					rz_table_free(table);
					rz_vector_free(methods);
					return;
				}
				rz_pvector_push(row_vec, rz_str_newf("%d", i++));
				rz_pvector_push(row_vec, rz_str_new(meth->real_name));
				rz_pvector_push(row_vec, rz_str_newf("0x%" PFMT64x, meth->addr));
				if (meth->vtable_offset >= 0) {
					rz_pvector_push(row_vec, rz_str_newf("0x%" PFMT64x, meth->vtable_offset));
				} else {
					rz_pvector_push(row_vec, rz_str_new("-1"));
				}
				rz_pvector_push(row_vec, rz_str_new(method_type[meth->method_type]));
				rz_table_add_row_vec(table, row_vec);
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
		rz_vector_foreach(bases, base) {
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
		rz_vector_foreach(vtables, vtable) {
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
		rz_vector_foreach(methods, meth) {
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

static bool analysis_class_print_to_json_cb(void *user, const char *k, const char *v) {
	ListJsonCtx *ctx = user;
	analysis_class_print_to_json(ctx->analysis, ctx->pj, k);
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
		rz_vector_foreach(bases, base) {
			rz_cons_printf("acb %s %s %" PFMT64u "\n", class_name, base->class_name, base->offset);
		}
		rz_vector_free(bases);
	}

	RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);
	if (vtables) {
		RzAnalysisVTable *vtable;
		rz_vector_foreach(vtables, vtable) {
			rz_cons_printf("acv %s 0x%" PFMT64x " %" PFMT64u "\n", class_name, vtable->addr, vtable->offset);
		}
		rz_vector_free(vtables);
	}

	RzVector *methods = rz_analysis_class_method_get_all(analysis, class_name);
	if (methods) {
		RzAnalysisMethod *meth;
		rz_vector_foreach(methods, meth) {
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

	SdbList *classes = rz_analysis_class_get_all(core->analysis, state->mode != RZ_OUTPUT_MODE_RIZIN);
	SdbListIter *iter;
	SdbKv *kv;
	if (state->mode == RZ_OUTPUT_MODE_RIZIN) {
		ls_foreach (classes, iter, kv) {
			// need to create all classes first, so they can be referenced
			rz_cons_printf("ac %s\n", sdbkv_key(kv));
		}
		ls_foreach (classes, iter, kv) {
			analysis_class_print_as_cmd(core->analysis, sdbkv_key(kv));
		}
	} else {
		ls_foreach (classes, iter, kv) {
			analysis_class_print(core->analysis, sdbkv_key(kv), state->mode == RZ_OUTPUT_MODE_LONG);
		}
	}
	ls_free(classes);
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
	rz_core_graph_print(core, graph, -1, false, "");
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
	meth.name = strdup(argv[2]);
	meth.real_name = strdup(argv[2]);
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
	base.class_name = strdup(argv[2]);
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
	rz_vector_foreach(bases, base) {
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
		rz_vector_foreach(vtables, vtable) {
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
	rz_vector_foreach(vtables, vtable) {
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
	SdbList *classes = rz_analysis_class_get_all(core->analysis, true);
	SdbListIter *iter;
	SdbKv *kv;
	ls_foreach (classes, iter, kv) {
		const char *name = sdbkv_key(kv);
		list_all_functions_at_vtable_offset(core->analysis, name, offset);
	}
	ls_free(classes);
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
			const char *pad = rz_str_pad(' ', 16 - strlen(ptr));
			rz_cons_printf("%s%s%s\n", ptr, pad, desc);
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

RZ_IPI RzCmdStatus rz_analyse_name_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *name = NULL;
	st32 ret = 0;

	if (argc > 1) {
		name = argv[1];
	}

	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		ret = core_analysis_name(core, name, state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		ret = core_analysis_name(core, name, NULL);
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	if (!ret) {
		// name exists when error happens
		RZ_LOG_ERROR("Error happens while handling name: %s\n", name);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
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

static RzList *get_xrefs(RzAnalysisBlock *block) {
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

static RzList *get_calls(RzAnalysisBlock *block) {
	ut8 *data = malloc(block->size);
	if (!data) {
		return NULL;
	}
	RzList *list = NULL;
	RzAnalysisOp op;
	block->analysis->iob.read_at(block->analysis->iob.io, block->addr, data, block->size);
	for (size_t i = 0; i < block->size; i++) {
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
			char *jump = block->jump != UT64_MAX ? rz_str_newf("0x%08" PFMT64x, block->jump) : strdup("");
			char *fail = block->fail != UT64_MAX ? rz_str_newf("0x%08" PFMT64x, block->fail) : strdup("");
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

typedef enum {
	CORE_ANALYSIS_SIMPLE, ///< aa
	CORE_ANALYSIS_DEEP, ///< aaa
	CORE_ANALYSIS_EXPERIMENTAL, ///< aaaa
} CoreAnalysisType;

static void core_perform_auto_analysis(RzCore *core, CoreAnalysisType type) {
	ut64 timeout = rz_config_get_i(core->config, "analysis.timeout");
	char *debugger = NULL;
	ut64 old_offset = core->offset;
	const char *notify = "Analyze all flags starting with sym. and entry0 (aa)";
	rz_core_notify_begin(core, "%s", notify);
	rz_cons_break_push(NULL, NULL);
	rz_cons_break_timeout(timeout);
	rz_core_analysis_all(core);
	rz_core_notify_done(core, "%s", notify);
	rz_core_task_yield(&core->tasks);
	if (type == CORE_ANALYSIS_SIMPLE || rz_cons_is_breaked()) {
		goto finish;
	}
	// Run pending analysis immediately after analysis
	// Usefull when running commands with ";" or via rizin -c,-i
	debugger = core->dbg->cur ? strdup(core->dbg->cur->name) : strdup("esil");
	if (core->io && core->io->desc && core->io->desc->plugin && !core->io->desc->plugin->isdbg) {
		// set it only if is debugging
		RZ_FREE(debugger);
	}
	rz_cons_clear_line(1);
	rz_core_analysis_everything(core, type == CORE_ANALYSIS_EXPERIMENTAL, debugger);
finish:
	rz_core_seek(core, old_offset, true);
	// XXX this shouldnt be called. flags muts be created wheen the function is registered
	rz_core_analysis_flag_every_function(core);
	rz_cons_break_pop();
	RZ_FREE(debugger);
}

RZ_IPI RzCmdStatus rz_analyze_simple_handler(RzCore *core, int argc, const char **argv) {
	core_perform_auto_analysis(core, CORE_ANALYSIS_SIMPLE);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_everything_handler(RzCore *core, int argc, const char **argv) {
	core_perform_auto_analysis(core, CORE_ANALYSIS_DEEP);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_analyze_everything_experimental_handler(RzCore *core, int argc, const char **argv) {
	core_perform_auto_analysis(core, CORE_ANALYSIS_EXPERIMENTAL);
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
	rz_core_analysis_types_propagation(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_apply_signatures_from_sigdb_handler(RzCore *core, int argc, const char **argv) {
	const char *filter = argc == 2 ? argv[1] : NULL;
	rz_core_analysis_sigdb_apply(core, NULL, filter);
	return RZ_CMD_STATUS_OK;
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
	st64 code = compute_code(core);
	st64 covr = compute_coverage(core);
	st64 call = compute_calls(core);
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
		rz_cons_printf("percentuage: %.2f%% (coverage on code size)\n", precentage);
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
	cmd_analysis_objc(core, false);
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

	const RzList *symbols = rz_bin_object_get_symbols(obj);
	RzListIter *it;
	RzBinSymbol *symbol;

	rz_list_foreach (symbols, it, symbol) {
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
		rz_core_link_stroff(core, fcn);
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
		rz_core_link_stroff(core, fcn);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_commands_after_traps_handler(RzCore *core, int argc, const char **argv) {
	ut64 n_bytes = argc == 2 ? rz_num_math(core->num, argv[1]) : 0;
	print_cmd_analysis_after_traps_print(core, n_bytes);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_areas_no_functions_handler(RzCore *core, int argc, const char **argv) {
	size_t min_len = argc == 2 ? rz_num_math(core->num, argv[1]) : 16;
	if (min_len < 1) {
		min_len = 1;
	}

	ut64 code_size = rz_num_get(core->num, "$SS");
	ut64 base_addr = rz_num_get(core->num, "$S");
	ut64 chunk_size, chunk_offset, i;
	RzListIter *iter, *iter2;
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
		rz_list_foreach (fcn->bbs, iter2, b) {
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
