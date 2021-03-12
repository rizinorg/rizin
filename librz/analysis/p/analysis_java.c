// SPDX-FileCopyrightText: 2010-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2010-2019 Adam Pridgen <dso@rice.edu>
// SPDX-License-Identifier: Apache-2.0

#include <string.h>

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_analysis.h>

#include "../../asm/arch/java/ops.h"
#include "../../asm/arch/java/code.h"
#include "../../bin/format/java/class.h"

#ifdef IFDBG
#define dprintf eprintf
#endif

#define DO_THE_DBG 0
#define IFDBG      if (DO_THE_DBG)
#define IFINT      if (0)

ut64 METHOD_START = 0;

static void java_update_analysis_types(RzAnalysis *analysis, RzBinJavaObj *bin_obj);

static int java_cmd_ext(RzAnalysis *analysis, const char *input);

static int java_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask);

static RzBinJavaObj *get_java_bin_obj(RzAnalysis *analysis);

static RzBinJavaObj *get_java_bin_obj(RzAnalysis *analysis) {
	RzBin *b = analysis->binb.bin;
	RzBinPlugin *plugin = b->cur && b->cur->o ? b->cur->o->plugin : NULL;
	ut8 is_java = (plugin && strcmp(plugin->name, "java") == 0) ? 1 : 0;
	return is_java ? b->cur->o->bin_obj : NULL;
}

static ut64 java_get_method_start(void) {
	return METHOD_START;
}

static int java_switch_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len) {
	ut8 op_byte = data[0];
	ut64 offset = addr - java_get_method_start();
	ut8 pos = (offset + 1) % 4 ? 1 + 4 - (offset + 1) % 4 : 1;

	if (op_byte == 0xaa) {
		// handle a table switch condition
		if (pos + 8 + 8 > len) {
			return op->size;
		}
		const int min_val = (ut32)(rz_read_at_be32(data, pos + 4));
		const int max_val = (ut32)(rz_read_at_be32(data, pos + 8));

		ut32 default_loc = (ut32)(rz_read_at_be32(data, pos)), cur_case = 0;
		op->switch_op = rz_analysis_switch_op_new(addr, min_val, max_val, default_loc);
		pos += 12;
		if (max_val > min_val && (((ut32)max_val - (ut32)min_val) < (UT16_MAX / 4))) {
			//caseop = rz_analysis_switch_op_add_case(op->switch_op, addr+default_loc, -1, addr+offset);
			for (cur_case = 0; cur_case <= max_val - min_val; pos += 4, cur_case++) {
				//ut32 value = (ut32)(rz_read_at_be32 (data, pos));
				if (pos + 4 >= len) {
					// switch is too big can't read further
					break;
				}
				st32 offset = (st32)(rz_read_at_be32(data, pos));
				rz_analysis_switch_op_add_case(op->switch_op, addr + pos, cur_case + min_val, addr + offset);
			}
		} else {
			eprintf("Invalid switch boundaries at 0x%" PFMT64x "\n", addr);
		}
	}
	op->size = pos;
	return op->size;
}

static ut64 extract_bin_op(ut64 ranal2_op_type) {
	ut64 bin_op_val = ranal2_op_type & (RZ_ANALYSIS_JAVA_BIN_OP | 0x80000);
	switch (bin_op_val) {
	case RZ_ANALYSIS_JAVA_BINOP_XCHG: return RZ_ANALYSIS_OP_TYPE_XCHG;
	case RZ_ANALYSIS_JAVA_BINOP_CMP: return RZ_ANALYSIS_OP_TYPE_CMP;
	case RZ_ANALYSIS_JAVA_BINOP_ADD: return RZ_ANALYSIS_OP_TYPE_ADD;
	case RZ_ANALYSIS_JAVA_BINOP_SUB: return RZ_ANALYSIS_OP_TYPE_SUB;
	case RZ_ANALYSIS_JAVA_BINOP_MUL: return RZ_ANALYSIS_OP_TYPE_MUL;
	case RZ_ANALYSIS_JAVA_BINOP_DIV: return RZ_ANALYSIS_OP_TYPE_DIV;
	case RZ_ANALYSIS_JAVA_BINOP_SHR: return RZ_ANALYSIS_OP_TYPE_SHR;
	case RZ_ANALYSIS_JAVA_BINOP_SHL: return RZ_ANALYSIS_OP_TYPE_SHL;
	case RZ_ANALYSIS_JAVA_BINOP_SAL: return RZ_ANALYSIS_OP_TYPE_SAL;
	case RZ_ANALYSIS_JAVA_BINOP_SAR: return RZ_ANALYSIS_OP_TYPE_SAR;
	case RZ_ANALYSIS_JAVA_BINOP_OR: return RZ_ANALYSIS_OP_TYPE_OR;
	case RZ_ANALYSIS_JAVA_BINOP_AND: return RZ_ANALYSIS_OP_TYPE_AND;
	case RZ_ANALYSIS_JAVA_BINOP_XOR: return RZ_ANALYSIS_OP_TYPE_XOR;
	case RZ_ANALYSIS_JAVA_BINOP_NOT: return RZ_ANALYSIS_OP_TYPE_NOT;
	case RZ_ANALYSIS_JAVA_BINOP_MOD: return RZ_ANALYSIS_OP_TYPE_MOD;
	case RZ_ANALYSIS_JAVA_BINOP_ROR: return RZ_ANALYSIS_OP_TYPE_ROR;
	case RZ_ANALYSIS_JAVA_BINOP_ROL: return RZ_ANALYSIS_OP_TYPE_ROL;
	default: break;
	}
	return RZ_ANALYSIS_OP_TYPE_UNK;
}

ut64 extract_unknown_op(ut64 ranal2_op_type) {
	if ((ranal2_op_type & RZ_ANALYSIS_JAVA_CODEOP_JMP) == RZ_ANALYSIS_JAVA_CODEOP_JMP) {
		return RZ_ANALYSIS_OP_TYPE_UJMP;
	}
	if ((ranal2_op_type & RZ_ANALYSIS_JAVA_CODEOP_CALL) == RZ_ANALYSIS_JAVA_CODEOP_CALL) {
		return RZ_ANALYSIS_OP_TYPE_UCALL;
	}
	if ((ranal2_op_type & RZ_ANALYSIS_JAVA_LDST_OP_PUSH) == RZ_ANALYSIS_JAVA_LDST_OP_PUSH) {
		return RZ_ANALYSIS_OP_TYPE_UPUSH;
	}
	return RZ_ANALYSIS_OP_TYPE_UNK;
}

static ut64 extract_code_op(ut64 ranal2_op_type) {
	ut64 conditional = RZ_ANALYSIS_JAVA_COND_OP & ranal2_op_type ? RZ_ANALYSIS_OP_TYPE_COND : 0;
	ut64 code_op_val = ranal2_op_type & (RZ_ANALYSIS_JAVA_CODE_OP | 0x1FF);
	switch (code_op_val) {
	case RZ_ANALYSIS_JAVA_CODEOP_CALL: return conditional | RZ_ANALYSIS_OP_TYPE_CALL;
	case RZ_ANALYSIS_JAVA_CODEOP_JMP: return conditional | RZ_ANALYSIS_OP_TYPE_JMP;
	case RZ_ANALYSIS_JAVA_CODEOP_RET: return conditional | RZ_ANALYSIS_OP_TYPE_RET;
	case RZ_ANALYSIS_JAVA_CODEOP_LEAVE: return RZ_ANALYSIS_OP_TYPE_LEAVE;
	case RZ_ANALYSIS_JAVA_CODEOP_SWI: return RZ_ANALYSIS_OP_TYPE_SWI;
	case RZ_ANALYSIS_JAVA_CODEOP_TRAP: return RZ_ANALYSIS_OP_TYPE_TRAP;
	case RZ_ANALYSIS_JAVA_CODEOP_SWITCH: return RZ_ANALYSIS_OP_TYPE_SWITCH;
	}
	return RZ_ANALYSIS_OP_TYPE_UNK;
}

ut64 extract_load_store_op(ut64 ranal2_op_type) {
	if ((ranal2_op_type & RZ_ANALYSIS_JAVA_LDST_OP_PUSH) == RZ_ANALYSIS_JAVA_LDST_OP_PUSH) {
		return RZ_ANALYSIS_OP_TYPE_PUSH;
	}
	if ((ranal2_op_type & RZ_ANALYSIS_JAVA_LDST_OP_POP) == RZ_ANALYSIS_JAVA_LDST_OP_POP) {
		return RZ_ANALYSIS_OP_TYPE_POP;
	}
	if ((ranal2_op_type & RZ_ANALYSIS_JAVA_LDST_OP_MOV) == RZ_ANALYSIS_JAVA_LDST_OP_MOV) {
		return RZ_ANALYSIS_OP_TYPE_MOV;
	}
	if ((ranal2_op_type & RZ_ANALYSIS_JAVA_LDST_OP_EFF_ADDR) == RZ_ANALYSIS_JAVA_LDST_OP_EFF_ADDR) {
		return RZ_ANALYSIS_OP_TYPE_LEA;
	}
	return RZ_ANALYSIS_OP_TYPE_UNK;
}

static ut64 map_java_op_to_analysis_op_type(ut64 t) {
	ut64 t2 = extract_bin_op(t);
	if (t2 != RZ_ANALYSIS_OP_TYPE_UNK) {
		return t2;
	}
	switch (t) {
	case RZ_ANALYSIS_JAVA_NULL_OP: return RZ_ANALYSIS_OP_TYPE_NULL;
	case RZ_ANALYSIS_JAVA_NOP: return RZ_ANALYSIS_OP_TYPE_NOP;
	case RZ_ANALYSIS_JAVA_BINOP_ADD: return RZ_ANALYSIS_OP_TYPE_ADD;
	case RZ_ANALYSIS_JAVA_BINOP_AND: return RZ_ANALYSIS_OP_TYPE_AND;
	case RZ_ANALYSIS_JAVA_BINOP_MUL: return RZ_ANALYSIS_OP_TYPE_MUL;
	case RZ_ANALYSIS_JAVA_BINOP_XOR: return RZ_ANALYSIS_OP_TYPE_XOR;
	case RZ_ANALYSIS_JAVA_BINOP_XCHG: return RZ_ANALYSIS_OP_TYPE_MOV;
	case RZ_ANALYSIS_JAVA_OBJOP_NEW: return RZ_ANALYSIS_OP_TYPE_UCALL;
	case RZ_ANALYSIS_JAVA_OBJOP_SIZE: return RZ_ANALYSIS_OP_TYPE_UCALL;
	case RZ_ANALYSIS_JAVA_ILL_OP: return RZ_ANALYSIS_OP_TYPE_ILL;
	default:
		if (t & RZ_ANALYSIS_JAVA_UNK_OP) {
			return extract_unknown_op(t);
		}
		if (t & RZ_ANALYSIS_JAVA_CODE_OP) {
			return extract_code_op(t);
		}
		if (t & RZ_ANALYSIS_JAVA_REP_OP) {
			ut64 ret = map_java_op_to_analysis_op_type(t & ~RZ_ANALYSIS_JAVA_REP_OP);
			return RZ_ANALYSIS_OP_TYPE_REP | ret;
		}
		if (t & (RZ_ANALYSIS_JAVA_LOAD_OP | RZ_ANALYSIS_JAVA_STORE_OP)) {
			return extract_load_store_op(t);
		}
		if (t & RZ_ANALYSIS_JAVA_BIN_OP) {
			return extract_bin_op(t);
		}
		break;
	}
	if (RZ_ANALYSIS_JAVA_OBJOP_CAST & t) {
		return RZ_ANALYSIS_OP_TYPE_MOV;
	}
	return RZ_ANALYSIS_OP_TYPE_UNK;
}

static int rz_analysis_java_is_op_type_eop(ut64 x) {
	ut8 result = (x & RZ_ANALYSIS_JAVA_CODE_OP) ? 1 : 0;
	return result &&
		((x & RZ_ANALYSIS_JAVA_CODEOP_LEAVE) == RZ_ANALYSIS_JAVA_CODEOP_LEAVE ||
			(x & RZ_ANALYSIS_JAVA_CODEOP_RET) == RZ_ANALYSIS_JAVA_CODEOP_RET ||
			(x & RZ_ANALYSIS_JAVA_CODEOP_JMP) == RZ_ANALYSIS_JAVA_CODEOP_JMP ||
			(x & RZ_ANALYSIS_JAVA_CODEOP_SWITCH) == RZ_ANALYSIS_JAVA_CODEOP_SWITCH);
}

static int java_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	/* get opcode size */
	if (len < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		return 1;
	}
	//ut8 op_byte = data[0];
	ut8 op_byte = data[0];
	int sz = JAVA_OPS[op_byte].size;
	if (!op) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		return sz;
	}
	IFDBG {
		//eprintf ("Extracting op from buffer (%d byte(s)) @ 0x%04x\n", len, addr);
		//eprintf ("Parsing op: (0x%02x) %s.\n", op_byte, JAVA_OPS[op_byte].name);
	}
	op->addr = addr;
	op->size = sz;
	op->id = data[0];
	op->type2 = JAVA_OPS[op_byte].op_type;
	op->type = map_java_op_to_analysis_op_type(op->type2);
	// handle lookup and table switch offsets
	if (op_byte == 0xaa || op_byte == 0xab) {
		java_switch_op(analysis, op, addr, data, len);
		// IN_SWITCH_OP = 1;
	}
	/* TODO:
	// not sure how to handle the states for IN_SWITCH_OP, SWITCH_OP_CASES,
	// and NUM_CASES_SEEN, because these are dependent on whether or not we
	// are in a switch, and given the non-reentrant state of opcode analysis
	// this can't always be guaranteed.  Below is the pseudo code for handling
	// the easy parts though
	if (IN_SWITCH_OP) {
		NUM_CASES_SEEN++;
		if (NUM_CASES_SEEN == SWITCH_OP_CASES) IN_SWITCH_OP=0;
		op->addr = addr;
		op->size = 4;
		op->type2 = 0;
		op->type = RZ_ANALYSIS_OP_TYPE_CASE
		op->eob = 0;
		return op->sizes;
	}
	*/

	op->eob = rz_analysis_java_is_op_type_eop(op->type2);
	IFDBG {
		const char *ot_str = rz_analysis_optype_to_string(op->type);
		eprintf("op_type2: %s @ 0x%04" PFMT64x " 0x%08" PFMT64x " op_type: (0x%02" PFMT64x ") %s.\n",
			JAVA_OPS[op_byte].name, addr, (ut64)op->type2, (ut64)op->type, ot_str);
		//eprintf ("op_eob: 0x%02x.\n", op->eob);
		//eprintf ("op_byte @ 0: 0x%02x op_byte @ 0x%04x: 0x%02x.\n", data[0], addr, data[addr]);
	}

	if (len < 4) {
		// incomplete analysis here
		return 0;
	}
	if (op->type == RZ_ANALYSIS_OP_TYPE_POP) {
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 8;
	}
	op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
	if (op->type == RZ_ANALYSIS_OP_TYPE_PUSH) {
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -8;
	}
	if (op->type == RZ_ANALYSIS_OP_TYPE_CJMP) {
		op->jump = addr + (short)(rz_read_at_be16(data, 1));
		op->fail = addr + sz;
		IFDBG eprintf("%s jmpto 0x%04" PFMT64x "  failto 0x%04" PFMT64x ".\n",
			JAVA_OPS[op_byte].name, op->jump, op->fail);
	} else if (op->type == RZ_ANALYSIS_OP_TYPE_JMP) {
		op->jump = addr + (short)(rz_read_at_be16(data, 1));
		IFDBG eprintf("%s jmpto 0x%04" PFMT64x ".\n", JAVA_OPS[op_byte].name, op->jump);
	} else if ((op->type & RZ_ANALYSIS_OP_TYPE_CALL) == RZ_ANALYSIS_OP_TYPE_CALL) {
		op->jump = (int)(short)(rz_read_at_be16(data, 1));
		op->fail = addr + sz;
		//IFDBG eprintf ("%s callto 0x%04x  failto 0x%04x.\n", JAVA_OPS[op_byte].name, op->jump, op->fail);
	}

	//rz_java_disasm(addr, data, len, output, outlen);
	//IFDBG eprintf ("%s\n", output);
	return op->size;
}

static void java_update_analysis_types(RzAnalysis *analysis, RzBinJavaObj *bin_obj) {
	Sdb *D = analysis->sdb_types;
	if (D && bin_obj) {
		RzListIter *iter;
		char *str;
		RzList *the_list = rz_bin_java_extract_all_bin_type_values(bin_obj);
		if (the_list) {
			rz_list_foreach (the_list, iter, str) {
				IFDBG eprintf("Adding type: %s to known types.\n", str);
				if (str) {
					sdb_set(D, str, "type", 0);
				}
			}
		}
		rz_list_free(the_list);
	}
}

static int java_cmd_ext(RzAnalysis *analysis, const char *input) {
	RzBinJavaObj *obj = (RzBinJavaObj *)get_java_bin_obj(analysis);

	if (!obj) {
		eprintf("Execute \"af\" to set the current bin, and this will bind the current bin\n");
		return -1;
	}
	switch (*input) {
	case 'c':
		// reset bytes counter for case operations
		rz_java_new_method();
		break;
	case 'u':
		switch (*(input + 1)) {
		case 't': {
			java_update_analysis_types(analysis, obj);
			return true;
		}
		default: break;
		}
		break;
	case 's':
		switch (*(input + 1)) {
		//case 'e': return java_resolve_cp_idx_b64 (analysis, input+2);
		default: break;
		}
		break;

	default: eprintf("Command not supported"); break;
	}
	return 0;
}

RzAnalysisPlugin rz_analysis_plugin_java = {
	.name = "java",
	.desc = "Java bytecode analysis plugin",
	.license = "Apache",
	.arch = "java",
	.bits = 32,
	.op = &java_op,
	.cmd_ext = java_cmd_ext,
	0
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_java,
	.version = RZ_VERSION
};
#endif
