// SPDX-FileCopyrightText: 2017-2021 xvilka <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2017-2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#undef RZ_IPI
#define RZ_IPI static
#include "../../bin/format/wasm/wasm.h"
#include "wasm/wasm.c"

#define WASM_STACK_SIZE 256

static ut64 scope_hint = UT64_MAX;
static ut64 addr_old = UT64_MAX;

// finds the address of the call function (essentially where to jump to).
static ut64 get_cf_offset(RzAnalysis *analysis, const ut8 *data, int len) {
	ut32 fcn_id;

	if (!read_u32_leb128(&data[1], &data[len - 1], &fcn_id)) {
		return UT64_MAX;
	}
	rz_cons_push();
	// 0xfff.. are bad addresses for wasm
	// cgvwzq: 0xfff... can be external imported JS funcs
	char *s = analysis->coreb.cmdstrf(analysis->coreb.core, "is~FUNC[2:%u]", fcn_id);
	rz_cons_pop();
	if (s) {
		ut64 n = rz_num_get(NULL, s);
		free(s);
		return n;
	}
	return UT64_MAX;
}

static bool advance_till_scope_end(RzAnalysis *analysis, RzAnalysisOp *op, ut64 address, ut32 expected_type, ut32 depth, bool use_else) {
	ut8 buffer[16];
	ut8 *ptr = buffer;
	ut8 *end = ptr + sizeof(buffer);
	WasmOp wop = { { 0 } };
	int size = 0;
	while (analysis->iob.read_at(analysis->iob.io, address, buffer, sizeof(buffer))) {
		size = wasm_dis(&wop, ptr, end - ptr);
		if (!wop.txt || (wop.type == WASM_TYPE_OP_CORE && wop.op.core == WASM_OP_TRAP)) {
			// if invalid stop here.
			break;
		}
		if (wop.type == WASM_TYPE_OP_CORE) {
			WasmOpCodes wopop = wop.op.core;
			if (wopop == WASM_OP_LOOP || wopop == WASM_OP_BLOCK || wopop == WASM_OP_IF) {
				depth++;
			}
			if (use_else && wopop == WASM_OP_ELSE && !depth) {
				op->type = expected_type;
				op->jump = address + 1; // else size == 1
				return true;
			} else if (wopop == WASM_OP_END && depth > 0) {
				// let's wait till i get the final depth
				depth--;
			} else if (wopop == WASM_OP_END && !depth) {
				op->type = expected_type;
				op->jump = address;
				return true;
			}
		}
		address += size;
	}
	return false;
}

// analyzes the wasm opcode.
static int wasm_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	WasmOp wop = { { 0 } };
	RzAnalysisHint *hint = NULL;
	int ret = wasm_dis(&wop, data, len);
	op->size = ret;
	op->addr = addr;
	op->sign = true;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	switch (wop.type) {
	case WASM_TYPE_OP_CORE:
		op->id = wop.op.core;
		break;
	case WASM_TYPE_OP_ATOMIC:
		op->id = (0xfe << 8) | wop.op.atomic;
		break;
	case WASM_TYPE_OP_SIMD:
		op->id = 0xfd;
		break;
	}

	if (!wop.txt || !strncmp(wop.txt, "invalid", 7)) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		free(wop.txt);
		return -1;
	}

	if (addr_old == addr && (wop.type != WASM_TYPE_OP_CORE || wop.op.core != WASM_OP_END)) {
		goto analysis_end;
	}

	switch (wop.type) {
	case WASM_TYPE_OP_CORE:
		switch (wop.op.core) {
		/* Calls here are using index instead of address */
		case WASM_OP_LOOP:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			if (!(hint = rz_analysis_hint_get(analysis, addr))) {
				scope_hint--;
				rz_analysis_hint_set_opcode(analysis, scope_hint, "loop");
				rz_analysis_hint_set_jump(analysis, scope_hint, addr);
			}
			break;
		case WASM_OP_BLOCK:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			if (!(hint = rz_analysis_hint_get(analysis, addr))) {
				scope_hint--;
				rz_analysis_hint_set_opcode(analysis, scope_hint, "block");
				rz_analysis_hint_set_jump(analysis, scope_hint, addr);
			}
			break;
		case WASM_OP_IF:
			if (!(hint = rz_analysis_hint_get(analysis, addr))) {
				scope_hint--;
				rz_analysis_hint_set_opcode(analysis, scope_hint, "if");
				rz_analysis_hint_set_jump(analysis, scope_hint, addr);
				if (advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_CJMP, 0, true)) {
					op->fail = addr + op->size;
				}
			} else {
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->jump = hint->jump;
				op->fail = addr + op->size;
			}
			break;
		case WASM_OP_ELSE:
			// get if and set hint.
			if (!(hint = rz_analysis_hint_get(analysis, addr))) {
				advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_JMP, 0, true);
			} else {
				op->type = RZ_ANALYSIS_OP_TYPE_JMP;
				op->jump = hint->jump;
			}
			break;
		case WASM_OP_BR: {
			RzAnalysisHint *hint2 = NULL;
			ut32 val;
			read_u32_leb128(data + 1, data + len, &val);
			if ((hint2 = rz_analysis_hint_get(analysis, addr)) && hint2->jump != UT64_MAX) {
				op->type = RZ_ANALYSIS_OP_TYPE_JMP;
				op->jump = hint2->jump;
			} else if ((hint = rz_analysis_hint_get(analysis, scope_hint))) {
				if (hint->opcode && !strncmp("loop", hint->opcode, 4)) {
					op->type = RZ_ANALYSIS_OP_TYPE_JMP;
					op->jump = hint->jump;
					rz_analysis_hint_set_jump(analysis, addr, op->jump);
				} else {
					if (advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_JMP, val, false)) {
						rz_analysis_hint_set_jump(analysis, addr, op->jump);
					}
				}
			} else {
				if (advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_JMP, val, false)) {
					RZ_LOG_ERROR("wasm: cannot find jump type for br (using block type)\n");
					rz_analysis_hint_set_jump(analysis, addr, op->jump);
				} else {
					RZ_LOG_ERROR("wasm: cannot find jump for br\n");
				}
			}
			rz_analysis_hint_free(hint2);
		} break;
		case WASM_OP_BRIF: {
			RzAnalysisHint *hint2 = NULL;
			ut32 val;
			read_u32_leb128(data + 1, data + len, &val);
			if ((hint2 = rz_analysis_hint_get(analysis, addr)) && hint2->jump != UT64_MAX) {
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->jump = hint2->jump;
				op->fail = addr + op->size;
			} else if ((hint = rz_analysis_hint_get(analysis, scope_hint))) {
				if (hint->opcode && !strncmp("loop", hint->opcode, 4)) {
					op->fail = addr + op->size;
					op->jump = hint->jump;
					rz_analysis_hint_set_jump(analysis, addr, op->jump);
				} else {
					if (advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_CJMP, val, false)) {
						op->fail = addr + op->size;
						rz_analysis_hint_set_jump(analysis, addr, op->jump);
					}
				}
			} else {
				if (advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_CJMP, val, false)) {
					RZ_LOG_ERROR("wasm: cannot find jump type for br_if (using block type)\n");
					op->fail = addr + op->size;
					rz_analysis_hint_set_jump(analysis, addr, op->jump);
				} else {
					RZ_LOG_ERROR("wasm: cannot find jump for br_if\n");
				}
			}
			rz_analysis_hint_free(hint2);
		} break;
		case WASM_OP_END: {
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			if (scope_hint < UT64_MAX) {
				hint = rz_analysis_hint_get(analysis, scope_hint);
				if (hint && !strncmp("loop", hint->opcode, 4)) {
					rz_analysis_hint_set_jump(analysis, addr, op->jump);
					rz_analysis_hint_set_jump(analysis, op->jump, addr);
				} else if (hint && !strncmp("block", hint->opcode, 5)) {
					// if/else/block
					rz_analysis_hint_set_jump(analysis, hint->jump, addr);
					rz_analysis_hint_set_jump(analysis, addr, UT64_MAX);
				}
				if (hint) {
					rz_analysis_hint_set_opcode(analysis, scope_hint, "invalid");
					rz_analysis_hint_set_jump(analysis, scope_hint, UT64_MAX);
					rz_analysis_hint_del(analysis, scope_hint, 1);
					scope_hint++;
				} else {
					// all wasm routines ends with an end.
					op->eob = true;
					op->type = RZ_ANALYSIS_OP_TYPE_RET;
					scope_hint = UT64_MAX;
				}
			} else {
				if (!(hint = rz_analysis_hint_get(analysis, addr))) {
					// all wasm routines ends with an end.
					op->eob = true;
					op->type = RZ_ANALYSIS_OP_TYPE_RET;
				}
			}
		} break;
		case WASM_OP_I32REMS:
		case WASM_OP_I32REMU:
			op->type = RZ_ANALYSIS_OP_TYPE_MOD;
			break;
		case WASM_OP_GETLOCAL:
		case WASM_OP_I32LOAD:
		case WASM_OP_I64LOAD:
		case WASM_OP_F32LOAD:
		case WASM_OP_F64LOAD:
		case WASM_OP_I32LOAD8S:
		case WASM_OP_I32LOAD8U:
		case WASM_OP_I32LOAD16S:
		case WASM_OP_I32LOAD16U:
		case WASM_OP_I64LOAD8S:
		case WASM_OP_I64LOAD8U:
		case WASM_OP_I64LOAD16S:
		case WASM_OP_I64LOAD16U:
		case WASM_OP_I64LOAD32S:
		case WASM_OP_I64LOAD32U:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case WASM_OP_SETLOCAL:
		case WASM_OP_TEELOCAL:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		case WASM_OP_I32EQZ:
		case WASM_OP_I32EQ:
		case WASM_OP_I32NE:
		case WASM_OP_I32LTS:
		case WASM_OP_I32LTU:
		case WASM_OP_I32GTS:
		case WASM_OP_I32GTU:
		case WASM_OP_I32LES:
		case WASM_OP_I32LEU:
		case WASM_OP_I32GES:
		case WASM_OP_I32GEU:
		case WASM_OP_I64EQZ:
		case WASM_OP_I64EQ:
		case WASM_OP_I64NE:
		case WASM_OP_I64LTS:
		case WASM_OP_I64LTU:
		case WASM_OP_I64GTS:
		case WASM_OP_I64GTU:
		case WASM_OP_I64LES:
		case WASM_OP_I64LEU:
		case WASM_OP_I64GES:
		case WASM_OP_I64GEU:
		case WASM_OP_F32EQ:
		case WASM_OP_F32NE:
		case WASM_OP_F32LT:
		case WASM_OP_F32GT:
		case WASM_OP_F32LE:
		case WASM_OP_F32GE:
		case WASM_OP_F64EQ:
		case WASM_OP_F64NE:
		case WASM_OP_F64LT:
		case WASM_OP_F64GT:
		case WASM_OP_F64LE:
		case WASM_OP_F64GE:
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		case WASM_OP_I64OR:
		case WASM_OP_I32OR:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			break;
		case WASM_OP_I64XOR:
		case WASM_OP_I32XOR:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			break;
		case WASM_OP_I32CONST:
		case WASM_OP_I64CONST:
		case WASM_OP_F32CONST:
		case WASM_OP_F64CONST:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		case WASM_OP_I64ADD:
		case WASM_OP_I32ADD:
		case WASM_OP_F32ADD:
		case WASM_OP_F64ADD:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case WASM_OP_I64SUB:
		case WASM_OP_I32SUB:
		case WASM_OP_F32SUB:
		case WASM_OP_F64SUB:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			break;
		case WASM_OP_NOP:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		case WASM_OP_CALL:
		case WASM_OP_CALLINDIRECT:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = get_cf_offset(analysis, data, len);
			op->fail = addr + op->size;
			if (op->jump != UT64_MAX) {
				op->ptr = op->jump;
			}
			break;
		case WASM_OP_RETURN:
			// should be ret, but if there the analisys is stopped.
			op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		default:
			break;
		}
		break;
	case WASM_TYPE_OP_ATOMIC:
		switch (wop.op.atomic) {
		case WASM_OP_I32ATOMICLOAD:
		case WASM_OP_I64ATOMICLOAD:
		case WASM_OP_I32ATOMICLOAD8U:
		case WASM_OP_I32ATOMICLOAD16U:
		case WASM_OP_I64ATOMICLOAD8U:
		case WASM_OP_I64ATOMICLOAD16U:
		case WASM_OP_I64ATOMICLOAD32U:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case WASM_OP_I32ATOMICSTORE:
		case WASM_OP_I64ATOMICSTORE:
		case WASM_OP_I32ATOMICSTORE8:
		case WASM_OP_I32ATOMICSTORE16:
		case WASM_OP_I64ATOMICSTORE8:
		case WASM_OP_I64ATOMICSTORE16:
		case WASM_OP_I64ATOMICSTORE32:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		case WASM_OP_I32ATOMICRMWADD:
		case WASM_OP_I64ATOMICRMWADD:
		case WASM_OP_I32ATOMICRMW8UADD:
		case WASM_OP_I32ATOMICRMW16UADD:
		case WASM_OP_I64ATOMICRMW8UADD:
		case WASM_OP_I64ATOMICRMW16UADD:
		case WASM_OP_I64ATOMICRMW32UADD:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case WASM_OP_I32ATOMICRMW8USUB:
		case WASM_OP_I32ATOMICRMW16USUB:
		case WASM_OP_I32ATOMICRMWSUB:
		case WASM_OP_I64ATOMICRMW8USUB:
		case WASM_OP_I64ATOMICRMW16USUB:
		case WASM_OP_I64ATOMICRMW32USUB:
		case WASM_OP_I64ATOMICRMWSUB:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			break;
		case WASM_OP_I32ATOMICRMWAND:
		case WASM_OP_I64ATOMICRMWAND:
		case WASM_OP_I32ATOMICRMW8UAND:
		case WASM_OP_I32ATOMICRMW16UAND:
		case WASM_OP_I64ATOMICRMW8UAND:
		case WASM_OP_I64ATOMICRMW16UAND:
		case WASM_OP_I64ATOMICRMW32UAND:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			break;
		case WASM_OP_I32ATOMICRMWOR:
		case WASM_OP_I64ATOMICRMWOR:
		case WASM_OP_I32ATOMICRMW8UOR:
		case WASM_OP_I32ATOMICRMW16UOR:
		case WASM_OP_I64ATOMICRMW8UOR:
		case WASM_OP_I64ATOMICRMW16UOR:
		case WASM_OP_I64ATOMICRMW32UOR:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			break;
		case WASM_OP_I32ATOMICRMWXOR:
		case WASM_OP_I64ATOMICRMWXOR:
		case WASM_OP_I32ATOMICRMW8UXOR:
		case WASM_OP_I32ATOMICRMW16UXOR:
		case WASM_OP_I64ATOMICRMW8UXOR:
		case WASM_OP_I64ATOMICRMW16UXOR:
		case WASM_OP_I64ATOMICRMW32UXOR:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			break;
		case WASM_OP_I32ATOMICRMWXCHG:
		case WASM_OP_I64ATOMICRMWXCHG:
		case WASM_OP_I32ATOMICRMW8UXCHG:
		case WASM_OP_I32ATOMICRMW16UXCHG:
		case WASM_OP_I64ATOMICRMW8UXCHG:
		case WASM_OP_I64ATOMICRMW16UXCHG:
		case WASM_OP_I64ATOMICRMW32UXCHG:
			op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
			break;
		default:
			break;
		}
	default:
		break;
	}

analysis_end:
	addr_old = addr;
	free(wop.txt);
	rz_analysis_hint_free(hint);
	return op->size;
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return false;
	default:
		return -1;
	}
}

static char *get_reg_profile(RzAnalysis *analysis) {
	return rz_str_dup(
		"=PC	pc\n"
		"=BP	bp\n"
		"=SP	sp\n"
		"=A0	r0\n"
		"gpr	sp	.32	0	0\n" // stack pointer
		"gpr	pc	.32	4	0\n" // program counter
		"gpr	bp	.32	8	0\n" // base pointer // unused
	);
}

RzAnalysisPlugin rz_analysis_plugin_wasm = {
	.name = "wasm",
	.desc = "WebAssembly analysis plugin",
	.license = "LGPL3",
	.arch = "wasm",
	.bits = 64,
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
	.op = &wasm_op,
};
