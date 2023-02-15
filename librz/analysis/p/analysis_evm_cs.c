// SPDX-FileCopyrightText: 2023 Yaroslav Yashin <yaroslav.yashin@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_log.h"
#include <rz_analysis.h>
#include <rz_lib.h>
#include <capstone/capstone.h>
#include <capstone/sparc.h>
#include <capstone/evm.h>

#if CS_API_MAJOR < 5
#error Old Capstone not supported
#endif

#define INSOP(n) insn->detail->sparc.operands[n]
#define INSCC    insn->detail->sparc.cc

static int parse_reg_name(RzRegItem *reg, csh handle, cs_insn *insn, int reg_num) {
	if (!reg) {
		return -1;
	}
	switch (INSOP(reg_num).type) {
	case SPARC_OP_REG:
		reg->name = (char *)cs_reg_name(handle, INSOP(reg_num).reg);
		break;
	case SPARC_OP_MEM:
		if (INSOP(reg_num).mem.base != SPARC_REG_INVALID) {
			reg->name = (char *)cs_reg_name(handle, INSOP(reg_num).mem.base);
			break;
		}
	default:
		break;
	}
	return 0;
}

static void op_fillval(RzAnalysisOp *op, csh handle, cs_insn *insn) {
	static RzRegItem reg;
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		if (INSOP(0).type == SPARC_OP_MEM) {
			ZERO_FILL(reg);
			op->src[0] = rz_analysis_value_new();
			op->src[0]->type = RZ_ANALYSIS_VAL_MEM;
			op->src[0]->reg = &reg;
			parse_reg_name(op->src[0]->reg, handle, insn, 0);
			op->src[0]->delta = INSOP(0).mem.disp;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
		if (INSOP(1).type == SPARC_OP_MEM) {
			ZERO_FILL(reg);
			op->dst = rz_analysis_value_new();
			op->dst->type = RZ_ANALYSIS_VAL_MEM;
			op->dst->reg = &reg;
			parse_reg_name(op->dst->reg, handle, insn, 1);
			op->dst->delta = INSOP(1).mem.disp;
		}
		break;
	}
}

static int analop(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	static csh handle = 0;
	static int omode;
	cs_insn *insn;
	int mode, n, ret;

	if (mode != omode) {
		cs_close(&handle);
		handle = 0;
		omode = mode;
	}
	if (handle == 0) {
		ret = cs_open(CS_ARCH_EVM, CS_MODE_LITTLE_ENDIAN, &handle);
		RZ_LOG_DEBUG("analysis_evm_cs.c:cs_open: %i\n", ret)
		if (ret != CS_ERR_OK) {
			return -1;
		}
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	// capstone-next
	n = cs_disasm(handle, (const ut8 *)buf, len, addr, 1, &insn);
	if (n < 1) {
		RZ_LOG_DEBUG("analysis_evm_cs.c:cs_disasm: %s\n", "RZ_ANALYSIS_OP_TYPE_ILL")
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
	} else {
		// RZ_LOG_DEBUG("analysis_evm_cs.c:cs_disasm: %s\n", "ELSE")
		op->size = insn->size;
		op->id = insn->id;
		RZ_LOG_DEBUG("analysis_evm_cs.c:cs_disasm:op->size(%#x), op->id(%#x)\n", insn->size, insn->id)
		switch (insn->id) {
		case EVM_INS_STOP:
			op->type = RZ_ANALYSIS_OP_TYPE_NULL;
			break;
		case EVM_INS_ADD:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case EVM_INS_MUL:
			op->type = RZ_ANALYSIS_OP_TYPE_MUL;
			break;
		case EVM_INS_SUB:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			break;
		case EVM_INS_DIV:
		case EVM_INS_SDIV:
			op->type = RZ_ANALYSIS_OP_TYPE_DIV;
			break;
		case EVM_INS_MOD:
		case EVM_INS_ADDMOD:
		case EVM_INS_MULMOD:
		case EVM_INS_SMOD:
			op->type = RZ_ANALYSIS_OP_TYPE_MOD;
			break;
		case EVM_INS_AND:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			break;
		case EVM_INS_OR:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			break;
		case EVM_INS_XOR:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			break;
		case EVM_INS_NOT:
			op->type = RZ_ANALYSIS_OP_TYPE_NOT;
			break;
		case EVM_INS_POP:
			op->type = RZ_ANALYSIS_OP_TYPE_POP;
			break;
		case EVM_INS_MLOAD:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case EVM_INS_MSTORE:
		case EVM_INS_MSTORE8:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		case EVM_INS_JUMP:
			op->type = RZ_ANALYSIS_ADDR_HINT_TYPE_JUMP;
			break;
		case EVM_INS_JUMPI:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			break;

		case EVM_INS_PUSH1:
		case EVM_INS_PUSH2:
		case EVM_INS_PUSH3:
		case EVM_INS_PUSH4:
		case EVM_INS_PUSH5:
		case EVM_INS_PUSH6:
		case EVM_INS_PUSH7:
		case EVM_INS_PUSH8:
		case EVM_INS_PUSH9:
		case EVM_INS_PUSH10:
		case EVM_INS_PUSH11:
		case EVM_INS_PUSH12:
		case EVM_INS_PUSH13:
		case EVM_INS_PUSH14:
		case EVM_INS_PUSH15:
		case EVM_INS_PUSH16:
		case EVM_INS_PUSH17:
		case EVM_INS_PUSH18:
		case EVM_INS_PUSH19:
		case EVM_INS_PUSH20:
		case EVM_INS_PUSH21:
		case EVM_INS_PUSH22:
		case EVM_INS_PUSH23:
		case EVM_INS_PUSH24:
		case EVM_INS_PUSH25:
		case EVM_INS_PUSH26:
		case EVM_INS_PUSH27:
		case EVM_INS_PUSH28:
		case EVM_INS_PUSH29:
		case EVM_INS_PUSH30:
		case EVM_INS_PUSH31:
		case EVM_INS_PUSH32:
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			break;
		case EVM_INS_DUP1:
		case EVM_INS_DUP2:
		case EVM_INS_DUP3:
		case EVM_INS_DUP4:
		case EVM_INS_DUP5:
		case EVM_INS_DUP6:
		case EVM_INS_DUP7:
		case EVM_INS_DUP8:
		case EVM_INS_DUP9:
		case EVM_INS_DUP10:
		case EVM_INS_DUP11:
		case EVM_INS_DUP12:
		case EVM_INS_DUP13:
		case EVM_INS_DUP14:
		case EVM_INS_DUP15:
		case EVM_INS_DUP16:
			RZ_LOG_DEBUG("NOT IMPLEMENTED: op->id(%#x)\n", insn->id);
			break;
		case EVM_INS_SWAP1:
		case EVM_INS_SWAP2:
		case EVM_INS_SWAP3:
		case EVM_INS_SWAP4:
		case EVM_INS_SWAP5:
		case EVM_INS_SWAP6:
		case EVM_INS_SWAP7:
		case EVM_INS_SWAP8:
		case EVM_INS_SWAP9:
		case EVM_INS_SWAP10:
		case EVM_INS_SWAP11:
		case EVM_INS_SWAP12:
		case EVM_INS_SWAP13:
		case EVM_INS_SWAP14:
		case EVM_INS_SWAP15:
		case EVM_INS_SWAP16:
			RZ_LOG_DEBUG("NOT IMPLEMENTED: op->id(%#x)\n", insn->id);
			break;
		case EVM_INS_LOG0:
		case EVM_INS_LOG1:
		case EVM_INS_LOG2:
		case EVM_INS_LOG3:
		case EVM_INS_LOG4:
			RZ_LOG_DEBUG("NOT IMPLEMENTED: op->id(%#x)\n", insn->id);
			break;

		case EVM_INS_CALL:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			break;
		case EVM_INS_RETURN:
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			break;

		case EVM_INS_INVALID:
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			break;

		// Not implemented yet
		case EVM_INS_SIGNEXTEND:
		case EVM_INS_EXP:
		case EVM_INS_LT:
		case EVM_INS_GT:
		case EVM_INS_SLT:
		case EVM_INS_SGT:
		case EVM_INS_EQ:
		case EVM_INS_ISZERO:
		case EVM_INS_BYTE:
		// case EVM_INS_SHL: 	// logical shift left
		// case EVM_INS_SHR: 	// logical shift right
		// case EVM_INS_SAR: 	// arithmetic shigt right
		case EVM_INS_SHA3: // kessac256 hash
		case EVM_INS_ADDRESS:
		case EVM_INS_BALANCE:
		case EVM_INS_ORIGIN:
		case EVM_INS_CALLER:
		case EVM_INS_CALLVALUE:
		case EVM_INS_CALLDATALOAD:
		case EVM_INS_CALLDATASIZE:
		case EVM_INS_CALLDATACOPY:
		case EVM_INS_CODESIZE:
		case EVM_INS_CODECOPY:
		case EVM_INS_GASPRICE:
		case EVM_INS_EXTCODESIZE:
		case EVM_INS_EXTCODECOPY:
		case EVM_INS_RETURNDATASIZE:
		case EVM_INS_RETURNDATACOPY:
		// case EVM_INS_EXTCODEHASH:
		case EVM_INS_BLOCKHASH:
		case EVM_INS_COINBASE:
		case EVM_INS_TIMESTAMP:
		case EVM_INS_NUMBER: // Number of a current block
		case EVM_INS_DIFFICULTY:
		case EVM_INS_GASLIMIT:
		// case EVM_INS_CHAINID:
		// case EVM_INS_SELFBALANCE:
		// case EVM_INS_BASEFEE:
		case EVM_INS_PC:
		case EVM_INS_MSIZE:
		case EVM_INS_GAS:
		case EVM_INS_JUMPDEST:
		case EVM_INS_CREATE:
		case EVM_INS_CALLCODE:
		case EVM_INS_DELEGATECALL:
			// case EVM_INS_CREATE2:
		case EVM_INS_STATICCALL:
			// case EVM_INS_SELFDESTRUCT:
			RZ_LOG_DEBUG("NOT IMPLEMENTED: op->id(%#x)\n", insn->id);
			break;

			if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
				op_fillval(op, handle, insn);
			}
			cs_free(insn, n);
		}
	}
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	return strdup(
		"=PC	pc\n"
		"=BP	bp\n"
		"=SP	sp\n"
		"=A0	r0\n"
		"gpr	sp	.256	0	0\n" // stack pointer
		"gpr	pc	.32	256	0\n" // program counter
		"gpr	bp	.32	288	0\n" // base pointer // unused
	);
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 33;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		/* fall-thru */
	default:
		return 0;
	}
}

RzAnalysisPlugin rz_analysis_plugin_evm_cs = {
	.name = "evm",
	.desc = "Capstone EVM analysis",
	.esil = false,
	.license = "BSD",
	.arch = "evm",
	.bits = 256,
	.archinfo = archinfo,
	.op = &analop,
	.get_reg_profile = &get_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_evm_cs,
	.version = RZ_VERSION
};
#endif
