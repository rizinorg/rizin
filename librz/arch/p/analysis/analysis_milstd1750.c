// SPDX-FileCopyrightText: 2026 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_analysis.h>
#include <milstd1750/milstd1750_disas.h>

// Reference: MIL-STD-1750A Military Standard Sixteen-Bit
// Computer Instruction Set Architecture
// Section 5.24 Jump on condition
static RzTypeCond jc_cond_to_type(ut8 cc) {
	switch (cc & 0xF) {
	case 0x1: return RZ_TYPE_COND_LT;
	case 0x2: return RZ_TYPE_COND_EQ;
	case 0x3: return RZ_TYPE_COND_LE;
	case 0x4: return RZ_TYPE_COND_GT;
	case 0x5: return RZ_TYPE_COND_NE;
	case 0x6: return RZ_TYPE_COND_GE;
	case 0x8: return RZ_TYPE_COND_HS;
	case 0x9: return RZ_TYPE_COND_LT; //< carry or LT
	case 0xA: return RZ_TYPE_COND_EQ; //< carry or EQ
	case 0xB: return RZ_TYPE_COND_LE; //< carry or LE
	case 0xC: return RZ_TYPE_COND_GT; //< carry or GT
	case 0xD: return RZ_TYPE_COND_NE; //< carry or NE
	case 0xE: return RZ_TYPE_COND_GE; //< carry or GE
	default: return RZ_TYPE_COND_AL;
	}
}

static const char *milstd_reg_name(ut8 n) {
	static const char *const regs[16] = {
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
	};
	return regs[n & 0xF];
}

// True for instruction formats that reference memory (as opposed to
// register-only or immediate forms). Used to decide whether a data-processing
// op actually touches memory.
static bool milstd_format_mem(MilStd1750Format f) {
	switch (f) {
	case MIL_FMT_MEM:
	case MIL_FMT_B:
	case MIL_FMT_BX:
	case MIL_FMT_ADDR:
	case MIL_FMT_IM_0_15:
	case MIL_FMT_IM_1_16:
		return true;
	default:
		return false;
	}
}

// Set op->direction (READ/WRITE/EXEC) from the resolved type and addressing
// format. MIL-STD-1750 is memory-oriented: arithmetic/compare may take a memory
// source operand (READ), and the in-memory bit/increment ops are
// read-modify-write (READ|WRITE). Register/immediate forms touch no memory.
static void milstd_set_direction(RzAnalysisOp *op, MilStd1750Format fmt) {
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_LOAD:
	case RZ_ANALYSIS_OP_TYPE_POP: // POPM reads from the stack
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
	case RZ_ANALYSIS_OP_TYPE_PUSH: // PSHM writes to the stack
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		break;
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_MJMP:
	case RZ_ANALYSIS_OP_TYPE_MCJMP:
	case RZ_ANALYSIS_OP_TYPE_RET:
		op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
		break;
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_MUL:
	case RZ_ANALYSIS_OP_TYPE_DIV:
	case RZ_ANALYSIS_OP_TYPE_AND:
	case RZ_ANALYSIS_OP_TYPE_OR:
	case RZ_ANALYSIS_OP_TYPE_XOR:
	case RZ_ANALYSIS_OP_TYPE_NOT:
		if (fmt == MIL_FMT_IM_0_15 || fmt == MIL_FMT_IM_1_16) {
			// in-memory bit set/reset and INCM/DECM: the memory word is both
			// source and destination
			op->direction = RZ_ANALYSIS_OP_DIR_READ | RZ_ANALYSIS_OP_DIR_WRITE;
		} else if (milstd_format_mem(fmt)) {
			// memory operand read into the accumulator (e.g. A/S/AND ADDR)
			op->direction = RZ_ANALYSIS_OP_DIR_READ;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_CMP:
		if (milstd_format_mem(fmt)) {
			op->direction = RZ_ANALYSIS_OP_DIR_READ;
		}
		break;
	default:
		break;
	}
}

// Set op->val to the instruction's immediate operand, where one is encoded.
// The B/ICR displacement fields describe branch/data targets rather than data
// values and are deliberately left out (they surface via op->jump instead).
static void milstd_set_val(RzAnalysisOp *op, const MilStd1750Instruction *insn) {
	switch (insn->format) {
	case MIL_FMT_IS: // Ra, short immediate (1..16)
	case MIL_FMT_IMM_R: // 4-bit immediate, Rb
	case MIL_FMT_R_IMM: // Rb, immediate (incl. shift counts)
	case MIL_FMT_IM_0_15: // bit index / register count
	case MIL_FMT_IM_1_16: // INCM/DECM count
		op->val = insn->imm8;
		break;
	case MIL_FMT_IM_OCX: // 16-bit immediate (AIM/SIM/.../CIM)
		op->val = insn->imm16;
		break;
	case MIL_FMT_XIO: // 16-bit I/O command word
		op->val = insn->xio_cmd;
		break;
	default:
		break;
	}
}

// Memory-operand data width in bytes for a memory-format opcode (op->ptrsize).
static int milstd_mem_size(ut16 opc) {
	switch (opc) {
	// extended floating, 48-bit
	case MIL_OP_EFL:
	case MIL_OP_EFA:
	case MIL_OP_EFS:
	case MIL_OP_EFM:
	case MIL_OP_EFD:
	case MIL_OP_EFC:
	case MIL_OP_EFST:
		return 6;
	// double-precision integer and single floating, 32-bit
	case MIL_OP_DL:
	case MIL_OP_DLI:
	case MIL_OP_DLE:
	case MIL_OP_DST:
	case MIL_OP_DSTI:
	case MIL_OP_DSTE:
	case MIL_OP_DA:
	case MIL_OP_DS:
	case MIL_OP_DM:
	case MIL_OP_DD:
	case MIL_OP_DC:
	case MIL_OP_FA:
	case MIL_OP_FS:
	case MIL_OP_FM:
	case MIL_OP_FD:
	case MIL_OP_FC:
	// ... and their base-relative (B) and base-relative-indexed (BX) forms
	case MIL_OP_DLB:
	case MIL_OP_DLBX:
	case MIL_OP_DSTB:
	case MIL_OP_DSTX:
	case MIL_OP_FAB:
	case MIL_OP_FABX:
	case MIL_OP_FSB:
	case MIL_OP_FSBX:
	case MIL_OP_FMB:
	case MIL_OP_FMBX:
	case MIL_OP_FDB:
	case MIL_OP_FDBX:
	case MIL_OP_FCB:
	case MIL_OP_FCBX:
		return 4;
	// byte operand, 8-bit
	case MIL_OP_LUB:
	case MIL_OP_LLB:
	case MIL_OP_LUBI:
	case MIL_OP_LLBI:
	case MIL_OP_STUB:
	case MIL_OP_STLB:
	case MIL_OP_SUBI:
	case MIL_OP_SLBI:
		return 1;
	default:
		return 2; // single word (16-bit)
	}
}

// Set op->ptr / op->ptrsize for instructions that statically reference memory
// via a direct address word. 1750 encodes word indices, so the byte address is
// addr*2. op->refptr is intentionally left 0 (ptr is a direct reference): the
// indirect *I forms hold a word-indexed pointer that the byte-oriented refptr
// auto-follow would misread, so indirection is not resolved here.
static void milstd_set_ptr(RzAnalysisOp *op, const MilStd1750Instruction *insn) {
	switch (insn->format) {
	case MIL_FMT_MEM:
	case MIL_FMT_IM_0_15:
	case MIL_FMT_IM_1_16:
		break;
	default:
		return; // no direct address field (register/immediate/base-relative)
	}
	if (insn->opcode == MIL_OP_LIM) {
		return; // LIM: the second word is an immediate value, not an address
	}
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_MJMP:
	case RZ_ANALYSIS_OP_TYPE_MCJMP:
	case RZ_ANALYSIS_OP_TYPE_RET:
		return; // JS/SJS/SOJ: addr is a code target (op->jump), not data
	default:
		break;
	}
	op->ptr = (ut64)insn->addr * 2;
	op->ptrsize = milstd_mem_size(insn->opcode);
}

// Set op->datatype: floating-point for F* (single, 32-bit) and EF* (extended,
// 48-bit) ops, otherwise the integer width of the memory operand.
static void milstd_set_datatype(RzAnalysisOp *op, const MilStd1750Instruction *insn) {
	const char *m = insn->mnemonic;
	if (m && (m[0] == 'F' || (m[0] == 'E' && m[1] == 'F'))) {
		op->datatype = RZ_ANALYSIS_DATATYPE_FLOAT;
		return;
	}
	switch (op->ptrsize) {
	case 2: op->datatype = RZ_ANALYSIS_DATATYPE_INT16; break;
	case 4: op->datatype = RZ_ANALYSIS_DATATYPE_INT32; break;
	default: break; // byte (1) or no memory operand (0): leave NULL
	}
}

// Set op->stackop / op->stackptr for the stack instructions. Per MIL-STD-1750A
// R15 is the implicit stack pointer and the stack grows toward lower addresses,
// matching rizin's convention (RZ_ANALYSIS_STACK_INC applies sp -= stackptr, so
// a positive stackptr means the stack grows). Each register is one 16-bit word;
// stackptr is expressed in bytes to match the plugin's byte-addressed model.
static void milstd_set_stack(RzAnalysisOp *op, const MilStd1750Instruction *insn) {
	switch (insn->opcode) {
	// PSHM/POPM transfer the inclusive register range Ra..Rb, wrapping the
	// register selector modulo 16 (so Ra > Rb pushes Ra..R15, R0..Rb). The
	// count is therefore ((Rb - Ra) mod 16) + 1, always 1..16.
	case MIL_OP_PSHM: { // PSHM Ra, Rb — push registers (SP grows)
		int count = ((insn->rb - insn->ra) & 0xF) + 1;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = count * 2;
		break;
	}
	case MIL_OP_POPM: { // POPM Ra, Rb — pop registers (SP shrinks)
		int count = ((insn->rb - insn->ra) & 0xF) + 1;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -count * 2;
		break;
	}
	case MIL_OP_SJS: // SJS — stack the IC and jump (push one word)
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 2;
		break;
	case MIL_OP_URS: // URS — unstack the IC and return (pop one word)
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -2;
		break;
	default:
		break;
	}
}

// Set op->reg (destination register) and op->ireg (register used to compute a
// memory effective address). Driven by the addressing format; op->type filters
// out instructions that have no register destination.
static void milstd_set_reg(RzAnalysisOp *op, const MilStd1750Instruction *insn) {
	// Index / base register of the effective-address computation.
	switch (insn->format) {
	case MIL_FMT_MEM:
	case MIL_FMT_IM_0_15:
	case MIL_FMT_IM_1_16:
	case MIL_FMT_ADDR:
		if (insn->rx) { // Rx == 0 means no indexing
			op->ireg = milstd_reg_name(insn->rx);
		}
		break;
	case MIL_FMT_BX: // base-relative indexed: base R(br), index Rx
		op->ireg = milstd_reg_name(insn->rx ? insn->rx : insn->br);
		break;
	case MIL_FMT_B: // base-relative: address computed from base register
		op->ireg = milstd_reg_name(insn->br);
		break;
	default:
		break;
	}

	// Destination register: Ra for the Ra-based forms, Rb for the immediate
	// forms (IMM_R/R_IMM, e.g. shifts and register bit ops).
	const char *dst = NULL;
	switch (insn->format) {
	case MIL_FMT_R:
	case MIL_FMT_SR:
	case MIL_FMT_IS:
	case MIL_FMT_IM_OCX:
	case MIL_FMT_MEM:
		dst = milstd_reg_name(insn->ra);
		break;
	case MIL_FMT_IMM_R:
	case MIL_FMT_R_IMM:
		dst = milstd_reg_name(insn->rb);
		break;
	default:
		break;
	}
	// Drop it for ops with no register destination: compares, stores (memory is
	// the destination), the multi-register stack ops, and control flow.
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_CMP:
	case RZ_ANALYSIS_OP_TYPE_STORE:
	case RZ_ANALYSIS_OP_TYPE_PUSH:
	case RZ_ANALYSIS_OP_TYPE_POP:
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_MJMP:
	case RZ_ANALYSIS_OP_TYPE_MCJMP:
	case RZ_ANALYSIS_OP_TYPE_RET:
		dst = NULL;
		break;
	default:
		break;
	}
	op->reg = dst;
}

// --- RzAnalysisValue constructors (RZ_ANALYSIS_OP_MASK_VAL) ---
// RzAnalysisValue holds no owned sub-allocations (RzRegItem* are borrowed from
// the reg profile), so it is freed with plain free() and copied shallowly.

static RzAnalysisValue *milstd_v_reg(RzAnalysis *a, ut8 n, RzAnalysisValueAccess acc) {
	RzAnalysisValue *v = rz_analysis_value_new();
	if (!v) {
		return NULL;
	}

	v->type = RZ_ANALYSIS_VAL_REG;
	v->access = acc;
	v->reg = rz_reg_get(a->reg, milstd_reg_name(n), RZ_REG_TYPE_ANY);

	return v;
}

static RzAnalysisValue *milstd_v_imm(st64 imm) {
	RzAnalysisValue *v = rz_analysis_value_new();
	if (!v) {
		return NULL;
	}

	v->type = RZ_ANALYSIS_VAL_IMM;
	v->access = RZ_ANALYSIS_ACC_R;
	v->imm = imm;

	return v;
}

// Direct memory operand: byte address `base` plus optional word index Rx.
static RzAnalysisValue *milstd_v_mem(RzAnalysis *a, ut64 base, ut8 rx, int memref, RzAnalysisValueAccess acc) {
	RzAnalysisValue *v = rz_analysis_value_new();
	if (!v) {
		return NULL;
	}

	v->type = RZ_ANALYSIS_VAL_MEM;
	v->access = acc;
	v->memref = memref;
	v->base = base;
	if (rx) {
		v->regdelta = rz_reg_get(a->reg, milstd_reg_name(rx), RZ_REG_TYPE_ANY);
		v->mul = 2; // index counts 16-bit words
	}

	return v;
}

// Base-relative memory operand: base register R(br) + index Rx (BX) or disp (B).
static RzAnalysisValue *milstd_v_basemem(RzAnalysis *a, ut8 br, ut8 rx, st64 disp, int memref, RzAnalysisValueAccess acc) {
	RzAnalysisValue *v = rz_analysis_value_new();
	if (!v) {
		return NULL;
	}

	v->type = RZ_ANALYSIS_VAL_MEM;
	v->access = acc;
	v->memref = memref;
	v->reg = rz_reg_get(a->reg, milstd_reg_name(br), RZ_REG_TYPE_ANY);
	v->delta = disp;
	if (rx) {
		v->regdelta = rz_reg_get(a->reg, milstd_reg_name(rx), RZ_REG_TYPE_ANY);
		v->mul = 1; // base-relative index is added unscaled
	}

	return v;
}

// --- Operand-shape combinators ------------------------------------------

// Ra = Rb
static void milstd_reg_reg(RzAnalysis *a, RzAnalysisOp *op, ut8 rd, ut8 rs) {
	op->dst = milstd_v_reg(a, rd, RZ_ANALYSIS_ACC_W);
	op->src[0] = milstd_v_reg(a, rs, RZ_ANALYSIS_ACC_R);
}

// Ra = imm
static void milstd_reg_imm(RzAnalysis *a, RzAnalysisOp *op, ut8 rd, st64 imm) {
	op->dst = milstd_v_reg(a, rd, RZ_ANALYSIS_ACC_W);
	op->src[0] = milstd_v_imm(imm);
}

// Ra = [mem]
static void milstd_reg_mem(RzAnalysis *a, RzAnalysisOp *op, ut8 rd, RzAnalysisValue *mem) {
	op->dst = milstd_v_reg(a, rd, RZ_ANALYSIS_ACC_W);
	op->src[0] = mem;
}

// [mem] = Ra
static void milstd_mem_reg(RzAnalysis *a, RzAnalysisOp *op, RzAnalysisValue *mem, ut8 rs) {
	op->dst = mem;
	op->src[0] = milstd_v_reg(a, rs, RZ_ANALYSIS_ACC_R);
}

// [mem] = imm (store, or read-modify-write when the mem value carries ACC_R|ACC_W)
static void milstd_mem_imm(RzAnalysisOp *op, RzAnalysisValue *mem, st64 imm) {
	op->dst = mem;
	op->src[0] = milstd_v_imm(imm);
}

// Ra = Ra (op) Rb
static void milstd_acc_reg(RzAnalysis *a, RzAnalysisOp *op, ut8 ra, ut8 rb) {
	op->dst = milstd_v_reg(a, ra, RZ_ANALYSIS_ACC_W);
	op->src[0] = milstd_v_reg(a, ra, RZ_ANALYSIS_ACC_R);
	op->src[1] = milstd_v_reg(a, rb, RZ_ANALYSIS_ACC_R);
}

// Ra = Ra (op) imm
static void milstd_acc_imm(RzAnalysis *a, RzAnalysisOp *op, ut8 ra, st64 imm) {
	op->dst = milstd_v_reg(a, ra, RZ_ANALYSIS_ACC_W);
	op->src[0] = milstd_v_reg(a, ra, RZ_ANALYSIS_ACC_R);
	op->src[1] = milstd_v_imm(imm);
}

// Ra = Ra (op) [mem]
static void milstd_acc_mem(RzAnalysis *a, RzAnalysisOp *op, ut8 ra, RzAnalysisValue *mem) {
	op->dst = milstd_v_reg(a, ra, RZ_ANALYSIS_ACC_W);
	op->src[0] = milstd_v_reg(a, ra, RZ_ANALYSIS_ACC_R);
	op->src[1] = mem;
}

// cmp Ra, Rb (two read sources, no destination)
static void milstd_cmp_reg_reg(RzAnalysis *a, RzAnalysisOp *op, ut8 r0, ut8 r1) {
	op->src[0] = milstd_v_reg(a, r0, RZ_ANALYSIS_ACC_R);
	op->src[1] = milstd_v_reg(a, r1, RZ_ANALYSIS_ACC_R);
}

// cmp Ra, imm
static void milstd_cmp_reg_imm(RzAnalysis *a, RzAnalysisOp *op, ut8 r, st64 imm) {
	op->src[0] = milstd_v_reg(a, r, RZ_ANALYSIS_ACC_R);
	op->src[1] = milstd_v_imm(imm);
}

// cmp Ra, [mem]
static void milstd_cmp_reg_mem(RzAnalysis *a, RzAnalysisOp *op, ut8 r, RzAnalysisValue *mem) {
	op->src[0] = milstd_v_reg(a, r, RZ_ANALYSIS_ACC_R);
	op->src[1] = mem;
}

// cmp [mem], imm (test bit in memory)
static void milstd_cmp_mem_imm(RzAnalysisOp *op, RzAnalysisValue *mem, st64 imm) {
	op->src[0] = mem;
	op->src[1] = milstd_v_imm(imm);
}

// Fill op->src[]/op->dst (analyzable operands) and op->access (flat read/write
// list). Driven by addressing format; op->type selects the read/write roles.
static void milstd_fill_val(RzAnalysis *a, RzAnalysisOp *op, const MilStd1750Instruction *insn) {
	ut32 type = op->type & RZ_ANALYSIS_OP_TYPE_MASK;
	int sz = milstd_mem_size(insn->opcode);

	switch (insn->format) {
	case MIL_FMT_R:
		if (type == RZ_ANALYSIS_OP_TYPE_PUSH || type == RZ_ANALYSIS_OP_TYPE_POP) {
			break; // PSHM/POPM: operands are a register range, not modelled
		}
		if (type == RZ_ANALYSIS_OP_TYPE_CMP) {
			milstd_cmp_reg_reg(a, op, insn->ra, insn->rb);
		} else if (type == RZ_ANALYSIS_OP_TYPE_LOAD) {
			milstd_reg_reg(a, op, insn->ra, insn->rb); // LR: Ra = Rb
		} else {
			milstd_acc_reg(a, op, insn->ra, insn->rb); // Ra = Ra (op) Rb
		}
		break;
	case MIL_FMT_SR:
		milstd_reg_reg(a, op, insn->ra, insn->ra); // Ra = (op) Ra
		break;
	case MIL_FMT_IS:
		if (type == RZ_ANALYSIS_OP_TYPE_LOAD) {
			milstd_reg_imm(a, op, insn->ra, insn->imm8);
		} else if (type == RZ_ANALYSIS_OP_TYPE_CMP) {
			milstd_cmp_reg_imm(a, op, insn->ra, insn->imm8);
		} else {
			milstd_acc_imm(a, op, insn->ra, insn->imm8);
		}
		break;
	case MIL_FMT_IMM_R:
	case MIL_FMT_R_IMM:
		if (type == RZ_ANALYSIS_OP_TYPE_CMP) {
			milstd_cmp_reg_imm(a, op, insn->rb, insn->imm8);
		} else {
			milstd_acc_imm(a, op, insn->rb, insn->imm8);
		}
		break;
	case MIL_FMT_IM_OCX:
		if (type == RZ_ANALYSIS_OP_TYPE_CMP) {
			milstd_cmp_reg_imm(a, op, insn->ra, insn->imm16);
		} else {
			milstd_acc_imm(a, op, insn->ra, insn->imm16);
		}
		break;
	case MIL_FMT_MEM: {
		if (type == RZ_ANALYSIS_OP_TYPE_CALL || type == RZ_ANALYSIS_OP_TYPE_CJMP) {
			break; // JS/SJS/SOJ: addr is a code target, not a data operand
		}
		if (insn->opcode == MIL_OP_LIM) { // LIM: the second word is an immediate, not memory
			milstd_reg_imm(a, op, insn->ra, insn->addr);
			break;
		}
		ut64 ea = (ut64)insn->addr * 2;
		if (type == RZ_ANALYSIS_OP_TYPE_LOAD) {
			milstd_reg_mem(a, op, insn->ra, milstd_v_mem(a, ea, insn->rx, sz, RZ_ANALYSIS_ACC_R));
		} else if (type == RZ_ANALYSIS_OP_TYPE_STORE) {
			milstd_mem_reg(a, op, milstd_v_mem(a, ea, insn->rx, sz, RZ_ANALYSIS_ACC_W), insn->ra);
		} else if (type == RZ_ANALYSIS_OP_TYPE_CMP) {
			milstd_cmp_reg_mem(a, op, insn->ra, milstd_v_mem(a, ea, insn->rx, sz, RZ_ANALYSIS_ACC_R));
		} else { // Ra = Ra (op) [mem]
			milstd_acc_mem(a, op, insn->ra, milstd_v_mem(a, ea, insn->rx, sz, RZ_ANALYSIS_ACC_R));
		}
		break;
	}
	case MIL_FMT_IM_0_15:
	case MIL_FMT_IM_1_16: {
		ut64 ea = (ut64)insn->addr * 2;
		if (type == RZ_ANALYSIS_OP_TYPE_LOAD) { // LM: memory into a register range
			op->src[0] = milstd_v_mem(a, ea, insn->rx, sz, RZ_ANALYSIS_ACC_R);
		} else if (type == RZ_ANALYSIS_OP_TYPE_STORE) { // STM/STC/STCI
			milstd_mem_imm(op, milstd_v_mem(a, ea, insn->rx, sz, RZ_ANALYSIS_ACC_W), insn->imm8);
		} else if (type == RZ_ANALYSIS_OP_TYPE_CMP) { // TB: test bit in memory
			milstd_cmp_mem_imm(op, milstd_v_mem(a, ea, insn->rx, sz, RZ_ANALYSIS_ACC_R), insn->imm8);
		} else { // SB/RB/INCM/DECM: read-modify-write the memory word
			milstd_mem_imm(op, milstd_v_mem(a, ea, insn->rx, sz, RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), insn->imm8);
		}
		break;
	}
	case MIL_FMT_B:
	case MIL_FMT_BX: {
		// Base-relative; the accumulator register is implied by the opcode and
		// not modelled. Only the memory operand is recorded.
		ut8 rx = (insn->format == MIL_FMT_BX) ? insn->rx : 0;
		st64 disp = (insn->format == MIL_FMT_B) ? insn->imm8 : 0;
		RzAnalysisValueAccess acc = (type == RZ_ANALYSIS_OP_TYPE_STORE) ? RZ_ANALYSIS_ACC_W : RZ_ANALYSIS_ACC_R;
		RzAnalysisValue *mem = milstd_v_basemem(a, insn->br, rx, disp, sz, acc);
		if (type == RZ_ANALYSIS_OP_TYPE_STORE) {
			op->dst = mem;
		} else {
			op->src[0] = mem;
		}
		break;
	}
	default:
		break;
	}

	// op->access: flat list of every value touched, owning independent copies
	// (op_fini frees src/dst and the list separately, so they must not alias).
	RzList *acc = rz_list_newf((RzListFree)rz_analysis_value_free);
	if (!acc) {
		return;
	}
	if (op->dst) {
		rz_list_append(acc, rz_analysis_value_copy(op->dst));
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(op->src); i++) {
		if (op->src[i]) {
			rz_list_append(acc, rz_analysis_value_copy(op->src[i]));
		}
	}
	if (rz_list_empty(acc)) {
		rz_list_free(acc);
	} else {
		op->access = acc;
	}
}

static void milstd_fill_operands(RzAnalysis *analysis, RzAnalysisOp *op, const MilStd1750Instruction *insn, RzAnalysisOpMask mask) {
	milstd_set_stack(op, insn);
	milstd_set_direction(op, insn->format);
	milstd_set_val(op, insn);
	milstd_set_ptr(op, insn);
	milstd_set_datatype(op, insn);
	milstd_set_reg(op, insn);
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		milstd_fill_val(analysis, op, insn);
	}
}

static void set_invalid(RzAnalysisOp *op, ut64 addr) {
	op->family = RZ_ANALYSIS_OP_FAMILY_UNKNOWN;
	op->type = RZ_ANALYSIS_OP_TYPE_ILL;
	op->addr = addr;
	op->size = 2;
	op->nopcode = 1;
	op->eob = true;
}

int rz_milstd1750_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	MilStd1750Instruction insn;
	if (!rz_milstd1750_decode(data, len, &insn)) {
		set_invalid(op, addr);
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("invalid");
		}
		return -1;
	}

	op->addr = addr;
	op->size = insn.size;
	op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		char *str = rz_milstd1750_stringify(&insn);
		op->mnemonic = str ? str : rz_str_dup("invalid");
	}

	// MIL-STD-1750A: encoded addresses are word indices; rizin uses
	// byte addresses with bits=8, so multiply by 2.
	ut64 icr_target = addr + (st64)(st8)insn.imm8 * 2;
	ut64 abs_target = (ut64)insn.addr * 2;
	ut64 next_pc = addr + insn.size;

	// insn.opcode is the canonical MIL_OP_* pattern the decoder matched: the
	// instruction word with its operand bits cleared (the mask depends on the
	// format, e.g. B hides a 2-bit BR field and BX/IM a 4-bit opcode extension
	// inside the word). So it can be compared against the constants directly.
	switch (insn.opcode) {
	// --- Special / control flow boundaries ---
	case MIL_OP_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case MIL_OP_BPT:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->eob = true;
		break;
	case MIL_OP_URS: // URS — Unstack IC and Return from Subroutine
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		break;

	// --- ICR branches: target = addr + disp*2 (D = signed 8-bit) ---
	case MIL_OP_BR: // BR — unconditional
		op->cond = RZ_TYPE_COND_AL;
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = icr_target;
		op->eob = true;
		break;
	case MIL_OP_BEZ: // BEZ — branch if equal zero (Z)
	case MIL_OP_BLT: // BLT — branch if less than zero (N)
	case MIL_OP_BLE: // BLE — branch if less or equal zero (N|Z)
	case MIL_OP_BGT: // BGT — branch if greater than zero (P)
	case MIL_OP_BNZ: // BNZ — branch if not zero (P|N)
	case MIL_OP_BGE: // BGE — branch if greater or equal zero (P|Z)
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		switch (insn.opcode) {
		case MIL_OP_BEZ: op->cond = RZ_TYPE_COND_EQ; break;
		case MIL_OP_BLT: op->cond = RZ_TYPE_COND_LT; break;
		case MIL_OP_BLE: op->cond = RZ_TYPE_COND_LE; break;
		case MIL_OP_BGT: op->cond = RZ_TYPE_COND_GT; break;
		case MIL_OP_BNZ: op->cond = RZ_TYPE_COND_NE; break;
		case MIL_OP_BGE: op->cond = RZ_TYPE_COND_GE; break;
		}
		op->jump = icr_target;
		op->fail = next_pc;
		break;

	// --- Memory-format jumps: target word in w2 → byte = w2*2 ---
	case MIL_OP_JC: // JC C, LABEL — Jump on Condition (direct)
		if (insn.cond == 0) {
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		} else if (insn.cond == 0x7 || insn.cond == 0xF) {
			op->cond = RZ_TYPE_COND_AL;
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->jump = abs_target;
			op->eob = true;
		} else {
			op->cond = jc_cond_to_type(insn.cond);
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = abs_target;
			op->fail = next_pc;
		}
		break;
	case MIL_OP_JCI: // JCI C, ADDR — Jump on Condition (indirect)
		if (insn.cond == 0) {
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		} else if (insn.cond == 0x7 || insn.cond == 0xF) {
			op->cond = RZ_TYPE_COND_AL;
			op->type = RZ_ANALYSIS_OP_TYPE_MJMP;
			op->eob = true;
		} else {
			op->cond = jc_cond_to_type(insn.cond);
			op->type = RZ_ANALYSIS_OP_TYPE_MCJMP;
			op->fail = next_pc;
		}
		break;
	case MIL_OP_JS: // JS — Jump to Subroutine (return addr in RA)
	case MIL_OP_SJS: // SJS — Stack IC and Jump to Subroutine
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = abs_target;
		op->fail = next_pc;
		break;
	case MIL_OP_SOJ: // SOJ — Subtract One and Jump (taken while RA != 0)
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->cond = RZ_TYPE_COND_NE;
		op->jump = abs_target;
		op->fail = next_pc;
		break;
	case MIL_OP_BEX: // BEX N — Branch to Executive (interrupt-vectored)
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		op->eob = true;
		break;
	case MIL_OP_BIF: // BIF — Branch on Input Flag (target unknown statically)
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->fail = next_pc;
		break;

	// --- LST/LSTI: load (MK,SW,IC) from memory; unconditional indirect jump ---
	case MIL_OP_LSTI: // LSTI ADDR — indirect load status (also reloads IC)
	case MIL_OP_LST: // LST ADDR — direct load status (also reloads IC)
		op->type = RZ_ANALYSIS_OP_TYPE_MJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		op->eob = true;
		break;

	// --- I/O ---
	case MIL_OP_XIO:
	case MIL_OP_VIO:
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->family = RZ_ANALYSIS_OP_FAMILY_IO;
		break;

	// --- Stack ---
	case MIL_OP_POPM: op->type = RZ_ANALYSIS_OP_TYPE_POP; break; // POPM
	case MIL_OP_PSHM:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// --- Move / exchange ---
	case MIL_OP_MOV:
	case MIL_OP_XBR:
	case MIL_OP_XWR:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// --- Add ---
	case MIL_OP_FA:
	case MIL_OP_FAB:
	case MIL_OP_FABX:
	case MIL_OP_FAR:
	case MIL_OP_EFA:
	case MIL_OP_EFAR:
	case MIL_OP_FABS:
	case MIL_OP_UAR:
	case MIL_OP_UA:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case MIL_OP_AB:
	case MIL_OP_ABX:
	case MIL_OP_A:
	case MIL_OP_AR:
	case MIL_OP_AIM:
	case MIL_OP_AISP:
	case MIL_OP_INCM:
	case MIL_OP_ABS:
	case MIL_OP_DABS:
	case MIL_OP_DA:
	case MIL_OP_DAR:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->sign = true;
		break;

	// --- Sub ---
	case MIL_OP_FS:
	case MIL_OP_FSB:
	case MIL_OP_FSBX:
	case MIL_OP_FSR:
	case MIL_OP_EFS:
	case MIL_OP_EFSR:
	case MIL_OP_FNEG:
	case MIL_OP_USR:
	case MIL_OP_US:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MIL_OP_SBB:
	case MIL_OP_SBBX:
	case MIL_OP_S:
	case MIL_OP_SR:
	case MIL_OP_SIM:
	case MIL_OP_SISP:
	case MIL_OP_DECM:
	case MIL_OP_NEG:
	case MIL_OP_DNEG:
	case MIL_OP_DS:
	case MIL_OP_DSR:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->sign = true;
		break;

	// --- Mul ---
	case MIL_OP_FM:
	case MIL_OP_FMB:
	case MIL_OP_FMBX:
	case MIL_OP_FMR:
	case MIL_OP_EFM:
	case MIL_OP_EFMR:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case MIL_OP_MB:
	case MIL_OP_MBX:
	case MIL_OP_MS:
	case MIL_OP_MSR:
	case MIL_OP_MIM:
	case MIL_OP_MSIM:
	case MIL_OP_MISP:
	case MIL_OP_MISN:
	case MIL_OP_M:
	case MIL_OP_MR:
	case MIL_OP_DM:
	case MIL_OP_DMR:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->sign = true;
		break;

	// --- Div ---
	case MIL_OP_FD:
	case MIL_OP_FDB:
	case MIL_OP_FDBX:
	case MIL_OP_FDR:
	case MIL_OP_EFD:
	case MIL_OP_EFDR:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case MIL_OP_DB:
	case MIL_OP_DBX:
	case MIL_OP_DV:
	case MIL_OP_DVR:
	case MIL_OP_DIM:
	case MIL_OP_DVIM:
	case MIL_OP_DISP:
	case MIL_OP_DISN:
	case MIL_OP_D:
	case MIL_OP_DR:
	case MIL_OP_DD:
	case MIL_OP_DDR:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		op->sign = true;
		break;

	// --- Logical ---
	case MIL_OP_ANDB:
	case MIL_OP_ANDX:
	case MIL_OP_AND:
	case MIL_OP_ANDM:
	case MIL_OP_ANDR:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case MIL_OP_ORB:
	case MIL_OP_ORBX:
	case MIL_OP_OR:
	case MIL_OP_ORIM:
	case MIL_OP_ORR:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case MIL_OP_XOR:
	case MIL_OP_XORM:
	case MIL_OP_XORR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case MIL_OP_N:
	case MIL_OP_NIM:
	case MIL_OP_NR:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;

	// --- Float/integer conversion ---
	case MIL_OP_FIX:
	case MIL_OP_FLT:
	case MIL_OP_EFIX:
	case MIL_OP_EFLT:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;

	// --- Shifts ---
	case MIL_OP_SLL:
	case MIL_OP_SLC:
	case MIL_OP_DSLL:
	case MIL_OP_DSLC:
	case MIL_OP_SLR:
	case MIL_OP_DSLR:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case MIL_OP_SRL:
	case MIL_OP_DSRL:
	case MIL_OP_SCR:
	case MIL_OP_DSCR:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case MIL_OP_SRA:
	case MIL_OP_DSRA:
	case MIL_OP_SAR:
	case MIL_OP_DSAR:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		op->sign = true;
		break;

	// --- Compare ---
	case MIL_OP_FC:
	case MIL_OP_FCB:
	case MIL_OP_FCBX:
	case MIL_OP_FCR:
	case MIL_OP_EFC:
	case MIL_OP_EFCR:
	case MIL_OP_UCR:
	case MIL_OP_UC:
	case MIL_OP_UCIM: // unsigned compare, immediate
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case MIL_OP_CB:
	case MIL_OP_CBX:
	case MIL_OP_C:
	case MIL_OP_CR:
	case MIL_OP_CIM:
	case MIL_OP_CISP:
	case MIL_OP_CISN:
	case MIL_OP_CBL:
	case MIL_OP_DC:
	case MIL_OP_DCR:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->sign = true;
		break;

	// --- Loads ---
	case MIL_OP_LB:
	case MIL_OP_LBX:
	case MIL_OP_DLB:
	case MIL_OP_DLBX:
	case MIL_OP_L:
	case MIL_OP_LR:
	case MIL_OP_LISP:
	case MIL_OP_LISN:
	case MIL_OP_LI:
	case MIL_OP_LIM:
	case MIL_OP_DL:
	case MIL_OP_DLR:
	case MIL_OP_DLI:
	case MIL_OP_LM:
	case MIL_OP_EFL:
	case MIL_OP_LUB:
	case MIL_OP_LLB:
	case MIL_OP_LUBI:
	case MIL_OP_LLBI:
	case MIL_OP_LE:
	case MIL_OP_DLE:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;

	// --- Stores ---
	case MIL_OP_STB:
	case MIL_OP_STBX:
	case MIL_OP_DSTB:
	case MIL_OP_DSTX:
	case MIL_OP_ST:
	case MIL_OP_STC:
	case MIL_OP_STCI:
	case MIL_OP_STI:
	case MIL_OP_SFBS:
	case MIL_OP_DST:
	case MIL_OP_SRM:
	case MIL_OP_DSTI:
	case MIL_OP_STM:
	case MIL_OP_EFST:
	case MIL_OP_STUB:
	case MIL_OP_STLB:
	case MIL_OP_SUBI:
	case MIL_OP_SLBI:
	case MIL_OP_STE:
	case MIL_OP_DSTE:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;

	// --- Bit set/reset/test ---
	case MIL_OP_SB:
	case MIL_OP_SBR:
	case MIL_OP_SBI:
	case MIL_OP_TSB:
	case MIL_OP_SVBR:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case MIL_OP_RB:
	case MIL_OP_RBR:
	case MIL_OP_RBI:
	case MIL_OP_RVBR:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case MIL_OP_TB:
	case MIL_OP_TBR:
	case MIL_OP_TBI:
	case MIL_OP_TVBR:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	}

	milstd_fill_operands(analysis, op, &insn, mask);
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	ic\n"
		"=SP	r15\n"
		"=BP	r14\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=R0	r0\n"

		"gpr	r0	.16	0	0\n"
		"gpr	r1	.16	2	0\n"
		"gpr	r2	.16	4	0\n"
		"gpr	r3	.16	6	0\n"
		"gpr	r4	.16	8	0\n"
		"gpr	r5	.16	10	0\n"
		"gpr	r6	.16	12	0\n"
		"gpr	r7	.16	14	0\n"
		"gpr	r8	.16	16	0\n"
		"gpr	r9	.16	18	0\n"
		"gpr	r10	.16	20	0\n"
		"gpr	r11	.16	22	0\n"
		"gpr	r12	.16	24	0\n"
		"gpr	r13	.16	26	0\n"
		"gpr	r14	.16	28	0\n"
		"gpr	r15	.16	30	0\n"

		"gpr	ic	.16	32	  0\n"
		"gpr	sw	.16	34	  0\n"
		"gpr	cf	.1	34.0  0\n"
		"gpr	pf	.1	34.1  0\n"
		"gpr	zf	.1	34.2  0\n"
		"gpr	nf	.1	34.3  0\n"
		"gpr	ft	.16	36	  0\n"
		"gpr	mk	.16	38	  0\n"
		"gpr	pi	.16	40	  0\n";

	return rz_str_dup(p);
}

static int archinfo(RzAnalysis *analysis, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 2;
	default:
		return -1;
	}
}

static int address_bits(RzAnalysis *analysis, int bits) {
	return bits == 8 ? 16 : -1;
}

RzAnalysisPlugin rz_analysis_plugin_milstd1750 = {
	.name = "milstd1750",
	.desc = "MIL-STD 1750 ISA analysis plugin",
	.license = "MIT",
	.arch = "milstd1750",
	.bits = 8 | 16,
	.op = &rz_milstd1750_analysis_op,
	.archinfo = archinfo,
	.address_bits = address_bits,
	.get_reg_profile = &get_reg_profile,
	.esil = false
};