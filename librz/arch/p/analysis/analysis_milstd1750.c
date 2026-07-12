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
static int milstd_mem_size(ut8 op8) {
	switch (op8) {
	// extended floating, 48-bit
	case MIL_OP_EFL >> 8:
	case MIL_OP_EFA >> 8:
	case MIL_OP_EFS >> 8:
	case MIL_OP_EFM >> 8:
	case MIL_OP_EFD >> 8:
	case MIL_OP_EFC >> 8:
	case MIL_OP_EFST >> 8:
		return 6;
	// double-precision integer and single floating, 32-bit
	case MIL_OP_DL >> 8:
	case MIL_OP_DLI >> 8:
	case MIL_OP_DLE >> 8:
	case MIL_OP_DST >> 8:
	case MIL_OP_DSTI >> 8:
	case MIL_OP_DSTE >> 8:
	case MIL_OP_DA >> 8:
	case MIL_OP_DS >> 8:
	case MIL_OP_DM >> 8:
	case MIL_OP_DD >> 8:
	case MIL_OP_DC >> 8:
	case MIL_OP_FA >> 8:
	case MIL_OP_FS >> 8:
	case MIL_OP_FM >> 8:
	case MIL_OP_FD >> 8:
	case MIL_OP_FC >> 8:
		return 4;
	// byte operand, 8-bit
	case MIL_OP_LUB >> 8:
	case MIL_OP_LLB >> 8:
	case MIL_OP_LUBI >> 8:
	case MIL_OP_LLBI >> 8:
	case MIL_OP_STUB >> 8:
	case MIL_OP_STLB >> 8:
	case MIL_OP_SUBI >> 8:
	case MIL_OP_SLBI >> 8:
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
static void milstd_set_ptr(RzAnalysisOp *op, const MilStd1750Instruction *insn, ut8 op8) {
	switch (insn->format) {
	case MIL_FMT_MEM:
	case MIL_FMT_IM_0_15:
	case MIL_FMT_IM_1_16:
		break;
	default:
		return; // no direct address field (register/immediate/base-relative)
	}
	if (op8 == 0x85) {
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
	op->ptrsize = milstd_mem_size(op8);
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
static void milstd_set_stack(RzAnalysisOp *op, const MilStd1750Instruction *insn, ut8 op8) {
	switch (op8) {
	// PSHM/POPM transfer the inclusive register range Ra..Rb, wrapping the
	// register selector modulo 16 (so Ra > Rb pushes Ra..R15, R0..Rb). The
	// count is therefore ((Rb - Ra) mod 16) + 1, always 1..16.
	case MIL_OP_PSHM >> 8: { // PSHM Ra, Rb — push registers (SP grows)
		int count = ((insn->rb - insn->ra) & 0xF) + 1;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = count * 2;
		break;
	}
	case MIL_OP_POPM >> 8: { // POPM Ra, Rb — pop registers (SP shrinks)
		int count = ((insn->rb - insn->ra) & 0xF) + 1;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -count * 2;
		break;
	}
	case MIL_OP_SJS >> 8: // SJS — stack the IC and jump (push one word)
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 2;
		break;
	case MIL_OP_URS >> 8: // URS — unstack the IC and return (pop one word)
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
static void milstd_fill_val(RzAnalysis *a, RzAnalysisOp *op, const MilStd1750Instruction *insn, ut8 op8) {
	ut32 type = op->type & RZ_ANALYSIS_OP_TYPE_MASK;
	int sz = milstd_mem_size(op8);

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
		if (op8 == 0x85) { // LIM: the second word is an immediate, not memory
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

static void milstd_fill_operands(RzAnalysis *analysis, RzAnalysisOp *op, const MilStd1750Instruction *insn, ut8 op8, RzAnalysisOpMask mask) {
	milstd_set_stack(op, insn, op8);
	milstd_set_direction(op, insn->format);
	milstd_set_val(op, insn);
	milstd_set_ptr(op, insn, op8);
	milstd_set_datatype(op, insn);
	milstd_set_reg(op, insn);
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		milstd_fill_val(analysis, op, insn, op8);
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

	// B-format opcodes encode the 2-bit BR field in the low bits of the
	// opcode byte; mask off to get the canonical opcode for type lookup.
	ut8 op8 = insn.raw_w1 >> 8;
	if (insn.format == MIL_FMT_B) {
		op8 &= 0xFC;
	}

	// IM-format (0x4A): 4-bit opex selects which immediate op
	if (insn.format == MIL_FMT_IM_OCX && op8 == (MIL_OP_AIM >> 8)) {
		switch (insn.opex) {
		case (MIL_OP_AIM & 0xF):
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			op->sign = true;
			break;
		case (MIL_OP_SIM & 0xF):
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			op->sign = true;
			break;
		case (MIL_OP_MIM & 0xF):
		case (MIL_OP_MSIM & 0xF):
			op->type = RZ_ANALYSIS_OP_TYPE_MUL;
			op->sign = true;
			break;
		case (MIL_OP_DIM & 0xF):
		case (MIL_OP_DVIM & 0xF):
			op->type = RZ_ANALYSIS_OP_TYPE_DIV;
			op->sign = true;
			break;
		case (MIL_OP_ANDM & 0xF): op->type = RZ_ANALYSIS_OP_TYPE_AND; break; // ANDM
		case (MIL_OP_ORIM & 0xF): op->type = RZ_ANALYSIS_OP_TYPE_OR; break; // ORIM
		case (MIL_OP_XORM & 0xF): op->type = RZ_ANALYSIS_OP_TYPE_XOR; break; // XORM
		case (MIL_OP_CIM & 0xF):
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			op->sign = true;
			break;
		case (MIL_OP_NIM & 0xF): op->type = RZ_ANALYSIS_OP_TYPE_NOT; break; // NIM
		}
		milstd_fill_operands(analysis, op, &insn, op8, mask);
		return op->size;
	}

	switch (op8) {
	// --- Special / control flow boundaries ---
	case MIL_OP_NOP >> 8:
		if (insn.raw_w1 == MIL_OP_BPT) {
			op->type = RZ_ANALYSIS_OP_TYPE_TRAP; // BPT
			op->eob = true;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		}
		break;
	case MIL_OP_URS >> 8: // URS — Unstack IC and Return from Subroutine
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		break;

	// --- ICR branches: target = addr + disp*2 (D = signed 8-bit) ---
	case MIL_OP_BR >> 8: // BR — unconditional
		op->cond = RZ_TYPE_COND_AL;
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = icr_target;
		op->eob = true;
		break;
	case MIL_OP_BEZ >> 8: // BEZ — branch if equal zero (Z)
	case MIL_OP_BLT >> 8: // BLT — branch if less than zero (N)
	case MIL_OP_BLE >> 8: // BLE — branch if less or equal zero (N|Z)
	case MIL_OP_BGT >> 8: // BGT — branch if greater than zero (P)
	case MIL_OP_BNZ >> 8: // BNZ — branch if not zero (P|N)
	case MIL_OP_BGE >> 8: // BGE — branch if greater or equal zero (P|Z)
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		switch (op8) {
		case MIL_OP_BEZ >> 8: op->cond = RZ_TYPE_COND_EQ; break;
		case MIL_OP_BLT >> 8: op->cond = RZ_TYPE_COND_LT; break;
		case MIL_OP_BLE >> 8: op->cond = RZ_TYPE_COND_LE; break;
		case MIL_OP_BGT >> 8: op->cond = RZ_TYPE_COND_GT; break;
		case MIL_OP_BNZ >> 8: op->cond = RZ_TYPE_COND_NE; break;
		case MIL_OP_BGE >> 8: op->cond = RZ_TYPE_COND_GE; break;
		}
		op->jump = icr_target;
		op->fail = next_pc;
		break;

	// --- Memory-format jumps: target word in w2 → byte = w2*2 ---
	case MIL_OP_JC >> 8: // JC C, LABEL — Jump on Condition (direct)
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
	case MIL_OP_JCI >> 8: // JCI C, ADDR — Jump on Condition (indirect)
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
	case MIL_OP_JS >> 8: // JS — Jump to Subroutine (return addr in RA)
	case MIL_OP_SJS >> 8: // SJS — Stack IC and Jump to Subroutine
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = abs_target;
		op->fail = next_pc;
		break;
	case MIL_OP_SOJ >> 8: // SOJ — Subtract One and Jump (taken while RA != 0)
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->cond = RZ_TYPE_COND_NE;
		op->jump = abs_target;
		op->fail = next_pc;
		break;
	case MIL_OP_BEX >> 8: // BEX N — Branch to Executive (interrupt-vectored)
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		op->eob = true;
		break;
	case MIL_OP_BIF >> 8: // BIF — Branch on Input Flag (target unknown statically)
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->fail = next_pc;
		break;

	// --- LST/LSTI: load (MK,SW,IC) from memory; unconditional indirect jump ---
	case MIL_OP_LSTI >> 8: // LSTI ADDR — indirect load status (also reloads IC)
	case MIL_OP_LST >> 8: // LST ADDR — direct load status (also reloads IC)
		op->type = RZ_ANALYSIS_OP_TYPE_MJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		op->eob = true;
		break;

	// --- I/O ---
	case MIL_OP_XIO >> 8:
	case MIL_OP_VIO >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->family = RZ_ANALYSIS_OP_FAMILY_IO;
		break;

	// --- Stack ---
	case MIL_OP_POPM >> 8: op->type = RZ_ANALYSIS_OP_TYPE_POP; break; // POPM
	case MIL_OP_PSHM >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// --- Move / exchange ---
	case MIL_OP_MOV >> 8:
	case MIL_OP_XBR >> 8:
	case MIL_OP_XWR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// --- Add ---
	case MIL_OP_FA >> 8:
	case MIL_OP_FAR >> 8:
	case MIL_OP_EFA >> 8:
	case MIL_OP_EFAR >> 8:
	case MIL_OP_FABS >> 8:
	case MIL_OP_UAR >> 8:
	case MIL_OP_UA >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case MIL_OP_AB >> 8:
	case MIL_OP_A >> 8:
	case MIL_OP_AR >> 8:
	case MIL_OP_AISP >> 8:
	case MIL_OP_INCM >> 8:
	case MIL_OP_ABS >> 8:
	case MIL_OP_DA >> 8:
	case MIL_OP_DAR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->sign = true;
		break;

	// --- Sub ---
	case MIL_OP_FS >> 8:
	case MIL_OP_FSR >> 8:
	case MIL_OP_EFS >> 8:
	case MIL_OP_EFSR >> 8:
	case MIL_OP_FNEG >> 8:
	case MIL_OP_USR >> 8:
	case MIL_OP_US >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case MIL_OP_SBB >> 8:
	case MIL_OP_S >> 8:
	case MIL_OP_SR >> 8:
	case MIL_OP_SISP >> 8:
	case MIL_OP_DECM >> 8:
	case MIL_OP_NEG >> 8:
	case MIL_OP_DNEG >> 8:
	case MIL_OP_DS >> 8:
	case MIL_OP_DSR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->sign = true;
		break;

	// --- Mul ---
	case MIL_OP_FM >> 8:
	case MIL_OP_FMR >> 8:
	case MIL_OP_EFM >> 8:
	case MIL_OP_EFMR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case MIL_OP_MB >> 8:
	case MIL_OP_MS >> 8:
	case MIL_OP_MSR >> 8:
	case MIL_OP_MISP >> 8:
	case MIL_OP_MISN >> 8:
	case MIL_OP_M >> 8:
	case MIL_OP_MR >> 8:
	case MIL_OP_DM >> 8:
	case MIL_OP_DMR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->sign = true;
		break;

	// --- Div ---
	case MIL_OP_FD >> 8:
	case MIL_OP_FDR >> 8:
	case MIL_OP_EFD >> 8:
	case MIL_OP_EFDR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case MIL_OP_DB >> 8:
	case MIL_OP_DV >> 8:
	case MIL_OP_DVR >> 8:
	case MIL_OP_DISP >> 8:
	case MIL_OP_DISN >> 8:
	case MIL_OP_D >> 8:
	case MIL_OP_DR >> 8:
	case MIL_OP_DD >> 8:
	case MIL_OP_DDR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		op->sign = true;
		break;

	// --- Logical ---
	case MIL_OP_ANDB >> 8:
	case MIL_OP_AND >> 8:
	case MIL_OP_ANDR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case MIL_OP_ORB >> 8:
	case MIL_OP_OR >> 8:
	case MIL_OP_ORR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case MIL_OP_XOR >> 8:
	case MIL_OP_XORR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case MIL_OP_N >> 8:
	case MIL_OP_NR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;

	// --- Shifts ---
	case MIL_OP_SLL >> 8:
	case MIL_OP_SLC >> 8:
	case MIL_OP_DSLL >> 8:
	case MIL_OP_DSLC >> 8:
	case MIL_OP_SLR >> 8:
	case MIL_OP_DSLR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case MIL_OP_SRL >> 8:
	case MIL_OP_DSRL >> 8:
	case MIL_OP_SCR >> 8:
	case MIL_OP_DSCR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case MIL_OP_SRA >> 8:
	case MIL_OP_DSRA >> 8:
	case MIL_OP_SAR >> 8:
	case MIL_OP_DSAR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		op->sign = true;
		break;

	// --- Compare ---
	case MIL_OP_FC >> 8:
	case MIL_OP_FCR >> 8:
	case MIL_OP_EFC >> 8:
	case MIL_OP_EFCR >> 8:
	case MIL_OP_UCR >> 8:
	case MIL_OP_UC >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case MIL_OP_CB >> 8:
	case MIL_OP_C >> 8:
	case MIL_OP_CR >> 8:
	case MIL_OP_CISP >> 8:
	case MIL_OP_CISN >> 8:
	case MIL_OP_CBL >> 8:
	case MIL_OP_DC >> 8:
	case MIL_OP_DCR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->sign = true;
		break;

	// --- Loads ---
	case MIL_OP_LB >> 8:
	case MIL_OP_DLB >> 8:
	case MIL_OP_L >> 8:
	case MIL_OP_LR >> 8:
	case MIL_OP_LISP >> 8:
	case MIL_OP_LISN >> 8:
	case MIL_OP_LI >> 8:
	case MIL_OP_LIM >> 8:
	case MIL_OP_DL >> 8:
	case MIL_OP_DLR >> 8:
	case MIL_OP_DLI >> 8:
	case MIL_OP_LM >> 8:
	case MIL_OP_EFL >> 8:
	case MIL_OP_LUB >> 8:
	case MIL_OP_LLB >> 8:
	case MIL_OP_LUBI >> 8:
	case MIL_OP_LLBI >> 8:
	case MIL_OP_LE >> 8:
	case MIL_OP_DLE >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;

	// --- Stores ---
	case MIL_OP_STB >> 8:
	case MIL_OP_DSTB >> 8:
	case MIL_OP_ST >> 8:
	case MIL_OP_STC >> 8:
	case MIL_OP_STCI >> 8:
	case MIL_OP_STI >> 8:
	case MIL_OP_SFBS >> 8:
	case MIL_OP_DST >> 8:
	case MIL_OP_SRM >> 8:
	case MIL_OP_DSTI >> 8:
	case MIL_OP_STM >> 8:
	case MIL_OP_EFST >> 8:
	case MIL_OP_STUB >> 8:
	case MIL_OP_STLB >> 8:
	case MIL_OP_SUBI >> 8:
	case MIL_OP_SLBI >> 8:
	case MIL_OP_STE >> 8:
	case MIL_OP_DSTE >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;

	// --- Bit set/reset/test ---
	case MIL_OP_SB >> 8:
	case MIL_OP_SBR >> 8:
	case MIL_OP_SBI >> 8:
	case MIL_OP_TSB >> 8:
	case MIL_OP_SVBR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case MIL_OP_RB >> 8:
	case MIL_OP_RBR >> 8:
	case MIL_OP_RBI >> 8:
	case MIL_OP_RVBR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case MIL_OP_TB >> 8:
	case MIL_OP_TBR >> 8:
	case MIL_OP_TBI >> 8:
	case MIL_OP_TVBR >> 8:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	}

	milstd_fill_operands(analysis, op, &insn, op8, mask);
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