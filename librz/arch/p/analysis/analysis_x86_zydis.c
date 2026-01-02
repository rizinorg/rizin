// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText : 2024-2025 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_lib.h>

#if USE_SYS_ZYDIS
#include <Zydis/Zydis.h>
#else
#include <Zydis.h>
#endif

#include <x86/x86_il.h>
#include <x86/x86_mnemonics.h>

// CYCLES:
// ======
// register access = 1
// memory access = 2
// jump = 3
// call = 4

#define CYCLE_REG 0
#define CYCLE_MEM 1
#define CYCLE_JMP 2

#define BUF_SZ 64
#define AR_DIM 4

#define SRC_AR    0
#define DST_AR    1
#define DST_R_AR  1
#define DST_W_AR  2
#define SRC2_AR   2
#define DST2_AR   2
#define DSTADD_AR 3
#define ARG0_AR   0
#define ARG1_AR   1
#define ARG2_AR   2

#define INSOP(n) zydx->zydeop[n]
#define INSOPS   zydx->zydecode->operand_count_visible
#define ISIMM(n) zydx->zydeop[n].type == X86_OP_IMM
#define ISMEM(n) zydx->zydeop[n].type == X86_OP_MEM

typedef struct zydis_x86_context_t {
	char buf[AR_DIM][BUF_SZ];
	ZydisMachineMode omode;
	ZydisDecodedInstruction *zydecode;
	ZydisDecodedOperand *zydeop;
	ut64 addr;
} X86ZYDISContext;

struct Getarg {
	ZydisDecodedInstruction *zydecode;
	ZydisDecodedOperand *zydeop;
	size_t bits;
};

static inline ut64 get_imm_reg_value(ZydisDecodedOperand *zydeop, ut64 addr, ut64 op_size, int bitness) {
	ut64 value = (zydeop->imm.is_relative ? (zydeop->imm.value.s + addr + op_size) : zydeop->imm.value.u);
	ut32 exponent = zydeop->size * 8;
	if (exponent < 64) {
		value &= ((1ull << exponent) - 1);
	}
	return value;
}

static void hidden_op(const X86ZYDISContext *zydx, int mode) {
	unsigned int mnemonic = zydx->zydecode->mnemonic;
	size_t regsz = 4;
	switch (mode) {
	case ZYDIS_MACHINE_MODE_LONG_64:
		regsz = 8;
		break;
	case ZYDIS_MACHINE_MODE_LONG_COMPAT_16:
		regsz = 2;
		break;
	default:
		regsz = 4; // 32 bit
		break;
	}

	switch (mnemonic) {
	case X86_INS_PUSHF:
	case X86_INS_POPF:
	case X86_INS_PUSHFD:
	case X86_INS_POPFD:
	case X86_INS_PUSHFQ:
	case X86_INS_POPFQ:
		zydx->zydecode->operand_count_visible = 1;
		ZydisDecodedOperand *op = &INSOP(0);
		op->type = X86_OP_REG;
		op->reg.value = X86_REG_EFLAGS;
		op->size = regsz;
		if (mnemonic == X86_INS_PUSHF || mnemonic == X86_INS_PUSHFD || mnemonic == X86_INS_PUSHFQ) {
			op->actions = 1;
		} else {
			op->actions = 2;
		}
		break;
	default:
		break;
	}
}

static RzStructuredData *x86_opex(const X86ZYDISContext *zydx, int mode, int bitness) {
	ZydisDecodedInstruction *zydecode = zydx->zydecode;
	if (zydecode->operand_count_visible == 0) {
		hidden_op(zydx, mode);
	}

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	RzStructuredData *opex = rz_structured_data_map_add_map(root, "opex");
	if (!opex) {
		rz_structured_data_free(root);
		return NULL;
	}

	RzStructuredData *operands = rz_structured_data_map_add_array(opex, "operands");
	for (size_t i = 0; i < zydecode->operand_count_visible; i++) {
		ZydisDecodedOperand *op = &INSOP(i);
		RzStructuredData *operand = rz_structured_data_array_add_map(operands);
		switch (op->type) {
		case X86_OP_REG:
			rz_structured_data_map_add_string(operand, "type", "reg");
			rz_structured_data_map_add_string(operand, "value", ZydisRegisterGetString(op->reg.value));
			break;
		case X86_OP_IMM:
			rz_structured_data_map_add_string(operand, "type", "imm");
			rz_structured_data_map_add_signed(operand, "value", get_imm_reg_value(op, zydx->addr, zydx->zydecode->length, bitness));
			break;
		case X86_OP_MEM:
			rz_structured_data_map_add_string(operand, "type", "mem");
			if (op->mem.segment != X86_REG_NONE) {
				rz_structured_data_map_add_string(operand, "segment", ZydisRegisterGetString(op->mem.segment));
			}
			if (op->mem.base != X86_REG_NONE) {
				rz_structured_data_map_add_string(operand, "base", ZydisRegisterGetString(op->mem.base));
			}
			if (op->mem.index != X86_REG_NONE) {
				rz_structured_data_map_add_string(operand, "index", ZydisRegisterGetString(op->mem.index));
			}
			rz_structured_data_map_add_signed(operand, "scale", op->mem.scale);
			rz_structured_data_map_add_signed(operand, "disp", op->mem.disp.value);
			break;
		default:
			rz_structured_data_map_add_string(operand, "type", "invalid");
			break;
		}
		if (op->actions & ZYDIS_OPERAND_ACTION_READ) {
			rz_structured_data_map_add_boolean(operand, "read", true);
		}
		if (op->actions & ZYDIS_OPERAND_ACTION_WRITE) {
			rz_structured_data_map_add_boolean(operand, "write", true);
		}
		if (op->actions & ZYDIS_OPERAND_ACTION_CONDREAD) {
			rz_structured_data_map_add_boolean(operand, "cond_read", true);
		}
		if (op->actions & ZYDIS_OPERAND_ACTION_CONDWRITE) {
			rz_structured_data_map_add_boolean(operand, "cond_write", true);
		}
		rz_structured_data_map_add_unsigned(operand, "nbits", op->size * 8, false);
	}

	if (zydecode->attributes & ZYDIS_ATTRIB_HAS_REX) {
		rz_structured_data_map_add_boolean(opex, "rex", true);
	}
	if (zydecode->raw.modrm.mod != 0) {
		rz_structured_data_map_add_boolean(opex, "modrm", true);
	}
	if (zydecode->raw.sib.scale != 0 || zydecode->raw.sib.index != 0 || zydecode->raw.sib.offset != 0 || zydecode->raw.sib.base != 0) {
		rz_structured_data_map_add_signed(opex, "sib", zydecode->raw.sib.base + (zydecode->raw.sib.index * zydecode->raw.sib.scale) + zydecode->raw.sib.offset);
	}
	if (zydecode->raw.disp.value != 0) {
		rz_structured_data_map_add_signed(opex, "disp", zydecode->raw.disp.value);
	}
	if (zydecode->raw.sib.index != X86_REG_NONE) {
		rz_structured_data_map_add_signed(opex, "sib_scale", zydecode->raw.sib.scale);
		rz_structured_data_map_add_string(opex, "sib_index", ZydisRegisterGetString(zydecode->raw.sib.index));
	}
	if (zydecode->raw.sib.base != X86_REG_NONE) {
		rz_structured_data_map_add_string(opex, "sib_base", ZydisRegisterGetString(zydecode->raw.sib.base));
	}

	return root;
}

static bool is_xmm_reg(const ZydisDecodedOperand op) {
	switch (op.reg.value) {
	case X86_REG_XMM0:
	case X86_REG_XMM1:
	case X86_REG_XMM2:
	case X86_REG_XMM3:
	case X86_REG_XMM4:
	case X86_REG_XMM5:
	case X86_REG_XMM6:
	case X86_REG_XMM7:
	case X86_REG_XMM8:
	case X86_REG_XMM9:
	case X86_REG_XMM10:
	case X86_REG_XMM11:
	case X86_REG_XMM12:
	case X86_REG_XMM13:
	case X86_REG_XMM14:
	case X86_REG_XMM15:
	case X86_REG_XMM16:
	case X86_REG_XMM17:
	case X86_REG_XMM18:
	case X86_REG_XMM19:
	case X86_REG_XMM20:
	case X86_REG_XMM21:
	case X86_REG_XMM22:
	case X86_REG_XMM23:
	case X86_REG_XMM24:
	case X86_REG_XMM25:
	case X86_REG_XMM26:
	case X86_REG_XMM27:
	case X86_REG_XMM28:
	case X86_REG_XMM29:
	case X86_REG_XMM30:
	case X86_REG_XMM31: return true;
	default: return false;
	}
}

/**
 * Translates operand N to esil
 *
 * \param  Getarg  Structure with Instruction & Operands
 * \param  n       Operand index
 * \param  set     if 1 it adds set (=) to the operand
 * \param  setop   Extra operation for the set (^, -, +, etc...)
 * \param  sel     Selector for output buffer in staic array
 * \param  bitsize Size of operand in bits
 * \param  addr	   pc value
 * \return         Pointer to esil operand in static array
 */
static RZ_OWN RZ_BORROW char *getarg(RzAnalysis *a, struct Getarg *gop, size_t n, size_t set, char *setop, size_t sel, RZ_OUT ut32 *bitsize, ut64 addr) {
	X86ZYDISContext *zydx = (X86ZYDISContext *)a->plugin_data;
	char *out = zydx->buf[sel];
	char *setarg = setop ? setop : "";
	ZydisDecodedInstruction *zydecode = gop->zydecode;
	ZydisDecodedOperand *zydeop = gop->zydeop;
	if (!zydecode) {
		return NULL;
	}
	if (n < 0 || n >= zydecode->operand_count_visible) {
		return NULL;
	}
	out[0] = 0;
	ZydisDecodedOperand op = zydeop[n];
	if (bitsize) {
		*bitsize = op.size * 8;
	}
	switch (op.type) {
	case X86_REG_NONE:
		return "invalid";
	case X86_OP_REG:
		if (set == 1) {
			rz_strf(zydx->buf[sel], "%s,%s=", ZydisRegisterGetString(op.reg.value), setarg);
			return out;
		}
		return (char *)ZydisRegisterGetString(op.reg.value);
	case X86_OP_IMM: {
		if (set == 1) {
			rz_strf(zydx->buf[sel], "%" PFMT64u ",%s=[%" PFMT32d "]", get_imm_reg_value(&op, addr, zydx->zydecode->length, a->bits), setarg, op.size);
			return out;
		}
		rz_strf(zydx->buf[sel], "%" PFMT64u, get_imm_reg_value(&op, addr, zydx->zydecode->length, a->bits));
		return out;
	default: break;
	}
	case X86_OP_MEM: {
		char mem_op_esil[BUF_SZ] = { 0 };
		size_t component_count = 0;
		const char *base = ZydisRegisterGetString(op.mem.base);
		const char *index = ZydisRegisterGetString(op.mem.index);
		int scale = op.mem.scale;
		st64 disp = op.mem.disp.value;

		if (disp != 0) {
			rz_strf(zydx->buf[sel], "0x%" PFMT64x ",", rz_num_abs(disp));
			component_count++;
		}

		if (!RZ_STR_EQ("none", index)) {
			if (scale > 1) {
				rz_strf(mem_op_esil, "%s%s,%" PFMT32d ",*,", out, index, scale);
			} else {
				rz_strf(mem_op_esil, "%s%s,", out, index);
			}
			rz_str_ncpy(out, mem_op_esil, BUF_SZ);
			component_count++;
		}

		if (!RZ_STR_EQ("none", base)) {
			rz_strf(mem_op_esil, "%s%s,", out, base);
			rz_str_ncpy(out, mem_op_esil, BUF_SZ);
			component_count++;
		}

		if (component_count > 1) {
			if (component_count > 2) {
				rz_strf(mem_op_esil, "%s+,", out);
				rz_str_ncpy(out, mem_op_esil, BUF_SZ);
			}
			if (disp < 0) {
				rz_strf(mem_op_esil, "%s-", out);
			} else {
				rz_strf(mem_op_esil, "%s+", out);
			}
			rz_str_ncpy(out, mem_op_esil, BUF_SZ);
		} else {
			// Remove the trailing ',' from esil statement.
			if (*out) {
				char *p = (char *)rz_str_rchr(out, NULL, ',');
				if (p) {
					*p = 0;
				}
			}
		}

		// set = 2 is reserved for lea, where the operand is a memory address,
		// but the corresponding memory is not loaded.
		if (set == 1) {
			rz_strf(mem_op_esil, "%s,%s=[%" PFMT32d "]", out, setarg, op.size == 10 ? 8 : op.size);
			rz_str_ncpy(out, mem_op_esil, BUF_SZ);
		} else if (set == 0) {
			if (!*out) {
				strcpy(out, "0");
			}
			rz_strf(mem_op_esil, "%s,[%" PFMT32d "]", out, op.size == 10 ? 8 : op.size);
			rz_str_ncpy(out, mem_op_esil, BUF_SZ);
		}
		out[BUF_SZ - 1] = 0;
		return out;
	}
	case X86_OP_PTR: {
		if (sel == ARG0_AR) {
			rz_strf(zydx->buf[sel], "%" PFMT32d "", (int)(op.ptr.segment));
		} else if (sel == ARG1_AR) {
			rz_strf(zydx->buf[sel], "%" PFMT32d "", (int)(op.ptr.offset));
		}
		return out;
	}
	}
	return NULL;
}

static int cond_x862r2(ZydisMnemonic mnemonic) {
	switch (mnemonic) {
	case X86_INS_JE:
		return RZ_TYPE_COND_EQ;
	case X86_INS_JNE:
		return RZ_TYPE_COND_NE;
	case X86_INS_JB:
	case X86_INS_JL:
		return RZ_TYPE_COND_LT;
	case X86_INS_JBE:
	case X86_INS_JLE:
		return RZ_TYPE_COND_LE;
	case X86_INS_JG:
	case X86_INS_JA:
		return RZ_TYPE_COND_GT;
	case X86_INS_JAE:
		return RZ_TYPE_COND_GE;
	case X86_INS_JS:
	case X86_INS_JNS:
	case X86_INS_JO:
	case X86_INS_JNO:
	case X86_INS_JGE:
	case X86_INS_JP:
	case X86_INS_JNP:
	case X86_INS_JCXZ:
	case X86_INS_JECXZ:
	default:
		break;
	}
	return 0;
}

/* reg indices are based on Intel doc for 32-bit ModR/M byte */
static const char *reg32_to_name(ut8 reg) {
	const char *const names[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
	return reg < RZ_ARRAY_SIZE(names) ? names[reg] : "unk";
}

static void anop_esil(RzAnalysis *a, RzAnalysisOp *op, const ut8 *buf, int len, X86ZYDISContext *zydx) {
	int rs = a->bits / 8;
	const char *pc = (a->bits == 16) ? "ip" : (a->bits == 32) ? "eip"
								  : "rip";
	const char *sp = (a->bits == 16) ? "sp" : (a->bits == 32) ? "esp"
								  : "rsp";
	const char *bp = (a->bits == 16) ? "bp" : (a->bits == 32) ? "ebp"
								  : "rbp";
	const char *si = (a->bits == 16) ? "si" : (a->bits == 32) ? "esi"
								  : "rsi";
	struct Getarg gop = {
		.zydecode = zydx->zydecode,
		.zydeop = zydx->zydeop,
		.bits = a->bits
	};
	const char *src = NULL;
	const char *src2 = NULL;
	const char *dst = NULL;
	const char *dst2 = NULL;
	const char *dst_r = NULL;
	const char *dst_w = NULL;
	const char *dstAdd = NULL;
	const char *arg0 = NULL;
	const char *arg1 = NULL;
	const char *arg2 = NULL;

	// counter for rep prefix
	const char *counter = (a->bits == 16) ? "cx" : (a->bits == 32) ? "ecx"
								       : "rcx";

	if (op->prefix & RZ_ANALYSIS_OP_PREFIX_REP) {
		esilprintf(op, "%s,!,?{,BREAK,},", counter);
	}

	switch (zydx->zydecode->mnemonic) {
	case X86_INS_FNOP:
	case X86_INS_NOP:
	case X86_INS_PAUSE:
		esilprintf(op, ",");
		break;
	case X86_INS_HLT:
		break;
	case X86_INS_FBLD:
	case X86_INS_FBSTP:
	case X86_INS_FCOMPP:
	case X86_INS_FDECSTP:
	case X86_INS_FEMMS:
	case X86_INS_FFREE:
	case X86_INS_FICOM:
	case X86_INS_FICOMP:
	case X86_INS_FINCSTP:
	case X86_INS_FNCLEX:
	case X86_INS_FNINIT:
	case X86_INS_FNSTCW:
	case X86_INS_FNSTSW:
	case X86_INS_FPATAN:
	case X86_INS_FPREM:
	case X86_INS_FPREM1:
	case X86_INS_FPTAN:
	case X86_INS_FFREEP:
	case X86_INS_FRNDINT:
	case X86_INS_FRSTOR:
	case X86_INS_FNSAVE:
	case X86_INS_FSCALE:
	case X86_INS_FSETPM287_NOP:
	case X86_INS_FSINCOS:
	case X86_INS_FNSTENV:
	case X86_INS_FXAM:
	case X86_INS_FXSAVE:
	case X86_INS_FXSAVE64:
	case X86_INS_FXTRACT:
	case X86_INS_FYL2X:
	case X86_INS_FYL2XP1:
	case X86_INS_FISTTP:
	case X86_INS_FSQRT:
	case X86_INS_FXCH:
		break;
	case X86_INS_FTST:
	case X86_INS_FUCOMI:
	case X86_INS_FUCOMPP:
	case X86_INS_FUCOMP:
	case X86_INS_FUCOM:
		break;
	case X86_INS_FABS:
		break;
	case X86_INS_FLDCW:
	case X86_INS_FLDENV:
	case X86_INS_FLDL2E:
	case X86_INS_FLDL2T:
	case X86_INS_FLDLG2:
	case X86_INS_FLDLN2:
	case X86_INS_FLDPI:
	case X86_INS_FLDZ:
	case X86_INS_FLD1:
	case X86_INS_FLD:
		break;
	case X86_INS_FIST:
	case X86_INS_FISTP:
	case X86_INS_FST:
	case X86_INS_FSTP:
	case X86_INS_FSTPNCE:
	case X86_INS_FXRSTOR:
	case X86_INS_FXRSTOR64:
		break;
	case X86_INS_FIDIV:
	case X86_INS_FIDIVR:
	case X86_INS_FDIV:
	case X86_INS_FDIVP:
	case X86_INS_FDIVR:
	case X86_INS_FDIVRP:
		break;
	case X86_INS_FSUBR:
	case X86_INS_FISUBR:
	case X86_INS_FSUBRP:
	case X86_INS_FSUB:
	case X86_INS_FISUB:
	case X86_INS_FSUBP:
		break;
	case X86_INS_FMUL:
	case X86_INS_FIMUL:
	case X86_INS_FMULP:
		break;
	case X86_INS_CLI:
		esilprintf(op, "0,if,:=");
		break;
	case X86_INS_STI:
		esilprintf(op, "1,if,:=");
		break;
	case X86_INS_CLC:
		esilprintf(op, "0,cf,:=");
		break;
	case X86_INS_CMC:
		esilprintf(op, "cf,!,cf,=");
		break;
	case X86_INS_STC:
		esilprintf(op, "1,cf,:=");
		break;
	case X86_INS_CLAC:
	case X86_INS_CLGI:
	case X86_INS_CLTS:
	case X86_INS_CLWB:
	case X86_INS_STAC:
	case X86_INS_STGI:
		break;
	// cmov
	case X86_INS_SETNZ:
	case X86_INS_SETNO:
	case X86_INS_SETNP:
	case X86_INS_SETNS:
	case X86_INS_SETO:
	case X86_INS_SETP:
	case X86_INS_SETS:
	case X86_INS_SETL:
	case X86_INS_SETLE:
	case X86_INS_SETB:
	case X86_INS_SETNLE:
	case X86_INS_SETNB:
	case X86_INS_SETNBE:
	case X86_INS_SETBE:
	case X86_INS_SETZ:
	case X86_INS_SETNL: {
		dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, zydx->addr);
		switch (zydx->zydecode->mnemonic) {
		case X86_INS_SETZ: esilprintf(op, "zf,%s", dst); break;
		case X86_INS_SETNZ: esilprintf(op, "zf,!,%s", dst); break;
		case X86_INS_SETO: esilprintf(op, "of,%s", dst); break;
		case X86_INS_SETNO: esilprintf(op, "of,!,%s", dst); break;
		case X86_INS_SETP: esilprintf(op, "pf,%s", dst); break;
		case X86_INS_SETNP: esilprintf(op, "pf,!,%s", dst); break;
		case X86_INS_SETS: esilprintf(op, "sf,%s", dst); break;
		case X86_INS_SETNS: esilprintf(op, "sf,!,%s", dst); break;
		case X86_INS_SETB: esilprintf(op, "cf,%s", dst); break;
		case X86_INS_SETNB: esilprintf(op, "cf,!,%s", dst); break;
		case X86_INS_SETL: esilprintf(op, "sf,of,^,%s", dst); break;
		case X86_INS_SETLE: esilprintf(op, "zf,sf,of,^,|,%s", dst); break;
		case X86_INS_SETNLE: esilprintf(op, "zf,!,sf,of,^,!,&,%s", dst); break;
		case X86_INS_SETNL: esilprintf(op, "sf,of,^,!,%s", dst); break;
		case X86_INS_SETNBE: esilprintf(op, "cf,zf,|,!,%s", dst); break;
		case X86_INS_SETBE: esilprintf(op, "cf,zf,|,%s", dst); break;
		default: break;
		}
	} break;
	// cmov
	case X86_INS_FCMOVBE:
	case X86_INS_FCMOVB:
	case X86_INS_FCMOVNBE:
	case X86_INS_FCMOVNB:
	case X86_INS_FCMOVE:
	case X86_INS_FCMOVNE:
	case X86_INS_FCMOVNU:
	case X86_INS_FCMOVU:
		break;
	case X86_INS_CMOVNBE:
	case X86_INS_CMOVNB:
	case X86_INS_CMOVB:
	case X86_INS_CMOVBE:
	case X86_INS_CMOVZ:
	case X86_INS_CMOVNLE:
	case X86_INS_CMOVNL:
	case X86_INS_CMOVL:
	case X86_INS_CMOVLE:
	case X86_INS_CMOVNZ:
	case X86_INS_CMOVNO:
	case X86_INS_CMOVNP:
	case X86_INS_CMOVNS:
	case X86_INS_CMOVO:
	case X86_INS_CMOVP:
	case X86_INS_CMOVS: {
		const char *conditional = NULL;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, zydx->addr);
		switch (zydx->zydecode->mnemonic) {
		case X86_INS_CMOVNBE:
			// mov if CF = 0 *AND* ZF = 0
			conditional = "cf,zf,|,!";
			break;
		case X86_INS_CMOVNB:
			// mov if CF = 0
			conditional = "cf,!";
			break;
		case X86_INS_CMOVB:
			// mov if CF = 1
			conditional = "cf";
			break;
		case X86_INS_CMOVBE:
			// mov if CF = 1 *OR* ZF = 1
			conditional = "cf,zf,|";
			break;
		case X86_INS_CMOVZ:
			// mov if ZF = 1
			conditional = "zf";
			break;
		case X86_INS_CMOVNLE:
			// mov if ZF = 0 *AND* SF = OF
			conditional = "zf,!,sf,of,^,!,&";
			break;
		case X86_INS_CMOVNL:
			// mov if SF = OF
			conditional = "sf,of,^,!";
			break;
		case X86_INS_CMOVL:
			// mov if SF != OF
			conditional = "sf,of,^";
			break;
		case X86_INS_CMOVLE:
			// mov if ZF = 1 *OR* SF != OF
			conditional = "zf,sf,of,^,|";
			break;
		case X86_INS_CMOVNZ:
			// mov if ZF = 0
			conditional = "zf,!";
			break;
		case X86_INS_CMOVNO:
			// mov if OF = 0
			conditional = "of,!";
			break;
		case X86_INS_CMOVNP:
			// mov if PF = 0
			conditional = "pf,!";
			break;
		case X86_INS_CMOVNS:
			// mov if SF = 0
			conditional = "sf,!";
			break;
		case X86_INS_CMOVO:
			// mov if OF = 1
			conditional = "of";
			break;
		case X86_INS_CMOVP:
			// mov if PF = 1
			conditional = "pf";
			break;
		case X86_INS_CMOVS:
			// mov if SF = 1
			conditional = "sf";
			break;
		default: break;
		}
		if (src && dst && conditional) {
			esilprintf(op, "%s,?{,%s,%s,}", conditional, src, dst);
		}
	} break;
	case X86_INS_STOSB:
		if (a->bits < 32) {
			rz_strbuf_appendf(&op->esil, "al,di,=[1],df,?{,1,di,-=,},df,!,?{,1,di,+=,}");
		} else {
			rz_strbuf_appendf(&op->esil, "al,edi,=[1],df,?{,1,edi,-=,},df,!,?{,1,edi,+=,}");
		}
		break;
	case X86_INS_STOSW:
		if (a->bits < 32) {
			rz_strbuf_appendf(&op->esil, "ax,di,=[2],df,?{,2,di,-=,},df,!,?{,2,di,+=,}");
		} else {
			rz_strbuf_appendf(&op->esil, "ax,edi,=[2],df,?{,2,edi,-=,},df,!,?{,2,edi,+=,}");
		}
		break;
	case X86_INS_STOSD:
		rz_strbuf_appendf(&op->esil, "eax,edi,=[4],df,?{,4,edi,-=,},df,!,?{,4,edi,+=,}");
		break;
	case X86_INS_STOSQ:
		rz_strbuf_appendf(&op->esil, "rax,rdi,=[8],df,?{,8,edi,-=,},df,!,?{,8,edi,+=,}");
		break;
	case X86_INS_LODSB:
		rz_strbuf_appendf(&op->esil, "%s,[1],al,=,df,?{,1,%s,-=,},df,!,?{,1,%s,+=,}", si, si, si);
		break;
	case X86_INS_LODSW:
		rz_strbuf_appendf(&op->esil, "%s,[2],ax,=,df,?{,2,%s,-=,},df,!,?{,2,%s,+=,}", si, si, si);
		break;
	case X86_INS_LODSD:
		rz_strbuf_appendf(&op->esil, "esi,[4],eax,=,df,?{,4,esi,-=,},df,!,?{,4,esi,+=,}");
		break;
	case X86_INS_LODSQ:
		rz_strbuf_appendf(&op->esil, "rsi,[8],rax,=,df,?{,8,rsi,-=,},df,!,?{,8,rsi,+=,}");
		break;
	case X86_INS_PEXTRB:
		rz_strbuf_appendf(&op->esil, "TODO");
		break;
	// string mov
	// PS: MOVSD can correspond to one of the two instruction (yes, intel x86
	// has the same pneumonic for two different opcodes!). We can decide which
	// of the two it is based on the operands.
	// For more information, see:
	// https://mudongliang.github.io/x86/html/file_module_x86_id_203.html
	//               (vs)
	// https://mudongliang.github.io/x86/html/file_module_x86_id_204.html
	case X86_INS_MOVSD:
		// Handle "Move Scalar Double-Precision Floating-Point Value"
		if (is_xmm_reg(INSOP(0)) || is_xmm_reg(INSOP(1))) {
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, zydx->addr);
			if (src && dst) {
				esilprintf(op, "%s,%s", src, dst);
			}
			break;
		}
		// fallthrough
	case X86_INS_MOVSB:
	case X86_INS_MOVSQ:
	case X86_INS_MOVSW:
		if (op->prefix & RZ_ANALYSIS_OP_PREFIX_REP) {
			int width = INSOP(0).size;
			src = ZydisRegisterGetString(INSOP(1).mem.base);
			dst = ZydisRegisterGetString(INSOP(0).mem.base);
			rz_strbuf_appendf(&op->esil,
				"%s,[%" PFMT32d "],%s,=[%" PFMT32d "],"
				"df,?{,%" PFMT32d ",%s,-=,%" PFMT32d ",%s,-=,},"
				"df,!,?{,%" PFMT32d ",%s,+=,%" PFMT32d ",%s,+=,}",
				src, width, dst, width,
				width, src, width, dst,
				width, src, width, dst);
		} else {
			int width = INSOP(0).size;
			src = ZydisRegisterGetString(INSOP(1).mem.base);
			dst = ZydisRegisterGetString(INSOP(0).mem.base);
			esilprintf(op, "%s,[%" PFMT32d "],%s,=[%" PFMT32d "],df,?{,%" PFMT32d ",%s,-=,%" PFMT32d ",%s,-=,},"
				       "df,!,?{,%" PFMT32d ",%s,+=,%" PFMT32d ",%s,+=,}",
				src, width, dst, width, width, src, width,
				dst, width, src, width, dst);
		}
		break;
	// comiss
	case X86_INS_COMISS:
	case X86_INS_UCOMISS:
	case X86_INS_VCOMISS:
	case X86_INS_VUCOMISS:
		op->type = RZ_ANALYSIS_OP_TYPE_SIMD | RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	// mov
	case X86_INS_MOVSS:
	case X86_INS_MOV:
	case X86_INS_MOVAPS:
	case X86_INS_MOVAPD:
	case X86_INS_MOVZX:
	case X86_INS_MOVUPS:
	case X86_INS_MOVHPD:
	case X86_INS_MOVHPS:
	case X86_INS_MOVLPD:
	case X86_INS_MOVLPS:
	case X86_INS_MOVBE:
	case X86_INS_MOVSX:
	case X86_INS_MOVSXD:
	case X86_INS_MOVQ:
	case X86_INS_MOVDQU:
	case X86_INS_MOVDQA:
	case X86_INS_MOVDQ2Q: {
		switch (INSOP(0).type) {
		case X86_OP_MEM:
			if (op->prefix & RZ_ANALYSIS_OP_PREFIX_REP) {
				int width = INSOP(0).size;
				src = ZydisRegisterGetString(INSOP(1).mem.base);
				dst = ZydisRegisterGetString(INSOP(0).mem.base);
				const char *counter = (a->bits == 16) ? "cx" : (a->bits == 32) ? "ecx"
											       : "rcx";
				esilprintf(op, "%s,!,?{,BREAK,},%s,NUM,%s,NUM,"
					       "%s,[%" PFMT32d "],%s,=[%" PFMT32d "],df,?{,%" PFMT32d ",%s,-=,%" PFMT32d ",%s,-=,},"
					       "df,!,?{,%" PFMT32d ",%s,+=,%" PFMT32d ",%s,+=,},%s,--=,%s,"
					       "?{,8,GOTO,}",
					counter, src, dst, src, width, dst,
					width, width, src, width, dst, width, src,
					width, dst, counter, counter);
			} else {
				src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
				dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, zydx->addr);
				esilprintf(op, "%s,%s", src, dst);
			}
			break;
		case X86_OP_REG:
		default:
			if (INSOP(0).type == X86_OP_MEM) {
				op->direction = 1; // read
			}
			if (INSOP(1).type == X86_OP_MEM) {
				// MOV REG, [PTR + IREG*SCALE]
				op->ireg = ZydisRegisterGetString(INSOP(1).mem.index);
				op->disp = INSOP(1).mem.disp.value;
				op->scale = INSOP(1).mem.scale;
			}
			{
				int width = INSOP(1).size;

				src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
				// dst is name of register from instruction.
				dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
				const char *dst64 = rz_reg_32_to_64(a->reg, dst);
				if (a->bits == 64 && dst64) {
					// Here it is still correct, because 'e** = X'
					// turns into 'r** = X' (first one will keep higher bytes,
					// second one will overwrite them with zeros).
					if (zydx->zydecode->mnemonic == X86_INS_MOVSX || zydx->zydecode->mnemonic == X86_INS_MOVSXD) {
						esilprintf(op, "%" PFMT32d ",%s,~,%s,=", width * 8, src, dst64);
					} else {
						esilprintf(op, "%s,%s,=", src, dst64);
					}

				} else {
					if (zydx->zydecode->mnemonic == X86_INS_MOVSX || zydx->zydecode->mnemonic == X86_INS_MOVSXD) {
						esilprintf(op, "%" PFMT32d ",%s,~,%s,=", width * 8, src, dst);
					} else {
						esilprintf(op, "%s,%s,=", src, dst);
					}
				}
			}
			break;
		}
	} break;
	case X86_INS_MOVD:
		if (is_xmm_reg(INSOP(0)) && !is_xmm_reg(INSOP(1))) {
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
			esilprintf(op, "%s,%sl,=", src, dst);
		}
		if (is_xmm_reg(INSOP(1)) && !is_xmm_reg(INSOP(0))) {
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, zydx->addr);
			esilprintf(op, "%sl,%s", src, dst);
		}
		break;
	case X86_INS_ROL:
	case X86_INS_RCL:
		// TODO: RCL Still does not work as intended
		//  - Set flags
		{
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
			esilprintf(op, "%s,%s,<<<,%s,=", src, dst, dst);
		}
		break;
	case X86_INS_ROR:
	case X86_INS_RCR:
		// TODO: RCR Still does not work as intended
		//  - Set flags
		{
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
			esilprintf(op, "%s,%s,>>>,%s,=", src, dst, dst);
		}
		break;
	case X86_INS_CPUID:
		// https://c9x.me/x86/html/file_module_x86_id_45.html
		// GenuineIntel
		esilprintf(op, "0xa,eax,=,0x756E6547,ebx,=,0x6C65746E,ecx,=,0x49656E69,edx,=");
		break;
	case X86_INS_SHLD:
	case X86_INS_SHLX:
		// TODO: SHLD is not implemented yet.
		{
			ut32 bitsize = 0;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst = getarg(a, &gop, 0, 1, "<<", DST_AR, &bitsize, zydx->addr);
			esilprintf(op, "%s,%s,$z,zf,:=,$p,pf,:=,%" PFMT32d ",$s,sf,:=", src, dst, bitsize - 1);
		}
		break;
	case X86_INS_SAR:
		// TODO: Set CF. See case X86_INS_SHL for more details.
		{
			ut32 bitsize = 0;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst_r = getarg(a, &gop, 0, 0, NULL, DST_R_AR, NULL, zydx->addr);
			dst_w = getarg(a, &gop, 0, 1, NULL, DST_W_AR, &bitsize, zydx->addr);
			esilprintf(op, "0,cf,:=,1,%s,-,1,<<,%s,&,?{,1,cf,:=,},%s,%s,>>>>,%s,$z,zf,:=,$p,pf,:=,%" PFMT32d ",$s,sf,:=",
				src, dst_r, src, dst_r, dst_w, bitsize - 1);
		}
		break;
	case X86_INS_SARX: {
		dst = getarg(a, &gop, 0, 1, NULL, 0, NULL, zydx->addr);
		src = getarg(a, &gop, 1, 0, NULL, 1, NULL, zydx->addr);
		src2 = getarg(a, &gop, 1, 0, NULL, 2, NULL, zydx->addr);
		esilprintf(op, "%s,%s,>>>>,%s,=", src2, src, dst);
	} break;
	case X86_INS_SHL: {
		ut64 val = 0;
		switch (INSOP(0).size) {
		case 1:
			val = 0x80;
			break;
		case 2:
			val = 0x8000;
			break;
		case 4:
			val = 0x80000000;
			break;
		case 8:
			val = 0x8000000000000000;
			break;
		default:
			RZ_LOG_ERROR("x86: unknown operand size: %" PFMT32d "\n", INSOP(0).size);
			val = 256;
			break;
		}
		ut32 bitsize = 0;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
		dst2 = getarg(a, &gop, 0, 1, "<<", DST2_AR, &bitsize, zydx->addr);
		esilprintf(op, "0,%s,!,!,?{,1,%s,-,%s,<<,0x%llx,&,!,!,^,},%s,%s,$z,zf,:=,$p,pf,:=,%" PFMT32d ",$s,sf,:=,cf,=",
			src, src, dst, val, src, dst2, bitsize - 1);
	} break;
	case X86_INS_SALC:
		esilprintf(op, "$z,DUP,zf,=,al,=");
		break;
	case X86_INS_SHR:
	case X86_INS_SHRD:
	case X86_INS_SHRX:
		// TODO: Set CF: See case X86_INS_SAL for more details.
		{
			ut32 bitsize = 0;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst_r = getarg(a, &gop, 0, 0, NULL, DST_R_AR, NULL, zydx->addr);
			dst_w = getarg(a, &gop, 0, 1, NULL, DST_W_AR, &bitsize, zydx->addr);
			esilprintf(op, "0,cf,:=,1,%s,-,1,<<,%s,&,?{,1,cf,:=,},%s,%s,>>,%s,$z,zf,:=,$p,pf,:=,%" PFMT32d ",$s,sf,:=",
				src, dst_r, src, dst_r, dst_w, bitsize - 1);
		}
		break;
	case X86_INS_CBW:
		esilprintf(op, "al,ax,=,7,ax,>>,?{,0xff00,ax,|=,}");
		break;
	case X86_INS_CWDE:
		esilprintf(op, "ax,eax,=,15,eax,>>,?{,0xffff0000,eax,|=,}");
		break;
	case X86_INS_CDQ:
		esilprintf(op, "0,edx,=,31,eax,>>,?{,0xffffffff,edx,=,}");
		break;
	case X86_INS_CDQE:
		esilprintf(op, "eax,rax,=,31,rax,>>,?{,0xffffffff00000000,rax,|=,}");
		break;
	case X86_INS_AAA:
		esilprintf(op, "0,cf,:=,0,af,:=,9,al,>,?{,10,al,-=,1,ah,+=,1,cf,:=,1,af,:=,}"); // don't
		break;
	case X86_INS_AAD:
		arg0 = "0,zf,:=,0,sf,:=,0,pf,:=,10,ah,*,al,+,ax,=";
		arg1 = "0,al,==,?{,1,zf,:=,},2,al,%,0,==,?{,1,pf,:=,},7,al,>>,?{,1,sf,:=,}";
		esilprintf(op, "%s,%s", arg0, arg1);
		break;
	case X86_INS_AAM:
		arg0 = "0,zf,:=,0,sf,:=,0,pf,:=,10,al,/,ah,=,10,al,%,al,=";
		arg1 = "0,al,==,?{,1,zf,:=,},2,al,%,0,==,?{,1,pf,:=,},7,al,>>,?{,1,sf,:=,}";
		esilprintf(op, "%s,%s", arg0, arg1);
		break;
	// XXX: case X86_INS_AAS: too tough to implement. BCD is deprecated anyways
	case X86_INS_CMP:
	case X86_INS_CMPPD:
	case X86_INS_CMPPS:
	case X86_INS_CMPSW:
	case X86_INS_CMPSD:
	case X86_INS_CMPSQ:
	case X86_INS_CMPSB:
	case X86_INS_CMPSS:
	case X86_INS_TEST: {
		ut32 bitsize = 0;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, &bitsize, zydx->addr);

		if (!bitsize || bitsize > 64) {
			break;
		}

		if (zydx->zydecode->mnemonic == X86_INS_TEST) {
			esilprintf(op, "0,%s,%s,&,==,$z,zf,:=,$p,pf,:=,%u,$s,sf,:=,0,cf,:=,0,of,:=",
				src, dst, bitsize - 1);
		} else if (zydx->zydecode->mnemonic == X86_INS_CMP) {
			esilprintf(op,
				"%s,%s,==,$z,zf,:=,%u,$b,cf,:=,$p,pf,:=,%u,$s,sf,:=,"
				"%s,0x%" PFMT64x ",-,!,%u,$o,^,of,:=,3,$b,af,:=",
				src, dst, bitsize, bitsize - 1, src, 1ULL << (bitsize - 1), bitsize - 1);
		} else {
			const char *rsrc = ZydisRegisterGetString(INSOP(1).mem.base);
			const char *rdst = ZydisRegisterGetString(INSOP(0).mem.base);
			const int width = INSOP(0).size;
			esilprintf(op,
				"%s,%s,==,$z,zf,:=,%u,$b,cf,:=,$p,pf,:=,%u,$s,sf,:=,%s,0x%" PFMT64x ","
				"-,!,%u,$o,^,of,:=,3,$b,af,:=,df,?{,%" PFMT32d ",%s,-=,%" PFMT32d ",%s,-=,}{,%" PFMT32d ",%s,+=,%" PFMT32d ",%s,+=,}",
				src, dst, bitsize, bitsize - 1, src, 1ULL << (bitsize - 1), bitsize - 1,
				width, rsrc, width, rdst, width, rsrc, width, rdst);
		}
	} break;
	case X86_INS_LEA: {
		src = getarg(a, &gop, 1, 2, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, zydx->addr);
		esilprintf(op, "%s,%s", src, dst);
	} break;
	// pushal, popal - push/pop EAX,EBX,ECX,EDX,ESP,EBP,ESI,EDI
	case X86_INS_PUSHAD: {
		esilprintf(op,
			"0,%s,+,"
			"%" PFMT32d ",%s,-=,%s,%s,=[%" PFMT32d "],"
			"%" PFMT32d ",%s,-=,%s,%s,=[%" PFMT32d "],"
			"%" PFMT32d ",%s,-=,%s,%s,=[%" PFMT32d "],"
			"%" PFMT32d ",%s,-=,%s,%s,=[%" PFMT32d "],"
			"%" PFMT32d ",%s,-=,%s,=[%" PFMT32d "],"
			"%" PFMT32d ",%s,-=,%s,%s,=[%" PFMT32d "],"
			"%" PFMT32d ",%s,-=,%s,%s,=[%" PFMT32d "],"
			"%" PFMT32d ",%s,-=,%s,%s,=[%" PFMT32d "]",
			sp,
			rs, sp, "eax", sp, rs,
			rs, sp, "ecx", sp, rs,
			rs, sp, "edx", sp, rs,
			rs, sp, "ebx", sp, rs,
			rs, sp, "esp", rs,
			rs, sp, "ebp", sp, rs,
			rs, sp, "esi", sp, rs,
			rs, sp, "edi", sp, rs);
	} break;
	case X86_INS_ENTER:
	case X86_INS_PUSH: {
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
		esilprintf(op, "%s,%" PFMT32d ",%s,-,=[%" PFMT32d "],%" PFMT32d ",%s,-=",
			dst ? dst : "eax", rs, sp, rs, rs, sp);
	} break;
	case X86_INS_PUSHF:
	case X86_INS_PUSHFD:
	case X86_INS_PUSHFQ:
		esilprintf(op, "%" PFMT32d ",%s,-=,eflags,%s,=[%" PFMT32d "]", rs, sp, sp, rs);
		break;
	case X86_INS_LEAVE:
		esilprintf(op, "%s,%s,=,%s,[%" PFMT32d "],%s,=,%" PFMT32d ",%s,+=",
			bp, sp, sp, rs, bp, rs, sp);
		break;
	case X86_INS_POPAD: {
		esilprintf(op,
			"%s,[%" PFMT32d "],%" PFMT32d ",%s,+=,%s,=,"
			"%s,[%" PFMT32d "],%" PFMT32d ",%s,+=,%s,=,"
			"%s,[%" PFMT32d "],%" PFMT32d ",%s,+=,%s,=,"
			"%s,[%" PFMT32d "],%" PFMT32d ",%s,+=,"
			"%s,[%" PFMT32d "],%" PFMT32d ",%s,+=,%s,=,"
			"%s,[%" PFMT32d "],%" PFMT32d ",%s,+=,%s,=,"
			"%s,[%" PFMT32d "],%" PFMT32d ",%s,+=,%s,=,"
			"%s,[%" PFMT32d "],%" PFMT32d ",%s,+=,%s,=,"
			"%s,=",
			sp, rs, rs, sp, "edi",
			sp, rs, rs, sp, "esi",
			sp, rs, rs, sp, "ebp",
			sp, rs, rs, sp,
			sp, rs, rs, sp, "ebx",
			sp, rs, rs, sp, "edx",
			sp, rs, rs, sp, "ecx",
			sp, rs, rs, sp, "eax",
			sp);
	} break;
	case X86_INS_POP: {
		switch (INSOP(0).type) {
		case X86_OP_MEM: {
			dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, zydx->addr);
			esilprintf(op,
				"%s,[%" PFMT32d "],%" PFMT32d ",%s,+=,%s",
				sp, rs, rs, sp, dst);
			break;
		}
		case X86_OP_REG:
		default: {
			dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
			esilprintf(op,
				"%s,[%" PFMT32d "],%" PFMT32d ",%s,+=,%s,=",
				sp, rs, rs, sp, dst);
			break;
		}
		}
	} break;
	case X86_INS_POPF:
	case X86_INS_POPFD:
	case X86_INS_POPFQ:
		esilprintf(op, "%s,[%" PFMT32d "],eflags,=", sp, rs);
		break;
	case X86_INS_RET:
	case X86_INS_IRET:
	case X86_INS_IRETD:
	case X86_INS_IRETQ:
	case X86_INS_SYSRET: {
		int cleanup = 0;
		if (INSOPS > 0) {
			cleanup = (int)get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits);
		}
		esilprintf(op, "%s,[%" PFMT32d "],%s,=,%" PFMT32d ",%s,+=",
			sp, rs, pc, rs + cleanup, sp);
	} break;
	case X86_INS_INT3:
		esilprintf(op, "3,$");
		break;
	case X86_INS_INT1:
		esilprintf(op, "1,$");
		break;
	case X86_INS_INT:
		esilprintf(op, "%" PFMT32d ",$",
			RZ_ABS((int)get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits)));
		break;
	case X86_INS_SYSCALL:
	case X86_INS_SYSENTER:
	case X86_INS_SYSEXIT:
		break;
	case X86_INS_INTO:
	case X86_INS_VMCALL:
	case X86_INS_VMMCALL:
		esilprintf(op, "%" PFMT32d ",$", (int)get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits));
		break;
	case X86_INS_JL:
	case X86_INS_JLE:
	case X86_INS_JA:
	case X86_INS_JAE:
	case X86_INS_JB:
	case X86_INS_JBE:
	case X86_INS_JCXZ:
	case X86_INS_JECXZ:
	case X86_INS_JRCXZ:
	case X86_INS_JO:
	case X86_INS_JNO:
	case X86_INS_JS:
	case X86_INS_JNS:
	case X86_INS_JP:
	case X86_INS_JNP:
	case X86_INS_JE:
	case X86_INS_JNE:
	case X86_INS_JG:
	case X86_INS_JGE:
	case X86_INS_LOOP:
	case X86_INS_LOOPE:
	case X86_INS_LOOPNE: {
		const char *cnt = (a->bits == 16) ? "cx" : (a->bits == 32) ? "ecx"
									   : "rcx";
		dst = getarg(a, &gop, 0, 2, NULL, DST_AR, NULL, zydx->addr);
		switch (zydx->zydecode->mnemonic) {
		case X86_INS_JL:
			esilprintf(op, "of,sf,^,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JLE:
			esilprintf(op, "of,sf,^,zf,|,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JA:
			esilprintf(op, "cf,zf,|,!,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JAE:
			esilprintf(op, "cf,!,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JB:
			esilprintf(op, "cf,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JO:
			esilprintf(op, "of,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JNO:
			esilprintf(op, "of,!,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JE:
			esilprintf(op, "zf,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JGE:
			esilprintf(op, "of,!,sf,^,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JNE:
			esilprintf(op, "zf,!,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JG:
			esilprintf(op, "sf,of,!,^,zf,!,&,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JS:
			esilprintf(op, "sf,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JNS:
			esilprintf(op, "sf,!,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JP:
			esilprintf(op, "pf,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JNP:
			esilprintf(op, "pf,!,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JBE:
			esilprintf(op, "zf,cf,|,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JCXZ:
			esilprintf(op, "cx,!,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JECXZ:
			esilprintf(op, "ecx,!,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_JRCXZ:
			esilprintf(op, "rcx,!,?{,%s,%s,=,}", dst, pc);
			break;
		case X86_INS_LOOP:
			esilprintf(op, "1,%s,-=,%s,?{,%s,%s,=,}", cnt, cnt, dst, pc);
			break;
		case X86_INS_LOOPE:
			esilprintf(op, "1,%s,-=,%s,?{,zf,?{,%s,%s,=,},}",
				cnt, cnt, dst, pc);
			break;
		case X86_INS_LOOPNE:
			esilprintf(op, "1,%s,-=,%s,?{,zf,!,?{,%s,%s,=,},}",
				cnt, cnt, dst, pc);
			break;
		default: break;
		}
	} break;
	case X86_INS_CALL: {
		if (zydx->zydecode->attributes & ZYDIS_ATTRIB_HAS_SEGMENT) { // far calls
			arg0 = getarg(a, &gop, 0, 0, NULL, ARG0_AR, NULL, zydx->addr);
			arg1 = getarg(a, &gop, 0, 0, NULL, ARG1_AR, NULL, zydx->addr);
			if (arg1) {
				esilprintf(op,
					"2,%s,-=,cs,%s,=[2]," // push CS
					"%" PFMT32d ",%s,-=,%s,%s,=[]," // push IP/EIP
					"%s,cs,=," // set CS
					"%s,%s,=", // set IP/EIP
					sp, sp, rs, sp, pc, sp, arg0, arg1, pc);
			} else {
				esilprintf(op,
					"%s,%s,-=,%" PFMT32d ",%s,=[]," // push IP/EIP
					"%s,%s,=", // set IP/EIP
					sp, sp, rs, sp, arg0, pc);
			}
			break;
		}
		if (a->read_at && a->bits != 16) {
			ut8 thunk[4] = { 0 };
			if (a->read_at(a, (ut64)get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits), thunk, sizeof(thunk))) {
				/* 8b xx x4    mov <reg>, dword [esp]
					   c3          ret
					*/
				if (thunk[0] == 0x8b && thunk[3] == 0xc3 && (thunk[1] & 0xc7) == 4 /* 00rrr100 */
					&& (thunk[2] & 0x3f) == 0x24) { /* --100100: ignore scale in SIB byte */
					ut8 reg = (thunk[1] & 0x38) >> 3;
					esilprintf(op, "0x%" PFMT64x ",%s,=", zydx->addr + op->size,
						reg32_to_name(reg));
					break;
				}
			}
		}
		arg0 = getarg(a, &gop, 0, 0, NULL, ARG0_AR, NULL, zydx->addr);
		esilprintf(op,
			"%s,%s,"
			"%" PFMT32d ",%s,-=,%s,"
			"=[],"
			"%s,=",
			arg0, pc, rs, sp, sp, pc);
		break;
	}
	case X86_INS_JMP: {
		src = getarg(a, &gop, 0, 0, NULL, SRC_AR, NULL, zydx->addr);
		esilprintf(op, "%s,%s,=", src, pc);
	}
		// TODO: what if UJMP?
		switch (INSOP(0).type) {
		case X86_OP_IMM:
			if (INSOP(1).type == X86_OP_IMM) {
				ut64 seg = get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits);
				ut64 off = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, a->bits);
				esilprintf(
					op,
					"0x%" PFMT64x ",cs,=,"
					"0x%" PFMT64x ",%s,=",
					seg, off, pc);
			} else {
				ut64 dst = get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits);
				esilprintf(op, "0x%" PFMT64x ",%s,=", dst + (zydx->addr & 0xF0000), pc);
			}
			break;
		case X86_OP_MEM:
			if (INSOP(0).mem.base == X86_REG_RIP) {
				/* nothing here */
			} else {
				ZydisDecodedOperand in = INSOP(0);
				if (in.mem.index == 0 && in.mem.base == 0 && in.mem.scale == 1) {
					if (in.mem.segment != X86_REG_NONE) {
						esilprintf(
							op,
							"4,%s,<<,0x%" PFMT64x ",+,[],%s,=",
							INSOP(0).mem.segment == X86_REG_ES           ? "es"
								: INSOP(0).mem.segment == X86_REG_CS ? "cs"
								: INSOP(0).mem.segment == X86_REG_DS ? "ds"
								: INSOP(0).mem.segment == X86_REG_FS ? "fs"
								: INSOP(0).mem.segment == X86_REG_GS ? "gs"
								: INSOP(0).mem.segment == X86_REG_SS ? "ss"
												     : "unknown_segment_register",
							(ut64)INSOP(0).mem.disp.value,
							pc);
					} else {
						esilprintf(
							op,
							"0x%" PFMT64x ",[],%s,=",
							(ut64)INSOP(0).mem.disp.value, pc);
					}
				}
			}
			break;
		case X86_OP_REG: {
			src = getarg(a, &gop, 0, 0, NULL, SRC_AR, NULL, zydx->addr);
			op->src[0] = rz_analysis_value_new();
			op->src[0]->reg = rz_reg_get(a->reg, src, RZ_REG_TYPE_GPR);
			break;
		}
		case X86_OP_PTR: {
			ut64 seg = INSOP(0).ptr.segment;
			ut64 off = INSOP(0).ptr.offset;
			esilprintf(
				op,
				"0x%" PFMT64x ",cs,=,"
				"0x%" PFMT64x ",%s,=",
				seg, off, pc);
		}
		default: // other?
			break;
		}
		break;
	case X86_INS_IN:
	case X86_INS_INSW:
	case X86_INS_INSD:
	case X86_INS_INSB:
		if (ISIMM(1)) {
			op->val = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, a->bits);
		}
		break;
	case X86_INS_OUT:
	case X86_INS_OUTSB:
	case X86_INS_OUTSD:
	case X86_INS_OUTSW:
		if (ISIMM(0)) {
			op->val = get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits);
		}
		break;
	case X86_INS_VXORPD:
	case X86_INS_VXORPS:
	case X86_INS_VPXORD:
	case X86_INS_VPXORQ:
	case X86_INS_VPXOR:
	case X86_INS_XORPS:
	case X86_INS_KXORW:
	case X86_INS_PXOR:
	case X86_INS_XOR: {
		ut32 bitsize = 0;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 1, "^", DST_AR, &bitsize, zydx->addr);
		dst2 = getarg(a, &gop, 0, 0, NULL, DST2_AR, NULL, zydx->addr);
		const char *dst_reg64 = rz_reg_32_to_64(a->reg, dst2); // 64-bit destination if exists
		if (a->bits == 64 && dst_reg64) {
			// (64-bit ^ 32-bit) & 0xFFFF FFFF -> 64-bit, it's alright, higher bytes will be eliminated
			// (consider this is operation with 32-bit regs in 64-bit environment).
			esilprintf(op, "%s,%s,^,0xffffffff,&,%s,=,$z,zf,:=,$p,pf,:=,%" PFMT32d ",$s,sf,:=,0,cf,:=,0,of,:=",
				src, dst_reg64, dst_reg64, bitsize - 1);
		} else {
			esilprintf(op, "%s,%s,$z,zf,:=,$p,pf,:=,%" PFMT32d ",$s,sf,:=,0,cf,:=,0,of,:=",
				src, dst, bitsize - 1);
		}
	} break;
	case X86_INS_BSF: {
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
		int bits = INSOP(0).size * 8;

		/*
		 * Here we first set ZF depending on the source operand
		 * (and bail out if it's 0), then test each bit in a loop
		 * by creating a mask on the stack and applying it, returning
		 * result if bit is set.
		 */
		esilprintf(op, "%s,!,?{,1,zf,=,BREAK,},0,zf,=,"
			       "%" PFMT32d ",DUP,%" PFMT32d ",-,1,<<,%s,&,?{,%" PFMT32d ",-,%s,=,BREAK,},12,REPEAT",
			src, bits, bits, src, bits, dst);
	} break;
	case X86_INS_BSR: {
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
		int bits = INSOP(0).size * 8;

		/*
		 * Similar to BSF, except we naturally don't
		 * need to subtract anything to create
		 * a mask and return the result.
		 */
		esilprintf(op, "%s,!,?{,1,zf,=,BREAK,},0,zf,=,"
			       "%" PFMT32d ",DUP,1,<<,%s,&,?{,%s,=,BREAK,},12,REPEAT",
			src, bits, src, dst);
	} break;
	case X86_INS_BSWAP: {
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
		if (INSOP(0).size == 4) {
			esilprintf(op, "0xff000000,24,%s,NUM,<<,&,24,%s,NUM,>>,|,"
				       "8,0x00ff0000,%s,NUM,&,>>,|,"
				       "8,0x0000ff00,%s,NUM,&,<<,|,"
				       "%s,=",
				dst, dst, dst, dst, dst);
		} else {
			esilprintf(op, "0xff00000000000000,56,%s,NUM,<<,&,"
				       "56,%s,NUM,>>,|,40,0xff000000000000,%s,NUM,&,>>,|,"
				       "40,0xff00,%s,NUM,&,<<,|,24,0xff0000000000,%s,NUM,&,>>,|,"
				       "24,0xff0000,%s,NUM,&,<<,|,8,0xff00000000,%s,NUM,&,>>,|,"
				       "8,0xff000000,%s,NUM,&,<<,|,"
				       "%s,=",
				dst, dst, dst, dst, dst, dst, dst, dst, dst);
		}
	} break;
	case X86_INS_OR:
		// The OF and CF flags are cleared; the SF, ZF, and PF flags are
		// set according to the result. The state of the AF flag is
		// undefined.
		{
			ut32 bitsize = 0;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst = getarg(a, &gop, 0, 1, "|", DST_AR, &bitsize, zydx->addr);
			esilprintf(op, "%s,%s,%" PFMT32d ",$s,sf,:=,$z,zf,:=,$p,pf,:=,0,of,:=,0,cf,:=",
				src, dst, bitsize - 1);
		}
		break;
	case X86_INS_INC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		{
			ut32 bitsize = 0;
			src = getarg(a, &gop, 0, 1, "++", SRC_AR, &bitsize, zydx->addr);
			esilprintf(op, "%s,%" PFMT32d ",$o,of,:=,%" PFMT32d ",$s,sf,:=,$z,zf,:=,$p,pf,:=,3,$c,af,:=", src, bitsize - 1, bitsize - 1);
		}
		break;
	case X86_INS_DEC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		{
			ut32 bitsize = 0;
			src = getarg(a, &gop, 0, 1, "--", SRC_AR, &bitsize, zydx->addr);
			esilprintf(op, "%s,%" PFMT32d ",$o,of,:=,%" PFMT32d ",$s,sf,:=,$z,zf,:=,$p,pf,:=,3,$b,af,:=", src, bitsize - 1, bitsize - 1);
		}
		break;
	case X86_INS_PSUBB:
	case X86_INS_PSUBW:
	case X86_INS_PSUBD:
	case X86_INS_PSUBQ:
	case X86_INS_PSUBSB:
	case X86_INS_PSUBSW:
	case X86_INS_PSUBUSB:
	case X86_INS_PSUBUSW: {
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 1, "-", DST_AR, NULL, zydx->addr);
		esilprintf(op, "%s,%s", src, dst);
	} break;
	case X86_INS_SUB: {
		ut32 bitsize = 0;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 1, "-", DST_AR, &bitsize, zydx->addr);

		if (!bitsize || bitsize > 64) {
			break;
		}

		// Set OF, SF, ZF, AF, PF, and CF flags.
		// We use $b rather than $c here as the carry flag really
		// represents a "borrow"
		esilprintf(op, "%s,%s,%s,0x%" PFMT64x ",-,!,%u,$o,^,of,:=,%u,$s,sf,:=,$z,zf,:=,$p,pf,:=,%u,$b,cf,:=,3,$b,af,:=",
			src, dst, src, 1ULL << (bitsize - 1), bitsize - 1, bitsize - 1, bitsize);
	} break;
	case X86_INS_SBB:
		// dst = dst - (src + cf)
		{
			ut32 bitsize = 0;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst = getarg(a, &gop, 0, 0, NULL, DST_AR, &bitsize, zydx->addr);
			esilprintf(op, "cf,%s,+,%s,-=,%" PFMT32d ",$o,of,:=,%" PFMT32d ",$s,sf,:=,$z,zf,:=,$p,pf,:=,%" PFMT32d ",$b,cf,:=",
				src, dst, bitsize - 1, bitsize - 1, bitsize);
		}
		break;
	case X86_INS_LIDT:
		break;
	case X86_INS_SIDT:
		break;
	case X86_INS_RDRAND:
	case X86_INS_RDSEED:
	case X86_INS_RDMSR:
	case X86_INS_RDPMC:
	case X86_INS_RDTSC:
	case X86_INS_RDTSCP:
	case X86_INS_CRC32:
	case X86_INS_SHA1MSG1:
	case X86_INS_SHA1MSG2:
	case X86_INS_SHA1NEXTE:
	case X86_INS_SHA1RNDS4:
	case X86_INS_SHA256MSG1:
	case X86_INS_SHA256MSG2:
	case X86_INS_SHA256RNDS2:
	case X86_INS_AESDECLAST:
	case X86_INS_AESDEC:
	case X86_INS_AESENCLAST:
	case X86_INS_AESENC:
	case X86_INS_AESIMC:
	case X86_INS_AESKEYGENASSIST:
		// AES instructions
		break;
	case X86_INS_AND:
	case X86_INS_ANDN:
	case X86_INS_ANDPD:
	case X86_INS_ANDPS:
	case X86_INS_ANDNPD:
	case X86_INS_ANDNPS: {
		ut32 bitsize = 0;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 1, "&", DST_AR, &bitsize, zydx->addr);
		dst2 = getarg(a, &gop, 0, 0, NULL, DST2_AR, NULL, zydx->addr);
		const char *dst_reg64 = rz_reg_32_to_64(a->reg, dst2); // 64-bit destination if exists
		if (a->bits == 64 && dst_reg64) {
			// (64-bit & 32-bit) & 0xFFFF FFFF -> 64-bit, it's alright, higher bytes will be eliminated
			// (consider this is operation with 32-bit regs in 64-bit environment).
			esilprintf(op, "%s,%s,&,0xffffffff,&,%s,=,$z,zf,:=,$p,pf,:=,%" PFMT32d ",$s,sf,:=,0,cf,:=,0,of,:=",
				src, dst_reg64, dst_reg64, bitsize - 1);
		} else {
			esilprintf(op, "%s,%s,$z,zf,:=,$p,pf,:=,%" PFMT32d ",$s,sf,:=,0,cf,:=,0,of,:=", src, dst, bitsize - 1);
		}
	} break;
	case X86_INS_IDIV: {
		arg0 = getarg(a, &gop, 0, 0, NULL, ARG0_AR, NULL, zydx->addr);
		arg1 = getarg(a, &gop, 1, 0, NULL, ARG1_AR, NULL, zydx->addr);
		arg2 = getarg(a, &gop, 2, 0, NULL, ARG2_AR, NULL, zydx->addr);
		// DONE handle signedness
		// IDIV does not change flags
		op->sign = true;
		if (!arg2 && !arg1) {
			// TODO: IDIV rbx not implemented. this is just a workaround
			//
			// http://www.tptp.cc/mirrors/siyobik.info/instruction/IDIV.html
			// Divides (signed) the value in the AX, DX:AX, or EDX:EAX registers (dividend) by the source operand (divisor) and stores the result in the AX (AH:AL), DX:AX, or EDX:EAX registers. The source operand can be a general-purpose register or a memory location. The action of this instruction depends on the operand size (dividend/divisor), as shown in the following table:
			// IDIV RBX    ==   RDX:RAX /= RBX

			//
			if (arg0) {
				int width = INSOP(0).size;
				const char *rz_quot = (width == 1) ? "al" : (width == 2) ? "ax"
					: (width == 4)                                   ? "eax"
											 : "rax";
				const char *rz_rema = (width == 1) ? "ah" : (width == 2) ? "dx"
					: (width == 4)                                   ? "edx"
											 : "rdx";
				const char *rz_nume = (width == 1) ? "ax" : rz_quot;

				esilprintf(op, "%" PFMT32d ",%s,~,%" PFMT32d ",%s,<<,%s,+,~%%,%" PFMT32d ",%s,~,%" PFMT32d ",%s,<<,%s,+,~/,%s,=,%s,=",
					width * 8, arg0, width * 8, rz_rema, rz_nume, width * 8, arg0, width * 8, rz_rema, rz_nume, rz_quot, rz_rema);
			} else {
				/* should never happen */
			}
		} else {
			// does this instruction even exist?
			int width = INSOP(0).size;
			esilprintf(op, "%" PFMT32d ",%s,~,%" PFMT32d ",%s,~,~/,%s,=", width * 8, arg2, width * 8, arg1, arg0);
		}
	} break;
	case X86_INS_DIV: {
		int width = INSOP(0).size;
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
		const char *rz_quot = (width == 1) ? "al" : (width == 2) ? "ax"
			: (width == 4)                                   ? "eax"
									 : "rax";
		const char *rz_rema = (width == 1) ? "ah" : (width == 2) ? "dx"
			: (width == 4)                                   ? "edx"
									 : "rdx";
		const char *rz_nume = (width == 1) ? "ax" : rz_quot;
		// DIV does not change flags and is unsigned

		esilprintf(op, "%s,%" PFMT32d ",%s,<<,%s,+,%%,%s,%" PFMT32d ",%s,<<,%s,+,/,%s,=,%s,=",
			dst, width * 8, rz_rema, rz_nume, dst, width * 8, rz_rema, rz_nume, rz_quot, rz_rema);
	} break;
	case X86_INS_IMUL: {
		arg0 = getarg(a, &gop, 0, 0, NULL, ARG0_AR, NULL, zydx->addr);
		arg1 = getarg(a, &gop, 1, 0, NULL, ARG1_AR, NULL, zydx->addr);
		arg2 = getarg(a, &gop, 2, 0, NULL, ARG2_AR, NULL, zydx->addr);
		op->sign = true;
		int width = INSOP(0).size;
		if (arg2) {
			// flags and sign have been handled
			esilprintf(op, "%" PFMT32d ",%s,~,%" PFMT32d ",%s,~,*,DUP,%s,=,%s,-,?{,1,1,}{,0,0,},cf,:=,of,:=", width * 8, arg2, width * 8, arg1, arg0, arg0);
		} else {
			if (arg1) {
				esilprintf(op, "%" PFMT32d ",%s,~,%" PFMT32d ",%s,~,*,DUP,%s,=,%s,-,?{,1,1,}{,0,0,},cf,:=,of,:=", width * 8, arg0, width * 8, arg1, arg0, arg0);
			} else {
				if (arg0) {
					const char *rz_quot = (width == 1) ? "al" : (width == 2) ? "ax"
						: (width == 4)                                   ? "eax"
												 : "rax";
					const char *rz_rema = (width == 1) ? "ah" : (width == 2) ? "dx"
						: (width == 4)                                   ? "edx"
												 : "rdx";
					const char *rz_nume = (width == 1) ? "ax" : rz_quot;

					if (width == 1) {
						esilprintf(op, "0xffffff00,eflags,&=,%s,%s,%%,eflags,|=,%s,%s,*,%s,=,0xff,eflags,&,%s,=,0xffffff00,eflags,&=,2,eflags,|=",
							arg0, rz_nume, arg0, rz_nume, rz_quot, rz_rema);
					} else {
						// this got a little bit crazy,
						esilprintf(op, "%" PFMT32d ",%" PFMT32d ",%s,~,%" PFMT32d ",%s,~,*,>>,%s,=,%s,%s,*=,%" PFMT32d ",%" PFMT32d ",%s,~,>>,%s,-,?{,1,1,}{,0,0,},cf,:=,of,:=",
							width * 8, width * 8, arg0, width * 8, rz_nume, rz_rema, arg0, rz_nume, width * 8, width * 8, rz_nume, rz_rema);
					}
				} else {
					/* should never happen */
				}
			}
		}
	} break;
	case X86_INS_MUL: {
		src = getarg(a, &gop, 0, 0, NULL, SRC_AR, NULL, zydx->addr);
		if (src) {
			int width = INSOP(0).size;
			const char *rz_quot = (width == 1) ? "al" : (width == 2) ? "ax"
				: (width == 4)                                   ? "eax"
										 : "rax";
			const char *rz_rema = (width == 1) ? "ah" : (width == 2) ? "dx"
				: (width == 4)                                   ? "edx"
										 : "rdx";
			const char *rz_nume = (width == 1) ? "ax" : rz_quot;

			if (width == 1) {
				esilprintf(op, "0xffffff00,eflags,&=,%s,%s,%%,eflags,|=,%s,%s,*,%s,=,0xff,eflags,&,%s,=,0xffffff00,eflags,&=,2,eflags,|=",
					src, rz_nume, src, rz_nume, rz_quot, rz_rema);
			} else {
				esilprintf(op, "%" PFMT32d ",%s,%s,*,>>,%s,=,%s,%s,*=,%s,?{,1,1,}{,0,0,},cf,:=,of,:=",
					width * 8, src, rz_nume, rz_rema, src, rz_nume, rz_rema);
			}
		} else {
			/* should never happen */
		}
	} break;
	case X86_INS_MULX:
	case X86_INS_MULPD:
	case X86_INS_MULPS:
	case X86_INS_MULSD:
	case X86_INS_MULSS: {
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 1, "*", DST_AR, NULL, zydx->addr);
		if (!src && dst) {
			switch (dst[0]) {
			case 'r':
				src = "rax";
				break;
			case 'e':
				src = "eax";
				break;
			default:
				src = "al";
				break;
			}
		}
		esilprintf(op, "%s,%s", src, dst);
	} break;
	case X86_INS_NEG: {
		ut32 bitsize = 0;
		src = getarg(a, &gop, 0, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 1, NULL, DST_AR, &bitsize, zydx->addr);
		ut64 xor = 0;
		switch (bitsize) {
		case 8:
			xor = 0xff;
			break;
		case 16:
			xor = 0xffff;
			break;
		case 32:
			xor = 0xffffffff;
			break;
		case 64:
			xor = 0xffffffffffffffff;
			break;
		default:
			RZ_LOG_ERROR("x86: unhandled neg bitsize %" PFMT32d "\n", bitsize);
			break;
		}
		esilprintf(op, "%s,!,!,cf,:=,%s,0x%" PFMT64x ",^,1,+,%s,$z,zf,:=,0,of,:=,%" PFMT32d ",$s,sf,:=,%" PFMT32d ",$o,pf,:=",
			src, src, xor, dst, bitsize - 1, bitsize - 1);
	} break;
	case X86_INS_NOT: {
		dst = getarg(a, &gop, 0, 1, "^", DST_AR, NULL, zydx->addr);
		esilprintf(op, "-1,%s", dst);
	} break;
	case X86_INS_PACKSSDW:
	case X86_INS_PACKSSWB:
	case X86_INS_PACKUSWB:
		break;
	case X86_INS_PADDB:
	case X86_INS_PADDD:
	case X86_INS_PADDW:
	case X86_INS_PADDSB:
	case X86_INS_PADDSW:
	case X86_INS_PADDUSB:
	case X86_INS_PADDUSW:
		break;
	case X86_INS_XCHG: {
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		if (INSOP(0).type == X86_OP_MEM) {
			dst2 = getarg(a, &gop, 0, 1, NULL, DST2_AR, NULL, zydx->addr);
			esilprintf(op,
				"%s,%s,^,%s,=,"
				"%s,%s,^,%s,"
				"%s,%s,^,%s,=",
				dst, src, src, // x = x ^ y
				src, dst, dst2, // y = y ^ x
				dst, src, src); // x = x ^ y
		} else {
			esilprintf(op,
				"%s,%s,^,%s,=,"
				"%s,%s,^,%s,=,"
				"%s,%s,^,%s,=",
				dst, src, src, // x = x ^ y
				src, dst, dst, // y = y ^ x
				dst, src, src); // x = x ^ y
			// esilprintf (op, "%s,%s,%s,=,%s", src, dst, src, dst);
		}
	} break;
	case X86_INS_XADD: /* xchg + add */
	{
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, zydx->addr);
		dstAdd = getarg(a, &gop, 0, 1, "+", DSTADD_AR, NULL, zydx->addr);
		if (INSOP(0).type == X86_OP_MEM) {
			dst2 = getarg(a, &gop, 0, 1, NULL, DST2_AR, NULL, zydx->addr);
			esilprintf(op,
				"%s,%s,^,%s,=,"
				"%s,%s,^,%s,"
				"%s,%s,^,%s,=,"
				"%s,%s",
				dst, src, src, // x = x ^ y
				src, dst, dst2, // y = y ^ x
				dst, src, src, // x = x ^ y
				src, dstAdd);
		} else {
			esilprintf(op,
				"%s,%s,^,%s,=,"
				"%s,%s,^,%s,=,"
				"%s,%s,^,%s,=,"
				"%s,%s",
				dst, src, src, // x = x ^ y
				src, dst, dst, // y = y ^ x
				dst, src, src, // x = x ^ y
				src, dstAdd);
			// esilprintf (op, "%s,%s,%s,=,%s", src, dst, src, dst);
		}
	} break;
	case X86_INS_FADD:
	case X86_INS_FADDP:
	case X86_INS_PFADD:
		break;
	case X86_INS_ADDPS:
	case X86_INS_ADDSD:
	case X86_INS_ADDSS:
	case X86_INS_ADDSUBPD:
	case X86_INS_ADDSUBPS:
	case X86_INS_ADDPD:
		// The OF, SF, ZF, AF, CF, and PF flags are set according to the
		// result.
		if (INSOP(0).type == X86_OP_MEM) {
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			src2 = getarg(a, &gop, 0, 0, NULL, SRC2_AR, NULL, zydx->addr);
			dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, zydx->addr);
			esilprintf(op, "%s,%s,+,%s", src, src2, dst);
		} else {
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst = getarg(a, &gop, 0, 1, "+", DST_AR, NULL, zydx->addr);
			esilprintf(op, "%s,%s", src, dst);
		}
		break;
	case X86_INS_ADD:
		// The OF, SF, ZF, AF, CF, and PF flags are set according to the
		// result.
		{
			ut32 bitsize = 0;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst = getarg(a, &gop, 0, 1, "+", DST_AR, &bitsize, zydx->addr);
			esilprintf(op, "%s,%s,%" PFMT32d ",$o,of,:=,%" PFMT32d ",$s,sf,:=,$z,zf,:=,%" PFMT32d ",$c,cf,:=,$p,pf,:=,3,$c,af,:=",
				src, dst, bitsize - 1, bitsize - 1, bitsize - 1);
		}
		break;
	case X86_INS_ADC: {
		ut32 bitsize = 0;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
		dst = getarg(a, &gop, 0, 1, "+", DST_AR, &bitsize, zydx->addr);
		// dst = dst + src + cf
		// NOTE: We would like to add the carry first before adding the
		// source to ensure that the flag computation from $c belongs
		// to the operation of adding dst += src rather than the one
		// that adds carry (as esil only keeps track of the last
		// addition to set the flags).
		esilprintf(op, "cf,%s,+,%s,%" PFMT32d ",$o,of,:=,%" PFMT32d ",$s,sf,:=,$z,zf,:=,%" PFMT32d ",$c,cf,:=,$p,pf,:=,3,$c,af,:=",
			src, dst, bitsize - 1, bitsize - 1, bitsize - 1);
	} break;
		/* Direction flag */
	case X86_INS_CLD:
		esilprintf(op, "0,df,:=");
		break;
	case X86_INS_STD:
		esilprintf(op, "1,df,:=");
		break;
	case X86_INS_SUBSD: // cvtss2sd
	case X86_INS_CVTSS2SD: // cvtss2sd
		break;
	case X86_INS_BT:
	case X86_INS_BTC:
	case X86_INS_BTR:
	case X86_INS_BTS:
		if (INSOP(0).type == X86_OP_MEM && INSOP(1).type == X86_OP_REG) {
			int width = INSOP(0).size;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst_r = getarg(a, &gop, 0, 2 /* use the address without loading */, NULL, DST_R_AR, NULL, zydx->addr);
			esilprintf(op, "0,cf,:=,%" PFMT32d ",%s,%%,1,<<,%" PFMT32d ",%s,/,%s,+,[%" PFMT32d "],&,?{,1,cf,:=,}",
				width * 8, src, width * 8, src, dst_r, width);
			switch (zydx->zydecode->mnemonic) {
			case X86_INS_BTS:
			case X86_INS_BTC:
				rz_strbuf_appendf(&op->esil, ",%" PFMT32d ",%s,%%,1,<<,%" PFMT32d ",%s,/,%s,+,%c=[%" PFMT32d "]",
					width * 8, src, width * 8, src, dst_r,
					(zydx->zydecode->mnemonic == X86_INS_BTS) ? '|' : '^', width);
				break;
			case X86_INS_BTR:
				getarg(a, &gop, 0, 1, "&", DST_R_AR, NULL, zydx->addr);
				rz_strbuf_appendf(&op->esil, ",%" PFMT32d ",%s,%%,1,<<,-1,^,%" PFMT32d ",%s,/,%s,+,&=[%" PFMT32d "]",
					width * 8, src, width * 8, src, dst_r, width);
				break;
			default: break;
			}
		} else {
			int width = INSOP(0).size;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, zydx->addr);
			dst_r = getarg(a, &gop, 0, 0, NULL, DST_R_AR, NULL, zydx->addr);
			esilprintf(op, "0,cf,:=,%" PFMT32d ",%s,%%,1,<<,%s,&,?{,1,cf,:=,}",
				width * 8, src, dst_r);
			switch (zydx->zydecode->mnemonic) {
			case X86_INS_BTS:
			case X86_INS_BTC:
				dst_w = getarg(a, &gop, 0, 1, (zydx->zydecode->mnemonic == X86_INS_BTS) ? "|" : "^", DST_R_AR, NULL, zydx->addr);
				rz_strbuf_appendf(&op->esil, ",%" PFMT32d ",%s,%%,1,<<,%s", width * 8, src, dst_w);
				break;
			case X86_INS_BTR:
				dst_w = getarg(a, &gop, 0, 1, "&", DST_R_AR, NULL, zydx->addr);
				rz_strbuf_appendf(&op->esil, ",%" PFMT32d ",%s,%%,1,<<,-1,^,%s", width * 8, src, dst_w);
				break;
			default: break;
			}
		}
		break;
	default: break;
	}

	if (op->prefix & RZ_ANALYSIS_OP_PREFIX_REP) {
		rz_strbuf_appendf(&op->esil, ",%s,--=,%s,?{,5,GOTO,}", counter, counter);
	}
}

static RzRegItem *zydis_reg2reg(RzReg *reg, int type) {
	if (type == X86_REG_NONE) {
		return NULL;
	}
	return rz_reg_get(reg, ZydisRegisterGetString(type), -1);
}

static void set_access_info(RzReg *reg, RzAnalysisOp *op, const X86ZYDISContext *zydx, int mode) {
	RzAnalysisValue *val;
	size_t regsz;
	ZydisRegister sp, ip;
	switch (mode) {
	case ZYDIS_MACHINE_MODE_LONG_64:
		regsz = 8;
		sp = X86_REG_RSP;
		ip = X86_REG_RIP;
		break;
	default:
		regsz = 4;
		sp = X86_REG_ESP;
		ip = X86_REG_EIP;
		break;
	}
	RzList *ret = rz_list_newf((RzListFree)rz_analysis_value_free);
	if (!ret) {
		return;
	}

	// PC register
	val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_REG;
	val->access = RZ_ANALYSIS_ACC_W;
	val->reg = zydis_reg2reg(reg, ip);
	rz_list_append(ret, val);

	// Register access info
	ZydisRegister regs_read[ZYDIS_MAX_OPERAND_COUNT];
	ZydisRegister regs_write[ZYDIS_MAX_OPERAND_COUNT];
	ut8 read_count = 0;
	ut8 write_count = 0;
	for (size_t i = 0; i < zydx->zydecode->operand_count_visible; i++) {
		ZydisDecodedOperand *operand = &INSOP(i);
		if (operand->type != X86_OP_REG) {
			continue;
		}
		if (operand->actions & ZYDIS_OPERAND_ACTION_READ) {
			regs_read[read_count++] = operand->reg.value;
		} else if (operand->actions & ZYDIS_OPERAND_ACTION_WRITE) {
			regs_write[write_count++] = operand->reg.value;
		}
	}

	if (read_count > 0) {
		for (size_t i = 0; i < read_count; i++) {
			val = rz_analysis_value_new();
			val->type = RZ_ANALYSIS_VAL_REG;
			val->access = RZ_ANALYSIS_ACC_R;
			val->reg = zydis_reg2reg(reg, regs_read[i]);
			rz_list_append(ret, val);
		}
	}
	if (write_count > 0) {
		for (size_t i = 0; i < write_count; i++) {
			val = rz_analysis_value_new();
			val->type = RZ_ANALYSIS_VAL_REG;
			val->access = RZ_ANALYSIS_ACC_W;
			val->reg = zydis_reg2reg(reg, regs_write[i]);
			rz_list_append(ret, val);
		}
	}

	switch (zydx->zydecode->mnemonic) {
	case X86_INS_PUSH:
		val = rz_analysis_value_new();
		val->type = RZ_ANALYSIS_VAL_MEM;
		val->access = RZ_ANALYSIS_ACC_W;
		val->reg = zydis_reg2reg(reg, sp);
		val->delta = -INSOP(0).size;
		val->memref = INSOP(0).size;
		rz_list_append(ret, val);
		break;
	case X86_INS_PUSHAD:
	case X86_INS_PUSHF:
		val = rz_analysis_value_new();
		val->type = RZ_ANALYSIS_VAL_MEM;
		val->access = RZ_ANALYSIS_ACC_W;
		val->reg = zydis_reg2reg(reg, sp);
		val->delta = -2;
		val->memref = 2;
		rz_list_append(ret, val);
		break;
	case X86_INS_PUSHFD:
		val = rz_analysis_value_new();
		val->type = RZ_ANALYSIS_VAL_MEM;
		val->access = RZ_ANALYSIS_ACC_W;
		val->reg = zydis_reg2reg(reg, sp);
		val->delta = -4;
		val->memref = 4;
		rz_list_append(ret, val);
		break;
	case X86_INS_PUSHFQ:
		val = rz_analysis_value_new();
		val->type = RZ_ANALYSIS_VAL_MEM;
		val->access = RZ_ANALYSIS_ACC_W;
		val->reg = zydis_reg2reg(reg, sp);
		val->delta = -8;
		val->memref = 8;
		rz_list_append(ret, val);
		break;
	case X86_INS_CALL:
		val = rz_analysis_value_new();
		val->type = RZ_ANALYSIS_VAL_MEM;
		val->access = RZ_ANALYSIS_ACC_W;
		val->reg = zydis_reg2reg(reg, sp);
		val->delta = -regsz;
		val->memref = regsz;
		rz_list_append(ret, val);
		break;
	default:
		break;
	}

	// Memory access info based on operands
	for (size_t i = 0; i < zydx->zydecode->operand_count; i++) {
		if (INSOP(i).type == X86_OP_MEM) {
			val = rz_analysis_value_new();
			val->type = RZ_ANALYSIS_VAL_MEM;
			switch (INSOP(i).actions) {
			case ZYDIS_OPERAND_ACTION_READ:
				val->access = RZ_ANALYSIS_ACC_R;
				break;
			case ZYDIS_OPERAND_ACTION_WRITE:
				val->access = RZ_ANALYSIS_ACC_W;
				break;
			default:
				val->access = RZ_ANALYSIS_ACC_UNKNOWN;
				break;
			}
			val->mul = INSOP(i).mem.scale;
			val->delta = INSOP(i).mem.disp.value;
			if (INSOP(0).mem.base == X86_REG_RIP || INSOP(0).mem.base == X86_REG_EIP) {
				val->delta += zydx->zydecode->length;
			}
			val->memref = INSOP(i).size;
			val->seg = zydis_reg2reg(reg, INSOP(i).mem.segment);
			val->reg = zydis_reg2reg(reg, INSOP(i).mem.base);
			val->regdelta = zydis_reg2reg(reg, INSOP(i).mem.index);
			rz_list_append(ret, val);
		}
	}
	op->access = ret;
}

#define CREATE_SRC_DST(op) \
	(op)->src[0] = rz_analysis_value_new(); \
	(op)->src[1] = rz_analysis_value_new(); \
	(op)->src[2] = rz_analysis_value_new(); \
	(op)->dst = rz_analysis_value_new();

static void set_src_dst(RzReg *reg, RzAnalysisValue *val, X86ZYDISContext *zydx, int x, int bitness) {
	if (x >= zydx->zydecode->operand_count_visible) {
		return;
	}
	switch (INSOP(x).type) {
	case X86_OP_MEM:
		val->type = RZ_ANALYSIS_VAL_MEM;
		val->mul = INSOP(x).mem.scale;
		val->delta = INSOP(x).mem.disp.value;
		val->memref = INSOP(x).size;
		val->seg = zydis_reg2reg(reg, INSOP(x).mem.segment);
		val->reg = zydis_reg2reg(reg, INSOP(x).mem.base);
		val->regdelta = zydis_reg2reg(reg, INSOP(x).mem.index);
		break;
	case X86_OP_REG:
		val->type = RZ_ANALYSIS_VAL_REG;
		val->reg = zydis_reg2reg(reg, INSOP(x).reg.value);
		break;
	case X86_OP_IMM:
		val->type = RZ_ANALYSIS_VAL_IMM;
		val->imm = get_imm_reg_value(&INSOP(x), zydx->addr, zydx->zydecode->length, bitness);
		break;
	default:
		break;
	}
}

static void op_fillval(RzAnalysis *a, RzAnalysisOp *op, int mode, X86ZYDISContext *zydx) {
	set_access_info(a->reg, op, zydx, mode);
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_CMP:
	case RZ_ANALYSIS_OP_TYPE_LEA:
	case RZ_ANALYSIS_OP_TYPE_CMOV:
	case RZ_ANALYSIS_OP_TYPE_SHL:
	case RZ_ANALYSIS_OP_TYPE_SHR:
	case RZ_ANALYSIS_OP_TYPE_SAL:
	case RZ_ANALYSIS_OP_TYPE_SAR:
	case RZ_ANALYSIS_OP_TYPE_ROL:
	case RZ_ANALYSIS_OP_TYPE_ROR:
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_AND:
	case RZ_ANALYSIS_OP_TYPE_OR:
	case RZ_ANALYSIS_OP_TYPE_XOR:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_XCHG:
	case RZ_ANALYSIS_OP_TYPE_POP:
	case RZ_ANALYSIS_OP_TYPE_NOT:
	case RZ_ANALYSIS_OP_TYPE_ACMP:
		CREATE_SRC_DST(op);
		set_src_dst(a->reg, op->dst, zydx, 0, a->bits);
		set_src_dst(a->reg, op->src[0], zydx, 1, a->bits);
		set_src_dst(a->reg, op->src[1], zydx, 2, a->bits);
		set_src_dst(a->reg, op->src[2], zydx, 3, a->bits);
		break;
	case RZ_ANALYSIS_OP_TYPE_UPUSH:
		if ((op->type & RZ_ANALYSIS_OP_TYPE_REG)) {
			CREATE_SRC_DST(op);
			set_src_dst(a->reg, op->src[0], zydx, 0, a->bits);
		}
		break;
	default:
		break;
	}
}

static void op0_memimmhandle(RzAnalysisOp *op, X86ZYDISContext *zydx, size_t regsz, int bitness) {
	op->ptr = UT64_MAX;
	switch (INSOP(0).type) {
	case X86_OP_MEM:
		op->cycles = CYCLE_MEM;
		op->disp = INSOP(0).mem.disp.value;
		if (!op->disp) {
			op->disp = UT64_MAX;
		}
		op->refptr = INSOP(0).size;
		if (INSOP(0).mem.base == X86_REG_RIP) {
			op->ptr = zydx->addr + zydx->zydecode->length + op->disp;
		} else if (INSOP(0).mem.base == X86_REG_RBP || INSOP(0).mem.base == X86_REG_EBP) {
			op->type |= RZ_ANALYSIS_OP_TYPE_REG;
			op->stackop = RZ_ANALYSIS_STACK_SET;
			op->stackptr = regsz;
		} else if (INSOP(1).mem.segment == X86_REG_DS && INSOP(1).mem.base == X86_REG_NONE && INSOP(1).mem.index == X86_REG_NONE && INSOP(1).mem.scale == 0) { // [<addr>]
			op->ptr = op->disp;
			if (op->ptr < 0x1000) {
				op->ptr = UT64_MAX;
			}
		}
		if (INSOP(1).type == X86_OP_IMM) {
			op->val = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, bitness);
		}
		break;
	case X86_OP_REG:
		if (INSOP(1).type == X86_OP_IMM) {
			//	(INSOP(0).reg != X86_REG_RSP) && (INSOP(0).reg != X86_REG_ESP)) {
			op->val = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, bitness);
		}
		break;
	default:
		break;
	}
}

static void op1_memimmhandle(RzAnalysisOp *op, X86ZYDISContext *zydx, size_t regsz, int bitness) {
	if (op->refptr < 1 || op->ptr == UT64_MAX) {
		switch (INSOP(1).type) {
		case X86_OP_MEM:
			op->disp = INSOP(1).mem.disp.value;
			op->refptr = INSOP(1).size;
			if (INSOP(1).mem.base == X86_REG_RIP) {
				op->ptr = zydx->addr + zydx->zydecode->length + op->disp;
			} else if (INSOP(1).mem.base == X86_REG_RBP || INSOP(1).mem.base == X86_REG_EBP) {
				op->stackop = RZ_ANALYSIS_STACK_GET;
				op->stackptr = regsz;
			} else if (INSOP(1).mem.segment == X86_REG_DS && INSOP(1).mem.base == X86_REG_NONE && INSOP(1).mem.index == X86_REG_NONE && INSOP(1).mem.scale == 0) { // [<addr>]
				op->ptr = op->disp;
			}
			break;
		case X86_OP_IMM:
			if ((get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, bitness) > 10) &&
				(INSOP(0).reg.value != X86_REG_RSP) && (INSOP(0).reg.value != X86_REG_ESP)) {
				op->ptr = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, bitness);
			}
			break;
		default:
			break;
		}
	}
}

static void op_stackidx(RzAnalysisOp *op, X86ZYDISContext *zydx, bool minus, int bitness) {
	if (INSOP(0).type == X86_OP_REG && INSOP(1).type == X86_OP_IMM) {
		if (INSOP(0).reg.value == X86_REG_RSP || INSOP(0).reg.value == X86_REG_ESP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			if (minus) {
				op->stackptr = -1 * (int)get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, bitness);
			} else {
				op->stackptr = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, bitness);
			}
		}
	}
}

static void set_opdir(RzAnalysisOp *op, X86ZYDISContext *zydx) {
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_MOV:
		switch (INSOP(0).type) {
		case X86_OP_MEM:
			op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
			break;
		case X86_OP_REG:
			if (INSOP(1).type == X86_OP_MEM) {
				op->direction = RZ_ANALYSIS_OP_DIR_READ;
			}
			break;
		default:
			break;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_LEA:
		op->direction = RZ_ANALYSIS_OP_DIR_REF;
		break;
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
		op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
		break;
	default:
		break;
	}
}

static void anop(RzAnalysis *a, RzAnalysisOp *op, const ut8 *buf, int len, X86ZYDISContext *zydx) {
	size_t regsz = 4;
	switch (a->bits) {
	case 64: regsz = 8; break;
	case 16: regsz = 2; break;
	default: regsz = 4; break; // 32
	}
	switch (zydx->zydecode->mnemonic) {
	case X86_INS_FNOP:
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		/* fallthru */
	case X86_INS_NOP:
	case X86_INS_PAUSE:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case X86_INS_HLT:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case X86_INS_FBLD:
	case X86_INS_FBSTP:
	case X86_INS_FCOMPP:
	case X86_INS_FDECSTP:
	case X86_INS_FEMMS:
	case X86_INS_FFREE:
	case X86_INS_FICOM:
	case X86_INS_FICOMP:
	case X86_INS_FINCSTP:
	case X86_INS_FNCLEX:
	case X86_INS_FNINIT:
	case X86_INS_FNSTCW:
	case X86_INS_FNSTSW:
	case X86_INS_FPATAN:
	case X86_INS_FPREM:
	case X86_INS_FPREM1:
	case X86_INS_FPTAN:
	case X86_INS_FFREEP:
	case X86_INS_FRNDINT:
	case X86_INS_FRSTOR:
	case X86_INS_FNSAVE:
	case X86_INS_FSCALE:
	case X86_INS_FSETPM287_NOP:
	case X86_INS_FSINCOS:
	case X86_INS_FNSTENV:
	case X86_INS_FXAM:
	case X86_INS_FXSAVE:
	case X86_INS_FXSAVE64:
	case X86_INS_FXTRACT:
	case X86_INS_FYL2X:
	case X86_INS_FYL2XP1:
	case X86_INS_FISTTP:
	case X86_INS_FSQRT:
	case X86_INS_FXCH:
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case X86_INS_FTST:
	case X86_INS_FUCOMI:
	case X86_INS_FUCOMPP:
	case X86_INS_FUCOMP:
	case X86_INS_FUCOM:
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case X86_INS_BT:
	case X86_INS_BTC:
	case X86_INS_BTR:
	case X86_INS_BTS:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case X86_INS_FABS:
		op->type = RZ_ANALYSIS_OP_TYPE_ABS;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case X86_INS_FLDCW:
	case X86_INS_FLDENV:
	case X86_INS_FLDL2E:
	case X86_INS_FLDL2T:
	case X86_INS_FLDLG2:
	case X86_INS_FLDLN2:
	case X86_INS_FLDPI:
	case X86_INS_FLDZ:
	case X86_INS_FLD1:
	case X86_INS_FLD:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case X86_INS_FIST:
	case X86_INS_FISTP:
	case X86_INS_FST:
	case X86_INS_FSTP:
	case X86_INS_FSTPNCE:
	case X86_INS_FXRSTOR:
	case X86_INS_FXRSTOR64:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case X86_INS_FDIV:
	case X86_INS_FIDIV:
	case X86_INS_FDIVP:
	case X86_INS_FDIVR:
	case X86_INS_FIDIVR:
	case X86_INS_FDIVRP:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case X86_INS_FSUBR:
	case X86_INS_FISUBR:
	case X86_INS_FSUBRP:
	case X86_INS_FSUB:
	case X86_INS_FISUB:
	case X86_INS_FSUBP:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case X86_INS_FMUL:
	case X86_INS_FIMUL:
	case X86_INS_FMULP:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case X86_INS_CLI:
	case X86_INS_STI:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	case X86_INS_CLC:
	case X86_INS_STC:
	case X86_INS_CLAC:
	case X86_INS_CLGI:
	case X86_INS_CLTS:
	case X86_INS_CLWB:
	case X86_INS_STAC:
	case X86_INS_STGI:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	// cmov
	case X86_INS_SETNZ:
	case X86_INS_SETNO:
	case X86_INS_SETNP:
	case X86_INS_SETNS:
	case X86_INS_SETO:
	case X86_INS_SETP:
	case X86_INS_SETS:
	case X86_INS_SETL:
	case X86_INS_SETLE:
	case X86_INS_SETB:
	case X86_INS_SETNLE:
	case X86_INS_SETNB:
	case X86_INS_SETNBE:
	case X86_INS_SETBE:
	case X86_INS_SETZ:
	case X86_INS_SETNL:
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		op->family = 0;
		break;
	// cmov
	case X86_INS_FCMOVBE:
	case X86_INS_FCMOVB:
	case X86_INS_FCMOVNBE:
	case X86_INS_FCMOVNB:
	case X86_INS_FCMOVE:
	case X86_INS_FCMOVNE:
	case X86_INS_FCMOVNU:
	case X86_INS_FCMOVU:
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		break;
	case X86_INS_CMOVNBE:
	case X86_INS_CMOVNB:
	case X86_INS_CMOVB:
	case X86_INS_CMOVBE:
	case X86_INS_CMOVZ:
	case X86_INS_CMOVNLE:
	case X86_INS_CMOVNL:
	case X86_INS_CMOVL:
	case X86_INS_CMOVLE:
	case X86_INS_CMOVNZ:
	case X86_INS_CMOVNO:
	case X86_INS_CMOVNP:
	case X86_INS_CMOVNS:
	case X86_INS_CMOVO:
	case X86_INS_CMOVP:
	case X86_INS_CMOVS:
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		break;
	case X86_INS_STOSB:
	case X86_INS_STOSD:
	case X86_INS_STOSQ:
	case X86_INS_STOSW:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case X86_INS_LODSB:
	case X86_INS_LODSD:
	case X86_INS_LODSQ:
	case X86_INS_LODSW:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case X86_INS_PALIGNR:
	case X86_INS_VALIGND:
	case X86_INS_VALIGNQ:
	case X86_INS_VPALIGNR:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case X86_INS_CPUID:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case X86_INS_SFENCE:
	case X86_INS_LFENCE:
	case X86_INS_MFENCE:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_THREAD;
		break;
	// mov
	case X86_INS_MOVNTQ:
	case X86_INS_MOVNTDQA:
	case X86_INS_MOVNTDQ:
	case X86_INS_MOVNTI:
	case X86_INS_MOVNTPD:
	case X86_INS_MOVNTPS:
	case X86_INS_MOVNTSD:
	case X86_INS_MOVNTSS:
	case X86_INS_VMOVNTDQA:
	case X86_INS_VMOVNTDQ:
	case X86_INS_VMOVNTPD:
	case X86_INS_VMOVNTPS:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_SSE;
		break;
	case X86_INS_PCMPEQB:
	case X86_INS_PCMPEQD:
	case X86_INS_PCMPEQW:
	case X86_INS_PCMPGTB:
	case X86_INS_PCMPGTD:
	case X86_INS_PCMPGTW:
	case X86_INS_PCMPEQQ:
	case X86_INS_PCMPESTRI:
	case X86_INS_PCMPESTRM:
	case X86_INS_PCMPGTQ:
	case X86_INS_PCMPISTRI:
	case X86_INS_PCMPISTRM:
	case X86_INS_VPCMPB:
	case X86_INS_VPCMPD:
	case X86_INS_VPCMPEQB:
	case X86_INS_VPCMPEQD:
	case X86_INS_VPCMPEQQ:
	case X86_INS_VPCMPEQW:
	case X86_INS_VPCMPESTRI:
	case X86_INS_VPCMPESTRM:
	case X86_INS_VPCMPGTB:
	case X86_INS_VPCMPGTD:
	case X86_INS_VPCMPGTQ:
	case X86_INS_VPCMPGTW:
	case X86_INS_VPCMPISTRI:
	case X86_INS_VPCMPISTRM:
	case X86_INS_VPCMPQ:
	case X86_INS_VPCMPUB:
	case X86_INS_VPCMPUD:
	case X86_INS_VPCMPUQ:
	case X86_INS_VPCMPUW:
	case X86_INS_VPCMPW:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_SSE;
		break;
	case X86_INS_MOVSS:
	case X86_INS_MOV:
	case X86_INS_MOVAPS:
	case X86_INS_MOVAPD:
	case X86_INS_MOVZX:
	case X86_INS_MOVUPS:
	case X86_INS_MOVHPD:
	case X86_INS_MOVHPS:
	case X86_INS_MOVLPD:
	case X86_INS_MOVLPS:
	case X86_INS_MOVBE:
	case X86_INS_MOVSB:
	case X86_INS_MOVSD:
	case X86_INS_MOVSQ:
	case X86_INS_MOVSX:
	case X86_INS_MOVSXD:
	case X86_INS_MOVSW:
	case X86_INS_MOVD:
	case X86_INS_MOVQ:
	case X86_INS_MOVDQ2Q: {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op0_memimmhandle(op, zydx, regsz, a->bits);
		op1_memimmhandle(op, zydx, regsz, a->bits);
	} break;
	case X86_INS_ROL:
	case X86_INS_RCL:
		// TODO: RCL Still does not work as intended
		//  - Set flags
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case X86_INS_ROR:
	case X86_INS_RCR:
		// TODO: RCR Still does not work as intended
		//  - Set flags
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case X86_INS_SHL:
	case X86_INS_SHLD:
	case X86_INS_SHLX:
		// TODO: Set CF: Carry flag is the last bit shifted out due to
		// this operation. It is undefined for SHL and SHR where the
		// number of bits shifted is greater than the size of the
		// destination.
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case X86_INS_SAR:
	case X86_INS_SARX:
		// TODO: Set CF. See case X86_INS_SHL for more details.
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case X86_INS_SALC:
		op->type = RZ_ANALYSIS_OP_TYPE_SAL;
		break;
	case X86_INS_SHR:
	case X86_INS_SHRD:
	case X86_INS_SHRX:
		// TODO: Set CF: See case X86_INS_SAL for more details.
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		op->val = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, a->bits);
		// XXX this should be op->imm
		// op->src[0] = rz_analysis_value_new ();
		// op->src[0]->imm = get_imm_reg_value(&INSOP(1),addr,zydecode->length);
		break;
	case X86_INS_CMP:
	case X86_INS_CMPPD:
	case X86_INS_CMPPS:
	case X86_INS_CMPSW:
	case X86_INS_CMPSD:
	case X86_INS_CMPSQ:
	case X86_INS_CMPSB:
	case X86_INS_CMPSS:
	case X86_INS_TEST:
		if (zydx->zydecode->mnemonic == X86_INS_TEST) {
			op->type = RZ_ANALYSIS_OP_TYPE_ACMP; // compare via and
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		}
		switch (INSOP(0).type) {
		case X86_OP_MEM:
			op->disp = INSOP(0).mem.disp.value;
			op->refptr = INSOP(0).size;
			if (INSOP(0).mem.base == X86_REG_RIP) {
				op->ptr = zydx->addr + zydx->zydecode->length + op->disp;
			} else if (INSOP(0).mem.base == X86_REG_RBP || INSOP(0).mem.base == X86_REG_EBP) {
				op->stackop = RZ_ANALYSIS_STACK_SET;
				op->stackptr = regsz;
				op->type |= RZ_ANALYSIS_OP_TYPE_REG;
			} else if (INSOP(0).mem.segment == X86_REG_DS && INSOP(0).mem.base == X86_REG_NONE && INSOP(0).mem.index == X86_REG_NONE && INSOP(0).mem.scale == 0) { // [<addr>]
				op->ptr = op->disp;
			}
			if (INSOP(1).type == X86_OP_IMM) {
				op->val = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, a->bits);
			}
			break;
		default:
			switch (INSOP(1).type) {
			case X86_OP_MEM:
				op->disp = INSOP(1).mem.disp.value;
				op->refptr = INSOP(1).size;
				if (INSOP(1).mem.base == X86_REG_RIP) {
					op->ptr = zydx->addr + zydx->zydecode->length + op->disp;
				} else if (INSOP(1).mem.base == X86_REG_RBP || INSOP(1).mem.base == X86_REG_EBP) {
					op->type |= RZ_ANALYSIS_OP_TYPE_REG;
					op->stackop = RZ_ANALYSIS_STACK_SET;
					op->stackptr = regsz;
				} else if (INSOP(1).mem.segment == X86_REG_DS && INSOP(1).mem.base == X86_REG_NONE && INSOP(1).mem.index == X86_REG_NONE && INSOP(1).mem.scale == 0) { // [<addr>]
					op->ptr = op->disp;
				}
				if (INSOP(0).type == X86_OP_IMM) {
					op->val = get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits);
				}
				break;
			case X86_OP_IMM:
				op->val = op->ptr = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, a->bits);
				break;
			default:
				break;
			}
			break;
		}
		break;
	case X86_INS_LEA:
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		switch (INSOP(1).type) {
		case X86_OP_MEM:
			op->disp = INSOP(1).mem.disp.value;
			op->refptr = INSOP(1).size;
			switch (INSOP(1).mem.base) {
			case X86_REG_RIP:
				op->ptr = zydx->addr + op->size + op->disp;
				break;
			case X86_REG_RBP:
			case X86_REG_EBP:
				op->stackop = RZ_ANALYSIS_STACK_GET;
				op->stackptr = regsz;
				break;
			default:
				/* unhandled */
				break;
			}
			break;
		case X86_OP_IMM:
			if (get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, a->bits) > 10) {
				op->ptr = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, a->bits);
			}
			break;
		default:
			break;
		}
		break;
	// pushal, popal - push/pop EAX,EBX,ECX,EDX,ESP,EBP,ESI,EDI
	case X86_INS_PUSHAD:
	case X86_INS_ENTER:
	case X86_INS_PUSH:
	case X86_INS_PUSHF:
	case X86_INS_PUSHFD:
	case X86_INS_PUSHFQ:
		switch (INSOP(0).type) {
		case X86_OP_MEM:
			if (INSOP(0).mem.disp.value && INSOP(0).mem.base == X86_REG_NONE && INSOP(0).mem.index == X86_REG_NONE) {
				op->val = op->ptr = INSOP(0).mem.disp.value;
				op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			} else {
				op->type = RZ_ANALYSIS_OP_TYPE_UPUSH;
			}
			op->cycles = CYCLE_REG + CYCLE_MEM;
			break;
		case X86_OP_IMM:
			op->val = op->ptr = get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits);
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			op->cycles = CYCLE_REG + CYCLE_MEM;
			break;
		case X86_OP_REG:
			op->type = RZ_ANALYSIS_OP_TYPE_RPUSH;
			op->cycles = CYCLE_REG + CYCLE_MEM;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_UPUSH;
			op->cycles = CYCLE_MEM + CYCLE_MEM;
			break;
		}
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = regsz;
		break;
	case X86_INS_LEAVE:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		// leave is mov rsp, rbp; pop rbp
		// which may not be exactly a reset depending on the context,
		// but usually it is and this is the best guess we can make here.
		op->stackop = RZ_ANALYSIS_STACK_RESET;
		break;
	case X86_INS_POP:
	case X86_INS_POPF:
	case X86_INS_POPFD:
	case X86_INS_POPFQ:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -regsz;
		break;
	case X86_INS_POPAD:
	case X86_INS_IRET:
	case X86_INS_IRETD:
	case X86_INS_IRETQ:
	case X86_INS_SYSRET:
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		/* fallthrough */
	case X86_INS_RET:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -regsz;
		op->cycles = CYCLE_MEM + CYCLE_JMP;
		break;
	case X86_INS_UD0:
	case X86_INS_UD2:
	case X86_INS_INT3:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP; // TRAP
		break;
	case X86_INS_INT1:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->val = 1;
		break;
	case X86_INS_INT:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->val = (int)get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits);
		break;
	case X86_INS_SYSCALL:
	case X86_INS_SYSENTER:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->cycles = CYCLE_JMP;
		break;
	case X86_INS_SYSEXIT:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	case X86_INS_INTO:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		// int4 if overflow bit is set , so this is an optional swi
		op->type |= RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case X86_INS_VMCALL:
	case X86_INS_VMMCALL:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case X86_INS_JL:
	case X86_INS_JLE:
	case X86_INS_JA:
	case X86_INS_JAE:
	case X86_INS_JB:
	case X86_INS_JBE:
	case X86_INS_JCXZ:
	case X86_INS_JECXZ:
	case X86_INS_JRCXZ:
	case X86_INS_JO:
	case X86_INS_JNO:
	case X86_INS_JS:
	case X86_INS_JNS:
	case X86_INS_JP:
	case X86_INS_JNP:
	case X86_INS_JE:
	case X86_INS_JNE:
	case X86_INS_JG:
	case X86_INS_JGE:
	case X86_INS_LOOP:
	case X86_INS_LOOPE:
	case X86_INS_LOOPNE:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = get_imm_reg_value(&INSOP(0), zydx->addr, op->size, a->bits);
		op->fail = zydx->addr + op->size;
		op->cycles = CYCLE_JMP;
		switch (zydx->zydecode->mnemonic) {
		case X86_INS_JL:
		case X86_INS_JLE:
		case X86_INS_JS:
		case X86_INS_JG:
		case X86_INS_JGE:
			op->sign = true;
			break;
		default: break;
		}
		break;
	case X86_INS_CALL:
		op->cycles = CYCLE_JMP + CYCLE_MEM;
		switch (INSOP(0).type) {
		case X86_OP_IMM:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			// TODO: what if UCALL?
			if (INSOP(1).type == X86_OP_IMM) {
				ut64 seg = get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits);
				ut64 off = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, a->bits);
				op->ptr = INSOP(0).mem.disp.value;
				op->jump = (seg << a->seggrn) + off;
			} else {
				op->jump = get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits);
			}
			op->fail = zydx->addr + op->size;
			break;
		case X86_OP_MEM:
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
			op->jump = UT64_MAX;
			op->ptr = INSOP(0).mem.disp.value;
			op->disp = INSOP(0).mem.disp.value;
			op->reg = NULL;
			op->ireg = NULL;
			op->cycles += CYCLE_MEM;
			if (INSOP(0).mem.index == X86_REG_NONE) {
				if (INSOP(0).mem.base != X86_REG_NONE) {
					op->reg = ZydisRegisterGetString(INSOP(0).mem.base);
					op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
				}
			} else {
				op->ireg = ZydisRegisterGetString(INSOP(0).mem.index);
				op->scale = INSOP(0).mem.scale;
			}
			if (INSOP(0).mem.base == X86_REG_RIP) {
				op->ptr += zydx->addr + zydx->zydecode->length;
				op->refptr = 8;
			}
			break;
		case X86_OP_REG:
			op->reg = ZydisRegisterGetString(INSOP(0).reg.value);
			op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
			op->ptr = UT64_MAX;
			op->cycles += CYCLE_REG;
			break;
		case X86_OP_PTR:
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
			op->jump = INSOP(0).ptr.segment * (a->bits) + INSOP(0).ptr.offset;
			op->ptr = INSOP(0).ptr.segment * (a->bits) + INSOP(0).ptr.offset;
			op->disp = INSOP(0).ptr.segment * (a->bits) + INSOP(0).ptr.offset;
			op->reg = NULL;
			op->ireg = NULL;
			op->cycles += CYCLE_MEM;
			op->fail = zydx->addr + op->size;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
			op->jump = UT64_MAX;
			break;
		}
		break;
	case X86_INS_JMP:
		//  TODO: what if UJMP?
		switch (INSOP(0).type) {
		case X86_OP_IMM:
			if (INSOP(1).type == X86_OP_IMM) {
				ut64 seg = get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits);
				ut64 off = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, a->bits);
				op->ptr = INSOP(0).mem.disp.value;
				op->jump = (seg << a->seggrn) + off;
			} else {
				op->jump = get_imm_reg_value(&INSOP(0), zydx->addr, zydx->zydecode->length, a->bits);
				if (a->bits == 16) {
					// https://github.com/capstone-engine/capstone/issues/111
					// according to the x86 manual: the upper two bytes of the EIP register are cleared.
					op->jump &= UT16_MAX;
					op->jump |= (UT64_16U & zydx->addr);
				}
			}
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->cycles = CYCLE_JMP;
			break;
		case X86_OP_MEM:
			op->type = RZ_ANALYSIS_OP_TYPE_MJMP;
			op->ptr = INSOP(0).mem.disp.value;
			op->disp = INSOP(0).mem.disp.value;
			op->reg = NULL;
			op->ireg = NULL;
			op->cycles = CYCLE_JMP + CYCLE_MEM;
			if (INSOP(0).mem.base != X86_REG_NONE) {
				if (INSOP(0).mem.base != X86_REG_NONE) {
					op->reg = ZydisRegisterGetString(INSOP(0).mem.base);
					op->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
				}
			}
			if (INSOP(0).mem.index == X86_REG_NONE) {
				op->ireg = NULL;
			} else {
				op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
				op->ireg = ZydisRegisterGetString(INSOP(0).mem.index);
				op->scale = INSOP(0).mem.scale;
			}
			if (INSOP(0).mem.base == X86_REG_RIP) {
				op->ptr += zydx->addr + zydx->zydecode->length;
				op->refptr = 8;
			}
			break;
		case X86_OP_REG: {
			op->cycles = CYCLE_JMP + CYCLE_REG;
			op->reg = ZydisRegisterGetString(INSOP(0).reg.value);
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
			op->ptr = UT64_MAX;
		} break;
		case X86_OP_PTR: {
			ut64 seg = INSOP(0).ptr.segment;
			ut64 off = INSOP(0).ptr.offset;
			op->ptr = INSOP(0).mem.disp.value;
			op->jump = (seg << a->seggrn) + off;
		} break;
		default: // other?
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			op->ptr = UT64_MAX;
			break;
		}
		break;
	case X86_INS_IN:
	case X86_INS_INSW:
	case X86_INS_INSD:
	case X86_INS_INSB:
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->type2 = 0;
		break;
	case X86_INS_OUT:
	case X86_INS_OUTSB:
	case X86_INS_OUTSD:
	case X86_INS_OUTSW:
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->type2 = 1;
		break;
	case X86_INS_VXORPD:
	case X86_INS_VXORPS:
	case X86_INS_VPXORD:
	case X86_INS_VPXORQ:
	case X86_INS_VPXOR:
	case X86_INS_XORPS:
	case X86_INS_KXORW:
	case X86_INS_PXOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case X86_INS_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		// TODO: Add stack indexing handling chang
		op0_memimmhandle(op, zydx, regsz, a->bits);
		op1_memimmhandle(op, zydx, regsz, a->bits);
		break;
	case X86_INS_OR:
		// The OF and CF flags are cleared; the SF, ZF, and PF flags are
		// set according to the result. The state of the AF flag is
		// undefined.
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		// TODO: Add stack indexing handling chang
		op0_memimmhandle(op, zydx, regsz, a->bits);
		op1_memimmhandle(op, zydx, regsz, a->bits);
		break;
	case X86_INS_INC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->val = 1;
		break;
	case X86_INS_DEC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->val = 1;
		break;
	case X86_INS_NEG:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case X86_INS_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case X86_INS_PSUBB:
	case X86_INS_PSUBW:
	case X86_INS_PSUBD:
	case X86_INS_PSUBQ:
	case X86_INS_PSUBSB:
	case X86_INS_PSUBSW:
	case X86_INS_PSUBUSB:
	case X86_INS_PSUBUSW:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case X86_INS_SUB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op_stackidx(op, zydx, false, a->bits);
		op0_memimmhandle(op, zydx, regsz, a->bits);
		op1_memimmhandle(op, zydx, regsz, a->bits);
		break;
	case X86_INS_SBB:
		// dst = dst - (src + cf)
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case X86_INS_LIDT:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	case X86_INS_SIDT:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	case X86_INS_RDRAND:
	case X86_INS_RDSEED:
	case X86_INS_RDMSR:
	case X86_INS_RDPMC:
	case X86_INS_RDTSC:
	case X86_INS_RDTSCP:
	case X86_INS_CRC32:
	case X86_INS_SHA1MSG1:
	case X86_INS_SHA1MSG2:
	case X86_INS_SHA1NEXTE:
	case X86_INS_SHA1RNDS4:
	case X86_INS_SHA256MSG1:
	case X86_INS_SHA256MSG2:
	case X86_INS_SHA256RNDS2:
	case X86_INS_AESDECLAST:
	case X86_INS_AESDEC:
	case X86_INS_AESENCLAST:
	case X86_INS_AESENC:
	case X86_INS_AESIMC:
	case X86_INS_AESKEYGENASSIST:
		// AES instructions
		op->family = RZ_ANALYSIS_OP_FAMILY_CRYPTO;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV; // XXX
		break;
	case X86_INS_ANDN:
	case X86_INS_ANDPD:
	case X86_INS_ANDPS:
	case X86_INS_ANDNPD:
	case X86_INS_ANDNPS:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case X86_INS_AND:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		// TODO: Add stack register change operation
		op0_memimmhandle(op, zydx, regsz, a->bits);
		op1_memimmhandle(op, zydx, regsz, a->bits);
		break;
	case X86_INS_IDIV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case X86_INS_DIV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case X86_INS_IMUL:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->sign = true;
		break;
	case X86_INS_AAM:
	case X86_INS_MUL:
	case X86_INS_MULX:
	case X86_INS_MULPD:
	case X86_INS_MULPS:
	case X86_INS_MULSD:
	case X86_INS_MULSS:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case X86_INS_PACKSSDW:
	case X86_INS_PACKSSWB:
	case X86_INS_PACKUSWB:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
		break;
	case X86_INS_PADDB:
	case X86_INS_PADDD:
	case X86_INS_PADDW:
	case X86_INS_PADDSB:
	case X86_INS_PADDSW:
	case X86_INS_PADDUSB:
	case X86_INS_PADDUSW:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
		break;
	case X86_INS_XCHG:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case X86_INS_XADD: /* xchg + add */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case X86_INS_FADD:
	case X86_INS_FADDP:
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case X86_INS_ADDPS:
	case X86_INS_ADDSD:
	case X86_INS_ADDSS:
	case X86_INS_ADDSUBPD:
	case X86_INS_ADDSUBPS:
	case X86_INS_ADDPD:
		// The OF, SF, ZF, AF, CF, and PF flags are set according to the
		// result.
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op_stackidx(op, zydx, true, a->bits);
		op->val = get_imm_reg_value(&INSOP(1), zydx->addr, zydx->zydecode->length, a->bits);
		break;
	case X86_INS_ADD:
		// The OF, SF, ZF, AF, CF, and PF flags are set according to the
		// result.
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op_stackidx(op, zydx, true, a->bits);
		op0_memimmhandle(op, zydx, regsz, a->bits);
		op1_memimmhandle(op, zydx, regsz, a->bits);
		break;
	case X86_INS_ADC:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
		/* Direction flag */
	case X86_INS_CLD:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case X86_INS_STD:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case X86_INS_SUBSD: // cvtss2sd
	case X86_INS_CVTSS2SD: // cvtss2sd
		break;
	default: break;
	}

	switch (zydx->zydecode->mnemonic) {
	case X86_INS_PADDB:
	case X86_INS_PADDW:
	case X86_INS_PADDD:
	case X86_INS_PSUBB:
	case X86_INS_PSUBW:
	case X86_INS_PSUBD:
	case X86_INS_PMULHW:
	case X86_INS_PMULLW:
	case X86_INS_PMADDWD:
	case X86_INS_PAND:
	case X86_INS_PANDN:
	case X86_INS_POR:
	case X86_INS_PXOR:
	case X86_INS_PCMPEQB:
	case X86_INS_PCMPEQW:
	case X86_INS_PCMPEQD:
	case X86_INS_PSLLD:
	case X86_INS_PSLLW:
	case X86_INS_PSRLQ:
	case X86_INS_PSUBSB:
	case X86_INS_PSUBSW:
	case X86_INS_PADDQ:
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
		break;
	// SSE1 Instructions:
	case X86_INS_ADDPS:
	case X86_INS_ADDSS:
	case X86_INS_ANDPS:
	case X86_INS_CMPPS:
	case X86_INS_CMPSS:
	case X86_INS_DIVPS:
	case X86_INS_DIVSS:
	case X86_INS_MAXPS:
	case X86_INS_MAXSS:
	case X86_INS_MINPS:
	case X86_INS_MINSS:
	case X86_INS_MULPS:
	case X86_INS_MULSS:
	case X86_INS_ORPS:
	case X86_INS_RSQRTPS:
	case X86_INS_RSQRTSS:
	case X86_INS_SUBPS:
	case X86_INS_SUBSS:
	case X86_INS_SQRTPS:
	case X86_INS_SQRTSS:
	case X86_INS_CVTPI2PS:
	case X86_INS_CVTSS2SI:
	case X86_INS_CVTPS2PI:
	case X86_INS_CVTSI2SS:
	case X86_INS_CVTTPD2DQ:
	case X86_INS_CVTPD2PS:
	case X86_INS_CVTPS2PD:
	case X86_INS_CVTSD2SI:
	case X86_INS_CVTSS2SD:
	case X86_INS_CVTSD2SS:
	case X86_INS_MOVAPD:
	case X86_INS_MOVAPS:
	case X86_INS_MOVD:
	case X86_INS_MOVQ:
	case X86_INS_PMOVMSKB:
	case X86_INS_PSHUFD:
	case X86_INS_PSHUFHW:
	case X86_INS_PSHUFLW:
	case X86_INS_PTEST:
	// SSE3 Instructions:
	case X86_INS_ADDPD:
	case X86_INS_CMPPD:
	// case X86_INS_CMPPS:
	case X86_INS_CVTDQ2PS:
	case X86_INS_CVTPS2DQ:
	case X86_INS_MOVDDUP:
	case X86_INS_MOVSS:
	case X86_INS_RCPPS:
		op->family = RZ_ANALYSIS_OP_FAMILY_SSE;
		break;
	default: break;
	}
}

static inline ZydisMachineMode select_mode(RzAnalysis *a) {
	switch (a->bits) {
	case 64:
		return ZYDIS_MACHINE_MODE_LONG_64;
	case 32:
		return ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
	case 16:
		return ZYDIS_MACHINE_MODE_LONG_COMPAT_16;
	default:
		return 0;
	}
}

static void change_size(RzAnalysis *a, X86ZYDISContext *zydx) {
	for (size_t i = 0; i < zydx->zydecode->operand_count; i++) { // not operand_count_visible to change even the hidden operands
		INSOP(i).size = INSOP(i).size / 8; // Convert from bits to bytes
		if (zydx->zydeop->type == X86_OP_IMM) {
			if (zydx->zydeop->imm.is_relative) {
				zydx->zydeop->size = (a->bits) / 8;
			}
		}
	}
	if (INSOP(1).type == X86_OP_IMM) {
		switch (zydx->zydecode->mnemonic) {
		case X86_INS_XOR:
		case X86_INS_ADD:
		case X86_INS_AND:
		case X86_INS_SUB:
		case X86_INS_MOV:
		case X86_INS_CMP:
		case X86_INS_TEST:
			INSOP(1).size = INSOP(0).size;
		default: break;
		}
	}
}

static int analyze_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	X86ZYDISContext *zydx = (X86ZYDISContext *)a->plugin_data;

	ZydisMachineMode mode = select_mode(a);
	ZydisStackWidth st_mode;

	zydx->omode = mode;
	switch (mode) {
	case ZYDIS_MACHINE_MODE_LONG_64:
		st_mode = ZYDIS_STACK_WIDTH_64;
		break;
	case ZYDIS_MACHINE_MODE_LONG_COMPAT_16:
		st_mode = ZYDIS_STACK_WIDTH_16;
		break;
	default:
		st_mode = ZYDIS_STACK_WIDTH_32;
		break;
	}

	ZydisDecoder decoder;
	ZyanStatus ret = ZydisDecoderInit(&decoder, mode, st_mode);
	if (!ZYAN_SUCCESS(ret)) {
		return 0;
	}
	zydx->addr = addr;
	ZydisDecodedInstruction zydecode;
	ZydisDecodedOperand zydeop[ZYDIS_MAX_OPERAND_COUNT];
	zydx->zydecode = &zydecode;
	zydx->zydeop = zydeop;
	bool check = false;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
		&decoder, buf, len, zydx->zydecode, zydx->zydeop))) {
		check = true;
		break;
	}
	if (!check) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("invalid");
		}
		zydx->zydeop = NULL;
		zydx->zydecode = NULL;
		return 0;
	}
	change_size(a, zydx);
	op->mnemonic = calloc(256, sizeof(char));
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		ZydisFormatter formatter;
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
		ZydisFormatterFormatInstruction(&formatter, zydx->zydecode, zydx->zydeop,
			zydx->zydecode->operand_count, op->mnemonic, 256, addr, NULL);
		ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
	}
	op->cycles = 1;
	op->nopcode = zydx->zydecode->raw.prefix_count + zydx->zydecode->opcode_map;
	op->size = zydx->zydecode->length;
	op->id = zydx->zydecode->mnemonic;
	op->family = RZ_ANALYSIS_OP_FAMILY_CPU; // Almost everything is CPU by default
	op->prefix = 0;
	op->cond = cond_x862r2(zydx->zydecode->mnemonic);
	if (zydx->zydecode->raw.prefixes[0].value == 0xF2) {
		op->prefix |= RZ_ANALYSIS_OP_PREFIX_REPNE;
	} else if (zydx->zydecode->raw.prefixes[0].value == 0xF3) {
		op->prefix |= RZ_ANALYSIS_OP_PREFIX_REP;
	} else if (zydx->zydecode->raw.prefixes[0].value == 0xF0) {
		op->prefix |= RZ_ANALYSIS_OP_PREFIX_LOCK;
		op->family = RZ_ANALYSIS_OP_FAMILY_THREAD; // XXX ?
	}
	anop(a, op, buf, len, zydx);
	set_opdir(op, zydx);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		anop_esil(a, op, buf, len, zydx);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = x86_opex(zydx, mode, a->bits);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		op_fillval(a, op, mode, zydx);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		// x86 RzIL uplifting
		X86ILIns x86_il_ins = {
			.structure = zydx->zydecode,
			.operands = zydx->zydeop,
			.mnem = zydx->zydecode->mnemonic,
			.ins_size = op->size
		};
		rz_x86_il_opcode(a, op, addr + op->size, &x86_il_ins);
	}
	zydx->zydeop = NULL;
	zydx->zydecode = NULL;
	return op->size;
}

static bool x86_init(void **user) {
	X86ZYDISContext *zydx = RZ_NEW0(X86ZYDISContext);
	if (!zydx) {
		return false;
	}
	*user = zydx;
	return true;
}

static bool x86_fini(void *user) {
	rz_return_val_if_fail(user, false);
	X86ZYDISContext *zydx = (X86ZYDISContext *)user;
	free(zydx);
	return true;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p = NULL;
	switch (analysis->bits) {
	case 16: p =
			 "=PC	ip\n"
			 "=SP	sp\n"
			 "=BP	bp\n"
			 "=A0	ax\n"
			 "=A1	bx\n"
			 "=A2	cx\n"
			 "=A3	dx\n"
			 "=A4	si\n"
			 "=A5	di\n"
			 "=SN	ah\n"
			 "gpr	ip	.16	48	0\n"
			 "gpr	ax	.16	24	0\n"
			 "gpr	ah	.8	25	0\n"
			 "gpr	al	.8	24	0\n"
			 "gpr	bx	.16	0	0\n"
			 "gpr	bh	.8	1	0\n"
			 "gpr	bl	.8	0	0\n"
			 "gpr	cx	.16	4	0\n"
			 "gpr	ch	.8	5	0\n"
			 "gpr	cl	.8	4	0\n"
			 "gpr	dx	.16	8	0\n"
			 "gpr	dh	.8	9	0\n"
			 "gpr	dl	.8	8	0\n"
			 "gpr	sp	.16	60	0\n"
			 "gpr	bp	.16	20	0\n"
			 "gpr	si	.16	12	0\n"
			 "gpr	di	.16	16	0\n"
			 "seg	cs	.16	52	0\n"
			 "seg	ss	.16	54	0\n"
			 "seg	ds	.16	56	0\n"
			 "seg	es	.16	58	0\n"
			 "gpr	flags	.16	56	0\n"
			 "flg	cf	.1	.448	0\n"
			 "flg	pf	.1	.450	0\n"
			 "flg	af	.1	.452	0\n"
			 "flg	zf	.1	.454	0\n"
			 "flg	sf	.1	.455	0\n"
			 "flg	tf	.1	.456	0\n"
			 "flg	if	.1	.457	0\n"
			 "flg	df	.1	.458	0\n"
			 "flg	of	.1	.459	0\n"
			 "flg	nt	.1	.462	0\n";
#if 0
		"drx	dr0	.32	0	0\n"
		"drx	dr1	.32	4	0\n"
		"drx	dr2	.32	8	0\n"
		"drx	dr3	.32	12	0\n"
		//"drx	dr4	.32	16	0\n"
		//"drx	dr5	.32	20	0\n"
		"drx	dr6	.32	24	0\n"
		"drx	dr7	.32	28	0\n"
#endif
		break;
	case 32:
		p =
			"=PC	eip\n"
			"=SP	esp\n"
			"=BP	ebp\n"
			"=A0	eax\n"
			"=A1	ebx\n"
			"=A2	ecx\n"
			"=A3	edx\n"
			"=A4	esi\n"
			"=A5	edi\n"
			"=SN	eax\n"
			"gpr	oeax	.32	44	0\n"
			"gpr	eax	.32	24	0\n"
			"gpr	ax	.16	24	0\n"
			"gpr	ah	.8	25	0\n"
			"gpr	al	.8	24	0\n"
			"gpr	ebx	.32	0	0\n"
			"gpr	bx	.16	0	0\n"
			"gpr	bh	.8	1	0\n"
			"gpr	bl	.8	0	0\n"
			"gpr	ecx	.32	4	0\n"
			"gpr	cx	.16	4	0\n"
			"gpr	ch	.8	5	0\n"
			"gpr	cl	.8	4	0\n"
			"gpr	edx	.32	8	0\n"
			"gpr	dx	.16	8	0\n"
			"gpr	dh	.8	9	0\n"
			"gpr	dl	.8	8	0\n"
			"gpr	esi	.32	12	0\n"
			"gpr	si	.16	12	0\n"
			"gpr	edi	.32	16	0\n"
			"gpr	di	.16	16	0\n"
			"gpr	esp	.32	60	0\n"
			"gpr	sp	.16	60	0\n"
			"gpr	ebp	.32	20	0\n"
			"gpr	bp	.16	20	0\n"
			"gpr	eip	.32	48	0\n"
			"gpr	ip	.16	48	0\n"
			"seg	xds	.32	28	0\n"
			"seg	ds	.16	28	0\n"
			"seg	xes	.32	32	0\n"
			"seg	es	.16	32	0\n"
			"seg	xfs	.32	36	0\n"
			"seg	fs	.16	36	0\n"
			"seg	xgs	.32	40	0\n"
			"seg	gs	.16	40	0\n"
			"seg	xss	.32	64	0\n"
			"seg	ss	.16	64	0\n"
			"seg	xcs	.32	52	0\n"
			"seg	cs	.16	52	0\n"
			"flg	eflags	.32	.448	0	c1p.a.zstido.n.rv\n"
			"flg	flags	.16	.448	0\n"
			"flg	cf	.1	.448	0\n"
			"flg	pf	.1	.450	0\n"
			"flg	af	.1	.452	0\n"
			"flg	zf	.1	.454	0\n"
			"flg	sf	.1	.455	0\n"
			"flg	tf	.1	.456	0\n"
			"flg	if	.1	.457	0\n"
			"flg	df	.1	.458	0\n"
			"flg	of	.1	.459	0\n"
			"flg	nt	.1	.462	0\n"
			"flg	rf	.1	.464	0\n"
			"flg	vm	.1	.465	0\n"
			"flg	ac	.1	.466	0\n"
			"drx	dr0	.32	0	0\n"
			"drx	dr1	.32	4	0\n"
			"drx	dr2	.32	8	0\n"
			"drx	dr3	.32	12	0\n"
			"drx	dr4	.32	16	0\n"
			"drx	dr5	.32	20	0\n"
			"drx	dr6	.32	24	0\n"
			"drx	dr7	.32	28	0\n"
			"ctr	cr0	.32	0	0\n"
			"ctr	cr1	.32	4	0\n"
			"ctr	cr2	.32	8	0\n"
			"ctr	cr3	.32	12	0\n"
			"ctr	cr4	.32	16	0\n"
			"ctr	cr5	.32	20	0\n"
			"ctr	cr6	.32	24	0\n"
			"ctr	cr7	.32	28	0\n"
			"xmm@fpu    xmm0  .128 160  4\n"
			"fpu    xmm0l .64 160  0\n"
			"fpu    xmm0h .64 168  0\n"

			"xmm@fpu    xmm1  .128 176  4\n"
			"fpu    xmm1l .64 176  0\n"
			"fpu    xmm1h .64 184  0\n"

			"xmm@fpu    xmm2  .128 192  4\n"
			"fpu    xmm2l .64 192  0\n"
			"fpu    xmm2h .64 200  0\n"

			"xmm@fpu    xmm3  .128 208  4\n"
			"fpu    xmm3l .64 208  0\n"
			"fpu    xmm3h .64 216  0\n"

			"xmm@fpu    xmm4  .128 224  4\n"
			"fpu    xmm4l .64 224  0\n"
			"fpu    xmm4h .64 232  0\n"

			"xmm@fpu    xmm5  .128 240  4\n"
			"fpu    xmm5l .64 240  0\n"
			"fpu    xmm5h .64 248  0\n"

			"xmm@fpu    xmm6  .128 256  4\n"
			"fpu    xmm6l .64 256  0\n"
			"fpu    xmm6h .64 264  0\n"

			"xmm@fpu    xmm7  .128 272  4\n"
			"fpu    xmm7l .64 272  0\n"
			"fpu    xmm7h .64 280  0\n";

		break;
	case 64: {
		const char *cc = rz_analysis_cc_default(analysis);
		const char *args_prof = cc && !strcmp(cc, "ms")
			? // Microsoft x64 CC
			"# RAX     return value\n"
			"# RCX     argument 1\n"
			"# RDX     argument 2\n"
			"# R8      argument 3\n"
			"# R9      argument 4\n"
			"# R10-R11 syscall/sysret\n"
			"# R12-R15 GP preserved\n"
			"# RSI     preserved source\n"
			"# RDI     preserved destination\n"
			"# RSP     stack pointer\n"
			"=PC	rip\n"
			"=SP	rsp\n"
			"=BP	rbp\n"
			"=A0	rcx\n"
			"=A1	rdx\n"
			"=A2	r8\n"
			"=A3	r9\n"
			"=SN	rax\n"
			: // System V AMD64 ABI
			"=PC	rip\n"
			"=SP	rsp\n"
			"=BP	rbp\n"
			"=A0	rdi\n"
			"=A1	rsi\n"
			"=A2	rdx\n"
			"=A3	rcx\n"
			"=A4	r8\n"
			"=A5	r9\n"
			"=A6	r10\n"
			"=A7	r11\n"
			"=SN	rax\n";
		char *prof = rz_str_newf("%s%s", args_prof,
			"gpr	rax	.64	80	0\n"
			"gpr	eax	.32	80	0\n"
			"gpr	ax	.16	80	0\n"
			"gpr	al	.8	80	0\n"
			"gpr	ah	.8	81	0\n"
			"gpr	rbx	.64	40	0\n"
			"gpr	ebx	.32	40	0\n"
			"gpr	bx	.16	40	0\n"
			"gpr	bl	.8	40	0\n"
			"gpr	bh	.8	41	0\n"
			"gpr	rcx	.64	88	0\n"
			"gpr	ecx	.32	88	0\n"
			"gpr	cx	.16	88	0\n"
			"gpr	cl	.8	88	0\n"
			"gpr	ch	.8	89	0\n"
			"gpr	rdx	.64	96	0\n"
			"gpr	edx	.32	96	0\n"
			"gpr	dx	.16	96	0\n"
			"gpr	dl	.8	96	0\n"
			"gpr	dh	.8	97	0\n"
			"gpr	rsi	.64	104	0\n"
			"gpr	esi	.32	104	0\n"
			"gpr	si	.16	104	0\n"
			"gpr	sil	.8	104	0\n"
			"gpr	rdi	.64	112	0\n"
			"gpr	edi	.32	112	0\n"
			"gpr	di	.16	112	0\n"
			"gpr	dil	.8	112	0\n"
			"gpr	r8	.64	72	0\n"
			"gpr	r8d	.32	72	0\n"
			"gpr	r8w	.16	72	0\n"
			"gpr	r8b	.8	72	0\n"
			"gpr	r9	.64	64	0\n"
			"gpr	r9d	.32	64	0\n"
			"gpr	r9w	.16	64	0\n"
			"gpr	r9b	.8	64	0\n"
			"gpr	r10	.64	56	0\n"
			"gpr	r10d	.32	56	0\n"
			"gpr	r10w	.16	56	0\n"
			"gpr	r10b	.8	56	0\n"
			"gpr	r11	.64	48	0\n"
			"gpr	r11d	.32	48	0\n"
			"gpr	r11w	.16	48	0\n"
			"gpr	r11b	.8	48	0\n"
			"gpr	r12	.64	24	0\n"
			"gpr	r12d	.32	24	0\n"
			"gpr	r12w	.16	24	0\n"
			"gpr	r12b	.8	24	0\n"
			"gpr	r13	.64	16	0\n"
			"gpr	r13d	.32	16	0\n"
			"gpr	r13w	.16	16	0\n"
			"gpr	r13b	.8	16	0\n"
			"gpr	r14	.64	8	0\n"
			"gpr	r14d	.32	8	0\n"
			"gpr	r14w	.16	8	0\n"
			"gpr	r14b	.8	8	0\n"
			"gpr	r15	.64	0	0\n"
			"gpr	r15d	.32	0	0\n"
			"gpr	r15w	.16	0	0\n"
			"gpr	r15b	.8	0	0\n"
			"gpr	rip	.64	128	0\n"
			"gpr	rbp	.64	32	0\n"
			"gpr	ebp	.32	32	0\n"
			"gpr	bp	.16	32	0\n"
			"gpr	bpl	.8	32	0\n"
			"seg	cs	.64	136	0\n"
			"flg	rflags	.64	144	0	c1p.a.zstido.n.rv\n"
			"flg	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
			"flg	cf	.1	144.0	0	carry\n"
			"flg	pf	.1	144.2	0	parity\n"
			//"gpr	cf	.1	.1152	0	carry\n"
			//"gpr	pf	.1	.1154	0	parity\n"
			"flg	af	.1	144.4	0	adjust\n"
			"flg	zf	.1	144.6	0	zero\n"
			"flg	sf	.1	144.7	0	sign\n"
			"flg	tf	.1	.1160	0	trap\n"
			"flg	if	.1	.1161	0	interrupt\n"
			"flg	df	.1	.1162	0	direction\n"
			"flg	of	.1	.1163	0	overflow\n"
			"flg	nt	.1	.1166	0\n"
			"flg	rf	.1	.1168	0\n"
			"flg	vm	.1	.1169	0\n"
			"flg	ac	.1	.1170	0\n"

			"gpr	rsp	.64	152	0\n"
			"gpr	esp	.32	152	0\n"
			"gpr	sp	.16	152	0\n"
			"gpr	spl	.8	152	0\n"
			"seg	ss	.64	160	0\n"
			"seg	fs_base	.64	168	0\n"
			"seg	gs_base	.64	176	0\n"
			"seg	ds	.64	184	0\n"
			"seg	es	.64	192	0\n"
			"seg	fs	.64	200	0\n"
			"seg	gs	.64	208	0\n"
			"drx	dr0	.64	0	0\n"
			"drx	dr1	.64	8	0\n"
			"drx	dr2	.64	16	0\n"
			"drx	dr3	.64	24	0\n"
			"drx	dr4	.64	32	0\n"
			"drx	dr5	.64	40	0\n"
			"drx	dr6	.64	48	0\n"
			"drx	dr7	.64	56	0\n"
			"ctr	cr0	.64	0	0\n"
			"ctr	cr1	.64	8	0\n"
			"ctr	cr2	.64	16	0\n"
			"ctr	cr3	.64	24	0\n"
			"ctr	cr4	.64	32	0\n"
			"ctr	cr5	.64	40	0\n"
			"ctr	cr6	.64	48	0\n"
			"ctr	cr7	.64	56	0\n"

			/*0030 struct user_fpregs_struct
		   0031 {
		   0032   __uint16_t        cwd;
		   0033   __uint16_t        swd;
		   0034   __uint16_t        ftw;
		   0035   __uint16_t        fop;
		   0036   __uint64_t        rip;
		   0037   __uint64_t        rdp;
		   0038   __uint32_t        mxcsr;
		   0039   __uint32_t        mxcr_mask;
		   0040   __uint32_t        st_space[32];   // 8*16 bytes for each FP-reg = 128 bytes
		   0041   __uint32_t        xmm_space[64];  // 16*16 bytes for each XMM-reg = 256 bytes
		   0042   __uint32_t        padding[24];
		   0043 };
		  */
			"fpu    cwd .16 0   0\n"
			"fpu    swd .16 2   0\n"
			"fpu    ftw .16 4   0\n"
			"fpu    fop .16 6   0\n"
			"fpu    frip .64 8   0\n"
			"fpu    frdp .64 16  0\n"
			"fpu    mxcsr .32 24  0\n"
			"fpu    mxcr_mask .32 28  0\n"

			"fpu    st0 .80 32  0\n"
			"fpu    st1 .80 48  0\n"
			"fpu    st2 .80 64  0\n"
			"fpu    st3 .80 80  0\n"
			"fpu    st4 .80 96  0\n"
			"fpu    st5 .80 112  0\n"
			"fpu    st6 .80 128  0\n"
			"fpu    st7 .80 144  0\n"

			"xmm@fpu    xmm0  .128 160  4\n"
			"fpu    xmm0l .64 160  0\n"
			"fpu    xmm0h .64 168  0\n"

			"xmm@fpu    xmm1  .128 176  4\n"
			"fpu    xmm1l .64 176  0\n"
			"fpu    xmm1h .64 184  0\n"

			"xmm@fpu    xmm2  .128 192  4\n"
			"fpu    xmm2l .64 192  0\n"
			"fpu    xmm2h .64 200  0\n"

			"xmm@fpu    xmm3  .128 208  4\n"
			"fpu    xmm3l .64 208  0\n"
			"fpu    xmm3h .64 216  0\n"

			"xmm@fpu    xmm4  .128 224  4\n"
			"fpu    xmm4l .64 224  0\n"
			"fpu    xmm4h .64 232  0\n"

			"xmm@fpu    xmm5  .128 240  4\n"
			"fpu    xmm5l .64 240  0\n"
			"fpu    xmm5h .64 248  0\n"

			"xmm@fpu    xmm6  .128 256  4\n"
			"fpu    xmm6l .64 256  0\n"
			"fpu    xmm6h .64 264  0\n"

			"xmm@fpu    xmm7  .128 272  4\n"
			"fpu    xmm7l .64 272  0\n"
			"fpu    xmm7h .64 280  0\n"
			"fpu    x64   .64 288  0\n");
		return prof;
	}
#if 0
	default: p= /* XXX */
		 "=PC	rip\n"
		 "=SP	rsp\n"
		 "=BP	rbp\n"
		 "=A0	rax\n"
		 "=A1	rbx\n"
		 "=A2	rcx\n"
		 "=A3	rdx\n"
		 "# no profile defined for x86-64\n"
		 "gpr	r15	.64	0	0\n"
		 "gpr	r14	.64	8	0\n"
		 "gpr	r13	.64	16	0\n"
		 "gpr	r12	.64	24	0\n"
		 "gpr	rbp	.64	32	0\n"
		 "gpr	ebp	.32	32	0\n"
		 "gpr	rbx	.64	40	0\n"
		 "gpr	ebx	.32	40	0\n"
		 "gpr	bx	.16	40	0\n"
		 "gpr	bh	.8	41	0\n"
		 "gpr	bl	.8	40	0\n"
		 "gpr	r11	.64	48	0\n"
		 "gpr	r10	.64	56	0\n"
		 "gpr	r9	.64	64	0\n"
		 "gpr	r8	.64	72	0\n"
		 "gpr	rax	.64	80	0\n"
		 "gpr	eax	.32	80	0\n"
		 "gpr	rcx	.64	88	0\n"
		 "gpr	ecx	.32	88	0\n"
		 "gpr	rdx	.64	96	0\n"
		 "gpr	edx	.32	96	0\n"
		 "gpr	rsi	.64	104	0\n"
		 "gpr	esi	.32	104	0\n"
		 "gpr	rdi	.64	112	0\n"
		 "gpr	edi	.32	112	0\n"
		 "gpr	oeax	.64	120	0\n"
		 "gpr	rip	.64	128	0\n"
		 "seg	cs	.64	136	0\n"
		 //"flg	eflags	.64	144	0\n"
		 "gpr	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
		 "flg	cf	.1	.1152	0\n"
		 "flg	pf	.1	.1153	0\n"
		 "flg	af	.1	.1154	0\n"
		 "flg	zf	.1	.1155	0\n"
		 "flg	sf	.1	.1156	0\n"
		 "flg	tf	.1	.1157	0\n"
		 "flg	if	.1	.1158	0\n"
		 "flg	df	.1	.1159	0\n"
		 "flg	of	.1	.1160	0\n"
		 "flg	rf	.1	.1161	0\n"
		 "gpr	rsp	.64	152	0\n"
		 "seg	ss	.64	160	0\n"
		 "seg	fs_base	.64	168	0\n"
		 "seg	gs_base	.64	176	0\n"
		 "seg	ds	.64	184	0\n"
		 "seg	es	.64	192	0\n"
		 "seg	fs	.64	200	0\n"
		 "seg	gs	.64	208	0\n"
		 "drx	dr0	.32	0	0\n"
		 "drx	dr1	.32	4	0\n"
		 "drx	dr2	.32	8	0\n"
		 "drx	dr3	.32	12	0\n"
		 "drx	dr6	.32	24	0\n"
		 "drx	dr7	.32	28	0\n";
		 break;
#endif
	}
	return rz_str_dup(p);
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 16;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

static RzList /*<RzSearchKeyword *>*/ *analysis_preludes(RzAnalysis *analysis) {
#define KW(d, ds, m, ms) rz_list_append(l, rz_search_keyword_new((const ut8 *)d, ds, (const ut8 *)m, ms, NULL))
	RzList *l = rz_list_newf((RzListFree)rz_search_keyword_free);
	switch (analysis->bits) {
	case 32:
		KW("\x8b\xff\x55\x8b\xec", 5, NULL, 0);
		KW("\x55\x89\xe5", 3, NULL, 0);
		KW("\x55\x8b\xec", 3, NULL, 0);
		KW("\xf3\x0f\x1e\xfb", 4, NULL, 0); // endbr32
		break;
	case 64:
		KW("\x55\x48\x89\xe5", 4, NULL, 0);
		KW("\x55\x48\x8b\xec", 4, NULL, 0);
		KW("\xf3\x0f\x1e\xfa", 4, NULL, 0); // endbr64
		break;
	default:
		rz_list_free(l);
		l = NULL;
		break;
	}
	return l;
}

static int esil_x86_zydis_init(RzAnalysisEsil *esil) {
	if (!esil) {
		return false;
	}
	// XXX. this depends on kernel
	// rz_analysis_esil_set_interrupt (esil, 0x80, x86_int_0x80);
	/* disable by default */
	//	rz_analysis_esil_set_interrupt (esil, 0x80, NULL,addr);	// this is stupid, don't do this
	return true;
}

static int esil_x86_zydis_fini(RzAnalysisEsil *esil) {
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_x86_zydis = {
	.name = "x86",
	.desc = "Zydis X86 analysis",
	.esil = true,
	.license = "MIT",
	.arch = "x86",
	.bits = 16 | 32 | 64,
	.op = &analyze_op,
	.preludes = analysis_preludes,
	.archinfo = archinfo,
	.get_reg_profile = &get_reg_profile,
	.init = x86_init,
	.fini = x86_fini,
	.esil_init = esil_x86_zydis_init,
	.esil_fini = esil_x86_zydis_fini,
	.il_config = rz_x86_il_config
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_x86_zydis,
	.version = RZ_VERSION,
};
#endif
