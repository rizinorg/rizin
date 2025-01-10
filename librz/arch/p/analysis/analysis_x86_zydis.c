// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText : 2024 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_lib.h>
#include <Zydis.h>
#include <x86/x86_il.h>

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

#define opexprintf(op, fmt, ...) rz_strbuf_setf(&op->opex, fmt, ##__VA_ARGS__)
#define INSOP(n)                 zydeop[n]
#define INSOPS                   zydecode->operand_count_visible
#define ISIMM(x)                 zydeop[x].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
#define ISMEM(x)                 zydeop[x].type == ZYDIS_OPERAND_TYPE_MEMORY

typedef struct zydis_x86_context_t {
	char buf[AR_DIM][BUF_SZ];
	ZydisMachineMode omode;
	ZydisDecodedInstruction *zydecode;
	ZydisDecodedOperand *zydeop;
} X86ZYDISContext;

struct Getarg {
	ZydisDecodedInstruction *zydecode;
	ZydisDecodedOperand *zydeop;
	int bits;
};

static inline ut64 get_imm_reg_value(ZydisDecodedOperand *zydeop, ut64 addr, ut64 op_size) {
	return (zydeop->imm.is_relative ? (zydeop->imm.value.s + addr + op_size) : zydeop->imm.value.u);
}

static void hidden_op(ZydisDecodedInstruction *zydecode, ZydisDecodedOperand *zydeop, int mode) {
	unsigned int mnemonic = zydecode->mnemonic;
	int regsz = 4;
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
	case ZYDIS_MNEMONIC_PUSHF:
	case ZYDIS_MNEMONIC_POPF:
	case ZYDIS_MNEMONIC_PUSHFD:
	case ZYDIS_MNEMONIC_POPFD:
	case ZYDIS_MNEMONIC_PUSHFQ:
	case ZYDIS_MNEMONIC_POPFQ:
		zydecode->operand_count = 1;
		ZydisDecodedOperand *op = &zydeop[0];
		op->type = ZYDIS_OPERAND_TYPE_REGISTER;
		op->reg.value = ZYDIS_REGISTER_EFLAGS;
		op->size = regsz;
		if (mnemonic == ZYDIS_MNEMONIC_PUSHF || mnemonic == ZYDIS_MNEMONIC_PUSHFD || mnemonic == ZYDIS_MNEMONIC_PUSHFQ) {
			op->visibility = ZYDIS_OPERAND_VISIBILITY_EXPLICIT;
		} else {
			op->visibility = ZYDIS_OPERAND_VISIBILITY_HIDDEN;
		}
		break;
	default:
		break;
	}
}

static void opex(RzStrBuf *buf, X86ZYDISContext *zydx, int mode, ut64 addr) {
	ZydisDecodedInstruction *zydecode = zydx->zydecode;
	ZydisDecodedOperand *zydeop = zydx->zydeop;
	int i;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	if (zydecode->operand_count == 0) {
		hidden_op(zydecode, zydeop, mode);
	}
	pj_ka(pj, "operands");
	for (i = 0; i < zydecode->operand_count; i++) {
		ZydisDecodedOperand *op = zydeop + i;
		pj_o(pj);
		pj_ki(pj, "size", op->size);
		pj_ki(pj, "rw", op->visibility);
		switch (op->type) {
		case ZYDIS_OPERAND_TYPE_REGISTER:
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", ZydisRegisterGetString(op->reg.value));
			break;
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			pj_ks(pj, "type", "imm");
			pj_kN(pj, "value", get_imm_reg_value(op, addr, zydecode->length));
			break;
		case ZYDIS_OPERAND_TYPE_MEMORY:
			pj_ks(pj, "type", "mem");
			if (op->mem.segment != ZYDIS_REGISTER_NONE) {
				pj_ks(pj, "segment", ZydisRegisterGetString(op->mem.segment));
			}
			if (op->mem.base != ZYDIS_REGISTER_NONE) {
				pj_ks(pj, "base", ZydisRegisterGetString(op->mem.base));
			}
			if (op->mem.index != ZYDIS_REGISTER_NONE) {
				pj_ks(pj, "index", ZydisRegisterGetString(op->mem.index));
			}
			break;
		default:
			pj_ks(pj, "type", "invalid");
			break;
		}
		pj_end(pj);
	}
	pj_end(pj);
	if (zydecode->attributes & ZYDIS_ATTRIB_HAS_REX) {
		pj_kb(pj, "rex", true);
	}
	if (zydecode->raw.modrm.mod != 0) {
		pj_kb(pj, "modrm", true);
	}
	if (zydecode->raw.sib.scale != 0 || zydecode->raw.sib.index != 0 || zydecode->raw.sib.offset != 0 || zydecode->raw.sib.base != 0) {
		pj_ki(pj, "sib", zydecode->raw.sib.base + (zydecode->raw.sib.index * zydecode->raw.sib.scale) + zydecode->raw.sib.offset);
	}
	if (zydecode->raw.disp.value != 0) {
		pj_ki(pj, "disp", zydecode->raw.disp.value);
	}
	if (zydecode->raw.sib.index != ZYDIS_REGISTER_NONE) {
		pj_ki(pj, "sib_scale", zydecode->raw.sib.scale);
		pj_ks(pj, "sib_index", ZydisRegisterGetString(zydecode->raw.sib.index));
	}
	if (zydecode->raw.sib.base != ZYDIS_REGISTER_NONE) {
		pj_ks(pj, "sib_base", ZydisRegisterGetString(zydecode->raw.sib.base));
	}
	pj_end(pj);
}

static bool is_xmm_reg(ZydisDecodedOperand op) {
	switch (op.reg.value) {
	case ZYDIS_REGISTER_XMM0:
	case ZYDIS_REGISTER_XMM1:
	case ZYDIS_REGISTER_XMM2:
	case ZYDIS_REGISTER_XMM3:
	case ZYDIS_REGISTER_XMM4:
	case ZYDIS_REGISTER_XMM5:
	case ZYDIS_REGISTER_XMM6:
	case ZYDIS_REGISTER_XMM7:
	case ZYDIS_REGISTER_XMM8:
	case ZYDIS_REGISTER_XMM9:
	case ZYDIS_REGISTER_XMM10:
	case ZYDIS_REGISTER_XMM11:
	case ZYDIS_REGISTER_XMM12:
	case ZYDIS_REGISTER_XMM13:
	case ZYDIS_REGISTER_XMM14:
	case ZYDIS_REGISTER_XMM15:
	case ZYDIS_REGISTER_XMM16:
	case ZYDIS_REGISTER_XMM17:
	case ZYDIS_REGISTER_XMM18:
	case ZYDIS_REGISTER_XMM19:
	case ZYDIS_REGISTER_XMM20:
	case ZYDIS_REGISTER_XMM21:
	case ZYDIS_REGISTER_XMM22:
	case ZYDIS_REGISTER_XMM23:
	case ZYDIS_REGISTER_XMM24:
	case ZYDIS_REGISTER_XMM25:
	case ZYDIS_REGISTER_XMM26:
	case ZYDIS_REGISTER_XMM27:
	case ZYDIS_REGISTER_XMM28:
	case ZYDIS_REGISTER_XMM29:
	case ZYDIS_REGISTER_XMM30:
	case ZYDIS_REGISTER_XMM31: return true;
	default: return false;
	}
}

static char *getarg(RzAnalysis *a, struct Getarg *gop, int n, int set, char *setop, int sel, ut32 *bitsize, ut64 addr) {
	X86ZYDISContext *zydx = (X86ZYDISContext *)a->plugin_data;
	char *out = zydx->buf[sel];
	char *setarg = setop ? setop : "";
	ZydisDecodedInstruction *zydecode = gop->zydecode;
	ZydisDecodedOperand *zydeop = gop->zydeop;
	if (!zydecode) {
		return NULL;
	}
	if (n < 0 || n >= zydecode->operand_count) {
		return NULL;
	}
	out[0] = 0;
	ZydisDecodedOperand op = zydeop[n];
	if (bitsize) {
		*bitsize = op.size * 8;
	}
	switch (op.type) {
	case ZYDIS_REGISTER_NONE:
		return "invalid";
	case ZYDIS_OPERAND_TYPE_REGISTER:
		if (set == 1) {
			snprintf(out, BUF_SZ, "%s,%s=", ZydisRegisterGetString(op.reg.value), setarg);
			return out;
		}
		return (char *)ZydisRegisterGetString(op.reg.value);
	case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
		if (set == 1) {
			snprintf(out, BUF_SZ, "%" PFMT64u ",%s=[%d]", get_imm_reg_value(&op, addr, zydx->zydecode->length), setarg, op.size);
			return out;
		}
		snprintf(out, BUF_SZ, "%" PFMT64u, get_imm_reg_value(&op, addr, zydx->zydecode->length));
		return out;
	}
	case ZYDIS_OPERAND_TYPE_MEMORY: {
		char buf_[BUF_SZ] = { 0 };
		int component_count = 0;
		const char *base = ZydisRegisterGetString(op.mem.base);
		const char *index = ZydisRegisterGetString(op.mem.index);
		int scale = op.mem.scale;
		st64 disp = op.mem.disp.value;

		if (disp != 0) {
			snprintf(out, BUF_SZ, "0x%" PFMT64x ",", (disp < 0) ? -disp : disp);
			component_count++;
		}

		if (index != "none") {
			if (scale > 1) {
				rz_strf(buf_, "%s%s,%d,*,", out, index, scale);
			} else {
				rz_strf(buf_, "%s%s,", out, index);
			}
			strncpy(out, buf_, BUF_SZ);
			component_count++;
		}

		if (base != "none") {
			rz_strf(buf_, "%s%s,", out, base);
			strncpy(out, buf_, BUF_SZ);
			component_count++;
		}

		if (component_count > 1) {
			if (component_count > 2) {
				rz_strf(buf_, "%s+,", out);
				strncpy(out, buf_, BUF_SZ);
			}
			if (disp < 0) {
				rz_strf(buf_, "%s-", out);
			} else {
				rz_strf(buf_, "%s+", out);
			}
			strncpy(out, buf_, BUF_SZ);
		} else {
			// Remove the trailing ',' from esil statement.
			if (*out) {
				int out_len = strlen(out);
				out[out_len > 0 ? out_len - 1 : 0] = 0;
			}
		}

		// set = 2 is reserved for lea, where the operand is a memory address,
		// but the corresponding memory is not loaded.
		if (set == 1) {
			rz_strf(buf_, "%s,%s=[%d]", out, setarg, op.size == 10 ? 8 : op.size);
			strncpy(out, buf_, BUF_SZ);
		} else if (set == 0) {
			if (!*out) {
				strcpy(out, "0");
			}
			rz_strf(buf_, "%s,[%d]", out, op.size == 10 ? 8 : op.size);
			strncpy(out, buf_, BUF_SZ);
		}
		out[BUF_SZ - 1] = 0;
		return out;
	}
	}
	return NULL;
}

static int cond_x862r2(ZydisMnemonic mnemonic) {
	// TODO : Some cases to be handled
	switch (mnemonic) {
	case ZYDIS_MNEMONIC_JZ: // Should be JE but JE is alias of JZ
		return RZ_TYPE_COND_EQ;
	case ZYDIS_MNEMONIC_JNZ:
		return RZ_TYPE_COND_NE;
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JL:
		return RZ_TYPE_COND_LT;
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JLE:
		return RZ_TYPE_COND_LE;
	case ZYDIS_MNEMONIC_JNBE:
		return RZ_TYPE_COND_GT;
	case ZYDIS_MNEMONIC_JNLE:
		return RZ_TYPE_COND_GE;
	case ZYDIS_MNEMONIC_JNB:
		return RZ_TYPE_COND_GE;
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
		break;
	}
	return 0;
}

/* reg indices are based on Intel doc for 32-bit ModR/M byte */
static const char *reg32_to_name(ut8 reg) {
	const char *const names[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
	return reg < RZ_ARRAY_SIZE(names) ? names[reg] : "unk";
}

static void anop_esil(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, ZydisDecodedInstruction *zydecode, ZydisDecodedOperand *zydeop) {
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
		.zydecode = zydecode,
		.zydeop = zydeop,
		.bits = a->bits
	};
	char *src;
	char *src2;
	char *dst;
	char *dst2;
	char *dst_r;
	char *dst_w;
	char *dstAdd;
	char *arg0;
	char *arg1;
	char *arg2;

	// counter for rep prefix
	const char *counter = (a->bits == 16) ? "cx" : (a->bits == 32) ? "ecx"
								       : "rcx";

	if (op->prefix & RZ_ANALYSIS_OP_PREFIX_REP) {
		esilprintf(op, "%s,!,?{,BREAK,},", counter);
	}

	switch (zydecode->mnemonic) {
	case ZYDIS_MNEMONIC_FNOP:
	case ZYDIS_MNEMONIC_NOP:
	case ZYDIS_MNEMONIC_PAUSE:
		esilprintf(op, ",");
		break;
	case ZYDIS_MNEMONIC_HLT:
		break;
	case ZYDIS_MNEMONIC_FBLD:
	case ZYDIS_MNEMONIC_FBSTP:
	case ZYDIS_MNEMONIC_FCOMPP:
	case ZYDIS_MNEMONIC_FDECSTP:
	case ZYDIS_MNEMONIC_FEMMS:
	case ZYDIS_MNEMONIC_FFREE:
	case ZYDIS_MNEMONIC_FICOM:
	case ZYDIS_MNEMONIC_FICOMP:
	case ZYDIS_MNEMONIC_FINCSTP:
	case ZYDIS_MNEMONIC_FNCLEX:
	case ZYDIS_MNEMONIC_FNINIT:
	case ZYDIS_MNEMONIC_FNSTCW:
	case ZYDIS_MNEMONIC_FNSTSW:
	case ZYDIS_MNEMONIC_FPATAN:
	case ZYDIS_MNEMONIC_FPREM:
	case ZYDIS_MNEMONIC_FPREM1:
	case ZYDIS_MNEMONIC_FPTAN:
	case ZYDIS_MNEMONIC_FFREEP:
	case ZYDIS_MNEMONIC_FRNDINT:
	case ZYDIS_MNEMONIC_FRSTOR:
	case ZYDIS_MNEMONIC_FNSAVE:
	case ZYDIS_MNEMONIC_FSCALE:
	case ZYDIS_MNEMONIC_FSETPM287_NOP:
	case ZYDIS_MNEMONIC_FSINCOS:
	case ZYDIS_MNEMONIC_FNSTENV:
	case ZYDIS_MNEMONIC_FXAM:
	case ZYDIS_MNEMONIC_FXSAVE:
	case ZYDIS_MNEMONIC_FXSAVE64:
	case ZYDIS_MNEMONIC_FXTRACT:
	case ZYDIS_MNEMONIC_FYL2X:
	case ZYDIS_MNEMONIC_FYL2XP1:
	case ZYDIS_MNEMONIC_FISTTP:
	case ZYDIS_MNEMONIC_FSQRT:
	case ZYDIS_MNEMONIC_FXCH:
		break;
	case ZYDIS_MNEMONIC_FTST:
	case ZYDIS_MNEMONIC_FUCOMI:
	case ZYDIS_MNEMONIC_FUCOMPP:
	case ZYDIS_MNEMONIC_FUCOMP:
	case ZYDIS_MNEMONIC_FUCOM:
		break;
	case ZYDIS_MNEMONIC_FABS:
		break;
	case ZYDIS_MNEMONIC_FLDCW:
	case ZYDIS_MNEMONIC_FLDENV:
	case ZYDIS_MNEMONIC_FLDL2E:
	case ZYDIS_MNEMONIC_FLDL2T:
	case ZYDIS_MNEMONIC_FLDLG2:
	case ZYDIS_MNEMONIC_FLDLN2:
	case ZYDIS_MNEMONIC_FLDPI:
	case ZYDIS_MNEMONIC_FLDZ:
	case ZYDIS_MNEMONIC_FLD1:
	case ZYDIS_MNEMONIC_FLD:
		break;
	case ZYDIS_MNEMONIC_FIST:
	case ZYDIS_MNEMONIC_FISTP:
	case ZYDIS_MNEMONIC_FST:
	case ZYDIS_MNEMONIC_FSTP:
	case ZYDIS_MNEMONIC_FSTPNCE:
	case ZYDIS_MNEMONIC_FXRSTOR:
	case ZYDIS_MNEMONIC_FXRSTOR64:
		break;
	case ZYDIS_MNEMONIC_FIDIV:
	case ZYDIS_MNEMONIC_FIDIVR:
	case ZYDIS_MNEMONIC_FDIV:
	case ZYDIS_MNEMONIC_FDIVP:
	case ZYDIS_MNEMONIC_FDIVR:
	case ZYDIS_MNEMONIC_FDIVRP:
		break;
	case ZYDIS_MNEMONIC_FSUBR:
	case ZYDIS_MNEMONIC_FISUBR:
	case ZYDIS_MNEMONIC_FSUBRP:
	case ZYDIS_MNEMONIC_FSUB:
	case ZYDIS_MNEMONIC_FISUB:
	case ZYDIS_MNEMONIC_FSUBP:
		break;
	case ZYDIS_MNEMONIC_FMUL:
	case ZYDIS_MNEMONIC_FIMUL:
	case ZYDIS_MNEMONIC_FMULP:
		break;
	case ZYDIS_MNEMONIC_CLI:
		esilprintf(op, "0,if,:=");
		break;
	case ZYDIS_MNEMONIC_STI:
		esilprintf(op, "1,if,:=");
		break;
	case ZYDIS_MNEMONIC_CLC:
		esilprintf(op, "0,cf,:=");
		break;
	case ZYDIS_MNEMONIC_CMC:
		esilprintf(op, "cf,!,cf,=");
		break;
	case ZYDIS_MNEMONIC_STC:
		esilprintf(op, "1,cf,:=");
		break;
	case ZYDIS_MNEMONIC_CLAC:
	case ZYDIS_MNEMONIC_CLGI:
	case ZYDIS_MNEMONIC_CLTS:
	case ZYDIS_MNEMONIC_CLWB:
	case ZYDIS_MNEMONIC_STAC:
	case ZYDIS_MNEMONIC_STGI:
		break;
	// cmov
	case ZYDIS_MNEMONIC_SETNZ:
	case ZYDIS_MNEMONIC_SETNO:
	case ZYDIS_MNEMONIC_SETNP:
	case ZYDIS_MNEMONIC_SETNS:
	case ZYDIS_MNEMONIC_SETO:
	case ZYDIS_MNEMONIC_SETP:
	case ZYDIS_MNEMONIC_SETS:
	case ZYDIS_MNEMONIC_SETL:
	case ZYDIS_MNEMONIC_SETLE:
	case ZYDIS_MNEMONIC_SETB:
	case ZYDIS_MNEMONIC_SETNLE:
	case ZYDIS_MNEMONIC_SETNB:
	case ZYDIS_MNEMONIC_SETNBE:
	case ZYDIS_MNEMONIC_SETBE:
	case ZYDIS_MNEMONIC_SETZ:
	case ZYDIS_MNEMONIC_SETNL: {
		dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, addr);
		switch (zydecode->mnemonic) {
		case ZYDIS_MNEMONIC_SETZ: esilprintf(op, "zf,%s", dst); break;
		case ZYDIS_MNEMONIC_SETNZ: esilprintf(op, "zf,!,%s", dst); break;
		case ZYDIS_MNEMONIC_SETO: esilprintf(op, "of,%s", dst); break;
		case ZYDIS_MNEMONIC_SETNO: esilprintf(op, "of,!,%s", dst); break;
		case ZYDIS_MNEMONIC_SETP: esilprintf(op, "pf,%s", dst); break;
		case ZYDIS_MNEMONIC_SETNP: esilprintf(op, "pf,!,%s", dst); break;
		case ZYDIS_MNEMONIC_SETS: esilprintf(op, "sf,%s", dst); break;
		case ZYDIS_MNEMONIC_SETNS: esilprintf(op, "sf,!,%s", dst); break;
		case ZYDIS_MNEMONIC_SETB: esilprintf(op, "cf,%s", dst); break;
		case ZYDIS_MNEMONIC_SETNB: esilprintf(op, "cf,!,%s", dst); break;
		case ZYDIS_MNEMONIC_SETL: esilprintf(op, "sf,of,^,%s", dst); break;
		case ZYDIS_MNEMONIC_SETLE: esilprintf(op, "zf,sf,of,^,|,%s", dst); break;
		case ZYDIS_MNEMONIC_SETNLE: esilprintf(op, "zf,!,sf,of,^,!,&,%s", dst); break;
		case ZYDIS_MNEMONIC_SETNL: esilprintf(op, "sf,of,^,!,%s", dst); break;
		case ZYDIS_MNEMONIC_SETNBE: esilprintf(op, "cf,zf,|,!,%s", dst); break;
		case ZYDIS_MNEMONIC_SETBE: esilprintf(op, "cf,zf,|,%s", dst); break;
		}
	} break;
	// cmov
	case ZYDIS_MNEMONIC_FCMOVBE:
	case ZYDIS_MNEMONIC_FCMOVB:
	case ZYDIS_MNEMONIC_FCMOVNBE:
	case ZYDIS_MNEMONIC_FCMOVNB:
	case ZYDIS_MNEMONIC_FCMOVE:
	case ZYDIS_MNEMONIC_FCMOVNE:
	case ZYDIS_MNEMONIC_FCMOVNU:
	case ZYDIS_MNEMONIC_FCMOVU:
		break;
	case ZYDIS_MNEMONIC_CMOVNBE:
	case ZYDIS_MNEMONIC_CMOVNB:
	case ZYDIS_MNEMONIC_CMOVB:
	case ZYDIS_MNEMONIC_CMOVBE:
	case ZYDIS_MNEMONIC_CMOVZ:
	case ZYDIS_MNEMONIC_CMOVNLE:
	case ZYDIS_MNEMONIC_CMOVNL:
	case ZYDIS_MNEMONIC_CMOVL:
	case ZYDIS_MNEMONIC_CMOVLE:
	case ZYDIS_MNEMONIC_CMOVNZ:
	case ZYDIS_MNEMONIC_CMOVNO:
	case ZYDIS_MNEMONIC_CMOVNP:
	case ZYDIS_MNEMONIC_CMOVNS:
	case ZYDIS_MNEMONIC_CMOVO:
	case ZYDIS_MNEMONIC_CMOVP:
	case ZYDIS_MNEMONIC_CMOVS: {
		const char *conditional = NULL;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, addr);
		switch (zydecode->mnemonic) {
		case ZYDIS_MNEMONIC_CMOVNBE:
			// mov if CF = 0 *AND* ZF = 0
			conditional = "cf,zf,|,!";
			break;
		case ZYDIS_MNEMONIC_CMOVNB:
			// mov if CF = 0
			conditional = "cf,!";
			break;
		case ZYDIS_MNEMONIC_CMOVB:
			// mov if CF = 1
			conditional = "cf";
			break;
		case ZYDIS_MNEMONIC_CMOVBE:
			// mov if CF = 1 *OR* ZF = 1
			conditional = "cf,zf,|";
			break;
		case ZYDIS_MNEMONIC_CMOVZ:
			// mov if ZF = 1
			conditional = "zf";
			break;
		case ZYDIS_MNEMONIC_CMOVNLE:
			// mov if ZF = 0 *AND* SF = OF
			conditional = "zf,!,sf,of,^,!,&";
			break;
		case ZYDIS_MNEMONIC_CMOVNL:
			// mov if SF = OF
			conditional = "sf,of,^,!";
			break;
		case ZYDIS_MNEMONIC_CMOVL:
			// mov if SF != OF
			conditional = "sf,of,^";
			break;
		case ZYDIS_MNEMONIC_CMOVLE:
			// mov if ZF = 1 *OR* SF != OF
			conditional = "zf,sf,of,^,|";
			break;
		case ZYDIS_MNEMONIC_CMOVNZ:
			// mov if ZF = 0
			conditional = "zf,!";
			break;
		case ZYDIS_MNEMONIC_CMOVNO:
			// mov if OF = 0
			conditional = "of,!";
			break;
		case ZYDIS_MNEMONIC_CMOVNP:
			// mov if PF = 0
			conditional = "pf,!";
			break;
		case ZYDIS_MNEMONIC_CMOVNS:
			// mov if SF = 0
			conditional = "sf,!";
			break;
		case ZYDIS_MNEMONIC_CMOVO:
			// mov if OF = 1
			conditional = "of";
			break;
		case ZYDIS_MNEMONIC_CMOVP:
			// mov if PF = 1
			conditional = "pf";
			break;
		case ZYDIS_MNEMONIC_CMOVS:
			// mov if SF = 1
			conditional = "sf";
			break;
		}
		if (src && dst && conditional) {
			esilprintf(op, "%s,?{,%s,%s,}", conditional, src, dst);
		}
	} break;
	case ZYDIS_MNEMONIC_STOSB:
		if (a->bits < 32) {
			rz_strbuf_appendf(&op->esil, "al,di,=[1],df,?{,1,di,-=,},df,!,?{,1,di,+=,}");
		} else {
			rz_strbuf_appendf(&op->esil, "al,edi,=[1],df,?{,1,edi,-=,},df,!,?{,1,edi,+=,}");
		}
		break;
	case ZYDIS_MNEMONIC_STOSW:
		if (a->bits < 32) {
			rz_strbuf_appendf(&op->esil, "ax,di,=[2],df,?{,2,di,-=,},df,!,?{,2,di,+=,}");
		} else {
			rz_strbuf_appendf(&op->esil, "ax,edi,=[2],df,?{,2,edi,-=,},df,!,?{,2,edi,+=,}");
		}
		break;
	case ZYDIS_MNEMONIC_STOSD:
		rz_strbuf_appendf(&op->esil, "eax,edi,=[4],df,?{,4,edi,-=,},df,!,?{,4,edi,+=,}");
		break;
	case ZYDIS_MNEMONIC_STOSQ:
		rz_strbuf_appendf(&op->esil, "rax,rdi,=[8],df,?{,8,edi,-=,},df,!,?{,8,edi,+=,}");
		break;
	case ZYDIS_MNEMONIC_LODSB:
		rz_strbuf_appendf(&op->esil, "%s,[1],al,=,df,?{,1,%s,-=,},df,!,?{,1,%s,+=,}", si, si, si);
		break;
	case ZYDIS_MNEMONIC_LODSW:
		rz_strbuf_appendf(&op->esil, "%s,[2],ax,=,df,?{,2,%s,-=,},df,!,?{,2,%s,+=,}", si, si, si);
		break;
	case ZYDIS_MNEMONIC_LODSD:
		rz_strbuf_appendf(&op->esil, "esi,[4],eax,=,df,?{,4,esi,-=,},df,!,?{,4,esi,+=,}");
		break;
	case ZYDIS_MNEMONIC_LODSQ:
		rz_strbuf_appendf(&op->esil, "rsi,[8],rax,=,df,?{,8,rsi,-=,},df,!,?{,8,rsi,+=,}");
		break;
	case ZYDIS_MNEMONIC_PEXTRB:
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
	case ZYDIS_MNEMONIC_MOVSD:
		// Handle "Move Scalar Double-Precision Floating-Point Value"
		if (is_xmm_reg(INSOP(0)) || is_xmm_reg(INSOP(1))) {
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, addr);
			if (src && dst) {
				esilprintf(op, "%s,%s", src, dst);
			}
			break;
		}
		// fallthrough
	case ZYDIS_MNEMONIC_MOVSB:
	case ZYDIS_MNEMONIC_MOVSQ:
	case ZYDIS_MNEMONIC_MOVSW:
		if (op->prefix & RZ_ANALYSIS_OP_PREFIX_REP) {
			int width = INSOP(0).size;
			src = (char *)ZydisRegisterGetString(INSOP(1).mem.base);
			dst = (char *)ZydisRegisterGetString(INSOP(0).mem.base);
			rz_strbuf_appendf(&op->esil,
				"%s,[%d],%s,=[%d],"
				"df,?{,%d,%s,-=,%d,%s,-=,},"
				"df,!,?{,%d,%s,+=,%d,%s,+=,}",
				src, width, dst, width,
				width, src, width, dst,
				width, src, width, dst);
		} else {
			int width = INSOP(0).size;
			src = (char *)ZydisRegisterGetString(INSOP(1).mem.base);
			dst = (char *)ZydisRegisterGetString(INSOP(0).mem.base);
			esilprintf(op, "%s,[%d],%s,=[%d],df,?{,%d,%s,-=,%d,%s,-=,},"
				       "df,!,?{,%d,%s,+=,%d,%s,+=,}",
				src, width, dst, width, width, src, width,
				dst, width, src, width, dst);
		}
		break;
	// comiss
	case ZYDIS_MNEMONIC_COMISS:
	case ZYDIS_MNEMONIC_UCOMISS:
	case ZYDIS_MNEMONIC_VCOMISS:
	case ZYDIS_MNEMONIC_VUCOMISS:
		op->type = RZ_ANALYSIS_OP_TYPE_SIMD | RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	// mov
	case ZYDIS_MNEMONIC_MOVSS:
	case ZYDIS_MNEMONIC_MOV:
	case ZYDIS_MNEMONIC_MOVAPS:
	case ZYDIS_MNEMONIC_MOVAPD:
	case ZYDIS_MNEMONIC_MOVZX:
	case ZYDIS_MNEMONIC_MOVUPS:
	case ZYDIS_MNEMONIC_MOVHPD:
	case ZYDIS_MNEMONIC_MOVHPS:
	case ZYDIS_MNEMONIC_MOVLPD:
	case ZYDIS_MNEMONIC_MOVLPS:
	case ZYDIS_MNEMONIC_MOVBE:
	case ZYDIS_MNEMONIC_MOVSX:
	case ZYDIS_MNEMONIC_MOVSXD:
	case ZYDIS_MNEMONIC_MOVQ:
	case ZYDIS_MNEMONIC_MOVDQU:
	case ZYDIS_MNEMONIC_MOVDQA:
	case ZYDIS_MNEMONIC_MOVDQ2Q: {
		switch (INSOP(0).type) {
		case ZYDIS_OPERAND_TYPE_MEMORY:
			if (op->prefix & RZ_ANALYSIS_OP_PREFIX_REP) {
				int width = INSOP(0).size;
				src = (char *)ZydisRegisterGetString(INSOP(1).mem.base);
				dst = (char *)ZydisRegisterGetString(INSOP(0).mem.base);
				const char *counter = (a->bits == 16) ? "cx" : (a->bits == 32) ? "ecx"
											       : "rcx";
				esilprintf(op, "%s,!,?{,BREAK,},%s,NUM,%s,NUM,"
					       "%s,[%d],%s,=[%d],df,?{,%d,%s,-=,%d,%s,-=,},"
					       "df,!,?{,%d,%s,+=,%d,%s,+=,},%s,--=,%s,"
					       "?{,8,GOTO,}",
					counter, src, dst, src, width, dst,
					width, width, src, width, dst, width, src,
					width, dst, counter, counter);
			} else {
				src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
				dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, addr);
				esilprintf(op, "%s,%s", src, dst);
			}
			break;
		case ZYDIS_OPERAND_TYPE_REGISTER:
		default:
			if (INSOP(0).type == ZYDIS_OPERAND_TYPE_MEMORY) {
				op->direction = 1; // read
			}
			if (INSOP(1).type == ZYDIS_OPERAND_TYPE_MEMORY) {
				// MOV REG, [PTR + IREG*SCALE]
				op->ireg = ZydisRegisterGetString(INSOP(1).mem.index);
				op->disp = INSOP(1).mem.disp.value;
				op->scale = INSOP(1).mem.scale;
			}
			{
				int width = INSOP(1).size;

				src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
				// dst is name of register from instruction.
				dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
				const char *dst64 = rz_reg_32_to_64(a->reg, dst);
				if (a->bits == 64 && dst64) {
					// Here it is still correct, because 'e** = X'
					// turns into 'r** = X' (first one will keep higher bytes,
					// second one will overwrite them with zeros).
					if (zydecode->mnemonic == ZYDIS_MNEMONIC_MOVSX || zydecode->mnemonic == ZYDIS_MNEMONIC_MOVSXD) {
						esilprintf(op, "%d,%s,~,%s,=", width * 8, src, dst64);
					} else {
						esilprintf(op, "%s,%s,=", src, dst64);
					}

				} else {
					if (zydecode->mnemonic == ZYDIS_MNEMONIC_MOVSX || zydecode->mnemonic == ZYDIS_MNEMONIC_MOVSXD) {
						esilprintf(op, "%d,%s,~,%s,=", width * 8, src, dst);
					} else {
						esilprintf(op, "%s,%s,=", src, dst);
					}
				}
			}
			break;
		}
	} break;
	case ZYDIS_MNEMONIC_MOVD:
		if (is_xmm_reg(INSOP(0))) {
			if (!is_xmm_reg(INSOP(1))) {
				src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
				dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
				esilprintf(op, "%s,%sl,=", src, dst);
			}
		}
		if (is_xmm_reg(INSOP(1))) {
			if (!is_xmm_reg(INSOP(0))) {
				src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
				dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, addr);
				esilprintf(op, "%sl,%s", src, dst);
			}
		}
		break;
	case ZYDIS_MNEMONIC_ROL:
	case ZYDIS_MNEMONIC_RCL:
		// TODO: RCL Still does not work as intended
		//  - Set flags
		{
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
			esilprintf(op, "%s,%s,<<<,%s,=", src, dst, dst);
		}
		break;
	case ZYDIS_MNEMONIC_ROR:
	case ZYDIS_MNEMONIC_RCR:
		// TODO: RCR Still does not work as intended
		//  - Set flags
		{
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
			esilprintf(op, "%s,%s,>>>,%s,=", src, dst, dst);
		}
		break;
	case ZYDIS_MNEMONIC_CPUID:
		// https://c9x.me/x86/html/file_module_x86_id_45.html
		// GenuineIntel
		esilprintf(op, "0xa,eax,=,0x756E6547,ebx,=,0x6C65746E,ecx,=,0x49656E69,edx,=");
		break;
	case ZYDIS_MNEMONIC_SHLD:
	case ZYDIS_MNEMONIC_SHLX:
		// TODO: SHLD is not implemented yet.
		{
			ut32 bitsize;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst = getarg(a, &gop, 0, 1, "<<", DST_AR, &bitsize, addr);
			esilprintf(op, "%s,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=", src, dst, bitsize - 1);
		}
		break;
	case ZYDIS_MNEMONIC_SAR:
		// TODO: Set CF. See case ZYDIS_MNEMONIC_SHL for more details.
		{
			ut32 bitsize;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst_r = getarg(a, &gop, 0, 0, NULL, DST_R_AR, NULL, addr);
			dst_w = getarg(a, &gop, 0, 1, NULL, DST_W_AR, &bitsize, addr);
			esilprintf(op, "0,cf,:=,1,%s,-,1,<<,%s,&,?{,1,cf,:=,},%s,%s,>>>>,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=",
				src, dst_r, src, dst_r, dst_w, bitsize - 1);
		}
		break;
	case ZYDIS_MNEMONIC_SARX: {
		dst = getarg(a, &gop, 0, 1, NULL, 0, NULL, addr);
		src = getarg(a, &gop, 1, 0, NULL, 1, NULL, addr);
		src2 = getarg(a, &gop, 1, 0, NULL, 2, NULL, addr);
		esilprintf(op, "%s,%s,>>>>,%s,=", src2, src, dst);
	} break;
	case ZYDIS_MNEMONIC_SHL: {
		ut64 val = 0;
		switch (zydeop[0].size) {
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
			RZ_LOG_ERROR("x86: unknown operand size: %d\n", zydeop[0].size);
			val = 256;
			break;
		}
		ut32 bitsize;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
		dst2 = getarg(a, &gop, 0, 1, "<<", DST2_AR, &bitsize, addr);
		esilprintf(op, "0,%s,!,!,?{,1,%s,-,%s,<<,0x%llx,&,!,!,^,},%s,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,cf,=",
			src, src, dst, val, src, dst2, bitsize - 1);
	} break;
	case ZYDIS_MNEMONIC_SALC:
		esilprintf(op, "$z,DUP,zf,=,al,=");
		break;
	case ZYDIS_MNEMONIC_SHR:
	case ZYDIS_MNEMONIC_SHRD:
	case ZYDIS_MNEMONIC_SHRX:
		// TODO: Set CF: See case ZYDIS_MNEMONIC_SAL for more details.
		{
			ut32 bitsize;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst_r = getarg(a, &gop, 0, 0, NULL, DST_R_AR, NULL, addr);
			dst_w = getarg(a, &gop, 0, 1, NULL, DST_W_AR, &bitsize, addr);
			esilprintf(op, "0,cf,:=,1,%s,-,1,<<,%s,&,?{,1,cf,:=,},%s,%s,>>,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=",
				src, dst_r, src, dst_r, dst_w, bitsize - 1);
		}
		break;
	case ZYDIS_MNEMONIC_CBW:
		esilprintf(op, "al,ax,=,7,ax,>>,?{,0xff00,ax,|=,}");
		break;
	case ZYDIS_MNEMONIC_CWDE:
		esilprintf(op, "ax,eax,=,15,eax,>>,?{,0xffff0000,eax,|=,}");
		break;
	case ZYDIS_MNEMONIC_CDQ:
		esilprintf(op, "0,edx,=,31,eax,>>,?{,0xffffffff,edx,=,}");
		break;
	case ZYDIS_MNEMONIC_CDQE:
		esilprintf(op, "eax,rax,=,31,rax,>>,?{,0xffffffff00000000,rax,|=,}");
		break;
	case ZYDIS_MNEMONIC_AAA:
		esilprintf(op, "0,cf,:=,0,af,:=,9,al,>,?{,10,al,-=,1,ah,+=,1,cf,:=,1,af,:=,}"); // don't
		break;
	case ZYDIS_MNEMONIC_AAD:
		arg0 = "0,zf,:=,0,sf,:=,0,pf,:=,10,ah,*,al,+,ax,=";
		arg1 = "0,al,==,?{,1,zf,:=,},2,al,%,0,==,?{,1,pf,:=,},7,al,>>,?{,1,sf,:=,}";
		esilprintf(op, "%s,%s", arg0, arg1);
		break;
	case ZYDIS_MNEMONIC_AAM:
		arg0 = "0,zf,:=,0,sf,:=,0,pf,:=,10,al,/,ah,=,10,al,%,al,=";
		arg1 = "0,al,==,?{,1,zf,:=,},2,al,%,0,==,?{,1,pf,:=,},7,al,>>,?{,1,sf,:=,}";
		esilprintf(op, "%s,%s", arg0, arg1);
		break;
	// XXX: case ZYDIS_MNEMONIC_AAS: too tough to implement. BCD is deprecated anyways
	case ZYDIS_MNEMONIC_CMP:
	case ZYDIS_MNEMONIC_CMPPD:
	case ZYDIS_MNEMONIC_CMPPS:
	case ZYDIS_MNEMONIC_CMPSW:
	case ZYDIS_MNEMONIC_CMPSD:
	case ZYDIS_MNEMONIC_CMPSQ:
	case ZYDIS_MNEMONIC_CMPSB:
	case ZYDIS_MNEMONIC_CMPSS:
	case ZYDIS_MNEMONIC_TEST: {
		ut32 bitsize;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, &bitsize, addr);

		if (!bitsize || bitsize > 64) {
			break;
		}

		if (zydecode->mnemonic == ZYDIS_MNEMONIC_TEST) {
			esilprintf(op, "0,%s,%s,&,==,$z,zf,:=,$p,pf,:=,%u,$s,sf,:=,0,cf,:=,0,of,:=",
				src, dst, bitsize - 1);
		} else if (zydecode->mnemonic == ZYDIS_MNEMONIC_CMP) {
			esilprintf(op,
				"%s,%s,==,$z,zf,:=,%u,$b,cf,:=,$p,pf,:=,%u,$s,sf,:=,"
				"%s,0x%" PFMT64x ",-,!,%u,$o,^,of,:=,3,$b,af,:=",
				src, dst, bitsize, bitsize - 1, src, 1ULL << (bitsize - 1), bitsize - 1);
		} else {
			char *rsrc = (char *)ZydisRegisterGetString(INSOP(1).mem.base);
			char *rdst = (char *)ZydisRegisterGetString(INSOP(0).mem.base);
			const int width = INSOP(0).size;
			esilprintf(op,
				"%s,%s,==,$z,zf,:=,%u,$b,cf,:=,$p,pf,:=,%u,$s,sf,:=,%s,0x%" PFMT64x ","
				"-,!,%u,$o,^,of,:=,3,$b,af,:=,df,?{,%d,%s,-=,%d,%s,-=,}{,%d,%s,+=,%d,%s,+=,}",
				src, dst, bitsize, bitsize - 1, src, 1ULL << (bitsize - 1), bitsize - 1,
				width, rsrc, width, rdst, width, rsrc, width, rdst);
		}
	} break;
	case ZYDIS_MNEMONIC_LEA: {
		src = getarg(a, &gop, 1, 2, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, addr);
		esilprintf(op, "%s,%s", src, dst);
	} break;
	// pushal, popal - push/pop EAX,EBX,ECX,EDX,ESP,EBP,ESI,EDI
	case ZYDIS_MNEMONIC_PUSHAD: {
		esilprintf(op,
			"0,%s,+,"
			"%d,%s,-=,%s,%s,=[%d],"
			"%d,%s,-=,%s,%s,=[%d],"
			"%d,%s,-=,%s,%s,=[%d],"
			"%d,%s,-=,%s,%s,=[%d],"
			"%d,%s,-=,%s,=[%d],"
			"%d,%s,-=,%s,%s,=[%d],"
			"%d,%s,-=,%s,%s,=[%d],"
			"%d,%s,-=,%s,%s,=[%d]",
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
	case ZYDIS_MNEMONIC_ENTER:
	case ZYDIS_MNEMONIC_PUSH: {
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
		esilprintf(op, "%s,%d,%s,-,=[%d],%d,%s,-=",
			dst ? dst : "eax", rs, sp, rs, rs, sp);
	} break;
	case ZYDIS_MNEMONIC_PUSHF:
	case ZYDIS_MNEMONIC_PUSHFD:
	case ZYDIS_MNEMONIC_PUSHFQ:
		esilprintf(op, "%d,%s,-=,eflags,%s,=[%d]", rs, sp, sp, rs);
		break;
	case ZYDIS_MNEMONIC_LEAVE:
		esilprintf(op, "%s,%s,=,%s,[%d],%s,=,%d,%s,+=",
			bp, sp, sp, rs, bp, rs, sp);
		break;
	case ZYDIS_MNEMONIC_POPAD: {
		esilprintf(op,
			"%s,[%d],%d,%s,+=,%s,=,"
			"%s,[%d],%d,%s,+=,%s,=,"
			"%s,[%d],%d,%s,+=,%s,=,"
			"%s,[%d],%d,%s,+=,"
			"%s,[%d],%d,%s,+=,%s,=,"
			"%s,[%d],%d,%s,+=,%s,=,"
			"%s,[%d],%d,%s,+=,%s,=,"
			"%s,[%d],%d,%s,+=,%s,=,"
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
	case ZYDIS_MNEMONIC_POP: {
		switch (INSOP(0).type) {
		case ZYDIS_OPERAND_TYPE_MEMORY: {
			dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, addr);
			esilprintf(op,
				"%s,[%d],%d,%s,+=,%s",
				sp, rs, rs, sp, dst);
			break;
		}
		case ZYDIS_OPERAND_TYPE_REGISTER:
		default: {
			dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
			esilprintf(op,
				"%s,[%d],%d,%s,+=,%s,=",
				sp, rs, rs, sp, dst);
			break;
		}
		}
	} break;
	case ZYDIS_MNEMONIC_POPF:
	case ZYDIS_MNEMONIC_POPFD:
	case ZYDIS_MNEMONIC_POPFQ:
		esilprintf(op, "%s,[%d],eflags,=", sp, rs);
		break;
	case ZYDIS_MNEMONIC_RET:
	case ZYDIS_MNEMONIC_IRET:
	case ZYDIS_MNEMONIC_IRETD:
	case ZYDIS_MNEMONIC_IRETQ:
	case ZYDIS_MNEMONIC_SYSRET: {
		int cleanup = 0;
		if (INSOPS > 0) {
			cleanup = (int)get_imm_reg_value(op, addr, zydecode->length);
		}
		esilprintf(op, "%s,[%d],%s,=,%d,%s,+=",
			sp, rs, pc, rs + cleanup, sp);
	} break;
	case ZYDIS_MNEMONIC_INT3:
		esilprintf(op, "3,$");
		break;
	case ZYDIS_MNEMONIC_INT1:
		esilprintf(op, "1,$");
		break;
	case ZYDIS_MNEMONIC_INT:
		esilprintf(op, "%d,$",
			RZ_ABS((int)get_imm_reg_value(&INSOP(0), addr, zydecode->length)));
		break;
	case ZYDIS_MNEMONIC_SYSCALL:
	case ZYDIS_MNEMONIC_SYSENTER:
	case ZYDIS_MNEMONIC_SYSEXIT:
		break;
	case ZYDIS_MNEMONIC_INTO:
	case ZYDIS_MNEMONIC_VMCALL:
	case ZYDIS_MNEMONIC_VMMCALL:
		esilprintf(op, "%d,$", (int)get_imm_reg_value(&INSOP(0), addr, zydecode->length));
		break;
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_LOOP:
	case ZYDIS_MNEMONIC_LOOPE:
	case ZYDIS_MNEMONIC_LOOPNE: {
		const char *cnt = (a->bits == 16) ? "cx" : (a->bits == 32) ? "ecx"
									   : "rcx";
		dst = getarg(a, &gop, 0, 2, NULL, DST_AR, NULL, addr);
		switch (zydecode->mnemonic) {
		case ZYDIS_MNEMONIC_JL:
			esilprintf(op, "of,sf,^,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JLE:
			esilprintf(op, "of,sf,^,zf,|,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JNBE:
			esilprintf(op, "cf,zf,|,!,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JNB:
			esilprintf(op, "cf,!,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JB:
			esilprintf(op, "cf,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JO:
			esilprintf(op, "of,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JNO:
			esilprintf(op, "of,!,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JZ:
			esilprintf(op, "zf,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JNL:
			esilprintf(op, "of,!,sf,^,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JNZ:
			esilprintf(op, "zf,!,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JNLE:
			esilprintf(op, "sf,of,!,^,zf,!,&,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JS:
			esilprintf(op, "sf,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JNS:
			esilprintf(op, "sf,!,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JP:
			esilprintf(op, "pf,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JNP:
			esilprintf(op, "pf,!,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JBE:
			esilprintf(op, "zf,cf,|,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JCXZ:
			esilprintf(op, "cx,!,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JECXZ:
			esilprintf(op, "ecx,!,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_JRCXZ:
			esilprintf(op, "rcx,!,?{,%s,%s,=,}", dst, pc);
			break;
		case ZYDIS_MNEMONIC_LOOP:
			esilprintf(op, "1,%s,-=,%s,?{,%s,%s,=,}", cnt, cnt, dst, pc);
			break;
		case ZYDIS_MNEMONIC_LOOPE:
			esilprintf(op, "1,%s,-=,%s,?{,zf,?{,%s,%s,=,},}",
				cnt, cnt, dst, pc);
			break;
		case ZYDIS_MNEMONIC_LOOPNE:
			esilprintf(op, "1,%s,-=,%s,?{,zf,!,?{,%s,%s,=,},}",
				cnt, cnt, dst, pc);
			break;
		}
	} break;
	case ZYDIS_MNEMONIC_CALL: {
		if (a->read_at && a->bits != 16) {
			ut8 thunk[4] = { 0 };
			if (a->read_at(a, (ut64)get_imm_reg_value(&INSOP(0), addr, zydecode->length), thunk, sizeof(thunk))) {
				/* 8b xx x4    mov <reg>, dword [esp]
					   c3          ret
					*/
				if (thunk[0] == 0x8b && thunk[3] == 0xc3 && (thunk[1] & 0xc7) == 4 /* 00rrr100 */
					&& (thunk[2] & 0x3f) == 0x24) { /* --100100: ignore scale in SIB byte */
					ut8 reg = (thunk[1] & 0x38) >> 3;
					esilprintf(op, "0x%" PFMT64x ",%s,=", addr + op->size,
						reg32_to_name(reg));
					break;
				}
			}
		}
		arg0 = getarg(a, &gop, 0, 0, NULL, ARG0_AR, NULL, addr);
		esilprintf(op,
			"%s,%s,"
			"%d,%s,-=,%s,"
			"=[],"
			"%s,=",
			arg0, pc, rs, sp, sp, pc);
	} break;
	// case ZYDIS_MNEMONIC_LCALL: {
	//	arg0 = getarg(a, &gop, 0, 0, NULL, ARG0_AR, NULL,addr);
	//	arg1 = getarg(a, &gop, 1, 0, NULL, ARG1_AR, NULL,addr);
	//	if (arg1) {
	//		esilprintf(op,
	//			"2,%s,-=,cs,%s,=[2]," // push CS
	//			"%d,%s,-=,%s,%s,=[]," // push IP/EIP
	//			"%s,cs,=," // set CS
	//			"%s,%s,=", // set IP/EIP
	//			sp, sp, rs, sp, pc, sp, arg0, arg1, pc);
	//	} else {
	//		esilprintf(op,
	//			"%s,%s,-=,%d,%s,=[]," // push IP/EIP
	//			"%s,%s,=", // set IP/EIP
	//			sp, sp, rs, sp, arg0, pc);
	//	}
	// } break;
	case ZYDIS_MNEMONIC_JMP: {
		src = getarg(a, &gop, 0, 0, NULL, SRC_AR, NULL, addr);
		esilprintf(op, "%s,%s,=", src, pc);
	}
		// TODO: what if UJMP?
		switch (INSOP(0).type) {
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			if (INSOP(1).type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				ut64 seg = get_imm_reg_value(&INSOP(0), addr, zydecode->length);
				ut64 off = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
				esilprintf(
					op,
					"0x%" PFMT64x ",cs,=,"
					"0x%" PFMT64x ",%s,=",
					seg, off, pc);
			} else {
				ut64 dst = get_imm_reg_value(&INSOP(0), addr, zydecode->length);
				esilprintf(op, "0x%" PFMT64x ",%s,=", dst, pc);
			}
			break;
		case ZYDIS_OPERAND_TYPE_MEMORY:
			if (INSOP(0).mem.base == ZYDIS_REGISTER_RIP) {
				/* nothing here */
			} else {
				ZydisDecodedOperand in = INSOP(0);
				if (in.mem.index == 0 && in.mem.base == 0 && in.mem.scale == 1) {
					if (in.mem.segment != ZYDIS_REGISTER_NONE) {
						esilprintf(
							op,
							"4,%s,<<,0x%" PFMT64x ",+,[],%s,=",
							INSOP(0).mem.segment == ZYDIS_REGISTER_ES           ? "es"
								: INSOP(0).mem.segment == ZYDIS_REGISTER_CS ? "cs"
								: INSOP(0).mem.segment == ZYDIS_REGISTER_DS ? "ds"
								: INSOP(0).mem.segment == ZYDIS_REGISTER_FS ? "fs"
								: INSOP(0).mem.segment == ZYDIS_REGISTER_GS ? "gs"
								: INSOP(0).mem.segment == ZYDIS_REGISTER_SS ? "ss"
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
		case ZYDIS_OPERAND_TYPE_REGISTER: {
			src = getarg(a, &gop, 0, 0, NULL, SRC_AR, NULL, addr);
			op->src[0] = rz_analysis_value_new();
			op->src[0]->reg = rz_reg_get(a->reg, src, RZ_REG_TYPE_GPR);
			// XXX fallthrough
		}
		// case ZYDIS_OPERAND_TYPE_FP:
		default: // other?
			break;
		}
		break;
	case ZYDIS_MNEMONIC_IN:
	case ZYDIS_MNEMONIC_INSW:
	case ZYDIS_MNEMONIC_INSD:
	case ZYDIS_MNEMONIC_INSB:
		if (ISIMM(1)) {
			op->val = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
		}
		break;
	case ZYDIS_MNEMONIC_OUT:
	case ZYDIS_MNEMONIC_OUTSB:
	case ZYDIS_MNEMONIC_OUTSD:
	case ZYDIS_MNEMONIC_OUTSW:
		if (ISIMM(0)) {
			op->val = get_imm_reg_value(&INSOP(0), addr, zydecode->length);
		}
		break;
	case ZYDIS_MNEMONIC_VXORPD:
	case ZYDIS_MNEMONIC_VXORPS:
	case ZYDIS_MNEMONIC_VPXORD:
	case ZYDIS_MNEMONIC_VPXORQ:
	case ZYDIS_MNEMONIC_VPXOR:
	case ZYDIS_MNEMONIC_XORPS:
	case ZYDIS_MNEMONIC_KXORW:
	case ZYDIS_MNEMONIC_PXOR:
	case ZYDIS_MNEMONIC_XOR: {
		ut32 bitsize;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 1, "^", DST_AR, &bitsize, addr);
		dst2 = getarg(a, &gop, 0, 0, NULL, DST2_AR, NULL, addr);
		const char *dst_reg64 = rz_reg_32_to_64(a->reg, dst2); // 64-bit destination if exists
		if (a->bits == 64 && dst_reg64) {
			// (64-bit ^ 32-bit) & 0xFFFF FFFF -> 64-bit, it's alright, higher bytes will be eliminated
			// (consider this is operation with 32-bit regs in 64-bit environment).
			esilprintf(op, "%s,%s,^,0xffffffff,&,%s,=,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,0,cf,:=,0,of,:=",
				src, dst_reg64, dst_reg64, bitsize - 1);
		} else {
			esilprintf(op, "%s,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,0,cf,:=,0,of,:=",
				src, dst, bitsize - 1);
		}
	} break;
	case ZYDIS_MNEMONIC_BSF: {
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
		int bits = INSOP(0).size * 8;

		/*
		 * Here we first set ZF depending on the source operand
		 * (and bail out if it's 0), then test each bit in a loop
		 * by creating a mask on the stack and applying it, returning
		 * result if bit is set.
		 */
		esilprintf(op, "%s,!,?{,1,zf,=,BREAK,},0,zf,=,"
			       "%d,DUP,%d,-,1,<<,%s,&,?{,%d,-,%s,=,BREAK,},12,REPEAT",
			src, bits, bits, src, bits, dst);
	} break;
	case ZYDIS_MNEMONIC_BSR: {
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
		int bits = INSOP(0).size * 8;

		/*
		 * Similar to BSF, except we naturally don't
		 * need to subtract anything to create
		 * a mask and return the result.
		 */
		esilprintf(op, "%s,!,?{,1,zf,=,BREAK,},0,zf,=,"
			       "%d,DUP,1,<<,%s,&,?{,%s,=,BREAK,},12,REPEAT",
			src, bits, src, dst);
	} break;
	case ZYDIS_MNEMONIC_BSWAP: {
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
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
	case ZYDIS_MNEMONIC_OR:
		// The OF and CF flags are cleared; the SF, ZF, and PF flags are
		// set according to the result. The state of the AF flag is
		// undefined.
		{
			ut32 bitsize;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst = getarg(a, &gop, 0, 1, "|", DST_AR, &bitsize, addr);
			esilprintf(op, "%s,%s,%d,$s,sf,:=,$z,zf,:=,$p,pf,:=,0,of,:=,0,cf,:=",
				src, dst, bitsize - 1);
		}
		break;
	case ZYDIS_MNEMONIC_INC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		{
			ut32 bitsize;
			src = getarg(a, &gop, 0, 1, "++", SRC_AR, &bitsize, addr);
			esilprintf(op, "%s,%d,$o,of,:=,%d,$s,sf,:=,$z,zf,:=,$p,pf,:=,3,$c,af,:=", src, bitsize - 1, bitsize - 1);
		}
		break;
	case ZYDIS_MNEMONIC_DEC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		{
			ut32 bitsize;
			src = getarg(a, &gop, 0, 1, "--", SRC_AR, &bitsize, addr);
			esilprintf(op, "%s,%d,$o,of,:=,%d,$s,sf,:=,$z,zf,:=,$p,pf,:=,3,$b,af,:=", src, bitsize - 1, bitsize - 1);
		}
		break;
	case ZYDIS_MNEMONIC_PSUBB:
	case ZYDIS_MNEMONIC_PSUBW:
	case ZYDIS_MNEMONIC_PSUBD:
	case ZYDIS_MNEMONIC_PSUBQ:
	case ZYDIS_MNEMONIC_PSUBSB:
	case ZYDIS_MNEMONIC_PSUBSW:
	case ZYDIS_MNEMONIC_PSUBUSB:
	case ZYDIS_MNEMONIC_PSUBUSW: {
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 1, "-", DST_AR, NULL, addr);
		esilprintf(op, "%s,%s", src, dst);
	} break;
	case ZYDIS_MNEMONIC_SUB: {
		ut32 bitsize;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 1, "-", DST_AR, &bitsize, addr);

		if (!bitsize || bitsize > 64) {
			break;
		}

		// Set OF, SF, ZF, AF, PF, and CF flags.
		// We use $b rather than $c here as the carry flag really
		// represents a "borrow"
		esilprintf(op, "%s,%s,%s,0x%" PFMT64x ",-,!,%u,$o,^,of,:=,%u,$s,sf,:=,$z,zf,:=,$p,pf,:=,%u,$b,cf,:=,3,$b,af,:=",
			src, dst, src, 1ULL << (bitsize - 1), bitsize - 1, bitsize - 1, bitsize);
	} break;
	case ZYDIS_MNEMONIC_SBB:
		// dst = dst - (src + cf)
		{
			ut32 bitsize;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst = getarg(a, &gop, 0, 0, NULL, DST_AR, &bitsize, addr);
			esilprintf(op, "cf,%s,+,%s,-=,%d,$o,of,:=,%d,$s,sf,:=,$z,zf,:=,$p,pf,:=,%d,$b,cf,:=",
				src, dst, bitsize - 1, bitsize - 1, bitsize);
		}
		break;
	case ZYDIS_MNEMONIC_LIDT:
		break;
	case ZYDIS_MNEMONIC_SIDT:
		break;
	case ZYDIS_MNEMONIC_RDRAND:
	case ZYDIS_MNEMONIC_RDSEED:
	case ZYDIS_MNEMONIC_RDMSR:
	case ZYDIS_MNEMONIC_RDPMC:
	case ZYDIS_MNEMONIC_RDTSC:
	case ZYDIS_MNEMONIC_RDTSCP:
	case ZYDIS_MNEMONIC_CRC32:
	case ZYDIS_MNEMONIC_SHA1MSG1:
	case ZYDIS_MNEMONIC_SHA1MSG2:
	case ZYDIS_MNEMONIC_SHA1NEXTE:
	case ZYDIS_MNEMONIC_SHA1RNDS4:
	case ZYDIS_MNEMONIC_SHA256MSG1:
	case ZYDIS_MNEMONIC_SHA256MSG2:
	case ZYDIS_MNEMONIC_SHA256RNDS2:
	case ZYDIS_MNEMONIC_AESDECLAST:
	case ZYDIS_MNEMONIC_AESDEC:
	case ZYDIS_MNEMONIC_AESENCLAST:
	case ZYDIS_MNEMONIC_AESENC:
	case ZYDIS_MNEMONIC_AESIMC:
	case ZYDIS_MNEMONIC_AESKEYGENASSIST:
		// AES instructions
		break;
	case ZYDIS_MNEMONIC_AND:
	case ZYDIS_MNEMONIC_ANDN:
	case ZYDIS_MNEMONIC_ANDPD:
	case ZYDIS_MNEMONIC_ANDPS:
	case ZYDIS_MNEMONIC_ANDNPD:
	case ZYDIS_MNEMONIC_ANDNPS: {
		ut32 bitsize;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 1, "&", DST_AR, &bitsize, addr);
		dst2 = getarg(a, &gop, 0, 0, NULL, DST2_AR, NULL, addr);
		const char *dst_reg64 = rz_reg_32_to_64(a->reg, dst2); // 64-bit destination if exists
		if (a->bits == 64 && dst_reg64) {
			// (64-bit & 32-bit) & 0xFFFF FFFF -> 64-bit, it's alright, higher bytes will be eliminated
			// (consider this is operation with 32-bit regs in 64-bit environment).
			esilprintf(op, "%s,%s,&,0xffffffff,&,%s,=,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,0,cf,:=,0,of,:=",
				src, dst_reg64, dst_reg64, bitsize - 1);
		} else {
			esilprintf(op, "%s,%s,$z,zf,:=,$p,pf,:=,%d,$s,sf,:=,0,cf,:=,0,of,:=", src, dst, bitsize - 1);
		}
	} break;
	case ZYDIS_MNEMONIC_IDIV: {
		arg0 = getarg(a, &gop, 0, 0, NULL, ARG0_AR, NULL, addr);
		arg1 = getarg(a, &gop, 1, 0, NULL, ARG1_AR, NULL, addr);
		arg2 = getarg(a, &gop, 2, 0, NULL, ARG2_AR, NULL, addr);
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

				esilprintf(op, "%d,%s,~,%d,%s,<<,%s,+,~%%,%d,%s,~,%d,%s,<<,%s,+,~/,%s,=,%s,=",
					width * 8, arg0, width * 8, rz_rema, rz_nume, width * 8, arg0, width * 8, rz_rema, rz_nume, rz_quot, rz_rema);
			} else {
				/* should never happen */
			}
		} else {
			// does this instruction even exist?
			int width = INSOP(0).size;
			esilprintf(op, "%d,%s,~,%d,%s,~,~/,%s,=", width * 8, arg2, width * 8, arg1, arg0);
		}
	} break;
	case ZYDIS_MNEMONIC_DIV: {
		int width = INSOP(0).size;
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
		const char *rz_quot = (width == 1) ? "al" : (width == 2) ? "ax"
			: (width == 4)                                   ? "eax"
									 : "rax";
		const char *rz_rema = (width == 1) ? "ah" : (width == 2) ? "dx"
			: (width == 4)                                   ? "edx"
									 : "rdx";
		const char *rz_nume = (width == 1) ? "ax" : rz_quot;
		// DIV does not change flags and is unsigned

		esilprintf(op, "%s,%d,%s,<<,%s,+,%%,%s,%d,%s,<<,%s,+,/,%s,=,%s,=",
			dst, width * 8, rz_rema, rz_nume, dst, width * 8, rz_rema, rz_nume, rz_quot, rz_rema);
	} break;
	case ZYDIS_MNEMONIC_IMUL: {
		arg0 = getarg(a, &gop, 0, 0, NULL, ARG0_AR, NULL, addr);
		arg1 = getarg(a, &gop, 1, 0, NULL, ARG1_AR, NULL, addr);
		arg2 = getarg(a, &gop, 2, 0, NULL, ARG2_AR, NULL, addr);
		op->sign = true;
		int width = INSOP(0).size;
		if (arg2) {
			// flags and sign have been handled
			esilprintf(op, "%d,%s,~,%d,%s,~,*,DUP,%s,=,%s,-,?{,1,1,}{,0,0,},cf,:=,of,:=", width * 8, arg2, width * 8, arg1, arg0, arg0);
		} else {
			if (arg1) {
				esilprintf(op, "%d,%s,~,%d,%s,~,*,DUP,%s,=,%s,-,?{,1,1,}{,0,0,},cf,:=,of,:=", width * 8, arg0, width * 8, arg1, arg0, arg0);
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
						esilprintf(op, "%d,%d,%s,~,%d,%s,~,*,>>,%s,=,%s,%s,*=,%d,%d,%s,~,>>,%s,-,?{,1,1,}{,0,0,},cf,:=,of,:=",
							width * 8, width * 8, arg0, width * 8, rz_nume, rz_rema, arg0, rz_nume, width * 8, width * 8, rz_nume, rz_rema);
					}
				} else {
					/* should never happen */
				}
			}
		}
	} break;
	case ZYDIS_MNEMONIC_MUL: {
		src = getarg(a, &gop, 0, 0, NULL, SRC_AR, NULL, addr);
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
				esilprintf(op, "%d,%s,%s,*,>>,%s,=,%s,%s,*=,%s,?{,1,1,}{,0,0,},cf,:=,of,:=",
					width * 8, src, rz_nume, rz_rema, src, rz_nume, rz_rema);
			}
		} else {
			/* should never happen */
		}
	} break;
	case ZYDIS_MNEMONIC_MULX:
	case ZYDIS_MNEMONIC_MULPD:
	case ZYDIS_MNEMONIC_MULPS:
	case ZYDIS_MNEMONIC_MULSD:
	case ZYDIS_MNEMONIC_MULSS: {
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 1, "*", DST_AR, NULL, addr);
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
	case ZYDIS_MNEMONIC_NEG: {
		ut32 bitsize;
		src = getarg(a, &gop, 0, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 1, NULL, DST_AR, &bitsize, addr);
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
			RZ_LOG_ERROR("x86: unhandled neg bitsize %d\n", bitsize);
			break;
		}
		esilprintf(op, "%s,!,!,cf,:=,%s,0x%" PFMT64x ",^,1,+,%s,$z,zf,:=,0,of,:=,%d,$s,sf,:=,%d,$o,pf,:=",
			src, src, xor, dst, bitsize - 1, bitsize - 1);
	} break;
	case ZYDIS_MNEMONIC_NOT: {
		dst = getarg(a, &gop, 0, 1, "^", DST_AR, NULL, addr);
		esilprintf(op, "-1,%s", dst);
	} break;
	case ZYDIS_MNEMONIC_PACKSSDW:
	case ZYDIS_MNEMONIC_PACKSSWB:
	case ZYDIS_MNEMONIC_PACKUSWB:
		break;
	case ZYDIS_MNEMONIC_PADDB:
	case ZYDIS_MNEMONIC_PADDD:
	case ZYDIS_MNEMONIC_PADDW:
	case ZYDIS_MNEMONIC_PADDSB:
	case ZYDIS_MNEMONIC_PADDSW:
	case ZYDIS_MNEMONIC_PADDUSB:
	case ZYDIS_MNEMONIC_PADDUSW:
		break;
	case ZYDIS_MNEMONIC_XCHG: {
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		if (INSOP(0).type == ZYDIS_OPERAND_TYPE_MEMORY) {
			dst2 = getarg(a, &gop, 0, 1, NULL, DST2_AR, NULL, addr);
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
	case ZYDIS_MNEMONIC_XADD: /* xchg + add */
	{
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 0, NULL, DST_AR, NULL, addr);
		dstAdd = getarg(a, &gop, 0, 1, "+", DSTADD_AR, NULL, addr);
		if (INSOP(0).type == ZYDIS_OPERAND_TYPE_MEMORY) {
			dst2 = getarg(a, &gop, 0, 1, NULL, DST2_AR, NULL, addr);
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
	case ZYDIS_MNEMONIC_FADD:
	case ZYDIS_MNEMONIC_FADDP:
	case ZYDIS_MNEMONIC_PFADD:
		break;
	case ZYDIS_MNEMONIC_ADDPS:
	case ZYDIS_MNEMONIC_ADDSD:
	case ZYDIS_MNEMONIC_ADDSS:
	case ZYDIS_MNEMONIC_ADDSUBPD:
	case ZYDIS_MNEMONIC_ADDSUBPS:
	case ZYDIS_MNEMONIC_ADDPD:
		// The OF, SF, ZF, AF, CF, and PF flags are set according to the
		// result.
		if (INSOP(0).type == ZYDIS_OPERAND_TYPE_MEMORY) {
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			src2 = getarg(a, &gop, 0, 0, NULL, SRC2_AR, NULL, addr);
			dst = getarg(a, &gop, 0, 1, NULL, DST_AR, NULL, addr);
			esilprintf(op, "%s,%s,+,%s", src, src2, dst);
		} else {
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst = getarg(a, &gop, 0, 1, "+", DST_AR, NULL, addr);
			esilprintf(op, "%s,%s", src, dst);
		}
		break;
	case ZYDIS_MNEMONIC_ADD:
		// The OF, SF, ZF, AF, CF, and PF flags are set according to the
		// result.
		{
			ut32 bitsize;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst = getarg(a, &gop, 0, 1, "+", DST_AR, &bitsize, addr);
			esilprintf(op, "%s,%s,%d,$o,of,:=,%d,$s,sf,:=,$z,zf,:=,%d,$c,cf,:=,$p,pf,:=,3,$c,af,:=",
				src, dst, bitsize - 1, bitsize - 1, bitsize - 1);
		}
		break;
	case ZYDIS_MNEMONIC_ADC: {
		ut32 bitsize;
		src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
		dst = getarg(a, &gop, 0, 1, "+", DST_AR, &bitsize, addr);
		// dst = dst + src + cf
		// NOTE: We would like to add the carry first before adding the
		// source to ensure that the flag computation from $c belongs
		// to the operation of adding dst += src rather than the one
		// that adds carry (as esil only keeps track of the last
		// addition to set the flags).
		esilprintf(op, "cf,%s,+,%s,%d,$o,of,:=,%d,$s,sf,:=,$z,zf,:=,%d,$c,cf,:=,$p,pf,:=,3,$c,af,:=",
			src, dst, bitsize - 1, bitsize - 1, bitsize - 1);
	} break;
		/* Direction flag */
	case ZYDIS_MNEMONIC_CLD:
		esilprintf(op, "0,df,:=");
		break;
	case ZYDIS_MNEMONIC_STD:
		esilprintf(op, "1,df,:=");
		break;
	case ZYDIS_MNEMONIC_SUBSD: // cvtss2sd
	case ZYDIS_MNEMONIC_CVTSS2SD: // cvtss2sd
		break;
	case ZYDIS_MNEMONIC_BT:
	case ZYDIS_MNEMONIC_BTC:
	case ZYDIS_MNEMONIC_BTR:
	case ZYDIS_MNEMONIC_BTS:
		if (INSOP(0).type == ZYDIS_OPERAND_TYPE_MEMORY && INSOP(1).type == ZYDIS_OPERAND_TYPE_REGISTER) {
			int width = INSOP(0).size;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst_r = getarg(a, &gop, 0, 2 /* use the address without loading */, NULL, DST_R_AR, NULL, addr);
			esilprintf(op, "0,cf,:=,%d,%s,%%,1,<<,%d,%s,/,%s,+,[%d],&,?{,1,cf,:=,}",
				width * 8, src, width * 8, src, dst_r, width);
			switch (zydecode->mnemonic) {
			case ZYDIS_MNEMONIC_BTS:
			case ZYDIS_MNEMONIC_BTC:
				rz_strbuf_appendf(&op->esil, ",%d,%s,%%,1,<<,%d,%s,/,%s,+,%c=[%d]",
					width * 8, src, width * 8, src, dst_r,
					(zydecode->mnemonic == ZYDIS_MNEMONIC_BTS) ? '|' : '^', width);
				break;
			case ZYDIS_MNEMONIC_BTR:
				getarg(a, &gop, 0, 1, "&", DST_R_AR, NULL, addr);
				rz_strbuf_appendf(&op->esil, ",%d,%s,%%,1,<<,-1,^,%d,%s,/,%s,+,&=[%d]",
					width * 8, src, width * 8, src, dst_r, width);
				break;
			}
		} else {
			int width = INSOP(0).size;
			src = getarg(a, &gop, 1, 0, NULL, SRC_AR, NULL, addr);
			dst_r = getarg(a, &gop, 0, 0, NULL, DST_R_AR, NULL, addr);
			esilprintf(op, "0,cf,:=,%d,%s,%%,1,<<,%s,&,?{,1,cf,:=,}",
				width * 8, src, dst_r);
			switch (zydecode->mnemonic) {
			case ZYDIS_MNEMONIC_BTS:
			case ZYDIS_MNEMONIC_BTC:
				dst_w = getarg(a, &gop, 0, 1, (zydecode->mnemonic == ZYDIS_MNEMONIC_BTS) ? "|" : "^", DST_R_AR, NULL, addr);
				rz_strbuf_appendf(&op->esil, ",%d,%s,%%,1,<<,%s", width * 8, src, dst_w);
				break;
			case ZYDIS_MNEMONIC_BTR:
				dst_w = getarg(a, &gop, 0, 1, "&", DST_R_AR, NULL, addr);
				rz_strbuf_appendf(&op->esil, ",%d,%s,%%,1,<<,-1,^,%s", width * 8, src, dst_w);
				break;
			}
		}
		break;
	}

	if (op->prefix & RZ_ANALYSIS_OP_PREFIX_REP) {
		rz_strbuf_appendf(&op->esil, ",%s,--=,%s,?{,5,GOTO,}", counter, counter);
	}
}

static RzRegItem *zydis_reg2reg(RzReg *reg, int type) {
	if (type == ZYDIS_REGISTER_NONE) {
		return NULL;
	}
	return rz_reg_get(reg, (char *)ZydisRegisterGetString(type), -1);
}

static void set_access_info(RzReg *reg, RzAnalysisOp *op, ZydisDecodedInstruction *zydecode, ZydisDecodedOperand *zydeop, int mode) {
	int i;
	RzAnalysisValue *val;
	int regsz;
	ZydisRegister sp, ip;
	switch (mode) {
	case ZYDIS_MACHINE_MODE_LONG_64:
		regsz = 8;
		sp = ZYDIS_REGISTER_RSP;
		ip = ZYDIS_REGISTER_RIP;
		break;
	default:
		regsz = 4;
		sp = ZYDIS_REGISTER_ESP;
		ip = ZYDIS_REGISTER_EIP;
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
	ZydisRegister *regs_read, *regs_write;
	ut8 read_count = 0;
	ut8 write_count = 0;
	for (int i = 0; i < zydecode->operand_count; i++) {
		ZydisDecodedOperand *operand = &zydeop[i];
		if (operand->type != ZYDIS_OPERAND_TYPE_REGISTER) {
			continue;
		}
		if (operand->actions & ZYDIS_OPERAND_ACTION_READ) {
			regs_read[read_count++] = operand->reg.value;
		} else if (operand->actions & ZYDIS_OPERAND_ACTION_WRITE) {
			regs_write[write_count++] = operand->reg.value;
		}
	}

	if (read_count > 0) {
		for (i = 0; i < read_count; i++) {
			val = rz_analysis_value_new();
			val->type = RZ_ANALYSIS_VAL_REG;
			val->access = RZ_ANALYSIS_ACC_R;
			val->reg = zydis_reg2reg(reg, regs_read[i]);
			rz_list_append(ret, val);
		}
	}
	if (write_count > 0) {
		for (i = 0; i < write_count; i++) {
			val = rz_analysis_value_new();
			val->type = RZ_ANALYSIS_VAL_REG;
			val->access = RZ_ANALYSIS_ACC_W;
			val->reg = zydis_reg2reg(reg, regs_write[i]);
			rz_list_append(ret, val);
		}
	}

	switch (zydecode->mnemonic) {
	case ZYDIS_MNEMONIC_PUSH:
		val = rz_analysis_value_new();
		val->type = RZ_ANALYSIS_VAL_MEM;
		val->access = RZ_ANALYSIS_ACC_W;
		val->reg = zydis_reg2reg(reg, sp);
		val->delta = -zydeop[0].size;
		val->memref = zydeop[0].size;
		rz_list_append(ret, val);
		break;
	case ZYDIS_MNEMONIC_PUSHAD:
	case ZYDIS_MNEMONIC_PUSHF:
		val = rz_analysis_value_new();
		val->type = RZ_ANALYSIS_VAL_MEM;
		val->access = RZ_ANALYSIS_ACC_W;
		val->reg = zydis_reg2reg(reg, sp);
		val->delta = -2;
		val->memref = 2;
		rz_list_append(ret, val);
		break;
	case ZYDIS_MNEMONIC_PUSHFD:
		val = rz_analysis_value_new();
		val->type = RZ_ANALYSIS_VAL_MEM;
		val->access = RZ_ANALYSIS_ACC_W;
		val->reg = zydis_reg2reg(reg, sp);
		val->delta = -4;
		val->memref = 4;
		rz_list_append(ret, val);
		break;
	case ZYDIS_MNEMONIC_PUSHFQ:
		val = rz_analysis_value_new();
		val->type = RZ_ANALYSIS_VAL_MEM;
		val->access = RZ_ANALYSIS_ACC_W;
		val->reg = zydis_reg2reg(reg, sp);
		val->delta = -8;
		val->memref = 8;
		rz_list_append(ret, val);
		break;
	case ZYDIS_MNEMONIC_CALL:
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
	for (int i = 0; i < zydecode->operand_count; i++) {
		if (zydeop[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
			val = rz_analysis_value_new();
			val->type = RZ_ANALYSIS_VAL_MEM;
			switch (zydeop[i].actions) {
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
			val->mul = zydeop[i].mem.scale;
			val->delta = zydeop[i].mem.disp.value;
			if (zydeop[0].mem.base == ZYDIS_REGISTER_RIP || zydeop[0].mem.base == ZYDIS_REGISTER_EIP) {
				val->delta += zydecode->length;
			}
			val->memref = zydeop[i].size;
			val->seg = zydis_reg2reg(reg, zydeop[i].mem.segment);
			val->reg = zydis_reg2reg(reg, zydeop[i].mem.base);
			val->regdelta = zydis_reg2reg(reg, zydeop[i].mem.index);
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

static void set_src_dst(RzReg *reg, RzAnalysisValue *val, ZydisDecodedInstruction *zydecode, ZydisDecodedOperand *zydeop, int x, ut64 addr) {
	switch (zydeop[x].type) {
	case ZYDIS_OPERAND_TYPE_MEMORY:
		val->type = RZ_ANALYSIS_VAL_MEM;
		val->mul = zydeop[x].mem.scale;
		val->delta = zydeop[x].mem.disp.value;
		val->memref = zydeop[x].size;
		val->seg = zydis_reg2reg(reg, zydeop[x].mem.segment);
		val->reg = zydis_reg2reg(reg, zydeop[x].mem.base);
		val->regdelta = zydis_reg2reg(reg, zydeop[x].mem.index);
		break;
	case ZYDIS_OPERAND_TYPE_REGISTER:
		val->type = RZ_ANALYSIS_VAL_REG;
		val->reg = zydis_reg2reg(reg, zydeop[x].reg.value);
		break;
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		val->type = RZ_ANALYSIS_VAL_IMM;
		val->imm = get_imm_reg_value(&zydeop[x], addr, zydecode->length);
		break;
	default:
		break;
	}
}

static void op_fillval(RzAnalysis *a, RzAnalysisOp *op, ZydisDecodedInstruction *zydecode, ZydisDecodedInstruction *zydeop, int mode, ut64 addr) {
	set_access_info(a->reg, op, zydecode, zydeop, mode);
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
		set_src_dst(a->reg, op->dst, zydecode, zydeop, 0, addr);
		set_src_dst(a->reg, op->src[0], zydecode, zydeop, 1, addr);
		set_src_dst(a->reg, op->src[1], zydecode, zydeop, 2, addr);
		set_src_dst(a->reg, op->src[2], zydecode, zydeop, 3, addr);
		break;
	case RZ_ANALYSIS_OP_TYPE_UPUSH:
		if ((op->type & RZ_ANALYSIS_OP_TYPE_REG)) {
			CREATE_SRC_DST(op);
			set_src_dst(a->reg, op->src[0], zydecode, zydeop, 0, addr);
		}
		break;
	default:
		break;
	}
}

static void op0_memimmhandle(RzAnalysisOp *op, ZydisDecodedInstruction *zydecode, ZydisDecodedOperand *zydeop, ut64 addr, int regsz) {
	op->ptr = UT64_MAX;
	switch (zydeop[0].type) {
	case ZYDIS_OPERAND_TYPE_MEMORY:
		op->cycles = CYCLE_MEM;
		op->disp = zydeop[0].mem.disp.value;
		if (!op->disp) {
			op->disp = UT64_MAX;
		}
		op->refptr = zydeop[0].size;
		if (zydeop[0].mem.base == ZYDIS_REGISTER_RIP) {
			op->ptr = addr + zydecode->length + op->disp;
		} else if (zydeop[0].mem.base == ZYDIS_REGISTER_RBP || zydeop[0].mem.base == ZYDIS_REGISTER_EBP) {
			op->type |= RZ_ANALYSIS_OP_TYPE_REG;
			op->stackop = RZ_ANALYSIS_STACK_SET;
			op->stackptr = regsz;
		} else if (zydeop[0].mem.segment == ZYDIS_REGISTER_NONE && zydeop[0].mem.base == ZYDIS_REGISTER_NONE && zydeop[0].mem.index == ZYDIS_REGISTER_NONE && zydeop[0].mem.scale == 1) { // [<addr>]
			op->ptr = op->disp;
			if (op->ptr < 0x1000) {
				op->ptr = UT64_MAX;
			}
		}
		if (zydeop[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			op->val = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
		}
		break;
	case ZYDIS_OPERAND_TYPE_REGISTER:
		if (zydeop[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			//	(zydeop[0].reg != ZYDIS_REGISTER_RSP) && (zydeop[0].reg != ZYDIS_REGISTER_ESP)) {
			op->val = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
		}
		break;
	default:
		break;
	}
}

static void op1_memimmhandle(RzAnalysisOp *op, ZydisDecodedInstruction *zydecode, ZydisDecodedOperand *zydeop, ut64 addr, int regsz) {
	if (op->refptr < 1 || op->ptr == UT64_MAX) {
		switch (zydeop[1].type) {
		case ZYDIS_OPERAND_TYPE_MEMORY:
			op->disp = zydeop[1].mem.disp.value;
			op->refptr = zydeop[1].size;
			if (zydeop[1].mem.base == ZYDIS_REGISTER_RIP) {
				op->ptr = addr + zydecode->length + op->disp;
			} else if (zydeop[1].mem.base == ZYDIS_REGISTER_RBP || zydeop[1].mem.base == ZYDIS_REGISTER_EBP) {
				op->stackop = RZ_ANALYSIS_STACK_GET;
				op->stackptr = regsz;
			} else if (zydeop[1].mem.segment == ZYDIS_REGISTER_NONE && zydeop[1].mem.base == ZYDIS_REGISTER_NONE && zydeop[1].mem.index == ZYDIS_REGISTER_NONE && zydeop[1].mem.scale == 1) { // [<addr>]
				op->ptr = op->disp;
			}
			break;
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			if ((get_imm_reg_value(&INSOP(1), addr, zydecode->length) > 10) &&
				(zydeop[0].reg.value != ZYDIS_REGISTER_RSP) && (zydeop[0].reg.value != ZYDIS_REGISTER_ESP)) {
				op->ptr = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
			}
			break;
		default:
			break;
		}
	}
}

static void op_stackidx(RzAnalysisOp *op, ZydisDecodedInstruction *zydecode, ZydisDecodedOperand *zydeop, bool minus, ut64 addr) {
	if (zydeop[0].type == ZYDIS_OPERAND_TYPE_REGISTER && zydeop[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		if (zydeop[0].reg.value == ZYDIS_REGISTER_RSP || zydeop[0].reg.value == ZYDIS_REGISTER_ESP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			if (minus) {
				op->stackptr = -1 * (int)get_imm_reg_value(&INSOP(1), addr, zydecode->length);
			} else {
				op->stackptr = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
			}
		}
	}
}

static void set_opdir(RzAnalysisOp *op, ZydisDecodedInstruction *zydecode, ZydisDecodedOperand *zydeop) {
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_MOV:
		switch (zydeop[0].type) {
		case ZYDIS_OPERAND_TYPE_MEMORY:
			op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
			break;
		case ZYDIS_OPERAND_TYPE_REGISTER:
			if (zydeop[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
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

static void anop(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, ZydisDecodedInstruction *zydecode, ZydisDecodedOperand *zydeop) {
	struct Getarg gop = {
		.bits = a->bits,
		.zydecode = zydecode,
		.zydeop = zydeop
	};
	int regsz = 4;
	switch (a->bits) {
	case 64: regsz = 8; break;
	case 16: regsz = 2; break;
	default: regsz = 4; break; // 32
	}
	switch (zydecode->mnemonic) {
	case ZYDIS_MNEMONIC_FNOP:
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		/* fallthru */
	case ZYDIS_MNEMONIC_NOP:
	case ZYDIS_MNEMONIC_PAUSE:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case ZYDIS_MNEMONIC_HLT:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case ZYDIS_MNEMONIC_FBLD:
	case ZYDIS_MNEMONIC_FBSTP:
	case ZYDIS_MNEMONIC_FCOMPP:
	case ZYDIS_MNEMONIC_FDECSTP:
	case ZYDIS_MNEMONIC_FEMMS:
	case ZYDIS_MNEMONIC_FFREE:
	case ZYDIS_MNEMONIC_FICOM:
	case ZYDIS_MNEMONIC_FICOMP:
	case ZYDIS_MNEMONIC_FINCSTP:
	case ZYDIS_MNEMONIC_FNCLEX:
	case ZYDIS_MNEMONIC_FNINIT:
	case ZYDIS_MNEMONIC_FNSTCW:
	case ZYDIS_MNEMONIC_FNSTSW:
	case ZYDIS_MNEMONIC_FPATAN:
	case ZYDIS_MNEMONIC_FPREM:
	case ZYDIS_MNEMONIC_FPREM1:
	case ZYDIS_MNEMONIC_FPTAN:
	case ZYDIS_MNEMONIC_FFREEP:
	case ZYDIS_MNEMONIC_FRNDINT:
	case ZYDIS_MNEMONIC_FRSTOR:
	case ZYDIS_MNEMONIC_FNSAVE:
	case ZYDIS_MNEMONIC_FSCALE:
	case ZYDIS_MNEMONIC_FSETPM287_NOP:
	case ZYDIS_MNEMONIC_FSINCOS:
	case ZYDIS_MNEMONIC_FNSTENV:
	case ZYDIS_MNEMONIC_FXAM:
	case ZYDIS_MNEMONIC_FXSAVE:
	case ZYDIS_MNEMONIC_FXSAVE64:
	case ZYDIS_MNEMONIC_FXTRACT:
	case ZYDIS_MNEMONIC_FYL2X:
	case ZYDIS_MNEMONIC_FYL2XP1:
	case ZYDIS_MNEMONIC_FISTTP:
	case ZYDIS_MNEMONIC_FSQRT:
	case ZYDIS_MNEMONIC_FXCH:
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case ZYDIS_MNEMONIC_FTST:
	case ZYDIS_MNEMONIC_FUCOMI:
	case ZYDIS_MNEMONIC_FUCOMPP:
	case ZYDIS_MNEMONIC_FUCOMP:
	case ZYDIS_MNEMONIC_FUCOM:
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case ZYDIS_MNEMONIC_BT:
	case ZYDIS_MNEMONIC_BTC:
	case ZYDIS_MNEMONIC_BTR:
	case ZYDIS_MNEMONIC_BTS:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case ZYDIS_MNEMONIC_FABS:
		op->type = RZ_ANALYSIS_OP_TYPE_ABS;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case ZYDIS_MNEMONIC_FLDCW:
	case ZYDIS_MNEMONIC_FLDENV:
	case ZYDIS_MNEMONIC_FLDL2E:
	case ZYDIS_MNEMONIC_FLDL2T:
	case ZYDIS_MNEMONIC_FLDLG2:
	case ZYDIS_MNEMONIC_FLDLN2:
	case ZYDIS_MNEMONIC_FLDPI:
	case ZYDIS_MNEMONIC_FLDZ:
	case ZYDIS_MNEMONIC_FLD1:
	case ZYDIS_MNEMONIC_FLD:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case ZYDIS_MNEMONIC_FIST:
	case ZYDIS_MNEMONIC_FISTP:
	case ZYDIS_MNEMONIC_FST:
	case ZYDIS_MNEMONIC_FSTP:
	case ZYDIS_MNEMONIC_FSTPNCE:
	case ZYDIS_MNEMONIC_FXRSTOR:
	case ZYDIS_MNEMONIC_FXRSTOR64:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case ZYDIS_MNEMONIC_FDIV:
	case ZYDIS_MNEMONIC_FIDIV:
	case ZYDIS_MNEMONIC_FDIVP:
	case ZYDIS_MNEMONIC_FDIVR:
	case ZYDIS_MNEMONIC_FIDIVR:
	case ZYDIS_MNEMONIC_FDIVRP:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case ZYDIS_MNEMONIC_FSUBR:
	case ZYDIS_MNEMONIC_FISUBR:
	case ZYDIS_MNEMONIC_FSUBRP:
	case ZYDIS_MNEMONIC_FSUB:
	case ZYDIS_MNEMONIC_FISUB:
	case ZYDIS_MNEMONIC_FSUBP:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case ZYDIS_MNEMONIC_FMUL:
	case ZYDIS_MNEMONIC_FIMUL:
	case ZYDIS_MNEMONIC_FMULP:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case ZYDIS_MNEMONIC_CLI:
	case ZYDIS_MNEMONIC_STI:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	case ZYDIS_MNEMONIC_CLC:
	case ZYDIS_MNEMONIC_STC:
	case ZYDIS_MNEMONIC_CLAC:
	case ZYDIS_MNEMONIC_CLGI:
	case ZYDIS_MNEMONIC_CLTS:
	case ZYDIS_MNEMONIC_CLWB:
	case ZYDIS_MNEMONIC_STAC:
	case ZYDIS_MNEMONIC_STGI:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	// cmov
	case ZYDIS_MNEMONIC_SETNZ:
	case ZYDIS_MNEMONIC_SETNO:
	case ZYDIS_MNEMONIC_SETNP:
	case ZYDIS_MNEMONIC_SETNS:
	case ZYDIS_MNEMONIC_SETO:
	case ZYDIS_MNEMONIC_SETP:
	case ZYDIS_MNEMONIC_SETS:
	case ZYDIS_MNEMONIC_SETL:
	case ZYDIS_MNEMONIC_SETLE:
	case ZYDIS_MNEMONIC_SETB:
	case ZYDIS_MNEMONIC_SETNLE:
	case ZYDIS_MNEMONIC_SETNB:
	case ZYDIS_MNEMONIC_SETNBE:
	case ZYDIS_MNEMONIC_SETBE:
	case ZYDIS_MNEMONIC_SETZ:
	case ZYDIS_MNEMONIC_SETNL:
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		op->family = 0;
		break;
	// cmov
	case ZYDIS_MNEMONIC_FCMOVBE:
	case ZYDIS_MNEMONIC_FCMOVB:
	case ZYDIS_MNEMONIC_FCMOVNBE:
	case ZYDIS_MNEMONIC_FCMOVNB:
	case ZYDIS_MNEMONIC_FCMOVE:
	case ZYDIS_MNEMONIC_FCMOVNE:
	case ZYDIS_MNEMONIC_FCMOVNU:
	case ZYDIS_MNEMONIC_FCMOVU:
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		break;
	case ZYDIS_MNEMONIC_CMOVNBE:
	case ZYDIS_MNEMONIC_CMOVNB:
	case ZYDIS_MNEMONIC_CMOVB:
	case ZYDIS_MNEMONIC_CMOVBE:
	case ZYDIS_MNEMONIC_CMOVZ:
	case ZYDIS_MNEMONIC_CMOVNLE:
	case ZYDIS_MNEMONIC_CMOVNL:
	case ZYDIS_MNEMONIC_CMOVL:
	case ZYDIS_MNEMONIC_CMOVLE:
	case ZYDIS_MNEMONIC_CMOVNZ:
	case ZYDIS_MNEMONIC_CMOVNO:
	case ZYDIS_MNEMONIC_CMOVNP:
	case ZYDIS_MNEMONIC_CMOVNS:
	case ZYDIS_MNEMONIC_CMOVO:
	case ZYDIS_MNEMONIC_CMOVP:
	case ZYDIS_MNEMONIC_CMOVS:
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		break;
	case ZYDIS_MNEMONIC_STOSB:
	case ZYDIS_MNEMONIC_STOSD:
	case ZYDIS_MNEMONIC_STOSQ:
	case ZYDIS_MNEMONIC_STOSW:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case ZYDIS_MNEMONIC_LODSB:
	case ZYDIS_MNEMONIC_LODSD:
	case ZYDIS_MNEMONIC_LODSQ:
	case ZYDIS_MNEMONIC_LODSW:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case ZYDIS_MNEMONIC_PALIGNR:
	case ZYDIS_MNEMONIC_VALIGND:
	case ZYDIS_MNEMONIC_VALIGNQ:
	case ZYDIS_MNEMONIC_VPALIGNR:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case ZYDIS_MNEMONIC_CPUID:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case ZYDIS_MNEMONIC_SFENCE:
	case ZYDIS_MNEMONIC_LFENCE:
	case ZYDIS_MNEMONIC_MFENCE:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_THREAD;
		break;
	// mov
	case ZYDIS_MNEMONIC_MOVNTQ:
	case ZYDIS_MNEMONIC_MOVNTDQA:
	case ZYDIS_MNEMONIC_MOVNTDQ:
	case ZYDIS_MNEMONIC_MOVNTI:
	case ZYDIS_MNEMONIC_MOVNTPD:
	case ZYDIS_MNEMONIC_MOVNTPS:
	case ZYDIS_MNEMONIC_MOVNTSD:
	case ZYDIS_MNEMONIC_MOVNTSS:
	case ZYDIS_MNEMONIC_VMOVNTDQA:
	case ZYDIS_MNEMONIC_VMOVNTDQ:
	case ZYDIS_MNEMONIC_VMOVNTPD:
	case ZYDIS_MNEMONIC_VMOVNTPS:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_SSE;
		break;
	case ZYDIS_MNEMONIC_PCMPEQB:
	case ZYDIS_MNEMONIC_PCMPEQD:
	case ZYDIS_MNEMONIC_PCMPEQW:
	case ZYDIS_MNEMONIC_PCMPGTB:
	case ZYDIS_MNEMONIC_PCMPGTD:
	case ZYDIS_MNEMONIC_PCMPGTW:
	case ZYDIS_MNEMONIC_PCMPEQQ:
	case ZYDIS_MNEMONIC_PCMPESTRI:
	case ZYDIS_MNEMONIC_PCMPESTRM:
	case ZYDIS_MNEMONIC_PCMPGTQ:
	case ZYDIS_MNEMONIC_PCMPISTRI:
	case ZYDIS_MNEMONIC_PCMPISTRM:
	case ZYDIS_MNEMONIC_VPCMPB:
	case ZYDIS_MNEMONIC_VPCMPD:
	case ZYDIS_MNEMONIC_VPCMPEQB:
	case ZYDIS_MNEMONIC_VPCMPEQD:
	case ZYDIS_MNEMONIC_VPCMPEQQ:
	case ZYDIS_MNEMONIC_VPCMPEQW:
	case ZYDIS_MNEMONIC_VPCMPESTRI:
	case ZYDIS_MNEMONIC_VPCMPESTRM:
	case ZYDIS_MNEMONIC_VPCMPGTB:
	case ZYDIS_MNEMONIC_VPCMPGTD:
	case ZYDIS_MNEMONIC_VPCMPGTQ:
	case ZYDIS_MNEMONIC_VPCMPGTW:
	case ZYDIS_MNEMONIC_VPCMPISTRI:
	case ZYDIS_MNEMONIC_VPCMPISTRM:
	case ZYDIS_MNEMONIC_VPCMPQ:
	case ZYDIS_MNEMONIC_VPCMPUB:
	case ZYDIS_MNEMONIC_VPCMPUD:
	case ZYDIS_MNEMONIC_VPCMPUQ:
	case ZYDIS_MNEMONIC_VPCMPUW:
	case ZYDIS_MNEMONIC_VPCMPW:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_SSE;
		break;
	case ZYDIS_MNEMONIC_MOVSS:
	case ZYDIS_MNEMONIC_MOV:
	case ZYDIS_MNEMONIC_MOVAPS:
	case ZYDIS_MNEMONIC_MOVAPD:
	case ZYDIS_MNEMONIC_MOVZX:
	case ZYDIS_MNEMONIC_MOVUPS:
	case ZYDIS_MNEMONIC_MOVHPD:
	case ZYDIS_MNEMONIC_MOVHPS:
	case ZYDIS_MNEMONIC_MOVLPD:
	case ZYDIS_MNEMONIC_MOVLPS:
	case ZYDIS_MNEMONIC_MOVBE:
	case ZYDIS_MNEMONIC_MOVSB:
	case ZYDIS_MNEMONIC_MOVSD:
	case ZYDIS_MNEMONIC_MOVSQ:
	case ZYDIS_MNEMONIC_MOVSX:
	case ZYDIS_MNEMONIC_MOVSXD:
	case ZYDIS_MNEMONIC_MOVSW:
	case ZYDIS_MNEMONIC_MOVD:
	case ZYDIS_MNEMONIC_MOVQ:
	case ZYDIS_MNEMONIC_MOVDQ2Q: {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op0_memimmhandle(op, zydecode, zydeop, addr, regsz);
		op1_memimmhandle(op, zydecode, zydeop, addr, regsz);
	} break;
	case ZYDIS_MNEMONIC_ROL:
	case ZYDIS_MNEMONIC_RCL:
		// TODO: RCL Still does not work as intended
		//  - Set flags
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case ZYDIS_MNEMONIC_ROR:
	case ZYDIS_MNEMONIC_RCR:
		// TODO: RCR Still does not work as intended
		//  - Set flags
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case ZYDIS_MNEMONIC_SHL:
	case ZYDIS_MNEMONIC_SHLD:
	case ZYDIS_MNEMONIC_SHLX:
		// TODO: Set CF: Carry flag is the last bit shifted out due to
		// this operation. It is undefined for SHL and SHR where the
		// number of bits shifted is greater than the size of the
		// destination.
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case ZYDIS_MNEMONIC_SAR:
	case ZYDIS_MNEMONIC_SARX:
		// TODO: Set CF. See case ZYDIS_MNEMONIC_SHL for more details.
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	// case ZYDIS_MNEMONIC_SAL:
	case ZYDIS_MNEMONIC_SALC:
		op->type = RZ_ANALYSIS_OP_TYPE_SAL;
		break;
	case ZYDIS_MNEMONIC_SHR:
	case ZYDIS_MNEMONIC_SHRD:
	case ZYDIS_MNEMONIC_SHRX:
		// TODO: Set CF: See case ZYDIS_MNEMONIC_SAL for more details.
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		op->val = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
		// XXX this should be op->imm
		// op->src[0] = rz_analysis_value_new ();
		// op->src[0]->imm = get_imm_reg_value(&INSOP(1),addr,zydecode->length);
		break;
	case ZYDIS_MNEMONIC_CMP:
	case ZYDIS_MNEMONIC_CMPPD:
	case ZYDIS_MNEMONIC_CMPPS:
	case ZYDIS_MNEMONIC_CMPSW:
	case ZYDIS_MNEMONIC_CMPSD:
	case ZYDIS_MNEMONIC_CMPSQ:
	case ZYDIS_MNEMONIC_CMPSB:
	case ZYDIS_MNEMONIC_CMPSS:
	case ZYDIS_MNEMONIC_TEST:
		if (zydecode->mnemonic == ZYDIS_MNEMONIC_TEST) {
			op->type = RZ_ANALYSIS_OP_TYPE_ACMP; // compare via and
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		}
		switch (zydeop[0].type) {
		case ZYDIS_OPERAND_TYPE_MEMORY:
			op->disp = zydeop[0].mem.disp.value;
			op->refptr = zydeop[0].size;
			if (zydeop[0].mem.base == ZYDIS_REGISTER_RIP) {
				op->ptr = addr + zydecode->length + op->disp;
			} else if (zydeop[0].mem.base == ZYDIS_REGISTER_RBP || zydeop[0].mem.base == ZYDIS_REGISTER_EBP) {
				op->stackop = RZ_ANALYSIS_STACK_SET;
				op->stackptr = regsz;
				op->type |= RZ_ANALYSIS_OP_TYPE_REG;
			} else if (zydeop[0].mem.segment == ZYDIS_REGISTER_NONE && zydeop[0].mem.base == ZYDIS_REGISTER_NONE && zydeop[0].mem.index == ZYDIS_REGISTER_NONE && zydeop[0].mem.scale == 1) { // [<addr>]
				op->ptr = op->disp;
			}
			if (zydeop[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				op->val = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
			}
			break;
		default:
			switch (zydeop[1].type) {
			case ZYDIS_OPERAND_TYPE_MEMORY:
				op->disp = zydeop[1].mem.disp.value;
				op->refptr = zydeop[1].size;
				if (zydeop[1].mem.base == ZYDIS_REGISTER_RIP) {
					op->ptr = addr + zydecode->length + op->disp;
				} else if (zydeop[1].mem.base == ZYDIS_REGISTER_RBP || zydeop[1].mem.base == ZYDIS_REGISTER_EBP) {
					op->type |= RZ_ANALYSIS_OP_TYPE_REG;
					op->stackop = RZ_ANALYSIS_STACK_SET;
					op->stackptr = regsz;
				} else if (zydeop[1].mem.segment == ZYDIS_REGISTER_NONE && zydeop[1].mem.base == ZYDIS_REGISTER_NONE && zydeop[1].mem.index == ZYDIS_REGISTER_NONE && zydeop[1].mem.scale == 1) { // [<addr>]
					op->ptr = op->disp;
				}
				if (zydeop[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
					op->val = get_imm_reg_value(&INSOP(0), addr, zydecode->length);
				}
				break;
			case ZYDIS_OPERAND_TYPE_IMMEDIATE:
				op->val = op->ptr = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
				break;
			default:
				break;
			}
			break;
		}
		break;
	case ZYDIS_MNEMONIC_LEA:
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		switch (zydeop[1].type) {
		case ZYDIS_OPERAND_TYPE_MEMORY:
			// op->type = RZ_ANALYSIS_OP_TYPE_ULEA;
			op->disp = zydeop[1].mem.disp.value;
			op->refptr = zydeop[1].size;
			switch (zydeop[1].mem.base) {
			case ZYDIS_REGISTER_RIP:
				op->ptr = addr + op->size + op->disp;
				break;
			case ZYDIS_REGISTER_RBP:
			case ZYDIS_REGISTER_EBP:
				op->stackop = RZ_ANALYSIS_STACK_GET;
				op->stackptr = regsz;
				break;
			default:
				/* unhandled */
				break;
			}
			break;
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			if (get_imm_reg_value(&INSOP(1), addr, zydecode->length) > 10) {
				op->ptr = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
			}
			break;
		default:
			break;
		}
		break;
	// pushal, popal - push/pop EAX,EBX,ECX,EDX,ESP,EBP,ESI,EDI
	case ZYDIS_MNEMONIC_PUSHAD:
	case ZYDIS_MNEMONIC_ENTER:
	case ZYDIS_MNEMONIC_PUSH:
	case ZYDIS_MNEMONIC_PUSHF:
	case ZYDIS_MNEMONIC_PUSHFD:
	case ZYDIS_MNEMONIC_PUSHFQ:
		switch (zydeop[0].type) {
		case ZYDIS_OPERAND_TYPE_MEMORY:
			if (zydeop[0].mem.disp.value && !zydeop[0].mem.base && !zydeop[0].mem.index) {
				op->val = op->ptr = zydeop[0].mem.disp.value;
				op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			} else {
				op->type = RZ_ANALYSIS_OP_TYPE_UPUSH;
			}
			op->cycles = CYCLE_REG + CYCLE_MEM;
			break;
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			op->val = op->ptr = get_imm_reg_value(&INSOP(0), addr, zydecode->length);
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			op->cycles = CYCLE_REG + CYCLE_MEM;
			break;
		case ZYDIS_OPERAND_TYPE_REGISTER:
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
	case ZYDIS_MNEMONIC_LEAVE:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		// leave is mov rsp, rbp; pop rbp
		// which may not be exactly a reset depending on the context,
		// but usually it is and this is the best guess we can make here.
		op->stackop = RZ_ANALYSIS_STACK_RESET;
		break;
	case ZYDIS_MNEMONIC_POP:
	case ZYDIS_MNEMONIC_POPF:
	case ZYDIS_MNEMONIC_POPFD:
	case ZYDIS_MNEMONIC_POPFQ:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -regsz;
		break;
	case ZYDIS_MNEMONIC_POPAD:
	case ZYDIS_MNEMONIC_IRET:
	case ZYDIS_MNEMONIC_IRETD:
	case ZYDIS_MNEMONIC_IRETQ:
	case ZYDIS_MNEMONIC_SYSRET:
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		/* fallthrough */
	case ZYDIS_MNEMONIC_RET:
		// case ZYDIS_MNEMONIC_RETF:
		// case ZYDIS_MNEMONIC_RETFQ:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -regsz;
		op->cycles = CYCLE_MEM + CYCLE_JMP;
		break;
	case ZYDIS_MNEMONIC_UD0:
	case ZYDIS_MNEMONIC_UD2:
#if CS_API_MAJOR == 4
	case ZYDIS_MNEMONIC_UD2B:
#endif
	case ZYDIS_MNEMONIC_INT3:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP; // TRAP
		break;
	case ZYDIS_MNEMONIC_INT1:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->val = 1;
		break;
	case ZYDIS_MNEMONIC_INT:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->val = (int)get_imm_reg_value(&INSOP(0), addr, zydecode->length);
		break;
	case ZYDIS_MNEMONIC_SYSCALL:
	case ZYDIS_MNEMONIC_SYSENTER:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->cycles = CYCLE_JMP;
		break;
	case ZYDIS_MNEMONIC_SYSEXIT:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	case ZYDIS_MNEMONIC_INTO:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		// int4 if overflow bit is set , so this is an optional swi
		op->type |= RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case ZYDIS_MNEMONIC_VMCALL:
	case ZYDIS_MNEMONIC_VMMCALL:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_LOOP:
	case ZYDIS_MNEMONIC_LOOPE:
	case ZYDIS_MNEMONIC_LOOPNE:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + op->size + zydeop[0].imm.value.s;
		op->fail = addr + op->size;
		op->cycles = CYCLE_JMP;
		switch (zydecode->mnemonic) {
		case ZYDIS_MNEMONIC_JL:
		case ZYDIS_MNEMONIC_JLE:
		case ZYDIS_MNEMONIC_JS:
		case ZYDIS_MNEMONIC_JNLE:
		case ZYDIS_MNEMONIC_JNL:
			op->sign = true;
			break;
		}
		break;
	case ZYDIS_MNEMONIC_CALL:
		// case ZYDIS_MNEMONIC_LCALL:
		op->cycles = CYCLE_JMP + CYCLE_MEM;
		switch (zydeop[0].type) {
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			// TODO: what if UCALL?
			if (zydeop[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				ut64 seg = get_imm_reg_value(&INSOP(0), addr, zydecode->length);
				ut64 off = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
				op->ptr = zydeop[0].mem.disp.value;
				op->jump = (seg << a->seggrn) + off;
			} else {
				op->jump = get_imm_reg_value(&INSOP(0), addr, zydecode->length);
			}
			op->fail = addr + op->size;
			break;
		case ZYDIS_OPERAND_TYPE_MEMORY:
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
			op->jump = UT64_MAX;
			op->ptr = zydeop[0].mem.disp.value;
			op->disp = zydeop[0].mem.disp.value;
			op->reg = NULL;
			op->ireg = NULL;
			op->cycles += CYCLE_MEM;
			if (zydeop[0].mem.index == ZYDIS_REGISTER_NONE) {
				if (zydeop[0].mem.base != ZYDIS_REGISTER_NONE) {
					op->reg = ZydisRegisterGetString(zydeop[0].mem.base);
					op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
				}
			} else {
				op->ireg = ZydisRegisterGetString(zydeop[0].mem.index);
				op->scale = zydeop[0].mem.scale;
			}
			if (zydeop[0].mem.base == ZYDIS_REGISTER_RIP) {
				op->ptr += addr + zydecode->length;
				op->refptr = 8;
			}
			break;
		case ZYDIS_OPERAND_TYPE_REGISTER:
			op->reg = ZydisRegisterGetString(zydeop[0].reg.value);
			op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
			op->ptr = UT64_MAX;
			op->cycles += CYCLE_REG;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
			op->jump = UT64_MAX;
			break;
		}
		break;
	case ZYDIS_MNEMONIC_JMP:
		//  TODO: what if UJMP?
		switch (zydeop[0].type) {
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			if (zydeop[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				ut64 seg = get_imm_reg_value(&INSOP(0), addr, zydecode->length);
				ut64 off = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
				op->ptr = zydeop[0].mem.disp.value;
				op->jump = (seg << a->seggrn) + off;
			} else {
				op->jump = get_imm_reg_value(&INSOP(0), addr, zydecode->length);
				if (a->bits == 16) {
					// https://github.com/capstone-engine/capstone/issues/111
					// according to the x86 manual: the upper two bytes of the EIP register are cleared.
					op->jump &= UT16_MAX;
					op->jump |= (UT64_16U & addr);
				}
			}
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->cycles = CYCLE_JMP;
			break;
		case ZYDIS_OPERAND_TYPE_MEMORY:
			// op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			op->type = RZ_ANALYSIS_OP_TYPE_MJMP;
			op->ptr = zydeop[0].mem.disp.value;
			op->disp = zydeop[0].mem.disp.value;
			op->reg = NULL;
			op->ireg = NULL;
			op->cycles = CYCLE_JMP + CYCLE_MEM;
			if (zydeop[0].mem.base != ZYDIS_REGISTER_NONE) {
				if (zydeop[0].mem.base != ZYDIS_REGISTER_NONE) {
					op->reg = ZydisRegisterGetString(zydeop[0].mem.base);
					op->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
				}
			}
			if (zydeop[0].mem.index == ZYDIS_REGISTER_NONE) {
				op->ireg = NULL;
			} else {
				op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
				op->ireg = ZydisRegisterGetString(zydeop[0].mem.index);
				op->scale = zydeop[0].mem.scale;
			}
			if (zydeop[0].mem.base == ZYDIS_REGISTER_RIP) {
				op->ptr += addr + zydecode->length;
				op->refptr = 8;
			}
			break;
		case ZYDIS_OPERAND_TYPE_REGISTER: {
			op->cycles = CYCLE_JMP + CYCLE_REG;
			op->reg = ZydisRegisterGetString(zydeop[0].reg.value);
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
			op->ptr = UT64_MAX;
		} break;
		// case ZYDIS_OPERAND_TYPE_FP:
		default: // other?
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			op->ptr = UT64_MAX;
			break;
		}
		break;
	case ZYDIS_MNEMONIC_IN:
	case ZYDIS_MNEMONIC_INSW:
	case ZYDIS_MNEMONIC_INSD:
	case ZYDIS_MNEMONIC_INSB:
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->type2 = 0;
		break;
	case ZYDIS_MNEMONIC_OUT:
	case ZYDIS_MNEMONIC_OUTSB:
	case ZYDIS_MNEMONIC_OUTSD:
	case ZYDIS_MNEMONIC_OUTSW:
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->type2 = 1;
		break;
	case ZYDIS_MNEMONIC_VXORPD:
	case ZYDIS_MNEMONIC_VXORPS:
	case ZYDIS_MNEMONIC_VPXORD:
	case ZYDIS_MNEMONIC_VPXORQ:
	case ZYDIS_MNEMONIC_VPXOR:
	case ZYDIS_MNEMONIC_XORPS:
	case ZYDIS_MNEMONIC_KXORW:
	case ZYDIS_MNEMONIC_PXOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case ZYDIS_MNEMONIC_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		// TODO: Add stack indexing handling chang
		op0_memimmhandle(op, zydecode, zydeop, addr, regsz);
		op1_memimmhandle(op, zydecode, zydeop, addr, regsz);
		break;
	case ZYDIS_MNEMONIC_OR:
		// The OF and CF flags are cleared; the SF, ZF, and PF flags are
		// set according to the result. The state of the AF flag is
		// undefined.
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		// TODO: Add stack indexing handling chang
		op0_memimmhandle(op, zydecode, zydeop, addr, regsz);
		op1_memimmhandle(op, zydecode, zydeop, addr, regsz);
		break;
	case ZYDIS_MNEMONIC_INC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->val = 1;
		break;
	case ZYDIS_MNEMONIC_DEC:
		// The CF flag is not affected. The OF, SF, ZF, AF, and PF flags
		// are set according to the result.
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->val = 1;
		break;
	case ZYDIS_MNEMONIC_NEG:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case ZYDIS_MNEMONIC_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case ZYDIS_MNEMONIC_PSUBB:
	case ZYDIS_MNEMONIC_PSUBW:
	case ZYDIS_MNEMONIC_PSUBD:
	case ZYDIS_MNEMONIC_PSUBQ:
	case ZYDIS_MNEMONIC_PSUBSB:
	case ZYDIS_MNEMONIC_PSUBSW:
	case ZYDIS_MNEMONIC_PSUBUSB:
	case ZYDIS_MNEMONIC_PSUBUSW:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case ZYDIS_MNEMONIC_SUB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op_stackidx(op, zydecode, zydeop, true, addr);
		op0_memimmhandle(op, zydecode, zydeop, addr, regsz);
		op1_memimmhandle(op, zydecode, zydeop, addr, regsz);
		break;
	case ZYDIS_MNEMONIC_SBB:
		// dst = dst - (src + cf)
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case ZYDIS_MNEMONIC_LIDT:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	case ZYDIS_MNEMONIC_SIDT:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	case ZYDIS_MNEMONIC_RDRAND:
	case ZYDIS_MNEMONIC_RDSEED:
	case ZYDIS_MNEMONIC_RDMSR:
	case ZYDIS_MNEMONIC_RDPMC:
	case ZYDIS_MNEMONIC_RDTSC:
	case ZYDIS_MNEMONIC_RDTSCP:
	case ZYDIS_MNEMONIC_CRC32:
	case ZYDIS_MNEMONIC_SHA1MSG1:
	case ZYDIS_MNEMONIC_SHA1MSG2:
	case ZYDIS_MNEMONIC_SHA1NEXTE:
	case ZYDIS_MNEMONIC_SHA1RNDS4:
	case ZYDIS_MNEMONIC_SHA256MSG1:
	case ZYDIS_MNEMONIC_SHA256MSG2:
	case ZYDIS_MNEMONIC_SHA256RNDS2:
	case ZYDIS_MNEMONIC_AESDECLAST:
	case ZYDIS_MNEMONIC_AESDEC:
	case ZYDIS_MNEMONIC_AESENCLAST:
	case ZYDIS_MNEMONIC_AESENC:
	case ZYDIS_MNEMONIC_AESIMC:
	case ZYDIS_MNEMONIC_AESKEYGENASSIST:
		// AES instructions
		op->family = RZ_ANALYSIS_OP_FAMILY_CRYPTO;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV; // XXX
		break;
	case ZYDIS_MNEMONIC_ANDN:
	case ZYDIS_MNEMONIC_ANDPD:
	case ZYDIS_MNEMONIC_ANDPS:
	case ZYDIS_MNEMONIC_ANDNPD:
	case ZYDIS_MNEMONIC_ANDNPS:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case ZYDIS_MNEMONIC_AND:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		// TODO: Add stack register change operation
		op0_memimmhandle(op, zydecode, zydeop, addr, regsz);
		op1_memimmhandle(op, zydecode, zydeop, addr, regsz);
		break;
	case ZYDIS_MNEMONIC_IDIV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case ZYDIS_MNEMONIC_DIV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case ZYDIS_MNEMONIC_IMUL:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->sign = true;
		break;
	case ZYDIS_MNEMONIC_AAM:
	case ZYDIS_MNEMONIC_MUL:
	case ZYDIS_MNEMONIC_MULX:
	case ZYDIS_MNEMONIC_MULPD:
	case ZYDIS_MNEMONIC_MULPS:
	case ZYDIS_MNEMONIC_MULSD:
	case ZYDIS_MNEMONIC_MULSS:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case ZYDIS_MNEMONIC_PACKSSDW:
	case ZYDIS_MNEMONIC_PACKSSWB:
	case ZYDIS_MNEMONIC_PACKUSWB:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
		break;
	case ZYDIS_MNEMONIC_PADDB:
	case ZYDIS_MNEMONIC_PADDD:
	case ZYDIS_MNEMONIC_PADDW:
	case ZYDIS_MNEMONIC_PADDSB:
	case ZYDIS_MNEMONIC_PADDSW:
	case ZYDIS_MNEMONIC_PADDUSB:
	case ZYDIS_MNEMONIC_PADDUSW:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
		break;
	case ZYDIS_MNEMONIC_XCHG:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case ZYDIS_MNEMONIC_XADD: /* xchg + add */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	case ZYDIS_MNEMONIC_FADD:
#if CS_API_MAJOR == 4
	case ZYDIS_MNEMONIC_FADDP:
#endif
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case ZYDIS_MNEMONIC_ADDPS:
	case ZYDIS_MNEMONIC_ADDSD:
	case ZYDIS_MNEMONIC_ADDSS:
	case ZYDIS_MNEMONIC_ADDSUBPD:
	case ZYDIS_MNEMONIC_ADDSUBPS:
	case ZYDIS_MNEMONIC_ADDPD:
		// The OF, SF, ZF, AF, CF, and PF flags are set according to the
		// result.
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op_stackidx(op, zydecode, zydeop, true, addr);
		op->val = get_imm_reg_value(&INSOP(1), addr, zydecode->length);
		break;
	case ZYDIS_MNEMONIC_ADD:
		// The OF, SF, ZF, AF, CF, and PF flags are set according to the
		// result.
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op_stackidx(op, zydecode, zydeop, true, addr);
		op0_memimmhandle(op, zydecode, zydeop, addr, regsz);
		op1_memimmhandle(op, zydecode, zydeop, addr, regsz);
		break;
	case ZYDIS_MNEMONIC_ADC:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
		/* Direction flag */
	case ZYDIS_MNEMONIC_CLD:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case ZYDIS_MNEMONIC_STD:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case ZYDIS_MNEMONIC_SUBSD: // cvtss2sd
	case ZYDIS_MNEMONIC_CVTSS2SD: // cvtss2sd
		break;
	}

	switch (zydecode->mnemonic) {
	case ZYDIS_MNEMONIC_PADDB:
	case ZYDIS_MNEMONIC_PADDW:
	case ZYDIS_MNEMONIC_PADDD:
	case ZYDIS_MNEMONIC_PSUBB:
	case ZYDIS_MNEMONIC_PSUBW:
	case ZYDIS_MNEMONIC_PSUBD:
	case ZYDIS_MNEMONIC_PMULHW:
	case ZYDIS_MNEMONIC_PMULLW:
	case ZYDIS_MNEMONIC_PMADDWD:
	case ZYDIS_MNEMONIC_PAND:
	case ZYDIS_MNEMONIC_PANDN:
	case ZYDIS_MNEMONIC_POR:
	case ZYDIS_MNEMONIC_PXOR:
	case ZYDIS_MNEMONIC_PCMPEQB:
	case ZYDIS_MNEMONIC_PCMPEQW:
	case ZYDIS_MNEMONIC_PCMPEQD:
	case ZYDIS_MNEMONIC_PSLLD:
	case ZYDIS_MNEMONIC_PSLLW:
	case ZYDIS_MNEMONIC_PSRLQ:
	case ZYDIS_MNEMONIC_PSUBSB:
	case ZYDIS_MNEMONIC_PSUBSW:
	case ZYDIS_MNEMONIC_PADDQ:
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
		break;
	// SSE1 Instructions:
	case ZYDIS_MNEMONIC_ADDPS:
	case ZYDIS_MNEMONIC_ADDSS:
	case ZYDIS_MNEMONIC_ANDPS:
	case ZYDIS_MNEMONIC_CMPPS:
	case ZYDIS_MNEMONIC_CMPSS:
	case ZYDIS_MNEMONIC_DIVPS:
	case ZYDIS_MNEMONIC_DIVSS:
	case ZYDIS_MNEMONIC_MAXPS:
	case ZYDIS_MNEMONIC_MAXSS:
	case ZYDIS_MNEMONIC_MINPS:
	case ZYDIS_MNEMONIC_MINSS:
	case ZYDIS_MNEMONIC_MULPS:
	case ZYDIS_MNEMONIC_MULSS:
	case ZYDIS_MNEMONIC_ORPS:
	// case ZYDIS_MNEMONIC_ORSS:
	case ZYDIS_MNEMONIC_RSQRTPS:
	case ZYDIS_MNEMONIC_RSQRTSS:
	case ZYDIS_MNEMONIC_SUBPS:
	case ZYDIS_MNEMONIC_SUBSS:
	case ZYDIS_MNEMONIC_SQRTPS:
	case ZYDIS_MNEMONIC_SQRTSS:
	// SSE2 Instructions:
	// case ZYDIS_MNEMONIC_ADDPS:
	// case ZYDIS_MNEMONIC_ADDSS:
	// case ZYDIS_MNEMONIC_ADDPD:
	// case ZYDIS_MNEMONIC_SUBPS:
	// case ZYDIS_MNEMONIC_SUBSS:
	// case ZYDIS_MNEMONIC_MULPS:
	// case ZYDIS_MNEMONIC_MULSS:
	// case ZYDIS_MNEMONIC_DIVPS:
	// case ZYDIS_MNEMONIC_DIVSS:
	// case ZYDIS_MNEMONIC_MAXPS:
	// case ZYDIS_MNEMONIC_MAXSS:
	// case ZYDIS_MNEMONIC_MINPS:
	// case ZYDIS_MNEMONIC_MINSS:
	// case ZYDIS_MNEMONIC_CMPPS:
	// case ZYDIS_MNEMONIC_CMPSS:
	case ZYDIS_MNEMONIC_CVTPI2PS:
	case ZYDIS_MNEMONIC_CVTSS2SI:
	case ZYDIS_MNEMONIC_CVTPS2PI:
	case ZYDIS_MNEMONIC_CVTSI2SS:
	case ZYDIS_MNEMONIC_CVTTPD2DQ:
	case ZYDIS_MNEMONIC_CVTPD2PS:
	case ZYDIS_MNEMONIC_CVTPS2PD:
	case ZYDIS_MNEMONIC_CVTSD2SI:
	case ZYDIS_MNEMONIC_CVTSS2SD:
	case ZYDIS_MNEMONIC_CVTSD2SS:
	case ZYDIS_MNEMONIC_MOVAPD:
	case ZYDIS_MNEMONIC_MOVAPS:
	case ZYDIS_MNEMONIC_MOVD:
	case ZYDIS_MNEMONIC_MOVQ:
	case ZYDIS_MNEMONIC_PMOVMSKB:
	// case ZYDIS_MNEMONIC_PSHUFPS:
	case ZYDIS_MNEMONIC_PSHUFD:
	case ZYDIS_MNEMONIC_PSHUFHW:
	case ZYDIS_MNEMONIC_PSHUFLW:
	case ZYDIS_MNEMONIC_PTEST:
	// SSE3 Instructions:
	case ZYDIS_MNEMONIC_ADDPD:
	// case ZYDIS_MNEMONIC_ADDPS:
	// case ZYDIS_MNEMONIC_ANDPD:
	// case ZYDIS_MNEMONIC_ANDPS:
	case ZYDIS_MNEMONIC_CMPPD:
	// case ZYDIS_MNEMONIC_CMPPS:
	case ZYDIS_MNEMONIC_CVTDQ2PS:
	case ZYDIS_MNEMONIC_CVTPS2DQ:
	// case ZYDIS_MNEMONIC_CVTSS2SD:
	// case ZYDIS_MNEMONIC_CVTSD2SS:
	// case ZYDIS_MNEMONIC_CVTTPD2DQ:
	// case ZYDIS_MNEMONIC_CVTPD2PS:
	// case ZYDIS_MNEMONIC_MOVAPS:
	case ZYDIS_MNEMONIC_MOVDDUP:
	case ZYDIS_MNEMONIC_MOVSS:
	// case ZYDIS_MNEMONIC_PSHUFPS:
	case ZYDIS_MNEMONIC_RCPPS:
		// case ZYDIS_MNEMONIC_RSQRTPS:
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
		return ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
	default:
		return 0;
	}
}

static int analyze_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	X86ZYDISContext *zydx = (X86ZYDISContext *)a->plugin_data;

	ZydisMachineMode mode = select_mode(a);
	ZydisStackWidth st_mode;
	int n, ret;

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
	ret = ZydisDecoderInit(&decoder, mode, st_mode);
	if (!ZYAN_SUCCESS(ret)) {
		return 0;
	}
	zydx->zydecode = RZ_NEW0(ZydisDecodedInstruction);
	zydx->zydeop = RZ_NEWS(ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT);
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
		op->size = 0;
	}
	for (int i = 0; i < zydx->zydecode->operand_count; i++) {
		zydx->zydeop[i].size = zydx->zydeop[i].size / 8; // Convert from bits to bytes
	}
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		ZydisFormatter formatter;
		char mnemonic[256];
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
		ZydisFormatterFormatInstruction(&formatter, zydx->zydecode, zydx->zydeop,
			zydx->zydecode->operand_count, mnemonic, sizeof(mnemonic), addr, NULL);
		ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
		op->mnemonic = rz_str_dup(mnemonic);
	}
	op->cycles = 1;
	op->nopcode = zydx->zydecode->raw.prefix_count + zydx->zydecode->operand_count;
	op->size = zydx->zydecode->length;
	op->id = zydx->zydecode->mnemonic;
	op->family = RZ_ANALYSIS_OP_FAMILY_CPU; // Almost everything is CPU by default
	op->prefix = 0;
	op->cond = cond_x862r2(zydx->zydecode->mnemonic);
	for (int i = 0; i < zydx->zydecode->raw.prefix_count; i++) {
		if (zydx->zydecode->raw.prefixes[i].value == 0xF2) {
			op->prefix |= RZ_ANALYSIS_OP_PREFIX_REPNE;
			break;
		} else if (zydx->zydecode->raw.prefixes[i].value == 0xF3) {
			op->prefix |= RZ_ANALYSIS_OP_PREFIX_REP;
			break;
		} else if (zydx->zydecode->raw.prefixes[i].value == 0xF0) {
			op->prefix |= RZ_ANALYSIS_OP_PREFIX_LOCK;
			op->family = RZ_ANALYSIS_OP_FAMILY_THREAD; // XXX ?
			break;
		}
	}
	anop(a, op, addr, buf, len, zydx->zydecode, zydx->zydeop);
	set_opdir(op, zydx->zydecode, zydx->zydeop);
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		anop_esil(a, op, addr, buf, len, zydx->zydecode, zydx->zydeop);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		opex(&op->opex, zydx, mode, addr);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		op_fillval(a, op, zydx->zydecode, zydx->zydeop, mode, addr);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		// x86 RzIL uplifting
		X86ILIns x86_il_ins = {
			.structure = zydx->zydecode,
			.mnem = zydx->zydecode->mnemonic,
			.ins_size = op->size
		};
		rz_x86_il_opcode(a, op, addr + op->size, &x86_il_ins);
	}
	RZ_FREE(zydx->zydeop);
	RZ_FREE(zydx->zydecode);
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
		return 0;
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

static int esil_x86_cs_init(RzAnalysisEsil *esil) {
	if (!esil) {
		return false;
	}
	// XXX. this depends on kernel
	// rz_analysis_esil_set_interrupt (esil, 0x80, x86_int_0x80);
	/* disable by default */
	//	rz_analysis_esil_set_interrupt (esil, 0x80, NULL,addr);	// this is stupid, don't do this
	return true;
}

static int esil_x86_cs_fini(RzAnalysisEsil *esil) {
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
	.esil_init = esil_x86_cs_init,
	.esil_fini = esil_x86_cs_fini,
	.il_config = rz_x86_il_config
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_x86_zydis,
	.version = RZ_VERSION,
};
#endif