/* rizin - LGPL - Copyright 2013-2019 - pancake */

#include <rz_analysis.h>
#include <rz_lib.h>
#include <capstone.h>
#include <ppc.h>
#include "../../asm/arch/ppc/libvle/vle.h"

#define SPR_HID0 0x3f0 /* Hardware Implementation Register 0 */
#define SPR_HID1 0x3f1 /* Hardware Implementation Register 1 */
#define SPR_HID2 0x3f3 /* Hardware Implementation Register 2 */
#define SPR_HID4 0x3f4 /* Hardware Implementation Register 4 */
#define SPR_HID5 0x3f6 /* Hardware Implementation Register 5 */
#define SPR_HID6 0x3f9 /* Hardware Implementation Register 6 */

struct Getarg {
	csh handle;
	cs_insn *insn;
	int bits;
};

#define INSOPS insn->detail->ppc.op_count
#define INSOP(n) insn->detail->ppc.operands[n]
#define IMM(x) (ut64)(insn->detail->ppc.operands[x].imm)

#ifndef PFMT32x
#define PFMT32x "lx"
#endif

static ut64 mask64(ut64 mb, ut64 me) {
	ut64 maskmb = UT64_MAX >> mb;
	ut64 maskme = UT64_MAX << (63 - me);
	return (mb <= me) ? maskmb & maskme : maskmb | maskme;
}

static ut32 mask32(ut32 mb, ut32 me) {
	ut32 maskmb = UT32_MAX >> mb;
	ut32 maskme = UT32_MAX << (31 - me);
	return (mb <= me) ? maskmb & maskme : maskmb | maskme;
}

static const char* cmask64(const char *mb_c, const char *me_c) {
	static char cmask[32];
	ut64 mb = 0;
	ut64 me = 0;
	if (mb_c) {
		mb = strtol (mb_c, NULL, 16);
	}
	if (me_c) {
		me = strtol (me_c, NULL, 16);
	}
	snprintf (cmask, sizeof (cmask), "0x%"PFMT64x"", mask64 (mb, me));
	return cmask;
}

static const char* cmask32(const char *mb_c, const char *me_c) {
	static char cmask[32];
	ut32 mb = 0;
	ut32 me = 0;
	if (mb_c) {
		mb = strtol (mb_c, NULL, 16);
	}
	if (me_c) {
		me = strtol (me_c, NULL, 16);
	}
	snprintf (cmask, sizeof (cmask), "0x%"PFMT32x"", mask32 (mb, me));
	return cmask;
}

static char *getarg2(struct Getarg *gop, int n, const char *setstr) {
	cs_insn *insn = gop->insn;
	csh handle = gop->handle;
	static char words[8][64];
	cs_ppc_op op;

	if (n < 0 || n >= 8) {
		return NULL;
	}
	op = INSOP (n);
	switch (op.type) {
	case PPC_OP_INVALID:
		words[n][0] = '\0';
		//strcpy (words[n], "invalid");
		break;
	case PPC_OP_REG:
		snprintf (words[n], sizeof (words[n]),
				"%s%s", cs_reg_name (handle, op.reg), setstr);
		break;
	case PPC_OP_IMM:
		snprintf (words[n], sizeof (words[n]),
				"0x%"PFMT64x"%s", (ut64) op.imm, setstr);
		break;
	case PPC_OP_MEM:
		snprintf (words[n], sizeof (words[n]),
				"%"PFMT64d",%s,+,%s",
				(ut64) op.mem.disp,
				cs_reg_name (handle, op.mem.base), setstr);
		break;
	case PPC_OP_CRX: // Condition Register field
		snprintf (words[n], sizeof (words[n]),
				"%"PFMT64d"%s", (ut64) op.imm, setstr);
		break;
	}
	return words[n];
}

static ut64 getarg(struct Getarg *gop, int n) {
	ut64 value = 0;
	cs_insn *insn = gop->insn;
	cs_ppc_op op;

	if (n < 0 || n >= 8) {
		return 0;
	}

	op = INSOP (n);
	switch (op.type) {
	case PPC_OP_INVALID:
		break;
	case PPC_OP_REG:
		value = op.reg;
		break;
	case PPC_OP_IMM:
		value = (ut64) op.imm;
		break;
	case PPC_OP_MEM:
		value = op.mem.disp + op.mem.base;
		break;
	case PPC_OP_CRX: // Condition Register field
		value = (ut64) op.imm;
		break;
	}
	return value;
}

static const char* getspr(struct Getarg *gop, int n) {
	static char cspr[16];
	ut32 spr = 0;
	if (n < 0 || n >= 8) {
		return NULL;
	}
	spr = getarg (gop, 0);
	switch (spr) {
	case SPR_HID0:
		return "hid0";
	case SPR_HID1:
		return "hid1";
	case SPR_HID2:
		return "hid2";
	case SPR_HID4:
		return "hid4";
	case SPR_HID5:
		return "hid5";
	case SPR_HID6:
		return "hid6";
	default:
		snprintf (cspr, sizeof (cspr), "spr_%u", spr);
		break;
	}
	return cspr;
}

static void opex(RzStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	rz_strbuf_init (buf);
	rz_strbuf_append (buf, "{");
	cs_sysz *x = &insn->detail->sysz;
	rz_strbuf_append (buf, "\"operands\":[");
	for (i = 0; i < x->op_count; i++) {
		cs_sysz_op *op = &x->operands[i];
		if (i > 0) {
			rz_strbuf_append (buf, ",");
		}
		rz_strbuf_append (buf, "{");
		switch (op->type) {
		case SYSZ_OP_REG:
			rz_strbuf_append (buf, "\"type\":\"reg\"");
			rz_strbuf_appendf (buf, ",\"value\":\"%s\"", cs_reg_name (handle, op->reg));
			break;
		case SYSZ_OP_IMM:
			rz_strbuf_append (buf, "\"type\":\"imm\"");
			rz_strbuf_appendf (buf, ",\"value\":%" PFMT64d, (st64)op->imm);
			break;
		case SYSZ_OP_MEM:
			rz_strbuf_append (buf, "\"type\":\"mem\"");
			if (op->mem.base != SYSZ_REG_INVALID) {
				rz_strbuf_appendf (buf, ",\"base\":\"%s\"", cs_reg_name (handle, op->mem.base));
			}
			rz_strbuf_appendf (buf, ",\"index\":%"PFMT64d"", (st64) op->mem.index);
			rz_strbuf_appendf (buf, ",\"length\":%"PFMT64d"", (st64) op->mem.length);
			rz_strbuf_appendf (buf, ",\"disp\":%"PFMT64d"", (st64) op->mem.disp);
			break;
		default:
			rz_strbuf_append (buf, "\"type\":\"invalid\"");
			break;
		}
		rz_strbuf_append (buf, "}");
	}
	rz_strbuf_append (buf, "]}");
}

#define PPCSPR(n) getspr(&gop, n)
#define ARG(n) getarg2(&gop, n, "")
#define ARG2(n,m) getarg2(&gop, n, m)

static bool set_reg_profile(RzAnalysis *analysis) {
	const char *p = NULL;
	if (analysis->bits == 32) {
		p =
			"=PC	pc\n"
			"=SP	r1\n"
			"=BP	r31\n"
			"=SR	srr1\n" // status register ??
			"=SN	r3\n" // also for ret
			"=A0	r3\n" // also for ret
			"=A1	r4\n"
			"=A2	r5\n"
			"=A3	r6\n"
			"=A4	r7\n"
			"=A5	r8\n"
			"=A6	r6\n"
			"gpr	srr0   .32 0   0\n"
			"gpr	srr1   .32 4   0\n"
			"gpr	r0   .32 8   0\n"
			"gpr	r1   .32 12  0\n"
			"gpr	r2   .32 16  0\n"
			"gpr	r3   .32 20  0\n"
			"gpr	r4   .32 24  0\n"
			"gpr	r5   .32 28  0\n"
			"gpr	r6   .32 32  0\n"
			"gpr	r7   .32 36  0\n"
			"gpr	r8   .32 40  0\n"
			"gpr	r9   .32 44  0\n"
			"gpr	r10 .32 48  0\n"
			"gpr	r11 .32 52  0\n"
			"gpr	r12 .32 56  0\n"
			"gpr	r13 .32 60  0\n"
			"gpr	r14 .32 64  0\n"
			"gpr	r15 .32 68  0\n"
			"gpr	r16 .32 72  0\n"
			"gpr	r17 .32 76  0\n"
			"gpr	r18 .32 80  0\n"
			"gpr	r19 .32 84  0\n"
			"gpr	r20 .32 88  0\n"
			"gpr	r21 .32 92  0\n"
			"gpr	r22 .32 96  0\n"
			"gpr	r23 .32 100 0\n"
			"gpr	r24 .32 104 0\n"
			"gpr	r25 .32 108 0\n"
			"gpr	r26 .32 112 0\n"
			"gpr	r27 .32 116 0\n"
			"gpr	r28 .32 120 0\n"
			"gpr	r29 .32 124 0\n"
			"gpr	r30 .32 128 0\n"
			"gpr	r31 .32 132 0\n"
			"gpr	lr   .32 136 0\n"
			"gpr	ctr .32 140 0\n"
			"gpr	msr .32 144 0\n"
			"gpr	pc   .32 148 0\n"
			"gpr	cr  .64 152 0\n"
			"gpr	cr0 .8  152 0\n"
			"gpr	cr1 .8  153 0\n"
			"gpr	cr2 .8  154 0\n"
			"gpr	cr3 .8  155 0\n"
			"gpr	cr4 .8  156 0\n"
			"gpr	cr5 .8  157 0\n"
			"gpr	cr6 .8  158 0\n"
			"gpr	cr7 .8  159 0\n"
			"gpr	xer .32 160 0\n"
			"gpr	mq   .32 164 0\n"
			"gpr	fpscr  .32 168 0\n"
			"gpr	vrsave .32 172 0\n"
			"gpr	pvr .32 176 0\n"
			"gpr	dccr   .32 180 0\n"
			"gpr	iccr   .32 184 0\n"
			"gpr	dear   .32 188 0\n"
			"gpr	hid0   .32 192 0\n"
			"gpr	hid1   .32 196 0\n"
			"gpr	hid2   .32 200 0\n"
			"gpr	hid3   .32 204 0\n"
			"gpr	hid4   .32 208 0\n"
			"gpr	hid5   .32 212 0\n"
			"gpr	hid6   .32 216 0\n"
			"gpr	ibat0  .64 220 0\n"
			"gpr	ibat1  .64 228 0\n"
			"gpr	ibat2  .64 236 0\n"
			"gpr	ibat3  .64 244 0\n"
			"gpr	ibat0l .32 220 0\n"
			"gpr	ibat1l .32 228 0\n"
			"gpr	ibat2l .32 236 0\n"
			"gpr	ibat3l .32 244 0\n"
			"gpr	ibat0u .32 224 0\n"
			"gpr	ibat1u .32 232 0\n"
			"gpr	ibat2u .32 240 0\n"
			"gpr	ibat3u .32 248 0\n"
			"gpr	dbat0  .64 256 0\n"
			"gpr	dbat1  .64 264 0\n"
			"gpr	dbat2  .64 272 0\n"
			"gpr	dbat3  .64 280 0\n"
			"gpr	dbat0l .32 256 0\n"
			"gpr	dbat1l .32 264 0\n"
			"gpr	dbat2l .32 272 0\n"
			"gpr	dbat3l .32 280 0\n"
			"gpr	dbat0u .32 260 0\n"
			"gpr	dbat1u .32 268 0\n"
			"gpr	dbat2u .32 276 0\n"
			"gpr	dbat3u .32 284 0\n"
			"gpr	mask   .32 288 0\n";
	} else {
		p =
			"=PC	pc\n"
			"=SP	r1\n"
			"=SR	srr1\n" // status register ??
			"=SN	r0\n" // also for ret
			"=A0	r3\n" // also for ret
			"=A1	r4\n"
			"=A2	r5\n"
			"=A3	r6\n"
			"=A4	r7\n"
			"=A5	r8\n"
			"=A6	r6\n"
			"gpr	srr0   .64 0   0\n"
			"gpr	srr1   .64 8   0\n"
			"gpr	r0   .64 16  0\n"
			"gpr	r1   .64 24  0\n"
			"gpr	r2   .64 32  0\n"
			"gpr	r3   .64 40  0\n"
			"gpr	r4   .64 48  0\n"
			"gpr	r5   .64 56  0\n"
			"gpr	r6   .64 64  0\n"
			"gpr	r7   .64 72  0\n"
			"gpr	r8   .64 80  0\n"
			"gpr	r9   .64 88  0\n"
			"gpr	r10 .64 96  0\n"
			"gpr	r11 .64 104 0\n"
			"gpr	r12 .64 112 0\n"
			"gpr	r13 .64 120 0\n"
			"gpr	r14 .64 128 0\n"
			"gpr	r15 .64 136 0\n"
			"gpr	r16 .64 144 0\n"
			"gpr	r17 .64 152 0\n"
			"gpr	r18 .64 160 0\n"
			"gpr	r19 .64 168 0\n"
			"gpr	r20 .64 176 0\n"
			"gpr	r21 .64 184 0\n"
			"gpr	r22 .64 192 0\n"
			"gpr	r23 .64 200 0\n"
			"gpr	r24 .64 208 0\n"
			"gpr	r25 .64 216 0\n"
			"gpr	r26 .64 224 0\n"
			"gpr	r27 .64 232 0\n"
			"gpr	r28 .64 240 0\n"
			"gpr	r29 .64 248 0\n"
			"gpr	r30 .64 256 0\n"
			"gpr	r31 .64 264 0\n"
			"gpr	lr   .64 272 0\n"
			"gpr	ctr .64 280 0\n"
			"gpr	msr .64 288 0\n"
			"gpr	pc   .64 296 0\n"
			"gpr	cr  .64 304 0\n"
			"gpr	cr0 .8  304 0\n"
			"gpr	cr1 .8  305 0\n"
			"gpr	cr2 .8  306 0\n"
			"gpr	cr3 .8  307 0\n"
			"gpr	cr4 .8  308 0\n"
			"gpr	cr5 .8  309 0\n"
			"gpr	cr6 .8  310 0\n"
			"gpr	cr7 .8  311 0\n"
			"gpr	xer .64 312 0\n"
			"gpr	mq   .64 320 0\n"
			"gpr	fpscr  .64 328 0\n"
			"gpr	vrsave .64 336 0\n"
			"gpr	pvr .64 344 0\n"
			"gpr	dccr   .32 352 0\n"
			"gpr	iccr   .32 356 0\n"
			"gpr	dear   .32 360 0\n"
			"gpr	hid0   .64 364 0\n"
			"gpr	hid1   .64 372 0\n"
			"gpr	hid2   .64 380 0\n"
			"gpr	hid3   .64 388 0\n"
			"gpr	hid4   .64 396 0\n"
			"gpr	hid5   .64 404 0\n"
			"gpr	hid6   .64 412 0\n"
			"gpr	ibat0  .64 420 0\n"
			"gpr	ibat1  .64 428 0\n"
			"gpr	ibat2  .64 436 0\n"
			"gpr	ibat3  .64 444 0\n"
			"gpr	ibat0l .32 420 0\n"
			"gpr	ibat1l .32 428 0\n"
			"gpr	ibat2l .32 436 0\n"
			"gpr	ibat3l .32 444 0\n"
			"gpr	ibat0u .32 424 0\n"
			"gpr	ibat1u .32 432 0\n"
			"gpr	ibat2u .32 440 0\n"
			"gpr	ibat3u .32 448 0\n"
			"gpr	dbat0  .64 456 0\n"
			"gpr	dbat1  .64 464 0\n"
			"gpr	dbat2  .64 472 0\n"
			"gpr	dbat3  .64 480 0\n"
			"gpr	dbat0l .32 456 0\n"
			"gpr	dbat1l .32 464 0\n"
			"gpr	dbat2l .32 472 0\n"
			"gpr	dbat3l .32 480 0\n"
			"gpr	dbat0u .32 460 0\n"
			"gpr	dbat1u .32 468 0\n"
			"gpr	dbat2u .32 476 0\n"
			"gpr	dbat3u .32 484 0\n"
			"gpr	mask   .64 488 0\n"; //not a real register used on complex functions
	}
	return rz_reg_set_profile_string (analysis->reg, p);
}

static int analop_vle(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len) {
	vle_t* instr = NULL;
	vle_handle handle = {0};
	op->size = 2;
	if (len > 1 && !vle_init (&handle, buf, len) && (instr = vle_next (&handle))) {
		op->size = instr->size;
		op->type = instr->analysis_op;
		//op->id = instr->type;

		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_ILL:
			break;
		case RZ_ANALYSIS_OP_TYPE_ADD:
			break;
		case RZ_ANALYSIS_OP_TYPE_AND:
			break;
		case RZ_ANALYSIS_OP_TYPE_CALL:
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case RZ_ANALYSIS_OP_TYPE_CCALL:
			op->eob = true;
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case RZ_ANALYSIS_OP_TYPE_CJMP:
			op->cond = instr->cond; //RZ_ANALYSIS_COND_NE;
			op->eob = true;
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case RZ_ANALYSIS_OP_TYPE_CMP:
			break;
		case RZ_ANALYSIS_OP_TYPE_JMP:
			op->jump = addr + instr->fields[instr->n - 1].value;
			break;
		case RZ_ANALYSIS_OP_TYPE_LOAD:
			break;
		case RZ_ANALYSIS_OP_TYPE_MOV:
			break;
		case RZ_ANALYSIS_OP_TYPE_MUL:
			break;
		case RZ_ANALYSIS_OP_TYPE_NOT:
			break;
		case RZ_ANALYSIS_OP_TYPE_OR:
			break;
		case RZ_ANALYSIS_OP_TYPE_ROR:
			break;
		case RZ_ANALYSIS_OP_TYPE_ROL:
			break;
		case RZ_ANALYSIS_OP_TYPE_RCALL:
			op->eob = true;
			break;
		case RZ_ANALYSIS_OP_TYPE_RET:
			op->eob = true;
			break;
		case RZ_ANALYSIS_OP_TYPE_RJMP:
			break;
		case RZ_ANALYSIS_OP_TYPE_SHL:
			break;
		case RZ_ANALYSIS_OP_TYPE_SHR:
			break;
		case RZ_ANALYSIS_OP_TYPE_STORE:
			break;
		case RZ_ANALYSIS_OP_TYPE_SUB:
			break;
		case RZ_ANALYSIS_OP_TYPE_SWI:
			break;
		case RZ_ANALYSIS_OP_TYPE_SYNC:
			break;
		case RZ_ANALYSIS_OP_TYPE_TRAP:
			break;
		case RZ_ANALYSIS_OP_TYPE_XOR:
			break;
		default:
			//eprintf ("Missing an RZ_ANALYSIS_OP_TYPE (%"PFMT64u")\n", op->type);
			break;
		}
		vle_free (instr);
		return op->size;
	}
	return -1;
}

static int parse_reg_name(RzRegItem *reg, csh handle, cs_insn *insn, int reg_num) {
	if (!reg) {
		return -1;
	}
	switch (INSOP (reg_num).type) {
	case PPC_OP_REG:
		reg->name = (char *)cs_reg_name (handle, INSOP (reg_num).reg);
		break;
	case PPC_OP_MEM:
		if (INSOP (reg_num).mem.base != PPC_REG_INVALID) {
			reg->name = (char *)cs_reg_name (handle, INSOP (reg_num).mem.base);
		}
		break;
	default :
		break;
	}
	return 0;
}

static RzRegItem base_regs[4];

static void create_src_dst(RzAnalysisOp *op) {
	op->src[0] = rz_analysis_value_new ();
	op->src[1] = rz_analysis_value_new ();
	op->src[2] = rz_analysis_value_new ();
	op->dst = rz_analysis_value_new ();
	ZERO_FILL (base_regs[0]);
	ZERO_FILL (base_regs[1]);
	ZERO_FILL (base_regs[2]);
	ZERO_FILL (base_regs[3]);
}

static void set_src_dst(RzAnalysisValue *val, csh *handle, cs_insn *insn, int x) {
	cs_ppc_op ppcop = INSOP (x);
	parse_reg_name (&base_regs[x], *handle, insn, x);
	switch (ppcop.type) {
	case PPC_OP_REG:
		break;
	case PPC_OP_MEM:
		val->delta = ppcop.mem.disp;
		break;
	case PPC_OP_IMM:
		val->imm = ppcop.imm;
		break;
	default:
		break;
	}
	val->reg = &base_regs[x];
}

static void op_fillval(RzAnalysisOp *op, csh handle, cs_insn *insn) {
	create_src_dst (op);
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_CMP:
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_MUL:
	case RZ_ANALYSIS_OP_TYPE_DIV:
	case RZ_ANALYSIS_OP_TYPE_SHR:
	case RZ_ANALYSIS_OP_TYPE_SHL:
	case RZ_ANALYSIS_OP_TYPE_SAL:
	case RZ_ANALYSIS_OP_TYPE_SAR:
	case RZ_ANALYSIS_OP_TYPE_OR:
	case RZ_ANALYSIS_OP_TYPE_AND:
	case RZ_ANALYSIS_OP_TYPE_XOR:
	case RZ_ANALYSIS_OP_TYPE_NOR:
	case RZ_ANALYSIS_OP_TYPE_NOT:
	case RZ_ANALYSIS_OP_TYPE_LOAD:
	case RZ_ANALYSIS_OP_TYPE_LEA:
	case RZ_ANALYSIS_OP_TYPE_ROR:
	case RZ_ANALYSIS_OP_TYPE_ROL:
	case RZ_ANALYSIS_OP_TYPE_CAST:
		set_src_dst (op->src[2], &handle, insn, 3);
		set_src_dst (op->src[1], &handle, insn, 2);
		set_src_dst (op->src[0], &handle, insn, 1);
		set_src_dst (op->dst, &handle, insn, 0);
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
		set_src_dst (op->dst, &handle, insn, 1);
		set_src_dst (op->src[0], &handle, insn, 0);
		break;
	}
}

static int analop(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	static csh handle = 0;
	static int omode = -1, obits = -1;
	int n, ret;
	cs_insn *insn;
	char *op1;
	int mode = (a->bits == 64) ? CS_MODE_64 : (a->bits == 32) ? CS_MODE_32 : 0;
	mode |= a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;

	if (a->cpu && strncmp (a->cpu, "vle", 3) == 0) {
		// vle is big-endian only
		if (!a->big_endian) {
			return -1;
		}
		ret = analop_vle (a, op, addr, buf, len);
		if (ret >= 0) {
			return op->size;
		}
	}

	if (mode != omode || a->bits != obits) {
		cs_close (&handle);
		handle = 0;
		omode = mode;
		obits = a->bits;
	}
	if (handle == 0) {
		ret = cs_open (CS_ARCH_PPC, mode, &handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	op->size = 4;

	// capstone-next
	n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
	} else {
		if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
			opex (&op->opex, handle, insn);
		}
		struct Getarg gop = {
			.handle = handle,
			.insn = insn,
			.bits = a->bits
		};
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
#if CS_API_MAJOR >= 4
		case PPC_INS_CMPB:
#endif
		case PPC_INS_CMPD:
		case PPC_INS_CMPDI:
		case PPC_INS_CMPLD:
		case PPC_INS_CMPLDI:
		case PPC_INS_CMPLW:
		case PPC_INS_CMPLWI:
		case PPC_INS_CMPW:
		case PPC_INS_CMPWI:
#if CS_API_MAJOR > 4
		case PPC_INS_CMP:
		case PPC_INS_CMPI:
#endif
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			op->sign = true;
			if (ARG (2)[0] == '\0') {
				esilprintf (op, "%s,%s,-,0xff,&,cr0,=", ARG (1), ARG (0));
			} else {
				esilprintf (op, "%s,%s,-,0xff,&,%s,=", ARG (2), ARG (1), ARG (0));
			}
			break;
		case PPC_INS_MFLR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "lr,%s,=", ARG (0));
			break;
		case PPC_INS_MTLR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "%s,lr,=", ARG (0));
			break;
		case PPC_INS_MR:
		case PPC_INS_LI:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_LIS:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "%s0000,%s,=", ARG (1), ARG (0));
			break;
		case PPC_INS_CLRLWI:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			esilprintf (op, "%s,%s,&,%s,=", ARG (1), cmask32 (ARG (2), "0x1F"), ARG (0));
			break;
		case PPC_INS_RLWINM:
			op->type = RZ_ANALYSIS_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,<<<,%s,&,%s,=", ARG (2), ARG (1), cmask32 (ARG (3), ARG (4)), ARG (0));
			break;
		case PPC_INS_SC:
			op->type = RZ_ANALYSIS_OP_TYPE_SWI;
			esilprintf (op, "0,$");
			break;
		case PPC_INS_EXTSB:
			op->sign = true;
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			if (a->bits == 64) {
				esilprintf (op, "%s,0x80,&,?{,0xFFFFFFFFFFFFFF00,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			} else {
				esilprintf (op, "%s,0x80,&,?{,0xFFFFFF00,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			}
			break;
		case PPC_INS_EXTSH:
			op->sign = true;
			if (a->bits == 64) {
				esilprintf (op, "%s,0x8000,&,?{,0xFFFFFFFFFFFF0000,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			} else {
				esilprintf (op, "%s,0x8000,&,?{,0xFFFF0000,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			}
			break;
		case PPC_INS_EXTSW:
			op->sign = true;
			esilprintf (op, "%s,0x80000000,&,?{,0xFFFFFFFF00000000,%s,|,%s,=,}", ARG (1), ARG (1), ARG (0));
			break;
		case PPC_INS_SYNC:
		case PPC_INS_ISYNC:
		case PPC_INS_LWSYNC:
		case PPC_INS_MSYNC:
		case PPC_INS_PTESYNC:
		case PPC_INS_TLBSYNC:
		case PPC_INS_SLBIA:
		case PPC_INS_SLBIE:
		case PPC_INS_SLBMFEE:
		case PPC_INS_SLBMTE:
		case PPC_INS_EIEIO:
		case PPC_INS_NOP:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			esilprintf (op, ",");
			break;
		case PPC_INS_STW:
		case PPC_INS_STWUX:
		case PPC_INS_STWX:
		case PPC_INS_STWCX:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[4]"));
			break;
		case PPC_INS_STWU:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			op1 = ARG (1);
			op1[strlen (op1) - 1] = 0;
			esilprintf (op, "%s,%s,=[4],%s=", ARG (0), op1, op1);
			if (strstr (op1, "r1")) {
				op->stackop = RZ_ANALYSIS_STACK_INC;
				op->stackptr = -atoi (op1);
			}
			break;
		case PPC_INS_STWBRX:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		case PPC_INS_STB:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[1]"));
			break;
		case PPC_INS_STBU:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			op1 = ARG (1);
			op1[strlen (op1) - 1] = 0;
			esilprintf (op, "%s,%s,=[1],%s=", ARG (0), op1, op1);
			break;
		case PPC_INS_STH:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[2]"));
			break;
		case PPC_INS_STHU:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			op1 = ARG (1);
			op1[strlen (op1) - 1] = 0;
			esilprintf (op, "%s,%s,=[2],%s=", ARG (0), op1, op1);
			break;
		case PPC_INS_STD:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, "=[8]"));
			break;
		case PPC_INS_STDU:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			op1 = ARG (1);
			op1[strlen (op1) - 1] = 0;
			esilprintf (op, "%s,%s,=[8],%s=", ARG (0), op1, op1);
			break;
		case PPC_INS_LBZ:
#if CS_API_MAJOR >= 4
		case PPC_INS_LBZCIX:
#endif
		case PPC_INS_LBZU:
		case PPC_INS_LBZUX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			op1 = ARG (1);
			op1[strlen (op1) - 1] = 0;
			esilprintf (op, "%s,[1],%s,=,%s=", op1, ARG (0), op1);
			break;
		case PPC_INS_LBZX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[1]"), ARG (0));
			break;
		case PPC_INS_LD:
		case PPC_INS_LDARX:
#if CS_API_MAJOR >= 4
		case PPC_INS_LDCIX:
#endif
		case PPC_INS_LDU:
		case PPC_INS_LDUX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			op1 = ARG (1);
			op1[strlen (op1) - 1] = 0;
			esilprintf (op, "%s,[8],%s,=,%s=", op1, ARG (0), op1);
			break;
		case PPC_INS_LDX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[8]"), ARG (0));
			break;
		case PPC_INS_LDBRX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case PPC_INS_LFD:
		case PPC_INS_LFDU:
		case PPC_INS_LFDUX:
		case PPC_INS_LFDX:
		case PPC_INS_LFIWAX:
		case PPC_INS_LFIWZX:
		case PPC_INS_LFS:
		case PPC_INS_LFSU:
		case PPC_INS_LFSUX:
		case PPC_INS_LFSX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[4]"), ARG (0));
			break;
		case PPC_INS_LHA:
		case PPC_INS_LHAU:
		case PPC_INS_LHAUX:
		case PPC_INS_LHAX:
		case PPC_INS_LHZ:
		case PPC_INS_LHZU:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			op1 = ARG (1);
			op1[strlen (op1) - 1] = 0;
			esilprintf (op, "%s,[2],%s,=,%s=", op1, ARG (0), op1);
			break;
		case PPC_INS_LHBRX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case PPC_INS_LWA:
		case PPC_INS_LWARX:
		case PPC_INS_LWAUX:
		case PPC_INS_LWAX:
		case PPC_INS_LWZ:
#if CS_API_MAJOR >= 4
		case PPC_INS_LWZCIX:
#endif
		case PPC_INS_LWZX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			esilprintf (op, "%s,%s,=", ARG2 (1, "[4]"), ARG (0));
			break;
		case PPC_INS_LWZU:
		case PPC_INS_LWZUX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			op1 = ARG (1);
			op1[strlen(op1) - 1] = 0;
			esilprintf (op, "%s,[4],%s,=,%s=", op1, ARG (0), op1);
			break;
		case PPC_INS_LWBRX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case PPC_INS_SLW:
		case PPC_INS_SLWI:
			op->type = RZ_ANALYSIS_OP_TYPE_SHL;
			esilprintf (op, "%s,%s,<<,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_SRW:
		case PPC_INS_SRWI:
			op->type = RZ_ANALYSIS_OP_TYPE_SHR;
			esilprintf (op, "%s,%s,>>,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MULLI:
			op->sign = true;
		case PPC_INS_MULLW:
		case PPC_INS_MULLD:
			op->type = RZ_ANALYSIS_OP_TYPE_MUL;
			esilprintf (op, "%s,%s,*,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_SUB:
		case PPC_INS_SUBC:
		case PPC_INS_SUBF:
		case PPC_INS_SUBFIC:
		case PPC_INS_SUBFZE:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			esilprintf (op, "%s,%s,-,%s,=", ARG (1), ARG (2), ARG (0));
			break;
		case PPC_INS_ADD:
		case PPC_INS_ADDI:
			op->sign = true;
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			esilprintf (op, "%s,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_CRCLR:
		case PPC_INS_CRSET:
		case PPC_INS_CRMOVE:
		case PPC_INS_CRXOR:
		case PPC_INS_CRNOR:
		case PPC_INS_CRNOT:
			// reset conditional bits
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		case PPC_INS_ADDC:
		case PPC_INS_ADDIC:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			esilprintf (op, "%s,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ADDE:
		case PPC_INS_ADDIS:
		case PPC_INS_ADDME:
		case PPC_INS_ADDZE:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			esilprintf (op, "%s,%s,+,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MTSPR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", ARG (1), PPCSPR (0));
			break;
		case PPC_INS_BCTR: // switch table here
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			esilprintf (op, "ctr,pc,=");
			break;
		case PPC_INS_BCTRL: // switch table here
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			esilprintf (op, "pc,lr,=,ctr,pc,=");
			break;
		case PPC_INS_B:
		case PPC_INS_BC:
		case PPC_INS_BA:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = ARG (1)[0] == '\0' ? IMM (0) : IMM (1);
			op->fail = addr + op->size;
			switch (insn->detail->ppc.bc) {
			case PPC_BC_LT:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,!,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0x80,%s,&,!,!,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_LE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,!,cr0,!,|,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0x80,%s,&,!,!,0,%s,!,|,?{,%s,pc,=,},", ARG (0), ARG (0), ARG (1));
				}
				break;
			case PPC_BC_EQ:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "cr0,!,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "%s,!,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_GE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,cr0,!,|,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0x80,%s,&,!,%s,!,|,?{,%s,pc,=,},", ARG (0), ARG (0), ARG (1));
				}
				break;
			case PPC_BC_GT:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "0x80,%s,&,!,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_NE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "cr0,!,!,?{,%s,pc,=,},", ARG (0));
				} else {
					esilprintf (op, "%s,!,!,?{,%s,pc,=,},", ARG (0), ARG (1));
				}
				break;
			case PPC_BC_INVALID:
				op->type = RZ_ANALYSIS_OP_TYPE_JMP;
				esilprintf (op, "%s,pc,=", ARG (0));
			case PPC_BC_UN: // unordered
			case PPC_BC_NU: // not unordered
			case PPC_BC_SO: // summary overflow
			case PPC_BC_NS: // not summary overflow
			default:
				break;
			}
			break;
		case PPC_INS_BT:
		case PPC_INS_BF:
			switch (insn->detail->ppc.operands[0].type) {
			case PPC_OP_CRX:
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->fail = addr + op->size;
				break;
			case PPC_OP_REG:
				if (op->type == RZ_ANALYSIS_OP_TYPE_CJMP) {
					op->type = RZ_ANALYSIS_OP_TYPE_UCJMP;
				} else {
					op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				}
				op->jump = IMM (1);
				op->fail = addr + op->size;
				//op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			default:
				break;
			}
			break;
		case PPC_INS_BDNZ:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,!,?{,%s,pc,=,}", ARG (0));
			break;
		case PPC_INS_BDNZA:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZL:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZLA:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZLR:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,!,?{,lr,pc,=,},");
			break;
		case PPC_INS_BDNZLRL:
			op->fail = addr + op->size;
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			break;
		case PPC_INS_BDZ:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,?{,%s,pc,=,}", ARG (0));
			break;
		case PPC_INS_BDZA:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZL:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZLA:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZLR:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			esilprintf (op, "1,ctr,-=,$z,?{,lr,pc,=,}");
			break;
		case PPC_INS_BDZLRL:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			break;
		case PPC_INS_BLR:
		case PPC_INS_BLRL:
		case PPC_INS_BCLR:
		case PPC_INS_BCLRL:
			op->type = RZ_ANALYSIS_OP_TYPE_CRET;
			op->fail = addr + op->size;
			switch (insn->detail->ppc.bc) {
			case PPC_BC_INVALID:
				op->type = RZ_ANALYSIS_OP_TYPE_RET;
				esilprintf (op, "lr,pc,=");
				break;
			case PPC_BC_LT:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,!,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0x80,%s,&,!,!,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_LE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,!,cr0,!,|,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0x80,%s,&,!,!,0,%s,!,|,?{,lr,pc,=,},", ARG (0), ARG (0));
				}
				break;
			case PPC_BC_EQ:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "cr0,!,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "%s,!,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_GE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,cr0,!,|,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0x80,%s,&,!,%s,!,|,?{,lr,pc,=,},", ARG (0), ARG (0));
				}
				break;
			case PPC_BC_GT:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "0x80,cr0,&,!,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "0x80,%s,&,!,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_NE:
				if (ARG (1)[0] == '\0') {
					esilprintf (op, "cr0,!,!,?{,lr,pc,=,},");
				} else {
					esilprintf (op, "%s,!,!,?{,lr,pc,=,},", ARG (0));
				}
				break;
			case PPC_BC_UN: // unordered
			case PPC_BC_NU: // not unordered
			case PPC_BC_SO: // summary overflow
			case PPC_BC_NS: // not summary overflow
			default:
				break;
			}
			break;
		case PPC_INS_NOR:
			op->type = RZ_ANALYSIS_OP_TYPE_NOR;
			esilprintf (op, "%s,%s,|,!,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_XOR:
		case PPC_INS_XORI:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			esilprintf (op, "%s,%s,^,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_XORIS:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			esilprintf (op, "16,%s,<<,%s,^,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_DIVD:
		case PPC_INS_DIVW:
			op->sign = true;
			op->type = RZ_ANALYSIS_OP_TYPE_DIV;
			esilprintf (op, "%s,%s,/,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_DIVDU:
		case PPC_INS_DIVWU:
			op->type = RZ_ANALYSIS_OP_TYPE_DIV;
			esilprintf (op, "%s,%s,/,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_BL:
		case PPC_INS_BLA:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = IMM (0);
			op->fail = addr + op->size;
			esilprintf (op, "pc,lr,=,%s,pc,=", ARG (0));
			break;
		case PPC_INS_TRAP:
			op->sign = true;
			op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
			break;
		case PPC_INS_AND:
		case PPC_INS_NAND:
		case PPC_INS_ANDI:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			esilprintf (op, "%s,%s,&,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ANDIS:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			esilprintf (op, "16,%s,<<,%s,&,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_OR:
		case PPC_INS_ORI:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			esilprintf (op, "%s,%s,|,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_ORIS:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			esilprintf (op, "16,%s,<<,%s,|,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_MFPVR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "pvr,%s,=", ARG (0));
			break;
		case PPC_INS_MFSPR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "%s,%s,=", PPCSPR (1), ARG (0));
			break;
		case PPC_INS_MFCTR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "ctr,%s,=", ARG (0));
			break;
		case PPC_INS_MFDCCR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "dccr,%s,=", ARG (0));
			break;
		case PPC_INS_MFICCR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "iccr,%s,=", ARG (0));
			break;
		case PPC_INS_MFDEAR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "dear,%s,=", ARG (0));
			break;
		case PPC_INS_MFMSR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "msr,%s,=", ARG (0));
			break;
		case PPC_INS_MTCTR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "%s,ctr,=", ARG (0));
			break;
		case PPC_INS_MTDCCR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "%s,dccr,=", ARG (0));
			break;
		case PPC_INS_MTICCR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "%s,iccr,=", ARG (0));
			break;
		case PPC_INS_MTDEAR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "%s,dear,=", ARG (0));
			break;
		case PPC_INS_MTMSR:
		case PPC_INS_MTMSRD:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf (op, "%s,msr,=", ARG (0));
			break;
			// Data Cache Block Zero
		case PPC_INS_DCBZ:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			esilprintf (op, "%s,%s", ARG (0), ARG2 (1, ",=[128]"));
			break;
		case PPC_INS_CLRLDI:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			esilprintf (op, "%s,%s,&,%s,=", ARG (1), cmask64 (ARG (2), "0x3F"), ARG (0));
			break;
		case PPC_INS_ROTLDI:
			op->type = RZ_ANALYSIS_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,<<<,%s,=", ARG (2), ARG (1), ARG (0));
			break;
		case PPC_INS_RLDCL:
		case PPC_INS_RLDICL:
			op->type = RZ_ANALYSIS_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,<<<,%s,&,%s,=", ARG (2), ARG (1), cmask64 (ARG (3), "0x3F"), ARG (0));
			break;
		case PPC_INS_RLDCR:
		case PPC_INS_RLDICR:
			op->type = RZ_ANALYSIS_OP_TYPE_ROL;
			esilprintf (op, "%s,%s,<<<,%s,&,%s,=", ARG (2), ARG (1), cmask64 (0, ARG (3)), ARG (0));
			break;
		}
		if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
			op_fillval (op, handle, insn);
		}
		if (!(mask & RZ_ANALYSIS_OP_MASK_ESIL)) {
			rz_strbuf_fini (&op->esil);
		}
		cs_free (insn, n);
		//cs_close (&handle);
	}
	return op->size;
}

static int archinfo(RzAnalysis *a, int q) {
	if (a->cpu && !strncmp (a->cpu, "vle", 3)) {
		return 2;
	}
	return 4;
}

static RzList *analysis_preludes(RzAnalysis *analysis) {
#define KW(d,ds,m,ms) rz_list_append (l, rz_search_keyword_new((const ut8*)d,ds,(const ut8*)m, ms, NULL))
	RzList *l = rz_list_newf ((RzListFree)rz_search_keyword_free);
	KW ("\x7c\x08\x02\xa6", 4, NULL, 0);
	return l;
}

RzAnalysisPlugin rz_analysis_plugin_ppc_cs = {
	.name = "ppc",
	.desc = "Capstone PowerPC analysis",
	.license = "BSD",
	.esil = true,
	.arch = "ppc",
	.bits = 32 | 64,
	.archinfo = archinfo,
	.preludes = analysis_preludes,
	.op = &analop,
	.set_reg_profile = &set_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_ppc_cs,
	.version = RZ_VERSION
};
#endif
