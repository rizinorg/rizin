// SPDX-FileCopyrightText: 2024 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <capstone/capstone.h>

#include <hppa/hppa.inc>

/**
 * \brief Append fr0 to fr31 and their 32-bit halves, laid out as the
 * struct user_fp_struct of Linux.
 */
static char *hppa_fp_reg_profile(const char *gpr) {
	RzStrBuf *sb = rz_strbuf_new(gpr);
	if (!sb) {
		return NULL;
	}
	// the halves of fr0 to fr3 are the status and exception registers
	static const char *const status[] = { "fpsr", "fpe1", "fpe2", "fpe3", "fpe4", "fpe5", "fpe6", "fpe7" };
	for (int i = 0; i < 32; i++) {
		rz_strbuf_appendf(sb, "fpu\tfr%d\t.64\t%d\t0\n", i, 8 * i);
	}
	for (int i = 0; i < 32; i++) {
		if (i < 4) {
			rz_strbuf_appendf(sb, "fpu\t%s\t.32\t%d\t0\n", status[2 * i], 8 * i);
			rz_strbuf_appendf(sb, "fpu\t%s\t.32\t%d\t0\n", status[2 * i + 1], 8 * i + 4);
		} else {
			rz_strbuf_appendf(sb, "fpu\tfr%dL\t.32\t%d\t0\n", i, 8 * i);
			rz_strbuf_appendf(sb, "fpu\tfr%dR\t.32\t%d\t0\n", i, 8 * i + 4);
		}
	}
	return rz_strbuf_drain(sb);
}

static char *hppa_reg_profile(RzAnalysis *analysis) {
	if (analysis->bits == 64) {
		// linux/arch/parisc/include/uapi/asm/ptrace.h: struct user_regs_struct (64-bit)
		const char *p =
			"=PC	iaoq0\n"
			"=SP	r30\n"
			"=LR	r2\n"
			"=A0	r26\n"
			"=A1	r25\n"
			"=A2	r24\n"
			"=A3	r23\n"
			"=A4	r22\n"
			"=A5	r21\n"
			"=A6	r20\n"
			"=A7	r19\n"
			"=R0	r28\n"
			"=SN	r20\n"
			"gpr	r0	.64	0	0\n"
			"gpr	r1	.64	8	0\n"
			"gpr	r2	.64	16	0\n"
			"gpr	r3	.64	24	0\n"
			"gpr	r4	.64	32	0\n"
			"gpr	r5	.64	40	0\n"
			"gpr	r6	.64	48	0\n"
			"gpr	r7	.64	56	0\n"
			"gpr	r8	.64	64	0\n"
			"gpr	r9	.64	72	0\n"
			"gpr	r10	.64	80	0\n"
			"gpr	r11	.64	88	0\n"
			"gpr	r12	.64	96	0\n"
			"gpr	r13	.64	104	0\n"
			"gpr	r14	.64	112	0\n"
			"gpr	r15	.64	120	0\n"
			"gpr	r16	.64	128	0\n"
			"gpr	r17	.64	136	0\n"
			"gpr	r18	.64	144	0\n"
			"gpr	r19	.64	152	0\n"
			"gpr	r20	.64	160	0\n"
			"gpr	r21	.64	168	0\n"
			"gpr	r22	.64	176	0\n"
			"gpr	r23	.64	184	0\n"
			"gpr	r24	.64	192	0\n"
			"gpr	r25	.64	200	0\n"
			"gpr	r26	.64	208	0\n"
			"gpr	r27	.64	216	0\n"
			"gpr	r28	.64	224	0\n"
			"gpr	r29	.64	232	0\n"
			"gpr	r30	.64	240	0\n"
			"gpr	r31	.64	248	0\n"
			"gpr	sr0	.64	256	0\n"
			"gpr	sr1	.64	264	0\n"
			"gpr	sr2	.64	272	0\n"
			"gpr	sr3	.64	280	0\n"
			"gpr	sr4	.64	288	0\n"
			"gpr	sr5	.64	296	0\n"
			"gpr	sr6	.64	304	0\n"
			"gpr	sr7	.64	312	0\n"
			"gpr	iaoq0	.64	320	0\n"
			"gpr	iaoq1	.64	328	0\n"
			"gpr	iasq0	.64	336	0\n"
			"gpr	iasq1	.64	344	0\n"
			"gpr	sar	.64	352	0\n" // cr11
			"gpr	iir	.64	360	0\n" // cr19
			"gpr	isr	.64	368	0\n" // cr20
			"gpr	ior	.64	376	0\n" // cr21
			"gpr	ipsw	.64	384	0\n" // cr22
			"gpr	cr0	.64	392	0\n"
			"gpr	cr24	.64	400	0\n"
			"gpr	cr25	.64	408	0\n"
			"gpr	cr26	.64	416	0\n"
			"gpr	cr27	.64	424	0\n"
			"gpr	cr28	.64	432	0\n"
			"gpr	cr29	.64	440	0\n"
			"gpr	cr30	.64	448	0\n"
			"gpr	cr31	.64	456	0\n"
			"gpr	cr8	.64	464	0\n"
			"gpr	cr9	.64	472	0\n"
			"gpr	cr12	.64	480	0\n"
			"gpr	cr13	.64	488	0\n"
			"gpr	cr10	.64	496	0\n"
			"gpr	cr15	.64	504	0\n";
		return hppa_fp_reg_profile(p);
	} else {
		const char *p =
			"=PC	iaoq0\n"
			"=SP	r30\n"
			"=LR	r2\n"
			"=A0	r26\n"
			"=A1	r25\n"
			"=A2	r24\n"
			"=A3	r23\n"
			"=R0	r28\n"
			"=R1	r29\n"
			"=SN	r20\n"
			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	r3	.32	12	0\n"
			"gpr	r4	.32	16	0\n"
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	r13	.32	52	0\n"
			"gpr	r14	.32	56	0\n"
			"gpr	r15	.32	60	0\n"
			"gpr	r16	.32	64	0\n"
			"gpr	r17	.32	68	0\n"
			"gpr	r18	.32	72	0\n"
			"gpr	r19	.32	76	0\n"
			"gpr	r20	.32	80	0\n"
			"gpr	r21	.32	84	0\n"
			"gpr	r22	.32	88	0\n"
			"gpr	r23	.32	92	0\n"
			"gpr	r24	.32	96	0\n"
			"gpr	r25	.32	100	0\n"
			"gpr	r26	.32	104	0\n"
			"gpr	r27	.32	108	0\n"
			"gpr	r28	.32	112	0\n"
			"gpr	r29	.32	116	0\n"
			"gpr	r30	.32	120	0\n"
			"gpr	r31	.32	124	0\n"
			"gpr	sr0	.32	128	0\n"
			"gpr	sr1	.32	132	0\n"
			"gpr	sr2	.32	136	0\n"
			"gpr	sr3	.32	140	0\n"
			"gpr	sr4	.32	144	0\n"
			"gpr	sr5	.32	148	0\n"
			"gpr	sr6	.32	152	0\n"
			"gpr	sr7	.32	156	0\n"
			"gpr	iaoq0	.32	160	0\n"
			"gpr	iaoq1	.32	164	0\n"
			"gpr	iasq0	.32	168	0\n"
			"gpr	iasq1	.32	172	0\n"
			"gpr	sar	.32	176	0\n" // cr11
			"gpr	iir	.32	180	0\n" // cr19
			"gpr	isr	.32	184	0\n" // cr20
			"gpr	ior	.32	188	0\n" // cr21
			"gpr	ipsw	.32	192	0\n" // cr22
			"gpr	cr0	.32	196	0\n"
			"gpr	cr24	.32	200	0\n"
			"gpr	cr25	.32	204	0\n"
			"gpr	cr26	.32	208	0\n"
			"gpr	cr27	.32	212	0\n"
			"gpr	cr28	.32	216	0\n"
			"gpr	cr29	.32	220	0\n"
			"gpr	cr30	.32	224	0\n"
			"gpr	cr31	.32	228	0\n"
			"gpr	cr8	.32	232	0\n"
			"gpr	cr9	.32	236	0\n"
			"gpr	cr12	.32	240	0\n"
			"gpr	cr13	.32	244	0\n"
			"gpr	cr10	.32	248	0\n"
			"gpr	cr15	.32	252	0\n";
		return hppa_fp_reg_profile(p);
	}
}

#define HPPA_INSN_SIZE 4

/// stw rp,-0x14(sp): stores the return pointer into the frame marker
#define HPPA_STW_RP 0x6bc23fd9

/// Major opcode of BL, GATE, BLR, BV, BVE and the PA 2.0 B forms
#define HPPA_OPCODE_BRANCH 0x3a

typedef enum {
	HPPA_BRANCH_COND, ///< taken depending on the condition
	HPPA_BRANCH_ALWAYS,
	HPPA_BRANCH_NEVER,
} HPPABranchCond;

/**
 * \brief Check if the mnemonic carries the completer, e.g. "n" in "cmpb,<>,n".
 */
static bool hppa_has_completer(const cs_insn *insn, const char *completer) {
	size_t len = strlen(completer);
	for (const char *p = strchr(insn->mnemonic, ','); p; p = strchr(p, ',')) {
		p++;
		if (!strncmp(p, completer, len) && (!p[len] || p[len] == ',')) {
			return true;
		}
	}
	return false;
}

/**
 * \brief Name of a register in the register profile, which numbers the
 * general registers and some of the control registers unlike Capstone.
 */
static const char *hppa_reg_name(hppa_reg reg) {
	static const char *const gr[] = {
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		"r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
		"r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"
	};
	static const char *const sr[] = {
		"sr0", "sr1", "sr2", "sr3", "sr4", "sr5", "sr6", "sr7"
	};
	static const char *const cr[] = {
		"cr0", NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		"cr8", "cr9", "cr10", "sar", "cr12", "cr13", NULL, "cr15",
		NULL, NULL, NULL, "iir", "isr", "ior", "ipsw", NULL,
		"cr24", "cr25", "cr26", "cr27", "cr28", "cr29", "cr30", "cr31"
	};
	if (reg >= HPPA_REG_GR0 && reg <= HPPA_REG_GR31) {
		return gr[reg - HPPA_REG_GR0];
	}
	if (reg >= HPPA_REG_SR0 && reg <= HPPA_REG_SR7) {
		return sr[reg - HPPA_REG_SR0];
	}
	if (reg >= HPPA_REG_CR0 && reg <= HPPA_REG_CR31) {
		return cr[reg - HPPA_REG_CR0];
	}
	// whole registers, as the operands of single precision use the left halves too
	static const char *const fr[] = {
		"fr0", "fr1", "fr2", "fr3", "fr4", "fr5", "fr6", "fr7",
		"fr8", "fr9", "fr10", "fr11", "fr12", "fr13", "fr14", "fr15",
		"fr16", "fr17", "fr18", "fr19", "fr20", "fr21", "fr22", "fr23",
		"fr24", "fr25", "fr26", "fr27", "fr28", "fr29", "fr30", "fr31"
	};
	static const char *const right[] = {
		"fpe1", "fpe3", "fpe5", "fpe7", "fr4R", "fr5R", "fr6R", "fr7R",
		"fr8R", "fr9R", "fr10R", "fr11R", "fr12R", "fr13R", "fr14R", "fr15R",
		"fr16R", "fr17R", "fr18R", "fr19R", "fr20R", "fr21R", "fr22R", "fr23R",
		"fr24R", "fr25R", "fr26R", "fr27R", "fr28R", "fr29R", "fr30R", "fr31R"
	};
	static const char *const sp[] = {
		"fr16L", "fr17L", "fr18L", "fr19L", "fr20L", "fr21L", "fr22L", "fr23L",
		"fr24L", "fr25L", "fr26L", "fr27L", "fr28L", "fr29L", "fr30L", "fr31L",
		"fr16R", "fr17R", "fr18R", "fr19R", "fr20R", "fr21R", "fr22R", "fr23R",
		"fr24R", "fr25R", "fr26R", "fr27R", "fr28R", "fr29R", "fr30R", "fr31R"
	};
	if (reg >= HPPA_REG_FPR0 && reg <= HPPA_REG_FPR31) {
		return fr[reg - HPPA_REG_FPR0];
	}
	if (reg >= HPPA_REG_FPE0 && reg <= HPPA_REG_FPE31) {
		return right[reg - HPPA_REG_FPE0];
	}
	if (reg >= HPPA_REG_SP_FPR0 && reg <= HPPA_REG_SP_FPR31) {
		return sp[reg - HPPA_REG_SP_FPR0];
	}
	return NULL;
}

static RzRegItem *hppa_reg_get(const RzReg *rz_reg, hppa_reg reg) {
	const char *name = hppa_reg_name(reg);
	return name ? rz_reg_get(rz_reg, name, RZ_REG_TYPE_ANY) : NULL;
}

/// Displacement, which Capstone leaves zero-extended from 32 bits in some forms
static st64 hppa_disp(const cs_hppa_op *op) {
	return (st32)op->imm;
}

/// Width of the memory access of a load or store
static int hppa_mem_width(ut32 id) {
	switch (id) {
	case HPPA_INS_LDB:
	case HPPA_INS_LDBS:
	case HPPA_INS_LDBX:
	case HPPA_INS_STB:
	case HPPA_INS_STBS:
		return 1;
	case HPPA_INS_LDH:
	case HPPA_INS_LDHS:
	case HPPA_INS_LDHX:
	case HPPA_INS_STH:
	case HPPA_INS_STHS:
		return 2;
	case HPPA_INS_LDW:
	case HPPA_INS_LDWS:
	case HPPA_INS_LDWX:
	case HPPA_INS_LDWA:
	case HPPA_INS_LDWAS:
	case HPPA_INS_LDWAX:
	case HPPA_INS_LDWM:
	case HPPA_INS_LDCW:
	case HPPA_INS_LDCWS:
	case HPPA_INS_LDCWX:
	case HPPA_INS_STW:
	case HPPA_INS_STWS:
	case HPPA_INS_STWA:
	case HPPA_INS_STWAS:
	case HPPA_INS_STWM:
	case HPPA_INS_FLDW:
	case HPPA_INS_FLDWS:
	case HPPA_INS_FLDWX:
	case HPPA_INS_FSTW:
	case HPPA_INS_FSTWS:
	case HPPA_INS_FSTWX:
		return 4;
	case HPPA_INS_LDD:
	case HPPA_INS_LDDA:
	case HPPA_INS_LDCD:
	case HPPA_INS_STD:
	case HPPA_INS_STDA:
	case HPPA_INS_FLDD:
	case HPPA_INS_FLDDS:
	case HPPA_INS_FLDDX:
	case HPPA_INS_FSTD:
	case HPPA_INS_FSTDS:
	case HPPA_INS_FSTDX:
		return 8;
	default:
		return 0;
	}
}

/**
 * \brief Check if a load or store accesses memory at its base register before
 * adding the offset to it.
 *
 * PA 1.1 LDWM and STWM do so for positive displacements.
 */
static bool hppa_modifies_after(const cs_insn *insn, const cs_hppa_op *offset) {
	if (insn->id == HPPA_INS_LDWM || insn->id == HPPA_INS_STWM) {
		return offset->type == HPPA_OP_DISP && hppa_disp(offset) >= 0;
	}
	return hppa_has_completer(insn, "ma") || hppa_has_completer(insn, "m") || hppa_has_completer(insn, "sm");
}

/**
 * \brief Fill a value from an operand, with the displacement or index
 * register Capstone reports as the separate \p offset operand of a memory one.
 */
static void hppa_fillval(const RzReg *rz_reg, const cs_insn *insn, RzAnalysisValue *av, const cs_hppa_op *hop, const cs_hppa_op *offset) {
	switch (hop->type) {
	case HPPA_OP_INVALID:
	default:
		av->type = RZ_ANALYSIS_VAL_UNK;
		break;
	case HPPA_OP_IMM:
		av->type = RZ_ANALYSIS_VAL_IMM;
		av->imm = hop->imm;
		break;
	case HPPA_OP_DISP:
		av->type = RZ_ANALYSIS_VAL_IMM;
		av->imm = hppa_disp(hop);
		break;
	case HPPA_OP_TARGET:
		av->type = RZ_ANALYSIS_VAL_IMM;
		av->imm = insn->address + hop->imm;
		break;
	case HPPA_OP_REG:
	case HPPA_OP_IDX_REG:
		av->type = RZ_ANALYSIS_VAL_REG;
		av->reg = hppa_reg_get(rz_reg, hop->reg);
		break;
	case HPPA_OP_MEM:
		if (insn->id == HPPA_INS_LDO) {
			av->type = RZ_ANALYSIS_VAL_REG;
			av->reg = hppa_reg_get(rz_reg, hop->mem.base);
			break;
		}
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->reg = hppa_reg_get(rz_reg, hop->mem.base);
		if (hop->mem.space != HPPA_REG_INVALID) {
			av->seg = hppa_reg_get(rz_reg, hop->mem.space);
		}
		av->memref = hppa_mem_width(insn->id);
		if (!offset || hppa_modifies_after(insn, offset)) {
			// the base is updated after accessing memory at it
		} else if (offset->type == HPPA_OP_DISP) {
			av->delta = hppa_disp(offset);
		} else {
			av->regdelta = hppa_reg_get(rz_reg, offset->reg);
			av->mul = hppa_has_completer(insn, "s") ? av->memref : 1;
		}
		break;
	}
}

static void hppa_fillvals(const RzAsmHPPAContext *ctx, RzAnalysis *a, RzAnalysisOp *op) {
	uint8_t srci = 0;
	const cs_hppa *hc = &ctx->insn->detail->hppa;
	bool store = (op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_STORE;
	for (uint8_t i = 0; i < hc->op_count; ++i) {
		const cs_hppa_op *hop = &hc->operands[i];
		const cs_hppa_op *offset = NULL;
		// LDO adds without accessing memory
		if ((hop->type == HPPA_OP_DISP || hop->type == HPPA_OP_IDX_REG) && ctx->insn->id != HPPA_INS_LDO &&
			i + 1 < hc->op_count && hc->operands[i + 1].type == HPPA_OP_MEM) {
			offset = hop;
			hop = &hc->operands[++i];
		}
		RzAnalysisValue *av = rz_analysis_value_new();
		if (!av) {
			return;
		}
		hppa_fillval(a->reg, ctx->insn, av, hop, offset);
		// the access of a memory operand is the one of its base register,
		// immediates may lack one
		bool read = hop->type == HPPA_OP_MEM ? !store : (hop->access & CS_AC_READ) || hop->type == HPPA_OP_IMM || hop->type == HPPA_OP_DISP;
		bool write = hop->type == HPPA_OP_MEM ? store : hop->access & CS_AC_WRITE;
		bool owned = false;
		if (read && srci < RZ_ARRAY_SIZE(op->src)) {
			av->access |= RZ_ANALYSIS_ACC_R;
			op->src[srci++] = av;
			owned = true;
		}
		if (write) {
			av->access |= RZ_ANALYSIS_ACC_W;
			if (srci > 0 && av == op->src[srci - 1]) {
				av = rz_mem_dup(av, sizeof(RzAnalysisValue));
			}
			// a single op->dst slot: release the previous write operand
			rz_analysis_value_free(op->dst);
			op->dst = av;
			owned = true;
		}
		if (!owned) {
			// operand is neither read nor written, so nothing takes ownership
			rz_analysis_value_free(av);
		}
	}
}

static RzStructuredData *hppa_opex(csh handle, cs_insn *insn) {
	if (!insn->detail) {
		return NULL;
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
	cs_hppa *hpc = &insn->detail->hppa;
	for (st32 i = 0; i < hpc->op_count; i++) {
		cs_hppa_op *op = hpc->operands + i;
		RzStructuredData *operand = rz_structured_data_array_add_map(operands);
		switch (op->type) {
		case HPPA_OP_REG: {
			rz_structured_data_map_add_string(operand, "type", "reg");
			rz_structured_data_map_add_string(operand, "value", cs_reg_name(handle, op->reg));
			break;
		}
		case HPPA_OP_IDX_REG: {
			rz_structured_data_map_add_string(operand, "type", "idx_reg");
			rz_structured_data_map_add_string(operand, "value", cs_reg_name(handle, op->reg));
			break;
		}
		case HPPA_OP_IMM: {
			rz_structured_data_map_add_string(operand, "type", "imm");
			rz_structured_data_map_add_signed(operand, "value", op->imm);
			break;
		}
		case HPPA_OP_DISP: {
			rz_structured_data_map_add_string(operand, "type", "disp");
			rz_structured_data_map_add_signed(operand, "value", hppa_disp(op));
			break;
		}
		case HPPA_OP_TARGET: {
			rz_structured_data_map_add_string(operand, "type", "target");
			rz_structured_data_map_add_signed(operand, "value", op->imm);
			break;
		}
		case HPPA_OP_MEM: {
			rz_structured_data_map_add_string(operand, "type", "mem");
			if (op->mem.base != HPPA_REG_INVALID) {
				rz_structured_data_map_add_string(operand, "base", cs_reg_name(handle, op->mem.base));
			}
			if (op->mem.space != HPPA_REG_INVALID) {
				rz_structured_data_map_add_string(operand, "space", cs_reg_name(handle, op->mem.space));
			} else {
				rz_structured_data_map_add_string(operand, "space", "unavailable");
			}
			break;
		}
		default:
			rz_structured_data_map_add_string(operand, "type", "invalid");
			break;
		}
	}

	return root;
}

/**
 * \brief Classify the condition of a compare, add or move and branch.
 *
 * The condition is the first completer. PA 2.0 spells "always" as "tr" and
 * "never" as no condition. PA 1.1 names have no condition in the
 * always taken false forms (COMBF, ...) and the never taken true forms.
 */
static HPPABranchCond hppa_branch_cond(const cs_insn *insn) {
	const char *cond = strchr(insn->mnemonic, ',');
	cond = cond ? cond + 1 : "";
	if (*cond == '*') {
		// doubleword condition
		cond++;
	}
	size_t len = strcspn(cond, ",");
	if (len == 2 && !strncmp(cond, "tr", 2)) {
		return HPPA_BRANCH_ALWAYS;
	}
	if (len && !(len == 1 && *cond == 'n')) {
		return HPPA_BRANCH_COND;
	}
	switch (insn->id) {
	case HPPA_INS_COMBF:
	case HPPA_INS_COMIBF:
	case HPPA_INS_ADDBF:
	case HPPA_INS_ADDIBF:
		return HPPA_BRANCH_ALWAYS;
	case HPPA_INS_BB:
	case HPPA_INS_BVB:
		return HPPA_BRANCH_COND;
	default:
		return HPPA_BRANCH_NEVER;
	}
}

/**
 * \brief Set the target and delay slot of a branch.
 *
 * The ",n" completer nullifies the delay slot of an unconditional branch,
 * and of a conditional one when taken forward or not taken backward. A slot
 * running only on the fall-through path starts that path instead.
 */
static void hppa_set_branch(RzAnalysisOp *op, const cs_insn *insn, ut64 jump, bool conditional) {
	bool nullify = hppa_has_completer(insn, "n");
	op->jump = jump;
	if (!conditional) {
		op->delay = nullify ? 0 : 1;
	} else if (nullify && jump >= insn->address + 2 * HPPA_INSN_SIZE) {
		op->fail = insn->address + HPPA_INSN_SIZE;
	} else {
		op->delay = 1;
		op->fail = insn->address + 2 * HPPA_INSN_SIZE;
	}
}

/**
 * \brief Link register of BL, GATE and the PA 2.0 B branches.
 *
 * Read from the word as Capstone reports the t field for the 22-bit forms
 * too, where it holds displacement bits: B,L and B,L,PUSH link to rp there.
 */
static ut32 hppa_branch_link(ut32 word) {
	ut32 ext = (word >> 13) & 7;
	return ext == 4 || ext == 5 ? 2 : (word >> 21) & 0x1f;
}

static const cs_hppa_op *hppa_find_op(const cs_insn *insn, hppa_op_type type) {
	const cs_hppa *hc = &insn->detail->hppa;
	for (ut8 i = 0; i < hc->op_count; i++) {
		if (hc->operands[i].type == type) {
			return &hc->operands[i];
		}
	}
	return NULL;
}

static void hppa_op_set_branch_link(RzAnalysisOp *op, const cs_insn *insn, ut32 link) {
	const cs_hppa_op *target = hppa_find_op(insn, HPPA_OP_TARGET);
	if (!target) {
		return;
	}
	ut64 jump = insn->address + target->imm;
	if (!link) {
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
	} else if (jump == insn->address + 2 * HPPA_INSN_SIZE) {
		// "b,l .+8,rN" falls through, only reading the PC
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->val = jump;
		return;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->fail = insn->address + 2 * HPPA_INSN_SIZE;
	}
	hppa_set_branch(op, insn, jump, false);
}

static void hppa_op_set_cond_branch(RzAnalysisOp *op, const cs_insn *insn) {
	const cs_hppa_op *target = hppa_find_op(insn, HPPA_OP_TARGET);
	if (!target) {
		return;
	}
	switch (hppa_branch_cond(insn)) {
	case HPPA_BRANCH_ALWAYS:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		hppa_set_branch(op, insn, insn->address + target->imm, false);
		break;
	case HPPA_BRANCH_NEVER:
		switch (insn->id) {
		case HPPA_INS_ADDB:
		case HPPA_INS_ADDIB:
		case HPPA_INS_ADDBT:
		case HPPA_INS_ADDIBT:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case HPPA_INS_MOVB:
		case HPPA_INS_MOVIB:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		}
		break;
	case HPPA_BRANCH_COND:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		hppa_set_branch(op, insn, insn->address + target->imm, true);
		break;
	}
}

/**
 * \brief Type BV, BVE, BE and BLE: returns through rp, computed jumps and
 * calls, and Linux syscalls through the gateway page at 0(sr2,r0).
 */
static void hppa_op_set_ext_branch(RzAnalysisOp *op, const cs_insn *insn) {
	const cs_hppa_op *mem = hppa_find_op(insn, HPPA_OP_MEM);
	if (!mem) {
		return;
	}
	const cs_hppa_op *idx = hppa_find_op(insn, HPPA_OP_IDX_REG);
	const cs_hppa_op *disp = hppa_find_op(insn, HPPA_OP_DISP);
	bool indexed = idx && idx->reg != HPPA_REG_GR0;
	bool link = insn->id == HPPA_INS_BLE || hppa_has_completer(insn, "l");
	if (!link && !indexed && !disp && mem->mem.base == HPPA_REG_GR2) {
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
	} else if (mem->mem.base == HPPA_REG_GR0 && disp) {
		if (!link) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->jump = hppa_disp(disp);
		} else if (mem->mem.space == HPPA_REG_SR2) {
			op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = hppa_disp(disp);
		}
	} else {
		op->type = link ? RZ_ANALYSIS_OP_TYPE_RCALL : RZ_ANALYSIS_OP_TYPE_RJMP;
		op->reg = hppa_reg_name(mem->mem.base);
		if (indexed) {
			op->ireg = hppa_reg_name(idx->reg);
			op->scale = 8;
		}
		if (disp) {
			op->disp = hppa_disp(disp);
		}
	}
	if (link) {
		op->fail = insn->address + 2 * HPPA_INSN_SIZE;
	}
	hppa_set_branch(op, insn, op->jump, false);
}

static bool hppa_is_cond_completer(const char *c, size_t len) {
	static const char *const names[] = {
		"sv", "nsv", "od", "ev", "tr", "nuv", "uv", "znv", "vnz",
		"swz", "sbz", "shz", "sdc", "swc", "sbc", "shc",
		"nwz", "nbz", "nhz", "ndc", "nwc", "nbc", "nhc"
	};
	if (len && *c == '*') {
		// doubleword condition
		c++;
		len--;
	}
	if (len && (*c == '<' || *c == '>' || *c == '=')) {
		return true;
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(names); i++) {
		if (strlen(names[i]) == len && !strncmp(c, names[i], len)) {
			return true;
		}
	}
	return false;
}

/**
 * \brief Model the nullification of the next instruction by a computational
 * instruction as a branch over it.
 *
 * The next instruction is nullified when the condition completer holds,
 * always for "tr". Trapping forms trap on the condition instead.
 */
static bool hppa_op_set_skip(RzAnalysisOp *op, const cs_insn *insn) {
	switch (insn->id) {
	case HPPA_INS_ADD:
	case HPPA_INS_ADDC:
	case HPPA_INS_ADDCO:
	case HPPA_INS_ADDI:
	case HPPA_INS_ADDIO:
	case HPPA_INS_ADDL:
	case HPPA_INS_ADDO:
	case HPPA_INS_AND:
	case HPPA_INS_ANDCM:
	case HPPA_INS_CMPCLR:
	case HPPA_INS_CMPICLR:
	case HPPA_INS_COMCLR:
	case HPPA_INS_COMICLR:
	case HPPA_INS_DCOR:
	case HPPA_INS_DEP:
	case HPPA_INS_DEPD:
	case HPPA_INS_DEPDI:
	case HPPA_INS_DEPI:
	case HPPA_INS_DEPW:
	case HPPA_INS_DEPWI:
	case HPPA_INS_DS:
	case HPPA_INS_EXTRD:
	case HPPA_INS_EXTRS:
	case HPPA_INS_EXTRU:
	case HPPA_INS_EXTRW:
	case HPPA_INS_IDCOR:
	case HPPA_INS_OR:
	case HPPA_INS_SH1ADD:
	case HPPA_INS_SH1ADDL:
	case HPPA_INS_SH1ADDO:
	case HPPA_INS_SH2ADD:
	case HPPA_INS_SH2ADDL:
	case HPPA_INS_SH2ADDO:
	case HPPA_INS_SH3ADD:
	case HPPA_INS_SH3ADDL:
	case HPPA_INS_SH3ADDO:
	case HPPA_INS_SHD:
	case HPPA_INS_SHLADD:
	case HPPA_INS_SHRPD:
	case HPPA_INS_SHRPW:
	case HPPA_INS_SUB:
	case HPPA_INS_SUBB:
	case HPPA_INS_SUBBO:
	case HPPA_INS_SUBI:
	case HPPA_INS_SUBIO:
	case HPPA_INS_SUBO:
	case HPPA_INS_UADDCM:
	case HPPA_INS_UXOR:
	case HPPA_INS_VDEP:
	case HPPA_INS_VDEPI:
	case HPPA_INS_VEXTRS:
	case HPPA_INS_VEXTRU:
	case HPPA_INS_VSHD:
	case HPPA_INS_XOR:
	case HPPA_INS_ZDEP:
	case HPPA_INS_ZDEPI:
	case HPPA_INS_ZVDEP:
	case HPPA_INS_ZVDEPI:
		break;
	case HPPA_INS_FTEST:
		// nullifies after a true FCMP
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = insn->address + 2 * HPPA_INSN_SIZE;
		op->fail = insn->address + HPPA_INSN_SIZE;
		return true;
	default:
		return false;
	}
	if (hppa_has_completer(insn, "tc")) {
		return false;
	}
	for (const char *p = strchr(insn->mnemonic, ','); p; p = strchr(p, ',')) {
		p++;
		size_t len = strcspn(p, ",");
		if (!hppa_is_cond_completer(p, len)) {
			continue;
		}
		if (len == 2 && !strncmp(p, "tr", 2)) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		} else if (len == 3 && !strncmp(p, "*tr", 3)) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = insn->address + HPPA_INSN_SIZE;
		}
		op->jump = insn->address + 2 * HPPA_INSN_SIZE;
		return true;
	}
	return false;
}

/**
 * \brief Describe the memory operand of a load or store: absolute addresses
 * based on r0, and stack slots based on sp.
 */
static void hppa_op_set_mem(RzAnalysisOp *op, const cs_insn *insn, RzAnalysisStackOp stackop) {
	const cs_hppa_op *mem = hppa_find_op(insn, HPPA_OP_MEM);
	const cs_hppa_op *disp = hppa_find_op(insn, HPPA_OP_DISP);
	if (!mem || !disp) {
		return;
	}
	if (mem->mem.base == HPPA_REG_GR0) {
		op->ptr = (ut64)hppa_disp(disp);
		op->refptr = hppa_mem_width(insn->id);
	} else if (mem->mem.base == HPPA_REG_GR30) {
		op->stackop = stackop;
		op->stackptr = hppa_modifies_after(insn, disp) ? 0 : hppa_disp(disp);
	}
}

static void hppa_op_set_type(const RzAsmHPPAContext *ctx, RzAnalysisOp *op, ut32 word) {
	if (hppa_op_set_skip(op, ctx->insn)) {
		return;
	}
	switch (ctx->insn->id) {
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case HPPA_INS_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case HPPA_INS_ADD:
	case HPPA_INS_ADDI:
	case HPPA_INS_ADDIO:
	case HPPA_INS_ADDIT:
	case HPPA_INS_ADDITO:
	case HPPA_INS_ADDIL:
	case HPPA_INS_ADDC:
	case HPPA_INS_ADDCO:
	case HPPA_INS_ADDL:
	case HPPA_INS_ADDO:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case HPPA_INS_ADDB:
	case HPPA_INS_ADDIB:
	case HPPA_INS_ADDBT:
	case HPPA_INS_ADDBF:
	case HPPA_INS_ADDIBT:
	case HPPA_INS_ADDIBF:
	case HPPA_INS_BB:
	case HPPA_INS_BVB:
	case HPPA_INS_CMPB:
	case HPPA_INS_CMPIB:
	case HPPA_INS_COMBT:
	case HPPA_INS_COMBF:
	case HPPA_INS_COMIBT:
	case HPPA_INS_COMIBF:
	case HPPA_INS_MOVB:
	case HPPA_INS_MOVIB:
		hppa_op_set_cond_branch(op, ctx->insn);
		break;
	case HPPA_INS_AND:
	case HPPA_INS_ANDCM:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case HPPA_INS_B:
	case HPPA_INS_BL:
	case HPPA_INS_GATE:
		if (word >> 26 == HPPA_OPCODE_BRANCH) {
			hppa_op_set_branch_link(op, ctx->insn, hppa_branch_link(word));
		}
		break;
	case HPPA_INS_BE:
	case HPPA_INS_BLE:
	case HPPA_INS_BV:
	case HPPA_INS_BVE:
		hppa_op_set_ext_branch(op, ctx->insn);
		break;
	case HPPA_INS_BLR:
		// indexes a table of branches following the delay slot
		if (hppa_op_count(ctx->insn) == 2 && hppa_op_get(ctx->insn, 1)->reg != HPPA_REG_GR0) {
			op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
			op->fail = ctx->insn->address + 2 * HPPA_INSN_SIZE;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		}
		hppa_set_branch(op, ctx->insn, UT64_MAX, false);
		break;
	case HPPA_INS_LDB:
	case HPPA_INS_LDBS:
	case HPPA_INS_LDBX:
	case HPPA_INS_LDCD:
	case HPPA_INS_LDCW:
	case HPPA_INS_LDCWS:
	case HPPA_INS_LDCWX:
	case HPPA_INS_LDD:
	case HPPA_INS_LDDA:
	case HPPA_INS_LDH:
	case HPPA_INS_LDHS:
	case HPPA_INS_LDHX:
	case HPPA_INS_LDW:
	case HPPA_INS_LDWA:
	case HPPA_INS_LDWAS:
	case HPPA_INS_LDWAX:
	case HPPA_INS_LDWM:
	case HPPA_INS_LDWS:
	case HPPA_INS_LDWX:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		hppa_op_set_mem(op, ctx->insn, RZ_ANALYSIS_STACK_GET);
		break;
	case HPPA_INS_FLDD:
	case HPPA_INS_FLDDS:
	case HPPA_INS_FLDDX:
	case HPPA_INS_FLDW:
	case HPPA_INS_FLDWS:
	case HPPA_INS_FLDWX:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		hppa_op_set_mem(op, ctx->insn, RZ_ANALYSIS_STACK_GET);
		break;
	case HPPA_INS_LDSID:
	case HPPA_INS_MFCTL:
	case HPPA_INS_MFIA:
	case HPPA_INS_MFSP:
	case HPPA_INS_MTCTL:
	case HPPA_INS_MTSAR:
	case HPPA_INS_MTSARCM:
	case HPPA_INS_MTSP:
	case HPPA_INS_COPY:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case HPPA_INS_LDI:
	case HPPA_INS_LDIL:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->val = hppa_op_as_imm(ctx, 0);
		break;
	case HPPA_INS_LDO: {
		const cs_hppa_op *mem = hppa_find_op(ctx->insn, HPPA_OP_MEM);
		const cs_hppa_op *disp = hppa_find_op(ctx->insn, HPPA_OP_DISP);
		if (mem && disp && mem->mem.base == HPPA_REG_GR0) {
			// "ldi"
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			op->val = disp->imm;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		}
		break;
	}
	case HPPA_INS_LCI:
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		break;
	case HPPA_INS_OR:
		if (hppa_op_count(ctx->insn) == 3 && hppa_op_get(ctx->insn, 1)->reg == HPPA_REG_GR0) {
			// "copy" and "nop"
			op->type = hppa_op_get(ctx->insn, 2)->reg == HPPA_REG_GR0
				? RZ_ANALYSIS_OP_TYPE_NOP
				: RZ_ANALYSIS_OP_TYPE_MOV;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
		}
		break;
	case HPPA_INS_STB:
	case HPPA_INS_STBS:
	case HPPA_INS_STBY:
	case HPPA_INS_STBYS:
	case HPPA_INS_STD:
	case HPPA_INS_STDA:
	case HPPA_INS_STDBY:
	case HPPA_INS_STH:
	case HPPA_INS_STHS:
	case HPPA_INS_STW:
	case HPPA_INS_STWA:
	case HPPA_INS_STWAS:
	case HPPA_INS_STWS:
	case HPPA_INS_STWM:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		hppa_op_set_mem(op, ctx->insn, RZ_ANALYSIS_STACK_SET);
		break;
	case HPPA_INS_FSTD:
	case HPPA_INS_FSTDS:
	case HPPA_INS_FSTDX:
	case HPPA_INS_FSTQS:
	case HPPA_INS_FSTQX:
	case HPPA_INS_FSTW:
	case HPPA_INS_FSTWS:
	case HPPA_INS_FSTWX:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		hppa_op_set_mem(op, ctx->insn, RZ_ANALYSIS_STACK_SET);
		break;
	case HPPA_INS_SH1ADD:
	case HPPA_INS_SH1ADDL:
	case HPPA_INS_SH1ADDO:
	case HPPA_INS_SH2ADD:
	case HPPA_INS_SH2ADDL:
	case HPPA_INS_SH2ADDO:
	case HPPA_INS_SH3ADD:
	case HPPA_INS_SH3ADDL:
	case HPPA_INS_SH3ADDO:
	case HPPA_INS_SHLADD:
	case HPPA_INS_UADDCM:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case HPPA_INS_EXTRD:
	case HPPA_INS_EXTRW:
		op->type = hppa_has_completer(ctx->insn, "s") ? RZ_ANALYSIS_OP_TYPE_SAR : RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case HPPA_INS_EXTRS:
	case HPPA_INS_VEXTRS:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case HPPA_INS_EXTRU:
	case HPPA_INS_SHD:
	case HPPA_INS_SHRPD:
	case HPPA_INS_SHRPW:
	case HPPA_INS_VEXTRU:
	case HPPA_INS_VSHD:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case HPPA_INS_DEP:
	case HPPA_INS_DEPD:
	case HPPA_INS_DEPDI:
	case HPPA_INS_DEPI:
	case HPPA_INS_DEPW:
	case HPPA_INS_DEPWI:
	case HPPA_INS_VDEP:
	case HPPA_INS_VDEPI:
	case HPPA_INS_ZDEP:
	case HPPA_INS_ZDEPI:
	case HPPA_INS_ZVDEP:
	case HPPA_INS_ZVDEPI:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case HPPA_INS_CMPCLR:
	case HPPA_INS_CMPICLR:
	case HPPA_INS_COMCLR:
	case HPPA_INS_COMICLR:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case HPPA_INS_XMPYU:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case HPPA_INS_DS:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case HPPA_INS_FADD:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case HPPA_INS_FSUB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case HPPA_INS_FMPY:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case HPPA_INS_FDIV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case HPPA_INS_FABS:
		op->type = RZ_ANALYSIS_OP_TYPE_ABS;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case HPPA_INS_FCPY:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case HPPA_INS_FCMP:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case HPPA_INS_FCNV:
	case HPPA_INS_FCNVFF:
	case HPPA_INS_FCNVFX:
	case HPPA_INS_FCNVFXT:
	case HPPA_INS_FCNVXF:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	case HPPA_INS_BREAK:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case HPPA_INS_RFI:
	case HPPA_INS_RFIR:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	case HPPA_INS_SYNC:
	case HPPA_INS_SYNCDMA:
		op->type = RZ_ANALYSIS_OP_TYPE_SYNC;
		break;
	case HPPA_INS_SUB:
	case HPPA_INS_SUBB:
	case HPPA_INS_SUBBO:
	case HPPA_INS_SUBI:
	case HPPA_INS_SUBIO:
	case HPPA_INS_SUBO:
	case HPPA_INS_SUBT:
	case HPPA_INS_SUBTO:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case HPPA_INS_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	}
}

/// Instructions searched before a switch dispatch for the compare of its index
#define HPPA_SWITCH_WINDOW 8

#define HPPA_OPCODE_ARITH   0x02
#define HPPA_OPCODE_LDIL    0x08
#define HPPA_OPCODE_LDO     0x0d
#define HPPA_OPCODE_COMBT   0x20
#define HPPA_OPCODE_COMIBF  0x23
#define HPPA_OPCODE_COMICLR 0x24
#define HPPA_EXT6_COMCLR    0x22

/// \p len bits of \p w from bit \p lsb
#define HPPA_FIELD(w, lsb, len) (((w) >> (lsb)) & ((1u << (len)) - 1))

/// Immediate of \p len bits whose sign is the lowest one
static st32 hppa_low_sign_ext(ut32 x, int len) {
	st32 v = (st32)(x >> 1);
	return x & 1 ? v - (1 << (len - 1)) : v;
}

typedef enum {
	HPPA_CMP_NONE,
	HPPA_CMP_LTU,
	HPPA_CMP_LEU,
	HPPA_CMP_GTU,
	HPPA_CMP_GEU,
} HppaCmp;

/// The unsigned condition \p c of a compare, negated with \p neg
static HppaCmp hppa_cmp_cond(ut32 c, bool neg) {
	switch (c) {
	case 4:
		return neg ? HPPA_CMP_GEU : HPPA_CMP_LTU;
	case 5:
		return neg ? HPPA_CMP_GTU : HPPA_CMP_LEU;
	default:
		return HPPA_CMP_NONE;
	}
}

/**
 * \brief Count the cases a dispatch running while "lhs cmp rhs" reaches.
 *
 * \param index_lhs Whether the index is lhs, the other side being \p bound
 */
static ut64 hppa_cmp_count(HppaCmp cmp, bool index_lhs, ut32 bound) {
	if (!index_lhs) {
		// the bound above the index
		switch (cmp) {
		case HPPA_CMP_GTU:
			cmp = HPPA_CMP_LTU;
			break;
		case HPPA_CMP_GEU:
			cmp = HPPA_CMP_LEU;
			break;
		default:
			return 0;
		}
	}
	switch (cmp) {
	case HPPA_CMP_LTU:
		return bound;
	case HPPA_CMP_LEU:
		return (ut64)bound + 1;
	default:
		return 0;
	}
}

typedef struct {
	const RzAsmHPPAContext *ctx;
	RzAnalysis *a;
	cs_insn *insn; ///< scratch, to leave the instruction analyzed alone
} HppaScan;

/**
 * \brief Decode the instruction at \p addr and tell whether it may change
 * the control flow.
 */
static bool hppa_scan_decode(HppaScan *s, ut64 addr, ut32 *word, bool *flow, ut64 *jump) {
	ut8 buf[HPPA_INSN_SIZE];
	if (!s->a->iob.read_at(s->a->iob.io, addr, buf, sizeof(buf))) {
		return false;
	}
	const ut8 *code = buf;
	size_t size = sizeof(buf);
	uint64_t at = addr;
	if (!cs_disasm_iter(s->ctx->h, &code, &size, &at, s->insn)) {
		return false;
	}
	*word = rz_read_ble32(buf, s->a->big_endian);
	RzAsmHPPAContext tmp = *s->ctx;
	tmp.insn = s->insn;
	RzAnalysisOp op;
	rz_analysis_op_init(&op);
	op.addr = addr;
	op.size = HPPA_INSN_SIZE;
	hppa_op_set_type(&tmp, &op, *word);
	switch (op.type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_ILL:
	case RZ_ANALYSIS_OP_TYPE_TRAP:
	case RZ_ANALYSIS_OP_TYPE_SWI:
	case RZ_ANALYSIS_OP_TYPE_SWITCH:
		*flow = true;
		break;
	default:
		// skips are conditional jumps
		*flow = (op.type & RZ_ANALYSIS_OP_TYPE_COND) != 0;
		break;
	}
	*jump = op.jump;
	rz_analysis_op_fini(&op);
	return true;
}

/// Whether the decoded instruction may write \p reg
static bool hppa_scan_writes(const HppaScan *s, ut32 reg) {
	const cs_hppa *hc = &s->insn->detail->hppa;
	bool modify = s->insn->id == HPPA_INS_LDWM || s->insn->id == HPPA_INS_STWM ||
		hppa_has_completer(s->insn, "ma") || hppa_has_completer(s->insn, "mb") ||
		hppa_has_completer(s->insn, "m");
	for (ut8 i = 0; i < hc->op_count; i++) {
		const cs_hppa_op *op = &hc->operands[i];
		if (op->type == HPPA_OP_REG && op->reg == HPPA_REG_GR0 + reg && (op->access & CS_AC_WRITE)) {
			return true;
		}
		// Capstone leaves the base register of these read only
		if (op->type == HPPA_OP_MEM && op->mem.base == HPPA_REG_GR0 + reg && modify) {
			return true;
		}
	}
	return false;
}

/// Find the ldi setting \p reg before \p at on the path to it
static bool hppa_scan_ldi(HppaScan *s, ut64 at, ut32 reg, ut32 *value) {
	for (int k = 0; k < HPPA_SWITCH_WINDOW; k++) {
		at -= HPPA_INSN_SIZE;
		ut32 w;
		bool flow;
		ut64 jump;
		if (!hppa_scan_decode(s, at, &w, &flow, &jump) || flow) {
			return false;
		}
		if (HPPA_FIELD(w, 26, 6) == HPPA_OPCODE_LDO && !HPPA_FIELD(w, 21, 5) && HPPA_FIELD(w, 16, 5) == reg) {
			*value = (ut32)hppa_low_sign_ext(HPPA_FIELD(w, 0, 14), 14);
			return true;
		}
		if (hppa_scan_writes(s, reg)) {
			return false;
		}
	}
	return false;
}

/**
 * \brief Count the cases of the switch on \p index from the compare
 * bounding it on the path falling through to \p at.
 *
 * The compare branches to the default, or skips the branch to it.
 *
 * \return The count, or 0 if unknown
 */
static ut64 hppa_switch_bound(HppaScan *s, ut64 at, ut32 index, ut64 *def) {
	for (int k = 0; k < HPPA_SWITCH_WINDOW; k++) {
		at -= HPPA_INSN_SIZE;
		ut32 w;
		bool flow;
		ut64 jump;
		if (!hppa_scan_decode(s, at, &w, &flow, &jump)) {
			return 0;
		}
		ut32 opc = HPPA_FIELD(w, 26, 6);
		HppaCmp cmp;
		ut32 rhs = HPPA_FIELD(w, 21, 5);
		ut32 lhs = HPPA_FIELD(w, 16, 5);
		bool lhs_imm = false;
		if (opc >= HPPA_OPCODE_COMBT && opc <= HPPA_OPCODE_COMIBF) {
			// cmpb and cmpib branch when the condition holds, or fails for the F forms
			cmp = hppa_cmp_cond(HPPA_FIELD(w, 13, 3), !(opc & 2));
			lhs_imm = opc & 1;
			if (lhs_imm) {
				lhs = (ut32)hppa_low_sign_ext(lhs, 5);
			}
		} else if (flow) {
			// only cmpclr and cmpiclr skipping the branch to the default lead here
			ut64 branch = jump;
			at -= HPPA_INSN_SIZE;
			// b,l default,r0
			if ((w & ~(0x3ffu << 16 | 0xfffu << 1 | 1u)) != 0xe8000000 || HPPA_FIELD(w, 21, 5) ||
				!hppa_scan_decode(s, at, &w, &flow, &jump)) {
				return 0;
			}
			opc = HPPA_FIELD(w, 26, 6);
			rhs = HPPA_FIELD(w, 21, 5);
			if (opc == HPPA_OPCODE_COMICLR) {
				lhs = (ut32)hppa_low_sign_ext(HPPA_FIELD(w, 0, 11), 11);
				lhs_imm = true;
				if (HPPA_FIELD(w, 16, 5) == index) {
					return 0;
				}
			} else if (opc == HPPA_OPCODE_ARITH && HPPA_FIELD(w, 6, 6) == HPPA_EXT6_COMCLR) {
				lhs = HPPA_FIELD(w, 16, 5);
				if (HPPA_FIELD(w, 0, 5) == index) {
					return 0;
				}
			} else {
				return 0;
			}
			cmp = hppa_cmp_cond(HPPA_FIELD(w, 13, 3), HPPA_FIELD(w, 12, 1));
			jump = branch;
		} else {
			if (!hppa_scan_writes(s, index)) {
				continue;
			}
			if ((w & 0xffe0ffe0) == 0x08000240 && (w & 0x1f) == index) {
				// copy
				index = HPPA_FIELD(w, 16, 5);
				continue;
			}
			return 0;
		}
		ut32 bound;
		bool index_lhs;
		if (lhs_imm) {
			if (rhs != index) {
				return 0;
			}
			bound = lhs;
			index_lhs = false;
		} else {
			if (lhs == index) {
				index_lhs = true;
			} else if (rhs == index) {
				index_lhs = false;
			} else {
				return 0;
			}
			if (!hppa_scan_ldi(s, at, index_lhs ? rhs : lhs, &bound)) {
				return 0;
			}
		}
		*def = jump;
		return hppa_cmp_count(cmp, index_lhs, bound);
	}
	return 0;
}

static bool hppa_switch_target_valid(RzAnalysis *a, ut64 target) {
	if (target & (HPPA_INSN_SIZE - 1)) {
		return false;
	}
	RzIOMap *map = a->iob.map_get(a->iob.io, target);
	return map && (map->perm & RZ_PERM_X);
}

/**
 * \brief Recover the cases of a switch dispatched by bv through a table.
 *
 * GCC loads the target from an absolute table placed with ldil and ldo, or
 * in PIC adds the entry to the table address taken from b,l .+8, the table
 * then following the bv. The compare of the index bounds the table, else
 * in PIC the first case after the table ends it.
 */
static void hppa_op_set_switch(const RzAsmHPPAContext *ctx, RzAnalysis *a, RzAnalysisOp *op) {
	const cs_hppa_op *mem = hppa_find_op(ctx->insn, HPPA_OP_MEM);
	const cs_hppa_op *idx = hppa_find_op(ctx->insn, HPPA_OP_IDX_REG);
	if (a->bits != 32 || !a->opt.jmptbl || ctx->insn->id != HPPA_INS_BV || !mem ||
		(idx && idx->reg != HPPA_REG_GR0) || op->addr < 5 * HPPA_INSN_SIZE) {
		return;
	}
	ut32 target = mem->mem.base - HPPA_REG_GR0;
	ut8 buf[5 * HPPA_INSN_SIZE];
	if (!a->iob.read_at(a->iob.io, op->addr - sizeof(buf), buf, sizeof(buf))) {
		return;
	}
	// w[i] is the word i + 1 instructions before the bv
	ut32 w[5];
	for (int i = 0; i < 5; i++) {
		w[i] = rz_read_ble32(buf + sizeof(buf) - (i + 1) * HPPA_INSN_SIZE, a->big_endian);
	}
	bool pic = false;
	ut32 base = 0, index = 0;
	st32 disp = 0;
	ut64 table = UT64_MAX, start = UT64_MAX, count = 0, def = UT64_MAX;
	if ((w[0] & 0xfc00ffe0) == 0x08000a00 && (w[0] & 0x1f) == target) {
		// add,l of the table address and the entry
		base = HPPA_FIELD(w[0], 21, 5) == target ? HPPA_FIELD(w[0], 16, 5) : HPPA_FIELD(w[0], 21, 5);
		pic = true;
	}
	// ldw,s index(base),t
	ut32 load = w[pic];
	if ((load & 0xfc00ffe0) == 0x0c002080 && (load & 0x1f) == target &&
		(!pic || HPPA_FIELD(load, 21, 5) == base)) {
		base = HPPA_FIELD(load, 21, 5);
		index = HPPA_FIELD(load, 16, 5);
		ut32 ldo = w[pic + 1];
		bool base_ldo = HPPA_FIELD(ldo, 26, 6) == HPPA_OPCODE_LDO &&
			HPPA_FIELD(ldo, 21, 5) == base && HPPA_FIELD(ldo, 16, 5) == base;
		disp = hppa_low_sign_ext(HPPA_FIELD(ldo, 0, 14), 14);
		if (!base || !index || index == base || !base_ldo) {
			// no table
		} else if (pic && (w[3] & ~(0x1fu << 21)) == 0xd4001c1e && (w[4] & ~(0x1fu << 21)) == 0xe8000000 &&
			HPPA_FIELD(w[3], 21, 5) == base && HPPA_FIELD(w[4], 21, 5) == base) {
			// b,l .+8,base and depwi 0,31,2,base clearing the privilege level
			start = op->addr - 5 * HPPA_INSN_SIZE;
		} else if (!pic && HPPA_FIELD(w[2], 26, 6) == HPPA_OPCODE_LDIL && HPPA_FIELD(w[2], 21, 5) == base) {
			start = op->addr - 3 * HPPA_INSN_SIZE;
		}
	}
	if (start == UT64_MAX) {
		return;
	}
	HppaScan s = { ctx, a, cs_malloc(ctx->h) };
	if (!s.insn) {
		return;
	}
	ut32 word;
	bool flow;
	ut64 jump;
	const cs_hppa_op *imm;
	if (pic) {
		table = start + 2 * HPPA_INSN_SIZE + disp;
	} else if (hppa_scan_decode(&s, start, &word, &flow, &jump) && (imm = hppa_find_op(s.insn, HPPA_OP_IMM))) {
		// the value of ldil
		table = (ut32)(imm->imm + disp);
	}
	if (table != UT64_MAX) {
		count = hppa_switch_bound(&s, start, index, &def);
	}
	cs_free(s.insn, 1);
	ut64 max = a->opt.jmptbl_maxcount > 0 ? a->opt.jmptbl_maxcount : 512;
	if (table == UT64_MAX || count > max || (!pic && count < 2)) {
		return;
	}
	RzVector targets;
	rz_vector_init(&targets, sizeof(ut64), NULL, NULL);
	// the code after an inline table starts with its first case
	ut64 end = pic ? table + (count ? count : max) * HPPA_INSN_SIZE : UT64_MAX;
	for (ut64 at = table; pic ? at < end : rz_vector_len(&targets) < count; at += HPPA_INSN_SIZE) {
		ut8 entry[HPPA_INSN_SIZE];
		if (!a->iob.read_at(a->iob.io, at, entry, sizeof(entry))) {
			break;
		}
		ut32 value = rz_read_ble32(entry, a->big_endian);
		ut64 dst = pic ? table + (st32)value : value;
		if (!hppa_switch_target_valid(a, dst)) {
			break;
		}
		if (pic && dst >= table && dst < end) {
			if (count && dst < table + count * HPPA_INSN_SIZE) {
				// a case inside the table: not one
				break;
			}
			end = count ? end : dst;
		}
		rz_vector_push(&targets, &dst);
	}
	ut64 n = rz_vector_len(&targets);
	if (n >= 2 && (!count || n == count)) {
		RzAnalysisSwitchOp *sw = rz_analysis_switch_op_new(op->addr, 0, n - 1, def);
		if (sw) {
			for (ut64 i = 0; i < n; i++) {
				rz_analysis_switch_op_add_case(sw, table + i * HPPA_INSN_SIZE, i, *(ut64 *)rz_vector_index_ptr(&targets, i));
			}
			op->type = RZ_ANALYSIS_OP_TYPE_SWITCH;
			op->switch_op = sw;
		}
	}
	rz_vector_fini(&targets);
}

static int
hppa_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	if (!(a && op && data && len > 0)) {
		return -1;
	}

	RzAsmHPPAContext *ctx = a->plugin_data;
	if (!hppa_setup_cs_handle(ctx, rz_analysis_get_cpu(a), NULL, a->big_endian)) {
		return -1;
	}

	op->size = 4;

	ctx->insn = NULL;
	ctx->count = cs_disasm(ctx->h, (const ut8 *)data, len, addr, 1, &ctx->insn);
	if (ctx->count <= 0 || !ctx->insn) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = strdup("invalid");
		}
		goto beach;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s%s%s",
			ctx->insn->mnemonic, ctx->insn->op_str[0] ? " " : "", ctx->insn->op_str);
	}
	op->size = ctx->insn->size;
	op->id = (int)ctx->insn->id;
	op->addr = ctx->insn->address;
	hppa_op_set_type(ctx, op, rz_read_ble32(data, a->big_endian));
	if (op->type == RZ_ANALYSIS_OP_TYPE_RJMP) {
		hppa_op_set_switch(ctx, a, op);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = hppa_opex(ctx->h, ctx->insn);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		hppa_fillvals(ctx, a, op);
	}

beach:
	cs_free(ctx->insn, ctx->count);
	return op->size;
}

static int hppa_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
	default:
		return -1;
	}
}

/// Word and mask matching an instruction
typedef struct {
	ut32 word;
	ut32 mask;
} HppaPattern;

#define P_NONE      { 0, 0 }
#define P_ADDIL_DP  { 0x2b600000, 0xffe00000 } // addil L%x,dp,r1
#define P_ADDIL_R19 { 0x2a600000, 0xffe00000 } // addil L%x,r19,r1
#define P_LDIL      { 0x20000000, 0xfc000000 } // ldil L%x,rT
#define P_LDI       { 0x34000000, 0xffe00000 } // ldi i,rT
#define P_LDO       { 0x34000000, 0xfc000000 } // ldo d(rB),rT
#define P_LDW       { 0x48000000, 0xfc000000 } // ldw d(rB),rT
// copy rS,rT by one set bit of rS, as nop is copy r0,r0
#define P_COPY(bit) { 0x08000240 | (bit) << 16, 0xffe0ffe0 | (bit) << 16 }

/// Instructions GCC schedules before the store of rp, the longest first
static const HppaPattern hppa_scheduled[][2] = {
	{ P_LDIL, P_LDO },
	{ P_LDIL, P_LDW },
	{ P_LDI, P_LDI },
	{ P_ADDIL_DP, P_LDW },
	{ P_ADDIL_R19, P_LDW },
	{ P_ADDIL_DP, P_LDI },
	{ P_ADDIL_R19, P_LDI },
	{ P_NONE, P_ADDIL_DP },
	{ P_NONE, P_ADDIL_R19 },
	{ P_NONE, P_LDIL },
	{ P_NONE, P_LDI },
	{ P_NONE, P_COPY(1) },
	{ P_NONE, P_COPY(2) },
	{ P_NONE, P_COPY(4) },
	{ P_NONE, P_COPY(8) },
	{ P_NONE, P_COPY(16) },
	{ P_NONE, P_NONE },
};

#undef P_NONE
#undef P_ADDIL_DP
#undef P_ADDIL_R19
#undef P_LDIL
#undef P_LDI
#undef P_LDO
#undef P_LDW
#undef P_COPY

static RzList /*<RzSearchKeyword *>*/ *hppa_preludes(RzAnalysis *analysis) {
	if (analysis->bits != 32 || !analysis->big_endian) {
		return NULL;
	}
	RzList *l = rz_list_newf((RzListFree)rz_search_keyword_free);
	if (!l) {
		return NULL;
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(hppa_scheduled); i++) {
		ut8 kw[4 * (RZ_ARRAY_SIZE(hppa_scheduled[i]) + 1)], mask[sizeof(kw)];
		size_t len = 0;
		for (size_t j = 0; j < RZ_ARRAY_SIZE(hppa_scheduled[i]); j++) {
			if (hppa_scheduled[i][j].mask) {
				rz_write_be32(kw + len, hppa_scheduled[i][j].word);
				rz_write_be32(mask + len, hppa_scheduled[i][j].mask);
				len += 4;
			}
		}
		rz_write_be32(kw + len, HPPA_STW_RP);
		rz_write_be32(mask + len, UT32_MAX);
		len += 4;
		rz_list_append(l, rz_search_keyword_new(kw, len, mask, len, NULL));
	}
	return l;
}

static bool hppa_init(void **u) {
	if (!u) {
		return false;
	}
	RzAsmHPPAContext *ctx = RZ_NEW0(RzAsmHPPAContext);
	if (!ctx) {
		return false;
	}
	*u = ctx;
	return true;
}

static bool hppa_fini(void *u) {
	if (!u) {
		return true;
	}
	RzAsmHPPAContext *ctx = u;
	cs_close(&ctx->h);
	free(u);
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_hppa_cs = {
	.name = "hppa",
	.desc = "Capstone HP PA-RISC analysis plugin",
	.author = "xvilka",
	.license = "LGPL3",
	.arch = "hppa",
	.bits = 32 | 64,
	.get_reg_profile = hppa_reg_profile,
	.archinfo = hppa_archinfo,
	.preludes = hppa_preludes,
	.op = hppa_op,
	.init = hppa_init,
	.fini = hppa_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_hppa_cs,
	.version = RZ_VERSION
};
#endif
