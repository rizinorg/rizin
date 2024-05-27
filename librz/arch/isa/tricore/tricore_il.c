// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "tricore.inc"

#include "tricore_il.h"

static const char *TriCoreREGs[] = {
	"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11", "a12", "a13", "a14", "a15",
	"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
	"PCXI",
	"PSW",
	"PC",
	"SYSCON",
	"CPU_ID",
	"CORE_ID",
	"BIV",
	"BTV",
	"ISP",
	"ICR",
	"FCX",
	"LCX",
	"COMPAT",
	"DPR0_L",
	"DPR0_U",
	"DPR1_L",
	"DPR1_U",
	"DPR2_L",
	"DPR2_U",
	"DPR3_L",
	"DPR3_U",
	"DPR4_L",
	"DPR4_U",
	"DPR5_L",
	"DPR5_U",
	"DPR6_L",
	"DPR6_U",
	"DPR7_L",
	"DPR7_U",
	"DPR8_L",
	"DPR8_U",
	"DPR9_L",
	"DPR9_U",
	"DPR10_L",
	"DPR10_U",
	"DPR11_L",
	"DPR11_U",
	"DPR12_L",
	"DPR12_U",
	"DPR13_L",
	"DPR13_U",
	"DPR14_L",
	"DPR14_U",
	"DPR15_L",
	"DPR15_U",
	"CPR0_L",
	"CPR0_U",
	"CPR1_L",
	"CPR1_U",
	"CPR2_L",
	"CPR2_U",
	"CPR3_L",
	"CPR3_U",
	"CPR4_L",
	"CPR4_U",
	"CPR5_L",
	"CPR5_U",
	"CPR6_L",
	"CPR6_U",
	"CPR7_L",
	"CPR7_U",
	"CPR8_L",
	"CPR8_U",
	"CPR9_L",
	"CPR9_U",
	"CPR10_L",
	"CPR10_U",
	"CPR11_L",
	"CPR11_U",
	"CPR12_L",
	"CPR12_U",
	"CPR13_L",
	"CPR13_U",
	"CPR14_L",
	"CPR14_U",
	"CPR15_L",
	"CPR15_U",
	"CPXE_0",
	"CPXE_1",
	"CPXE_2",
	"CPXE_3",
	"CPXE_4",
	"CPXE_5",
	"CPXE_6",
	"CPXE_7",
	"DPRE_0",
	"DPRE_1",
	"DPRE_2",
	"DPRE_3",
	"DPRE_4",
	"DPRE_5",
	"DPRE_6",
	"DPRE_7",
	"DPWE_0",
	"DPWE_1",
	"DPWE_2",
	"DPWE_3",
	"DPWE_4",
	"DPWE_5",
	"DPWE_6",
	"DPWE_7",
	"TPS_CON",
	"TPS_TIMER0",
	"TPS_TIMER1",
	"TPS_TIMER2",
	"TPS_EXTIM_ENTRY_CVAL",
	"TPS_EXTIM_ENTRY_LVAL",
	"TPS_EXTIM_EXIT_CVAL",
	"TPS_EXTIM_EXIT_LVAL",
	"TPS_EXTIM_CLASS_EN",
	"TPS_EXTIM_STAT",
	"TPS_EXTIM_FCX",
	"MMU_CON",
	"MMU_ASI",
	"MMU_TVA",
	"MMU_TPA",
	"MMU_TPX",
	"MMU_TFA",
	"MMU_TFAS",
	"PMA01_",
	"PMA01",
	"PMA11",
	"PMA21",
	"DCON2",
	"DCON1",
	"SMACON",
	"DSTR",
	"DATR",
	"DEADD",
	"DIEAR",
	"DIETR",
	"DCON0",
	"PSTR",
	"PCON1",
	"PCON2",
	"PCON0",
	"PIEAR",
	"PIETR",
	"DBGSR",
	"EXEVT",
	"CREVT",
	"SWEVT",
	"TR0EVT",
	"TR0ADR",
	"TR1EVT",
	"TR1ADR",
	"TR2EVT",
	"TR2ADR",
	"TR3EVT",
	"TR3ADR",
	"TR4EVT",
	"TR4ADR",
	"TR5EVT",
	"TR5ADR",
	"TR6EVT",
	"TR6ADR",
	"TR7EVT",
	"TR7ADR",
	"TRIG_ACC",
	"DMS",
	"DCX",
	"TASK_ASI",
	"DBGTCR",
	"CCTRL",
	"CCNT",
	"ICNT",
	"M1CNT",
	"M2CNT",
	"M3CNT",
	"FPU_TRAP_CON",
	"FPU_TRAP_PC",
	"FPU_TRAP_OPC",
	"FPU_TRAP_SRC1",
	"FPU_TRAP_SRC2",
	"FPU_TRAP_SRC3",
	NULL
};

static const char *CR_Table(unsigned addr_offset) {
	addr_offset &= 0xffff;
	switch (addr_offset) {
	/// GPR
	case 0xFF00: return "d0";
	case 0xFF04: return "d1";
	case 0xFF08: return "d2";
	case 0xFF0C: return "d3";
	case 0xFF10: return "d4";
	case 0xFF14: return "d5";
	case 0xFF18: return "d6";
	case 0xFF1C: return "d7";
	case 0xFF20: return "d8";
	case 0xFF24: return "d9";
	case 0xFF28: return "d10";
	case 0xFF2C: return "d11";
	case 0xFF30: return "d12";
	case 0xFF34: return "d13";
	case 0xFF38: return "d14";
	case 0xFF3C: return "d15";
	case 0xFF80: return "a0";
	case 0xFF84: return "a1";
	case 0xFF88: return "a2";
	case 0xFF8C: return "a3";
	case 0xFF90: return "a4";
	case 0xFF94: return "a5";
	case 0xFF98: return "a6";
	case 0xFF9C: return "a7";
	case 0xFFA0: return "a8";
	case 0xFFA4: return "a9";
	case 0xFFA8: return "a10";
	case 0xFFAC: return "a11";
	case 0xFFB0: return "a12";
	case 0xFFB4: return "a13";
	case 0xFFB8: return "a14";
	case 0xFFBC: return "a15";
	/// CSFR
	case 0xFE00: return "PCXI";
	case 0xFE04: return "PSW";
	case 0xFE08: return "PC";
	case 0xFE14: return "SYSCON";
	case 0xFE18: return "CPU_ID";
	case 0xFE1C: return "CORE_ID";
	case 0xFE20: return "BIV";
	case 0xFE24: return "BTV";
	case 0xFE28: return "ISP";
	case 0xFE2C: return "ICR";
	case 0xFE38: return "FCX";
	case 0xFE3C: return "LCX";
	case 0x9400: return "COMPAT";
	/// Memory Protection Registers
	case 0xC000: return "DPR0_L";
	case 0xC004: return "DPR0_U";
	case 0xC008: return "DPR1_L";
	case 0xC00C: return "DPR1_U";
	case 0xC010: return "DPR2_L";
	case 0xC014: return "DPR2_U";
	case 0xC018: return "DPR3_L";
	case 0xC01C: return "DPR3_U";
	case 0xC020: return "DPR4_L";
	case 0xC024: return "DPR4_U";
	case 0xC028: return "DPR5_L";
	case 0xC02C: return "DPR5_U";
	case 0xC030: return "DPR6_L";
	case 0xC034: return "DPR6_U";
	case 0xC038: return "DPR7_L";
	case 0xC03C: return "DPR7_U";
	case 0xC040: return "DPR8_L";
	case 0xC044: return "DPR8_U";
	case 0xC048: return "DPR9_L";
	case 0xC04C: return "DPR9_U";
	case 0xC050: return "DPR10_L";
	case 0xC054: return "DPR10_U";
	case 0xC058: return "DPR11_L";
	case 0xC05C: return "DPR11_U";
	case 0xC060: return "DPR12_L";
	case 0xC064: return "DPR12_U";
	case 0xC068: return "DPR13_L";
	case 0xC06C: return "DPR13_U";
	case 0xC070: return "DPR14_L";
	case 0xC074: return "DPR14_U";
	case 0xC078: return "DPR15_L";
	case 0xC07C: return "DPR15_U";
	case 0xD000: return "CPR0_L";
	case 0xD004: return "CPR0_U";
	case 0xD008: return "CPR1_L";
	case 0xD00C: return "CPR1_U";
	case 0xD010: return "CPR2_L";
	case 0xD014: return "CPR2_U";
	case 0xD018: return "CPR3_L";
	case 0xD01C: return "CPR3_U";
	case 0xD020: return "CPR4_L";
	case 0xD024: return "CPR4_U";
	case 0xD028: return "CPR5_L";
	case 0xD02C: return "CPR5_U";
	case 0xD030: return "CPR6_L";
	case 0xD034: return "CPR6_U";
	case 0xD038: return "CPR7_L";
	case 0xD03C: return "CPR7_U";
	case 0xD040: return "CPR8_L";
	case 0xD044: return "CPR8_U";
	case 0xD048: return "CPR9_L";
	case 0xD04C: return "CPR9_U";
	case 0xD050: return "CPR10_L";
	case 0xD054: return "CPR10_U";
	case 0xD058: return "CPR11_L";
	case 0xD05C: return "CPR11_U";
	case 0xD060: return "CPR12_L";
	case 0xD064: return "CPR12_U";
	case 0xD068: return "CPR13_L";
	case 0xD06C: return "CPR13_U";
	case 0xD070: return "CPR14_L";
	case 0xD074: return "CPR14_U";
	case 0xD078: return "CPR15_L";
	case 0xD07C: return "CPR15_U";
	case 0xE000: return "CPXE_0";
	case 0xE004: return "CPXE_1";
	case 0xE008: return "CPXE_2";
	case 0xE00C: return "CPXE_3";
	case 0xE040: return "CPXE_4";
	case 0xE044: return "CPXE_5";
	case 0xE048: return "CPXE_6";
	case 0xE04C: return "CPXE_7";
	case 0xE010: return "DPRE_0";
	case 0xE014: return "DPRE_1";
	case 0xE018: return "DPRE_2";
	case 0xE01C: return "DPRE_3";
	case 0xE050: return "DPRE_4";
	case 0xE054: return "DPRE_5";
	case 0xE058: return "DPRE_6";
	case 0xE05C: return "DPRE_7";
	case 0xE020: return "DPWE_0";
	case 0xE024: return "DPWE_1";
	case 0xE028: return "DPWE_2";
	case 0xE02C: return "DPWE_3";
	case 0xE060: return "DPWE_4";
	case 0xE064: return "DPWE_5";
	case 0xE068: return "DPWE_6";
	case 0xE06C: return "DPWE_7";
	case 0xE400: return "TPS_CON";
	case 0xE404: return "TPS_TIMER0";
	case 0xE408: return "TPS_TIMER1";
	case 0xE40C: return "TPS_TIMER2";
	case 0xE440: return "TPS_EXTIM_ENTRY_CVAL";
	case 0xE444: return "TPS_EXTIM_ENTRY_LVAL";
	case 0xE448: return "TPS_EXTIM_EXIT_CVAL";
	case 0xE44C: return "TPS_EXTIM_EXIT_LVAL";
	case 0xE450: return "TPS_EXTIM_CLASS_EN";
	case 0xE454: return "TPS_EXTIM_STAT";
	case 0xE458: return "TPS_EXTIM_FCX";
	/// Memory Management Registers (If implemented)
	case 0x8000: return "MMU_CON";
	// case 0x8004: return "MMU_ASI";
	case 0x800C: return "MMU_TVA";
	case 0x8010: return "MMU_TPA";
	case 0x8014: return "MMU_TPX";
	case 0x8018: return "MMU_TFA";
	case 0x8020: return "MMU_TFAS";
	case 0x801C: return "PMA01_";
	case 0x8100: return "PMA01";
	case 0x8104: return "PMA11";
	case 0x8108: return "PMA21";
	case 0x9000: return "DCON2";
	case 0x9008: return "DCON1";
	case 0x900C: return "SMACON";
	case 0x9010: return "DSTR";
	case 0x9018: return "DATR";
	case 0x901C: return "DEADD";
	case 0x9020: return "DIEAR";
	case 0x9024: return "DIETR";
	case 0x9040: return "DCON0";
	case 0x9200: return "PSTR";
	case 0x9204: return "PCON1";
	case 0x9208: return "PCON2";
	case 0x920C: return "PCON0";
	case 0x9210: return "PIEAR";
	case 0x9214: return "PIETR";
	/// Debug Registers
	case 0xFD00: return "DBGSR";
	case 0xFD08: return "EXEVT";
	case 0xFD0C: return "CREVT";
	case 0xFD10: return "SWEVT";
	case 0xF000: return "TR0EVT";
	case 0xF004: return "TR0ADR";
	case 0xF008: return "TR1EVT";
	case 0xF00C: return "TR1ADR";
	case 0xF010: return "TR2EVT";
	case 0xF014: return "TR2ADR";
	case 0xF018: return "TR3EVT";
	case 0xF01C: return "TR3ADR";
	case 0xF020: return "TR4EVT";
	case 0xF024: return "TR4ADR";
	case 0xF028: return "TR5EVT";
	case 0xF02C: return "TR5ADR";
	case 0xF030: return "TR6EVT";
	case 0xF034: return "TR6ADR";
	case 0xF038: return "TR7EVT";
	case 0xF03C: return "TR7ADR";
	case 0xFD30: return "TRIG_ACC";
	case 0xFD40: return "DMS";
	case 0xFD44: return "DCX";
	case 0x8004: return "TASK_ASI";
	case 0xFD48: return "DBGTCR";
	case 0xFC00: return "CCTRL";
	case 0xFC04: return "CCNT";
	case 0xFC08: return "ICNT";
	case 0xFC0C: return "M1CNT";
	case 0xFC10: return "M2CNT";
	case 0xFC14: return "M3CNT";
	/// Floating Point Registers
	case 0xA000: return "FPU_TRAP_CON";
	case 0xA004: return "FPU_TRAP_PC";
	case 0xA008: return "FPU_TRAP_OPC";
	case 0xA010: return "FPU_TRAP_SRC1";
	case 0xA014: return "FPU_TRAP_SRC2";
	case 0xA018: return "FPU_TRAP_SRC3";
	default: break;
	}
	return NULL;
}

static bool is_pair_register(const char *name) {
	return name && (name[0] == 'e' || name[0] == 'p');
}

static unsigned reg_bits(const char *name) {
	return is_pair_register(name) ? 64 : 32;
}

static const char *REG_SUB(const char *name, bool ms) {
	rz_return_val_if_fail(name && strlen(name) >= 2, NULL);
	if (is_pair_register(name)) {
		const char y = name[0] == 'e' ? 16 : name[0] == 'p' ? 0
								    : -1;
		const ut64 i = strtol(name + 1, NULL, 10);
		rz_warn_if_fail(i < RZ_ARRAY_SIZE(TriCoreREGs));
		return TriCoreREGs[y + i + ms];
	}
	return NULL;
}

static RzILOpPure *VARG_SUB(const char *name, bool ms) {
	const char *x = REG_SUB(name, ms);
	if (x) {
		return VARG(x);
	}
	return NULL;
}

static RzILOpEffect *SETG_wrap(const char *name, RzILOpPure *x) {
	if (!(name && x)) {
		goto err;
	}
	if (is_pair_register(name)) {
		const char *a0 = REG_SUB(name, 0);
		const char *a1 = REG_SUB(name, 1);
		if (!(a0 && a1)) {
			goto err;
		}
		return SEQ3(
			SETL("temp", x),
			SETG(a0, UNSIGNED(32, VARL("temp"))),
			SETG(a1, UNSIGNED(32, BITS64(VARL("temp"), 32, 32))));
	}
	if (RZ_STR_EQ(name, "sp")) {
		return SETG("a10", x);
	}
	return SETG(name, x);
err:
	rz_warn_if_reached();
	if (x) {
		rz_il_op_pure_free(x);
	}
	return NULL;
}

static RzILOpPure *VARG_wrap(const char *name) {
	rz_return_val_if_fail(name, NULL);
	if (is_pair_register(name)) {
		const char *a0 = REG_SUB(name, 0);
		const char *a1 = REG_SUB(name, 1);
		if (!(a0 && a1)) {
			return NULL;
		}
		return APPEND(VARG(a1), VARG(a0));
	}
	if (RZ_STR_EQ(name, "sp")) {
		return VARG("a10");
	}
	return VARG(name);
}

#undef SETG
#define SETG(n, x) SETG_wrap(n, x)
#undef VARG
#define VARG(n) VARG_wrap(n)

static RzAnalysisLiftedILOp status_conditional(RzILOpPure *cnd);

static RzAnalysisLiftedILOp ST_MB(RzILOpPure *dst, size_t n, ...) {
	rz_return_val_if_fail(dst && n > 0, rz_il_op_new_nop());
	va_list args;
	va_start(args, n);

	RzILOpEffect *root = NULL;
	RzILOpEffect *eff = RZ_NEW0(RzILOpEffect);
	if (!eff) {
		goto err;
	}
	root = eff;
	eff->code = RZ_IL_OP_SEQ;
	eff->op.seq.x = STOREW(dst, va_arg(args, RzILOpPure *));
	if (!eff->op.seq.x) {
		goto err;
	}

	for (int i = 1; i < n; ++i) {
		RzILOpEffect *act = STOREW(ADD(DUP(dst), U32(i * 4)), va_arg(args, RzILOpPure *));
		if (!act) {
			goto err;
		}
		if (i == n - 1) {
			eff->op.seq.y = act;
			break;
		}
		RzILOpEffect *seq = RZ_NEW0(RzILOpEffect);
		if (!seq) {
			rz_il_op_effect_free(act);
			goto err;
		}
		seq->code = RZ_IL_OP_SEQ;
		seq->op.seq.x = act;

		eff->op.seq.y = seq;
		eff = seq;
	}
	va_end(args);
	return root;
err:
	va_end(args);
	rz_il_op_effect_free(root);
	return NULL;
}

static unsigned reg_index(const char *x) {
	size_t index = 0;
	rz_array_find(TriCoreREGs, x, index, 0, RZ_ARRAY_SIZE(TriCoreREGs), strcmp);
}

static RzAnalysisLiftedILOp SETG_MB(const char *fst, size_t n, ...) {
	rz_return_val_if_fail(fst && n > 0, rz_il_op_new_nop());

	va_list args;
	va_start(args, n);

	RzILOpEffect *root = NULL;
	RzILOpEffect *eff = NULL;
	size_t index = reg_index(fst);
	if (index + n >= RZ_ARRAY_SIZE(TriCoreREGs)) {
		goto err;
	}
	eff = RZ_NEW0(RzILOpEffect);
	if (!eff) {
		goto err;
	}
	root = eff;
	eff->code = RZ_IL_OP_SEQ;
	eff->op.seq.x = SETG(TriCoreREGs[index], va_arg(args, RzILOpPure *));

	if (!eff->op.seq.x) {
		goto err;
	}

	for (int i = 1; i < n; ++i) {
		index += 1;
		RzILOpEffect *act = SETG(TriCoreREGs[index], va_arg(args, RzILOpPure *));
		if (!act) {
			goto err;
		}
		if (i == n - 1) {
			eff->op.seq.y = act;
			break;
		}
		RzILOpEffect *seq = RZ_NEW0(RzILOpEffect);
		if (!seq) {
			rz_il_op_effect_free(act);
			goto err;
		}
		seq->code = RZ_IL_OP_SEQ;
		seq->op.seq.x = act;

		eff->op.seq.y = seq;
		eff = seq;
	}
	va_end(args);
	return root;
err:
	rz_warn_if_reached();
	va_end(args);
	rz_il_op_effect_free(root);
	return NULL;
}

#define R(x)     tricore_op_as_reg(ctx, x)
#define I(x)     tricore_op_as_imm(ctx, x)
#define M(x)     tricore_op_as_mem(ctx, x)
#define OPC1     ctx->insn->bytes[0]
#define OPC1_BRN (ctx->insn->bytes[0] & 0x7f)

enum trap_kind_t {
	/// Class 0 — MMU
	VAF, ///< Virtual Address Fill.
	VAP, ///< Virtual Address Protection.

	/// Class 1 — Internal Protection Traps
	PRIV, ///< Privileged Instruction.
	MPR, ///< Memory Protection Read.
	MPW, ///< Memory Protection Write.
	MPX, ///< Memory Protection Execution.
	MPP, ///< Memory Protection Peripheral Access.
	MPN, ///< Memory Protection Null Address.
	GRWP, ///< Global Register Write Protection.

	/// Class 2 — Instruction Errors
	IOPC, ///< Illegal Opcode.
	UOPC, ///< Unimplemented Opcode.
	OPD, ///< Invalid Operand specification.
	ALN, ///< Data Address Alignment.
	MEM, ///< Invalid Local Memory Address.

	/// Class 3 — Context Management
	FCD, ///< Free Context List Depletion (FCX = LCX).
	CDO, ///< Call Depth Overflow.
	CDU, ///< Call Depth Underflow.
	FCU, ///< Free Context List Underflow (FCX = 0).
	CSU, ///< Call Stack Underflow (PCX = 0).
	CTYP, ///< Context Type (PCXI.UL wrong).
	NEST, ///< Nesting Error: RFE with non-zero call depth.

	/// Class 4 — System Bus and Peripheral Errors
	PSE, ///< Program Fetch Synchronous Error.
	DSE, ///< Data Access Synchronous Error.
	DAE, ///< Data Access Asynchronous Error.
	CAE, ///< Coprocessor Trap Asynchronous Error.
	PIE, ///< Program Memory Integrity Error.
	DIE, ///< Data Memory Integrity Error.
	TAE, ///< Temporal Asynchronous Error

	/// Class 5 — Assertion Traps
	OVF, ///< Arithmetic Overflow.
	SOVF, ///< Sticky Arithmetic Overflow.

	/// Class 6 — System Call
	SYS, ///< System Call.

	/// Class 7 — Non-Maskable Interrupt
	NMI ///< Non-Maskable Interrupt.
};

static inline RzILOpEffect *trap(enum trap_kind_t kind) {
	return NOP();
}

static inline RzILOpPure *PSW_CDC_COUNT() {
	return LET("CDC", PSW_CDC(),
		ITE(EQ(BITS32(VARLP("CDC"), 6, 1), U32(0)),
			BITS32(VARLP("CDC"), 0, 6),
			ITE(EQ(BITS32(VARLP("CDC"), 5, 2), U32(0b10)),
				BITS32(VARLP("CDC"), 0, 5),
				ITE(EQ(BITS32(VARLP("CDC"), 4, 3), U32(0b110)),
					BITS32(VARLP("CDC"), 0, 4),
					ITE(EQ(BITS32(VARLP("CDC"), 3, 4), U32(0b1110)),
						BITS32(VARLP("CDC"), 0, 3),
						ITE(EQ(BITS32(VARLP("CDC"), 2, 5), U32(0b11110)),
							BITS32(VARLP("CDC"), 0, 2),
							ITE(EQ(BITS32(VARLP("CDC"), 1, 6), U32(0b111110)),
								BITS32(VARLP("CDC"), 0, 1),
								U32(0))))))));
}

static inline RzILOpPure *PSW_CDC_COUNT_LEN() {
	return LET("CDC", PSW_CDC(),
		ITE(EQ(BITS32(VARLP("CDC"), 6, 1), U32(0b0)),
			U32(6),
			ITE(EQ(BITS32(VARLP("CDC"), 5, 2), U32(0b10)),
				U32(5),
				ITE(EQ(BITS32(VARLP("CDC"), 4, 3), U32(0b110)),
					U32(4),
					ITE(EQ(BITS32(VARLP("CDC"), 3, 4), U32(0b1110)),
						U32(3),
						ITE(EQ(BITS32(VARLP("CDC"), 2, 5), U32(0b11110)),
							U32(2),
							ITE(EQ(BITS32(VARLP("CDC"), 1, 6), U32(0b111110)),
								U32(1),
								U32(0))))))));
}

static inline RzILOpEffect *set_PSW_CDC_COUNT(RzILOpPure *val, RzILOpEffect *overflow, RzILOpEffect *underflow) {
	RzILOpEffect *eff = NULL;
	if (overflow) {
		eff = BRANCH(EQ(VARL("CDC_COUNT"), SUB(SHIFTL0(U32(1), VARL("CDC_i")), U32(1))), overflow, NOP());
	} else if (underflow) {
		eff = BRANCH(EQ(VARL("CDC_COUNT"), U32(0x0)), underflow, NOP());
	} else {
		eff = NOP();
	}

	return SEQ5(
		SETL("CDC", PSW_CDC()),
		SETL("CDC_COUNT", PSW_CDC_COUNT()),
		SETL("CDC_i", PSW_CDC_COUNT_LEN()),
		SETG("PSW", DEPOSIT32(VARG("PSW"), U32(0), VARL("CDC_i"), val)),
		eff);
}

/**
 * If PSW.CDC == 7’b1111111 returns FALSE, otherwise decrements
 * PSW.CDC.COUNT and returns TRUE if PSW.CDC.COUNT underflows,
 * otherwise returns FALSE
 */
static inline RzILOpEffect *cdc_decrement(RzILOpEffect *eff_true) {
	RzILOpEffect *dec = set_PSW_CDC_COUNT(SUB(PSW_CDC_COUNT(), U32(1)), NULL, eff_true);
	return BRANCH(EQ(PSW_CDC(), U32(0x7F)), dec, NOP());
}

/**
 * If PSW.CDC == 7'b1111111 returns FALSE, otherwise increments
 * PSW.CDC.COUNT and returns TRUE if PSW.CDC.COUNT overflows, otherwise
 * returns FALSE
 */
static inline RzILOpEffect *cdc_increment(RzILOpEffect *eff_true) {
	RzILOpEffect *inc = set_PSW_CDC_COUNT(ADD(VARL("_psw_cdc"), U32(1)), eff_true, NULL);
	return SEQ2(
		SETL("_psw_cdc", PSW_CDC()),
		BRANCH(EQ(VARL("_psw_cdc"), U32(0x7F)), inc, NOP()));
}

/**
 * Returns TRUE if PCW.CDC.COUNT == 0 or if PSW.CDC == 7'b1111111,
 * otherwise returns FALSE
 */
static inline RzILOpPure *cdc_zero() {
	return OR(EQ(PSW_CDC(), U32(0x7F)), EQ(PSW_CDC_COUNT(), U32(0)));
}

#define PC_NEXT (ctx->insn->address + ctx->insn->size)

static RzAnalysisLiftedILOp fast_call(const RzAsmTriCoreContext *ctx, RzILOpPure *target) {
	const ut64 ret = PC_NEXT;
	RzILOpEffect *EA = SETL("EA", SUB(VARG("a10"), U32(4)));
	RzILOpEffect *M = STOREW(VARL("EA"), VARG("a11"));
	RzILOpEffect *jmp = JMP(target);
	RzILOpEffect *a11 = SETG("a11", U32(ret));
	RzILOpEffect *a10 = SETG("a10", VARL("EA"));
	return SEQ5(EA, M, a11, a10, jmp);
}

static RzAnalysisLiftedILOp abs_call(RzAsmTriCoreContext *ctx, RzILOpPure *target) {
	RzILOpEffect *pcxi = NULL;
	switch (ctx->mode) {
	case CS_MODE_TRICORE_162: {
		pcxi = SEQ4(set_PCXI_PCPN_v162(ICR_CCPN()),
			set_PCXI_PCPN_v162(ICR_IE()),
			set_PCXI_PCPN_v162(U32(1)),
			SETG("PCXI", BITS32_U(VARG("PCXI"), 0, 20, BITS32(VARG("FCX"), 0, 20))));
		break;
	}
	case CS_MODE_TRICORE_160: {
		pcxi = SEQ4(set_PCXI_PCPN_v160(ICR_CCPN()),
			set_PCXI_PCPN_v160(ICR_IE()),
			set_PCXI_PCPN_v160(U32(1)),
			SETG("PCXI", BITS32_U(VARG("PCXI"), 0, 20, BITS32(VARG("FCX"), 0, 20))));
		break;
	}
	default: {
		RZ_LOG_ERROR("Unknown tricore version: %d\n", ctx->mode);
		return NULL;
	}
	}

	RzILOpEffect *cde = set_PSW_CDE(U32(1));

	RzILOpEffect *tmp_FCX = SETL("tmp_FCX", VARG("FCX"));

	RzILOpEffect *EA = SETL("EA", LOGOR(SHIFTL0(FCX_FCXS(), U32(28)), SHIFTL0(FCX_FCXO(), U32(6))));

	RzILOpEffect *new_FCX = SETL("new_FCX", LOADW(32, VARL("EA")));

	RzILOpEffect *M = ST_MB(VARL("EA"), 16,
		VARG("d15"), VARG("d14"), VARG("d13"), VARG("d12"),
		VARG("a15"), VARG("a14"), VARG("a13"), VARG("a12"),
		VARG("d11"), VARG("d10"), VARG("d9"), VARG("d8"),
		VARG("a11"), VARG("a10"), VARG("PSW"), VARG("PCXI"));

	RzILOpEffect *fcx = SETG("FCX", BITS32_U(VARG("FCX"), 0, 20, BITS32(VARL("new_FCX"), 0, 20)));

	RzILOpEffect *jmp = JMP(target);

	ut64 ret = PC_NEXT;
	RzILOpEffect *a11 = SETG("a11", U32(ret));

	return BRANCH(IS_ZERO(VARG("FCX")), trap(FCU),
		SEQ2(
			BRANCH(NON_ZERO(PSW_CDE()), cdc_increment(trap(CDO)), NOP()),
			SEQ9(cde, tmp_FCX, EA, new_FCX, M, pcxi, fcx, a11,
				BRANCH(EQ(VARL("new_FCX"), VARG("LCX")), trap(FCD), jmp))));
}

static RzAnalysisLiftedILOp fret() {
	RzILOpEffect *PC = JMP(LOGAND(VARL("a11_tmp"), U32(0xfffffffe)));
	RzILOpEffect *EA = SETL("EA", VARG("a10"));
	RzILOpEffect *A11 = SETG("a11", LOADW(32, VARL("EA")));
	RzILOpEffect *A10 = SETG("a10", ADD(VARG("a10"), U32(4)));
	return SEQ5(SETL("a11_tmp", VARG("a11")), EA, A11, A10, PC);
}

static RzILOpPure *sign_32bit(RzILOpPure *val) {
	return MSB(val);
}

#define Byte_b       8
#define HalfWord_b   16
#define Word_b       32
#define DoubleWord_b 64
#define Byte_B       1
#define HalfWord_B   2
#define Word_B       4
#define DoubleWord_B 8

static RzILOpPure *EA_disp24(ut32 x) {
	return U32(((x & 0xfffff) << 1) | ((x & 0xf0000) << 28));
}

static RzILOpPure *EA_off18(ut32 x) {
	return U32((x & (0xfU << 28)) | (x & 0x3fffU));
}

static RzILOpEffect *SETG_EA(const char *x, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32)) {
	RzILOpPure *v = LOADW(B, VARL("EA"));
	if (f) {
		v = UNSIGNED(reg_bits(x), f(v, B));
	} else if (reg_bits(x) != B) {
		v = UNSIGNED(reg_bits(x), v);
	}
	return SETG(x, v);
}

/// reverse the n-bit binary value
static RzILOpPure *reflect(RzILOpPure *x, ut8 n) {
	if (n <= 1) {
		return x;
	}
	ut8 m = n / 2;
	if (n % 2 == 0) {
		return LET("tmp", x,
			LOGOR(reflect(BITS32(VARLP("tmp"), 0, m), m), SHL0(reflect(BITS32(VARLP("tmp"), m, m), m), m)));
	}
	return LET("tmp", x,
		LOGOR(LOGOR(reflect(BITS32(VARLP("tmp"), 0, m), m),
			      SHL0(reflect(BITS32(VARLP("tmp"), m, m), m), m)),
			BITS32(VARLP("tmp"), m * 2, 1)));
}

/// reverse the 16-bit binary value
static RzILOpPure *reverse16(RzILOpPure *x) {
	return reflect(x, 16);
}

static RzAnalysisLiftedILOp f_cons_(RzILOpEffect *x, RzILOpEffect *y) {
	if (!(x && x->code == RZ_IL_OP_SEQ)) {
		goto err;
	}
	RzILOpEffect *last = x;
	while (last->op.seq.y && last->op.seq.y->code == RZ_IL_OP_SEQ) {
		last = last->op.seq.y;
	}
	if (last->op.seq.y) {
		RzILOpEffect *seq = RZ_NEW0(RzILOpEffect);
		if (!seq) {
			goto err;
		}
		seq->code = RZ_IL_OP_SEQ;
		seq->op.seq.x = last->op.seq.y;
		seq->op.seq.y = y;
		last->op.seq.y = seq;
	} else {
		last->op.seq.y = y;
	}
	return x;
err:
	rz_warn_if_reached();
	rz_il_op_effect_free(x);
	rz_il_op_effect_free(y);
	return NULL;
}

#define merr(x) \
	if (!x) { \
		rz_warn_if_reached(); \
		return NULL; \
	}

#define f_cons(_x, _y) \
	merr(f_cons_(_x, _y))

static RzILOpPure *swap_bit_i(RzILOpPure *x, RzILOpPure *ia, RzILOpPure *ib) {
	return LET("swap_bit_i_x", x,
		LET("swap_bit_i_ia", ia,
			LET("swap_bit_i_ib", ib,
				LET("swap_bit_i_a", EXTRACT32(VARLP("swap_bit_i_x"), VARLP("swap_bit_i_ia"), U32(1)),
					LET("swap_bit_i_b", EXTRACT32(VARLP("swap_bit_i_x"), VARLP("swap_bit_i_ib"), U32(1)),
						LET("swap_bit_i_1", DEPOSIT32(VARLP("swap_bit_i_x"), VARLP("swap_bit_i_ia"), U32(1), VARLP("swap_bit_i_b")),
							DEPOSIT32(VARLP("swap_bit_i_1"), VARLP("swap_bit_i_ib"), U32(1), VARLP("swap_bit_i_a"))))))));
}

/// reverse the n-bit binary value
static RzILOpEffect *reverseV(const char *name, RzILOpPure *x, RzILOpPure *n) {
	rz_return_val_if_fail(name && x && n, NULL);

	RzILOpEffect *xs = SEQ2(
		SETL(name, x),
		SETL("reverseV_i", U32(0)));
	return f_cons_(xs,
		REPEAT(ULT(VARL("reverseV_i"), n),
			SEQ2(
				SETL(name, swap_bit_i(VARL(name), VARL("reverseV_i"), SUB(U32(31), VARL("reverseV_i")))),
				SETL("reverseV_i", ADD(VARL("reverseV_i"), U32(1))))));
}

static RzAnalysisLiftedILOp ld_addr_abs(RzAsmTriCoreContext *ctx, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32)) {
	return SEQ2(
		SETL("EA", EA_off18(I(1))),
		SETG_EA(R(0), B, f));
}

static RzILOpPure *EA_bso(TriCoreMem m) {
	return ADD(VARG(m.reg), sign_ext32_bv(m.disp, 10));
}

static RzAnalysisLiftedILOp ld_base_short_offset(RzAsmTriCoreContext *ctx, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32)) {
	TriCoreMem m = M(1);
	return SEQ2(SETL("EA", ADD(VARG(m.reg), sign_ext32_bv(m.disp, 10))),
		SETG_EA(R(0), B, f));
}
static RzAnalysisLiftedILOp st_base_short_offset(RzAsmTriCoreContext *ctx, ut8 L, ut8 B) {
	TriCoreMem m = M(0);
	const char *b = m.reg;
	const char *a = R(1);
	unsigned off10 = m.disp;
	return STOREW(ADD(VARG(b), sign_ext32_bv(off10, 10)), B >= Word_b ? VARG(a) : BITS32(VARG(a), L, B));
}

static RzAnalysisLiftedILOp ld_base_long_offset(RzAsmTriCoreContext *ctx, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32)) {
	TriCoreMem m = M(1);
	return SEQ2(SETL("EA", ADD(VARG(m.reg), sign_ext32_bv(m.disp, 16))),
		SETG_EA(R(0), B, f));
}
static RzAnalysisLiftedILOp st_base_long_offset(RzAsmTriCoreContext *ctx, ut8 B) {
	TriCoreMem m = M(0);
	const char *b = m.reg;
	const char *a = R(1);
	unsigned off16 = m.disp;
	return STOREW(ADD(VARG(b), sign_ext32_bv(off16, 16)), UNSIGNED(B, VARG(a)));
}

static RzAnalysisLiftedILOp ld_post_increment(RzAsmTriCoreContext *ctx, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32)) {
	TriCoreMem m = M(1);
	return SEQ3(
		SETL("EA", VARG(m.reg)),
		SETG_EA(R(0), B, f),
		SETG(m.reg, ADD(VARL("EA"), sign_ext32_bv(m.disp, 10))));
}
static RzAnalysisLiftedILOp st_post_increment(RzAsmTriCoreContext *ctx, ut8 L, ut8 B) {
	TriCoreMem m = M(0);
	const char *b = m.reg;
	const char *a = R(1);
	unsigned off10 = m.disp;
	return SEQ3(
		SETL("EA", VARG(b)),
		STOREW(VARL("EA"), B >= Word_b ? VARG(a) : BITS32(VARG(a), L, B)),
		SETG(b, ADD(VARL("EA"), sign_ext32_bv(off10, 10))));
}

static RzAnalysisLiftedILOp ld_pre_increment(RzAsmTriCoreContext *ctx, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32)) {
	TriCoreMem m = M(1);
	return SEQ3(
		SETL("EA", ADD(VARG(m.reg), sign_ext32_bv(m.disp, 10))),
		SETG_EA(R(0), B, f),
		SETG(m.reg, VARL("EA")));
}
static RzAnalysisLiftedILOp st_pre_increment(RzAsmTriCoreContext *ctx, ut8 L, ut8 B) {
	TriCoreMem m = M(0);
	const char *b = m.reg;
	const char *a = R(1);
	unsigned off10 = m.disp;
	return SEQ3(
		SETL("EA", ADD(VARG(b), sign_ext32_bv(off10, 10))),
		STOREW(VARL("EA"), B >= Word_b ? VARG(a) : BITS32(VARG(a), L, B)),
		SETG(b, VARL("EA")));
}

static RzAnalysisLiftedILOp addr_bit_reverse(RzAsmTriCoreContext *ctx, const char *reg, RzILOpEffect *eff) {
	return SEQ6(
		SETL("index", BITS32(VARG_SUB(reg, false), 0, 16)),
		SETL("incr", BITS32(VARG_SUB(reg, false), 16, 16)),
		SETL("EA", ADD(VARG_SUB(reg, true), VARL("index"))),
		eff,
		SETL("new_index", reverse16(ADD(reverse16(VARL("index")), reverse16(VARL("incr"))))),
		SETG(REG_SUB(reg, false), LOGOR(SHL0(VARL("incr"), 16), VARL("new_index"))));
}
static RzAnalysisLiftedILOp ld_bit_reverse(RzAsmTriCoreContext *ctx, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32)) {
	return addr_bit_reverse(ctx, R(1), SETG_EA(R(0), B, f));
}
static RzAnalysisLiftedILOp st_bit_reverse(RzAsmTriCoreContext *ctx, ut8 L, ut8 B) {
	const char *b1 = REG_SUB(R(0), 1);
	const char *b = REG_SUB(R(0), 0);
	const char *a = R(1);
	return SEQ6(
		SETL("index", BITS32(VARG(b1), 0, 16)),
		SETL("incr", BITS32(VARG(b1), 16, 16)),
		SETL("EA", ADD(VARG(b), VARL("index"))),
		STOREW(VARL("EA"), B >= Word_b ? VARG(R(1)) : UNSIGNED(B, is_pair_register(a) ? BITS64(VARG(a), L, B) : BITS32(VARG(a), L, B))),
		SETL("new_index", reverse16(ADD(reverse16(VARL("index")), reverse16(VARL("incr"))))),
		SETG(b1, APPEND(UNSIGNED(16, VARL("incr")), UNSIGNED(16, VARL("new_index")))));
}

static RzAnalysisLiftedILOp addr_circular(RzAsmTriCoreContext *ctx, TriCoreMem m, RzILOpEffect *eff) {
	const char *b1 = REG_SUB(m.reg, false);
	return SEQ6(
		SETL("index", BITS32(VARG(b1), 0, 16)),
		SETL("length", BITS32(VARG(b1), 16, 16)),
		eff,
		SETL("new_index", ADD(VARL("index"), sign_ext32_bv(m.disp, 10))),
		SETL("new_index", ITE(SLE(VARL("new_index"), U32(0)), ADD(VARL("new_index"), VARL("length")), MOD(VARL("new_index"), VARL("length")))),
		SETG(b1, APPEND(UNSIGNED(16, VARL("length")), UNSIGNED(16, VARL("new_index")))));
}
static RzAnalysisLiftedILOp ld_circular(RzAsmTriCoreContext *ctx, ut8 B,
	RzILOpPure *(*g)(RzILOpPure *, ut32),
	RzAnalysisLiftedILOp (*f)(ut8, RzILOpPure *(*)(RzILOpPure *, ut32), const char *, const char *)) {
	TriCoreMem m = M(1);
	return addr_circular(ctx, m, f(B, g, REG_SUB(m.reg, true), R(0)));
}

typedef enum {
	ST_8,
	ST_16,
	ST_16h,
	ST_16x2,
	ST_16x4,
	ST_32,
	ST_32x2,
	ST_64,
} ST_MODE;
static RzAnalysisLiftedILOp st_circular(RzAsmTriCoreContext *ctx, ST_MODE mode) {
	TriCoreMem m = M(0);
	const char *b1 = REG_SUB(m.reg, 1);
	const char *b = REG_SUB(m.reg, 0);
	const char *a = R(1);
	unsigned off10 = m.disp;
	RzAnalysisLiftedILOp e = SEQ2(
		SETL("index", BITS32(VARG(b1), 0, 16)),
		SETL("length", BITS32(VARG(b1), 16, 16)));

	if (mode == ST_32 || mode == ST_64) {
		f_cons(e, SETL("EA", ADD(VARG(b), VARL("index"))));
		f_cons(e, STOREW(VARL("EA"), VARG(a)));
	} else if (mode == ST_16) {
		f_cons(e, SETL("EA", ADD(VARG(b), VARL("index"))));
		f_cons(e, STOREW(VARL("EA"), UNSIGNED(16, VARG(a))));
	} else if (mode == ST_16h) {
		f_cons(e, SETL("EA", ADD(VARG(b), VARL("index"))));
		f_cons(e, STOREW(VARL("EA"), UNSIGNED(16, SHR0(VARG(a), 16))));
	} else if (mode == ST_8) {
		f_cons(e, SETL("EA", ADD(VARG(b), VARL("index"))));
		f_cons(e, STOREW(VARL("EA"), UNSIGNED(Byte_b, VARG(a))));
	} else if (mode == ST_16x2) {
		f_cons(e, SETL("EA0", ADD(VARG(b), VARL("index"))));
		f_cons(e, SETL("EA2", ADD(VARG(b), MOD(ADD(VARL("index"), U32(2)), VARL("length")))));
		f_cons(e, STOREW(VARL("EA0"), UNSIGNED(16, VARG(a))));
		f_cons(e, STOREW(VARL("EA2"), UNSIGNED(16, BITS32(VARG(a), 16, 16))));
	} else if (mode == ST_32x2) {
		const char *a1 = REG_SUB(R(1), 1);
		a = REG_SUB(R(1), 0);
		f_cons(e, SETL("EA0", ADD(VARG(b), VARL("index"))));
		f_cons(e, SETL("EA4", ADD(VARG(b), MOD(ADD(VARL("index"), U32(4)), VARL("length")))));
		f_cons(e, STOREW(VARL("EA0"), VARG(a)));
		f_cons(e, STOREW(VARL("EA4"), VARG(a1)));
	} else if (mode == ST_16x4) {
		const char *a1 = REG_SUB(R(1), 1);
		a = REG_SUB(R(1), 0);
		f_cons(e, SETL("EA0", ADD(VARG(b), VARL("index"))));
		f_cons(e, SETL("EA2", ADD(VARG(b), MOD(ADD(VARL("index"), U32(2)), VARL("length")))));
		f_cons(e, SETL("EA4", ADD(VARG(b), MOD(ADD(VARL("index"), U32(4)), VARL("length")))));
		f_cons(e, SETL("EA6", ADD(VARG(b), MOD(ADD(VARL("index"), U32(6)), VARL("length")))));
		f_cons(e, STOREW(VARL("EA0"), UNSIGNED(16, VARG(a))));
		f_cons(e, STOREW(VARL("EA2"), UNSIGNED(16, BITS32(VARG(a), 16, 16))));
		f_cons(e, STOREW(VARL("EA4"), UNSIGNED(16, VARG(a1))));
		f_cons(e, STOREW(VARL("EA6"), UNSIGNED(16, BITS32(VARG(a1), 16, 16))));
	}
	f_cons(e, SETL("new_index", ADD(VARL("index"), sign_ext32_bv(off10, 10))));
	f_cons(e, SETL("new_index", ITE(SLE(VARL("new_index"), S32(0)), ADD(VARL("new_index"), VARL("length")), MOD(VARL("new_index"), VARL("length")))));
	f_cons(e, SETG(b1, APPEND(UNSIGNED(16, VARL("length")), UNSIGNED(16, VARL("new_index")))));
	return e;
}

static RzAnalysisLiftedILOp addr_circular_single(ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32), const char *b, const char *a) {
	return SEQ2(
		SETL("EA", ADD(VARG(b), VARL("index"))),
		SETG_EA(a, B, f));
}
static RzAnalysisLiftedILOp addr_circular_4(ut8 B, RzILOpPure *(*g)(RzILOpPure *, ut32), const char *b, const char *a) {
	return SEQ5(
		SETL("EA", ADD(VARG(b), VARL("index"))),
		SETL("EA2", ADD(VARG(b), MOD(ADD(VARL("index"), U32(2)), VARL("length")))),
		SETL("EA4", ADD(VARG(b), MOD(ADD(VARL("index"), U32(4)), VARL("length")))),
		SETL("EA6", ADD(VARG(b), MOD(ADD(VARL("index"), U32(6)), VARL("length")))),
		SETG(a, APPEND(APPEND(LOADW(HalfWord_b, VARL("EA6")), LOADW(HalfWord_b, VARL("EA4"))), APPEND(LOADW(HalfWord_b, VARL("EA2")), LOADW(HalfWord_b, VARL("EA"))))));
}
static RzAnalysisLiftedILOp addr_circular_2(ut8 B, RzILOpPure *(*g)(RzILOpPure *, ut32), const char *b, const char *a) {
	return SEQ3(
		SETL("EA", ADD(VARG(b), VARL("index"))),
		SETL("EA4", ADD(VARG(b), MOD(ADD(VARL("index"), U32(B / 8)), VARL("length")))),
		SETG(a, APPEND(LOADW(B, VARL("EA4")), LOADW(B, VARL("EA")))));
}

static RzAnalysisLiftedILOp ld_sc(RzAsmTriCoreContext *ctx, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32), const char rprefx) {
	if (rprefx == 'a') {
		return SEQ2(
			SETL("EA", ADD(VARG(/*a10*/ TriCoreREGs[10]), U32(I(0) * 4))),
			SETG_EA("a15", B, f));
	}
	if (rprefx == 'd') {
		return SEQ2(
			SETL("EA", ADD(VARG(/*d10*/ TriCoreREGs[16 + 10]), U32(I(0) * 4))),
			SETG_EA("d15", B, f));
	}
	rz_warn_if_reached();
	return NULL;
}
static RzAnalysisLiftedILOp st_sc(RzAsmTriCoreContext *ctx, ut8 B, const char rprefx) {
	unsigned const8 = I(0);
	if (rprefx == 'a' || rprefx == 'd') {
		return STOREW(ADD(VARG("a10"), U32(B / 8 * const8)), UNSIGNED(B, VARG(rprefx == 'a' ? "a15" : "d15")));
	}
	rz_warn_if_reached();
	return NULL;
}

static RzAnalysisLiftedILOp ld_slr(RzAsmTriCoreContext *ctx, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32)) {
	return SEQ2(
		SETL("EA", VARG(R(1))),
		SETG_EA(R(0), B, f));
}

static RzAnalysisLiftedILOp ld_slr_post_increment(RzAsmTriCoreContext *ctx, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32)) {
	return SEQ3(
		SETL("EA", VARG(R(1))),
		SETG_EA(R(0), B, f),
		SETG(R(1), ADD(VARG(R(1)), U32(B / 8))));
}

static RzAnalysisLiftedILOp ld_slro(RzAsmTriCoreContext *ctx, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32)) {
	TriCoreMem m = M(0);
	return SEQ2(
		SETL("EA", ADD(VARG("a15"), U32(4 * m.disp))),
		SETG_EA(m.reg, B, f));
}

static RzAnalysisLiftedILOp ld_sro(RzAsmTriCoreContext *ctx, ut8 B, RzILOpPure *(*f)(RzILOpPure *, ut32)) {
	TriCoreMem m = M(0);
	return SEQ2(
		SETL("EA", ADD(VARG(m.reg), U32(4 * m.disp))),
		SETG_EA("a15", B, f));
}
static RzAnalysisLiftedILOp st_sro(RzAsmTriCoreContext *ctx, ut8 B) {
	TriCoreMem m = M(0);
	const char *b = m.reg;
	unsigned const4 = m.disp;
	return STOREW(ADD(VARG(b), U32(B / 8 * const4)), UNSIGNED(B, VARG("a15")));
}

static RzAnalysisLiftedILOp st_ssr(RzAsmTriCoreContext *ctx, ut8 B) {
	const char *a = R(1);
	const char *b = R(0);
	return STOREW(VARG(b), UNSIGNED(B, VARG(a)));
}
static RzAnalysisLiftedILOp st_ssr_post_incr(RzAsmTriCoreContext *ctx, ut8 B) {
	const char *a = R(1);
	const char *b = R(0);
	return SEQ2(
		STOREW(VARG(b), UNSIGNED(B, VARG(a))),
		SETG(b, ADD(VARG(b), U32(B / 8))));
}
static RzAnalysisLiftedILOp st_ssro(RzAsmTriCoreContext *ctx, ut8 B) {
	const char *a = R(1);
	unsigned const4 = I(0);
	return STOREW(ADD(VARG("a15"), U32(B / 8 * const4)), UNSIGNED(B, VARG(a)));
}

static RzAnalysisLiftedILOp load_lower_context() {
	return SEQ4(SETG_MB("d4", 4, LOADW(Word_b, VARL("EA")), LOADW(Word_b, ADD(VARL("EA"), U32(4))), LOADW(Word_b, ADD(VARL("EA"), U32(8))), LOADW(Word_b, ADD(VARL("EA"), U32(12)))),
		SETG_MB("a4", 4, LOADW(Word_b, ADD(VARL("EA"), U32(16))), LOADW(Word_b, ADD(VARL("EA"), U32(20))), LOADW(Word_b, ADD(VARL("EA"), U32(24))), LOADW(Word_b, ADD(VARL("EA"), U32(28)))),
		SETG_MB("d0", 4, LOADW(Word_b, ADD(VARL("EA"), U32(32))), LOADW(Word_b, ADD(VARL("EA"), U32(36))), LOADW(Word_b, ADD(VARL("EA"), U32(40))), LOADW(Word_b, ADD(VARL("EA"), U32(44)))),
		SETG_MB("a2", 2, LOADW(Word_b, ADD(VARL("EA"), U32(48))), LOADW(Word_b, ADD(VARL("EA"), U32(52)))));
}

static RzAnalysisLiftedILOp load_upper_context() {
	return SEQ4(SETG_MB("d12", 4, LOADW(Word_b, VARL("EA")), LOADW(Word_b, ADD(VARL("EA"), U32(4))), LOADW(Word_b, ADD(VARL("EA"), U32(8))), LOADW(Word_b, ADD(VARL("EA"), U32(12)))),
		SETG_MB("a12", 4, LOADW(Word_b, ADD(VARL("EA"), U32(16))), LOADW(Word_b, ADD(VARL("EA"), U32(20))), LOADW(Word_b, ADD(VARL("EA"), U32(24))), LOADW(Word_b, ADD(VARL("EA"), U32(28)))),
		SETG_MB("d8", 4, LOADW(Word_b, ADD(VARL("EA"), U32(32))), LOADW(Word_b, ADD(VARL("EA"), U32(36))), LOADW(Word_b, ADD(VARL("EA"), U32(40))), LOADW(Word_b, ADD(VARL("EA"), U32(44)))),
		SETG_MB("a10", 2, LOADW(Word_b, ADD(VARL("EA"), U32(48))), LOADW(Word_b, ADD(VARL("EA"), U32(52)))));
}

static RzAnalysisLiftedILOp st_lower_context(RzILOpPure *ea) {
	return SEQ6(
		SETL("EA", ea),
		ST_MB(VARL("EA"), 4, VARG("d12"), VARG("d13"), VARG("d14"), VARG("d15")),
		ST_MB(ADD(VARL("EA"), U32(Word_b / 8 * 4)), 4, VARG("a12"), VARG("a13"), VARG("a14"), VARG("a15")),
		ST_MB(ADD(VARL("EA"), U32(Word_b / 8 * 8)), 4, VARG("d8"), VARG("d9"), VARG("d10"), VARG("d11")),
		ST_MB(ADD(VARL("EA"), U32(Word_b / 8 * 12)), 2, VARG("a10"), VARG("a11")),
		ST_MB(ADD(VARL("EA"), U32(Word_b / 8 * 14)), 2, VARG("PSW"), VARG("PCXI")));
}
static RzAnalysisLiftedILOp st_upper_context(RzILOpPure *ea) {
	return SEQ6(
		SETL("EA", ea),
		ST_MB(VARL("EA"), 4, VARG("d4"), VARG("d5"), VARG("d6"), VARG("d7")),
		ST_MB(ADD(VARL("EA"), U32(Word_b / 8 * 4)), 4, VARG("a4"), VARG("a5"), VARG("a6"), VARG("a7")),
		ST_MB(ADD(VARL("EA"), U32(Word_b / 8 * 8)), 4, VARG("d0"), VARG("d1"), VARG("d2"), VARG("d3")),
		ST_MB(ADD(VARL("EA"), U32(Word_b / 8 * 12)), 2, VARG("a2"), VARG("a3")),
		ST_MB(ADD(VARL("EA"), U32(Word_b / 8 * 14)), 2, VARG("a11"), VARG("PCXI")));
}

static RzAnalysisLiftedILOp
lift_ld_op(RzAsmTriCoreContext *ctx) {
	const char *dst_reg = tricore_op_count(ctx->insn) > 0 && tricore_op_get(ctx->insn, 0)->type == TRICORE_OP_REG
		? R(0)
		: NULL;
	RzILOpPure *src = NULL;
	switch (ctx->insn->bytes[0]) {
	case /*LD.(W|A|D|DA) ABS*/ 0x85: {
		switch (ctx->insn->id) {
		case TRICORE_INS_LD_W:
		case TRICORE_INS_LD_A:
			src = LOADW(32, EA_off18(I(1)));
			break;
		case TRICORE_INS_LD_D:
		case TRICORE_INS_LD_DA:
			src = LOADW(64, EA_off18(I(1)));
			break;
		}
		break;
	}
	case /*LD.(B|BU|H|HU) ABS*/ 0x05: {
		ut8 s26_27 = (ctx->word >> 26) & 0x3;
		switch (s26_27) {
		case 0x00: return ld_addr_abs(ctx, Byte_b, SEXT32);
		case 0x01: return ld_addr_abs(ctx, Byte_b, ZEXT32);
		case 0x02: return ld_addr_abs(ctx, HalfWord_b, SEXT32);
		case 0x03: return ld_addr_abs(ctx, HalfWord_b, ZEXT32);
		default: rz_warn_if_reached();
		}
		break;
	}
	case /*LD.Q ABS*/ 0x45: return ld_addr_abs(ctx, HalfWord_b, SHL0);
	case /*LDLCX|LDUCX ABS*/ 0x15: {
		ut8 s26_27 = extract32(ctx->word, 26, 2);
		switch (s26_27) {
		case /*LDLCX*/ 0x02: return SEQ2(SETL("EA", EA_off18(I(0))), load_lower_context());
		case /*LDUCX*/ 0x03: return SEQ2(SETL("EA", EA_off18(I(0))), load_upper_context()); ;
		default: rz_warn_if_reached(); break;
		}
		break;
	}
	case /*LDLCX|LDUCX|LEA BO*/ 0x49: {
		switch (extract32(ctx->word, 22, 6)) {
		case 0x24: return SEQ2(SETL("EA", ADD(VARG(M(0).reg), sign_ext32_bv(M(0).disp, 10))), load_lower_context());
		case 0x25: return SEQ2(SETL("EA", ADD(VARG(R(0)), sign_ext32_bv(I(1), 10))), load_upper_context());
		case 0x28: return SEQ2(SETL("EA", ADD(VARG(M(1).reg), sign_ext32_bv(M(1).disp, 10))), SETG(R(0), VARL("EA")));
		default: rz_warn_if_reached(); break;
		}
		break;
	}
	case /*LEA|LHA ABS*/ 0xc5: {
		switch (extract32(ctx->word, 26, 2)) {
		case 0x00: return SEQ2(SETL("EA", EA_off18(I(1))), SETG(R(0), VARL("EA")));
		case 0x01: return SEQ2(SETL("EA", U32(I(1) << 14)), SETG(R(0), VARL("EA")));
		default: rz_warn_if_reached(); break;
		}
		break;
	}
	case /*LEA BOL*/ 0xd9: return SEQ2(SETL("EA", ADD(VARG(M(1).reg), sign_ext32_bv(M(1).disp, 16))), SETG(R(0), VARL("EA")));
	case 0x29: {
		ut8 s22_27 = extract32(ctx->word, 22, 6);
		switch (s22_27) {
		case 0x06: return ld_bit_reverse(ctx, Word_b, NULL);
		case 0x16: return ld_circular(ctx, Word_b, NULL, addr_circular_single);
		case 0x00: return ld_bit_reverse(ctx, Byte_b, SEXT32);
		case 0x10: return ld_circular(ctx, Byte_b, SEXT32, addr_circular_single);
		case 0x01: return ld_bit_reverse(ctx, Byte_b, ZEXT32);
		case 0x11: return ld_circular(ctx, Byte_b, ZEXT32, addr_circular_single);
		case 0x05: return ld_bit_reverse(ctx, DoubleWord_b, ZEXT32);
		case 0x15: return ld_circular(ctx, HalfWord_b, NULL, addr_circular_4);
		case 0x07: return ld_bit_reverse(ctx, DoubleWord_b, NULL);
		case 0x17: return ld_circular(ctx, Word_b, NULL, addr_circular_2);
		case 0x02: return ld_bit_reverse(ctx, HalfWord_b, SEXT32);
		case 0x12: return ld_circular(ctx, HalfWord_b, SEXT32, addr_circular_single);
		case 0x03: return ld_bit_reverse(ctx, HalfWord_b, ZEXT32);
		case 0x13: return ld_circular(ctx, HalfWord_b, ZEXT32, addr_circular_single);
		case 0x08: return ld_bit_reverse(ctx, HalfWord_b, SHL0);
		case 0x18: return ld_circular(ctx, HalfWord_b, SHL0, addr_circular_single);
		case 0x04: return ld_bit_reverse(ctx, Word_b, NULL);
		case 0x14: return ld_circular(ctx, HalfWord_b, NULL, addr_circular_2);
		default: rz_warn_if_reached();
		}
		break;
	}
	case 0x09: {
		ut8 s22_27 = extract32(ctx->word, 22, 6);
		switch (s22_27) {
		case 0x26: {
			// LD.A A[a], A[b], off10 (BO)(Base + Short Offset Addressing Mode)
			return ld_base_short_offset(ctx, Word_b, NULL);
		}
		case 0x06: {
			// LD.A A[a], A[b], off10 (BO)(Post-increment Addressing Mode)
			return ld_post_increment(ctx, Word_b, NULL);
		}
		case 0x16: {
			// LD.A A[a], A[b], off10 (BO)(Pre-increment Addressing Mode)
			return ld_pre_increment(ctx, Word_b, NULL);
		}
		case 0x20: {
			// LD.B D[a], A[b], off10 (BO)(Base + Short Offset Addressing Mode)
			return ld_base_short_offset(ctx, Byte_b, SEXT32);
		}
		case 0x00: return ld_post_increment(ctx, Byte_b, SEXT32);
		case 0x10: return ld_pre_increment(ctx, Byte_b, SEXT32);
		case 0x21: {
			// LD.BU D[a], A[b], off10 (BO)(Base + Short Offset Addressing Mode)
			return ld_base_short_offset(ctx, Byte_b, ZEXT32);
		}
		case 0x01: return ld_post_increment(ctx, Byte_b, ZEXT32);
		case 0x11: return ld_pre_increment(ctx, Byte_b, ZEXT32);
		case 0x25: {
			// LD.D E[a], A[b], off10 (BO)(Base + Short Offset Addressing Mode)
			return ld_base_short_offset(ctx, DoubleWord_b, NULL);
		}
		case 0x05: return ld_post_increment(ctx, DoubleWord_b, NULL);
		case 0x15: return ld_pre_increment(ctx, DoubleWord_b, NULL);
		case 0x27: {
			// LD.DA P[a], A[b], off10 (BO)(Base + Short Offset Addressing Mode)
			return ld_base_short_offset(ctx, DoubleWord_b, NULL);
		}
		case 0x07: return ld_post_increment(ctx, DoubleWord_b, NULL);
		case 0x17: return ld_pre_increment(ctx, DoubleWord_b, NULL);
		case 0x22: {
			// LD.H D[a], A[b], off10 (BO)(Base + Short Offset Addressing Mode)
			return ld_base_short_offset(ctx, HalfWord_b, SEXT32);
		}
		case 0x02: return ld_post_increment(ctx, HalfWord_b, SEXT32);
		case 0x12: return ld_pre_increment(ctx, HalfWord_b, SEXT32);
		case 0x23: {
			// LD.HU D[a], A[b], off10 (BO)(Base + Short Offset Addressing Mode)
			return ld_base_short_offset(ctx, HalfWord_b, ZEXT32);
		}
		case 0x03: return ld_post_increment(ctx, HalfWord_b, ZEXT32);
		case 0x13: return ld_pre_increment(ctx, HalfWord_b, ZEXT32);
		case 0x28: {
			// LD.Q D[a], A[b], off10 (BO)(Base + Short Offset Addressing Mode)
			return ld_base_short_offset(ctx, HalfWord_b, SHL0);
		}
		case 0x08: return ld_post_increment(ctx, HalfWord_b, SHL0);
		case 0x18: return ld_pre_increment(ctx, HalfWord_b, SHL0);
		case 0x24: {
			// LD.W D[a], A[b], off10 (BO)(Base + Short Offset Addressing Mode)
			return ld_base_short_offset(ctx, Word_b, NULL);
		}
		case 0x04: return ld_post_increment(ctx, Word_b, NULL);
		case 0x14: return ld_pre_increment(ctx, Word_b, NULL);
		default: rz_warn_if_reached(); break;
		}
		break;
	}
	case /*LD.A BOL*/ 0x99: return ld_base_long_offset(ctx, Word_b, NULL);
	case /*LD.A SC*/ 0xd8: return ld_sc(ctx, Word_b, NULL, 'a');
	case /*LD.A SLR*/ 0xd4: return ld_slr(ctx, Word_b, NULL);
	case /*LD.A SLR*/ 0xc4: return ld_slr_post_increment(ctx, Word_b, NULL);
	case /*LD.A SLRO*/ 0xc8: return ld_slro(ctx, Word_b, NULL);
	case /*LD.A SRO*/ 0xcc: return ld_sro(ctx, Word_b, NULL);
	case /*LD.B BOL*/ 0x79: return ld_base_long_offset(ctx, Byte_b, SEXT32);
	case /*LD.BU BOL*/ 0x39: return ld_base_long_offset(ctx, Byte_b, ZEXT32);
	case /*LD.BU SLR*/ 0x14: return ld_slr(ctx, Byte_b, ZEXT32);
	case /*LD.BU SLR*/ 0x04: return ld_slr_post_increment(ctx, Byte_b, ZEXT32);
	case /*LD.BU SLRO*/ 0x08: return ld_slro(ctx, Byte_b, ZEXT32);
	case /*LD.BU SRO*/ 0x0c: return ld_sro(ctx, Byte_b, ZEXT32);
	case /*LD.H BOL*/ 0xc9: return ld_base_long_offset(ctx, HalfWord_b, SEXT32);
	case /*LD.H SLR*/ 0x94: return ld_slr(ctx, HalfWord_b, SEXT32);
	case /*LD.H SLR*/ 0x84: return ld_slr_post_increment(ctx, HalfWord_b, SEXT32);
	case /*LD.H SLRO*/ 0x88: return ld_slro(ctx, HalfWord_b, SEXT32);
	case /*LD.H SRO*/ 0x8c: return ld_sro(ctx, HalfWord_b, SEXT32);
	case /*LD.HU BOL*/ 0xb9: return ld_base_long_offset(ctx, HalfWord_b, ZEXT32);
	case /*LD.W BOL*/ 0x19: return ld_base_long_offset(ctx, Word_b, NULL);
	case /*LD.W SC*/ 0x58: return ld_sc(ctx, Word_b, NULL, 'd');
	case /*LD.W SLR*/ 0x54: return ld_slr(ctx, Word_b, NULL);
	case /*LD.W SLR*/ 0x44: return ld_slr_post_increment(ctx, Word_b, NULL);
	case /*LD.W SLRO*/ 0x48: return ld_slro(ctx, Word_b, NULL);
	case /*LD.W SRO*/ 0x4c: return ld_sro(ctx, Word_b, NULL);
	}
	if (!(src && dst_reg)) {
		return NULL;
	}
	return SETG(dst_reg, src);
}

static RzAnalysisLiftedILOp
lift_st_op(RzAsmTriCoreContext *ctx) {
	switch (ctx->insn->bytes[0]) {
	case /*ST.(W|A|D|DA) (ABS)*/ 0xa5:
	case /*ST.(B|H) ABS*/ 0x25:
	case /*ST.Q ABS*/ 0x65: {
		switch (ctx->insn->id) {
		case TRICORE_INS_ST_W:
		case TRICORE_INS_ST_A:
		case TRICORE_INS_ST_D:
		case TRICORE_INS_ST_DA: return STOREW(EA_off18(I(0)), VARG(R(1)));
		case TRICORE_INS_ST_B: return STOREW(EA_off18(I(0)), UNSIGNED(8, BITS32(VARG(R(1)), 0, 8)));
		case TRICORE_INS_ST_H: return STOREW(EA_off18(I(0)), UNSIGNED(16, BITS32(VARG(R(1)), 0, 16)));
		case TRICORE_INS_ST_Q: return STOREW(EA_off18(I(0)), UNSIGNED(16, BITS32(VARG(R(1)), 16, 16)));
		default: rz_warn_if_reached();
		}
		break;
	}
	case /*STLCX|STUCX ABS*/ 0x15: {
		ut8 s26_27 = extract32(ctx->word, 26, 2);
		switch (s26_27) {
		case /*STLCX*/ 0x00: return st_lower_context(EA_off18(I(0)));
		case /*STUCX*/ 0x01: return st_upper_context(EA_off18(I(0)));
		default: rz_warn_if_reached(); break;
		}
		break;
	}
	case /*STLCX|STUCX BO*/ 0x49: {
		switch (extract32(ctx->word, 22, 6)) {
		case /*STLCX*/ 0x26: return st_lower_context(ADD(VARG(M(0).reg), sign_ext32_bv(M(0).disp, 10)));
		case /*STUCX*/ 0x27: return st_upper_context(ADD(VARG(M(0).reg), sign_ext32_bv(M(0).disp, 10)));
		default: rz_warn_if_reached(); break;
		}
		break;
	}
	// (BO)(Base + Short Offset Addressing Mode)
	// (BO)(Post-increment Addressing Mode)
	// (BO)(Pre-increment Addressing Mode)
	case 0x89: {
		ut8 s22_27 = extract32(ctx->word, 22, 6);
		switch (s22_27) {
		/// ST.A
		case 0x26: return st_base_short_offset(ctx, 0, Word_b);
		case 0x06: return st_post_increment(ctx, 0, Word_b);
		case 0x16: return st_pre_increment(ctx, 0, Word_b);
		/// ST.B
		case 0x20: return st_base_short_offset(ctx, 0, Byte_b);
		case 0x00: return st_post_increment(ctx, 0, Byte_b);
		case 0x10: return st_pre_increment(ctx, 0, Byte_b);
		/// ST.D
		case 0x25: return st_base_short_offset(ctx, 0, DoubleWord_b);
		case 0x05: return st_post_increment(ctx, 0, DoubleWord_b);
		case 0x15: return st_pre_increment(ctx, 0, DoubleWord_b);
		/// ST.DA
		case 0x27: return st_base_short_offset(ctx, 0, DoubleWord_b);
		case 0x07: return st_post_increment(ctx, 0, DoubleWord_b);
		case 0x17: return st_pre_increment(ctx, 0, DoubleWord_b);
		/// ST.H
		case 0x22: return st_base_short_offset(ctx, 0, HalfWord_b);
		case 0x02: return st_post_increment(ctx, 0, HalfWord_b);
		case 0x12: return st_pre_increment(ctx, 0, HalfWord_b);
		/// ST.Q
		case 0x28: return st_base_short_offset(ctx, 16, HalfWord_b);
		case 0x08: return st_post_increment(ctx, 16, HalfWord_b);
		case 0x18: return st_pre_increment(ctx, 16, HalfWord_b);
		/// ST.W
		case 0x24: return st_base_short_offset(ctx, 0, Word_b);
		case 0x04: return st_post_increment(ctx, 0, Word_b);
		case 0x14: return st_pre_increment(ctx, 0, Word_b);
		default: rz_warn_if_reached(); break;
		}
		break;
	}
	// (BO)(Bit-reverse Addressing Mode)
	// (BO)(Circular Addressing Mode)
	case 0xa9: {
		ut8 s22_27 = extract32(ctx->word, 22, 6);
		switch (s22_27) {
		// ST.A
		case 0x06: return st_bit_reverse(ctx, 0, Word_b);
		case 0x16: return st_circular(ctx, ST_32);
		// ST.B
		case 0x00: return st_bit_reverse(ctx, 0, Byte_b);
		case 0x10: return st_circular(ctx, ST_8);
		// ST.D
		case 0x05: return st_bit_reverse(ctx, 0, Byte_b);
		case 0x15: return st_circular(ctx, ST_16x4);
		// ST.DA
		case 0x07: return st_bit_reverse(ctx, 0, DoubleWord_b);
		case 0x17: return st_circular(ctx, ST_32x2);
		// ST.H
		case 0x02: return st_bit_reverse(ctx, 0, HalfWord_b);
		case 0x12: return st_circular(ctx, ST_16);
		// ST.Q
		case 0x08: return st_bit_reverse(ctx, 16, HalfWord_b);
		case 0x18: return st_circular(ctx, ST_16h);
		// ST.W
		case 0x04: return st_bit_reverse(ctx, 0, Word_b);
		case 0x14: return st_circular(ctx, ST_16x2);
		default: rz_warn_if_reached();
		}
		break;
	}
	case /*ST.A BOL*/ 0xb5: return st_base_long_offset(ctx, Word_b);
	case /*ST.A SC*/ 0xf8: return st_sc(ctx, Word_b, 'a');
	case /*ST.A SRO*/ 0xec: return st_sro(ctx, Word_b);
	case /*ST.A SSR*/ 0xf4: return st_ssr(ctx, Word_b);
	case /*ST.A SSR(post)*/ 0xe4: return st_ssr_post_incr(ctx, Word_b);
	case /*ST.A SSRO*/ 0xe8: return st_ssro(ctx, Word_b);

	case /*ST.B BOL*/ 0xe9: return st_base_long_offset(ctx, Byte_b);
	case /*ST.B SRO*/ 0x2c: return st_sro(ctx, Byte_b);
	case /*ST.B SSR*/ 0x34: return st_ssr(ctx, Byte_b);
	case /*ST.B SSR(post)*/ 0x24: return st_ssr_post_incr(ctx, Byte_b);
	case /*ST.B SSRO*/ 0x28: return st_ssro(ctx, Byte_b);

	case /*ST.H BOL*/ 0xf9: return st_base_long_offset(ctx, HalfWord_b);
	case /*ST.H SRO*/ 0xac: return st_sro(ctx, Word_b);
	case /*ST.H SSR*/ 0xb4: return st_ssr(ctx, Word_b);
	case /*ST.H SSR(post)*/ 0xa4: return st_ssr_post_incr(ctx, Word_b);
	case /*ST.H SSRO*/ 0xa8: return st_ssro(ctx, Word_b);

	case /*ST.W BOL*/ 0x59: return st_base_long_offset(ctx, Word_b);
	case /*ST.W SC*/ 0x78: return st_sc(ctx, Word_b, 'd');
	case /*ST.W SRO*/ 0x6c: return st_sro(ctx, Word_b);
	case /*ST.W SSR*/ 0x74: return st_ssr(ctx, Word_b);
	case /*ST.W SSR(post)*/ 0x64: return st_ssr_post_incr(ctx, Word_b);
	case /*ST.W SSRO*/ 0x68: return st_ssro(ctx, Word_b);

	case /*ST.T (ABSB)*/ 0xd5: return STORE(EA_off18(I(0)), LOGOR(LOGAND(LOAD(EA_off18(I(0))), U8(~(1 << I(1)))), U8(I(2) << I(1))));
	}
	return NULL;
}

static RzAnalysisLiftedILOp load_MST(const char *reg) {
	return STOREW(VARL("EA"), LOGOR(LOGAND(LOADW(Word_b, VARL("EA")), NEG(VARG_SUB(reg, 1))), LOGAND(VARG_SUB(reg, 0), VARG_SUB(reg, 1))));
}

static RzAnalysisLiftedILOp e_SWAP_W_ea(RzILOpPure *ea, const char *reg, RzILOpEffect *delay) {
	RzAnalysisLiftedILOp e = SEQ4(
		SETL("EA", ea),
		SETL("tmp", LOADW(Word_b, VARL("EA"))),
		STOREW(VARL("EA"), VARG(reg)),
		SETG(reg, VARL("tmp")));
	if (delay) {
		f_cons(e, delay);
	}
	return e;
}
static RzAnalysisLiftedILOp e_SWAP_W(const char *reg) {
	return SEQ3(
		SETL("tmp", LOADW(Word_b, VARL("EA"))),
		STOREW(VARL("EA"), VARG(reg)),
		SETG(reg, VARL("tmp")));
}

static RzILOpPure *f_SWAPMSK_W(const char *reg) {
	const char *a0 = REG_SUB(reg, 0);
	const char *a1 = REG_SUB(reg, 1);
	return LOGOR(LOGAND(VARL("tmp"), LOGNOT(VARG(a1))), LOGAND(VARG(a0), VARG(a1)));
}
static RzAnalysisLiftedILOp e_SWAPMSK_W(const char *reg) {
	const char *a0 = REG_SUB(reg, 0);
	return SEQ3(
		SETL("tmp", LOADW(Word_b, VARL("EA"))),
		STOREW(VARL("EA"), f_SWAPMSK_W(reg)),
		SETG(a0, VARL("tmp")));
}
static RzAnalysisLiftedILOp e_SWAPMSK_W_ea(RzILOpPure *ea, const char *reg, RzILOpEffect *delay) {
	if (delay) {
		return SEQ2(
			SETL("EA", ea),
			f_cons_(e_SWAPMSK_W(reg), delay));
	} else {
		return SEQ2(
			SETL("EA", ea),
			e_SWAPMSK_W(reg));
	}
}

static RzILOpPure *LIKE(RzILOpPure *x, ut32 y) {
	rz_warn_if_fail(x->code == RZ_IL_OP_BITV);
	return SN(x->op.bitv.value->len, y);
}

static RzILOpPure *f_ABS(RzILOpPure *a, unsigned n, unsigned l, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)) {
	RzILOpPure *val = NULL;
	if (n || l) {
		a = SIGNED(l, BITS32(a, n, l));
	}
	l = l ? l : 32;
	val = LET("tmp", a,
		ITE(SGE(VARLP("tmp"), SN(l, 0)), VARLP("tmp"), SUB(SN(l, 0), VARLP("tmp"))));
	val = f ? f(val, UN(l, l)) : val;
	return val;
}
static RzILOpPure *f_ABSDIF(RzILOpPure *a, RzILOpPure *b, unsigned n, unsigned l, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)) {
	RzILOpPure *val = NULL;
	if (n || l) {
		a = SIGNED(l, BITS32(a, n, l));
		b = SIGNED(l, BITS32(b, n, l));
	}
	val = LET("a", a,
		LET("b", b,
			ITE(SGT(VARLP("a"), VARLP("b")), SUB(VARLP("a"), VARLP("b")), SUB(VARLP("b"), VARLP("a")))));
	l = l ? l : 32;
	val = f ? f(val, UN(l, l)) : val;
	return val;
}

static RzILOpPure *packed_4byte(RzILOpPure *a, RzILOpPure *b, RzILOpPure *c, RzILOpPure *d) {
	return LOGOR(UNSIGNED(32, SHL0(a, 8 * 3)), LOGOR(UNSIGNED(32, SHL0(b, 8 * 2)), LOGOR(UNSIGNED(32, SHL0(c, 8 * 1)), UNSIGNED(32, d))));
}
static RzILOpPure *packed_2halfword(RzILOpPure *a, RzILOpPure *b) {
	return LOGOR(UNSIGNED(32, SHL0(a, 16 * 1)), UNSIGNED(32, b));
}
static RzILOpPure *packed_2word(
	RzILOpPure *a, RzILOpPure *b) {
	return LOGOR(UNSIGNED(64, SHL0(a, 32)), b ? UNSIGNED(64, b) : U64(0));
}
static RzILOpPure *ssov(RzILOpPure *x, RzILOpPure *y) {
	return LET(
		"x", x,
		LET("y", y,
			LET("max_pos", SUB(SHIFTL0(LIKE(y, 1), SUB(VARLP("y"), LIKE(y, 1))), LIKE(y, 1)),
				LET("max_neg", NEG(SHIFTL0(LIKE(y, 1), SUB(VARLP("y"), LIKE(y, 1)))),
					ITE(SGT(VARLP("x"), VARLP("max_pos")), VARLP("max_pos"),
						ITE(SLT(VARLP("x"), VARLP("max_neg")), VARLP("max_neg"), VARLP("x")))))));
}
static RzILOpPure *ssov_n(RzILOpPure *x, unsigned n) {
	return ssov(x, UN(n, n));
}

#define H16_32(x) UNSIGNED(16, BITS32((x), 16, 16))

static RzILOpPure *append_h16_32(
	RzILOpPure *a, RzILOpPure *b) {
	return APPEND(H16_32(a), b ? H16_32(b) : U16(0));
}
static RzILOpPure *append_h16_32_ssov(
	RzILOpPure *a, RzILOpPure *b) {
	return LET("_a", H16_32(ssov(a, U32(32))),
		LET("_b", H16_32(b ? ssov(b, U32(32)) : U32(0)),
			APPEND(VARLP("_a"), VARLP("_b"))));
}
static RzILOpPure *append_ssov(
	RzILOpPure *a, RzILOpPure *b) {
	return LET("_a", ssov(a, U32(32)),
		LET("_b", b ? ssov(b, U32(32)) : U32(0),
			APPEND(VARLP("_a"), VARLP("_b"))));
}

static RzILOpEffect *e_ABS(const char *r, RzILOpPure *a, unsigned n, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)) {
	RzILOpPure *val = NULL;
	if (n == Word_b) {
		val = f_ABS(a, 0, 0, f);
	} else if (n == HalfWord_b) {
		RzILOpPure *h1 = f_ABS(a, 16, 16, f);
		RzILOpPure *h0 = f_ABS(DUP(a), 0, 16, f);
		val = packed_2halfword(h1, h0);
	} else if (n == Byte_b) {
		RzILOpPure *b3 = f_ABS(a, 24, 8, f);
		RzILOpPure *b2 = f_ABS(DUP(a), 16, 8, f);
		RzILOpPure *b1 = f_ABS(DUP(a), 8, 8, f);
		RzILOpPure *b0 = f_ABS(DUP(a), 0, 8, f);
		val = packed_4byte(b3, b2, b1, b0);
	}
	return SETG(r, val);
}
static RzILOpEffect *e_ABSDIF(const char *r, RzILOpPure *a, RzILOpPure *b, unsigned n, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)) {
	RzILOpPure *val = NULL;
	if (n == Word_b) {
		val = f_ABSDIF(a, b, 0, 0, f);
	} else if (n == HalfWord_b) {
		RzILOpPure *h1 = f_ABSDIF(a, b, 16, 16, f);
		RzILOpPure *h0 = f_ABSDIF(DUP(a), DUP(b), 0, 16, f);
		val = packed_2halfword(h1, h0);
	} else if (n == Byte_b) {
		RzILOpPure *b3 = f_ABSDIF(a, b, 24, 8, f);
		RzILOpPure *b2 = f_ABSDIF(DUP(a), DUP(b), 16, 8, f);
		RzILOpPure *b1 = f_ABSDIF(DUP(a), DUP(b), 8, 8, f);
		RzILOpPure *b0 = f_ABSDIF(DUP(a), DUP(b), 0, 8, f);
		val = packed_4byte(b3, b2, b1, b0);
	}
	return SETG(r, val);
}

static RzILOpPure *f_ADDU(RzILOpPure *a, RzILOpPure *b, unsigned n, unsigned l, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)) {
	RzILOpPure *val = NULL;
	if (n || l) {
		a = UNSIGNED(l, BITS32(a, n, l));
		b = UNSIGNED(l, BITS32(b, n, l));
	}
	l = l ? l : 32;
	val = ADD(a, b);
	val = f ? f(val, UN(l, l)) : val;
	return val;
}
static RzILOpPure *f_ADDC(RzILOpPure *a, RzILOpPure *b, RzILOpPure *c, unsigned n, unsigned l, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)) {
	RzILOpPure *val = NULL;
	if (n || l) {
		a = SIGNED(l, BITS32(a, n, l));
		b = SIGNED(l, BITS32(b, n, l));
	}
	l = l ? l : 32;
	val = ADD(a, ADD(b, c));
	val = f ? f(val, UN(l, l)) : val;
	return val;
}
static RzILOpPure *carry(RzILOpPure *a, RzILOpPure *b, RzILOpPure *c) {
	RzILOpPure *val = ADD(ADD(a, b), c);
	return BITS32(val, 0, 1);
}

static RzAnalysisLiftedILOp f_overflow32(
	RzAnalysisLiftedILOp e) {
	f_cons(e, SETL("overflow", OR(UGT(VARL("result"), U32(0x7fffffff)), SLT(VARL("result"), S32(-0x80000000)))));
	f_cons(e, SETL("advanced_overflow", XOR(BIT32(VARL("result"), 31), BIT32(VARL("result"), 30))));
	f_cons(e, set_PSW_V(BOOL_TO_BV32(VARL("overflow"))));
	f_cons(e, set_PSW_AV(BOOL_TO_BV32(VARL("advanced_overflow"))));
	f_cons(e, BRANCH(VARL("overflow"), set_PSW_SV(U32(1)), NOP()));
	f_cons(e, BRANCH(VARL("advanced_overflow"), set_PSW_SAV(U32(1)), NOP()));
	return e;
}
static RzAnalysisLiftedILOp f_overflow32_carry(
	RzAnalysisLiftedILOp e) {
	f_cons(e, set_PSW_C(BOOL_TO_BV32(VARL("carry_out"))));
	return f_overflow32(e);
}
static RzAnalysisLiftedILOp f_overflow64(
	RzAnalysisLiftedILOp e) {
	f_cons(e, SETL("overflow", OR(UGT(VARL("result"), U64(0x7fffffffffffffff)), SLT(VARL("result"), S64(-0x8000000000000000)))));
	f_cons(e, SETL("advanced_overflow", XOR(BIT64(VARL("result"), 63), BIT64(VARL("result"), 62))));
	f_cons(e, set_PSW_V(BOOL_TO_BV32(VARL("overflow"))));
	f_cons(e, set_PSW_AV(BOOL_TO_BV32(VARL("advanced_overflow"))));
	f_cons(e, BRANCH(VARL("overflow"), set_PSW_SV(U32(1)), NOP()));
	return f_cons_(e, BRANCH(VARL("advanced_overflow"), set_PSW_SAV(U32(1)), NOP()));
}
static RzAnalysisLiftedILOp f_overflow32x2(
	RzAnalysisLiftedILOp e, const char *n1, const char *n0) {
	f_cons(e, SETL("ov1", OR(UGT(VARL(n1), U32(0x7FFFFFFF)), SLT(VARL(n1), S32(-0x80000000)))));
	f_cons(e, SETL("ov0", OR(UGT(VARL(n0), U32(0x7FFFFFFF)), SLT(VARL(n0), S32(-0x80000000)))));
	f_cons(e, SETL("overflow", OR(VARL("ov1"), VARL("ov0"))));
	f_cons(e, SETL("aov1", XOR(BIT32(VARL(n1), 31), BIT32(VARL(n1), 30))));
	f_cons(e, SETL("aov0", XOR(BIT32(VARL(n0), 31), BIT32(VARL(n0), 30))));
	f_cons(e, SETL("advanced_overflow", OR(VARL("aov1"), VARL("aov0"))));
	f_cons(e, set_PSW_V(BOOL_TO_BV32(VARL("overflow"))));
	f_cons(e, set_PSW_AV(BOOL_TO_BV32(VARL("advanced_overflow"))));
	f_cons(e, BRANCH(VARL("overflow"), set_PSW_SV(U32(1)), NOP()));
	return f_cons_(e, BRANCH(VARL("advanced_overflow"), set_PSW_SAV(U32(1)), NOP()));
}
static RzAnalysisLiftedILOp f_overflow16x2(
	RzAnalysisLiftedILOp e, const char *n1, const char *n0) {
	f_cons(e, SETL("ov1", OR(UGT(VARL(n1), S16(0x7FFF)), SLT(VARL(n1), S16(-0x8000)))));
	f_cons(e, SETL("ov0", OR(UGT(VARL(n0), S16(0x7FFF)), SLT(VARL(n0), S16(-0x8000)))));
	f_cons(e, SETL("overflow", OR(VARL("ov1"), VARL("ov0"))));
	f_cons(e, SETL("aov1", XOR(BIT16(VARL(n1), 15), BIT16(VARL(n1), 14))));
	f_cons(e, SETL("aov0", XOR(BIT16(VARL(n0), 15), BIT16(VARL(n0), 14))));
	f_cons(e, SETL("advanced_overflow", OR(VARL("aov1"), VARL("aov0"))));
	f_cons(e, set_PSW_V(BOOL_TO_BV32(VARL("overflow"))));
	f_cons(e, set_PSW_AV(BOOL_TO_BV32(VARL("advanced_overflow"))));
	f_cons(e, BRANCH(VARL("overflow"), set_PSW_SV(U32(1)), NOP()));
	return f_cons_(e, BRANCH(VARL("advanced_overflow"), set_PSW_SAV(U32(1)), NOP()));
}
static RzAnalysisLiftedILOp f_overflow8x4(
	RzAnalysisLiftedILOp e, const char *n3, const char *n2, const char *n1, const char *n0) {
	f_cons(e, SETL("ov3", OR(UGT(VARL(n3), U8(0x7F)), SLT(VARL(n3), S8(-0x80)))));
	f_cons(e, SETL("ov2", OR(UGT(VARL(n2), U8(0x7F)), SLT(VARL(n2), S8(-0x80)))));
	f_cons(e, SETL("ov1", OR(UGT(VARL(n1), U8(0x7F)), SLT(VARL(n1), S8(-0x80)))));
	f_cons(e, SETL("ov0", OR(UGT(VARL(n0), U8(0x7F)), SLT(VARL(n0), S8(-0x80)))));
	f_cons(e, SETL("overflow", OR(OR(VARL("ov1"), VARL("ov0")), OR(VARL("ov3"), VARL("ov2")))));
	f_cons(e, SETL("aov3", XOR(BIT8(VARL(n3), 7), BIT8(VARL(n3), 6))));
	f_cons(e, SETL("aov2", XOR(BIT8(VARL(n2), 7), BIT8(VARL(n2), 6))));
	f_cons(e, SETL("aov1", XOR(BIT8(VARL(n1), 7), BIT8(VARL(n1), 6))));
	f_cons(e, SETL("aov0", XOR(BIT8(VARL(n0), 7), BIT8(VARL(n0), 6))));
	f_cons(e, SETL("advanced_overflow", OR(OR(VARL("aov1"), VARL("aov0")), OR(VARL("aov3"), VARL("aov2")))));
	f_cons(e, set_PSW_V(BOOL_TO_BV32(VARL("overflow"))));
	f_cons(e, set_PSW_AV(BOOL_TO_BV32(VARL("advanced_overflow"))));
	f_cons(e, BRANCH(VARL("overflow"), set_PSW_SV(U32(1)), NOP()));
	return f_cons_(e, BRANCH(VARL("advanced_overflow"), set_PSW_SAV(U32(1)), NOP()));
}

static RzILOpEffect *packed_op2_(
	const char *r, RzILOpPure *a, RzILOpPure *b, unsigned n,
	RzILOpPure *(*op)(RzILOpPure *a, RzILOpPure *b, unsigned n, unsigned l, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)),
	RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y),
	bool status_overflow) {

	RzILOpEffect *e = NULL;
	if (n == Word_b) {
		e = SEQ2(SETL("result", op(a, b, 0, 0, f)),
			SETG(r, VARL("result")));
		if (status_overflow) {
			return f_overflow32(e);
		}
	} else if (n == HalfWord_b) {
		e = SEQ4(SETL("result_hw1", op(a, b, 16, 16, f)),
			SETL("result_hw0", op(DUP(a), DUP(b), 0, 16, f)),
			SETL("result", packed_2halfword(VARL("result_hw1"), VARL("result_hw0"))),
			SETG(r, VARL("result")));
		if (status_overflow) {
			return f_overflow16x2(e, "result_hw1", "result_hw0");
		}
	} else if (n == Byte_b) {
		e = SEQ6(SETL("result_byte3", op(a, b, 24, 8, f)),
			SETL("result_byte2", op(DUP(a), DUP(b), 16, 8, f)),
			SETL("result_byte1", op(DUP(a), DUP(b), 8, 8, f)),
			SETL("result_byte0", op(DUP(a), DUP(b), 0, 8, f)),
			SETL("result", packed_4byte(VARL("result_byte3"), VARL("result_byte2"), VARL("result_byte1"), VARL("result_byte0"))),
			SETG(r, VARL("result")));
		if (status_overflow) {
			return f_overflow8x4(e, "result_byte3", "result_byte2", "result_byte1", "result_byte0");
		}
	}
	return e;
}

static RzILOpEffect *packed_op2(
	const char *r, RzILOpPure *a, RzILOpPure *b, unsigned n,
	RzILOpPure *(*op)(RzILOpPure *a, RzILOpPure *b, unsigned n, unsigned l, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)),
	RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)) {
	return packed_op2_(r, a, b, n, op, f, false);
}
static RzILOpEffect *packed_op2_ov(
	const char *r, RzILOpPure *a, RzILOpPure *b, unsigned n,
	RzILOpPure *(*op)(RzILOpPure *a, RzILOpPure *b, unsigned n, unsigned l, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)),
	RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)) {
	return packed_op2_(r, a, b, n, op, f, true);
}

typedef RzILOpPure *(*FUNC_OP2)(RzILOpPure *x, RzILOpPure *y);
typedef RzILOpPure *(*FUNC_OP3)(RzILOpPure *x, RzILOpPure *y, RzILOpPure *z);
#define ONES32(l) U32((1ULL << l) - 1ULL)
#define ONES64(l) U64((1ULL << l) - 1ULL)
static RzILOpPure *f_op2_raw(
	RzILOpPure *a, RzILOpPure *b, unsigned i, unsigned l,
	FUNC_OP2 op) {
	if (i || (l && l != 32)) {
		a = UNSIGNED(l, BITS32(a, i, l));
		b = UNSIGNED(l, BITS32(b, i, l));
	}
	return op(a, b);
}
static RzILOpPure *f_op2_cmp(
	RzILOpPure *a, RzILOpPure *b, unsigned i, unsigned l,
	FUNC_OP2 op) {
	return ITE(f_op2_raw(a, b, i, l, op), ONES32(l), U32(0));
}
static RzILOpEffect *packed_op2_cmp(
	const char *r, RzILOpPure *a, RzILOpPure *b, unsigned n,
	FUNC_OP2 op) {
	return packed_op2(r, a, b, n, f_op2_cmp, op);
}

static RzILOpPure *f_op2_minmax(
	RzILOpPure *a, RzILOpPure *b, unsigned i, unsigned l,
	FUNC_OP2 op) {
	if (i || (l && l != 32)) {
		a = BITS32(a, i, l);
		b = BITS32(b, i, l);
	}
	return LET("a", a, LET("b", b, ITE(op(VARLP("a"), VARLP("b")), VARLP("a"), VARLP("b"))));
}
static RzILOpEffect *packed_op2_minmax(
	const char *r, RzILOpPure *a, RzILOpPure *b, unsigned n,
	FUNC_OP2 op) {
	return packed_op2(r, a, b, n, f_op2_minmax, op);
}

static RzILOpEffect *packed_op2_raw(
	const char *r, RzILOpPure *a, RzILOpPure *b, unsigned n,
	RzILOpPure *(*op)(RzILOpPure *x, RzILOpPure *y)) {
	return packed_op2(r, a, b, n, f_op2_raw, op);
}

static RzILOpEffect *packed_op2_s(
	const char *r, RzILOpPure *a, RzILOpPure *b, unsigned n,
	RzILOpPure *(*op)(RzILOpPure *x, RzILOpPure *y),
	RzILOpPure *(*fini)(RzILOpPure *x, RzILOpPure *y),
	bool ov) {

	RzILOpEffect *e = NULL;
	if (n == Word_b || n == DoubleWord_b) {
		e = SEQ2(SETL("result", !fini ? op(a, b) : fini(op(a, b), UN(n, n))),
			SETG(r, VARL("result")));
		if (ov) {
			if (n == Word_b) {
				return f_overflow32(e);
			} else {
				return f_overflow64(e);
			}
		}
	} else if (n == HalfWord_b) {
		e = SEQ4(SETL("result_hw1", !fini ? f_op2_raw(a, b, 16, 16, op) : fini(f_op2_raw(a, b, 16, 16, op), U16(16))),
			SETL("result_hw0", !fini ? f_op2_raw(DUP(a), DUP(b), 0, 16, op) : fini(f_op2_raw(DUP(a), DUP(b), 0, 16, op), U16(16))),
			SETL("result", packed_2halfword(VARL("result_hw1"), VARL("result_hw0"))),
			SETG(r, VARL("result")));
		if (ov) {
			return f_overflow16x2(e, "result_hw1", "result_hw0");
		}
	} else if (n == Byte_b) {
		e = SEQ6(SETL("result_byte3", !fini ? f_op2_raw(a, b, 24, 8, op) : fini(f_op2_raw(a, b, 24, 8, op), U8(8))),
			SETL("result_byte2", !fini ? f_op2_raw(DUP(a), DUP(b), 16, 8, op) : fini(f_op2_raw(DUP(a), DUP(b), 16, 8, op), U8(8))),
			SETL("result_byte1", !fini ? f_op2_raw(DUP(a), DUP(b), 8, 8, op) : fini(f_op2_raw(DUP(a), DUP(b), 8, 8, op), U8(8))),
			SETL("result_byte0", !fini ? f_op2_raw(DUP(a), DUP(b), 0, 8, op) : fini(f_op2_raw(DUP(a), DUP(b), 0, 8, op), U8(8))),
			SETL("result", packed_4byte(VARL("result_byte3"), VARL("result_byte2"), VARL("result_byte1"), VARL("result_byte0"))),
			SETG(r, VARL("result")));
		if (ov) {
			return f_overflow8x4(e, "result_byte3", "result_byte2", "result_byte1", "result_byte0");
		}
	}
	return e;
}

static RzILOpEffect *e_op2_cond(
	const char *r, RzILOpPure *a, RzILOpPure *b, RzILOpPure *cond,
	RzILOpPure *(*op)(RzILOpPure *x, RzILOpPure *y)) {

	return SEQ4(
		SETL("condition", cond),
		SETL("result", ITE(VARL("condition"), op(a, b), DUP(a))),
		SETG(r, VARL("result")),
		status_conditional(VARL("condition")));
}

static RzILOpEffect *packed_op2_sov(
	const char *r, RzILOpPure *a, RzILOpPure *b, unsigned n,
	RzILOpPure *(*op)(RzILOpPure *x, RzILOpPure *y),
	RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)) {
	return packed_op2_s(r, a, b, n, op, f, true);
}

static RzILOpEffect *packed_op3_(
	const char *r, RzILOpPure *a, RzILOpPure *b, RzILOpPure *c, unsigned n,
	RzILOpPure *(*op)(RzILOpPure *a, RzILOpPure *b, RzILOpPure *c, unsigned n, unsigned l, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)),
	RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y), bool ov) {

	RzILOpEffect *e = NULL;
	if (n == Word_b) {
		e = SEQ2(SETL("result", op(a, b, c, 0, 0, f)),
			SETG(r, VARL("result")));
		if (ov) {
			return f_overflow32(e);
		}
	} else if (n == HalfWord_b) {
		e = SEQ4(SETL("result_hw1", op(a, b, c, 16, 16, f)),
			SETL("result_hw0", op(DUP(a), DUP(b), DUP(c), 0, 16, f)),
			SETL("result", packed_2halfword(VARL("result_hw1"), VARL("result_hw0"))),
			SETG(r, VARL("result")));
		if (ov) {
			return f_overflow16x2(e, "result_hw1", "result_hw0");
		}
	} else if (n == Byte_b) {
		e = SEQ6(SETL("result_byte3", op(a, b, c, 24, 8, f)),
			SETL("result_byte2", op(DUP(a), DUP(b), DUP(c), 16, 8, f)),
			SETL("result_byte1", op(DUP(a), DUP(b), DUP(c), 8, 8, f)),
			SETL("result_byte0", op(DUP(a), DUP(b), DUP(c), 0, 8, f)),
			SETL("result", packed_4byte(VARL("result_byte3"), VARL("result_byte2"), VARL("result_byte1"), VARL("result_byte0"))),
			SETG(r, VARL("result")));
		if (ov) {
			return f_overflow8x4(e, "result_byte3", "result_byte2", "result_byte1", "result_byte0");
		}
	}
	return e;
}
static RzILOpEffect *packed_op3(
	const char *r, RzILOpPure *a, RzILOpPure *b, RzILOpPure *c, unsigned n,
	RzILOpPure *(*op)(RzILOpPure *a, RzILOpPure *b, RzILOpPure *c, unsigned n, unsigned l, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)),
	RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)) {
	return packed_op3_(r, a, b, c, n, op, f, false);
}
static RzILOpEffect *packed_op3_ov(
	const char *r, RzILOpPure *a, RzILOpPure *b, RzILOpPure *c, unsigned n,
	RzILOpPure *(*op)(RzILOpPure *a, RzILOpPure *b, RzILOpPure *c, unsigned n, unsigned l, RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)),
	RzILOpPure *(*f)(RzILOpPure *x, RzILOpPure *y)) {
	return packed_op3_(r, a, b, c, n, op, f, true);
}

static RzILOpPure *suov(RzILOpPure *x, RzILOpPure *y) {
	return LET(
		"x", x,
		LET("y", y,
			LET("max_pos", SUB(SHIFTL0(LIKE(y, 1), VARLP("y")), LIKE(y, 1)),
				ITE(SGT(VARLP("x"), VARLP("max_pos")), VARLP("max_pos"),
					ITE(SLT(VARLP("x"), LIKE(y, 0)), LIKE(y, 0), VARLP("x"))))));
}
static RzILOpPure *suov_n(RzILOpPure *x, unsigned n) {
	return suov(x, UN(n, n));
}

static RzILOpPure *EA_ret() {
	return LET("_pcxi_pcxs", PCXI_PCXS(),
		LET("_pcxi_pcxo", PCXI_PCXO(),
			LOGOR(SHL0(VARLP("_pcxi_pcxo"), 6), SHL0(VARLP("_pcxi_pcxs"), 28))));
}

static RzAnalysisLiftedILOp lift_ret(const RzAsmTriCoreContext *ctx) {
	RzILOpEffect *e4 = SETL("PC", LOGAND(VARG("a11"), U32(~0U - 1)));
	RzILOpEffect *e5 = SETL("EA", EA_ret());
	RzILOpEffect *e61 = SETL("new_PCXI", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 15))));
	RzILOpEffect *e62 = SETL("new_PSW", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 14))));
	RzILOpEffect *e63 = SETG_MB("a10", 2, LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 13))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 12))));
	RzILOpEffect *e64 = SETG_MB("d8", 4, LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 11))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 10))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 9))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 8))));
	RzILOpEffect *e65 = SETG_MB("a12", 4, LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 7))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 6))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 5))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 4))));
	RzILOpEffect *e66 = SETG_MB("d12", 4, LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 3))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 2))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 1))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 0))));
	RzILOpEffect *e7 = STOREW(VARL("EA"), VARG("FCX"));
	RzILOpEffect *e8 = SETG("FCX", BITS32_U(VARG("FCX"), 0, 20, BITS32(VARG("PCXI"), 0, 20)));
	RzILOpEffect *e9 = SETG("PCXI", VARL("new_PCXI"));
	RzILOpEffect *e10 = SETG("PSW", LOGOR(BITS32(VARL("new_PSW"), 26, 6), LOGOR(BITS32(VARL("new_PSW"), 0, 24), BITS32(VARG("PSW"), 24, 2))));
	RzILOpEffect *e11 = JMP(VARL("PC"));
	RzILOpEffect *e = SEQN(13, e4, e5, e61, e62, e63, e64, e65, e66, e7, e8, e9, e10, e11);
	return SEQ4(
		BRANCH(NON_ZERO(PSW_CDE()), cdc_decrement(trap(CDU)), NOP()),
		BRANCH(IS_ZERO(BITS32(VARG("PCXI"), 0, 20)), trap(CSU), NOP()),
		BRANCH(IS_ZERO(PCXI_UL(ctx->mode)), trap(CTYP), NOP()),
		e);
}

static RzAnalysisLiftedILOp lift_rfe(const RzAsmTriCoreContext *ctx) {
	RzILOpEffect *e2 = SETL("PC", LOGAND(VARG("a11"), U32(~0U - 1)));
	RzILOpEffect *e3 = set_ICR_IE(PCXI_PIE(ctx->mode));
	RzILOpEffect *e4 = set_ICR_CCPN(PCXI_PCPN(ctx->mode));
	RzILOpEffect *e5 = SETL("EA", EA_ret());
	RzILOpEffect *e61 = SETL("new_PCXI", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 15))));
	RzILOpEffect *e62 = SETG("PSW", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 14))));
	RzILOpEffect *e63 = SETG_MB("a10", 2, LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 13))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 12))));
	RzILOpEffect *e64 = SETG_MB("d8", 4, LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 11))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 10))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 9))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 8))));
	RzILOpEffect *e65 = SETG_MB("a12", 4, LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 7))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 6))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 5))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 4))));
	RzILOpEffect *e66 = SETG_MB("d12", 4, LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 3))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 2))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 1))), LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 0))));
	RzILOpEffect *e7 = STOREW(VARL("EA"), VARG("FCX"));
	RzILOpEffect *e8 = SETG("FCX", BITS32_U(VARG("FCX"), 0, 20, BITS32(VARG("PCXI"), 0, 20)));
	RzILOpEffect *e9 = SETG("PCXI", VARL("new_PCXI"));
	RzILOpEffect *e10 = JMP(VARL("PC"));
	RzILOpEffect *e = SEQN(14, e2, e3, e4, e5, e61, e62, e63, e64, e65, e66, e7, e8, e9, e10);
	return SEQ4(
		BRANCH(IS_ZERO(BITS32(VARG("PCXI"), 0, 20)), trap(CSU), NOP()),
		BRANCH(IS_ZERO(PCXI_UL(ctx->mode)), trap(CTYP), NOP()),
		BRANCH(AND(INV(cdc_zero()), NON_ZERO(PSW_CDE())), trap(NEST), NOP()),
		e);
}

static RzAnalysisLiftedILOp lift_rfm(const RzAsmTriCoreContext *ctx) {
	RzILOpEffect *e = SEQ9(
		SETL("PC", LOGAND(VARG("a11"), U32(~0U - 1))),
		set_ICR_IE(PCXI_PIE(ctx->mode)),
		set_ICR_CCPN(PCXI_PCPN(ctx->mode)),
		SETL("EA", VARG("DCX")),
		SETG("PCXI", LOADW(Word_b, ADD(VARL("EA"), U32(3)))),
		SETG("PSW", LOADW(Word_b, ADD(VARL("EA"), U32(2)))),
		SETG("a10", LOADW(Word_b, ADD(VARL("EA"), U32(1)))),
		SETG("a11", LOADW(Word_b, ADD(VARL("EA"), U32(0)))),
		set_DBGTCR_DTA(U32(0)));
	return SEQ2(
		BRANCH(NE(PSW_IO(), U32(0b10)), trap(PRIV), NOP()),
		BRANCH(NON_ZERO(DBGSR_DE()), e, NOP()));
}

static RzAnalysisLiftedILOp lift_add(RzAsmTriCoreContext *ctx) {
	switch (OPC1) {
	case 0x8b: {
		switch (extract32(ctx->word, 21, 7)) {
		case 0x00: return packed_op2_sov(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), Word_b, rz_il_op_new_add, NULL);
		case 0x05: return SEQ2(
			packed_op3_ov(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), PSW_C(), Word_b, f_ADDC, NULL),
			set_PSW_C(carry(VARG(R(1)), sign_ext32_bv(I(2), 9), PSW_C())));
		case 0x02: return packed_op2_sov(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), Word_b, rz_il_op_new_add, ssov);
		case /*ADDS.U RC*/ 0x03: return packed_op2_sov(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), Word_b, rz_il_op_new_add, suov);
		case /*ADDX RC*/ 0x04: return SEQ2(
			packed_op3_ov(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), S32(0), Word_b, f_ADDC, NULL),
			set_PSW_C(carry(VARG(R(1)), sign_ext32_bv(I(2), 9), S32(0))));
		default: break;
		}
		break;
	}
	case 0x0b: {
		switch (extract32(ctx->word, 20, 8)) {
		case 0x00: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_add, NULL);
		case 0x40: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), Byte_b, rz_il_op_new_add, NULL);
		case 0x60: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_add, NULL);
		case 0x05: return SEQ2(
			packed_op3(R(0), VARG(R(1)), VARG(R(2)), PSW_C(), Word_b, f_ADDC, NULL),
			set_PSW_C(carry(VARG(R(1)), VARG(R(2)), PSW_C())));
		case /*ADDS RR*/ 0x02: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_add, ssov);
		case /*ADDS.U RR*/ 0x03: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_add, suov);
		case /*ADDS.H RR*/ 0x62: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_add, suov);
		case /*ADDS.HU RR*/ 0x63: return packed_op2_ov(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, f_ADDU, suov);
		case /*ADDX RR*/ 0x04: return SEQ2(
			packed_op3(R(0), VARG(R(1)), VARG(R(2)), S32(0), Word_b, f_ADDC, NULL),
			set_PSW_C(carry(VARG(R(1)), VARG(R(2)), S32(0))));
		default: break;
		}
		break;
	}
	case 0xc2: return packed_op2_sov(R(0), VARG(R(0)), sign_ext32_bv(I(1), 4), Word_b, rz_il_op_new_add, NULL);
	case 0x92: return packed_op2_sov(R(0), VARG("d15"), sign_ext32_bv(I(1), 4), Word_b, rz_il_op_new_add, NULL);
	case 0x9a: return packed_op2_sov("d15", VARG(R(0)), sign_ext32_bv(I(1), 4), Word_b, rz_il_op_new_add, NULL);
	case 0x42: return packed_op2_sov(R(0), VARG(R(0)), VARG(R(1)), Word_b, rz_il_op_new_add, NULL);
	case 0x12: return packed_op2_sov(R(0), VARG("d15"), VARG(R(1)), Word_b, rz_il_op_new_add, NULL);
	case 0x1a: return packed_op2_sov("d15", VARG(R(0)), VARG(R(1)), Word_b, rz_il_op_new_add, NULL);
	case 0x22: return packed_op2_sov(R(0), VARG(R(0)), VARG(R(1)), Word_b, rz_il_op_new_add, ssov);
	default: break;
	}
	rz_warn_if_reached();
	return NULL;
}

static RzAnalysisLiftedILOp status_conditional(RzILOpPure *cnd) {
	return SEQ6(
		SETL("overflow", OR(SGT(VARL("result"), S32(0x7FFFFFFF)), SLT(VARL("result"), S32(-80000000)))),
		BRANCH(cnd, set_PSW_V(BOOL_TO_BV32(VARL("overflow"))), NOP()),
		BRANCH(AND(DUP(cnd), VARL("overflow")), set_PSW_SV(U32(1)), NOP()),
		SETL("advanced_overflow", XOR(NON_ZERO(BITS32(VARL("result"), 30, 1)), NON_ZERO(BITS32(VARL("result"), 31, 1)))),
		BRANCH(DUP(cnd), set_PSW_AV(BOOL_TO_BV32(VARL("advanced_overflow"))), NOP()),
		BRANCH(AND(DUP(cnd), VARL("advanced_overflow")), set_PSW_SAV(U32(1)), NOP()));
}

static RzAnalysisLiftedILOp e_cadd(const char *dst, RzILOpPure *cnd, RzILOpPure *a, RzILOpPure *b) {
	return SEQ4(
		SETL("condition", cnd),
		SETL("result", ITE(VARL("condition"), ADD(a, b), DUP(a))),
		SETG(dst, VARL("result")),
		status_conditional(VARL("condition")));
}

static RzAnalysisLiftedILOp lift_cadd(RzAsmTriCoreContext *ctx) {
	switch (OPC1) {
	case /*RCR*/ 0xab: {
		switch (extract32(ctx->word, 21, 3)) {
		case /*CADD (RCR)*/ 0x00: return e_cadd(R(0), NON_ZERO(VARG(R(1))), VARG(R(2)), sign_ext32_bv(I(3), 9));
		case /*CADDN (RCR)*/ 0x01: return e_cadd(R(0), IS_ZERO(VARG(R(1))), VARG(R(2)), sign_ext32_bv(I(3), 9));
		default: break;
		}
		break;
	}
	case /*RRR*/ 0x2b: {
		switch (extract32(ctx->word, 21, 3)) {
		case /*CADD (RRR)*/ 0x00: return e_cadd(R(0), NON_ZERO(VARG(R(1))), VARG(R(2)), VARG(R(3)));
		case /*CADDN (RRR)*/ 0x01: return e_cadd(R(0), IS_ZERO(VARG(R(1))), VARG(R(2)), VARG(R(3)));
		default: break;
		}
		break;
	}
	case /*CADD (SRC)*/ 0x8a: return e_cadd(R(0), NON_ZERO(VARG("d15")), VARG(R(0)), sign_ext32_bv(I(1), 4));
	case /*CADDN (SRC)*/ 0xca: return e_cadd(R(0), IS_ZERO(VARG("d15")), VARG(R(0)), sign_ext32_bv(I(1), 4));
	default: break;
	}
	rz_warn_if_reached();
	return NULL;
}

static RzILOpEffect *e_eqany(
	const char *r, RzILOpPure *a, RzILOpPure *b, unsigned n) {
	RzILOpPure *val = NULL;
	if (n == Word_b) {
		val = EQ(a, b);
	} else if (n == HalfWord_b) {
		RzILOpPure *h1 = f_op2_raw(a, b, 16, 16, rz_il_op_new_eq);
		RzILOpPure *h0 = f_op2_raw(DUP(a), DUP(b), 0, 16, rz_il_op_new_eq);
		val = BOOL_TO_BV32(OR(h1, h0));
	} else if (n == Byte_b) {
		RzILOpPure *b3 = f_op2_raw(a, b, 24, 8, rz_il_op_new_eq);
		RzILOpPure *b2 = f_op2_raw(DUP(a), DUP(b), 16, 8, rz_il_op_new_eq);
		RzILOpPure *b1 = f_op2_raw(DUP(a), DUP(b), 8, 8, rz_il_op_new_eq);
		RzILOpPure *b0 = f_op2_raw(DUP(a), DUP(b), 0, 8, rz_il_op_new_eq);
		val = BOOL_TO_BV32(OR(OR(b3, b2), OR(b1, b0)));
	}
	return SETG(r, val);
}

static RzILOpEffect *lift_pack(RzAsmTriCoreContext *ctx) {
	RzILOpEffect *_1 = SETL("int_exp", VARG(REG_SUB(R(1), 1)));
	RzILOpEffect *_2 = SETL("int_mant", VARG(REG_SUB(R(1), 0)));
	RzILOpEffect *_3 = SETL("flag_rnd", AND(BIT32(VARL("int_mant"), 7), OR(BIT32(VARL("int_mant"), 8), OR(NON_ZERO(BITS32(VARL("int_mant"), 0, 7)), NON_ZERO(PSW_C())))));
	RzILOpEffect *_4 = SETL("fp_exp",
		ITE(OR(
			    AND(IS_ZERO(BITS32(VARL("int_mant"), 31, 1)), EQ(S32(255), VARL("int_exp"))),
			    AND(NON_ZERO(BITS32(VARL("int_mant"), 31, 1)), SGE(VARL("int_exp"), S32(127)))),
			S32(255),
			ITE(OR(
				    AND(NON_ZERO(BITS32(VARL("int_mant"), 31, 1)), SLE(VARL("int_exp"), S32(-128))),
				    EQ(VARL("int_mant"), U32(0))),
				S32(0),
				LET("temp_exp", ITE(IS_ZERO(BITS32(VARL("int_mant"), 31, 1)), U32(0), ADD(VARL("int_exp"), U32(128))),
					LET("fp_exp_frac", ADD(LOGOR(SHL0(BITS32(VARLP("temp_exp"), 0, 8), 23), BITS32(VARL("int_mant"), 8, 23)), BOOL_TO_BV32(VARL("flag_rnd"))),
						BITS32(VARLP("fp_exp_frac"), 23, 8))))));
	RzILOpEffect *_5 = SETL("fp_frac",
		ITE(AND(IS_ZERO(BITS32(VARL("int_mant"), 31, 1)), EQ(S32(255), VARL("int_exp"))),
			BITS32(VARL("int_mant"), 8, 23),
			ITE(OR(
				    AND(NON_ZERO(BITS32(VARL("int_mant"), 31, 1)), SGE(VARL("int_exp"), S32(127))),
				    OR(
					    AND(NON_ZERO(BITS32(VARL("int_mant"), 31, 1)), SLE(VARL("int_exp"), S32(-128))),
					    EQ(VARL("int_mant"), U32(0)))),
				S32(0),
				LET("temp_exp", ITE(IS_ZERO(BITS32(VARL("int_mant"), 31, 1)), U32(0), ADD(VARL("int_exp"), U32(128))),
					LET("fp_exp_frac", ADD(LOGOR(SHL0(BITS32(VARLP("temp_exp"), 0, 8), 23), BITS32(VARL("int_mant"), 8, 23)), BOOL_TO_BV32(VARL("flag_rnd"))),
						BITS32(VARLP("fp_exp_frac"), 0, 23))))));
	RzILOpEffect *_6 = SETG(R(0), LOGOR(SHL0(BITS32(VARG(R(2)), 31, 1), 31), LOGOR(SHL0(VARL("fp_exp"), 23), VARL("fp_frac"))));
	return SEQ6(_1, _2, _3, _4, _5, _6);
}
static RzILOpEffect *lift_unpack(RzAsmTriCoreContext *ctx) {
	RzILOpEffect *_1 = SETL("fp_exp", BITS32(VARG(R(1)), 23, 8));
	RzILOpEffect *_2 = SETL("fp_frac", BITS32(VARG(R(1)), 0, 23));
	RzILOpEffect *_3 = SETL("int_exp",
		ITE(EQ(VARL("fp_exp"), U32(255)),
			S32(255),
			ITE(AND(IS_ZERO(VARL("fp_exp")), IS_ZERO(VARL("fp_frac"))),
				S32(-127),
				ITE(AND(IS_ZERO(VARL("fp_exp")), NON_ZERO(VARL("fp_frac"))),
					S32(-126),
					SUB(VARL("fp_exp"), S32(127))))));
	RzILOpEffect *_4 = SETL("int_mant",
		ITE(EQ(VARL("fp_exp"), U32(255)),
			SHL0(BITS32(VARL("fp_frac"), 0, 23), 7),
			ITE(AND(IS_ZERO(VARL("fp_exp")), IS_ZERO(VARL("fp_frac"))),
				S32(0),
				ITE(AND(IS_ZERO(VARL("fp_exp")), NON_ZERO(VARL("fp_frac"))),
					SHL0(BITS32(VARL("fp_frac"), 0, 23), 7),
					LOGOR(SHL0(BITS32(VARL("fp_frac"), 0, 23), 7),
						SHL0(U32(0b01), 30))))));
	RzILOpEffect *_5 = SETG(R(0), APPEND(VARL("int_exp"), VARL("int_mant")));
	return SEQ5(_1, _2, _3, _4, _5);
}

static RzILOpEffect *e_op_op(
	const char *r, RzILOpPure *a, RzILOpPure *b, FUNC_OP2 op1, FUNC_OP2 op2) {
	return SETG(r, BITS32_U(VARG(r), 0, 1, BOOL_TO_BV32(op1(NON_ZERO(BITS32(VARG(r), 0, 1)), op2(a, b)))));
}
static RzILOpEffect *e_sh_op(
	const char *r, RzILOpPure *a, RzILOpPure *b, FUNC_OP2 op1) {
	return SETG(r, LOGOR(SHL0(BITS32(VARG(r), 0, 30), 1), BOOL_TO_BV32(op1(a, b))));
}

static RzILOpEffect *e_op_bit(
	RzAsmTriCoreContext *ctx, FUNC_OP2 op) {
	return SETG(R(0), BOOL_TO_BV32(op(NON_ZERO(BITS32(VARG(R(1)), I(2), 1)), NON_ZERO(BITS32(VARG(R(3)), I(4), 1)))));
}
static RzILOpEffect *e_op_op_bit(
	RzAsmTriCoreContext *ctx, FUNC_OP2 op1, FUNC_OP2 op2) {
	return e_op_op(R(0), NON_ZERO(BITS32(VARG(R(1)), I(2), 1)), NON_ZERO(BITS32(VARG(R(3)), I(4), 1)), op1, op2);
}
static RzILOpEffect *e_sh_op_bit(
	RzAsmTriCoreContext *ctx, FUNC_OP2 op1) {
	return SETG(R(0), LOGOR(SHL0(BITS32(VARG(R(0)), 0, 30), 1), BOOL_TO_BV32(op1(NON_ZERO(BITS32(VARG(R(1)), I(2), 1)), NON_ZERO(BITS32(VARG(R(3)), I(4), 1))))));
}
static RzILOpEffect *e_ins_bit(
	RzAsmTriCoreContext *ctx, bool inv) {
	unsigned pos1 = I(2);
	unsigned pos2 = I(4);
	RzILOpPure *b = SHL0(BITS32(VARG(R(3)), pos2, 1), pos1);
	b = inv ? LOGNOT(b) : b;
	return SETG(R(0),
		LOGOR(SHL0(BITS32(VARG(R(0)), pos1 + 1, 32 - pos1 - 1), pos1 + 1),
			LOGOR(BITS32(VARG(R(1)), 0, pos1), b)));
}

static RzILOpEffect *e_op2(
	const char *r, RzILOpPure *a, RzILOpPure *b, FUNC_OP2 op) {
	return SETG(r, op(a, b));
}

static RzILOpPure *f_andn(
	RzILOpPure *a, RzILOpPure *b) {
	return AND(a, INV(b));
}
static RzILOpPure *f_nor(
	RzILOpPure *a, RzILOpPure *b) {
	return INV(OR(a, b));
}
static RzILOpPure *f_nand(
	RzILOpPure *a, RzILOpPure *b) {
	return INV(AND(a, b));
}
static RzILOpPure *f_orn(
	RzILOpPure *a, RzILOpPure *b) {
	return OR(a, INV(b));
}
static RzILOpPure *f_xnor(
	RzILOpPure *a, RzILOpPure *b) {
	return INV(XOR(a, b));
}

static RzILOpPure *f_sh(
	RzILOpPure *c, RzILOpPure *x) {
	return LET("sh_c", c,
		LET("sh_x", x,
			ITE(SGT(VARLP("sh_c"), S32(0)), SHIFTL0(VARLP("sh_x"), VARLP("sh_c")), SHIFTR0(VARLP("sh_x"), NEG(VARLP("sh_c"))))));
}

static RzILOpPure *f_sha(
	RzILOpPure *c, RzILOpPure *x) {
	return LET("sh_c", c,
		LET("sh_x", x,
			ITE(SGT(VARLP("sh_c"), S32(0)), SHIFTL0(VARLP("sh_x"), VARLP("sh_c")), SHIFTRA(VARLP("sh_x"), NEG(VARLP("sh_c"))))));
}

static RzILOpEffect *e_sh(
	const char *tgt, RzILOpPure *c, RzILOpPure *x, unsigned B) {
	switch (B) {
	case Word_b: return SETG(tgt, f_sh(c, x));
	case HalfWord_b:
		return SETG(tgt,
			LET("shift_count", c,
				APPEND(
					UNSIGNED(16, f_sh(VARLP("shift_count"), BITS32(x, 16, 16))),
					UNSIGNED(16, f_sh(VARLP("shift_count"), BITS32(DUP(x), 0, 16))))));
	case Byte_b:
		return SETG(tgt,
			LET("shift_count", c,
				APPEND(APPEND(
					       UNSIGNED(8, f_sh(VARLP("shift_count"), BITS32(x, 24, 8))),
					       UNSIGNED(8, f_sh(VARLP("shift_count"), BITS32(DUP(x), 16, 8)))),
					APPEND(
						UNSIGNED(8, f_sh(VARLP("shift_count"), BITS32(DUP(x), 8, 8))),
						UNSIGNED(8, f_sh(VARLP("shift_count"), BITS32(DUP(x), 0, 8)))))));
	}
	rz_warn_if_reached();
	return NULL;
}

static RzILOpEffect *e_sha(
	const char *tgt, RzILOpPure *c, RzILOpPure *x, unsigned B) {
	switch (B) {
	case Word_b: {
		RzILOpEffect *e = SEQ3(
			SETL("carry_out",
				LET("shift_count", c,
					ITE(SGE(VARLP("shift_count"), S32(0)),
						AND(NON_ZERO(VARLP("shift_count")),
							NON_ZERO(EXTRACT32(DUP(x), SUB(U32(32), VARLP("shift_count")), ADD(VARLP("shift_count"), U32(1))))),
						NON_ZERO(EXTRACT32(DUP(x), U32(0), NEG(VARLP("shift_count"))))))),
			SETL("result", f_sha(DUP(c), x)),
			SETG(tgt, VARL("result")));
		f_overflow32_carry(e);
		return e;
	}
	case HalfWord_b: {
		return SETG(tgt,
			LET("shift_count", c,
				APPEND(
					UNSIGNED(16, f_sha(VARLP("shift_count"), BITS32(x, 16, 16))),
					UNSIGNED(16, f_sha(VARLP("shift_count"), BITS32(DUP(x), 0, 16))))));
	}
	case Byte_b:
		return SETG(tgt,
			LET("shift_count", c,
				APPEND(APPEND(
					       UNSIGNED(8, f_sha(VARLP("shift_count"), BITS32(x, 24, 8))),
					       UNSIGNED(8, f_sha(VARLP("shift_count"), BITS32(DUP(x), 16, 8)))),
					APPEND(
						UNSIGNED(8, f_sha(VARLP("shift_count"), BITS32(DUP(x), 8, 8))),
						UNSIGNED(8, f_sha(VARLP("shift_count"), BITS32(DUP(x), 0, 8)))))));
	}
	rz_warn_if_reached();
	return NULL;
}

static RzILOpEffect *e_shas(
	const char *tgt, RzILOpPure *c, RzILOpPure *x) {
	RzILOpEffect *e = SEQ2(
		SETL("result", ssov_n(f_sha(c, x), 32)),
		SETG(tgt, VARL("result")));
	return f_overflow32(e);
}

static RzILOpEffect *lift_div(RzAsmTriCoreContext *ctx) {
	RzILOpEffect *_1 = SETL("dividend", VARG(R(1)));
	RzILOpEffect *_2 = SETL("divisor", VARG(R(2)));
	RzILOpEffect *_3 = SETL("remainder",
		ITE(EQ(VARL("divisor"), U32(0)),
			U32(0x00000000),
			ITE(AND(EQ(VARL("divisor"), U32(0xffffffff)), EQ(VARL("dividend"), U32(0x80000000))),
				U32(0x00000000), MOD(VARL("dividend"), VARL("divisor")))));
	RzILOpEffect *_4 = SETL("quotient",
		ITE(EQ(VARL("divisor"), U32(0)),
			ITE(SGE(VARL("dividend"), S32(0)),
				U32(0x7fffffff), U32(0x80000000)),
			ITE(AND(EQ(VARL("divisor"), U32(0xffffffff)), EQ(VARL("dividend"), U32(0x80000000))),
				U32(0x7fffffff), DIV(SUB(VARL("dividend"), VARL("remainder")), VARL("divisor")))));
	RzILOpEffect *_5 = SETG(R(0), APPEND(VARL("remainder"), VARL("quotient")));
	return SEQ5(_1, _2, _3, _4, _5);
}
static RzILOpEffect *lift_div_u(RzAsmTriCoreContext *ctx) {
	RzILOpEffect *_1 = SETL("dividend", VARG(R(1)));
	RzILOpEffect *_2 = SETL("divisor", VARG(R(2)));
	RzILOpEffect *_3 = SETL("remainder",
		ITE(EQ(VARL("divisor"), U32(0)),
			U32(0x00000000),
			MOD(VARL("dividend"), VARL("divisor"))));
	RzILOpEffect *_4 = SETL("quotient",
		ITE(EQ(VARL("divisor"), U32(0)),
			U32(0xffffffff),
			DIV(SUB(VARL("dividend"), VARL("remainder")), VARL("divisor"))));
	RzILOpEffect *_5 = SETG(R(0), APPEND(VARL("remainder"), VARL("quotient")));
	return SEQ5(_1, _2, _3, _4, _5);
}

/**
 * DVINIT
 * if ((D[b] == 0) OR ((D[b] == 32’hFFFFFFFF) AND (D[a] == 32’h80000000))) then overflow = 1 else overflow = 0;
 * DVINIT.U
 * if (D[b] == 0) then overflow = 1 else overflow = 0;
 * DVINIT.B
 * if ((D[b] == 0) OR ((D[b] == 32’hFFFFFFFF AND (D[a] == 32’hFFFFFF80)) then overflow = 1 else overflow = 0;
 * DVINIT.BU
 * if (D[b]==0) then overflow = 1 else overflow = 0;
 * DVINIT.H
 * if ((D[b] == 0) OR ((D[b] == 32’hFFFFFFFF AND (D[a] == 32’hFFFF8000))) then overflow = 1 else overflow=0;
 * DVINIT.HU
 * if (D[b] == 0) then overflow = 1 else overflow = 0;
 * For all the DVINIT variations:
 * if (overflow) then PSW.V = 1 else PSW.V = 0;
 */
static RzILOpEffect *lift_dvinit(RzAsmTriCoreContext *ctx) {
	const unsigned id = ctx->insn->id;
	RzILOpEffect *e = NULL;
	switch (id) {
	case TRICORE_INS_DVINIT:
		e = SEQ4(
			SETL("overflow", OR(IS_ZERO(VARG(R(2))), AND(EQ(VARG(R(2)), U32(0xFFFFFFFF)), EQ(VARG(R(1)), U32(0x80000000))))),
			set_PSW_V(BOOL_TO_BV32(VARL("overflow"))),
			BRANCH(VARL("overflow"), set_PSW_SV(U32(1)), NOP()),
			set_PSW_AV(U32(0)));
		return SEQ2(
			SETG(R(0), SEXT64(VARG(R(1)), 32)),
			e);
	case TRICORE_INS_DVINIT_B: {
		e = SEQ4(
			SETL("overflow", OR(IS_ZERO(VARG(R(2))), AND(EQ(VARG(R(2)), U32(0xFFFFFFFF)), EQ(VARG(R(1)), U32(0xFFFFFF80))))),
			set_PSW_V(BOOL_TO_BV32(VARL("overflow"))),
			BRANCH(VARL("overflow"), set_PSW_SV(U32(1)), NOP()),
			set_PSW_AV(U32(0)));
		const unsigned sz = 24;
		return SEQ3(
			SETL("quotient_sign", NE(BITS32(VARG(R(1)), 31, 1), BITS32(VARG(R(2)), 31, 1))),
			SETG(R(0), LOGOR(ITE(VARL("quotient_sign"), ONES64(sz), U64(0)), SHL0(BITS64(SEXT64(VARG(R(1)), 32), 0, 64 - sz), sz))),
			e);
	}
	case TRICORE_INS_DVINIT_H: {
		e = SEQ4(
			SETL("overflow", OR(IS_ZERO(VARG(R(2))), AND(EQ(VARG(R(2)), U32(0xFFFFFFFF)), EQ(VARG(R(1)), U32(0xFFFF8000))))),
			set_PSW_V(BOOL_TO_BV32(VARL("overflow"))),
			BRANCH(VARL("overflow"), set_PSW_SV(U32(1)), NOP()),
			set_PSW_AV(U32(0)));
		const unsigned sz = 16;
		return SEQ3(
			SETL("quotient_sign", NE(BITS32(VARG(R(1)), 31, 1), BITS32(VARG(R(2)), 31, 1))),
			SETG(R(0), LOGOR(ITE(VARL("quotient_sign"), ONES64(sz), U64(0)), SHL0(BITS64(SEXT64(VARG(R(1)), 32), 0, 64 - sz), sz))),
			e);
	}
	case TRICORE_INS_DVINIT_U:
	case TRICORE_INS_DVINIT_BU:
	case TRICORE_INS_DVINIT_HU:
		e = SEQ4(
			SETL("overflow", IS_ZERO(VARG(R(2)))),
			set_PSW_V(BOOL_TO_BV32(VARL("overflow"))),
			BRANCH(VARL("overflow"), set_PSW_SV(U32(1)), NOP()),
			set_PSW_AV(U32(0)));
		return SEQ2(
			SETG(R(0), UNSIGNED(64, VARG(R(1)))),
			e);
	default: break;
	}
	rz_warn_if_reached();
	NOT_IMPLEMENTED;
}

static RzILOpPure *f_abs(RzILOpPure *x) {
	return LET("x", x, ITE(SGT(VARLP("x"), S32(0)), VARLP("x"), NEG(VARLP("x"))));
}

static RzILOpEffect *lift_dvadj(RzAsmTriCoreContext *ctx) {
	RzILOpEffect *_1 = SETL("q_sign", XOR(BIT32(VARG_SUB(R(1), 1), 31), BIT32(VARG(R(2)), 31)));
	RzILOpEffect *_2 = SETL("x_sign", BIT32(VARG_SUB(R(1), 1), 31));
	RzILOpEffect *_3 = SETL("eq_pos", AND(VARL("x_sign"), EQ(VARG_SUB(R(1), 1), VARG(R(2)))));
	RzILOpEffect *_4 = SETL("eq_neg", AND(VARL("x_sign"), EQ(VARG_SUB(R(1), 1), NEG(VARG(R(2))))));
	RzILOpEffect *_5 = SETL("quotient", ITE(OR(AND(VARL("q_sign"), INV(VARL("eq_neg"))), VARL("eq_pos")), ADD(U32(1), VARG_SUB(R(1), 0)), VARG_SUB(R(1), 0)));
	RzILOpEffect *_6 = SETL("remainder", ITE(OR(VARL("eq_pos"), VARL("eq_neg")), U32(0), VARG_SUB(R(1), 1)));
	RzILOpEffect *_7 = SETL("gt", SGT(f_abs(VARG_SUB(R(1), 1)), f_abs(VARG(R(2)))));
	RzILOpEffect *_8 = SETL("eq", AND(INV(BIT32(VARG_SUB(R(1), 1), 31)), EQ(f_abs(VARG_SUB(R(1), 1)), f_abs(VARG(R(2))))));
	RzILOpEffect *_9 = SETL("overflow", OR(VARL("eq"), VARL("gt")));
	RzILOpEffect *_10 = SETG(R(0), ITE(VARL("overflow"), U64(64), APPEND(VARL("remainder"), VARL("quotient"))));
	return SEQN(10, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10);
}

static RzILOpPure *f_beq(RzILOpPure *x, RzILOpPure *y) {
	return LET("x", x,
		LET("y", y,
			OR(AND(VARLP("x"), VARLP("y")),
				AND(INV(VARLP("x")), INV(VARLP("y"))))));
}
static RzILOpPure *f_bne(RzILOpPure *x, RzILOpPure *y) {
	return INV(f_beq(x, y));
}

static RzILOpEffect *lift_dvstep(RzAsmTriCoreContext *ctx) {
	RzILOpEffect *_1 = SETL("dividend_sign", BIT32(VARG_SUB(R(1), 1), 31));
	RzILOpEffect *_2 = SETL("divisor_sign", BIT32(VARG(R(2)), 31));
	RzILOpEffect *_3 = SETL("quotient_sign", f_bne(VARL("dividend_sign"), VARL("divisor_sign")));
	RzILOpEffect *_4 = SETL("addend", ITE(VARL("quotient_sign"), VARG(R(2)), NEG(VARG(R(2)))));
	RzILOpEffect *_5 = SETL("dividend_quotient", VARG_SUB(R(1), 0));
	RzILOpEffect *_6 = SETL("remainder", VARG_SUB(R(1), 1));
	RzILOpEffect *e = SEQ6(_1, _2, _3, _4, _5, _6);
	for (ut32 i = 0; i < 8; ++i) {
		f_cons(e, SETL("remainder", LOGOR(SHL0(VARL("remainder"), 1), BITS32(VARL("dividend_quotient"), 31, 1))));
		f_cons(e, SETL("dividend_quotient", SHL0(VARL("dividend_quotient"), 1)));
		f_cons(e, SETL("_temp", ADD(VARL("remainder"), VARL("addend"))));
		f_cons(e, SETL("remainder", ITE(f_beq(SLT(VARL("_temp"), S32(0)), VARL("dividend_sign")), VARL("_temp"), VARL("remainder"))));
		f_cons(e, SETL("dividend_quotient", LOGOR(VARL("dividend_quotient"), BOOL_TO_BV32(ITE(f_beq(SLT(VARL("_temp"), S32(0)), VARL("dividend_sign")), INV(VARL("quotient_sign")), VARL("quotient_sign"))))));
	}
	return f_cons_(e, SETG(R(0), APPEND(VARL("remainder"), VARL("dividend_quotient"))));
}
static RzILOpEffect *lift_dvstep_u(RzAsmTriCoreContext *ctx) {
	RzILOpEffect *_1 = SETL("divisor", VARG(R(2)));
	RzILOpEffect *_2 = SETL("dividend_quotient", VARG_SUB(R(1), 0));
	RzILOpEffect *_3 = SETL("remainder", VARG_SUB(R(1), 1));
	RzILOpEffect *e = SEQ3(_1, _2, _3);
	for (ut32 i = 0; i < 8; ++i) {
		f_cons(e, SETL("remainder", LOGOR(SHL0(VARL("remainder"), 1), BITS32(VARL("dividend_quotient"), 31, 1))));
		f_cons(e, SETL("dividend_quotient", SHL0(VARL("dividend_quotient"), 1)));
		f_cons(e, SETL("_temp", ADD(VARL("remainder"), VARL("divisor"))));
		f_cons(e, SETL("remainder", ITE(SLT(VARL("_temp"), S32(0)), VARL("remainder"), VARL("_temp"))));
		f_cons(e, SETL("dividend_quotient", LOGOR(VARL("dividend_quotient"), BOOL_TO_BV32(INV(SLT(VARL("_temp"), S32(0)))))));
	}
	return f_cons_(e, SETG(R(0), APPEND(VARL("remainder"), VARL("dividend_quotient"))));
}

static RzILOpPure *EA_PCXI() {
	return LOGOR(SHL0(FCX_FCXO(), 6), SHL0(FCX_FCXS(), 27));
}

static RzILOpEffect *e_bisr(RzAsmTriCoreContext *ctx) {
	RzILOpEffect *e = SEQN(12,
		SETL("tmp_FCX", VARG("FCX")),
		SETL("EA", EA_PCXI()),
		SETL("new_FCX", LOADW(Word_b, VARL("EA"))),
		ST_MB(VARL("EA"), 16, VARG("d7"), VARG("d6"), VARG("d5"), VARG("d4"), VARG("a7"), VARG("a6"), VARG("a5"), VARG("a4"), VARG("d3"), VARG("d2"), VARG("d1"), VARG("d0"), VARG("a3"), VARG("a2"), VARG("a11"), VARG("PCXI")),
		set_PCXI_PCPN(ctx->mode, ICR_CCPN()),
		set_PCXI_PIE(ctx->mode, ICR_IE()),
		set_PCXI_UL(ctx->mode, U32(0)),
		SETG("PCXI", BITS32_U(VARG("PCXI"), 0, 20, BITS32(VARG("FCX"), 0, 20))),
		SETG("FCX", BITS32_U(VARG("FCX"), 0, 20, BITS32(VARL("new_FCX"), 0, 20))),
		set_ICR_IE(U32(1)),
		set_ICR_CCPN(LOGAND(U32(I(0)), U32(0xff))),
		BRANCH(EQ(VARL("tmp_FCX"), VARG("LCX")), trap(FCD), NOP()));
	return SEQ2(BRANCH(IS_ZERO(VARG("FCX")), trap(FCU), NOP()),
		e);
}

// n start with 31
static RzILOpEffect *leading_ones(RzAnalysisLiftedILOp xs, const char *name, RzILOpPure *x, const unsigned N) {
	RzILOpEffect *y =
		REPEAT(AND(AND(ULT(VARL(name), U32(N)), UGE(VARL(name), U32(0))), NON_ZERO(EXTRACT32(x, VARL(name), U32(1)))), SETL(name, ADD(VARL(name), U32(1))));
	return xs ? f_cons_(f_cons_(xs, SETL(name, U32(N - 1))), y) : SEQ2(SETL(name, U32(N - 1)), y);
}
// n start with 30
static RzILOpEffect *leading_signs(RzAnalysisLiftedILOp xs, const char *name, RzILOpPure *x, const unsigned N) {
	RzILOpEffect *y =
		REPEAT(
			AND(AND(ULT(VARL(name), U32(N)), UGE(VARL(name), U32(0))),
				EQ(EXTRACT32(x, VARL(name), U32(1)), EXTRACT32(DUP(x), U32(N - 1), U32(1)))),
			SETL(name, ADD(VARL(name), U32(1))));
	return xs ? f_cons_(f_cons_(xs, SETL(name, U32(N - 2))), y) : SEQ2(SETL(name, U32(N - 2)), y);
}
// n start with 31
static RzILOpEffect *leading_zeros(RzAnalysisLiftedILOp xs, const char *name, RzILOpPure *x, const unsigned N) {
	RzILOpEffect *y = REPEAT(AND(AND(ULT(VARL(name), U32(N)), UGE(VARL(name), U32(0))), IS_ZERO(EXTRACT32(x, VARL(name), U32(1)))), SETL(name, ADD(VARL(name), U32(1))));
	return xs ? f_cons_(f_cons_(xs, SETL(name, U32(N - 1))), y) : SEQ2(SETL(name, U32(N - 1)), y);
}

typedef RzILOpEffect *(*FUNC_BS)(RzAnalysisLiftedILOp xs, const char *name, RzILOpPure *x, const unsigned N);
static RzILOpEffect *e_BS(RzAsmTriCoreContext *ctx, unsigned b, FUNC_BS f) {
	switch (b) {
	case Word_b: {
		RzILOpEffect *xs = f(NULL, "n", VARG(R(1)), Word_b);
		return f_cons_(xs, SETG(R(0), VARL("n")));
	}
	case HalfWord_b: {
		RzILOpEffect *xs = f(f(NULL, "n0", BITS32(VARG(R(1)), 0, 16), HalfWord_b),
			"n1", BITS32(VARG(R(1)), 16, 16), HalfWord_b);
		return f_cons_(xs, SETG(R(0), packed_2halfword(VARL("n1"), VARL("n0"))));
	}
	case Byte_b: {
		RzILOpEffect *xs = f(NULL, "n0", BITS32(VARG(R(1)), 0, 8), Byte_b);
		merr(xs);
		merr(f(xs, "n1", BITS32(VARG(R(1)), 8, 8), Byte_b));
		merr(f(xs, "n2", BITS32(VARG(R(1)), 16, 8), Byte_b));
		merr(f(xs, "n3", BITS32(VARG(R(1)), 24, 8), Byte_b));
		return f_cons_(xs, SETG(R(0), packed_4byte(VARL("n3"), VARL("n2"), VARL("n1"), VARL("n0"))));
	}
	}
	rz_warn_if_reached();
	return NULL;
}

#define MIN(x, y)        ITE(UGT(x, y), DUP(x), DUP(y))
#define CRC_32_GENERATOR 0xEDB88320
static RzILOpPure *crc_div(RzILOpPure *c, RzILOpPure *g, RzILOpPure *crc_width, RzILOpPure *data_width) {
	return LET("shift", MIN(crc_width, data_width),
		MOD(SHIFTL0(c, VARLP("shift")), LOGOR(g, SHIFTL0(U32(1), DUP(crc_width)))));
}

#define Mab(na, nb) \
	if (i1 || i2 || (n > 0 && n < Word_b)) { \
		if (xs) { \
			f_cons(xs, SETL(#na, BITS32(a, i1, n))); \
			f_cons(xs, SETL(#nb, BITS32(b, i2, n))); \
		} else { \
			xs = SEQ2( \
				SETL(#na, BITS32(a, i1, n)), \
				SETL(#nb, BITS32(b, i2, n))); \
		} \
	} else { \
		if (xs) { \
			f_cons(xs, SETL(#na, a)); \
			f_cons(xs, SETL(#nb, b)); \
		} else { \
			xs = SEQ2( \
				SETL(#na, a), \
				SETL(#nb, b)); \
		} \
	}

static RzAnalysisLiftedILOp f_madd(
	RzAnalysisLiftedILOp xs,
	const char *name1, const char *name2,
	RzILOpPure *a, RzILOpPure *b, unsigned arg_n, unsigned i1, unsigned i2, unsigned n) {
	rz_warn_if_fail(arg_n == 1 || arg_n == 0);
	Mab(madd_a, madd_b);

	f_cons(xs,
		SETL(name1,
			AND(
				EQ(VARL("madd_a"), U32(0x8000)),
				AND(
					EQ(VARL("madd_b"), U32(0x8000)),
					EQ(U32(arg_n), U32(1))))));
	return f_cons_(xs, SETL(name2, ITE(VARL(name1), U32(0x7fffffff), SHL0(MUL(VARL("madd_a"), VARL("madd_b")), arg_n))));
}
static RzAnalysisLiftedILOp e_madd(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2, unsigned i3, unsigned i4, unsigned n,
	FUNC_OP2 finish) {
	RzAnalysisLiftedILOp e = f_madd(NULL, "sc1", "result_word1", VARG(R(2)), VARG(R(3)), I(4), i1, i2, n);
	merr(e);
	merr(f_madd(e, "sc0", "result_word0", VARG(R(2)), VARG(R(3)), I(4), i3, i4, n));
	f_cons(e, SETL("result", ADD(VARG(R(1)), UNSIGNED(64, SHL0(ADD(VARL("result_word1"), VARL("result_word0")), 16)))));
	f_cons(e, SETG(R(0), finish ? finish(VARL("result"), U64(64)) : VARL("result")));

	return f_overflow64(e);
}

static RzAnalysisLiftedILOp f_mul(
	RzAnalysisLiftedILOp xs,
	const char *name1, const char *name2,
	RzILOpPure *a, RzILOpPure *b, unsigned arg_n, unsigned i1, unsigned i2, unsigned n) {
	rz_warn_if_fail(arg_n == 1 || arg_n == 0);
	Mab(mul_a, mul_b);

	f_cons(xs,
		SETL(name1,
			AND(
				EQ(VARL("mul_a"), U32(0x8000)),
				AND(
					EQ(VARL("mul_b"), U32(0x8000)),
					EQ(U32(arg_n), U32(1))))));
	return f_cons_(xs, SETL(name2, ITE(VARL(name1), U32(0x7fffffff), SHL0(MUL(VARL("mul_a"), VARL("mul_b")), arg_n))));
}
static RzAnalysisLiftedILOp f_mulr(
	RzAnalysisLiftedILOp xs,
	const char *name1, const char *name2,
	RzILOpPure *a, RzILOpPure *b, unsigned arg_n, unsigned i1, unsigned i2, unsigned n) {
	rz_warn_if_fail(arg_n == 1 || arg_n == 0);
	Mab(mulr_a, mulr_b);

	f_cons(xs,
		SETL(name1,
			AND(
				EQ(VARL("mulr_a"), U32(0x8000)),
				AND(
					EQ(VARL("mulr_b"), U32(0x8000)),
					EQ(U32(arg_n), U32(1))))));
	return f_cons_(xs, SETL(name2, ITE(VARL(name1), U32(0x7fffffff), ADD(SHL0(MUL(VARL("mulr_a"), VARL("mulr_b")), arg_n), U32(0x8000)))));
}

static RzAnalysisLiftedILOp f_maddr(
	RzAnalysisLiftedILOp xs, RzAsmTriCoreContext *ctx,
	const char *name1, const char *name2, const char *name3,
	RzILOpPure *a, RzILOpPure *b, unsigned arg_n, unsigned i1, unsigned i2, unsigned n) {
	rz_warn_if_fail(arg_n == 1 || arg_n == 0);
	xs = f_mul(xs, name1, name2, a, b, arg_n, i1, i2, n);
	return f_cons_(xs,
		SETL(name3,
			ADD(is_pair_register(R(1)) ? VARG_SUB(R(1), i1 == 16 ? 1 : 0) : SHL0(BITS32(VARG(R(1)), i1, n), 16),
				ADD(VARL(name2), U32(0x8000)))));
}

static RzAnalysisLiftedILOp e_maddr(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2, unsigned i3, unsigned i4, unsigned n,
	FUNC_OP2 pack) {
	RzAnalysisLiftedILOp e = f_maddr(NULL, ctx, "sc1", "mul_res1", "result_halfword1", VARG(R(2)), VARG(R(3)), I(4), i1, i2, n);
	merr(e);
	merr(f_maddr(e, ctx, "sc0", "mul_res0", "result_halfword0", VARG(R(2)), VARG(R(3)), I(4), i3, i4, n));
	f_cons(e, SETG(R(0), pack(VARL("result_halfword1"), VARL("result_halfword0"))));

	return f_overflow32x2(e, "result_halfword1", "result_halfword0");
}
static RzAnalysisLiftedILOp e_maddr_q(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2,
	FUNC_OP2 pack) {
	RzAnalysisLiftedILOp e = f_maddr(NULL, ctx, "sc", "mul_res", "result", VARG(R(2)), VARG(R(3)), I(4), i1, i2, HalfWord_b);
	merr(e);
	f_cons(e, SETG(R(0), pack(VARL("result"), NULL)));

	f_cons(e, SETL("overflow", OR(UGT(VARL("result"), U32(0x7fffffff)), SLT(VARL("result"), S32(-0x80000000)))));
	f_cons(e, SETL("advanced_overflow", XOR(BIT32(VARL("result"), 31), BIT32(VARL("result"), 30))));
	f_cons(e, set_PSW_V(BOOL_TO_BV32(VARL("overflow"))));
	f_cons(e, set_PSW_AV(BOOL_TO_BV32(VARL("advanced_overflow"))));
	f_cons(e, BRANCH(VARL("overflow"), set_PSW_SV(U32(1)), NOP()));
	f_cons(e, BRANCH(VARL("advanced_overflow"), set_PSW_SAV(U32(1)), NOP()));
	return e;
}

static RzAnalysisLiftedILOp e_maddsu(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2, unsigned i3, unsigned i4, unsigned n,
	FUNC_OP2 pack) {
	RzAnalysisLiftedILOp e = f_mul(NULL, "sc1", "mul_res1", VARG(R(2)), VARG(R(3)), I(4), i1, i2, n);
	merr(e);
	merr(f_mul(e, "sc0", "mul_res0", VARG(R(2)), VARG(R(3)), I(4), i3, i4, n));
	f_cons(e, SETL("result_word1", ADD(VARG_SUB(R(1), 1), VARL("mul_res1"))));
	f_cons(e, SETL("result_word0", ADD(VARG_SUB(R(1), 0), VARL("mul_res0"))));
	f_cons(e, SETG(R(0), pack(VARL("result_word1"), VARL("result_word0"))));

	return f_overflow32x2(e, "result_word1", "result_word0");
}

static RzAnalysisLiftedILOp e_maddsum(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2, unsigned i3, unsigned i4, unsigned n,
	FUNC_OP2 pack) {
	RzAnalysisLiftedILOp e = f_mul(NULL, "sc1", "result_word1", VARG(R(2)), VARG(R(3)), I(4), i1, i2, n);
	merr(e);
	merr(f_mul(e, "sc0", "result_word0", VARG(R(2)), VARG(R(3)), I(4), i3, i4, n));
	f_cons(e, SETL("result", ADD(VARG(R(1)), SHL0(UNSIGNED(64, SUB(VARL("result_word1"), VARL("result_word0"))), 16))));
	f_cons(e, SETG(R(0), pack ? pack(VARL("result"), U64(64)) : VARL("result")));

	return f_overflow64(e);
}

static RzAnalysisLiftedILOp e_maddsur(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2, unsigned i3, unsigned i4, unsigned n,
	FUNC_OP2 pack) {
	RzAnalysisLiftedILOp e = f_maddr(NULL, ctx, "sc1", "mul_res1", "result_halfword1", VARG(R(2)), VARG(R(3)), I(4), i1, i2, n);
	merr(e);
	merr(f_maddr(e, ctx, "sc0", "mul_res0", "result_halfword0", VARG(R(2)), VARG(R(3)), I(4), i3, i4, n));
	f_cons(e, SETG(R(0), pack(VARL("result_halfword1"), VARL("result_halfword0"))));

	return f_overflow32x2(e, "result_halfword1", "result_halfword0");
}

static RzAnalysisLiftedILOp e_msubh(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2, unsigned i3, unsigned i4,
	FUNC_OP2 pack) {
	RzAnalysisLiftedILOp e = f_mul(NULL, "sc1", "mul_res1", VARG(R(2)), VARG(R(3)), I(4), i1, i2, HalfWord_b);
	merr(e);
	merr(f_mul(e, "sc0", "mul_res0", VARG(R(2)), VARG(R(3)), I(4), i3, i4, HalfWord_b));
	f_cons(e, SETL("result_word1", SUB(VARG_SUB(R(1), 1), VARL("mul_res1"))));
	if (ctx->insn->id == TRICORE_INS_MSUBAD_H || ctx->insn->id == TRICORE_INS_MSUBADS_H) {
		f_cons(e, SETL("result_word0", ADD(VARG_SUB(R(1), 0), VARL("mul_res0"))));
	} else {
		f_cons(e, SETL("result_word0", SUB(VARG_SUB(R(1), 0), VARL("mul_res0"))));
	}
	f_cons(e, SETG(R(0), pack(VARL("result_word1"), VARL("result_word0"))));

	return f_overflow32x2(e, "result_word1", "result_word0");
}
static RzAnalysisLiftedILOp e_msubadmh(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2, unsigned i3, unsigned i4,
	FUNC_OP2 pack) {
	RzAnalysisLiftedILOp e = f_mul(NULL, "sc1", "mul_word1", VARG(R(2)), VARG(R(3)), I(4), i1, i2, HalfWord_b);
	merr(e);
	merr(f_mul(e, "sc0", "mul_word0", VARG(R(2)), VARG(R(3)), I(4), i3, i4, HalfWord_b));
	if (ctx->insn->id == TRICORE_INS_MSUBADM_H || ctx->insn->id == TRICORE_INS_MSUBADMS_H) {
		f_cons(e, SETL("result", SUB(VARG(R(1)), SHL0(UNSIGNED(64, SUB(VARL("mul_word1"), VARL("mul_word0"))), 16))));
	} else if (ctx->insn->id == TRICORE_INS_MSUBM_H || ctx->insn->id == TRICORE_INS_MSUBMS_H) {
		f_cons(e, SETL("result", SUB(VARG(R(1)), SHL0(UNSIGNED(64, ADD(VARL("mul_word1"), VARL("mul_word0"))), 16))));
	}
	f_cons(e, SETG(R(0), pack ? pack(VARL("result"), U64(64)) : VARL("result")));

	return f_overflow64(e);
}
static RzAnalysisLiftedILOp e_msubadrh(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2, unsigned i3, unsigned i4,
	FUNC_OP2 pack) {
	RzAnalysisLiftedILOp e = f_mul(NULL, "sc1", "mul_res1", VARG(R(2)), VARG(R(3)), I(4), i1, i2, HalfWord_b);
	merr(e);
	merr(f_mul(e, "sc0", "mul_res0", VARG(R(2)), VARG(R(3)), I(4), i3, i4, HalfWord_b));

	RzILOpPure *tmp1 = is_pair_register(R(1))
		? VARG_SUB(R(1), 1)
		: LOGAND(VARG(R(1)), U32(0xffff0000));
	f_cons(e, SETL("result_halfword1", ADD(SUB(tmp1, VARL("mul_res1")), U32(0x8000))));
	if (ctx->insn->id == TRICORE_INS_MSUBADR_H || ctx->insn->id == TRICORE_INS_MSUBADRS_H) {
		f_cons(e, SETL("result_halfword0", ADD(ADD(SHL0(BITS32(VARG(R(1)), 0, 16), 16), VARL("mul_res0")), U32(0x8000))));
	} else if (ctx->insn->id == TRICORE_INS_MSUBR_H || ctx->insn->id == TRICORE_INS_MSUBRS_H) {
		RzILOpPure *tmp0 = is_pair_register(R(1))
			? VARG_SUB(R(1), 0)
			: SHL0(BITS32(VARG(R(1)), 0, 16), 16);
		f_cons(e, SETL("result_halfword0", ADD(SUB(tmp0, VARL("mul_res0")), U32(0x8000))));
	}
	f_cons(e, SETG(R(0), pack(VARL("result_halfword1"), VARL("result_halfword0"))));

	return f_overflow32x2(e, "result_halfword1", "result_halfword0");
}

static RzILOpPure *f_add_shl16_64(
	RzILOpPure *a, RzILOpPure *b) {
	return UNSIGNED(64, SHL0(ADD(a, b), 16));
}

static RzAnalysisLiftedILOp e_mul(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2, unsigned i3, unsigned i4, unsigned n,
	FUNC_OP2 pack) {
	RzAnalysisLiftedILOp e = f_mul(NULL, "sc1", "result_word1", VARG(R(1)), VARG(R(2)), I(3), i1, i2, n);
	merr(e);
	merr(f_mul(e, "sc0", "result_word0", VARG(R(1)), VARG(R(2)), I(3), i3, i4, n));
	f_cons(e, SETG(R(0), pack(VARL("result_word1"), VARL("result_word0"))));
	return f_overflow32x2(e, "result_word1", "result_word0");
}

static RzAnalysisLiftedILOp e_mulr_h(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2, unsigned i3, unsigned i4, unsigned n,
	FUNC_OP2 pack) {
	RzAnalysisLiftedILOp e = f_mulr(NULL, "sc1", "result_word1", VARG(R(1)), VARG(R(2)), I(3), i1, i2, n);
	merr(e);
	merr(f_mulr(e, "sc0", "result_word0", VARG(R(1)), VARG(R(2)), I(3), i3, i4, n));
	f_cons(e, SETG(R(0), pack(VARL("result_word1"), VARL("result_word0"))));
	return f_overflow32x2(e, "result_word1", "result_word0");
}

static RzAnalysisLiftedILOp e_mulr_q(
	RzAsmTriCoreContext *ctx, unsigned i1, unsigned i2) {
	RzAnalysisLiftedILOp e = f_mulr(NULL, "sc", "result", VARG(R(1)), VARG(R(2)), I(3), i1, i2, HalfWord_b);
	merr(e);
	return f_cons_(e, SETL(R(0), append_h16_32(VARL("result"), NULL)));
}

static RzILOpPure *f_op2_chain4(FUNC_OP2 f,
	RzILOpPure *x0, RzILOpPure *x1, RzILOpPure *x2, RzILOpPure *x3) {
	return f(x0, f(x1, f(x2, x3)));
}
static RzILOpPure *f_op2_chain6(FUNC_OP2 f,
	RzILOpPure *x0, RzILOpPure *x1, RzILOpPure *x2, RzILOpPure *x3,
	RzILOpPure *x4, RzILOpPure *x5) {
	return f(x0, f(x1, f_op2_chain4(f, x2, x3, x4, x5)));
}
static RzILOpPure *f_op2_chain8(FUNC_OP2 f,
	RzILOpPure *x0, RzILOpPure *x1, RzILOpPure *x2, RzILOpPure *x3,
	RzILOpPure *x4, RzILOpPure *x5, RzILOpPure *x6, RzILOpPure *x7) {
	return f(f_op2_chain4(f, x0, x1, x2, x3),
		f_op2_chain4(f, x4, x5, x6, x7));
}

static RzILOpPure *f_xor8(
	RzILOpPure *a, unsigned low) {
	return f_op2_chain8(rz_il_op_new_bool_xor,
		BIT32(a, low),
		BIT32(DUP(a), low + 1),
		BIT32(DUP(a), low + 2),
		BIT32(DUP(a), low + 3),
		BIT32(DUP(a), low + 4),
		BIT32(DUP(a), low + 5),
		BIT32(DUP(a), low + 6),
		BIT32(DUP(a), low + 7));
}

static RzILOpPure *f_bmerge4x2(
	RzILOpPure *a, RzILOpPure *b, unsigned low) {
	return UNSIGNED(8,
		f_op2_chain8(rz_il_op_new_log_or,
			SHL0(BITS32(a, low + 3, 1), 7),
			SHL0(BITS32(b, low + 3, 1), 6),
			SHL0(BITS32(DUP(a), low + 2, 1), 5),
			SHL0(BITS32(DUP(b), low + 2, 1), 4),
			SHL0(BITS32(DUP(a), low + 1, 1), 3),
			SHL0(BITS32(DUP(b), low + 1, 1), 2),
			SHL0(BITS32(DUP(a), low, 1), 1),
			SHL0(BITS32(DUP(b), low, 1), 0)));
}

static RzILOpPure *f_bsplit8(
	RzILOpPure *a, unsigned low) {
	return UNSIGNED(8,
		f_op2_chain8(rz_il_op_new_log_or,
			SHL0(BITS32(a, low + 14, 1), 7),
			SHL0(BITS32(DUP(a), low + 12, 1), 6),
			SHL0(BITS32(DUP(a), low + 10, 1), 5),
			SHL0(BITS32(DUP(a), low + 8, 1), 4),
			SHL0(BITS32(DUP(a), low + 6, 1), 3),
			SHL0(BITS32(DUP(a), low + 4, 1), 2),
			SHL0(BITS32(DUP(a), low + 2, 1), 1),
			SHL0(BITS32(DUP(a), low, 1), 0)));
}

static RzILOpPure *byte_select(
	RzILOpPure *x, unsigned s) {
	return UNSIGNED(8, BITS32(x, 8 * s, 8));
}

static RzAnalysisLiftedILOp population_count(
	RzAnalysisLiftedILOp xs, const char *name, RzILOpPure *a) {
	if (xs) {
		f_cons(xs, SETL(name, U32(0)));
		f_cons(xs, SETL("_index", U32(0)));
		f_cons(xs, REPEAT(ULT(VARL("_index"), U32(32)), SETL("name", ITE(NON_ZERO(EXTRACT32(a, VARL("_index"), U32(1))), ADD(VARL(name), U32(1)), VARL(name)))));

	} else {
		return SEQ3(
			SETL(name, U32(0)),
			SETL("_index", U32(0)),
			REPEAT(ULT(VARL("_index"), U32(32)), SETL("name", ITE(NON_ZERO(EXTRACT32(a, VARL("_index"), U32(1))), ADD(VARL(name), U32(1)), VARL(name)))));
	}
	return xs;
}

#include "tricore_il_fp.inc"

RZ_IPI RzAnalysisLiftedILOp tricore_il_op(RzAsmTriCoreContext *ctx, RzAnalysis *a) {
	ctx->word = rz_read_le32(ctx->insn->bytes);
	switch (ctx->insn->id) {
	case TRICORE_INS_FCALLI: return fast_call(ctx, VARG(R(0)));
	case TRICORE_INS_FCALLA:
	case TRICORE_INS_FCALL: return fast_call(ctx, U32(I(0)));
	case TRICORE_INS_CALLI: return abs_call(ctx, VARG(R(0)));
	case TRICORE_INS_CALLA:
	case TRICORE_INS_CALL: return abs_call(ctx, U32(I(0)));
	case TRICORE_INS_FRET: return fret();
	case TRICORE_INS_FTOHP: return ftohp(ctx);
	case TRICORE_INS_FTOIZ: return ftoiz(ctx);
	case TRICORE_INS_FTOI: return ftoi(ctx);
	case TRICORE_INS_FTOQ31Z: return ftoq31z(ctx);
	case TRICORE_INS_FTOQ31: return ftoq31(ctx);
	case TRICORE_INS_FTOUZ: return ftouz(ctx);
	case TRICORE_INS_FTOU:return ftou(ctx);
	case TRICORE_INS_HPTOF:
	case TRICORE_INS_ITOF:
	case TRICORE_INS_Q31TOF:
	case TRICORE_INS_UTOF:
	case TRICORE_INS_DIV_F:
	case TRICORE_INS_ADD_F:
	case TRICORE_INS_MADD_F:
	case TRICORE_INS_MSUB_F:
	case TRICORE_INS_SUB_F:
	case TRICORE_INS_MUL_F:
	case TRICORE_INS_QSEED_F: NOT_IMPLEMENTED;
	case TRICORE_INS_CMP_F: return f_cmp(ctx);
	case TRICORE_INS_UPDFL: {
		RzILOpPure *m = BITS32(VARG(R(0)), 8, 8);
		RzILOpPure *v = BITS32(VARG(R(0)), 0, 8);
		RzILOpPure *orig = BITS32(VARG("PSW"), 24, 8);
		return SETG("PSW", BITS32_U(VARG("PSW"), 24, 8, LOGOR(LOGAND(orig, LOGNOT(m)), LOGAND(v, DUP(m)))));
	}
	case TRICORE_INS_UNPACK: return lift_unpack(ctx);
	case TRICORE_INS_PACK: return lift_pack(ctx);
	case TRICORE_INS_ABSDIFS: {
		switch (OPC1) {
		case 0x8b: return e_ABSDIF(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), Word_b, ssov);
		case 0x0b: return e_ABSDIF(R(0), VARG(R(1)), VARG(R(2)), Word_b, ssov);
		default: break;
		}
		break;
	}
	case TRICORE_INS_ABSDIFS_B: return e_ABSDIF(R(0), VARG(R(1)), VARG(R(2)), Byte_b, ssov);
	case TRICORE_INS_ABSDIFS_H: return e_ABSDIF(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, ssov);
	case TRICORE_INS_ABSDIF: {
		switch (OPC1) {
		case 0x8b: return e_ABSDIF(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), Word_b, NULL);
		case 0x0b: return e_ABSDIF(R(0), VARG(R(1)), VARG(R(2)), Word_b, NULL);
		default: break;
		}
		break;
	}
	case TRICORE_INS_ABSDIF_B: return e_ABSDIF(R(0), VARG(R(1)), VARG(R(2)), Byte_b, NULL);
	case TRICORE_INS_ABSDIF_H: return e_ABSDIF(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, NULL);
	case TRICORE_INS_ABSS: return e_ABS(R(0), VARG(R(1)), Word_b, ssov);
	case TRICORE_INS_ABSS_B: return e_ABS(R(0), VARG(R(1)), Byte_b, ssov);
	case TRICORE_INS_ABSS_H: return e_ABS(R(0), VARG(R(1)), HalfWord_b, ssov);
	case TRICORE_INS_ABS: return e_ABS(R(0), VARG(R(1)), Word_b, NULL);
	case TRICORE_INS_ABS_B: return e_ABS(R(0), VARG(R(1)), Byte_b, NULL);
	case TRICORE_INS_ABS_H: return e_ABS(R(0), VARG(R(1)), HalfWord_b, NULL);
	case TRICORE_INS_ADDI: return SETG(R(0), ADD(VARG(R(1)), sign_ext32_bv(I(2), 16)));
	case TRICORE_INS_ADDIH_A:
	case TRICORE_INS_ADDIH: return SETG(R(0), ADD(VARG(R(1)), SHL0(U32(I(2)), 16)));
	case TRICORE_INS_ADDC:
	case TRICORE_INS_ADDS_BU:
	case TRICORE_INS_ADDS_B:
	case TRICORE_INS_ADDS_H:
	case TRICORE_INS_ADDS_HU:
	case TRICORE_INS_ADDS_U:
	case TRICORE_INS_ADDS:
	case TRICORE_INS_ADDX:
	case TRICORE_INS_ADD_B:
	case TRICORE_INS_ADD_H:
	case TRICORE_INS_ADD: return lift_add(ctx);
	case TRICORE_INS_CADDN_A:
	case TRICORE_INS_CADDN:
	case TRICORE_INS_CADD_A:
	case TRICORE_INS_CADD: return lift_cadd(ctx);
	case TRICORE_INS_SYSCALL: return trap(SYS); /// trap(SYS, const9[7:0])
	case TRICORE_INS_TRAPSV: return BRANCH(NON_ZERO(PSW_SV()), trap(SOVF), NOP());
	case TRICORE_INS_TRAPV: return BRANCH(NON_ZERO(PSW_V()), trap(OVF), NOP());
	case TRICORE_INS_RSTV: return SEQ4(set_PSW_V(U32(0)), set_PSW_SV(U32(0)), set_PSW_AV(U32(0)), set_PSW_SAV(U32(0)));
	case TRICORE_INS_ISYNC:
	case TRICORE_INS_DSYNC:
	case TRICORE_INS_WAIT: return NOP();
	case TRICORE_INS_DISABLE: {
		if (OPC1 == 0x0d) {
			switch (extract32(ctx->word, 22, 6)) {
			case 0x0d: return set_ICR_IE(U32(0));
			case 0x0f: return SEQ2(
				SETG(R(0), ICR_IE()),
				set_ICR_IE(U32(0)));
			default: break;
			}
		}
		break;
	}
	case TRICORE_INS_ENABLE: return set_ICR_IE(U32(1));
	case TRICORE_INS_RESTORE: return set_ICR_IE(BITS32(VARG(R(0)), 0, 1));
	case TRICORE_INS_BISR: return e_bisr(ctx);
	case TRICORE_INS_RSLCX: {
		return SEQ3(
			BRANCH(IS_ZERO(BITS32(VARG("PCXI"), 0, 20)), trap(CSU), NOP()),
			BRANCH(EQ(PCXI_UL(ctx->mode), U32(1)), trap(CTYP), NOP()),
			SEQN(20,
				SETL("EA", EA_PCXI()),
				SETG("d7", LOADW(Word_b, VARL("EA"))),
				SETG("d6", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B)))),
				SETG("d5", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 2)))),
				SETG("d4", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 3)))),
				SETG("a7", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 4)))),
				SETG("a6", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 5)))),
				SETG("a5", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 6)))),
				SETG("a4", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 7)))),
				SETG("d3", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 8)))),
				SETG("d2", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 9)))),
				SETG("d1", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 10)))),
				SETG("d0", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 11)))),
				SETG("a3", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 12)))),
				SETG("a2", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 13)))),
				SETG("a11", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 14)))),
				SETL("new_PCXI", LOADW(Word_b, ADD(VARL("EA"), U32(Word_B * 15)))),
				STOREW(VARL("EA"), VARG("FCX")),
				SETG("FCX", BITS32_U(VARG("FCX"), 0, 20, BITS32(VARG("PCXI"), 0, 20))),
				SETG("PCXI", VARL("new_PCXI"))));
	}
	case TRICORE_INS_SVLCX: {
		return SEQ2(
			BRANCH(IS_ZERO(VARG("FCX")), trap(FCU), NOP()),
			SEQN(10,
				SETL("tmp_FCX", VARG("FCX")),
				SETL("EA", EA_PCXI()),
				SETL("new_FCX", LOADW(Word_b, VARL("EA"))),
				ST_MB(VARL("EA"), 16,
					VARG("d7"), VARG("d6"), VARG("d5"), VARG("d4"), VARG("a7"), VARG("a6"), VARG("a5"), VARG("a4"), VARG("d3"), VARG("d2"), VARG("d1"), VARG("d0"), VARG("a3"), VARG("a2"), VARG("a11"), VARG("PCXI")),
				set_PCXI_PCPN(ctx->mode, ICR_CCPN()),
				set_PCXI_PIE(ctx->mode, ICR_IE()),
				set_PCXI_UL(ctx->mode, U32(0)),
				SETG("PCXI", BITS32_U(VARG("PCXI"), 0, 20, BITS32(VARG("FCX"), 0, 20))),
				SETG("FCX", BITS32_U(VARG("FCX"), 0, 20, BITS32(VARL("new_FCX"), 0, 20))),
				BRANCH(EQ(VARL("tmp_FCX"), VARG("LCX")), trap(FCD), NOP())));
	}
	case TRICORE_INS_CACHEA_I:
	case TRICORE_INS_CACHEA_WI:
	case TRICORE_INS_CACHEA_W:
	case TRICORE_INS_CACHEI_I:
	case TRICORE_INS_CACHEI_WI:
	case TRICORE_INS_CACHEI_W: return NOP();
	case TRICORE_INS_CLO_B: return e_BS(ctx, Byte_b, leading_ones);
	case TRICORE_INS_CLO_H: return e_BS(ctx, HalfWord_b, leading_ones);
	case TRICORE_INS_CLO: return e_BS(ctx, Word_b, leading_ones);
	case TRICORE_INS_CLS_B: return e_BS(ctx, Byte_b, leading_signs);
	case TRICORE_INS_CLS_H: return e_BS(ctx, HalfWord_b, leading_signs);
	case TRICORE_INS_CLS: return e_BS(ctx, Word_b, leading_signs);
	case TRICORE_INS_CLZ_B: return e_BS(ctx, Byte_b, leading_zeros);
	case TRICORE_INS_CLZ_H: return e_BS(ctx, HalfWord_b, leading_zeros);
	case TRICORE_INS_CLZ: return e_BS(ctx, Word_b, leading_zeros);

	case TRICORE_INS_CRC32B_W:
		return SEQ6(
			SETL("A", reflect(BITS32(VARG(R(2)), 24, 8), 8)),
			SETL("B", reflect(BITS32(VARG(R(2)), 16, 8), 8)),
			SETL("C", reflect(BITS32(VARG(R(2)), 8, 8), 8)),
			SETL("D", reflect(BITS32(VARG(R(2)), 0, 8), 8)),
			SETL("crc_in", LOGXOR(LOGOR(SHL0(VARL("A"), 24), LOGOR(SHL0(VARL("B"), 16), LOGOR(SHL0(VARL("C"), 8), VARL("D")))), LOGNOT(reflect(VARG(R(1)), 32)))),
			SETG(R(0), LOGNOT(reflect(crc_div(VARL("crc_in"), U32(CRC_32_GENERATOR), U32(32), U32(32)), 32))));
	case TRICORE_INS_CRC32L_W:
		return SEQ6(
			SETL("A", reflect(BITS32(VARG(R(2)), 0, 8), 8)),
			SETL("B", reflect(BITS32(VARG(R(2)), 8, 8), 8)),
			SETL("C", reflect(BITS32(VARG(R(2)), 16, 8), 8)),
			SETL("D", reflect(BITS32(VARG(R(2)), 24, 8), 8)),
			SETL("crc_in", LOGXOR(LOGOR(SHL0(VARL("A"), 24), LOGOR(SHL0(VARL("B"), 16), LOGOR(SHL0(VARL("C"), 8), VARL("D")))), LOGNOT(reflect(VARG(R(1)), 32)))),
			SETG(R(0), LOGNOT(reflect(crc_div(VARL("crc_in"), U32(CRC_32_GENERATOR), U32(32), U32(32)), 32))));
	case TRICORE_INS_CRC32_B:
		return SEQ3(SETL("A", reflect(BITS32(VARG(R(2)), 0, 8), 8)),
			SETL("crc_in", LOGXOR(SHL0(VARL("A"), 24), LOGNOT(reflect(VARG(R(1)), 32)))),
			SETG(R(0), LOGNOT(reflect(crc_div(VARL("crc_in"), U32(CRC_32_GENERATOR), U32(32), U32(8)), 32))));
	case TRICORE_INS_CRCN: {
		RzAnalysisLiftedILOp e = SEQ2(
			SETL("N", ADD(BITS32(VARG(R(2)), 12, 4), U32(1))),
			SETL("GEN", EXTRACT32(VARG(R(2)), U32(16), SUB(ADD(U32(16), VARL("N")), U32(1)))));
		f_cons(e, SETL("INV", BIT32(VARG(R(1)), 9)));
		f_cons(e, SETL("LITTLE_E", BIT32(VARG(R(1)), 8)));
		f_cons(e, SETL("M", ADD(BITS32(VARG(R(2)), 0, 3), U32(1))));
		f_cons(e, SETL("data", EXTRACT32(VARG(R(3)), U32(0), SUB(VARL("M"), U32(1)))));
		f_cons(e, BRANCH(VARL("LITTLE_E"), reverseV("data", VARL("data"), VARL("M")), NOP()));
		f_cons(e, SETL("seed", EXTRACT32(VARG(R(1)), U32(0), SUB(VARL("N"), U32(1)))));
		f_cons(e, BRANCH(VARL("INV"), SETL("seed", LOGNOT(VARL("seed"))), NOP()));
		f_cons(e, SETL("crc_in", ITE(ULE(VARL("N"), VARL("M")), EXTRACT32(LOGXOR(VARL("data"), SHIFTL0(VARL("seed"), SUB(VARL("M"), VARL("N")))), U32(0), SUB(VARL("M"), U32(1))), EXTRACT32(LOGXOR(VARL("seed"), SHIFTL0(VARL("data"), SUB(VARL("N"), VARL("M")))), U32(0), SUB(VARL("M"), U32(1))))));
		f_cons(e, SETL("result", crc_div(VARL("crc_in"), VARL("GEN"), VARL("N"), VARL("M"))));
		f_cons(e, BRANCH(VARL("INV"), SETL("result", LOGNOT(VARL("result"))), NOP()));
		f_cons(e, SETG(R(0), EXTRACT32(VARL("result"), U32(0), SUB(VARL("N"), U32(1)))));
		return e;
	}
	case TRICORE_INS_DIV: return lift_div(ctx);
	case TRICORE_INS_DIV_U: return lift_div_u(ctx);
	case TRICORE_INS_DEBUG:
	case TRICORE_INS_NOP: return NOP();
	case TRICORE_INS_DEXTR:
	case TRICORE_INS_EXTR_U:
	case TRICORE_INS_EXTR: {
		switch (OPC1) {
		case 0x77: {
			switch (extract32(ctx->word, 21, 3)) {
			case /*DEXTR(RRPW)*/ 0x00: return SETG(R(0), UNSIGNED(32, SHR0(APPEND(VARG(R(1)), SHL0(VARG(R(2)), I(3))), 32)));
			default: break;
			}
			break;
		}
		case 0x37: {
			switch (extract32(ctx->word, 21, 2)) {
			case /*EXTR(RRPW)*/ 0x02: return SETG(R(0), SEXT32(UNSIGNED(I(3), SHR0(VARG(R(1)), I(2))), I(3)));
			case /*EXTR.U(RRPW)*/ 0x03: return SETG(R(0), BITS32(SHR0(VARG(R(1)), I(2)), 0, I(3)));
			default: break;
			}
			break;
		}
		case 0x17: {
			switch (extract32(ctx->word, 21, 3)) {
			case /*DEXTR(RRRR)*/ 0x04: return SETG(R(0), UNSIGNED(32, SHR0(APPEND(VARG(R(1)), SHIFTL0(VARG(R(2)), BITS32(VARG(R(3)), 0, 5))), 32)));
			case /*EXTR(RRRR)*/ 0x02:
				return SETG(R(0),
					LET("width", BITS32(VARG_SUB(R(2), 1), 0, 5),
						SEXTRACT32(EXTRACT32(SHIFTR0(VARG(R(1)), BITS32(VARG_SUB(R(2), 0), 0, 5)), U32(0), VARLP("width")), U32(0), VARLP("width"))));
			case /*EXTR.U(RRRR)*/ 0x03:
				return SETG(R(0),
					LET("width", BITS32(VARG_SUB(R(2), 1), 0, 5),
						EXTRACT32(SHIFTR0(VARG(R(1)), BITS32(VARG_SUB(R(2), 0), 0, 5)), U32(0), VARLP("width"))));

			default: break;
			}
			break;
		}
		case 0x57: {
			switch (extract32(ctx->word, 21, 3)) {
			case /*EXTR(RRRR)*/ 0x02:
				return SETG(R(0),
					SEXTRACT32(EXTRACT32(SHIFTR0(VARG(R(1)), BITS32(VARG(R(2)), 0, 5)), U32(0), U32(I(3))), U32(0), U32(I(3))));
			case /*EXTR.U(RRRR)*/ 0x03:
				return SETG(R(0),
					EXTRACT32(SHIFTR0(VARG(R(1)), BITS32(VARG(R(2)), 0, 5)), U32(0), U32(I(3))));
			default: break;
			}
			break;
		}
		}
		break;
	}
	case TRICORE_INS_INSERT:
	case TRICORE_INS_IMASK: {
		switch (OPC1) {
		case 0xb7: {
			switch (extract32(ctx->word, 21, 2)) {
			case /*INSERT(RCPW)*/ 0x00:
				return SETG(R(0),
					LET("mask",
						SHL0(U32((1 << I(4)) - 1), I(3)),
						LOGOR(LOGAND(VARG(R(1)), LOGNOT(VARLP("mask"))),
							LOGAND(SHL0(U32(I(2)), I(3)), VARLP("mask")))));
			case /*IMASK(RCPW)*/ 0x01: return SETG(R(0), APPEND(SHL0(U32((1 << I(3)) - 1), I(2)), SHL0(U32(I(1)), I(2))));
			default: break;
			}
			break;
		}
		case 0xd7: {
			switch (extract32(ctx->word, 21, 3)) {
			case /*INSERT(RCRW)*/ 0x00:
				return SETG(R(0),
					LET("mask",
						SHIFTL0(U32((1 << I(4)) - 1), BITS32(VARG(R(3)), 0, 5)),
						LOGOR(LOGAND(VARG(R(1)), LOGNOT(VARLP("mask"))),
							LOGAND(SHIFTL0(U32(I(2)), BITS32(VARG(R(3)), 0, 5)), VARLP("mask")))));

			case /*IMASK(RCRW)*/ 0x01:
				return SETG(R(0), APPEND(SHIFTL0(U32((1ULL << I(3)) - 1), BITS32(VARG(R(2)), 0, 5)), SHIFTL0(U32(I(1)), BITS32(VARG(R(2)), 0, 5))));
			default: break;
			}
			break;
		}
		case 0x37: {
			switch (extract32(ctx->word, 21, 2)) {
			case /*INSERT(RRPW)*/ 0x00: return SETG(R(0),
				LET("mask",
					SHL0(U32((1 << I(4)) - 1), I(3)),
					LOGOR(LOGAND(VARG(R(1)), LOGNOT(VARLP("mask"))),
						LOGAND(SHL0(VARG(R(2)), I(3)), VARLP("mask")))));

			case /*IMASK(RRPW)*/ 0x01: return SETG(R(0), APPEND(SHL0(U32((1 << I(3)) - 1), I(2)), SHL0(VARG(R(1)), I(2))));
			default: break;
			}
			break;
		}
		case 0x17: {
			switch (extract32(ctx->word, 21, 3)) {
			case /*INSERT(RRRR)*/ 0x00:
				return SETG(R(0),
					LET("width",
						BITS32(VARG_SUB(R(3), 1), 0, 5),
						LET("mask",
							SHIFTL0(SUB(SHIFTL0(U32(1), VARLP("width")), U32(1)), BITS32(VARG_SUB(R(3), 0), 0, 5)),
							LOGOR(LOGAND(VARG(R(1)), LOGNOT(VARLP("mask"))),
								LOGAND(SHIFTL0(VARG(R(2)), BITS32(VARG_SUB(R(3), 0), 0, 5)), VARLP("mask"))))));
			default: break;
			}
			break;
		}
		case 0x57: {
			switch (extract32(ctx->word, 21, 3)) {
			case /*INSERT(RRRW)*/ 0x00:
				return SETG(R(0),
					LET("mask",
						SHIFTL0(SUB(SHIFTL0(U32(1), U32(I(4))), U32(1)), BITS32(VARG(R(3)), 0, 5)),
						LOGOR(LOGAND(VARG(R(1)), LOGNOT(VARLP("mask"))),
							LOGAND(SHIFTL0(VARG(R(2)), BITS32(VARG(R(3)), 0, 5)), VARLP("mask")))));
			case /*IMASK(RRRW)*/ 0x01:
				return SETG(R(0), APPEND(SHIFTL0(U32((1 << I(3)) - 1), BITS32(VARG(R(2)), 0, 5)), SHIFTL0(VARG(R(1)), BITS32(VARG(R(2)), 0, 5))));
			default: break;
			}
			break;
		}
		case 0x97: {
			switch (extract32(ctx->word, 21, 3)) {
			case /*INSERT(RCRR)*/ 0x00:
				return SETG(R(0),
					LET("width",
						BITS32(VARG_SUB(R(3), 1), 0, 5),
						LET("mask",
							SHIFTL0(SUB(SHIFTL0(U32(1), VARLP("width")), U32(1)), BITS32(VARG_SUB(R(3), 0), 0, 5)),
							LOGOR(LOGAND(VARG(R(1)), LOGNOT(VARLP("mask"))),
								LOGAND(SHIFTL0(U32(I(2)), BITS32(VARG_SUB(R(3), 0), 0, 5)), VARLP("mask"))))));
			default: break;
			}
			break;
		}
		}
		break;
	}
	case TRICORE_INS_DIFSC_A: NOT_IMPLEMENTED;
	case TRICORE_INS_DVINIT_BU:
	case TRICORE_INS_DVINIT_B:
	case TRICORE_INS_DVINIT_HU:
	case TRICORE_INS_DVINIT_H:
	case TRICORE_INS_DVINIT_U:
	case TRICORE_INS_DVINIT: return lift_dvinit(ctx);
	case TRICORE_INS_DVADJ: return lift_dvadj(ctx);
	case TRICORE_INS_DVSTEP_U: return lift_dvstep_u(ctx);
	case TRICORE_INS_DVSTEP: return lift_dvstep(ctx);

	case TRICORE_INS_IXMAX_U:
	case TRICORE_INS_IXMAX:
	case TRICORE_INS_IXMIN_U:
	case TRICORE_INS_IXMIN: {
		RzILOpEffect *e = SEQ2(SETL("Ec15_0", MOD(ADD(BITS32(VARG_SUB(R(1), 0), 0, 16), U32(2)), U32(65535))),
			SETL("Ec63_48", U32(0)));
		f_cons(e, SETL("Ec47_32", BITS32(VARG_SUB(R(0), 1), 0, 16)));
		f_cons(e, SETL("Ec31_16", BITS32(VARG_SUB(R(0), 0), 16, 16)));
		f_cons(e, SETL("Db31_16", BITS32(VARG(R(2)), 16, 16)));
		f_cons(e, SETL("Db15_0", BITS32(VARG(R(2)), 0, 16)));
		f_cons(e, SETL("Ed47_32", BITS32(VARG_SUB(R(1), 1), 0, 16)));
		f_cons(e, SETL("Ed31_16", BITS32(VARG_SUB(R(1), 0), 16, 16)));
		f_cons(e, SETL("Ed15_0", BITS32(VARG_SUB(R(1), 0), 0, 16)));
		FUNC_OP2 f1 = (ctx->insn->id == TRICORE_INS_IXMAX || ctx->insn->id == TRICORE_INS_IXMAX_U) ? rz_il_op_new_uge : rz_il_op_new_ule;
		FUNC_OP2 f2 = (ctx->insn->id == TRICORE_INS_IXMAX || ctx->insn->id == TRICORE_INS_IXMAX_U) ? rz_il_op_new_ugt : rz_il_op_new_ult;
		f_cons(e,
			BRANCH(AND(f1(VARL("Db15_0"), VARL("Db31_16")), f2(VARL("Db15_0"), VARL("Ed47_32"))),
				SEQ2(SETL("Ec47_32", VARL("Db15_0")), SETL("Ec31_16", VARL("Ed15_0"))),
				BRANCH(AND(f2(VARL("Db31_16"), VARL("Db15_0")), f2(VARL("Db31_16"), VARL("Ed47_32"))),
					SEQ2(SETL("Ec47_32", VARL("Db31_16")), SETL("Ec31_16", MOD(ADD(VARL("Ed15_0"), U32(1)), U32(65535)))),
					SEQ2(SETL("Ec47_32", VARL("Ed47_32")), SETL("Ec31_16", VARL("Ed31_16"))))));
		f_cons(e, SETG(R(0), APPEND(packed_2halfword(VARL("Ec63_48"), VARL("Ec47_32")), packed_2halfword(VARL("Ec31_16"), VARL("Ec15_0")))));
		return e;
	}

	case TRICORE_INS_JA: return JMP(EA_disp24(I(0)));
	case TRICORE_INS_J:
		switch (OPC1) {
		case 0x1d:
		case 0x3c: return JMP(U32(I(0)));
		default: break;
		}
		break;
	case TRICORE_INS_JI: return JMP(LOGAND(VARG(R(0)), U32(0xfffffffe)));
	case TRICORE_INS_JL:
		return SEQ2(
			SETG("a11", U32(PC_NEXT)),
			JMP(U32(I(0))));
	case TRICORE_INS_JLA:
		return SEQ2(
			SETG("a11", U32(PC_NEXT)),
			JMP(EA_disp24(I(0))));
	case TRICORE_INS_JLEZ: return BRANCH(SLE(VARG(R(0)), S32(0)), JMP(U32(I(1))), NOP());
	case TRICORE_INS_JLI:
		return SEQ2(
			SETG("a11", U32(PC_NEXT)),
			JMP(LOGAND(VARG(R(0)), U32(0xfffffffe))));
	case TRICORE_INS_JLT:
		switch (OPC1) {
		case 0xbf: return BRANCH(SLT(VARG(R(0)), sign_ext32_bv(I(1), 4)), JMP(U32(I(2))), NOP());
		case 0x3f: return BRANCH(SLE(VARG(R(0)), VARG(R(1))), JMP(U32(I(2))), NOP());
		default: break;
		}
		break;
	case TRICORE_INS_JLT_U:
		switch (OPC1) {
		case 0xbf: return BRANCH(ULT(VARG(R(0)), U32(I(1))), JMP(U32(I(2))), NOP());
		case 0x3f: return BRANCH(ULE(VARG(R(0)), VARG(R(1))), JMP(U32(I(2))), NOP());
		default: break;
		}
		break;
	case TRICORE_INS_JLTZ: return BRANCH(SLT(VARG(R(0)), S32(0)), JMP(U32(I(1))), NOP());
	case TRICORE_INS_JNE:
		switch (OPC1) {
		case 0xdf: return BRANCH(NE(VARG(R(0)), sign_ext32_bv(I(1), 4)), JMP(U32(I(2))), NOP());
		case 0x5f: return BRANCH(NE(VARG(R(0)), VARG(R(1))), JMP(U32(I(2))), NOP());
		case 0x5e:
		case 0xde: return BRANCH(NE(VARG("d15"), sign_ext32_bv(I(0), 4)), JMP(U32(I(1))), NOP());
		case 0x7e:
		case 0xfe: return BRANCH(NE(VARG("d15"), VARG(R(0))), JMP(U32(I(1))), NOP());
		default: break;
		}
		break;
	case TRICORE_INS_JNE_A: return BRANCH(NE(VARG(R(0)), VARG(R(1))), JMP(U32(I(2))), NOP());
	case TRICORE_INS_JNED:
		switch (OPC1) {
		case 0x9f: return SEQ3(
			SETL("PC", ITE(NE(VARG(R(0)), sign_ext32_bv(I(1), 4)), U32(I(2)), U32(PC_NEXT))),
			SETG(R(0), SUB(VARG(R(0)), S32(1))),
			JMP(VARL("PC")));
		case 0x1f: return SEQ3(
			SETL("PC", ITE(NE(VARG(R(0)), VARG(R(1))), U32(I(2)), U32(PC_NEXT))),
			SETG(R(0), SUB(VARG(R(0)), S32(1))),
			JMP(VARL("PC")));
		default: break;
		}
		break;
	case TRICORE_INS_JNEI:
		switch (OPC1) {
		case 0x9f: return SEQ3(
			SETL("PC", ITE(NE(VARG(R(0)), sign_ext32_bv(I(1), 4)), U32(I(2)), U32(PC_NEXT))),
			SETG(R(0), ADD(VARG(R(0)), S32(1))),
			JMP(VARL("PC")));
		case 0x1f: return SEQ3(
			SETL("PC", ITE(NE(VARG(R(0)), VARG(R(1))), U32(I(2)), U32(PC_NEXT))),
			SETG(R(0), ADD(VARG(R(0)), S32(1))),
			JMP(VARL("PC")));
		default: break;
		}
		break;
	case TRICORE_INS_JNZ_A:
		switch (OPC1) {
		case 0xbd: return BRANCH(NE(VARG(R(0)), U32(0)), JMP(U32(I(1))), NOP());
		case 0x7c: return BRANCH(NE(VARG(R(0)), U32(0)), JMP(U32(I(1))), NOP());
		default: break;
		}
		break;
	case TRICORE_INS_JNZ_T:
		if (OPC1_BRN == 0x6f) {
			return BRANCH(BIT32(VARG(R(0)), I(1)), JMP(U32(I(2))), NOP());
		}
		if (OPC1 == 0xae) {
			return BRANCH(BIT32(VARG("d15"), I(0)), JMP(U32(I(1))), NOP());
		}
		break;
	case TRICORE_INS_JNZ:
		switch (OPC1) {
		case 0xee: return BRANCH(NE(VARG("d15"), U32(0)), JMP(U32(I(0))), NOP());
		case 0xf6: return BRANCH(NE(VARG(R(0)), U32(0)), JMP(U32(I(1))), NOP());
		default: break;
		}
		break;
	case TRICORE_INS_JEQ:
		switch (OPC1) {
		case 0xdf: return BRANCH(EQ(VARG(R(0)), sign_ext32_bv(I(1), 4)), JMP(U32(I(2))), NOP());
		case 0x5f: return BRANCH(EQ(VARG(R(0)), VARG(R(1))), JMP(U32(I(2))), NOP());
		case 0x1e:
		case 0x9e: return BRANCH(EQ(VARG("d15"), sign_ext32_bv(I(0), 4)), JMP(U32(I(1))), NOP());
		case 0x3e:
		case 0xbe: return BRANCH(EQ(VARG("d15"), VARG(R(0))), JMP(U32(I(1))), NOP());
		default: break;
		}
		break;
	case TRICORE_INS_JEQ_A: return BRANCH(EQ(VARG(R(0)), VARG(R(1))), JMP(U32(I(2))), NOP());
	case TRICORE_INS_JGE:
		switch (OPC1) {
		case 0xff: return BRANCH(SGE(VARG(R(0)), sign_ext32_bv(I(1), 4)), JMP(U32(I(2))), NOP());
		case 0x7f: return BRANCH(SGE(VARG(R(0)), VARG(R(1))), JMP(U32(I(2))), NOP());
		default: break;
		}
		break;
	case TRICORE_INS_JGE_U:
		switch (OPC1) {
		case 0xff: return BRANCH(UGE(VARG(R(0)), U32(I(1))), JMP(U32(I(2))), NOP());
		case 0x7f: return BRANCH(UGE(VARG(R(0)), VARG(R(1))), JMP(U32(I(2))), NOP());
		default: break;
		}
		break;
	case TRICORE_INS_JGEZ: return BRANCH(UGE(VARG(R(0)), U32(0)), JMP(U32(I(1))), NOP());
	case TRICORE_INS_JGTZ: return BRANCH(UGT(VARG(R(0)), U32(0)), JMP(U32(I(1))), NOP());
	case TRICORE_INS_JZ:
		switch (OPC1) {
		case 0x6e: return BRANCH(EQ(VARG("d15"), U32(0)), JMP(U32(I(0))), NOP());
		case 0x76: return BRANCH(IS_ZERO(VARG(R(0))), JMP(U32(I(1))), NOP());
		default: break;
		}
		break;
	case TRICORE_INS_JZ_A:
		switch (OPC1) {
		case 0xbd: return BRANCH(EQ(VARG(R(0)), U32(0)), JMP(U32(I(1))), NOP());
		case 0xbc: return BRANCH(IS_ZERO(VARG(R(0))), JMP(U32(I(1))), NOP());
		default: break;
		}
		break;
	case TRICORE_INS_JZ_T: {
		if (OPC1_BRN == 0x6f) {
			return BRANCH(INV(BIT32(VARG(R(0)), I(1))), JMP(U32(I(2))), NOP());
		}
		if (OPC1 == 0x2e) {
			return BRANCH(INV(BIT32(VARG("d15"), I(0))), JMP(U32(I(1))), NOP());
		}
		break;
	}
	case TRICORE_INS_LDLCX:
	case TRICORE_INS_LDUCX:
	case TRICORE_INS_LEA:
	case TRICORE_INS_LHA:
	case TRICORE_INS_LD_A:
	case TRICORE_INS_LD_BU:
	case TRICORE_INS_LD_B:
	case TRICORE_INS_LD_DA:
	case TRICORE_INS_LD_D:
	case TRICORE_INS_LD_HU:
	case TRICORE_INS_LD_H:
	case TRICORE_INS_LD_Q:
	case TRICORE_INS_LD_W:
		return lift_ld_op(ctx);
	case TRICORE_INS_LOOPU: return JMP(U32(I(0)));
	case TRICORE_INS_LOOP: {
		switch (OPC1) {
		case 0xfd:
		case 0xfc: return SEQ3(
			SETL("PC", ITE(NON_ZERO(VARG(R(0))), U32(I(1)), U32(PC_NEXT))),
			SETG(R(0), SUB(VARG(R(0)), U32(1))),
			JMP(VARL("PC")));
		default: break;
		}
		break;
	}
	case TRICORE_INS_LT_A: return SETG(R(0), BOOL_TO_BV(ULT(VARG(R(1)), VARG(R(2))), 32));
	case TRICORE_INS_NE_A: return SETG(R(0), BOOL_TO_BV(NE(VARG(R(1)), VARG(R(2))), 32));
	case TRICORE_INS_NEZ_A: return SETG(R(0), BOOL_TO_BV(NE(VARG(R(1)), U32(0)), 32));
	case TRICORE_INS_GE_A: return SETG(R(0), BOOL_TO_BV(UGE(VARG(R(1)), VARG(R(2))), 32));
	case TRICORE_INS_EQZ_A: return SETG(R(0), BOOL_TO_BV(EQ(VARG(R(1)), U32(0)), 32));
	case TRICORE_INS_EQ_A: return SETG(R(0), BOOL_TO_BV(EQ(VARG(R(1)), VARG(R(2))), 32));
	case TRICORE_INS_ADDSC_A:
	case TRICORE_INS_ADDSC_AT:
	case TRICORE_INS_ADD_A:
	case TRICORE_INS_SUB_A:
	case TRICORE_INS_MOV_A:
	case TRICORE_INS_MOV_AA:
	case TRICORE_INS_MOV_D: {
		switch (ctx->insn->bytes[0]) {
		case 0x01: {
			switch (extract32(ctx->word, 20, 8)) {
			case /*MOV.A RR*/ 0x63:
			case /*MOV.AA RR*/ 0x00:
			case /*MOV.D RR*/ 0x4c: return SETG(R(0), VARG(R(1)));
			case /*ADD.A RR*/ 0x01: return SETG(R(0), ADD(VARG(R(1)), VARG(R(2))));
			case /*SUB.A RR*/ 0x02: return SETG(R(0), SUB(VARG(R(1)), VARG(R(2))));
			case /*ADDSC.A RR*/ 0x60: return SETG(R(0), ADD(VARG(R(1)), SHL0(VARG(R(2)), I(3))));
			case /*ADDSC.AT RR*/ 0x62: return SETG(R(0), LOGAND(ADD(VARG(R(1)), SHIFTR0(VARG(R(2)), U32(3))), U32(0xfffffffc)));
			default: break;
			}
			break;
		}
		case /*MOV.A SRC*/ 0xa0: return SETG(R(0), U32(I(1)));
		case /*MOV.A SRR*/ 0x60:
		case /*MOV.AA SRR*/ 0x40:
		case /*MOV.D SRR*/ 0x80: return SETG(R(0), VARG(R(1)));
		case /*ADD.A SRC*/ 0xb0: return SETG(R(0), ADD(VARG(R(0)), U32(I(1))));
		case /*ADD.A SRR*/ 0x30: return SETG(R(0), ADD(VARG(R(0)), VARG(R(1))));
		case /*SUB.A SC*/ 0x20: return SETG("a10", SUB(VARG("a10"), U32(I(0))));
		default:
			if (extract32(ctx->word, 0, 6) == 0x10) {
				/*ADDSC.A SRRS*/
				return SETG(R(0), ADD(VARG(R(1)), SHL0(VARG("d15"), I(2))));
			}
			break;
		}
		rz_warn_if_reached();
		return NULL;
	}
	case TRICORE_INS_MOV: {
		switch (OPC1) {
		case 0x3b: return SETG(R(0), sign_ext32_bv(I(1), 16));
		case 0xfb: return SETG(R(0), sign_ext64_bv(I(1), 16));
		case 0x0b: {
			switch (extract32(ctx->word, 20, 8)) {
			case 0x1f: return SETG(R(0), VARG(R(1)));
			case 0x80: return SETG(R(0), SEXT64(UNSIGNED(64, VARG(R(1))), 32));
			case 0x81: return SETG(R(0), APPEND(VARG(R(1)), VARG(R(2))));
			}
			break;
		}
		case 0xda: return SETG("d15", U32(I(0)));
		case 0x82: return SETG(R(0), sign_ext32_bv(I(1), 4));
		case 0xd2: return SETG(R(0), sign_ext64_bv(I(1), 4));
		case 0x02: return SETG(R(0), VARG(R(1)));
		}
		break;
	}
	case TRICORE_INS_LT_B: return packed_op2_cmp(R(0), VARG(R(1)), VARG(R(2)), Byte_b, rz_il_op_new_slt);
	case TRICORE_INS_LT_BU: return packed_op2_cmp(R(0), VARG(R(1)), VARG(R(2)), Byte_b, rz_il_op_new_ult);
	case TRICORE_INS_LT_H: return packed_op2_cmp(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_slt);
	case TRICORE_INS_LT_HU: return packed_op2_cmp(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_ult);
	case TRICORE_INS_LT_W: return SETG(R(0), f_op2_cmp(VARG(R(1)), VARG(R(2)), 0, Word_b, rz_il_op_new_slt));
	case TRICORE_INS_LT_WU: return SETG(R(0), f_op2_cmp(VARG(R(1)), VARG(R(2)), 0, Word_b, rz_il_op_new_ult));
	case TRICORE_INS_EQ_B: return packed_op2_cmp(R(0), VARG(R(1)), VARG(R(2)), Byte_b, rz_il_op_new_eq);
	case TRICORE_INS_EQ_H: return packed_op2_cmp(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_eq);
	case TRICORE_INS_EQ_W: return packed_op2_cmp(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_eq);
	case TRICORE_INS_LT:
	case TRICORE_INS_LT_U:
	case TRICORE_INS_GE:
	case TRICORE_INS_GE_U:
	case TRICORE_INS_NE:
	case TRICORE_INS_EQ:
	case TRICORE_INS_EQANY_B:
	case TRICORE_INS_EQANY_H:

	case TRICORE_INS_RSUBS_U:
	case TRICORE_INS_RSUBS:
	case TRICORE_INS_RSUB:

	case TRICORE_INS_XOR_EQ:
	case TRICORE_INS_XOR_GE:
	case TRICORE_INS_XOR_GE_U:
	case TRICORE_INS_XOR_LT:
	case TRICORE_INS_XOR_LT_U:
	case TRICORE_INS_XOR_NE:

	case TRICORE_INS_AND_EQ:
	case TRICORE_INS_AND_GE:
	case TRICORE_INS_AND_GE_U:
	case TRICORE_INS_AND_LT:
	case TRICORE_INS_AND_LT_U:
	case TRICORE_INS_AND_NE:

	case TRICORE_INS_OR_EQ:
	case TRICORE_INS_OR_GE_U:
	case TRICORE_INS_OR_GE:
	case TRICORE_INS_OR_LT_U:
	case TRICORE_INS_OR_LT:
	case TRICORE_INS_OR_NE:

	case TRICORE_INS_SH_EQ:
	case TRICORE_INS_SH_NE:
	case TRICORE_INS_SH_GE_U:
	case TRICORE_INS_SH_GE:
	case TRICORE_INS_SH_LT_U:
	case TRICORE_INS_SH_LT:

	case TRICORE_INS_MAX_B:
	case TRICORE_INS_MAX_BU:
	case TRICORE_INS_MAX_H:
	case TRICORE_INS_MAX_HU:
	case TRICORE_INS_MAX_U:
	case TRICORE_INS_MAX:

	case TRICORE_INS_MIN_B:
	case TRICORE_INS_MIN_BU:
	case TRICORE_INS_MIN_H:
	case TRICORE_INS_MIN_HU:
	case TRICORE_INS_MIN_U:
	case TRICORE_INS_MIN: {
		switch (OPC1) {
		case 0x8b:
			switch (extract32(ctx->word, 21, 7)) {
			case /*EQ(RC)*/ 0x10: return SETG(R(0), BOOL_TO_BV32(EQ(VARG(R(1)), sign_ext32_bv(I(2), 9))));
			case /*NE(RC)*/ 0x11: return SETG(R(0), BOOL_TO_BV32(NE(VARG(R(1)), sign_ext32_bv(I(2), 9))));
			case /*LT(RC)*/ 0x12: return SETG(R(0), BOOL_TO_BV32(SLT(VARG(R(1)), sign_ext32_bv(I(2), 9))));
			case /*LT.U(RC)*/ 0x13: return SETG(R(0), BOOL_TO_BV32(ULT(VARG(R(1)), U32(I(2)))));
			case /*GE(RC)*/ 0x14: return SETG(R(0), BOOL_TO_BV32(SGE(VARG(R(1)), sign_ext32_bv(I(2), 9))));
			case /*GE.U(RC)*/ 0x15: return SETG(R(0), BOOL_TO_BV32(UGE(VARG(R(1)), sign_ext32_bv(I(2), 9))));
			case /*EQANY.B(RC)*/ 0x56: return e_eqany(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), Byte_b);
			case /*EQANY.H(RC)*/ 0x76: return e_eqany(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), HalfWord_b);

			case /*RSUB(RC)*/ 0x08: return SETG(R(0), SUB(sign_ext32_bv(I(2), 9), VARG(R(1))));
			case /*RSUBS(RC)*/ 0xa: return SETG(R(0), ssov(SUB(sign_ext32_bv(I(2), 9), VARG(R(1))), U32(32)));
			case /*RSUBS.U(RC)*/ 0x0b: return SETG(R(0), suov(SUB(sign_ext32_bv(I(2), 9), VARG(R(1))), U32(32)));

			case /*MAX(RC)*/ 0x1a: return SETG(R(0), ITE(SGT(VARG(R(1)), sign_ext32_bv(I(2), 9)), VARG(R(1)), sign_ext32_bv(I(2), 9)));
			case /*MAX.U(RC)*/ 0x1b: return SETG(R(0), ITE(UGT(VARG(R(1)), U32(I(2))), VARG(R(1)), U32(I(2))));
			case /*MIN(RC)*/ 0x18: return SETG(R(0), ITE(SLT(VARG(R(1)), sign_ext32_bv(I(2), 9)), VARG(R(1)), sign_ext32_bv(I(2), 9)));
			case /*MIN.U(RC)*/ 0x19: return SETG(R(0), ITE(ULT(VARG(R(1)), U32(I(2))), VARG(R(1)), U32(I(2))));

			case /*AND.EQ(RC)*/ 0x20: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_and, rz_il_op_new_eq);
			case /*AND.NE(RC)*/ 0x21: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_and, rz_il_op_new_ne);
			case /*AND.GE(RC)*/ 0x24: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_and, rz_il_op_new_sge);
			case /*AND.GE.U(RC)*/ 0x25: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_and, rz_il_op_new_uge);
			case /*AND.LT(RC)*/ 0x22: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_and, rz_il_op_new_slt);
			case /*AND.LT.U(RC)*/ 0x23: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_and, rz_il_op_new_ult);

			case /*XOR.EQ(RC)*/ 0x2f: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_xor, rz_il_op_new_eq);
			case /*XOR.NE(RC)*/ 0x30: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_xor, rz_il_op_new_ne);
			case /*XOR.GE(RC)*/ 0x33: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_xor, rz_il_op_new_sge);
			case /*XOR.GE.U(RC)*/ 0x34: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_xor, rz_il_op_new_uge);
			case /*XOR.LT(RC)*/ 0x31: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_xor, rz_il_op_new_slt);
			case /*XOR.LT.U(RC)*/ 0x32: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_xor, rz_il_op_new_ult);

			case /*OR.EQ(RC)*/ 0x27: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_or, rz_il_op_new_eq);
			case /*OR.NE(RC)*/ 0x28: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_or, rz_il_op_new_ne);
			case /*OR.GE(RC)*/ 0x2b: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_or, rz_il_op_new_sge);
			case /*OR.GE.U(RC)*/ 0x2c: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_or, rz_il_op_new_uge);
			case /*OR.LT(RC)*/ 0x29: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_or, rz_il_op_new_slt);
			case /*OR.LT.U(RC)*/ 0x2a: return e_op_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_bool_or, rz_il_op_new_ult);

			case /*SH.EQ(RC)*/ 0x37: return e_sh_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_eq);
			case /*SH.NE(RC)*/ 0x38: return e_sh_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_ne);
			case /*SH.GE(RC)*/ 0x3b: return e_sh_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_sge);
			case /*SH.GE.U(RC)*/ 0x3c: return e_sh_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_uge);
			case /*SH.LT(RC)*/ 0x39: return e_sh_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_slt);
			case /*SH.LT.U(RC)*/ 0x3a: return e_sh_op(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), rz_il_op_new_ult);

			default: break;
			}
			break;
		case 0x0b:
			switch (extract32(ctx->word, 20, 8)) {
			case /*EQ(RR)*/ 0x10: return SETG(R(0), BOOL_TO_BV32(EQ(VARG(R(1)), VARG(R(2)))));
			case /*NE(RR)*/ 0x11: return SETG(R(0), BOOL_TO_BV32(NE(VARG(R(1)), VARG(R(2)))));
			case /*LT(RR)*/ 0x12: return SETG(R(0), BOOL_TO_BV32(SLT(VARG(R(1)), VARG(R(2)))));
			case /*LT.U(RR)*/ 0x13: return SETG(R(0), BOOL_TO_BV32(ULT(VARG(R(1)), VARG(R(2)))));
			case /*GE(RR)*/ 0x14: return SETG(R(0), BOOL_TO_BV32(SGE(VARG(R(1)), VARG(R(2)))));
			case /*GE.U(RR)*/ 0x15: return SETG(R(0), BOOL_TO_BV32(UGE(VARG(R(1)), VARG(R(2)))));
			case /*EQANY.B(RR)*/ 0x56: return e_eqany(R(0), VARG(R(1)), VARG(R(2)), Byte_b);
			case /*EQANY.H(RR)*/ 0x76: return e_eqany(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b);

			case /*MAX(RR)*/ 0x1a: return SETG(R(0), ITE(SGT(VARG(R(1)), VARG(R(2))), VARG(R(1)), VARG(R(2))));
			case /*MAX.U(RR)*/ 0x1b: return SETG(R(0), ITE(UGT(VARG(R(1)), VARG(R(2))), VARG(R(1)), VARG(R(2))));
			case /*MAX.B(RR)*/ 0x5a: return packed_op2_minmax(R(0), VARG(R(1)), VARG(R(2)), Byte_b, rz_il_op_new_sgt);
			case /*MAX.BU(RR)*/ 0x5b: return packed_op2_minmax(R(0), VARG(R(1)), VARG(R(2)), Byte_b, rz_il_op_new_ugt);
			case /*MAX.H(RR)*/ 0x7a: return packed_op2_minmax(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_sgt);
			case /*MAX.HU(RR)*/ 0x7b: return packed_op2_minmax(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_ugt);

			case /*MIN(RR)*/ 0x18: return SETG(R(0), ITE(SLT(VARG(R(1)), VARG(R(2))), VARG(R(1)), VARG(R(2))));
			case /*MIN.U(RR)*/ 0x19: return SETG(R(0), ITE(ULT(VARG(R(1)), VARG(R(2))), VARG(R(1)), VARG(R(2))));
			case /*MIN.B(RR)*/ 0x58: return packed_op2_minmax(R(0), VARG(R(1)), VARG(R(2)), Byte_b, rz_il_op_new_slt);
			case /*MIN.BU(RR)*/ 0x59: return packed_op2_minmax(R(0), VARG(R(1)), VARG(R(2)), Byte_b, rz_il_op_new_ult);
			case /*MIN.H(RR)*/ 0x78: return packed_op2_minmax(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_slt);
			case /*MIN.HU(RR)*/ 0x79: return packed_op2_minmax(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_ult);

			case /*AND.EQ(RR)*/ 0x20: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_and, rz_il_op_new_eq);
			case /*AND.NE(RR)*/ 0x21: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_and, rz_il_op_new_ne);
			case /*AND.GE(RR)*/ 0x24: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_and, rz_il_op_new_sge);
			case /*AND.GE.U(RR)*/ 0x25: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_and, rz_il_op_new_uge);
			case /*AND.LT(RR)*/ 0x22: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_and, rz_il_op_new_slt);
			case /*AND.LT.U(RR)*/ 0x23: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_and, rz_il_op_new_ult);

			case /*XOR.EQ(RR)*/ 0x2f: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_xor, rz_il_op_new_eq);
			case /*XOR.NE(RR)*/ 0x30: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_xor, rz_il_op_new_ne);
			case /*XOR.GE(RR)*/ 0x33: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_xor, rz_il_op_new_sge);
			case /*XOR.GE.U(RR)*/ 0x34: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_xor, rz_il_op_new_uge);
			case /*XOR.LT(RR)*/ 0x31: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_xor, rz_il_op_new_slt);
			case /*XOR.LT.U(RR)*/ 0x32: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_xor, rz_il_op_new_ult);

			case /*OR.EQ(RR)*/ 0x27: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_or, rz_il_op_new_eq);
			case /*OR.NE(RR)*/ 0x28: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_or, rz_il_op_new_ne);
			case /*OR.GE(RR)*/ 0x2b: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_or, rz_il_op_new_sge);
			case /*OR.GE.U(RR)*/ 0x2c: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_or, rz_il_op_new_uge);
			case /*OR.LT(RR)*/ 0x29: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_or, rz_il_op_new_slt);
			case /*OR.LT.U(RR)*/ 0x2a: return e_op_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_bool_or, rz_il_op_new_ult);

			case /*SH.EQ(RR)*/ 0x37: return e_sh_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_eq);
			case /*SH.NE(RR)*/ 0x38: return e_sh_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_ne);
			case /*SH.GE(RR)*/ 0x3b: return e_sh_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_sge);
			case /*SH.GE.U(RR)*/ 0x3c: return e_sh_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_uge);
			case /*SH.LT(RR)*/ 0x39: return e_sh_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_slt);
			case /*SH.LT.U(RR)*/ 0x3a: return e_sh_op(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_ult);

			default: break;
			}
			break;
		case /*LT(SRC)*/ 0xfa: return SETG("d15", BOOL_TO_BV32(SLT(VARG(R(0)), sign_ext32_bv(I(1), 4))));
		case /*LT(SRR)*/ 0x7a: return SETG("d15", BOOL_TO_BV32(SLT(VARG(R(0)), VARG(R(1)))));
		case /*EQ(SRC)*/ 0xba: return SETG("d15", BOOL_TO_BV32(EQ(VARG(R(0)), sign_ext32_bv(I(1), 4))));
		case /*EQ(SRR)*/ 0x3a: return SETG("d15", BOOL_TO_BV32(EQ(VARG(R(0)), VARG(R(1)))));
		case /*RSUB(SR)*/ 0x08: SETG(R(0), SUB(S32(0), VARG(R(1))));
		default: break;
		}
		break;
	}
	case TRICORE_INS_CMPSWAP_W: {
		switch (OPC1) {
		case 0x49: {
			switch (extract32(ctx->word, 22, 6)) {
			case /*CMPSWAP.W(BO)(Base + Short Offset Addressing Mode)*/ 0x23: {
				return SEQ4(
					SETL("EA", ADD(VARG(M(0).reg), sign_ext32_bv(M(0).disp, 10))),
					SETL("tmp", LOADW(Word_b, VARL("EA"))),
					STOREW(VARL("EA"), ITE(EQ(VARL("tmp"), VARG_SUB(R(1), 1)), VARG_SUB(R(1), 0), VARL("tmp"))),
					SETG(REG_SUB(R(1), 0), VARL("tmp")));
			}
			case /*CMPSWAP.W A[b], off10, E[a] (BO)(Post-increment Addressing Mode)*/ 0x03: {
				return SEQ5(
					SETL("EA", VARG(M(0).reg)),
					SETL("tmp", LOADW(Word_b, VARL("EA"))),
					STOREW(VARL("EA"), ITE(EQ(VARL("tmp"), VARG_SUB(R(1), 1)), VARG_SUB(R(1), 0), VARL("tmp"))),
					SETG(REG_SUB(R(1), 0), VARL("tmp")),
					SETG(M(0).reg, VARL("EA")));
			}
			case /*CMPSWAP.W A[b], off10, E[a] (BO)(Pre-increment Addressing Mode)*/ 0x13: {
				return SEQ5(
					SETL("EA", ADD(VARG(M(0).reg), sign_ext32_bv(M(0).disp, 10))),
					SETL("tmp", LOADW(Word_b, VARL("EA"))),
					STOREW(VARL("EA"), ITE(EQ(VARL("tmp"), VARG_SUB(R(1), 1)), VARG_SUB(R(1), 0), VARL("tmp"))),
					SETG(REG_SUB(R(1), 0), VARL("tmp")),
					SETG(M(0).reg, VARL("EA")));
			}
			default: break;
			}
			break;
		}
		case 0x69: {
			switch (extract32(ctx->word, 22, 6)) {
			case /*CMPSWAP.W P[b], E[a] (BO)(Bit-reverse Addressing Mode)*/ 0x03: {
				return SEQ8(
					SETL("index", BITS32(VARG_SUB(R(0), 1), 0, 16)),
					SETL("incr", BITS32(VARG_SUB(R(0), 1), 16, 16)),
					SETL("EA", ADD(VARG_SUB(R(0), 0), VARL("index"))),
					SETL("tmp", LOADW(Word_b, VARL("EA"))),
					STOREW(VARL("EA"), ITE(EQ(VARL("tmp"), VARG_SUB(R(1), 1)), VARG_SUB(R(1), 0), VARL("tmp"))),
					SETG(REG_SUB(R(1), 0), VARL("tmp")),
					SETL("new_index", reverse16(ADD(reverse16(VARL("index")), reverse16(VARL("incr"))))),
					SETG(REG_SUB(R(0), 1), LOGOR(SHL0(VARL("incr"), 16), BITS32(VARL("new_index"), 0, 16))));
			}
			case /*CMPSWAP.W P[b], off10, E[a] (BO)(Circular Addressing Mode)*/ 0x13: {
				return SEQ9(
					SETL("index", BITS32(VARG_SUB(M(0).reg, 1), 0, 16)),
					SETL("length", BITS32(VARG_SUB(M(0).reg, 1), 16, 16)),
					SETL("EA", ADD(VARG_SUB(M(0).reg, 0), VARL("index"))),
					SETL("tmp", LOADW(Word_b, VARL("EA"))),
					STOREW(VARL("EA"), ITE(EQ(VARL("tmp"), VARG_SUB(R(1), 1)), VARG_SUB(R(1), 0), VARL("tmp"))),
					SETG(REG_SUB(R(1), 0), VARL("tmp")),
					SETL("new_index", ADD(VARL("index"), sign_ext32_bv(M(0).disp, 10))),
					SETL("new_index",
						ITE(SLT(VARL("new_index"), S32(0)),
							ADD(VARL("new_index"), VARL("length")),
							MOD(VARL("new_index"), VARL("length")))),
					SETG(REG_SUB(M(0).reg, 1), LOGOR(SHL0(VARL("length"), 16), BITS32(VARL("new_index"), 0, 16))));
			}
			default: break;
			}
			break;
		}
		default: break;
		}
		break;
	}
	case TRICORE_INS_MADDMS_H:
	case TRICORE_INS_MADDMS_U:
	case TRICORE_INS_MADDMS:
	case TRICORE_INS_MADDM_H:
	case TRICORE_INS_MADDM_Q:
	case TRICORE_INS_MADDM_U:
	case TRICORE_INS_MADDM:
	case TRICORE_INS_MADDRS_H:
	case TRICORE_INS_MADDRS_Q:
	case TRICORE_INS_MADDR_H:
	case TRICORE_INS_MADDR_Q:
	case TRICORE_INS_MADDSUMS_H:
	case TRICORE_INS_MADDSUM_H:
	case TRICORE_INS_MADDSURS_H:
	case TRICORE_INS_MADDSUR_H:
	case TRICORE_INS_MADDSUS_H:
	case TRICORE_INS_MADDSU_H:
	case TRICORE_INS_MADDS_H:
	case TRICORE_INS_MADDS_Q:
	case TRICORE_INS_MADDS_U:
	case TRICORE_INS_MADD_H:
	case TRICORE_INS_MADD_Q:
	case TRICORE_INS_MADD_U:
	case TRICORE_INS_MADD:
	case TRICORE_INS_MADDS: {
		RzILOpEffect *e = NULL;
		bool is_32bit_result = true;
		switch (OPC1) {
		case 0x13: {
			switch (extract32(ctx->word, 21, 3)) {
			case /*MADD D[c], D[d], D[a], const9 (RCR)*/ 0x01:
				e = SEQ2(SETL("result", ADD(VARG(R(1)), MUL(VARG(R(2)), sign_ext32_bv(I(3), 9)))),
					SETG(R(0), VARL("result")));
				break;
			case /*MADD E[c], E[d], D[a], const9 (RCR)*/ 0x03:
				is_32bit_result = false;
				e = SEQ2(SETL("result", ADD(VARG(R(1)), UNSIGNED(64, MUL(VARG(R(2)), sign_ext32_bv(I(3), 9))))),
					SETG(R(0), VARL("result")));
				break;
			case /*MADDS D[c], D[d], D[a], const9 (RCR)*/ 0x05:
				e = SEQ2(SETL("result", ADD(VARG(R(1)), MUL(VARG(R(2)), sign_ext32_bv(I(3), 9)))),
					SETG(R(0), ssov(VARL("result"), U32(32))));
				break;
			case /*MADDS E[c], E[d], D[a], const9 (RCR)*/ 0x07:
				is_32bit_result = false;
				e = SEQ2(SETL("result", ADD(VARG(R(1)), UNSIGNED(64, MUL(VARG(R(2)), sign_ext32_bv(I(3), 9))))),
					SETG(R(0), ssov(VARL("result"), U64(64))));
				break;
			default: break;
			}
			break;
		}
		case 0x03: {
			switch (extract32(ctx->word, 16, 8)) {
			case /*MADD D[c], D[d], D[a], D[b] (RRR2)*/ 0x0a:
				e = SEQ2(SETL("result", ADD(VARG(R(1)), MUL(VARG(R(2)), VARG(R(3))))),
					SETG(R(0), VARL("result")));
				break;
			case /*MADD E[c], E[d], D[a], D[b] (RRR2)*/ 0x6a:
				is_32bit_result = false;
				e = SEQ2(SETL("result", ADD(VARG(R(1)), UNSIGNED(64, MUL(VARG(R(2)), VARG(R(3)))))),
					SETG(R(0), VARL("result")));
				break;
			case /*MADDS D[c], D[d], D[a], D[b] (RRR2)*/ 0x8a:
				e = SEQ2(SETL("result", ADD(VARG(R(1)), MUL(VARG(R(2)), VARG(R(3))))),
					SETG(R(0), ssov(VARL("result"), U32(32))));
				break;
			case /*MADDS E[c], E[d], D[a], D[b] (RRR2)*/ 0xea:
				is_32bit_result = false;
				e = SEQ2(SETL("result", ADD(VARG(R(1)), UNSIGNED(64, MUL(VARG(R(2)), VARG(R(3)))))),
					SETG(R(0), ssov(VARL("result"), U64(64))));
				break;
			default: break;
			}
			break;
		}
		case 0x83:
			switch (extract32(ctx->word, 18, 6)) {
			// MADDM.H MADDMS.H
			case 0x1e: return e_madd(ctx, 16, 0, 0, 0, HalfWord_b, NULL);
			case 0x1d: return e_madd(ctx, 16, 0, 0, 16, HalfWord_b, NULL);
			case 0x1c: return e_madd(ctx, 16, 16, 0, 0, HalfWord_b, NULL);
			case 0x1f: return e_madd(ctx, 0, 16, 16, 16, HalfWord_b, NULL);
			case 0x3e: return e_madd(ctx, 16, 0, 0, 0, HalfWord_b, ssov);
			case 0x3d: return e_madd(ctx, 16, 0, 0, 16, HalfWord_b, ssov);
			case 0x3c: return e_madd(ctx, 16, 16, 0, 0, HalfWord_b, ssov);
			case 0x3f: return e_madd(ctx, 0, 16, 16, 16, HalfWord_b, ssov);

			// MADDR.H MADDRS.H
			case 0x0e: return e_maddr(ctx, 16, 0, 0, 0, HalfWord_b, append_h16_32);
			case 0x0d: return e_maddr(ctx, 16, 0, 0, 16, HalfWord_b, append_h16_32);
			case 0x0c: return e_maddr(ctx, 16, 16, 0, 0, HalfWord_b, append_h16_32);
			case 0x0f: return e_maddr(ctx, 0, 16, 16, 16, HalfWord_b, append_h16_32);
			case 0x2e: return e_maddr(ctx, 16, 0, 0, 0, HalfWord_b, append_h16_32_ssov);
			case 0x2d: return e_maddr(ctx, 16, 0, 0, 16, HalfWord_b, append_h16_32_ssov);
			case 0x2c: return e_maddr(ctx, 16, 16, 0, 0, HalfWord_b, append_h16_32_ssov);
			case 0x2f: return e_maddr(ctx, 0, 16, 16, 16, HalfWord_b, append_h16_32_ssov);
			default: break;
			}
			break;
		case 0x43:
			switch (extract32(ctx->word, 18, 6)) {
			// MADDR.H MADDRS.H
			case 0x1e: return e_maddr(ctx, 16, 16, 0, 0, HalfWord_b, append_h16_32);
			case 0x3e: return e_maddr(ctx, 16, 16, 0, 0, HalfWord_b, append_h16_32_ssov);

			// MADDR.Q MADDRS.Q
			case 0x07: return e_maddr_q(ctx, 0, 0, append_h16_32);
			case 0x06: return e_maddr_q(ctx, 16, 16, append_h16_32);
			case 0x27: return e_maddr_q(ctx, 0, 0, append_h16_32_ssov);
			case 0x26: return e_maddr_q(ctx, 16, 16, append_h16_32_ssov);
			default: break;
			}
			break;
		case 0xc3:
			switch (extract32(ctx->word, 18, 6)) {
			// MADDSU.H MADDSUS.H
			case 0x1a: return e_maddsu(ctx, 16, 0, 0, 0, HalfWord_b, packed_2word);
			case 0x19: return e_maddsu(ctx, 16, 0, 0, 16, HalfWord_b, packed_2word);
			case 0x18: return e_maddsu(ctx, 16, 16, 0, 0, HalfWord_b, packed_2word);
			case 0x1b: return e_maddsu(ctx, 0, 16, 16, 16, HalfWord_b, packed_2word);
			case 0x3a: return e_maddsu(ctx, 16, 0, 0, 0, HalfWord_b, append_ssov);
			case 0x39: return e_maddsu(ctx, 16, 0, 0, 16, HalfWord_b, append_ssov);
			case 0x38: return e_maddsu(ctx, 16, 16, 0, 0, HalfWord_b, append_ssov);
			case 0x3b: return e_maddsu(ctx, 0, 16, 16, 16, HalfWord_b, append_ssov);

			// MADDSUM.H MADDSUMS.H
			case 0x1e: return e_maddsum(ctx, 16, 0, 0, 0, HalfWord_b, NULL);
			case 0x1d: return e_maddsum(ctx, 16, 0, 0, 16, HalfWord_b, NULL);
			case 0x1c: return e_maddsum(ctx, 16, 16, 0, 0, HalfWord_b, NULL);
			case 0x1f: return e_maddsum(ctx, 0, 16, 16, 16, HalfWord_b, NULL);
			case 0x3e: return e_maddsum(ctx, 16, 0, 0, 0, HalfWord_b, ssov);
			case 0x3d: return e_maddsum(ctx, 16, 0, 0, 16, HalfWord_b, ssov);
			case 0x3c: return e_maddsum(ctx, 16, 16, 0, 0, HalfWord_b, ssov);
			case 0x3f: return e_maddsum(ctx, 0, 16, 16, 16, HalfWord_b, ssov);

			// MADDSUR.H MADDSURS.H
			case 0x0e: return e_maddsur(ctx, 16, 0, 0, 0, HalfWord_b, append_h16_32);
			case 0x0d: return e_maddsur(ctx, 16, 0, 0, 16, HalfWord_b, append_h16_32);
			case 0x0c: return e_maddsur(ctx, 16, 16, 0, 0, HalfWord_b, append_h16_32);
			case 0x0f: return e_maddsur(ctx, 0, 16, 16, 16, HalfWord_b, append_h16_32);
			case 0x2e: return e_maddsur(ctx, 16, 0, 0, 0, HalfWord_b, append_h16_32_ssov);
			case 0x2d: return e_maddsur(ctx, 16, 0, 0, 16, HalfWord_b, append_h16_32_ssov);
			case 0x2c: return e_maddsur(ctx, 16, 16, 0, 0, HalfWord_b, append_h16_32_ssov);
			case 0x2f: return e_maddsur(ctx, 0, 16, 16, 16, HalfWord_b, append_h16_32_ssov);
			default: break;
			}
		default: break;
		}
		if (!e) {
			break;
		}
		RzILOpEffect *ov = (is_32bit_result ? SETL("overflow", OR(UGT(VARL("result"), U32(0x7fffffff)), SLT(VARL("result"), S32(-0x80000000))))
						    : SETL("overflow", OR(UGT(VARL("result"), U64(0x7fffffffffffffffULL)), SLT(VARL("result"), S64(-0x8000000000000000LL)))));
		RzILOpEffect *av = (is_32bit_result ? SETL("advanced_overflow", XOR(BIT32(VARL("result"), 31), BIT32(VARL("result"), 30)))
						    : SETL("advanced_overflow", XOR(BIT64(VARL("result"), 63), BIT64(VARL("result"), 62))));
		return f_cons_(e,
			SEQ6(
				ov,
				set_PSW_V(BOOL_TO_BV32(VARL("overflow"))),
				BRANCH(VARL("overflow"), set_PSW_SV(U32(1)), NOP()),
				av,
				set_PSW_AV(BOOL_TO_BV32(VARL("advanced_overflow"))),
				BRANCH(VARL("advanced_overflow"), set_PSW_SAV(U32(1)), NOP())));
	}
	case TRICORE_INS_MOVH_A:
	case TRICORE_INS_MOVH: return SETG(R(0), SHL0(U32(I(1)), 16));
	case TRICORE_INS_MOVZ_A: rz_warn_if_reached(); return NULL;
	case TRICORE_INS_MOV_U: return SETG(R(0), U32(I(1)));
	case TRICORE_INS_CMOVN:
	case TRICORE_INS_CMOV: {
		switch (OPC1) {
		case 0xaa: return SETG(R(0), ITE(NON_ZERO(VARG("d15")), sign_ext32_bv(I(1), 4), VARG(R(0))));
		case 0x2a: return SETG(R(0), ITE(NON_ZERO(VARG("d15")), VARG(R(1)), VARG(R(0))));
		case 0xea: return SETG(R(0), ITE(IS_ZERO(VARG("d15")), sign_ext32_bv(I(1), 4), VARG(R(0))));
		case 0x6a: return SETG(R(0), ITE(IS_ZERO(VARG("d15")), VARG(R(1)), VARG(R(0))));
		default: break;
		}
		break;
	}
	case TRICORE_INS_MFCR: {
		const char *cr = CR_Table(I(1));
		if (!cr) {
			return NULL;
		}
		return SETG(R(0), VARG(cr));
	}
	case TRICORE_INS_MTCR: {
		const char *cr = CR_Table(I(0));
		if (!cr) {
			return NULL;
		}
		return SETG(cr, VARG(R(1)));
	}
	case TRICORE_INS_BMERGE:
		return SETG(R(0),
			APPEND(
				APPEND(f_bmerge4x2(VARG(R(1)), VARG(R(2)), 12), f_bmerge4x2(VARG(R(1)), VARG(R(2)), 8)),
				APPEND(f_bmerge4x2(VARG(R(1)), VARG(R(2)), 4), f_bmerge4x2(VARG(R(1)), VARG(R(2)), 0))));
	case TRICORE_INS_BSPLIT:
		return SETG(R(0),
			LOGOR(
				SHL0(UNSIGNED(64, APPEND(f_bsplit8(VARG(R(1)), 17), f_bsplit8(VARG(R(1)), 1))), 32),
				UNSIGNED(64, APPEND(f_bsplit8(VARG(R(1)), 16), f_bsplit8(VARG(R(1)), 0)))));
	case TRICORE_INS_SHUFFLE: {
		return SETG(R(0),
			LET("A", byte_select(VARG(R(1)), extract32(I(2), 0, 2)),
				LET("B", byte_select(VARG(R(1)), extract32(I(2), 2, 2)),
					LET("C", byte_select(VARG(R(1)), extract32(I(2), 4, 2)),
						LET("D", byte_select(VARG(R(1)), extract32(I(2), 6, 2)),
							f_op2_chain4(rz_il_op_new_append,
								extract32(I(2), 8, 1) ? reflect(VARLP("A"), 8) : VARLP("A"),
								extract32(I(2), 8, 1) ? reflect(VARLP("B"), 8) : VARLP("B"),
								extract32(I(2), 8, 1) ? reflect(VARLP("C"), 8) : VARLP("C"),
								extract32(I(2), 8, 1) ? reflect(VARLP("D"), 8) : VARLP("D")))))));
	}
	case TRICORE_INS_MSUBADMS_H:
	case TRICORE_INS_MSUBADM_H:
	case TRICORE_INS_MSUBADRS_H:
	case TRICORE_INS_MSUBADR_H:
	case TRICORE_INS_MSUBADS_H:
	case TRICORE_INS_MSUBAD_H:
	case TRICORE_INS_MSUBMS_H:
	case TRICORE_INS_MSUBMS_U:
	case TRICORE_INS_MSUBMS:
	case TRICORE_INS_MSUBM_H:
	case TRICORE_INS_MSUBM_Q:
	case TRICORE_INS_MSUBM_U:
	case TRICORE_INS_MSUBM:
	case TRICORE_INS_MSUBRS_H:
	case TRICORE_INS_MSUBRS_Q:
	case TRICORE_INS_MSUBR_H:
	case TRICORE_INS_MSUBR_Q:
	case TRICORE_INS_MSUBS_H:
	case TRICORE_INS_MSUBS_Q:
	case TRICORE_INS_MSUBS_U:
	case TRICORE_INS_MSUBS:
	case TRICORE_INS_MSUB_H:
	case TRICORE_INS_MSUB_Q:
	case TRICORE_INS_MSUB_U:
	case TRICORE_INS_MSUB: {
		switch (OPC1) {
		case 0x33:
			switch (extract32(ctx->word, 21, 3)) {
			// MSUB, MSUBS
			case 0x01: return f_overflow32(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(VARG(R(2)), sign_ext32_bv(I(3), 9)))), SETG(R(0), VARL("result"))));
			case 0x03: return f_overflow64(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(SIGNED(64, VARG(R(2))), sign_ext64_bv(I(3), 9)))), SETG(R(0), VARL("result"))));
			case 0x05: return f_overflow32(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(VARG(R(2)), sign_ext32_bv(I(3), 9)))), SETG(R(0), ssov(VARL("result"), U32(32)))));
			case 0x07: return f_overflow64(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(SIGNED(64, VARG(R(2))), sign_ext64_bv(I(3), 9)))), SETG(R(0), ssov(VARL("result"), U64(64)))));

			// MSUB.U, MSUBS.U
			case 0x02: return f_overflow64(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(UNSIGNED(64, VARG(R(2))), U64(I(3))))), SETG(R(0), VARL("result"))));
			case 0x04: return f_overflow32(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(VARG(R(2)), U32(I(3))))), SETG(R(0), suov_n(VARL("result"), 32))));
			case 0x06: return f_overflow64(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(UNSIGNED(64, VARG(R(2))), U64(I(3))))), SETG(R(0), suov_n(VARL("result"), 64))));
			}
			break;
		case 0x23:
			switch (extract32(ctx->word, 16, 8)) {
			// MSUB, MSUBS
			case 0x0a: return f_overflow32(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(VARG(R(2)), VARG(R(3))))), SETG(R(0), VARL("result"))));
			case 0x6a: return f_overflow64(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(SIGNED(64, VARG(R(2))), SIGNED(64, VARG(R(3)))))), SETG(R(0), VARL("result"))));
			case 0x8a: return f_overflow32(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(VARG(R(2)), VARG(R(3))))), SETG(R(0), ssov(VARL("result"), U32(32)))));
			case 0xea: return f_overflow64(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(SIGNED(64, VARG(R(2))), SIGNED(64, VARG(R(3)))))), SETG(R(0), ssov(VARL("result"), U64(64)))));

			// MSUB.H, MSUBS.H
			case 0x68: return f_overflow64(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, VARG(R(3)))))), SETG(R(0), VARL("result"))));
			case 0x88: return f_overflow32(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(VARG(R(2)), VARG(R(3))))), SETG(R(0), suov_n(VARL("result"), 32))));
			case 0xe8: return f_overflow64(SEQ2(SETL("result", SUB(VARG(R(1)), MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, VARG(R(3)))))), SETG(R(0), suov_n(VARL("result"), 64))));
			}
			break;
		case 0xa3:
		case 0xe3:
			switch (extract32(ctx->word, 18, 6)) {
			// MSUB.H, MSUBS.H
			// MSUBAD.H, MSUBADS.H
			case 0x1a: return e_msubh(ctx, 16, 0, 0, 0, packed_2word);
			case 0x19: return e_msubh(ctx, 16, 0, 0, 16, packed_2word);
			case 0x18: return e_msubh(ctx, 16, 16, 0, 0, packed_2word);
			case 0x1b: return e_msubh(ctx, 0, 16, 16, 16, packed_2word);
			case 0x3a: return e_msubh(ctx, 16, 0, 0, 0, append_ssov);
			case 0x39: return e_msubh(ctx, 16, 0, 0, 16, append_ssov);
			case 0x38: return e_msubh(ctx, 16, 16, 0, 0, append_ssov);
			case 0x3b: return e_msubh(ctx, 0, 16, 16, 16, append_ssov);

			// MSUBADM.H MSUBADMS.H
			// MSUBM.H MSUBMS.H
			case 0x1e: return e_msubadmh(ctx, 16, 0, 0, 0, NULL);
			case 0x1d: return e_msubadmh(ctx, 16, 0, 0, 16, NULL);
			case 0x1c: return e_msubadmh(ctx, 16, 16, 0, 0, NULL);
			case 0x1f: return e_msubadmh(ctx, 0, 16, 16, 16, NULL);
			case 0x3e: return e_msubadmh(ctx, 16, 0, 0, 0, ssov);
			case 0x3d: return e_msubadmh(ctx, 16, 0, 0, 16, ssov);
			case 0x3c: return e_msubadmh(ctx, 16, 16, 0, 0, ssov);
			case 0x3f: return e_msubadmh(ctx, 0, 16, 16, 16, ssov);

			// MSUBADR.H MSUBADRS.H
			// MSUBR.H MSUBRS.H
			case 0x0e: return e_msubadrh(ctx, 16, 0, 0, 0, append_h16_32);
			case 0x0d: return e_msubadrh(ctx, 16, 0, 0, 16, append_h16_32);
			case 0x0c: return e_msubadrh(ctx, 16, 16, 0, 0, append_h16_32);
			case 0x0f: return e_msubadrh(ctx, 0, 16, 16, 16, append_h16_32);
			case 0x2e: return e_msubadrh(ctx, 16, 0, 0, 0, append_h16_32_ssov);
			case 0x2d: return e_msubadrh(ctx, 16, 0, 0, 16, append_h16_32_ssov);
			case 0x2c: return e_msubadrh(ctx, 16, 16, 0, 0, append_h16_32_ssov);
			case 0x2f: return e_msubadrh(ctx, 0, 16, 16, 16, append_h16_32_ssov);
			}
			break;
		case 0x63:
			switch (extract32(ctx->word, 18, 6)) {
			// MSUB.Q, MSUBS.Q
			case 0x02:
				return f_overflow32(SEQ2(
					SETL("result",
						UNSIGNED(32, SHR0(SUB(SHL0(UNSIGNED(64, VARG(R(1))), 32), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, VARG(R(3)))), I(4))), 32))),
					SETG(R(0), VARL("result"))));
			case 0x1b:
				return f_overflow64(SEQ2(
					SETL("result", SUB(VARG(R(1)), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, VARG(R(3)))), I(4)))),
					SETG(R(0), VARL("result"))));
			case 0x01:
				return f_overflow32(SEQ2(
					SETL("result",
						UNSIGNED(32, SHR0(SUB(SHL0(UNSIGNED(64, VARG(R(1))), 16), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, BITS32(VARG(R(3)), 0, 16))), I(4))), 16))),
					SETG(R(0), VARL("result"))));
			case 0x19:
				return f_overflow64(SEQ2(
					SETL("result", SUB(VARG(R(1)), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, BITS32(VARG(R(3)), 0, 16))), I(4)))),
					SETG(R(0), VARL("result"))));
			case 0x00:
				return f_overflow32(SEQ2(
					SETL("result",
						UNSIGNED(32, SHR0(SUB(SHL0(UNSIGNED(64, VARG(R(1))), 16), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, BITS32(VARG(R(3)), 16, 0))), I(4))), 16))),
					SETG(R(0), VARL("result"))));
			case 0x18:
				return f_overflow64(SEQ2(
					SETL("result", SUB(VARG(R(1)), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, BITS32(VARG(R(3)), 31, 16))), I(4)))),
					SETG(R(0), VARL("result"))));
			case 0x05: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 0, 0, HalfWord_b);
				f_cons(e, SETL("result", SUB(VARG(R(1)), VARL("mul_res"))));
				f_cons(e, SETG(R(0), VARL("result")));
				return f_overflow32(e);
			}
			case 0x1d: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 0, 0, HalfWord_b);
				f_cons(e, SETL("result", SUB(VARG(R(1)), UNSIGNED(64, SHL0(VARL("mul_res"), 16)))));
				f_cons(e, SETG(R(0), VARL("result")));
				return f_overflow64(e);
			}
			case 0x04: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 16, 16, HalfWord_b);
				f_cons(e, SETL("result", SUB(VARG(R(1)), VARL("mul_res"))));
				f_cons(e, SETG(R(0), VARL("result")));
				return f_overflow32(e);
			}
			case 0x1c: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 16, 16, HalfWord_b);
				f_cons(e, SETL("result", SUB(VARG(R(1)), UNSIGNED(64, SHL0(VARL("mul_res"), 16)))));
				f_cons(e, SETG(R(0), VARL("result")));
				return f_overflow64(e);
			}
			case 0x22:
				return f_overflow32(SEQ2(
					SETL("result",
						UNSIGNED(32, SHR0(SUB(SHL0(UNSIGNED(64, VARG(R(1))), 32), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, VARG(R(3)))), I(4))), 32))),
					SETG(R(0), ssov_n(VARL("result"), 32))));
			case 0x3b:
				return f_overflow64(SEQ2(
					SETL("result", SUB(VARG(R(1)), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, VARG(R(3)))), I(4)))),
					SETG(R(0), ssov_n(VARL("result"), 64))));
			case 0x21:
				return f_overflow32(SEQ2(
					SETL("result",
						UNSIGNED(32, SHR0(SUB(SHL0(UNSIGNED(64, VARG(R(1))), 16), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, BITS32(VARG(R(3)), 0, 16))), I(4))), 16))),
					SETG(R(0), ssov_n(VARL("result"), 32))));
			case 0x39:
				return f_overflow64(SEQ2(
					SETL("result", SUB(VARG(R(1)), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, BITS32(VARG(R(3)), 0, 16))), I(4)))),
					SETG(R(0), ssov_n(VARL("result"), 64))));
			case 0x20:
				return f_overflow32(SEQ2(
					SETL("result",
						UNSIGNED(32, SHR0(SUB(SHL0(UNSIGNED(64, VARG(R(1))), 16), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, BITS32(VARG(R(3)), 16, 0))), I(4))), 16))),
					SETG(R(0), ssov_n(VARL("result"), 32))));
			case 0x38:
				return f_overflow64(SEQ2(
					SETL("result", SUB(VARG(R(1)), SHL0(MUL(UNSIGNED(64, VARG(R(2))), UNSIGNED(64, BITS32(VARG(R(3)), 31, 16))), I(4)))),
					SETG(R(0), ssov_n(VARL("result"), 64))));
			case 0x25: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 0, 0, HalfWord_b);
				f_cons(e, SETL("result", SUB(VARG(R(1)), VARL("mul_res"))));
				f_cons(e, SETG(R(0), ssov_n(VARL("result"), 32)));
				return f_overflow32(e);
			}
			case 0x3d: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 0, 0, HalfWord_b);
				f_cons(e, SETL("result", SUB(VARG(R(1)), UNSIGNED(64, SHL0(VARL("mul_res"), 16)))));
				f_cons(e, SETG(R(0), ssov_n(VARL("result"), 64)));
				return f_overflow64(e);
			}
			case 0x24: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 16, 16, HalfWord_b);
				f_cons(e, SETL("result", SUB(VARG(R(1)), VARL("mul_res"))));
				f_cons(e, SETG(R(0), ssov_n(VARL("result"), 32)));
				return f_overflow32(e);
			}
			case 0x3c: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 16, 16, HalfWord_b);
				f_cons(e, SETL("result", SUB(VARG(R(1)), UNSIGNED(64, SHL0(VARL("mul_res"), 16)))));
				f_cons(e, SETG(R(0), ssov_n(VARL("result"), 64)));
				return f_overflow64(e);
			}

			// MSUBR.H MSUBRS.H
			case 0x1e: return e_msubadrh(ctx, 16, 16, 0, 0, append_h16_32);
			case 0x3e: return e_msubadrh(ctx, 16, 16, 0, 0, append_h16_32_ssov);

			case 0x07: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 0, 0, HalfWord_b);
				f_cons(e, SETL("result", ADD(SUB(VARG(R(1)), VARL("mul_res")), S32(0x8000))));
				f_cons(e, SETG(R(0), LOGAND(VARL("result"), U32(0xffff0000))));
				return f_overflow32(e);
			}
			case 0x06: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 16, 16, HalfWord_b);
				f_cons(e, SETL("result", ADD(SUB(VARG(R(1)), VARL("mul_res")), S32(0x8000))));
				f_cons(e, SETG(R(0), LOGAND(VARL("result"), U32(0xffff0000))));
				return f_overflow32(e);
			}
			case 0x27: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 0, 0, HalfWord_b);
				f_cons(e, SETL("result", ADD(SUB(VARG(R(1)), VARL("mul_res")), S32(0x8000))));
				f_cons(e, SETG(R(0), LOGAND(ssov_n(VARL("result"), 32), U32(0xffff0000))));
				return f_overflow32(e);
			}
			case 0x26: {
				RzILOpEffect *e = f_mul(NULL, "sc", "mul_res", VARG(R(2)), VARG(R(3)), I(4), 16, 16, HalfWord_b);
				f_cons(e, SETL("result", ADD(SUB(VARG(R(1)), VARL("mul_res")), S32(0x8000))));
				f_cons(e, SETG(R(0), LOGAND(ssov_n(VARL("result"), 32), U32(0xffff0000))));
				return f_overflow32(e);
			}
			}
			break;
		}
		break;
	}
	case TRICORE_INS_CSUBN_A: break;
	case TRICORE_INS_CSUBN: return e_op2_cond(R(0), VARG(R(1)), VARG(R(2)), IS_ZERO(VARG(R(3))), rz_il_op_new_sub);
	case TRICORE_INS_CSUB_A: break;
	case TRICORE_INS_CSUB: return e_op2_cond(R(0), VARG(R(1)), VARG(R(2)), NON_ZERO(VARG(R(3))), rz_il_op_new_sub);
	case TRICORE_INS_SUBC: {
		RzILOpEffect *e = packed_op2_raw(R(0), ADD(VARG(R(1)), PSW_C()), ADD(VARG(R(2)), U32(1)), Word_b, rz_il_op_new_sub);
		f_cons(e, SETL("carry_out", carry(VARG(R(1)), NEG(VARG(R(2))), PSW_C())));
		f_cons(e, set_PSW_C(VARL("carry_out")));
		return e;
	}
	case TRICORE_INS_SUBX: {
		RzILOpEffect *e = packed_op2_raw(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_sub);
		f_cons(e, SETL("carry_out", carry(VARG(R(1)), NEG(VARG(R(2))), U32(1))));
		f_cons(e, set_PSW_C(VARL("carry_out")));
		return e;
	}
	case TRICORE_INS_SUBSC_A: break;
	case TRICORE_INS_SUBS_BU:
	case TRICORE_INS_SUBS_B:
	case TRICORE_INS_SUBS_HU:
	case TRICORE_INS_SUBS_H:
	case TRICORE_INS_SUBS_U:
	case TRICORE_INS_SUBS:
	case TRICORE_INS_SUB: {
		switch (OPC1) {
		case 0x0b:
			switch (extract32(ctx->word, 20, 8)) {
			// SUB
			case 0x08: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_sub, NULL);
			// SUBS
			case 0x0a: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_sub, ssov);
			case 0x0b: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_sub, suov);
			// SUBS.H
			case 0x6a: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_sub, ssov);
			// SUBS.HU
			case 0x6b: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_sub, suov);
			default: break;
			}
			break;
		// SUB
		case 0xa2: return packed_op2_sov(R(0), VARG(R(0)), VARG(R(1)), Word_b, rz_il_op_new_sub, NULL);
		case 0x52: return packed_op2_sov(R(0), VARG("d15"), VARG(R(1)), Word_b, rz_il_op_new_sub, NULL);
		case 0x5a: return packed_op2_sov("d15", VARG(R(0)), VARG(R(1)), Word_b, rz_il_op_new_sub, NULL);
		case 0x01:
			switch (extract32(ctx->word, 20, 8)) {
			// SUB.A
			case 0x02: return packed_op2_s(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_sub, NULL, false);
			default: break;
			}
			break;
		// SUB.A
		case 0x20: return packed_op2_s("a10", VARG("a10"), VARG(R(0)), Word_b, rz_il_op_new_sub, NULL, false);
		// SUBS
		case 0x62: return packed_op2_sov(R(0), VARG(R(0)), VARG(R(1)), Word_b, rz_il_op_new_sub, ssov);
		default: break;
		}
		break;
	}
	case TRICORE_INS_SUB_B: return packed_op2_s(R(0), VARG(R(1)), VARG(R(2)), Byte_b, rz_il_op_new_sub, NULL, true);
	case TRICORE_INS_SUB_H: return packed_op2_s(R(0), VARG(R(1)), VARG(R(2)), HalfWord_b, rz_il_op_new_sub, NULL, true);
	case TRICORE_INS_MULMS_H:
	case TRICORE_INS_MULM_H:
	case TRICORE_INS_MULM_U:
	case TRICORE_INS_MULM:
		switch (OPC1) {
		case 0xB3:
			switch (extract32(ctx->word, 18, 9)) {
			case 0x1e: return e_mul(ctx, 16, 0, 0, 0, HalfWord_b, f_add_shl16_64);
			case 0x1d: return e_mul(ctx, 16, 0, 0, 16, HalfWord_b, f_add_shl16_64);
			case 0x1c: return e_mul(ctx, 16, 16, 0, 0, HalfWord_b, f_add_shl16_64);
			case 0x1f: return e_mul(ctx, 0, 16, 16, 16, HalfWord_b, f_add_shl16_64);
			}
			break;
		}
		break;
	case TRICORE_INS_MULR_H:
		switch (OPC1) {
		case 0xB3:
			switch (extract32(ctx->word, 18, 9)) {
			case 0x0e: return e_mulr_h(ctx, 16, 0, 0, 0, HalfWord_b, append_h16_32);
			case 0x0d: return e_mulr_h(ctx, 16, 0, 0, 16, HalfWord_b, append_h16_32);
			case 0x0c: return e_mulr_h(ctx, 16, 16, 0, 0, HalfWord_b, append_h16_32);
			case 0x0f: return e_mulr_h(ctx, 0, 16, 16, 16, HalfWord_b, append_h16_32);
			}
			break;
		}
		break;
	case TRICORE_INS_MULR_Q: {
		switch (OPC1) {
		case 0x93:
			switch (extract32(ctx->word, 18, 9)) {
			case 0x07: return e_mulr_q(ctx, 0, 0);
			case 0x06: return e_mulr_q(ctx, 16, 16);
			}
			break;
		}
		break;
	}
	case TRICORE_INS_MUL_H:
		switch (OPC1) {
		case 0xb3:
			switch (extract32(ctx->word, 18, 9)) {
			// MUL.H
			case 0x1a: return e_mul(ctx, 16, 0, 0, 0, HalfWord_b, rz_il_op_new_append);
			case 0x19: return e_mul(ctx, 16, 0, 0, 16, HalfWord_b, rz_il_op_new_append);
			case 0x18: return e_mul(ctx, 16, 16, 0, 0, HalfWord_b, rz_il_op_new_append);
			case 0x1b: return e_mul(ctx, 0, 16, 16, 16, HalfWord_b, rz_il_op_new_append);
			}
			break;
		}
		break;

	case TRICORE_INS_MUL_Q: {
		switch (OPC1) {
		case 0x93:
			switch (extract32(ctx->word, 18, 9)) {
			// MUL.Q
			case 0x02: return f_overflow32(SEQ2(SETL("result", UNSIGNED(32, SHR0(SHL0(MUL(SIGNED(64, VARG(R(1))), SIGNED(64, VARG(R(2)))), I(3)), 32))), SETG(R(0), VARL("result"))));
			case 0x1b: return f_overflow64(SEQ2(SETL("result", SHL0(MUL(SIGNED(64, VARG(R(1))), SIGNED(64, VARG(R(2)))), I(3))), SETG(R(0), VARL("result"))));
			case 0x01: return f_overflow32(SEQ2(SETL("result", UNSIGNED(32, SHR0(SHL0(MUL(SIGNED(64, VARG(R(1))), SIGNED(64, BITS32(VARG(R(2)), 0, 16))), I(3)), 16))), SETG(R(0), VARL("result"))));
			case 0x19: return f_overflow64(SEQ2(SETL("result", SHL0(MUL(SIGNED(64, VARG(R(1))), SIGNED(64, BITS32(VARG(R(2)), 0, 16))), I(3))), SETG(R(0), VARL("result"))));
			case 0x00: return f_overflow32(SEQ2(SETL("result", UNSIGNED(32, SHR0(SHL0(MUL(SIGNED(64, VARG(R(1))), SIGNED(64, BITS32(VARG(R(2)), 16, 16))), I(3)), 16))), SETG(R(0), VARL("result"))));
			case 0x18: return f_overflow64(SEQ2(SETL("result", SHL0(MUL(SIGNED(64, VARG(R(1))), SIGNED(64, BITS32(VARG(R(2)), 16, 16))), I(3))), SETG(R(0), VARL("result"))));
			case 0x05: return f_overflow32(f_cons_(f_mul(NULL, "sc", "result", VARG(R(1)), VARG(R(2)), I(3), 0, 0, HalfWord_b), SETG(R(0), VARL("result"))));
			case 0x04: return f_overflow32(f_cons_(f_mul(NULL, "sc", "result", VARG(R(1)), VARG(R(2)), I(3), 16, 16, HalfWord_b), SETG(R(0), VARL("result"))));
			}
			break;
		}
		break;
	}
	case TRICORE_INS_MULS_U:
	case TRICORE_INS_MULS:
	case TRICORE_INS_MUL_U:
	case TRICORE_INS_MUL: {
		switch (OPC1) {
		case 0x53:
			switch (extract32(ctx->word, 21, 7)) {
			// MUL
			case 0x01: return packed_op2_sov(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), Word_b, rz_il_op_new_mul, NULL);
			case 0x03: return packed_op2_sov(R(0), SIGNED(64, VARG(R(1))), sign_ext64_bv(I(2), 9), DoubleWord_b, rz_il_op_new_mul, NULL);
			// MULS
			case 0x05: return packed_op2_sov(R(0), VARG(R(1)), sign_ext32_bv(I(2), 9), Word_b, rz_il_op_new_mul, ssov);
			// MUL.U
			case 0x02: return packed_op2_sov(R(0), UNSIGNED(64, VARG(R(1))), U64(I(2)), DoubleWord_b, rz_il_op_new_mul, NULL);
			// MULS.U
			case 0x04: return packed_op2_sov(R(0), VARG(R(1)), U32(I(2)), Word_b, rz_il_op_new_mul, suov);
			}
			break;
		case 0x73:
			switch (extract32(ctx->word, 16, 12)) {
			// MUL
			case 0x0a: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_mul, NULL);
			case 0x6a: return packed_op2_sov(R(0), SIGNED(64, VARG(R(1))), SIGNED(64, VARG(R(2))), DoubleWord_b, rz_il_op_new_mul, NULL);
			// MULS
			case 0x8a: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_mul, ssov);
			// MUL.U
			case 0x68: return packed_op2_sov(R(0), UNSIGNED(64, VARG(R(1))), UNSIGNED(64, VARG(R(2))), DoubleWord_b, rz_il_op_new_mul, NULL);
			// MULS.U
			case 0x88: return packed_op2_sov(R(0), VARG(R(1)), VARG(R(2)), Word_b, rz_il_op_new_mul, suov);
			}
			break;
		case 0xe2: return packed_op2_sov(R(0), VARG(R(0)), VARG(R(1)), Word_b, rz_il_op_new_mul, NULL);
		}
		break;
	}
	case TRICORE_INS_AND_AND_T: return e_op_op_bit(ctx, rz_il_op_new_bool_and, rz_il_op_new_bool_and);
	case TRICORE_INS_AND_ANDN_T: return e_op_op_bit(ctx, rz_il_op_new_bool_and, f_andn);
	case TRICORE_INS_AND_NOR_T: return e_op_op_bit(ctx, rz_il_op_new_bool_and, f_nor);
	case TRICORE_INS_AND_OR_T: return e_op_op_bit(ctx, rz_il_op_new_bool_and, rz_il_op_new_bool_or);

	case TRICORE_INS_OR_AND_T: return e_op_op_bit(ctx, rz_il_op_new_bool_or, rz_il_op_new_bool_and);
	case TRICORE_INS_OR_ANDN_T: return e_op_op_bit(ctx, rz_il_op_new_bool_or, f_andn);
	case TRICORE_INS_OR_NOR_T: return e_op_op_bit(ctx, rz_il_op_new_bool_or, f_nor);
	case TRICORE_INS_OR_OR_T: return e_op_op_bit(ctx, rz_il_op_new_bool_or, rz_il_op_new_bool_or);

	case TRICORE_INS_SH_AND_T: return e_sh_op_bit(ctx, rz_il_op_new_bool_and);
	case TRICORE_INS_SH_ANDN_T: return e_sh_op_bit(ctx, f_andn);
	case TRICORE_INS_SH_NAND_T: return e_sh_op_bit(ctx, f_nand);
	case TRICORE_INS_SH_NOR_T: return e_sh_op_bit(ctx, f_nor);
	case TRICORE_INS_SH_ORN_T: return e_sh_op_bit(ctx, f_orn);
	case TRICORE_INS_SH_OR_T: return e_sh_op_bit(ctx, rz_il_op_new_bool_or);
	case TRICORE_INS_SH_XNOR_T: return e_sh_op_bit(ctx, f_xnor);
	case TRICORE_INS_SH_XOR_T: return e_sh_op_bit(ctx, rz_il_op_new_bool_xor);

	case TRICORE_INS_AND_T: return e_op_bit(ctx, rz_il_op_new_bool_and);
	case TRICORE_INS_OR_T: return e_op_bit(ctx, rz_il_op_new_bool_or);
	case TRICORE_INS_ANDN_T: return e_op_bit(ctx, f_andn);
	case TRICORE_INS_NOR_T: return e_op_bit(ctx, f_nor);
	case TRICORE_INS_NAND_T: return e_op_bit(ctx, f_nand);
	case TRICORE_INS_ORN_T: return e_op_bit(ctx, f_orn);
	case TRICORE_INS_XNOR_T: return e_op_bit(ctx, f_xnor);
	case TRICORE_INS_XOR_T: return e_op_bit(ctx, rz_il_op_new_bool_xor);

	case TRICORE_INS_INS_T: return e_ins_bit(ctx, false);
	case TRICORE_INS_INSN_T: return e_ins_bit(ctx, true);

	case TRICORE_INS_PARITY:
		return SETG(R(0),
			LET("_31_24", BOOL_TO_BV8(f_xor8(VARG(R(1)), 24)),
				LET("_23_16", BOOL_TO_BV8(f_xor8(VARG(R(1)), 16)),
					LET("_15_8", BOOL_TO_BV8(f_xor8(VARG(R(1)), 8)),
						LET("_7_0", BOOL_TO_BV8(f_xor8(VARG(R(1)), 0)),
							APPEND(APPEND(VARLP("_31_24"), VARLP("_23_16")),
								APPEND(VARLP("_15_8"), VARLP("_7_0"))))))));
	case TRICORE_INS_POPCNT_W: {
		RzAnalysisLiftedILOp e = population_count(NULL, "cnt", VARG(R(1)));
		return f_cons_(e, SETG(R(0), VARL("cnt")));
	}
	case TRICORE_INS_RET: return lift_ret(ctx);
	case TRICORE_INS_RFE: return lift_rfe(ctx);
	case TRICORE_INS_RFM: return lift_rfm(ctx);
	case TRICORE_INS_SAT_BU:
		switch (OPC1) {
		case 0x0b:
			return SETG(R(0), ITE(SGT(VARG(R(1)), U32(0xff)), U32(0xff), VARG(R(1))));
		case 0x32:
			return SETG(R(0), ITE(SGT(VARG(R(0)), U32(0xff)), U32(0xff), VARG(R(0))));
		}
		break;
	case TRICORE_INS_SAT_B:
		switch (OPC1) {
		case 0x0b:
			return SETG(R(0),
				LET("sat_neg", ITE(SLT(VARG(R(1)), S32(-0x80)), S32(-0x80), VARG(R(1))),
					ITE(SGT(VARLP("sat_neg"), S32(0x7f)), S32(0x7f), VARLP("sat_neg"))));
		case 0x32:
			return SETG(R(0),
				LET("sat_neg", ITE(SLT(VARG(R(0)), S32(-0x80)), S32(-0x80), VARG(R(0))),
					ITE(SGT(VARLP("sat_neg"), S32(0x7f)), S32(0x7f), VARLP("sat_neg"))));
		}
		break;
	case TRICORE_INS_SAT_HU: {
		switch (OPC1) {
		case 0x0b:
			return SETG(R(0), ITE(SGT(VARG(R(1)), U32(0xffff)), U32(0xffff), VARG(R(1))));
		case 0x32:
			return SETG(R(0), ITE(SGT(VARG(R(0)), U32(0xffff)), U32(0xffff), VARG(R(0))));
		}
		break;
	}
	case TRICORE_INS_SAT_H: {
		switch (OPC1) {
		case 0x0b:
			return SETG(R(0),
				LET("sat_neg", ITE(SLT(VARG(R(1)), S32(-0x8000)), S32(-0x8000), VARG(R(1))),
					ITE(SGT(VARLP("sat_neg"), S32(0x7fff)), S32(0x7fff), VARLP("sat_neg"))));
		case 0x32:
			return SETG(R(0),
				LET("sat_neg", ITE(SLT(VARG(R(0)), S32(-0x8000)), S32(-0x8000), VARG(R(0))),
					ITE(SGT(VARLP("sat_neg"), S32(0x7fff)), S32(0x7fff), VARLP("sat_neg"))));
		}
		break;
	}
	case TRICORE_INS_SELN_A:
	case TRICORE_INS_SELN:
		switch (OPC1) {
		case 0xab: return SETG(R(0), ITE(IS_ZERO(VARG(R(1))), VARG(R(2)), sign_ext32_bv(I(3), 9)));
		case 0x2b: return SETG(R(0), ITE(IS_ZERO(VARG(R(1))), VARG(R(2)), VARG(R(3))));
		}
		break;
	case TRICORE_INS_SEL_A:
	case TRICORE_INS_SEL:
		switch (OPC1) {
		case 0xab: return SETG(R(0), ITE(NON_ZERO(VARG(R(1))), VARG(R(2)), sign_ext32_bv(I(3), 9)));
		case 0x2b: return SETG(R(0), ITE(NON_ZERO(VARG(R(1))), VARG(R(2)), VARG(R(3))));
		}
		break;
	case TRICORE_INS_SHAS:
		switch (OPC1) {
		case 0x8f: return e_shas(R(0), sign_ext32_bv(I(2), 6), VARG(R(1)));
		case 0x0f: return e_shas(R(0), SEXT32(VARG(R(2)), 6), VARG(R(1)));
		}
		break;
	case TRICORE_INS_SHA_B:
		switch (OPC1) {
		case 0x8f: return e_sha(R(0), sign_ext32_bv(I(2), 6), VARG(R(1)), Byte_b);
		case 0x0f: return e_sha(R(0), SEXT32(VARG(R(2)), 6), VARG(R(1)), Byte_b);
		}
		break;
	case TRICORE_INS_SHA_H:
		switch (OPC1) {
		case 0x8f: return e_sha(R(0), sign_ext32_bv(I(2), 6), VARG(R(1)), HalfWord_b);
		case 0x0f: return e_sha(R(0), SEXT32(VARG(R(2)), 6), VARG(R(1)), HalfWord_b);
		}
		break;
	case TRICORE_INS_SHA:
		switch (OPC1) {
		case 0x8f: return e_sha(R(0), sign_ext32_bv(I(2), 6), VARG(R(1)), Word_b);
		case 0x0f: return e_sha(R(0), SEXT32(VARG(R(2)), 6), VARG(R(1)), Word_b);
		case 0x86: return e_sha(R(0), sign_ext32_bv(I(1), 4), VARG(R(0)), Word_b);
		}
		break;
	case TRICORE_INS_SH_B:
		switch (OPC1) {
		case 0x8f: return e_sh(R(0), sign_ext32_bv(I(2), 6), VARG(R(1)), Byte_b);
		case 0x0f: return e_sh(R(0), SEXT32(VARG(R(2)), 6), VARG(R(1)), Byte_b);
		}
		break;
	case TRICORE_INS_SH_H:
		switch (OPC1) {
		case 0x8f: return e_sh(R(0), sign_ext32_bv(I(2), 6), VARG(R(1)), HalfWord_b);
		case 0x0f: return e_sh(R(0), SEXT32(VARG(R(2)), 6), VARG(R(1)), HalfWord_b);
		}
		break;
	case TRICORE_INS_SH: {
		switch (OPC1) {
		case 0x8f: return e_sh(R(0), sign_ext32_bv(I(2), 6), VARG(R(1)), Word_b);
		case 0x0f: return e_sh(R(0), SEXT32(VARG(R(2)), 6), VARG(R(1)), Word_b);
		case 0x06: return e_sh(R(0), sign_ext32_bv(I(1), 4), VARG(R(0)), Word_b);
		}
		break;
	}
	case TRICORE_INS_STLCX:
	case TRICORE_INS_STUCX:
	case TRICORE_INS_ST_A:
	case TRICORE_INS_ST_B:
	case TRICORE_INS_ST_DA:
	case TRICORE_INS_ST_D:
	case TRICORE_INS_ST_H:
	case TRICORE_INS_ST_Q:
	case TRICORE_INS_ST_T:
	case TRICORE_INS_ST_W: return lift_st_op(ctx);
	case TRICORE_INS_SWAP_A: break;
	case TRICORE_INS_LDMST:
	case TRICORE_INS_SWAP_W: {
		switch (ctx->insn->bytes[0]) {
		case 0xe5: {
			switch (extract32(ctx->word, 26, 2)) {
			case /*LDMST ABS*/ 0x01: return SEQ2(
				SETL("EA", EA_off18(I(0))),
				load_MST(R(1)));
			case /*SWAP.W ABS*/ 0x00: return e_SWAP_W_ea(EA_off18(I(0)), R(1), NULL);
			default: rz_warn_if_reached(); return NULL;
			}
		}
		case 0x49: {
			switch (extract32(ctx->word, 22, 6)) {
			case 0x21: return SEQ2(
				SETL("EA", EA_bso(M(0))),
				load_MST(R(1)));
			case 0x01: return SEQ3(
				SETL("EA", VARG(M(0).reg)),
				load_MST(R(1)),
				SETG(M(0).reg, ADD(VARL("EA"), sign_ext32_bv(M(0).disp, 10))));
			case 0x11: return SEQ3(
				SETL("EA", EA_bso(M(0))),
				load_MST(R(1)),
				SETG(M(0).reg, VARL("EA")));
			case 0x20: return e_SWAP_W_ea(EA_bso(M(0)), R(1), NULL);
			case 0x00: return e_SWAP_W_ea(
				VARG(M(0).reg),
				R(1),
				SETG(M(0).reg, ADD(VARL("EA"), sign_ext32_bv(M(0).disp, 10))));
			case 0x10: return e_SWAP_W_ea(
				EA_bso(M(0)),
				R(1),
				SETG(M(0).reg, VARL("EA")));
			default: rz_warn_if_reached(); return NULL;
			}
		}
		case 0x69: {
			switch (extract32(ctx->word, 22, 6)) {
			case 0x01: return addr_bit_reverse(ctx, R(0),
				SEQ2(SETL("EA", ADD(VARG_SUB(R(0), 0), VARL("index"))), load_MST(R(1))));
			case 0x11: return addr_circular(ctx, M(0),
				SEQ2(SETL("EA", ADD(VARG_SUB(M(0).reg, 0), VARL("index"))), load_MST(R(1))));
			case 0x00: return addr_bit_reverse(ctx, R(0), e_SWAP_W(R(1)));
			case 0x10: return addr_circular(ctx, M(0),
				e_SWAP_W_ea(ADD(VARG_SUB(M(0).reg, 0), VARL("index")), R(1), NULL));
			case /*swap.w [p0+i], d0*/ 0x20: /*TODO: This instruction was not found in "TriCore TC1.6.2 core architecture manual"*/
			default: rz_warn_if_reached(); return NULL;
			}
		}
		}
		break;
	}
	case TRICORE_INS_SWAPMSK_W:
		switch (OPC1) {
		case 0x49: {
			switch (extract32(ctx->word, 22, 6)) {
			case 0x22: return e_SWAPMSK_W_ea(ADD(VARG(M(0).reg), sign_ext32_bv(M(0).disp, 10)), R(1), NULL);
			case 0x02: return e_SWAPMSK_W_ea(VARG(M(0).reg), R(1), SETG(M(0).reg, ADD(VARL("EA"), sign_ext32_bv(M(0).disp, 10))));
			case 0x12: return e_SWAPMSK_W_ea(ADD(VARG(M(0).reg), sign_ext32_bv(M(0).disp, 10)), R(1), SETG(M(0).reg, VARL("EA")));
			}
		} break;
		case 0x69:
			switch (extract32(ctx->word, 22, 6)) {
			case 0x02: return addr_bit_reverse(ctx, R(0), e_SWAPMSK_W(R(1)));
			case 0x12: return addr_circular(ctx, M(0), e_SWAPMSK_W_ea(ADD(VARG_SUB(M(0).reg, 0), VARL("index")), R(1), NULL));
			case 0x22: NOT_IMPLEMENTED;
			}
			break;
		}
		break;
	case TRICORE_INS_TLBDEMAP:
	case TRICORE_INS_TLBFLUSH_A:
	case TRICORE_INS_TLBFLUSH_B:
	case TRICORE_INS_TLBMAP:
	case TRICORE_INS_TLBPROBE_A:
	case TRICORE_INS_TLBPROBE_I: NOT_IMPLEMENTED;
	case TRICORE_INS_AND:
	case TRICORE_INS_ANDN:
	case TRICORE_INS_NAND:
	case TRICORE_INS_NOR:
	case TRICORE_INS_NOT:
	case TRICORE_INS_OR:
	case TRICORE_INS_ORN:
	case TRICORE_INS_XNOR:
	case TRICORE_INS_XOR: {
		switch (OPC1) {
		case 0x8f: {
			switch (extract32(ctx->word, 21, 6)) {
			case /*AND(RC)*/ 0x08: return e_op2(R(0), VARG(R(1)), U32(I(2)), rz_il_op_new_log_and);
			case /*ANDN(RC)*/ 0x0e: return e_op2(R(0), VARG(R(1)), LOGNOT(U32(I(2))), rz_il_op_new_log_and);
			case /*NOR(RC)*/ 0x0b: return SETG(R(0), LOGNOT(LOGOR(VARG(R(1)), U32(I(2)))));
			case /*NAND(RC)*/ 0x09: return SETG(R(0), LOGNOT(LOGAND(VARG(R(1)), U32(I(2)))));
			case /*OR(RC)*/ 0x0a: return e_op2(R(0), VARG(R(1)), U32(I(2)), rz_il_op_new_log_or);
			case /*ORN(RC)*/ 0x0f: return e_op2(R(0), VARG(R(1)), LOGNOT(U32(I(2))), rz_il_op_new_log_or);
			case /*XNOR(RC)*/ 0x0d: return SETG(R(0), LOGNOT(LOGXOR(VARG(R(1)), U32(I(2)))));
			case /*XOR(RC)*/ 0x0c: return e_op2(R(0), VARG(R(1)), U32(I(2)), rz_il_op_new_log_xor);
			default: break;
			}
			break;
		}
		case 0x0f: {
			switch (extract32(ctx->word, 20, 8)) {
			case /*AND(RR)*/ 0x08: return e_op2(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_log_and);
			case /*ANDN(RR)*/ 0x0e: return e_op2(R(0), VARG(R(1)), LOGNOT(VARG(R(2))), rz_il_op_new_log_and);
			case /*NOR(RR)*/ 0x0b: return SETG(R(0), LOGNOT(LOGOR(VARG(R(1)), VARG(R(2)))));
			case /*NAND(RR)*/ 0x09: return SETG(R(0), LOGNOT(LOGAND(VARG(R(1)), VARG(R(2)))));
			case /*OR(RR)*/ 0x0a: return e_op2(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_log_or);
			case /*ORN(RR)*/ 0x0f: return e_op2(R(0), VARG(R(1)), LOGNOT(VARG(R(2))), rz_il_op_new_log_or);
			case /*XNOR(RR)*/ 0x0d: return SETG(R(0), LOGNOT(LOGXOR(VARG(R(1)), VARG(R(2)))));
			case /*XOR(RR)*/ 0x0c: return e_op2(R(0), VARG(R(1)), VARG(R(2)), rz_il_op_new_log_xor);
			default: break;
			}
			break;
		}
		case /*AND(SC)*/ 0x16: return e_op2("d15", VARG("d15"), U32(I(0)), rz_il_op_new_log_and);
		case /*AND(SRR)*/ 0x26: return e_op2(R(0), VARG(R(0)), VARG(R(1)), rz_il_op_new_log_and);
		case /*NOT(SR)*/ 0x46: return SETG(R(0), LOGNOT(VARG(R(0))));
		case /*OR(SC)*/ 0x96: return e_op2("d15", VARG("d15"), U32(I(0)), rz_il_op_new_log_or);
		case /*OR(SRR)*/ 0xa6: return e_op2(R(0), VARG(R(0)), VARG(R(1)), rz_il_op_new_log_or);
		case /*XOR(SRR)*/ 0xc6: return e_op2(R(0), VARG(R(0)), VARG(R(1)), rz_il_op_new_log_xor);
		default: break;
		}
		break;
	}
	}
	NOT_IMPLEMENTED;
}

#include "rz_il/rz_il_opbuilder_end.h"

static void trap_hook(RzILVM *vm, RzILOpEffect *op) {}

RZ_IPI RzAnalysisILConfig *tricore_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 32);
	cfg->reg_bindings = TriCoreREGs;

	RzILEffectLabel *int_label = rz_il_effect_label_new("trap", EFFECT_LABEL_SYSCALL);
	int_label->hook = trap_hook;
	rz_analysis_il_config_add_label(cfg, int_label);

	return cfg;
}
