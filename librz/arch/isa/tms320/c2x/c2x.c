// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * TMS320C2x (legacy single-accumulator fixed-point DSP, e.g. TMS320C25)
 * disassembly + analysis, built on the shared C55 decode engine (c55_ir.[ch]).
 *
 * The C2x is a 16-bit word-addressed Harvard machine. Memory-reference
 * instructions carry one addressing byte (the low 8 bits of the opcode word):
 * bit 7 selects direct (0) or indirect (1) addressing.
 *   - Direct:   bits 6-0 are a 7-bit data-page offset (dma); the effective
 *               address is (DP[8:0] << 7) | dma.
 *   - Indirect: bits 6-4 (M) select an auxiliary-register modification applied
 *               to the ARP-selected AR; bits 3-0 (N), when N>=8, reload ARP to
 *               N&7 (rendered ",arX"). M: 0=* 1=*- 2=*+ 4=*BR0- 5=*0- 6=*0+
 *               7=*BR0+.
 *
 * Opcode bit patterns are transcribed from the public TMS320C2x instruction set
 * (matching MAME's tested TMS320x25 disassembler). Words are stored MSB-first,
 * so the engine's per-word byte-swap (words_le) is NOT used. mask/match operate
 * on the engine's 4-byte MSB-first "head" (opcode word in head bits 31:16);
 * operand extractors index the c55_pack() word (opcode word in the low 16 bits
 * for a 2-byte instruction, the leading word in bits 31:16 for a 4-byte one).
 *
 * Validation status: written against the encoding reference and the engine
 * contracts; NOT yet round-tripped through a built rz-asm or cross-checked
 * against a hardware/reference disassembler. The F8..FF branch tail in
 * particular (B/CALL/BANZ/BBZ/BBNZ/BIOZ opcodes) is reconstructed and should be
 * verified before merge.
 */

#include "c2x.h"

// bitfield helper (c55_field is private to the engine)

static ut64 c2x_field(ut64 bits, ut8 lo, ut8 width) {
	if (width >= 64) {
		return bits >> lo;
	}
	return (bits >> lo) & (((ut64)1 << width) - 1);
}

// operand extractors

static const char *const c2x_indir_raw[8] = {
	"*", "*-", "*+", "*?", "*br0-", "*0-", "*0+", "*br0+"
};
static const C55AddrMode c2x_indir_amode[8] = {
	C55_AM_INDIRECT, C55_AM_POSTDEC, C55_AM_POSTINC, C55_AM_INDIRECT /* reserved */,
	C55_AM_BITREV_SUB, C55_AM_POSTSUB, C55_AM_POSTADD, C55_AM_BITREV
};
static const char *const c2x_arx_raw[8] = {
	"ar0", "ar1", "ar2", "ar3", "ar4", "ar5", "ar6", "ar7"
};

// Single data-memory operand: the byte at d->lo is the addressing byte. Direct
// addressing is represented structurally (C55_AM_DIRECT + 7-bit dma in disp) so
// the lifter can form its EA via c2x_ea(); indirect addressing is ARP-relative
// (no statically known AR), so it renders verbatim via raw and is opaque to IL.
RZ_IPI void c2x_x_mem(RZ_UNUSED const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 b = (ut8)c2x_field(bits, d->lo, 8);
	out->kind = C55_OP_MEM;
	out->access = 16;
	if (b & 0x80) {
		ut8 m = (b >> 4) & 7;
		out->amode = c2x_indir_amode[m];
		out->reg.cls = C55_RC_AR; // ARP-selected at run time; placeholder index
		out->reg.num = 0;
		out->raw = c2x_indir_raw[m];
	} else {
		out->amode = C55_AM_DIRECT;
		out->disp = (st32)(b & 0x7f);
	}
}

// next-ARP nibble (N field): N>=8 reloads ARP to N&7, rendered ",arX".
RZ_IPI void c2x_x_nextarp(RZ_UNUSED const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	ut8 n = (ut8)c2x_field(bits, d->lo, 4);
	if (n & 0x8) {
		out->kind = C55_OP_REG;
		out->reg.cls = C55_RC_AR;
		out->reg.num = n & 7;
		out->width = 16;
		out->raw = c2x_arx_raw[n & 7];
	} else {
		out->kind = C55_OP_NONE;
	}
}

// shift count (T 4-bit / S 3-bit), rendered as an immediate.
RZ_IPI void c2x_x_shift(RZ_UNUSED const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_IMM;
	out->imm = c2x_field(bits, d->lo, d->width);
	out->width = 16;
}

// auxiliary-register number (R field) -> arX register operand.
RZ_IPI void c2x_x_reg(RZ_UNUSED const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AR;
	out->reg.num = (ut8)c2x_field(bits, d->lo, d->width);
	out->width = 16;
	out->raw = (out->reg.num < 8) ? c2x_arx_raw[out->reg.num] : NULL;
}

// immediate (D 8-bit / K small / W 16-bit / MPYK 13-bit); param 1 => signed.
RZ_IPI void c2x_x_imm(RZ_UNUSED const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_IMM;
	out->imm = c2x_field(bits, d->lo, d->width);
	out->width = d->width;
	out->imm_signed = (d->param == 1);
}

// 16-bit absolute branch/call target carried in the trailing word.
RZ_IPI void c2x_x_branch(RZ_UNUSED const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	out->kind = C55_OP_IMM;
	out->imm = c2x_field(bits, d->lo, 16);
	out->width = 16;
	out->addr = true;
	out->abs_target = true;
}

// decode table

#include "c2x_rowdefs.h"

static const C55InsnDef c2x_table[] = {
#include "c2x_core_rows.inc"
};

#include "c2x_rowundefs.h"

// register resolver

static const C55RegInfo c2x_reg_acc = { "acc", "acc", 32 };
static const C55RegInfo c2x_reg_t = { "t", "t", 16 };
static const C55RegInfo c2x_reg_dp = { "dp", "dp", 16 };
static const C55RegInfo c2x_reg_arp = { "arp", "arp", 16 };
static const C55RegInfo c2x_reg_p = { "p", "p", 32 };
static const C55RegInfo c2x_reg_pc = { "pc", "pc", 16 };
static const C55RegInfo c2x_reg_ar[8] = {
	{ "ar0", "ar0", 16 }, { "ar1", "ar1", 16 }, { "ar2", "ar2", 16 }, { "ar3", "ar3", 16 },
	{ "ar4", "ar4", 16 }, { "ar5", "ar5", 16 }, { "ar6", "ar6", 16 }, { "ar7", "ar7", 16 }
};
static const C55RegInfo c2x_reg_st[2] = { { "st0", "st0", 16 }, { "st1", "st1", 16 } };

RZ_IPI const C55RegInfo *c2x_reg_info(C55RegClass cls, ut8 num, RZ_UNUSED C55SubReg sub) {
	switch (cls) {
	case C55_RC_AC: return &c2x_reg_acc;
	case C55_RC_T: return &c2x_reg_t;
	case C55_RC_DP: return &c2x_reg_dp;
	case C55_RC_ARP: return &c2x_reg_arp;
	case C55_RC_AR: return num < 8 ? &c2x_reg_ar[num] : NULL;
	case C55_RC_ST: return num < 2 ? &c2x_reg_st[num] : NULL;
	// SPECIAL num 0 is the product register P, 1 is PC.
	case C55_RC_SPECIAL: return num == 0 ? &c2x_reg_p : &c2x_reg_pc;
	default: return NULL;
	}
}

// id -> RzAnalysisOp type

RZ_IPI ut32 c2x_op_type(ut16 id) {
	switch (id) {
	case C2X_INS_NOP:
		return RZ_ANALYSIS_OP_TYPE_NOP;
	case C2X_INS_ADD:
	case C2X_INS_ADDH:
	case C2X_INS_ADDS:
	case C2X_INS_ADDT:
	case C2X_INS_ADDC:
	case C2X_INS_ADDK:
	case C2X_INS_ADLK:
	case C2X_INS_APAC:
	case C2X_INS_ADRK:
		return RZ_ANALYSIS_OP_TYPE_ADD;
	case C2X_INS_SUB:
	case C2X_INS_SUBH:
	case C2X_INS_SUBS:
	case C2X_INS_SUBT:
	case C2X_INS_SUBC:
	case C2X_INS_SUBB:
	case C2X_INS_SUBK:
	case C2X_INS_SBLK:
	case C2X_INS_SPAC:
	case C2X_INS_SBRK:
	case C2X_INS_NEG:
		return RZ_ANALYSIS_OP_TYPE_SUB;
	case C2X_INS_AND:
	case C2X_INS_ANDK:
		return RZ_ANALYSIS_OP_TYPE_AND;
	case C2X_INS_OR:
	case C2X_INS_ORK:
		return RZ_ANALYSIS_OP_TYPE_OR;
	case C2X_INS_XOR:
	case C2X_INS_XORK:
		return RZ_ANALYSIS_OP_TYPE_XOR;
	case C2X_INS_CMPL:
		return RZ_ANALYSIS_OP_TYPE_NOT;
	case C2X_INS_SFL:
	case C2X_INS_ROL:
		return RZ_ANALYSIS_OP_TYPE_SHL;
	case C2X_INS_SFR:
	case C2X_INS_ROR:
		return RZ_ANALYSIS_OP_TYPE_SHR;
	case C2X_INS_MPY:
	case C2X_INS_MPYK:
	case C2X_INS_MPYA:
	case C2X_INS_MPYS:
	case C2X_INS_MPYU:
	case C2X_INS_SQRA:
	case C2X_INS_SQRS:
	case C2X_INS_PAC:
	case C2X_INS_MAC:
	case C2X_INS_MACD:
		return RZ_ANALYSIS_OP_TYPE_MUL;
	case C2X_INS_LAC:
	case C2X_INS_LACT:
	case C2X_INS_LACK:
	case C2X_INS_ZAC:
	case C2X_INS_ZALH:
	case C2X_INS_ZALS:
	case C2X_INS_ZALR:
	case C2X_INS_LAR:
	case C2X_INS_LARK:
	case C2X_INS_LRLK:
	case C2X_INS_LALK:
	case C2X_INS_LDP:
	case C2X_INS_LDPK:
	case C2X_INS_LT:
	case C2X_INS_LTA:
	case C2X_INS_LTD:
	case C2X_INS_LTP:
	case C2X_INS_LTS:
	case C2X_INS_LST:
	case C2X_INS_LST1:
	case C2X_INS_LPH:
	case C2X_INS_DMOV:
	case C2X_INS_PSHD:
	case C2X_INS_PUSH:
	case C2X_INS_ABS:
		return RZ_ANALYSIS_OP_TYPE_MOV;
	case C2X_INS_SACL:
	case C2X_INS_SACH:
	case C2X_INS_SAR:
	case C2X_INS_SST:
	case C2X_INS_SST1:
	case C2X_INS_SPL:
	case C2X_INS_SPH:
	case C2X_INS_POPD:
	case C2X_INS_POP:
	case C2X_INS_TBLW:
		return RZ_ANALYSIS_OP_TYPE_STORE;
	case C2X_INS_TBLR:
		return RZ_ANALYSIS_OP_TYPE_LOAD;
	case C2X_INS_IN:
	case C2X_INS_OUT:
		return RZ_ANALYSIS_OP_TYPE_IO;
	case C2X_INS_B:
		return RZ_ANALYSIS_OP_TYPE_JMP;
	case C2X_INS_BACC:
		return RZ_ANALYSIS_OP_TYPE_UJMP;
	case C2X_INS_BV:
	case C2X_INS_BGZ:
	case C2X_INS_BLEZ:
	case C2X_INS_BLZ:
	case C2X_INS_BGEZ:
	case C2X_INS_BNZ:
	case C2X_INS_BZ:
	case C2X_INS_BNV:
	case C2X_INS_BBZ:
	case C2X_INS_BBNZ:
	case C2X_INS_BIOZ:
	case C2X_INS_BANZ:
	case C2X_INS_BC:
	case C2X_INS_BNC:
		return RZ_ANALYSIS_OP_TYPE_CJMP;
	case C2X_INS_CALL:
		return RZ_ANALYSIS_OP_TYPE_CALL;
	case C2X_INS_CALA:
		return RZ_ANALYSIS_OP_TYPE_UCALL;
	case C2X_INS_RET:
		return RZ_ANALYSIS_OP_TYPE_RET;
	case C2X_INS_TRAP:
		return RZ_ANALYSIS_OP_TYPE_TRAP;
	default:
		return RZ_ANALYSIS_OP_TYPE_NULL;
	}
}

// id -> mnemonic (indexed by the C2X_INS_* id; unset ids read back "invalid")
static const char *const c2x_mnemonics[] = {
	[C2X_INS_NOP] = "nop",
	[C2X_INS_ADD] = "add",
	[C2X_INS_ADDH] = "addh",
	[C2X_INS_ADDS] = "adds",
	[C2X_INS_ADDT] = "addt",
	[C2X_INS_ADDC] = "addc",
	[C2X_INS_SUB] = "sub",
	[C2X_INS_SUBH] = "subh",
	[C2X_INS_SUBS] = "subs",
	[C2X_INS_SUBT] = "subt",
	[C2X_INS_SUBC] = "subc",
	[C2X_INS_SUBB] = "subb",
	[C2X_INS_LAC] = "lac",
	[C2X_INS_LACT] = "lact",
	[C2X_INS_LACK] = "lack",
	[C2X_INS_ZAC] = "zac",
	[C2X_INS_ZALH] = "zalh",
	[C2X_INS_ZALS] = "zals",
	[C2X_INS_ZALR] = "zalr",
	[C2X_INS_ADDK] = "addk",
	[C2X_INS_SUBK] = "subk",
	[C2X_INS_ABS] = "abs",
	[C2X_INS_NEG] = "neg",
	[C2X_INS_CMPL] = "cmpl",
	[C2X_INS_SFL] = "sfl",
	[C2X_INS_SFR] = "sfr",
	[C2X_INS_ROL] = "rol",
	[C2X_INS_ROR] = "ror",
	[C2X_INS_NORM] = "norm",
	[C2X_INS_SACL] = "sacl",
	[C2X_INS_SACH] = "sach",
	[C2X_INS_PAC] = "pac",
	[C2X_INS_APAC] = "apac",
	[C2X_INS_SPAC] = "spac",
	[C2X_INS_LPH] = "lph",
	[C2X_INS_SPL] = "spl",
	[C2X_INS_SPH] = "sph",
	[C2X_INS_LAR] = "lar",
	[C2X_INS_SAR] = "sar",
	[C2X_INS_LARK] = "lark",
	[C2X_INS_LARP] = "larp",
	[C2X_INS_MAR] = "mar",
	[C2X_INS_LDP] = "ldp",
	[C2X_INS_LDPK] = "ldpk",
	[C2X_INS_ADRK] = "adrk",
	[C2X_INS_SBRK] = "sbrk",
	[C2X_INS_LT] = "lt",
	[C2X_INS_LTA] = "lta",
	[C2X_INS_LTD] = "ltd",
	[C2X_INS_LTP] = "ltp",
	[C2X_INS_LTS] = "lts",
	[C2X_INS_MPY] = "mpy",
	[C2X_INS_MPYK] = "mpyk",
	[C2X_INS_MPYA] = "mpya",
	[C2X_INS_MPYS] = "mpys",
	[C2X_INS_MPYU] = "mpyu",
	[C2X_INS_SQRA] = "sqra",
	[C2X_INS_SQRS] = "sqrs",
	[C2X_INS_MAC] = "mac",
	[C2X_INS_MACD] = "macd",
	[C2X_INS_AND] = "and",
	[C2X_INS_OR] = "or",
	[C2X_INS_XOR] = "xor",
	[C2X_INS_ANDK] = "andk",
	[C2X_INS_ORK] = "ork",
	[C2X_INS_XORK] = "xork",
	[C2X_INS_LST] = "lst",
	[C2X_INS_LST1] = "lst1",
	[C2X_INS_SST] = "sst",
	[C2X_INS_SST1] = "sst1",
	[C2X_INS_LALK] = "lalk",
	[C2X_INS_ADLK] = "adlk",
	[C2X_INS_SBLK] = "sblk",
	[C2X_INS_LRLK] = "lrlk",
	[C2X_INS_RPT] = "rpt",
	[C2X_INS_RPTK] = "rptk",
	[C2X_INS_DMOV] = "dmov",
	[C2X_INS_PSHD] = "pshd",
	[C2X_INS_POPD] = "popd",
	[C2X_INS_PUSH] = "push",
	[C2X_INS_POP] = "pop",
	[C2X_INS_BITT] = "bitt",
	[C2X_INS_BIT] = "bit",
	[C2X_INS_TBLR] = "tblr",
	[C2X_INS_TBLW] = "tblw",
	[C2X_INS_BLKD] = "blkd",
	[C2X_INS_BLKP] = "blkp",
	[C2X_INS_IN] = "in",
	[C2X_INS_OUT] = "out",
	[C2X_INS_B] = "b",
	[C2X_INS_BACC] = "bacc",
	[C2X_INS_CALA] = "cala",
	[C2X_INS_CALL] = "call",
	[C2X_INS_RET] = "ret",
	[C2X_INS_BANZ] = "banz",
	[C2X_INS_BV] = "bv",
	[C2X_INS_BGZ] = "bgz",
	[C2X_INS_BLEZ] = "blez",
	[C2X_INS_BLZ] = "blz",
	[C2X_INS_BGEZ] = "bgez",
	[C2X_INS_BNZ] = "bnz",
	[C2X_INS_BZ] = "bz",
	[C2X_INS_BNV] = "bnv",
	[C2X_INS_BBZ] = "bbz",
	[C2X_INS_BBNZ] = "bbnz",
	[C2X_INS_BIOZ] = "bioz",
	[C2X_INS_BC] = "bc",
	[C2X_INS_BNC] = "bnc",
	[C2X_INS_TRAP] = "trap",
	[C2X_INS_IDLE] = "idle",
	[C2X_INS_EINT] = "eint",
	[C2X_INS_DINT] = "dint",
	[C2X_INS_ROVM] = "rovm",
	[C2X_INS_SOVM] = "sovm",
	[C2X_INS_CNFD] = "cnfd",
	[C2X_INS_CNFP] = "cnfp",
	[C2X_INS_RSXM] = "rsxm",
	[C2X_INS_SSXM] = "ssxm",
	[C2X_INS_SPM] = "spm",
	[C2X_INS_RXF] = "rxf",
	[C2X_INS_SXF] = "sxf",
	[C2X_INS_FORT] = "fort",
	[C2X_INS_RC] = "rc",
	[C2X_INS_SC] = "sc",
	[C2X_INS_RTC] = "rtc",
	[C2X_INS_STC] = "stc",
	[C2X_INS_RFSM] = "rfsm",
	[C2X_INS_SFSM] = "sfsm",
	[C2X_INS_RHM] = "rhm",
	[C2X_INS_SHM] = "shm",
	[C2X_INS_RTXM] = "rtxm",
	[C2X_INS_STXM] = "stxm",
	[C2X_INS_CMPR] = "cmpr",
	[C2X_INS_CONF] = "conf",
};

RZ_IPI const char *c2x_mnemonic(ut16 id) {
	if (id < RZ_ARRAY_SIZE(c2x_mnemonics) && c2x_mnemonics[id]) {
		return c2x_mnemonics[id];
	}
	return "invalid";
}

// descriptor + analysis entry

/**
 * \brief C2x architecture descriptor for the shared C55 engine.
 *
 * Binds the C2x opcode table, operand extractors and consumers; the C5x
 * superset reuses these for the instruction ids the two share.
 */
const C55ArchDesc c2x_arch_desc = {
	.arch = C55_ARCH_C2X,
	.cpu_name = "c2x",
	.table = c2x_table,
	.table_len = sizeof(c2x_table) / sizeof(c2x_table[0]),
	.insn_len = NULL, // every row carries a fixed .len
	.reg_info = c2x_reg_info,
	.mnemonic = c2x_mnemonic,
	.op_type = c2x_op_type,
	.lift = c2x_lift,
	.mem = { .addr_unit_log2 = 0, .ptr_width = 16, .big_endian = true, .page_reg = "dp" },
	.ea = c2x_ea,
	.fill_dual = NULL,
	.words_le = false, // C2x words are stored MSB-first; no per-word swap
	.cond_exec_prefix = false,
	.parallel_prefix = false,
};

// Populate the data-flow analysis fields from the decoded operands so variable
// and argument analysis (and data-xref tracking) can inspect the instruction:
// the source/destination access values (op->src/op->dst) for register and memory
// operands, and op->ptr for direct (data-page-relative) data accesses. Shared by
// the C2x and C5x analysis paths, which use the same operand representation. The
// register/memory roles follow the load/store direction the shared filler has
// already resolved (a load's register operand is the destination; a store's
// memory operand is the destination), with the accumulator left implicit.
RZ_IPI void c2x_fill_op_access(RzAnalysis *analysis, const C55ArchDesc *a,
	const C55Insn *insn, RzAnalysisOp *op) {
	if (!analysis || !a || !insn || !op) {
		return;
	}
	RzReg *reg = rz_analysis_get_reg(analysis);
	// Resolve the memory role from the analysis op type: a store writes its
	// memory operand, a load / accumulator-move reads it; everything else
	// (arithmetic, logic, ...) reads its operands into the implicit
	// accumulator. The shared filler's load/store direction targets the C54x
	// operand layout, so set the read/write direction here for the C2x/C5x
	// memory forms.
	const bool is_store = op->type == RZ_ANALYSIS_OP_TYPE_STORE;
	const bool is_load = op->type == RZ_ANALYSIS_OP_TYPE_LOAD ||
		op->type == RZ_ANALYSIS_OP_TYPE_MOV;
	bool has_mem = false;
	size_t srci = 0;
	for (ut8 i = 0; i < insn->n_ops; i++) {
		const C55Operand *o = &insn->ops[i];
		if (o->kind == C55_OP_MEM) {
			has_mem = true;
			RzAnalysisValue *v = rz_analysis_value_new();
			if (!v) {
				continue;
			}
			v->type = RZ_ANALYSIS_VAL_MEM;
			v->memref = (o->access ? o->access : 16) / 8;
			if (o->amode == C55_AM_DIRECT) {
				// Direct addressing: the 7-bit field is the data offset within
				// the current data page; expose it as the access pointer.
				v->base = (ut64)(o->disp & 0x7f);
				op->ptr = v->base;
				op->ptrsize = v->memref;
			}
			// Indirect forms select the auxiliary register through ARP at run
			// time, so no base register is known here; naming one would point
			// every indirect access at the same AR.
			if (is_store && !op->dst) {
				op->dst = v;
			} else if (srci < RZ_ARRAY_SIZE(op->src)) {
				op->src[srci++] = v;
			} else {
				rz_analysis_value_free(v);
			}
		} else if (o->kind == C55_OP_REG && a->reg_info) {
			const C55RegInfo *ri = a->reg_info(o->reg.cls, o->reg.num, o->reg.sub);
			if (!ri) {
				continue;
			}
			RzAnalysisValue *v = rz_analysis_value_new();
			if (!v) {
				continue;
			}
			v->type = RZ_ANALYSIS_VAL_REG;
			v->reg = rz_reg_get(reg, ri->name, RZ_REG_TYPE_ANY);
			if (is_load && !op->dst) {
				op->dst = v;
			} else if (srci < RZ_ARRAY_SIZE(op->src)) {
				op->src[srci++] = v;
			} else {
				rz_analysis_value_free(v);
			}
		} else if (o->kind == C55_OP_IMM && srci < RZ_ARRAY_SIZE(op->src)) {
			RzAnalysisValue *v = rz_analysis_value_new();
			if (!v) {
				continue;
			}
			v->type = RZ_ANALYSIS_VAL_IMM;
			v->imm = (st64)o->imm;
			op->src[srci++] = v;
		}
	}
	if (has_mem) {
		if (is_store) {
			op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		} else if (is_load || op->direction == 0) {
			op->direction = RZ_ANALYSIS_OP_DIR_READ;
		}
	}
}

/**
 * \brief Analysis entry point for the "c2x" CPU.
 * \param analysis Current analysis session
 * \param op Operation to fill in
 * \param addr Address \p buf was read from
 * \param buf Instruction bytes
 * \param len Number of readable bytes in \p buf
 * \param mask Which parts of \p op the caller wants filled
 * \return Instruction length in bytes, or -1 on an undecodable word
 */
RZ_IPI int tms320_c2x_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (!op || !buf || len < 1) {
		return 0;
	}
	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_NULL;
	C55Insn ci;
	if (c55_decode(&c2x_arch_desc, buf, len, &ci)) {
		c55_fill_analysis(&c2x_arch_desc, &ci, op);
		c2x_fill_op_access(analysis, &c2x_arch_desc, &ci, op);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = c55_lift(&c2x_arch_desc, &ci, op->addr);
		}
	} else {
		// Undecodable word: flag it and give a one-word fallback size, but
		// report the failure to the caller with -1 (the common plugin convention).
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->size = 1;
		return -1;
	}
	return op->size;
}

/*
 * Complete TMS320C2x encoding map (for extending c2x_table). Bit legend:
 *   A 7-bit direct dma | M 3-bit AR-modify | N 4-bit next-ARP | T 4-bit shift
 *   S 3-bit shift | R 3-bit AR# | P 4-bit port | D 8-bit imm | K small imm
 *   W 16-bit imm (next word) | C 2-bit compare | B 16-bit branch target (word)
 *
 * 0xxx ADD A,T / M,T,N        40xx ZALH    50xx LST     78xx SST     8xxx IN A,P
 * 1xxx SUB                    41xx ZALS    51xx LST1    79xx SST1    9xxx BIT A,T
 * 2xxx LAC                    42xx LACT    52xx LDP     7Axx POPD    Axx-Bxx MPYK W
 * 3xxx LAR R,A                43xx ADDC    53xx LPH     7Bxx ZALR    Cxxx LARK R,D
 * 38xx MPY    3Cxx LT         44xx SUBH    54xx PSHD    7Cxx SPL     C8xx LDPK K
 * 39xx SQRA   3Dxx LTA        45xx SUBS    55xx MAR/NOP 7Dxx SPH     CAxx LACK (CA00=ZAC)
 * 3Axx MPYA   3Exx LTP        46xx SUBT    56xx DMOV    7Exx ADRK    CBxx RPTK
 * 3Bxx MPYS   3Fxx LTD        47xx SUBC    57xx BITT    7Fxx SBRK    CCxx ADDK
 *                             48xx ADDH    58xx TBLR                 CDxx SUBK
 *                             49xx ADDS    59xx TBLW    5Cxx MACD B,*   CExx (no-op block)
 *                             4Axx ADDT    5Axx SQRS    5Dxx MAC  B,*   CFxx MPYS
 *                             4Bxx RPT     5Bxx LTS     5Exx BC   B     Dx00 LRLK R,W
 *                             4Cxx XOR                  5Fxx BNC  B     Dx01 LALK W,T
 *                             4Dxx OR      60xx SACL S                  Dx02 ADLK
 *                             4Exx AND     68xx SACH S   Exxx OUT A,P    Dx03 SBLK
 *                             4Fxx SUBB    70xx SAR R,A                  Dx04 ANDK
 *                                                                        Dx05 ORK
 * CE block (exact): CE00 EINT CE01 DINT CE02 ROVM CE03 SOVM CE04 CNFD   Dx06 XORK
 *   CE05 CNFP CE06 RSXM CE07 SSXM CE08-B SPM K CE0C RXF CE0D SXF
 *   CE0E-F FORT K CE14 PAC CE15 APAC CE16 SPAC CE18 SFL CE19 SFR CE1B ABS
 *   CE1C PUSH CE1D POP CE1E TRAP CE1F IDLE CE20 RTXM CE21 STXM CE23 NEG
 *   CE24 CALA CE25 BACC CE26 RET CE27 CMPL CE30 RC CE31 SC CE32 RTC CE33 STC
 *   CE34 ROL CE35 ROR CE36 RFSM CE37 SFSM CE38 RHM CE39 SHM CE3C-F CONF K
 *   CE50-3 CMPR C  CEx2 (110011101mmm0010) NORM M
 * F-block branches (opcode + B word + addressing byte, bit7=1): F0 BV F1 BGZ
 *   F2 BLEZ F3 BLZ F4 BGEZ F5 BNZ F6 BZ F7 BNV  (F8 BBZ F9 BBNZ FA BIOZ
 *   FB BANZ FE CALL FF B are the conventional assignments; verify the tail).
 *   BLKD/BLKP are the block-move forms (opcode + source-address word).
 */
