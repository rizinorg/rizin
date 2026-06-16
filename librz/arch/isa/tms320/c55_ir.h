// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TMS320_C55_IR_H
#define RZ_TMS320_C55_IR_H

#include <rz_types.h>
#include <rz_analysis.h> // RzAnalysisOp, RzAnalysisOpType, RzILOpEffect, RzILOpPure

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * Shared decode IR for the TMS320 fixed-point DSP family (C54x / C55x / C55x+).
 *
 * Decoders run once and produce a \ref C55Insn; three pure consumers read it and
 * never re-parse text: c55_format() (asm string), c55_fill_analysis()
 * (RzAnalysisOp) and c55_lift() (RzIL). Everything generic (IR, decode engine,
 * operand extractors, consumers, RzIL primitives) is shared; everything
 * arch-specific (encoding, register set, mnemonic/op-type/lift tables, exotic
 * addressing) sits behind one \ref C55ArchDesc. C55x and C55x+ differ only in
 * encoding and share id/register/mnemonic tables; C54x supplies its own
 * descriptor but reuses the engine, IR and primitives.
 *
 * An arch may skip the decode engine and fill \ref C55Insn from its own
 * front-end while still using the consumers and primitives -- this is how a
 * future C64x RzIL lifter would attach to capstone's existing C64x disassembler
 * (C64x has disasm but no IL yet), so the decode-table fields of \ref C55ArchDesc
 * are optional.
 */

/** Family member (so shared code can special-case where unavoidable). */
typedef enum {
	C55_ARCH_C54X = 0, ///< TMS320C54x
	C55_ARCH_C55X, ///< TMS320C55x
	C55_ARCH_C55XPLUS, ///< TMS320C55x+
} C55Arch;

/** Register class; family-wide superset, each arch uses only its subset. */
typedef enum {
	C55_RC_NONE = 0, ///< no register
	C55_RC_AC, ///< accumulators: C54x A/B (0..1), C55x AC0..31 (40-bit)
	C55_RC_AR, ///< 16-bit auxiliary regs ARn (C54x AR0..7; C55x low 16 of XARn)
	C55_RC_XAR, ///< 23-bit extended aux regs XARn (C55x/C55x+)
	C55_RC_T, ///< temp regs: C54x T (0); C55x T0..3
	C55_RC_TRN, ///< transition register(s) (Viterbi)
	C55_RC_CDP, ///< coefficient data pointer (CDP / XCDP)
	C55_RC_SP, ///< stack pointer
	C55_RC_DP, ///< data-page pointer (C54x DP; C55x DPH:DP)
	C55_RC_BK, ///< circular-buffer size reg(s) (BK; BK03/BK47/BKC)
	C55_RC_ARP, ///< aux-reg pointer (C54x indirect-mode selector)
	C55_RC_ST, ///< status regs (C54x ST0/ST1/PMST; C55x ST0_55..ST3_55)
	C55_RC_SPECIAL, ///< anything else addressed by name (PC, RPTC, BRC, ...)
	C55_RC_TC, ///< test-control status bits TC1/TC2 (the btst destination)
} C55RegClass;

/** Accumulator sub-field selector. */
typedef enum {
	C55_SUB_NONE = 0, ///< whole register
	C55_SUB_LO, ///< .l, bits 15:0
	C55_SUB_HI, ///< .h, bits 31:16
	C55_SUB_GUARD, ///< .g, bits 39:32 (accumulator guard)
} C55SubReg;

/** Register reference, resolved to name/IL-var/width by C55ArchDesc::reg_info(). */
typedef struct {
	C55RegClass cls; ///< register class
	ut8 num; ///< index within the class (0 for singletons)
	C55SubReg sub; ///< accumulator sub-field selector
} C55Reg;

/** Per-arch register descriptor returned by C55ArchDesc::reg_info(). */
typedef struct {
	const char *name; ///< display name for the formatter ("ac0", "a", "xar15")
	const char *il_var; ///< RzIL global-variable name for the lifter (often == name)
	ut8 width; ///< IL bit-width (AR/T 16, XAR 23, AC 40, status 16, ...)
} C55RegInfo;

/**
 * Data-memory addressing mode (family-wide superset).
 *
 * EA-boundary contract: the GENERIC modes (above the divider) have an effective
 * address of base +/- {const | index | scaled index} in linear space and are
 * computed by c55_generic_ea() from \ref C55MemModel alone, with no arch state.
 * The ARCH-SPECIFIC modes need paging / BK / ARP / reverse-carry state and are
 * delegated to C55ArchDesc::ea(). Keeping this divider fixed is what lets a later
 * C54x (DP-direct / MMR / circular) attach without touching shipped C55 code.
 */
typedef enum {
	C55_AM_NONE = 0, ///< not a memory operand
	// generic: c55_generic_ea()
	C55_AM_INDIRECT, ///< *arN
	C55_AM_POSTINC, ///< *arN+
	C55_AM_POSTDEC, ///< *arN-
	C55_AM_PREINC, ///< *+arN
	C55_AM_PREDEC, ///< *-arN
	C55_AM_INDEXED, ///< *arN(short(#K)) / *sp(#K)
	C55_AM_IDXREG, ///< *arN(tM)
	C55_AM_POSTADD, ///< *(arN+tM)
	C55_AM_POSTSUB, ///< *(arN-tM)
	C55_AM_IDXSCALE, ///< *arN(tM<<#1)
	C55_AM_ABSOLUTE, ///< *(#k) absolute address
	C55_AM_CONST_IDX, ///< *arN(#K16) long const-index (2-byte extension, ARn unmodified)
	C55_AM_CONST_IDX_PRE, ///< *+arN(#K16) long const-index with pre-modify (2-byte extension, ARn += K16)
	C55_AM_ABS16, ///< abs16(#k16) data-page absolute: DPH:k16 (2-byte extension, k16 unsigned)
	// arch-specific: C55ArchDesc::ea()
	C55_AM_BITREV, ///< *(arN+t0b) reverse-carry (C54x *arN+0B)
	C55_AM_XAR15, ///< *arN(xar15)
	C55_AM_DIRECT, ///< C54x DP/SP-relative direct (@addr / addr)
	C55_AM_MMR, ///< C54x memory-mapped register
	C55_AM_CIRCULAR, ///< explicit circular via BK/ARP
	C55_AM_BITREV_SUB, ///< *(arN-t0b) reverse-carry (the decrement bit-reverse form)
} C55AddrMode;

/** Parameters c55_generic_ea() needs; set per session, not baked in. */
typedef struct {
	ut8 addr_unit_log2; ///< 0 = byte-addressed; 1 = word-pointer (EA = reg<<1, C55x)
	ut8 ptr_width; ///< pointer-register width in bits (C54x AR 16, C55x XAR 23)
	bool big_endian; ///< image endianness
	const char *page_reg; ///< il_var of the data-page register for abs16 (DPH); NULL = page 0
} C55MemModel;

/** Operand kind; selects which of the fields below are meaningful. */
typedef enum {
	C55_OP_NONE = 0, ///< unused slot
	C55_OP_REG, ///< register (optional sub-field, optional shift wrapper)
	C55_OP_IMM, ///< immediate (width + signedness, optional shift wrapper)
	C55_OP_MEM, ///< data-memory operand (base + amode + index + disp + access)
	C55_OP_COND, ///< condition: reg <relop> 0|imm|reg (bcc/xcc/cmp/btst)
	C55_OP_INVALID, ///< operand the decoder cannot represent yet; forces legacy fallback
} C55OpKind;

/** Relational operator for \ref C55_OP_COND. */
typedef enum {
	C55_REL_EQ, ///< ==
	C55_REL_NE, ///< !=
	C55_REL_LT, ///< <
	C55_REL_LE, ///< <=
	C55_REL_GT, ///< >
	C55_REL_GE, ///< >=
} C55Relop;

/** A decoded operand. */
typedef struct {
	C55OpKind kind; ///< discriminates which fields below apply
	const char *raw; ///< if set, the operand renders as this verbatim string (the un-decoded "Baddr" bit-address placeholder of btstp); other fields ignored

	C55Reg reg; ///< REG / MEM base / COND subject register
	ut64 imm; ///< IMM value or COND compare-constant
	bool imm_signed; ///< IMM / disp is signed
	ut8 width; ///< IL width of the REG / IMM

	C55AddrMode amode; ///< MEM: addressing mode
	C55Reg index; ///< MEM: index register (Tm) for indexed / post-modify modes
	st32 disp; ///< MEM: signed displacement (INDEXED / DIRECT)
	ut64 abs_addr; ///< MEM: address for ABSOLUTE / MMR
	ut8 access; ///< MEM: access width in bits (8/16/32 = byte/word/dbl)
	bool uns; ///< MEM: uns() wrapper -> zero-extend on load
	ut8 byte_sel; ///< MEM: 0 none, 1 high_byte(), 2 low_byte(), 3 byte() wrapper

	int8_t shamt; ///< REG/IMM: shift amount (when not \ref sh_by_reg)
	bool sh_left; ///< REG/IMM: shift left (else right)
	bool sh_by_reg; ///< REG/IMM: shift amount is \ref index register, not \ref shamt
	bool shamt_hex; ///< IMM: render the shift count as "<< 0x%X" (always, even 0) rather than "<< #%d"
	bool neg_imm; ///< IMM: a negated-magnitude immediate, always rendered "-0x%X" (even -0); see opcode 0x3e
	bool shl_join; ///< IMM: render joined to the previous operand by " << " (the "ACx << #SHIFTW" syntax) rather than ", "
	bool qual_join; ///< render joined to the previous operand by " || " (the b/call ACx "|| local()/|| far()" parallel qualifiers) rather than ", "
	bool space_join; ///< render joined to the previous operand by " " (no comma); used for the first operand of the C54x parallel second operation ("|| add Xmem, dst")
	C55Reg sh_mem_reg; ///< MEM: a register shift count Tx rendered as " << Tx" after the operand (the "Smem << Tx" forms), distinct from \ref index
	bool sh_mem_reg_set; ///< MEM: \ref sh_mem_reg is present
	bool mem_round; ///< MEM: render the whole memory operand wrapped in rnd(...) (the "mov rnd(Smem << Tx), ACx" rounding forms)
	ut8 wrap_half; ///< REG: 1 -> hi(...), 2 -> lo(...) wrapper around the (shifted) accumulator (the 0xb4 "mov hi(ACx << Tx), Smem" store forms)
	bool wrap_round; ///< REG: render the (shifted) accumulator wrapped in rnd(...)
	bool wrap_uns; ///< REG: render the (shifted) accumulator wrapped in uns(...)
	bool dbl; ///< REG: rendered dbl(...) (full accumulator / pointer push-pop)
	bool dual_wrap; ///< MEM: render the memory operand wrapped in dual(...) (the subadd dual-access form)
	bool addr; ///< IMM: rendered as a 24-bit address (#0x%06x), e.g. branch/call fields
	bool is_bit; ///< IMM: a bit number rendered with the '@#' prefix (the btst/bclr/bset/bnot/btstp bit operand)
	bool hash_dec; ///< IMM: rendered as a signed decimal with a '#' prefix (#1 / #-1), e.g. the sftl fixed-shift literal
	bool reltarget; ///< IMM: a pc-relative branch offset used for target computation but rendered as a plain immediate (not a 24-bit address)
	bool reltarget_unsigned; ///< IMM: a \ref reltarget whose offset is non-negative, so it is not sign-extended before being added to pc
	bool abs_target; ///< IMM: an absolute branch target (the operand value is the target, not a pc-relative displacement)

	C55Relop relop; ///< COND: relational operator
	bool cmp_to_reg; ///< COND: compare to \ref index register rather than \ref imm
	bool cond_is_flag; ///< COND: a status-bit flag expression rather than reg <relop> 0
	ut8 cond_flag; ///< COND: status-flag id (when \ref cond_is_flag)
	bool cmp_imm; ///< COND: compare to an explicit immediate (#0x..) vs literal #0
	bool cmp_mem; ///< COND: the left-hand side is a memory operand (cmp Smem <rel> #k)
	bool elide_if_eq_prev; ///< REG: omit this operand (and its separator) when it equals the immediately preceding operand (mpyk/mack ACy defaulting to ACx)
	bool circular; ///< MEM: C54x circular-addressing variant (the '%' suffix: *arN+%, *arN+0%, ...)
	bool is_shift; ///< IMM: this operand is a standalone C54x shift count applied to the preceding value (\ref shamt / \ref sh_left carry the amount/direction)
} C55Operand;

/// Max operands: amar carries 3 memory operands (+dst); dmaxdiff/maxdiff reach 5.
#define C55_MAX_OPS 6

/// Sentinel abs_addr value meaning "the absolute address is a trailing extension
/// to be filled by the decoder" (out of the 24-bit program-address range).
#define C55_ABS_EXT 0xffffffffffffffffULL

/**
 * Lift operation for instructions whose RzAnalysis op type does not determine
 * their RzIL semantics. For example neg maps to RZ_ANALYSIS_OP_TYPE_SUB (there
 * is no dedicated NEG op type), so the lifter cannot tell it apart from a real
 * sub by the op type alone; the decode table sets this field to select the
 * lift explicitly. C55_LOP_NONE (the default) means the lifter dispatches on
 * the op type as usual.
 */
typedef enum {
	C55_LOP_NONE = 0,
	C55_LOP_NEG, ///< dst = -src
	C55_LOP_MAX, ///< dst = (src > dst) ? src : dst
	C55_LOP_MIN, ///< dst = (src < dst) ? src : dst
	C55_LOP_ABS, ///< dst = (src < 0) ? -src : src
	C55_LOP_MAC, ///< dst += product (multiply-accumulate, on the MUL path)
	C55_LOP_MAS, ///< dst -= product (multiply-subtract, on the MUL path)
	C55_LOP_FIRSADD, ///< FIR symmetric: ACy += ACx.h*Cmem :: ACx = (Xmem<<16)+(Ymem<<16)
	C55_LOP_FIRSSUB, ///< FIR antisymmetric: ACy += ACx.h*Cmem :: ACx = (Xmem<<16)-(Ymem<<16)
	C55_LOP_SQDST, ///< square distance: ACy += ACx.h*ACx.h :: ACx = (Xmem<<16)-(Ymem<<16)
	C55_LOP_ABDST, ///< absolute distance: ACy += |ACx.h| :: ACx = (Xmem<<16)-(Ymem<<16)
	C55_LOP_LMS, ///< least mean square: ACy += Xmem*Ymem :: ACx = round(ACx + (Xmem<<16))
	C55_LOP_ROUND, ///< dst = round(src) -- (src + 0x8000) with the low word cleared
	C55_LOP_SAT, ///< dst = saturate(src) to the 32-bit signed range
	C55_LOP_ADDV, ///< dst = dst + |src(32-16)| (addition with absolute value)
	C55_LOP_SFTL, ///< dst = sftl(src, Tx): logical shift, right by -Tx when Tx<0 else left by Tx
	C55_LOP_SFTS, ///< dst = sfts(src, Tx): arithmetic right shift (sign-fill) / logical left
	C55_LOP_ANDSHL, ///< dst = dst & (src << #SHIFTW)
	C55_LOP_ORSHL, ///< dst = dst | (src << #SHIFTW)
	C55_LOP_XORSHL, ///< dst = dst ^ (src << #SHIFTW)
	C55_LOP_ADDSHL, ///< dst = dst + (src << #SHIFTW)
	C55_LOP_SUBSHL, ///< dst = dst - (src << #SHIFTW)
	C55_LOP_MOVSHL, ///< dst = (src << #SHIFTW): load a shifted immediate (mov #k16 << #sh)
	C55_LOP_ANDMEM, ///< ACy = ACx & sx(Smem)
	C55_LOP_ORMEM, ///< ACy = ACx | sx(Smem)
	C55_LOP_XORMEM, ///< ACy = ACx ^ sx(Smem)
	C55_LOP_BITCLR, ///< STx = STx & ~(1 << #k4): clear a status-register bit (bclr); also the register bit ops with an is_bit operand
	C55_LOP_BITSET, ///< STx = STx | (1 << #k4): set a status-register bit (bset)
	C55_LOP_BITNOT, ///< dst = dst ^ (1 << k): toggle a register bit (bnot)
	C55_LOP_STBITCLR, ///< st0_55 = ite(0, st0_55 | (1<<bit), st0_55 & ~(1<<bit)): clear an st0_55 named bit
	C55_LOP_STBITSET, ///< st0_55 = ite(1, st0_55 | (1<<bit), st0_55 & ~(1<<bit)): set an st0_55 named bit
	C55_LOP_AMOV, ///< dst = zero-extend(#k16): load a 16-bit constant/address (amov)
	C55_LOP_CMP, ///< TCz = (SRC <relop> DST): register compare writing a status TC bit
	C55_LOP_CMPAND, ///< TCz = (SRC <relop> DST) && TCx
	C55_LOP_CMPOR, ///< TCz = (SRC <relop> DST) || TCx
	C55_LOP_AREG_MOV, ///< dst = cast(dst, src): register move with width conversion (amov ACx,ACy)
	C55_LOP_AREG_SUB, ///< dst = dst - cast(dst, src): register address subtract (asub ACx,ACy)
	C55_LOP_AREG_ADD, ///< dst = dst + cast(dst, src): register/immediate address add (aadd #k,reg)
	C55_LOP_AREG_AND, ///< dst = dst & cast(dst, src): A-unit register and (and src, dst)
	C55_LOP_AREG_OR, ///< dst = dst | cast(dst, src): A-unit register or (or src, dst)
	C55_LOP_AREG_XOR, ///< dst = dst ^ cast(dst, src): A-unit register xor (xor src, dst)
	C55_LOP_NOP, ///< no data effect: lift to nop (repeat/loop control etc.)
	C55_LOP_MOVMEM, ///< storew(Ymem, loadw(Xmem)): dual-memory move (Xmem=src, Ymem=dst); dbl operands move a 32-bit word
	C55_LOP_DUALADD, ///< ACx = sx(Xmem) + sx(Ymem): dual-memory add into an accumulator
	C55_LOP_DUALSUB, ///< ACx = sx(Xmem) - sx(Ymem): dual-memory subtract into an accumulator
	C55_LOP_OPAQUE, ///< decode + analyse only; data effect not modelled (no IL)
	C55_LOP_ROL, ///< ACy = rotate-left(ACx) by one through a status bit (carry/tc2)
	C55_LOP_ROR, ///< ACy = rotate-right(ACx) by one through a status bit (carry/tc2)
	C55_LOP_MPYK, ///< ACy = #k * ACx: multiply accumulator low word by a signed constant (mpyk/mpykr)
	C55_LOP_MACK, ///< ACy = ACx + #k * Tx: multiply-accumulate a signed constant by a Tx coefficient (mack/mackr)
	C55_LOP_ADDK, ///< dst = ACx + zero-extend(#k16): immediate add (opcode 0x7b)
	C55_LOP_SUBK, ///< dst = ACx - zero-extend(#k16): immediate subtract (opcode 0x7c)
	C55_LOP_ANDK, ///< dst = ACx & zero-extend(#k16): immediate and (opcode 0x7d)
	C55_LOP_ORK, ///< dst = ACx | zero-extend(#k16): immediate or (opcode 0x7e)
	C55_LOP_XORK, ///< dst = ACx ^ zero-extend(#k16): immediate xor (opcode 0x7f)
	C55_LOP_RPTADD, ///< CSR = CSR + src: single-repeat-counter add (rptadd CSR, src). The repeat loop itself (the next instruction running CSR+1 times) is a control-flow effect that one-instruction RzIL cannot express; only the named CSR write is modelled.
	C55_LOP_RPTSUB, ///< CSR = CSR - src: single-repeat-counter subtract (rptsub CSR, src). As with RPTADD, only the CSR write is modelled, not the repeat loop.
} C55LiftOp;

/** A fully decoded instruction: the single hand-off from decode to the consumers. */
typedef struct {
	C55Arch arch; ///< producing family member
	ut16 id; ///< arch-local instruction id (TMS320C5{4,5}_INS_*); opaque to shared code
	C55LiftOp lop; ///< explicit lift op (C55_LOP_NONE => dispatch on the op type)
	ut8 size; ///< instruction length in bytes

	C55Operand ops[C55_MAX_OPS]; ///< operands, in assembly order
	ut8 n_ops; ///< number of valid entries in \ref ops

	bool round; ///< rounding variant (r)
	bool fract; ///< fractional-mode variant (f), rendered before the 'r' suffix (mpyk -> mpykf -> mpykfr)
	bool m40; ///< M40 / 40-bit mode (40)
	bool saturate; ///< saturating variant ((saturate / sat)
	bool side_load; ///< memory-MAC side-load: also load Smem into T3 ([T3 = ]Smem)
	bool square; ///< squaring multiply: the (memory) multiplicand is multiplied by itself
	bool parallel; ///< has a "||" parallel companion slot
	bool dual; ///< "::" paired form (dual MAC: two parallel sub-ops sharing Cmem)
	C55LiftOp lop2; ///< dual: lift op of the second sub-MAC (sub1 uses \ref lop)
	bool amar1; ///< dual: sub1 is an "amar" address-modify (no product)
	bool shift1; ///< dual: sub1 accumulates with the accumulator shifted right 16 (">> #16")
	bool shift2; ///< dual: sub2 accumulates with the accumulator shifted right 16 (">> #16")
	bool shift16; ///< single MAC: the accumulator term is shifted right 16 before the product (macm ... ACx >> #16)
	bool mac_mov; ///< MAC :: parallel load: a Tx-coefficient MAC (ops[0..2]) with a parallel "mov Ymem << #16, ACy" (ops[3..4])
	bool mant_nexp; ///< "mant ACa, ACb :: nexp ACa, ACc": ops [0]=ACa [1]=ACb [2]=ACc, ACa shared by both halves
	bool mac_store; ///< C55x 0x87 parallel dual-MAC store: "MN Xmem, Tx, ACy :: mov hi(ACx << t2), Ymem" and the add/sub/mov << #16 variants
	bool diff_pair; ///< max/min-diff form: ops [0..3]=ACc,ACd,ACa,ACb [4]=trn; the trn is wrapped in pair() (the non-d variants)
	bool diff_form; ///< max/min/dmax/dmin-diff "ACc, ACd, ACa, ACb, [pair(]trn[)]" rendering
	bool uns_all; ///< whole-operation unsigned (mnemonic 'u' suffix, e.g. mpymu): operands multiplied unsigned, no per-operand uns() wrapper rendered
	bool both; ///< register-pair stack op (popboth / pshboth): pushed/popped as a pair, left unlifted by the shared push/pop lifter
	bool xcc_guard; ///< xccpart conditional-execute guard: in a "||" parallel pair the *other* sub-instruction executes only when this one's condition holds
	bool quad; ///< swap4: exchange four consecutive register pairs (the XCHG lifter emits four XOR-swaps)

	bool has_branch; ///< \ref branch_target is valid
	ut64 branch_target; ///< absolute target for B/BC/CALL/RPTB/... (precomputed)
	st32 stack_delta; ///< net SP change for psh/pop/aadd sp / frame ops
	bool cond_exec; ///< carried a conditional-execution prefix (C55x+ 0x2e/0x2f if(!TC1)/if(TC1)); rendered/lifted transparently, as the legacy decoder does
	bool parallel_pair; ///< a "||" parallel pair of two independent sub-instructions (C55x+ 0x3N prefix): the two sub-instructions are re-decoded on demand from \ref par_bytes
	ut8 par_bytes[16]; ///< raw instruction bytes (parallel pair only), so the two sub-instructions can be re-decoded by the format / lift / analysis consumers
	ut8 par_off1; ///< byte offset of the first sub-instruction within \ref par_bytes
	ut8 par_off2; ///< byte offset of the second sub-instruction within \ref par_bytes
	bool par_swap; ///< render / sequence the second sub-instruction before the first (the legacy hash 0xF0/0xF1 ordering)
} C55Insn;

struct c55_arch_desc_t;
struct c55_op_desc_t;

/**
 * Shared operand extractor: fills one \ref C55Operand from the instruction bits.
 * \param a arch descriptor (for reg_info / memory model)
 * \param bits whole instruction, packed MSB-first into a word (up to 8 bytes)
 * \param d the operand slot being decoded (its \ref C55OpDesc.lo / .width / .param)
 * \param out operand to fill
 */
typedef void (*C55Extract)(const struct c55_arch_desc_t *a, ut64 bits, const struct c55_op_desc_t *d, C55Operand *out);

/** One operand slot in a \ref C55InsnDef: which bits feed which extractor. */
typedef struct c55_op_desc_t {
	ut8 lo; ///< bitfield start (LSB index within the packed instruction word)
	ut8 width; ///< bitfield width
	C55Extract fn; ///< shared extractor to run
	ut8 param; ///< class selector / scale / width hint passed to \ref fn
} C55OpDesc;

/** One row of a per-arch instruction table (data only; the engine is shared). */
typedef struct {
	ut32 mask; ///< opcode discriminator mask over the leading byte(s)
	ut32 match; ///< required value under \ref mask
	ut16 id; ///< arch-local instruction id
	C55LiftOp lop; ///< explicit lift op copied to \ref C55Insn.lop (0 => dispatch on op type)
	ut8 len; ///< fixed length in bytes, or 0 => C55ArchDesc::insn_len()
	C55OpDesc ops[C55_MAX_OPS]; ///< operand slots
	ut32 mods; ///< variant-flag bit positions, packed as 5-bit (position+1, 0=absent) fields: rounding in bits 0-4, side-load (T3=) in 5-9, M40 in 10-14, fractional (f) in 15-19
	ut8 alt_bit; ///< sub-discriminator bit position (in the full packed bits, LSB-counted) + 1, or 0 if absent: when that bit is set the decode uses \ref alt_id / \ref alt_lop instead of \ref id / \ref lop (for variants whose selector lies beyond the 4-byte match head)
	ut16 alt_id; ///< instruction id when \ref alt_bit fires
	C55LiftOp alt_lop; ///< lift op when \ref alt_bit fires
	bool no_parallel; ///< suppress the parallel-bit derivation (bit 0 of the leading byte is an operand/opcode field here, not the parallel marker)
	bool square; ///< squaring multiply: the (memory) multiplicand is multiplied by itself (sqrm / sqam / sqsm)
	bool dual; ///< dual "::" MAC: operands filled by C55ArchDesc::fill_dual, not the ops[] extractors
	C55LiftOp lop2; ///< dual: lift op of the second sub-MAC (sub1 uses \ref lop)
	bool amar1; ///< dual: sub1 is an "amar" address-modify (no product, no Cmem/dst)
	bool shift1; ///< dual: sub1 accumulates with the accumulator shifted right 16 (">> #16")
	bool shift2; ///< dual: sub2 accumulates with the accumulator shifted right 16 (">> #16")
	bool shift16; ///< single MAC: the accumulator term is shifted right 16 before the product (macm ... ACx >> #16)
	bool mac_mov; ///< MAC :: parallel load form (macm/masm Xmem, Tx, ACx :: mov Ymem << #16, ACy)
	bool mant_nexp; ///< "mant ACa, ACb :: nexp ACa, ACc" dual form (copied to \ref C55Insn.mant_nexp)
	bool mac_store; ///< C55x 0x87 parallel dual-MAC store form (copied to \ref C55Insn.mac_store)
	bool diff_pair; ///< max/min-diff: the trn operand is wrapped in pair() (copied to \ref C55Insn.diff_pair)
	bool diff_form; ///< max/min/dmax/dmin-diff rendering (copied to \ref C55Insn.diff_form)
	bool uns_all; ///< whole-operation unsigned (mpymu): 'u' mnemonic suffix; multiplicand operands carry uns
	bool side_load; ///< memory-MAC side-load: also load Smem into T3 ([T3 = ]Smem), copied to \ref C55Insn.side_load
	bool both; ///< register-pair stack op (popboth / pshboth): copied to \ref C55Insn.both; the shared push/pop lifter leaves it unlifted
	bool xcc_guard; ///< xccpart parallel-slot guard form (copied to \ref C55Insn.xcc_guard)
	bool quad; ///< swap4: copied to \ref C55Insn.quad; the XCHG lifter exchanges four consecutive register pairs
} C55InsnDef;

/**
 * The arch extension point. Adding C54x = providing one of these; C55x/C55x+
 * each provide one but share id/register/mnemonic tables. The decode fields
 * (\ref table .. \ref insn_len) are optional: an arch may instead fill
 * \ref C55Insn from its own front-end (e.g. capstone for a future C64x lifter)
 * and still use the consumers and primitives.
 */
typedef struct c55_arch_desc_t {
	C55Arch arch; ///< family member
	const char *cpu_name; ///< "c54x" / "c55x" / "c55x+"

	const C55InsnDef *table; ///< instruction table (NULL if decoded externally)
	size_t table_len; ///< number of rows in \ref table
	ut8 (*insn_len)(const ut8 *buf, int len); ///< variable-length decode helper

	const C55RegInfo *(*reg_info)(C55RegClass cls, ut8 num, C55SubReg sub); ///< register resolver

	const char *(*mnemonic)(ut16 id); ///< id -> mnemonic; NULL if disasm is external
	ut32 (*op_type)(ut16 id); ///< id -> RZ_ANALYSIS_OP_TYPE_* (the type of RzAnalysisOp::type)
	RzILOpEffect *(*lift)(const C55Insn *insn, ut64 pc); ///< id -> RzIL (per-arch dispatch)

	C55MemModel mem; ///< memory model for c55_generic_ea()
	RzILOpPure *(*ea)(const struct c55_arch_desc_t *a, const C55Operand *m); ///< arch-specific EA; NULL => generic only
	/// Dual "::" MAC operand filler: for a row with C55InsnDef::dual set, fills the
	/// canonical 6-slot layout (Xmem, Cmem-x, ACx, Ymem, Cmem-y, ACy) plus the dual
	/// sub-op metadata on \ref C55Insn, returning false (-> legacy) on an
	/// unrepresentable mode. NULL => the arch has no dual forms.
	bool (*fill_dual)(const struct c55_arch_desc_t *a, ut64 bits, const C55InsnDef *def, C55Insn *out);
	bool words_le; ///< instruction stream is a sequence of little-endian 16-bit words (C54x); the engine byte-swaps each word so the table can match the datasheet's MSB-first opcodes
	bool cond_exec_prefix; ///< the arch has the 0x2e/0x2f conditional-execution prefix (C55x+); a leading 0x2e/0x2f is consumed and the following instruction decoded transparently
	bool parallel_prefix; ///< the arch has the 0x3N parallel-pair prefix (C55x+): a leading byte in 0x30-0x3F introduces two independent sub-instructions joined by " || ", the low nibble giving the total byte length
} C55ArchDesc;

// shared API: one decode, three pure consumers
bool c55_decode(const C55ArchDesc *a, const ut8 *buf, int len, C55Insn *out);
char *c55_format(const C55ArchDesc *a, const C55Insn *insn); // caller frees
void c55_fill_analysis(const C55ArchDesc *a, const C55Insn *insn, RzAnalysisOp *op);
RzILOpEffect *c55_lift(const C55ArchDesc *a, const C55Insn *insn, ut64 pc);

// shared operand extractors referenced by the per-arch tables
void c55_x_reg(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out);
void c55_x_mem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out);
void c55_x_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out);
void c55_x_cond(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out);

// shared RzIL primitives used by each arch's ::lift; c55_generic_ea() serves only
// the generic addressing modes (the EA-boundary contract on C55AddrMode).
RzILOpPure *c55_generic_ea(const C55ArchDesc *a, const C55Operand *m);
RzILOpPure *c55_read(const C55ArchDesc *a, const C55Operand *op);
RzILOpEffect *c55_write(const C55ArchDesc *a, const C55Operand *dst, RzILOpPure *val);
RzILOpEffect *c55_post_effect(const C55ArchDesc *a, const C55Operand *m);

#ifdef __cplusplus
}
#endif
#endif /* RZ_TMS320_C55_IR_H */
