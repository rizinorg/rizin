// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c55plus_il.c
 *
 * RzIL lifting for the TMS320C55x+ (shared with plain C55x: same integer core
 * and register model; C55x+ only adds the high accumulators AC16..AC31 in the
 * operand encoding and the parallel-instruction wrapper, neither of which adds
 * new IL op-semantics).
 *
 * Operand model. Rizin architecture lifters normally consume a *structured*
 * operand list (the Capstone-style `cs_detail.operands[]`, or an arch-specific
 * decoded-instruction struct). The TMS320C55x+ decoder in this tree is the
 * th0rpe token engine, which produces only an algebraic-syntax *string* (e.g.
 * "mov #0x5, t0") and no structured operands. To give the lifter the same
 * structured interface the rest of rizin uses, this file defines a small
 * instruction-information structure -- `C55Insn` with a typed `C55Operand[]`
 * array -- and a normaliser, `c55_decode_insn()`, that fills it. The per-
 * instruction lifters then switch on operand *types* (register / immediate /
 * other) and read typed fields (resolved register name + IL width, immediate
 * value), instead of each doing ad-hoc string slicing.
 *
 * Today `c55_decode_insn()` derives the typed operands from the decoder's
 * algebraic output (the only operand information the th0rpe decoder exposes).
 * The lower-level follow-on -- having the token decoder record these typed
 * operands directly from the instruction bit-fields, so the intermediate
 * string disappears entirely -- is the same operand-decoding work tracked in
 * docs/rizin-analysis-gaps.md; the `C55Insn` interface here is exactly what it
 * will populate, so the lifters do not change when it lands.
 *
 * Invariant: **correct-or-NULL**. Any form that cannot be lifted with certain
 * semantics (memory operands, shifted operands, half-register .l/.h sub-fields,
 * parallel slots, unbound high accumulators, saturating accumulator
 * arithmetic) returns NULL -- no IL -- rather than approximate IL that would
 * corrupt emulation.
 */

#include <rz_analysis.h>
#include <rz_il.h>
#include <ctype.h>

#include "c55plus_analysis.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// IL variable bindings. Names must match the tms320 C55x/C55x+ register
// profile (get_reg_profile). The integer-core register set the lifter can
// reference is bound here.
static const char *c55x_plus_il_regs[] = {
	"ac0", "ac1", "ac2", "ac3", "ac4", "ac5", "ac6", "ac7",
	"ar0", "ar1", "ar2", "ar3", "ar4", "ar5", "ar6", "ar7",
	"xar0", "xar1", "xar2", "xar3", "xar4", "xar5", "xar6", "xar7",
	"t0", "t1", "t2", "t3",
	"sp", "ssp", "dp", "dph", "sph", "pdp", "pc",
	"cdp", "cdph", "xcdp", "csr", "rptc",
	"brc0", "brc1", "brs1", "trn0", "trn1",
	"bk03", "bk47", "bkc",
	"bsa01", "bsa23", "bsa45", "bsa67", "bsac",
	"st0_55", "st1_55", "st2_55", "st3_55",
	NULL
};

// Static register-name tables. The IL SET/VAR ops *borrow* the variable-name
// pointer, so it must have static lifetime -- never a pointer into the decoded
// syntax buffer (which is on the stack of the analysis op and freed by the
// time the IL is evaluated/printed).
static const char *const C55_AC[8] = { "ac0", "ac1", "ac2", "ac3", "ac4", "ac5", "ac6", "ac7" };
static const char *const C55_AR[8] = { "ar0", "ar1", "ar2", "ar3", "ar4", "ar5", "ar6", "ar7" };
static const char *const C55_XAR[8] = { "xar0", "xar1", "xar2", "xar3", "xar4", "xar5", "xar6", "xar7" };
static const char *const C55_T[4] = { "t0", "t1", "t2", "t3" };

/**
 * If \p tok is exactly a simple bound register name (ac0-3, ar0-7, xar0-7,
 * t0-3), return a pointer to its *static* canonical name and set \p width to
 * its IL bit-width; otherwise return NULL. Rejects half-register sub-fields
 * (".l"/".h"), memory syntax ("*", "("), and any non-alphanumeric token.
 */
static const char *c55_reg(const char *tok, ut32 *width) {
	if (!tok || !*tok) {
		return NULL;
	}
	// Control / system registers (varied lengths and underscores, so matched
	// here before the simple-register length/charset checks below). The widths
	// match the analysis register profile; the names are static-lifetime.
	static const struct {
		const char *name;
		ut32 width;
	} c55_ctrl[] = {
		{ "sp", 16 }, { "ssp", 16 }, { "dp", 16 }, { "dph", 7 }, { "sph", 7 },
		{ "pdp", 9 }, { "cdp", 16 }, { "cdph", 7 }, { "csr", 16 }, { "rptc", 16 },
		{ "brc0", 16 }, { "brc1", 16 }, { "brs1", 16 }, { "trn0", 16 }, { "trn1", 16 },
		{ "bk03", 16 }, { "bk47", 16 }, { "bkc", 16 },
		{ "bsa01", 16 }, { "bsa23", 16 }, { "bsa45", 16 }, { "bsa67", 16 }, { "bsac", 16 },
		{ "st0_55", 16 }, { "st1_55", 16 }, { "st2_55", 16 }, { "st3_55", 16 }
	};
	for (size_t ci = 0; ci < sizeof(c55_ctrl) / sizeof(c55_ctrl[0]); ci++) {
		if (!strcmp(tok, c55_ctrl[ci].name)) {
			*width = c55_ctrl[ci].width;
			return c55_ctrl[ci].name;
		}
	}
	size_t n = strlen(tok);
	if (n < 2 || n > 4) {
		return NULL;
	}
	for (size_t i = 0; i < n; i++) {
		if (!isalnum((unsigned char)tok[i])) {
			return NULL; // ".l", "*ar3", "(", etc. are not simple registers
		}
	}
	char *end = NULL;
	if (tok[0] == 'x' && tok[1] == 'a' && tok[2] == 'r') {
		long idx = strtol(tok + 3, &end, 10);
		if (end && *end == '\0' && idx >= 0 && idx <= 7) {
			*width = 23;
			return C55_XAR[idx];
		}
		return NULL;
	}
	if (tok[0] == 'a' && tok[1] == 'c') {
		long idx = strtol(tok + 2, &end, 10);
		if (end && *end == '\0' && idx >= 0 && idx <= 7) {
			*width = 40;
			return C55_AC[idx];
		}
	} else if (tok[0] == 'a' && tok[1] == 'r') {
		long idx = strtol(tok + 2, &end, 10);
		if (end && *end == '\0' && idx >= 0 && idx <= 7) {
			*width = 16;
			return C55_AR[idx];
		}
	} else if (tok[0] == 't') {
		long idx = strtol(tok + 1, &end, 10);
		if (end && *end == '\0' && idx >= 0 && idx <= 3) {
			*width = 16;
			return C55_T[idx];
		}
	}
	return NULL;
}

/** Parse "#0x..." / "#123" into an unsigned value. Returns false on any
 * sign, shift, or trailing garbage (kept conservative). */
static bool c55_parse_imm(const char *tok, ut64 *out) {
	if (!tok) {
		return false;
	}
	const char *p = tok;
	if (*p == '#') {
		p++; // C55x+ prefixes immediates with '#'; plain C55x often omits it
	}
	if (*p == '-' || *p == '+' || *p == '\0') {
		return false; // signed immediates not modelled yet
	}
	size_t n = strlen(p);
	char *end = NULL;
	errno = 0;
	// TI 'h' hex suffix (e.g. "4Dh", "#0h"): parse the digits as base 16
	if (n >= 2 && (p[n - 1] == 'h' || p[n - 1] == 'H')) {
		char buf[40];
		if (n - 1 >= sizeof(buf)) {
			return false;
		}
		memcpy(buf, p, n - 1);
		buf[n - 1] = '\0';
		ut64 v = strtoull(buf, &end, 16);
		if (errno || !end || *end != '\0') {
			return false;
		}
		*out = v;
		return true;
	}
	// "0x..." hex, "0..." octal, or decimal (strtoull base 0 auto-detects)
	ut64 v = strtoull(p, &end, 0);
	if (errno || !end || *end != '\0') {
		return false; // e.g. "#0x1 << #0xe" leaves " << ..." -> reject
	}
	*out = v;
	return true;
}

// ---- Instruction-information structure (the structured operand interface) --

typedef enum {
	C55_OP_NONE = 0,
	C55_OP_REG, // a simple bound register: .reg (static name) + .width
	C55_OP_REGHALF, // low/high 16-bit half of an accumulator: .reg = ACx, .half
	C55_OP_IMM, // an unsigned immediate: .imm + .width (width = 0 if unsized)
	C55_OP_MEM, // a single data-memory operand: *arN / *arN+ / *arN- (.reg = XAR base)
	C55_OP_OTHER // shifted, half-register dst, condition, indexed/dbl/uns memory, etc.
} C55OpKind;

// Data-memory addressing mode for a C55_OP_MEM operand. The effective-address
// and pointer side effect of each represented mode are explicitly known; any
// other memory syntax (register-indexed *arN(tM), *(arN+tM), mmap, pre-modify,
// circular) is classified C55_OP_OTHER so lifting falls through to NULL.
//
// Pointer-unit convention (word-pointer mode, matching the rest of this lifter):
// a register base (XARn / SP) holds a 23-bit word address, so its byte address
// is (reg << 1). The K16 displacement is added in word units before the shift
// ((base + K16) << 1, keeping word/dbl accesses aligned); the k24 absolute
// constant is already a 24-bit byte address.
typedef enum {
	C55_AM_INDIRECT, // *arN              : EA = XARn<<1, no side effect
	C55_AM_POSTINC, // *arN+             : EA = XARn<<1, then XARn += 1 word
	C55_AM_POSTDEC, // *arN-             : EA = XARn<<1, then XARn -= 1 word
	C55_AM_INDEXED, // *arN(short(#K)) / *sp(#K) : EA = (base + sx(K))<<1
	C55_AM_ABSOLUTE, // *(#K)             : EA = K (24-bit byte address)
	C55_AM_IDXOFF, // *arN(tM)          : EA = (XARn + sx(Tm))<<1, no side effect
	C55_AM_POSTADD, // *(arN+tM)         : EA = XARn<<1, then XARn += sx(Tm)
	C55_AM_POSTSUB // *(arN-tM)         : EA = XARn<<1, then XARn -= sx(Tm)
} C55AddrMode;

typedef struct {
	C55OpKind kind;
	const char *reg; // REG: static reg name. MEM: static base-register name (XARn/sp/xcdp), NULL if absolute.
	const char *index; // MEM register-indexed modes: static index-register name (Tm), else NULL
	ut32 width; // IL bit-width of the register / immediate
	ut64 imm; // immediate value when kind == C55_OP_IMM
	C55AddrMode amode; // addressing mode when kind == C55_OP_MEM
	int half; // C55_OP_REGHALF: 1 = .l (bits 15:0), 2 = .h (bits 31:16)
	int access_bits; // MEM access width in bits: 8 (byte), 16 (word, default), 32 (dbl)
	bool mem_uns; // MEM: uns() wrapper -> zero-extend on load (default sign-extend)
	st64 disp; // MEM C55_AM_INDEXED: signed byte displacement (K16, sign-extended)
	ut64 abs_addr; // MEM C55_AM_ABSOLUTE: 24-bit byte address (k24)
} C55Operand;

#define C55_MAX_OPS 4

typedef struct {
	char mnem[16]; // lowercased mnemonic ("mov", "add", ...)
	C55Operand ops[C55_MAX_OPS];
	int n_ops;
	bool parallel; // instruction has a "||" parallel slot (not modelled)
	bool truncated; // operand list overflowed C55_MAX_OPS (be conservative)
} C55Insn;

/** Map an "arN" token (N=0..7) to its static XAR base-register name, or NULL.
 * In word-pointer mode, data addressing uses the full 23-bit XARn (ARn is its
 * low 16 bits), so "*arN" addresses through XARn. */
static const char *c55_xar_for_ar(const char *tok) {
	if (tok && tok[0] == 'a' && tok[1] == 'r' && tok[2] >= '0' && tok[2] <= '7' && tok[3] == '\0') {
		return C55_XAR[tok[2] - '0'];
	}
	return NULL;
}

/** Parse a single data-memory operand "*arN" / "*arN+" / "*arN-" into \p op
 * (kind C55_OP_MEM, .reg = static XAR base, .amode set). Returns false for any
 * other memory syntax (indexed *arN(tM), *(arN+tM), *sp(#k), dbl()/uns()
 * wrappers, mmap, pre-modify, ar8..15 which are unbound) so the caller
 * classifies it C55_OP_OTHER. */
static bool c55_parse_mem(const char *tok, C55Operand *op) {
	if (!tok) {
		return false;
	}
	// Peel uns()/byte()/dbl() access-size and extension wrappers. They may
	// nest (e.g. "uns(byte(...))"); each requires a matching trailing ')'.
	char inner[80];
	size_t n = strlen(tok);
	if (n == 0 || n >= sizeof(inner)) {
		return false;
	}
	memcpy(inner, tok, n + 1);
	int access = 16;
	bool uns = false;
	for (;;) {
		size_t L = strlen(inner);
		const char *body = NULL;
		int acc = 0;
		bool is_uns = false;
		if (!strncmp(inner, "uns(", 4)) {
			body = inner + 4;
			is_uns = true;
		} else if (!strncmp(inner, "byte(", 5)) {
			body = inner + 5;
			acc = 8;
		} else if (!strncmp(inner, "dbl(", 4)) {
			body = inner + 4;
			acc = 32;
		} else {
			break;
		}
		if (L == 0 || inner[L - 1] != ')') {
			return false;
		}
		if (is_uns) {
			uns = true;
		} else {
			access = acc;
		}
		size_t off = (size_t)(body - inner);
		size_t newlen = L - off - 1; // also drop the trailing ')'
		memmove(inner, body, newlen);
		inner[newlen] = '\0';
	}
	if (inner[0] != '*') {
		return false;
	}
	const char *p = inner + 1;

	// "*(...)" : absolute *(#k24), or register-indexed *(base +/- Tm)
	if (p[0] == '(') {
		const char *q = p + 1;
		size_t ql = strlen(q);
		if (ql < 2 || q[ql - 1] != ')') {
			return false;
		}
		char body[64];
		size_t bl = ql - 1;
		if (bl >= sizeof(body)) {
			return false;
		}
		memcpy(body, q, bl);
		body[bl] = '\0';
		// register-indexed post-modify: "<base> + <Tm>" / "<base> - <Tm>"
		char *plus = strchr(body, '+');
		char *minus = strchr(body, '-');
		char *opc = plus ? plus : minus;
		if (opc) {
			char bb[32], ix[16];
			size_t blen = (size_t)(opc - body);
			while (blen > 0 && body[blen - 1] == ' ') {
				blen--;
			}
			const char *ixs = opc + 1;
			while (*ixs == ' ') {
				ixs++;
			}
			if (blen == 0 || blen >= sizeof(bb) || strlen(ixs) >= sizeof(ix)) {
				return false;
			}
			memcpy(bb, body, blen);
			bb[blen] = '\0';
			rz_str_ncpy(ix, ixs, sizeof(ix));
			const char *b2 = c55_xar_for_ar(bb);
			if (!b2 && !strcmp(bb, "cdp")) {
				b2 = "xcdp";
			}
			ut32 iw = 0;
			const char *idx = c55_reg(ix, &iw);
			if (!b2 || !idx || iw != 16 || idx[0] != 't') {
				return false; // e.g. bit-reversed "t0b" -> unmodelled
			}
			op->kind = C55_OP_MEM;
			op->reg = b2;
			op->index = idx;
			op->amode = plus ? C55_AM_POSTADD : C55_AM_POSTSUB;
			op->access_bits = access;
			op->mem_uns = uns;
			op->width = 16;
			return true;
		}
		// absolute *(#k24)
		ut64 k = 0;
		if (!c55_parse_imm(body, &k)) {
			return false;
		}
		op->kind = C55_OP_MEM;
		op->reg = NULL;
		op->amode = C55_AM_ABSOLUTE;
		op->abs_addr = k & 0xffffffULL;
		op->access_bits = access;
		op->mem_uns = uns;
		op->width = 16;
		return true;
	}

	// base register: arN (-> XARn), sp, or cdp (-> xcdp)
	const char *base = NULL;
	const char *rest = NULL;
	if (p[0] == 'a' && p[1] == 'r' && p[2] >= '0' && p[2] <= '9') {
		char reg[4] = { 'a', 'r', p[2], '\0' };
		base = c55_xar_for_ar(reg);
		rest = p + 3;
	} else if (p[0] == 's' && p[1] == 'p') {
		base = "sp";
		rest = p + 2;
	} else if (!strncmp(p, "cdp", 3)) {
		base = "xcdp";
		rest = p + 3;
	}
	if (!base) {
		return false;
	}

	if (rest[0] == '\0') {
		op->amode = C55_AM_INDIRECT;
	} else if (rest[0] == '+' && rest[1] == '\0') {
		op->amode = C55_AM_POSTINC;
	} else if (rest[0] == '-' && rest[1] == '\0') {
		op->amode = C55_AM_POSTDEC;
	} else if (rest[0] == '(') {
		// indexed: (short(#K16)) / (#K16) [constant], or (tM) [register index]
		const char *q = rest + 1;
		size_t ql = strlen(q);
		if (ql < 2 || q[ql - 1] != ')') {
			return false;
		}
		char dispbuf[48];
		size_t dl = ql - 1;
		if (dl >= sizeof(dispbuf)) {
			return false;
		}
		memcpy(dispbuf, q, dl);
		dispbuf[dl] = '\0';
		// register index *base(tM) -> IDXOFF (EA = (base + sx(Tm))<<1, no modify)
		ut32 iw = 0;
		const char *idx = c55_reg(dispbuf, &iw);
		if (idx && iw == 16 && idx[0] == 't') {
			op->amode = C55_AM_IDXOFF;
			op->index = idx;
		} else {
			char *d = dispbuf;
			if (!strncmp(d, "short(", 6)) {
				size_t L = strlen(d);
				if (L == 0 || d[L - 1] != ')') {
					return false;
				}
				d[L - 1] = '\0';
				d += 6;
			}
			ut64 k = 0;
			if (!c55_parse_imm(d, &k)) {
				return false; // "t0<<#1" (scaled index), etc. -> unmodelled
			}
			// K16 is a signed 16-bit displacement, sign-extended into the byte space
			op->amode = C55_AM_INDEXED;
			op->disp = (k & 0x8000ULL) ? (st64)(k | 0xffffffffffff0000ULL) : (st64)(k & 0xffffULL);
		}
	} else {
		return false; // "*arN+ << t2", pre-modify "*+arN", etc.
	}
	op->kind = C55_OP_MEM;
	op->reg = base;
	op->access_bits = access;
	op->mem_uns = uns;
	op->width = 16;
	return true;
}

/** Parse an accumulator half-register source "acN.l" / "acN.h" (N=0..3) into
 * \p op (kind C55_OP_REGHALF, .reg = static ACx name, .half = 1/2/3). Returns
 * false otherwise. Recognises .l (bits 15:0), .h (bits 31:16) and .g (guard
 * bits 39:32). */
static bool c55_parse_half(const char *tok, C55Operand *op) {
	if (!(tok && tok[0] == 'a' && tok[1] == 'c' && tok[2] >= '0' && tok[2] <= '7' &&
		    tok[3] == '.' && tok[5] == '\0')) {
		return false;
	}
	int half;
	if (tok[4] == 'l') {
		half = 1;
	} else if (tok[4] == 'h') {
		half = 2;
	} else if (tok[4] == 'g') {
		half = 3;
	} else {
		return false;
	}
	op->kind = C55_OP_REGHALF;
	op->reg = C55_AC[tok[2] - '0'];
	op->width = 16;
	op->half = half;
	return true;
}

/**
 * Normalise a decoded C55x+ syntax string into the structured `C55Insn`.
 * Splits the mnemonic and the comma-separated operands and classifies each
 * operand into a register / immediate / other. Returns false if there is no
 * mnemonic. (Operand classification is exact for the register and immediate
 * forms; everything else -- memory, shifts, conditions, half-registers -- is
 * deliberately classified C55_OP_OTHER so the lifters fall through to NULL.)
 */
static bool c55_decode_insn(const char *syntax, C55Insn *insn) {
	if (!syntax || !*syntax) {
		return false;
	}
	memset(insn, 0, sizeof(*insn));
	// A parallel instruction packs two operations around "||"; we do not model
	// the slot interaction, so flag it and only look at the first half.
	const char *par = strstr(syntax, "||");
	size_t scan_len = par ? (size_t)(par - syntax) : strlen(syntax);
	if (par) {
		insn->parallel = true;
	}
	const char *sp = memchr(syntax, ' ', scan_len);
	size_t mlen = sp ? (size_t)(sp - syntax) : scan_len;
	if (mlen == 0 || mlen >= sizeof(insn->mnem)) {
		return false;
	}
	memcpy(insn->mnem, syntax, mlen);
	insn->mnem[mlen] = '\0';
	if (!sp) {
		return true; // operandless mnemonic (e.g. "ret", "nop")
	}
	// Walk the comma-separated operand list within the first (pre-"||") half.
	const char *p = sp + 1;
	const char *end = syntax + scan_len;
	while (p < end) {
		// skip leading spaces
		while (p < end && *p == ' ') {
			p++;
		}
		if (p >= end) {
			break;
		}
		const char *comma = memchr(p, ',', end - p);
		const char *tok_end = comma ? comma : end;
		// right-trim spaces
		const char *te = tok_end;
		while (te > p && te[-1] == ' ') {
			te--;
		}
		size_t toklen = te - p;
		if (insn->n_ops >= C55_MAX_OPS) {
			insn->truncated = true;
			break;
		}
		C55Operand *op = &insn->ops[insn->n_ops++];
		char buf[64];
		if (toklen > 0 && toklen < sizeof(buf)) {
			memcpy(buf, p, toklen);
			buf[toklen] = '\0';
			ut64 imm = 0;
			ut32 w = 0;
			const char *rn = c55_reg(buf, &w);
			if (rn) {
				op->kind = C55_OP_REG;
				op->reg = rn;
				op->width = w;
			} else if (c55_parse_imm(buf, &imm)) {
				op->kind = C55_OP_IMM;
				op->imm = imm;
			} else if (c55_parse_mem(buf, op)) {
				// op filled by c55_parse_mem (kind C55_OP_MEM)
			} else if (c55_parse_half(buf, op)) {
				// op filled by c55_parse_half (kind C55_OP_REGHALF)
			} else {
				op->kind = C55_OP_OTHER;
			}
		} else {
			op->kind = C55_OP_OTHER;
		}
		p = comma ? comma + 1 : end;
	}
	return true;
}

// ---- Typed-operand lifters --------------------------------------------------

// Effective *byte* address of a C55_OP_MEM operand. Word-pointer unit
// convention (matching the rest of this lifter): a register base (XARn / SP) is
// a 23-bit *word* address, and the K16 displacement is added in word units, so
// the byte address is (base + K16) << 1 -- which keeps word/dbl accesses
// aligned. The k24 absolute constant is already a 24-bit byte address. Suitable
// for LOADW/STOREW.
//
// Caveat: if this firmware actually runs the A-unit in C55x+ byte-pointer mode
// (plausible given the byte() access density and odd k24 byte addresses), the
// register base is itself a byte address and these register-relative EAs are
// scaled by an extra 2; that correction is localised to this one helper.
static RzILOpBitVector *c55_mem_byte_addr(const C55Operand *m) {
	if (m->amode == C55_AM_ABSOLUTE) {
		return UN(24, m->abs_addr);
	}
	if (m->amode == C55_AM_INDEXED) {
		// (word base + signed word displacement) << 1
		return MUL(ADD(UNSIGNED(24, VARG(m->reg)), SN(24, m->disp)), UN(24, 2));
	}
	if (m->amode == C55_AM_IDXOFF) {
		// (word base + signed word index Tm) << 1, base unchanged
		return MUL(ADD(UNSIGNED(24, VARG(m->reg)), SIGNED(24, VARG(m->index))), UN(24, 2));
	}
	return MUL(UNSIGNED(24, VARG(m->reg)), UN(24, 2));
}

// The pointer side effect of a post-modify mode (NULL otherwise): XARn +/- 1 word.
static RzAnalysisLiftedILOp c55_mem_post_effect(const C55Operand *m) {
	switch (m->amode) {
	case C55_AM_POSTINC: return SETG(m->reg, ADD(VARG(m->reg), UN(23, 1)));
	case C55_AM_POSTDEC: return SETG(m->reg, SUB(VARG(m->reg), UN(23, 1)));
	case C55_AM_POSTADD: return SETG(m->reg, ADD(VARG(m->reg), SIGNED(23, VARG(m->index))));
	case C55_AM_POSTSUB: return SETG(m->reg, SUB(VARG(m->reg), SIGNED(23, VARG(m->index))));
	default: return NULL;
	}
}

// Resize a bitvector from \p src_bits to \p dst_bits: low-bit truncation when
// narrowing (exact), and sign- or zero-extension (per \p uns) when widening.
static RzILOpBitVector *c55_resize(RzILOpBitVector *v, int src_bits, ut32 dst_bits, bool uns) {
	if (dst_bits == (ut32)src_bits) {
		return v;
	}
	if (dst_bits < (ut32)src_bits) {
		return CAST(dst_bits, IL_FALSE, v);
	}
	return uns ? UNSIGNED(dst_bits, v) : SIGNED(dst_bits, v);
}

/** The 16-bit value of a 16-bit source operand: a 16-bit register (T/AR), a
 * full accumulator truncated to its low word, or an accumulator half .l/.h.
 * Returns NULL for anything else. */
static RzILOpBitVector *c55_src16(const C55Operand *op) {
	if (op->kind == C55_OP_REG) {
		if (op->width == 16) {
			return VARG(op->reg);
		}
		if (op->width == 40) {
			return CAST(16, IL_FALSE, VARG(op->reg)); // low word of AC
		}
		return NULL;
	}
	if (op->kind == C55_OP_REGHALF) {
		if (op->half == 1) {
			return CAST(16, IL_FALSE, VARG(op->reg)); // .l = bits 15:0
		}
		if (op->half == 2) {
			return CAST(16, IL_FALSE, SHIFTR(IL_FALSE, VARG(op->reg), UN(8, 16))); // .h = bits 31:16
		}
		if (op->half == 3) {
			return CAST(16, IL_FALSE, SHIFTR(IL_FALSE, VARG(op->reg), UN(8, 32))); // .g = guard bits 39:32
		}
	}
	return NULL;
}

/** The 16-bit value of a read16-able operand: a 16-bit register, an accumulator
 * (low word) or half via c55_src16, or an immediate truncated to 16 bits.
 * Returns NULL otherwise. */
static RzILOpBitVector *c55_read16(const C55Operand *op) {
	if (op->kind == C55_OP_IMM) {
		return UN(16, op->imm & 0xffff);
	}
	return c55_src16(op);
}

/** Write a 16-bit value \p val16 (consumed) to a 16-bit destination operand: a
 * 16-bit register (T/AR) via SETG, or an accumulator half .l/.h via read-modify-
 * write of the 40-bit accumulator -- clearing the target half and OR-ing the new
 * value in, leaving the other half and the guard bits untouched. Returns NULL
 * (after freeing \p val16) for any other destination kind. */
static RzAnalysisLiftedILOp c55_write16(const C55Operand *dst, RzILOpBitVector *val16) {
	if (dst->kind == C55_OP_REG && dst->width == 16) {
		return SETG(dst->reg, val16);
	}
	if (dst->kind == C55_OP_REGHALF) {
		RzILOpBitVector *wide = UNSIGNED(40, val16);
		if (dst->half == 1) {
			// .l : clear bits 15:0, OR in the value
			return SETG(dst->reg, LOGOR(LOGAND(VARG(dst->reg), UN(40, 0xffffff0000ULL)), wide));
		}
		if (dst->half == 3) {
			// .g : clear guard bits 39:32, OR in (value & 0xff) << 32
			return SETG(dst->reg,
				LOGOR(LOGAND(VARG(dst->reg), UN(40, 0x00ffffffffULL)),
					SHIFTL(IL_FALSE, LOGAND(wide, UN(40, 0xff)), UN(6, 32))));
		}
		// .h : clear bits 31:16, OR in (value << 16)
		return SETG(dst->reg,
			LOGOR(LOGAND(VARG(dst->reg), UN(40, 0xff0000ffffULL)),
				SHIFTL(IL_FALSE, wide, UN(6, 16))));
	}
	rz_il_op_pure_free(val16);
	return NULL;
}

/**
 * mov / copy: immediate load, register copy (equal-width, cross-width narrowing,
 * and sign-extending widen from a 16-bit data register), and data-memory load /
 * store. Memory access size is 8 (byte()), 16 (word, default) or 32 (dbl()), at
 * the byte effective address from c55_mem_byte_addr (word-pointer mode, little-
 * endian). Loads extend to the destination width with sign extension (SXMD = 1,
 * the reset default) unless an uns() wrapper forces zero extension; stores write
 * the low \p access_bits of the source (16-bit register, AC low word, AC half,
 * or immediate). Post-increment/decrement apply the XARn +/- 1-word side effect
 * after the access, sequenced via SEQ. Forms outside this set return NULL.
 */
static RzAnalysisLiftedILOp c55_lift_mov(const C55Insn *in) {
	if (in->n_ops != 2) {
		return NULL;
	}
	const C55Operand *src = &in->ops[0];
	const C55Operand *dst = &in->ops[1];

	// ---- destination: full register ----
	if (dst->kind == C55_OP_REG) {
		if (src->kind == C55_OP_IMM) {
			return SETG(dst->reg, UN(dst->width, src->imm));
		}
		if (src->kind == C55_OP_REG) {
			if (src->width == dst->width) {
				return SETG(dst->reg, VARG(src->reg));
			}
			if (dst->width < src->width) {
				// narrowing: exact low-bit truncation (e.g. ac -> xar, ac -> t)
				return SETG(dst->reg, CAST(dst->width, IL_FALSE, VARG(src->reg)));
			}
			if (src->width == 16) {
				// widen a 16-bit data register with sign extension (SXMD = 1)
				return SETG(dst->reg, SIGNED(dst->width, VARG(src->reg)));
			}
			if (src->width == 23) {
				// widen a 23-bit address register: it holds an unsigned data
				// address, so zero-extend (e.g. "mov xar0, ac2").
				return SETG(dst->reg, UNSIGNED(dst->width, VARG(src->reg)));
			}
			return NULL; // widening from another register class: extension unclear
		}
		if (src->kind == C55_OP_MEM) {
			int ab = src->access_bits ? src->access_bits : 16;
			RzILOpBitVector *load = LOADW(ab, c55_mem_byte_addr(src));
			RzILOpBitVector *val = c55_resize(load, ab, dst->width, src->mem_uns);
			RzAnalysisLiftedILOp set = SETG(dst->reg, val);
			RzAnalysisLiftedILOp post = c55_mem_post_effect(src);
			return post ? SEQ2(set, post) : set;
		}
		if (src->kind == C55_OP_REGHALF) {
			// half-register source into a register: a 16-bit value sign-extended
			// to the destination width (SXMD = 1, reset default), matching the
			// 16-bit-register widening case above.
			RzILOpBitVector *v16 = c55_src16(src);
			if (!v16) {
				return NULL;
			}
			return (dst->width == 16)
				? SETG(dst->reg, v16)
				: SETG(dst->reg, SIGNED(dst->width, v16));
		}
		return NULL;
	}

	// ---- destination: accumulator half (.l / .h) ----
	if (dst->kind == C55_OP_REGHALF) {
		RzILOpBitVector *val16 = NULL;
		RzAnalysisLiftedILOp post = NULL;
		if (src->kind == C55_OP_IMM) {
			val16 = UN(16, src->imm & 0xffff);
		} else if (src->kind == C55_OP_MEM) {
			int ab = src->access_bits ? src->access_bits : 16;
			RzILOpBitVector *load = LOADW(ab, c55_mem_byte_addr(src));
			val16 = c55_resize(load, ab, 16, src->mem_uns);
			post = c55_mem_post_effect(src);
		} else {
			val16 = c55_src16(src);
		}
		if (!val16) {
			return NULL;
		}
		RzILOpBitVector *wide = UNSIGNED(40, val16);
		RzAnalysisLiftedILOp set;
		if (dst->half == 1) {
			// .l : clear bits 15:0, OR in the value
			set = SETG(dst->reg, LOGOR(LOGAND(VARG(dst->reg), UN(40, 0xffffff0000ULL)), wide));
		} else {
			// .h : clear bits 31:16, OR in (value << 16)
			set = SETG(dst->reg,
				LOGOR(LOGAND(VARG(dst->reg), UN(40, 0xff0000ffffULL)),
					SHIFTL(IL_FALSE, wide, UN(6, 16))));
		}
		return post ? SEQ2(set, post) : set;
	}

	// ---- memory-to-memory move (load src, store dst, equal access width) ----
	if (dst->kind == C55_OP_MEM && src->kind == C55_OP_MEM) {
		int sab = src->access_bits ? src->access_bits : 16;
		int dab = dst->access_bits ? dst->access_bits : 16;
		if (sab != dab) {
			return NULL;
		}
		RzILOpBitVector *load = LOADW(sab, c55_mem_byte_addr(src));
		RzAnalysisLiftedILOp eff = STOREW(c55_mem_byte_addr(dst), load);
		RzAnalysisLiftedILOp sp = c55_mem_post_effect(src);
		RzAnalysisLiftedILOp dp = c55_mem_post_effect(dst);
		if (sp) {
			eff = SEQ2(eff, sp);
		}
		if (dp) {
			eff = SEQ2(eff, dp);
		}
		return eff;
	}

	// ---- destination: memory (store) ----
	if (dst->kind == C55_OP_MEM) {
		int ab = dst->access_bits ? dst->access_bits : 16;
		RzILOpBitVector *sval = NULL;
		if (ab == 32) {
			if (src->kind == C55_OP_IMM) {
				sval = UN(32, src->imm & 0xffffffffULL);
			} else if (src->kind == C55_OP_REG) {
				sval = c55_resize(VARG(src->reg), src->width, 32, true);
			} else if (src->kind == C55_OP_REGHALF) {
				RzILOpBitVector *h = c55_src16(src);
				if (h) {
					sval = UNSIGNED(32, h);
				}
			}
		} else {
			RzILOpBitVector *v16 = (src->kind == C55_OP_IMM)
				? UN(16, src->imm & 0xffff)
				: c55_src16(src);
			if (v16) {
				sval = (ab == 8) ? CAST(8, IL_FALSE, v16) : v16;
			}
		}
		if (!sval) {
			return NULL;
		}
		RzAnalysisLiftedILOp st = STOREW(c55_mem_byte_addr(dst), sval);
		RzAnalysisLiftedILOp post = c55_mem_post_effect(dst);
		return post ? SEQ2(st, post) : st;
	}
	return NULL;
}

/**
 * Bitwise and/or/xor: "<op> src, dst" -> dst := dst <op> src, restricted to two
 * equal-width registers. Bitwise ops take no extension, carry no value-
 * affecting status side effects, and do not saturate, so the lift is exact.
 * The 3-operand same-register form ("xor #imm, ARx, ARx") is also lifted when
 * both register operands are the same 16-bit register.
 */
typedef enum {
	C55_AND,
	C55_OR,
	C55_XOR
} C55BitOp;

static RzILOpBitVector *c55_apply_bitop(C55BitOp kind, RzILOpBitVector *a, RzILOpBitVector *b) {
	switch (kind) {
	case C55_AND: return LOGAND(a, b);
	case C55_OR: return LOGOR(a, b);
	case C55_XOR: return LOGXOR(a, b);
	}
	return NULL;
}

static RzAnalysisLiftedILOp c55_lift_bitop(C55BitOp kind, const C55Insn *in) {
	if (in->n_ops == 2) {
		const C55Operand *src = &in->ops[0];
		const C55Operand *dst = &in->ops[1];
		if (src->kind == C55_OP_REG && dst->kind == C55_OP_REG && src->width == dst->width) {
			return SETG(dst->reg, c55_apply_bitop(kind, VARG(dst->reg), VARG(src->reg)));
		}
		// 16-bit form: "<op> SRC, DSThalf" / "<op> SRC, REG16" -> DST := DST <op>
		// SRC at 16 bits, where DST is an accumulator half or a 16-bit register
		// and SRC is a 16-bit value (immediate, 16-bit register, AC low word or
		// AC half). Bitwise ops take no extension/saturation, and the half write
		// preserves the rest of the accumulator, so the 16-bit lift is exact.
		if (dst->kind == C55_OP_REGHALF || (dst->kind == C55_OP_REG && dst->width == 16)) {
			RzILOpBitVector *sval = c55_read16(src);
			if (!sval) {
				return NULL;
			}
			RzILOpBitVector *dval = c55_read16(dst);
			if (!dval) {
				rz_il_op_pure_free(sval);
				return NULL;
			}
			return c55_write16(dst, c55_apply_bitop(kind, dval, sval));
		}
		// 16-bit source into a 40-bit accumulator, e.g. "xor t1, ac0". The
		// source is zero-extended to 40 bits: XOR/OR then leave the upper 24
		// bits (high + guard) unchanged (op with 0 is identity), while AND
		// clears them (AND with a zero-extended mask). Modelled exactly per
		// that per-op upper-bit behaviour.
		if (dst->kind == C55_OP_REG && dst->width == 40) {
			RzILOpBitVector *sval = c55_read16(src);
			if (!sval) {
				return NULL;
			}
			RzILOpBitVector *res = c55_apply_bitop(kind, CAST(16, IL_FALSE, VARG(dst->reg)), sval);
			if (kind == C55_AND) {
				return SETG(dst->reg, UNSIGNED(40, res));
			}
			return SETG(dst->reg,
				LOGOR(LOGAND(VARG(dst->reg), UN(40, 0xffffff0000ULL)), UNSIGNED(40, res)));
		}
		return NULL;
	}
	if (in->n_ops == 3) {
		// "<op> A, S2, DST" -> DST := A <op> S2. A is an immediate, a memory
		// word (sized to DST), or a register; DST need not equal S2 (e.g.
		// "xor *ar3, ar1, ar2"). Bitwise, so exact at the bound width with no
		// saturation/extension side effects.
		const C55Operand *a = &in->ops[0];
		const C55Operand *s2 = &in->ops[1];
		const C55Operand *dst = &in->ops[2];
		// full-width register form: S2 and DST are registers of the same width.
		if (s2->kind == C55_OP_REG && dst->kind == C55_OP_REG && s2->width == dst->width) {
			const ut32 w = dst->width;
			RzILOpBitVector *aval = NULL;
			RzAnalysisLiftedILOp post = NULL;
			if (a->kind == C55_OP_IMM) {
				aval = UN(w, a->imm);
			} else if (a->kind == C55_OP_MEM) {
				int ab = a->access_bits ? a->access_bits : 16;
				RzILOpBitVector *load = LOADW(ab, c55_mem_byte_addr(a));
				aval = c55_resize(load, ab, w, a->mem_uns);
				post = c55_mem_post_effect(a);
			} else if (a->kind == C55_OP_REG && a->width == w) {
				aval = VARG(a->reg);
			} else {
				return NULL;
			}
			RzAnalysisLiftedILOp set = SETG(dst->reg, c55_apply_bitop(kind, VARG(s2->reg), aval));
			return post ? SEQ2(set, post) : set;
		}
		// 16-bit form: DST and S2 are accumulator halves / 16-bit registers and
		// A is a 16-bit value -> DST := S2 <op> A at 16 bits (bitwise, exact),
		// e.g. "and #0xff, ac0.l, ac2.l".
		bool dst16 = dst->kind == C55_OP_REGHALF || (dst->kind == C55_OP_REG && dst->width == 16);
		bool s216 = s2->kind == C55_OP_REGHALF ||
			(s2->kind == C55_OP_REG && (s2->width == 16 || s2->width == 40));
		if (dst16 && s216) {
			RzILOpBitVector *aval = c55_read16(a);
			if (!aval) {
				return NULL;
			}
			RzILOpBitVector *s2val = c55_read16(s2);
			if (!s2val) {
				rz_il_op_pure_free(aval);
				return NULL;
			}
			return c55_write16(dst, c55_apply_bitop(kind, s2val, aval));
		}
		return NULL;
	}
	return NULL;
}

/**
 * Bitwise complement: "not src, dst" -> dst := ~src, or the in-place "not dst"
 * -> dst := ~dst. Restricted to register operands of matching width (for the
 * two-operand form). Like and/or/xor this carries no extension, saturation, or
 * value-affecting status side effects, so the complement over the register's
 * bound width is exact.
 */
static RzAnalysisLiftedILOp c55_lift_not(const C55Insn *in) {
	if (in->n_ops == 1) {
		const C55Operand *dst = &in->ops[0];
		if (dst->kind == C55_OP_REG) {
			return SETG(dst->reg, LOGNOT(VARG(dst->reg)));
		}
		return NULL;
	}
	if (in->n_ops == 2) {
		const C55Operand *src = &in->ops[0];
		const C55Operand *dst = &in->ops[1];
		if (src->kind == C55_OP_REG && dst->kind == C55_OP_REG && src->width == dst->width) {
			return SETG(dst->reg, LOGNOT(VARG(src->reg)));
		}
		return NULL;
	}
	return NULL;
}

/**
 * Arithmetic / logical accumulator shift by a compile-time 6-bit signed count:
 * "sfts ACx, #SHIFTW[, ACy]" (arithmetic) and "sftl ..." (logical). SHIFTW is a
 * 6-bit signed field — positive shifts left, negative shifts right. A left shift
 * is modulo 2^40; a right shift fills with the sign bit (sfts) or with zero
 * (sftl). Restricted to accumulator (40-bit) register operands with an immediate
 * count (the common form). The default non-saturating shift is modelled; the
 * optional SATD/M40 saturation modes are not represented (the same convention
 * the accumulator add/sub lift uses). Register-count and memory forms return
 * NULL.
 */
static RzAnalysisLiftedILOp c55_lift_shift(bool arith, const C55Insn *in) {
	const C55Operand *src;
	const C55Operand *cnt;
	const C55Operand *dst;
	if (in->n_ops == 3) {
		src = &in->ops[0];
		cnt = &in->ops[1];
		dst = &in->ops[2];
	} else if (in->n_ops == 2) {
		src = &in->ops[0];
		cnt = &in->ops[1];
		dst = &in->ops[0];
	} else {
		return NULL;
	}
	if (src->kind != C55_OP_REG || dst->kind != C55_OP_REG ||
		src->width != dst->width || src->width != 40) {
		return NULL;
	}
	// Register shift count (Tm, 16-bit signed): positive shifts left, negative
	// shifts right (arithmetic fills with the sign bit, logical with zero).
	if (cnt->kind == C55_OP_REG && cnt->width == 16) {
		RzILOpBool *fill = arith ? MSB(VARG(src->reg)) : IL_FALSE;
		return SETG(dst->reg,
			ITE(SLT(VARG(cnt->reg), SN(16, 0)),
				SHIFTR(fill, VARG(src->reg), SUB(SN(16, 0), VARG(cnt->reg))),
				SHIFTL(IL_FALSE, VARG(src->reg), VARG(cnt->reg))));
	}
	if (cnt->kind != C55_OP_IMM || cnt->imm > 0x3f) {
		return NULL;
	}
	// SHIFTW is a 6-bit signed shift count (positive = left, negative = right).
	long imm = (long)(cnt->imm & 0x3f);
	long c = (imm & 0x20) ? imm - 0x40 : imm;
	if (c == 0) {
		return SETG(dst->reg, VARG(src->reg));
	}
	if (c > 0) {
		return SETG(dst->reg, SHIFTL(IL_FALSE, VARG(src->reg), UN(6, (ut64)c)));
	}
	RzILOpBool *fill = arith ? MSB(VARG(src->reg)) : IL_FALSE;
	return SETG(dst->reg, SHIFTR(fill, VARG(src->reg), UN(6, (ut64)(-c))));
}

/**
 * Value-exact 16-bit-destination add/sub. Two-operand "<op> #imm/src, dst16"
 * (dst16 is a T or AR register) and the three-operand "<op> #imm/src16, ACx,
 * Tx" form, where the low word of (ACx +/- sx(src)) is written to the 16-bit
 * destination. A 16-bit destination uses plain modulo-2^16 arithmetic with no
 * saturation, and truncation commutes with add/sub, so the low-word result is
 * exact regardless of whether the ALU is 16- or 40-bit. Accumulator-destination
 * add/sub is handled elsewhere (saturation / M40 modes).
 */
typedef enum {
	C55_ADD,
	C55_SUB
} C55ArithOp;

static RzAnalysisLiftedILOp c55_lift_arith16(C55ArithOp kind, const C55Insn *in) {
	if (in->n_ops == 3) {
		// "<op> src, ACx, Tx" : Tx = low16(ACx +/- sx(src))
		const C55Operand *s = &in->ops[0];
		const C55Operand *a = &in->ops[1];
		const C55Operand *d = &in->ops[2];
		if (a->kind != C55_OP_REG || a->width != 40 || d->kind != C55_OP_REG || d->width != 16) {
			return NULL;
		}
		RzILOpBitVector *sv = NULL;
		if (s->kind == C55_OP_IMM) {
			sv = SN(40, (st64)(st16)(ut16)s->imm);
		} else if (s->kind == C55_OP_REG && s->width == 16) {
			sv = SIGNED(40, VARG(s->reg));
		} else {
			return NULL;
		}
		RzILOpBitVector *r = (kind == C55_ADD) ? ADD(VARG(a->reg), sv) : SUB(VARG(a->reg), sv);
		return SETG(d->reg, CAST(16, IL_FALSE, r));
	}
	if (in->n_ops != 2) {
		return NULL;
	}
	const C55Operand *src = &in->ops[0];
	const C55Operand *dst = &in->ops[1];
	if (dst->kind != C55_OP_REG || dst->width != 16) {
		return NULL;
	}
	RzILOpBitVector *operand = NULL;
	if (src->kind == C55_OP_IMM) {
		operand = UN(16, src->imm);
	} else if (src->kind == C55_OP_REG && src->width == 16) {
		operand = VARG(src->reg);
	} else if (src->kind == C55_OP_REG && src->width == 40) {
		operand = CAST(16, IL_FALSE, VARG(src->reg)); // ACx low word
	} else {
		return NULL;
	}
	switch (kind) {
	case C55_ADD: return SETG(dst->reg, ADD(VARG(dst->reg), operand));
	case C55_SUB: return SETG(dst->reg, SUB(VARG(dst->reg), operand));
	}
	return NULL;
}

/**
 * Value-exact accumulator add/sub: "<op> #imm, ACx", "<op> ACx, ACy", or
 * "<op> Tx, ACy". The 40-bit accumulator ALU is plain modulo-2^40 when
 * saturation is disabled (ST1 SATD = 0 -- the reset default, and the mode this
 * firmware runs in), so the result is exact: the M40 bit only changes overflow
 * flagging and the sign-bit position, not the stored value when not saturating.
 * 16-bit source operands are sign-extended into the 40-bit datapath
 * (SXMD = 1, reset default). Saturation (SATD = 1) and the status-flag side
 * effects are deliberately not modelled -- like the carry/overflow flags they
 * await a status model; this lift is exact for SATD = 0.
 */
static RzAnalysisLiftedILOp c55_lift_acarith(C55ArithOp kind, const C55Insn *in) {
	if (in->n_ops != 2) {
		return NULL;
	}
	const C55Operand *src = &in->ops[0];
	const C55Operand *dst = &in->ops[1];
	if (dst->kind != C55_OP_REG || dst->width != 40) {
		return NULL; // accumulator destination only
	}
	RzILOpBitVector *operand = NULL;
	if (src->kind == C55_OP_IMM) {
		operand = UN(40, src->imm); // parser admits only non-negative immediates
	} else if (src->kind == C55_OP_REG && src->width == 40) {
		operand = VARG(src->reg);
	} else if (src->kind == C55_OP_REG && src->width == 16) {
		operand = SIGNED(40, VARG(src->reg)); // SXMD = 1
	} else {
		return NULL;
	}
	switch (kind) {
	case C55_ADD: return SETG(dst->reg, ADD(VARG(dst->reg), operand));
	case C55_SUB: return SETG(dst->reg, SUB(VARG(dst->reg), operand));
	}
	return NULL;
}

/**
 * Build the IL predicate for a C55x+ conditional-branch condition string, taken
 * from the decoded syntax after the target operand. Two condition families are
 * handled exactly:
 *   - status flags `tc1` / `tc2` / `carry` (and their `!`-negated forms), read
 *     as bits 13 / 12 / 11 of ST0_55;
 *   - a register / accumulator-half compared against an immediate, e.g.
 *     `ac5 >= #0x7`, `ac1.l < #0x3`. Comparisons are signed for `bcc` and
 *     unsigned for `bccu` (the \p is_unsigned flag).
 * Anything else (register-vs-register conditions, unknown flags) returns NULL so
 * the branch is left unlifted rather than approximated.
 */
static RzILOpBool *c55_cond_value(const char *tok, ut32 *width) {
	ut32 w = 0;
	const char *rn = c55_reg(tok, &w);
	if (rn) {
		*width = w;
		return VARG(rn);
	}
	C55Operand h;
	if (c55_parse_half(tok, &h)) {
		*width = 16;
		if (h.half == 1) {
			return CAST(16, IL_FALSE, VARG(h.reg)); // .l = bits 15:0
		}
		return CAST(16, IL_FALSE, SHIFTR(IL_FALSE, VARG(h.reg), UN(8, 16))); // .h = bits 31:16
	}
	return NULL;
}

static RzILOpBool *c55_lift_cond(const char *syntax, bool is_unsigned) {
	if (!syntax) {
		return NULL;
	}
	const char *comma = strchr(syntax, ',');
	if (!comma) {
		return NULL;
	}
	const char *c = comma + 1;
	while (*c == ' ') {
		c++;
	}
	char buf[48];
	size_t n = strlen(c);
	while (n > 0 && (c[n - 1] == ' ' || c[n - 1] == '\n')) {
		n--;
	}
	if (n == 0 || n >= sizeof(buf)) {
		return NULL;
	}
	memcpy(buf, c, n);
	buf[n] = '\0';

	// status-flag conditions: [!]tc1 / [!]tc2 / [!]carry
	{
		char *p = buf;
		bool neg = false;
		if (*p == '!') {
			neg = true;
			p++;
		}
		int bit = -1;
		if (!strcmp(p, "tc1")) {
			bit = 13;
		} else if (!strcmp(p, "tc2")) {
			bit = 12;
		} else if (!strcmp(p, "carry")) {
			bit = 11;
		}
		if (bit >= 0) {
			RzILOpBool *b = LSB(SHIFTR(IL_FALSE, VARG("st0_55"), UN(4, (ut64)bit)));
			return neg ? INV(b) : b;
		}
	}

	// comparison: <reg|half> <relop> #imm
	static const struct {
		const char *s;
		int kind;
	} relops[] = { { "==", 0 }, { "!=", 1 }, { "<=", 2 }, { ">=", 3 }, { "<", 4 }, { ">", 5 } };
	char *op = NULL;
	int kind = -1;
	size_t oplen = 0;
	for (size_t i = 0; i < sizeof(relops) / sizeof(relops[0]); i++) {
		char *f = strstr(buf, relops[i].s);
		if (f) {
			op = f;
			kind = relops[i].kind;
			oplen = strlen(relops[i].s);
			break;
		}
	}
	if (!op) {
		return NULL;
	}
	// left/right tokens
	char left[24];
	char right[24];
	size_t ll = (size_t)(op - buf);
	while (ll > 0 && buf[ll - 1] == ' ') {
		ll--;
	}
	const char *r = op + oplen;
	while (*r == ' ') {
		r++;
	}
	size_t rl = strlen(r);
	while (rl > 0 && r[rl - 1] == ' ') {
		rl--;
	}
	if (ll == 0 || ll >= sizeof(left) || rl == 0 || rl >= sizeof(right)) {
		return NULL;
	}
	memcpy(left, buf, ll);
	left[ll] = '\0';
	memcpy(right, r, rl);
	right[rl] = '\0';
	ut32 lw = 0;
	RzILOpBitVector *lhs = c55_cond_value(left, &lw);
	if (!lhs) {
		return NULL;
	}
	// RHS is a register/half (width-matched to the LHS, extended per signedness)
	// or an immediate -- the same operand shapes c55_lift_cmp accepts.
	RzILOpBitVector *rhs = NULL;
	ut32 rw = 0;
	RzILOpBitVector *rv = c55_cond_value(right, &rw);
	if (rv) {
		if (rw < lw) {
			rv = is_unsigned ? UNSIGNED(lw, rv) : SIGNED(lw, rv);
		} else if (rw > lw) {
			lhs = is_unsigned ? UNSIGNED(rw, lhs) : SIGNED(rw, lhs);
			lw = rw;
		}
		rhs = rv;
	} else {
		ut64 imm = 0;
		if (!c55_parse_imm(right, &imm)) {
			rz_il_op_pure_free(lhs);
			return NULL;
		}
		rhs = UN(lw, imm);
	}
	switch (kind) {
	case 0: return EQ(lhs, rhs);
	case 1: return INV(EQ(lhs, rhs));
	case 2: return is_unsigned ? ULE(lhs, rhs) : SLE(lhs, rhs);
	case 3: return INV(is_unsigned ? ULT(lhs, rhs) : SLT(lhs, rhs));
	case 4: return is_unsigned ? ULT(lhs, rhs) : SLT(lhs, rhs);
	case 5: return is_unsigned ? UGT(lhs, rhs) : SGT(lhs, rhs);
	default: break;
	}
	rz_il_op_pure_free(lhs);
	rz_il_op_pure_free(rhs);
	return NULL;
}

// Map a status-bit token to its ST0_55 register and bit position. Accepts the
// disassembler's names ("st0_carry", "st0_tc1", "st0_acov0", ...) and the bare
// "carry"/"tc1"/"tc2" forms. ST0_55 layout: ACOV1=9, ACOV0=10, CARRY=11, TC2=12,
// TC1=13, ACOV3=14, ACOV2=15. Returns false for an unknown name.
static bool c55_status_bit(const char *name, const char **reg, int *bit) {
	*reg = "st0_55";
	if (!strcmp(name, "carry") || !strcmp(name, "st0_carry")) {
		*bit = 11;
	} else if (!strcmp(name, "tc1") || !strcmp(name, "st0_tc1")) {
		*bit = 13;
	} else if (!strcmp(name, "tc2") || !strcmp(name, "st0_tc2")) {
		*bit = 12;
	} else if (!strcmp(name, "st0_acov0")) {
		*bit = 10;
	} else if (!strcmp(name, "st0_acov1")) {
		*bit = 9;
	} else if (!strcmp(name, "st0_acov2")) {
		*bit = 15;
	} else if (!strcmp(name, "st0_acov3")) {
		*bit = 14;
	} else {
		return false;
	}
	return true;
}

// Status bit `bit` of `reg` isolated as a \p width-bit value that is 0 or 1.
static RzILOpBitVector *c55_bit_val(const char *reg, int bit, ut32 width) {
	RzILOpBitVector *v = LOGAND(SHIFTR(IL_FALSE, VARG(reg), UN(8, (ut64)bit)), UN(16, 1));
	return (width == 16) ? v : UNSIGNED(width, v);
}

// Status bit `bit` of `reg` as an IL bool (true iff set).
static RzILOpBool *c55_bit_bool(const char *reg, int bit) {
	return INV(IS_ZERO(LOGAND(VARG(reg), UN(16, 1u << bit))));
}

// Read-modify-write: set status bit `bit` of `reg` to the bool `cond` (consumed).
static RzAnalysisLiftedILOp c55_set_bit(const char *reg, int bit, RzILOpBool *cond) {
	ut32 mask = 1u << bit;
	return SETG(reg,
		ITE(cond,
			LOGOR(VARG(reg), UN(16, mask)),
			LOGAND(VARG(reg), UN(16, (~mask) & 0xffff))));
}

// Parse a relational expression "A <relop> B" into an IL bool (signed relational
// operators unless \p is_unsigned). A and B are register / accumulator-half /
// immediate values, width-matched by extending the narrower side. Returns NULL
// for a form that does not parse.
static RzILOpBool *c55_relexpr_bool(const char *expr, bool is_unsigned) {
	static const struct {
		const char *s;
		int kind;
	} relops[] = { { "==", 0 }, { "!=", 1 }, { "<=", 2 }, { ">=", 3 }, { "<", 4 }, { ">", 5 } };
	char *op = NULL;
	int kind = -1;
	size_t oplen = 0;
	for (size_t i = 0; i < sizeof(relops) / sizeof(relops[0]); i++) {
		char *f = strstr(expr, relops[i].s);
		if (f) {
			op = f;
			kind = relops[i].kind;
			oplen = strlen(relops[i].s);
			break;
		}
	}
	if (!op) {
		return NULL;
	}
	char left[24];
	char right[24];
	size_t ll = (size_t)(op - expr);
	while (ll > 0 && expr[ll - 1] == ' ') {
		ll--;
	}
	const char *r = op + oplen;
	while (*r == ' ') {
		r++;
	}
	size_t rl = strlen(r);
	while (rl > 0 && r[rl - 1] == ' ') {
		rl--;
	}
	if (ll == 0 || ll >= sizeof(left) || rl == 0 || rl >= sizeof(right)) {
		return NULL;
	}
	memcpy(left, expr, ll);
	left[ll] = '\0';
	memcpy(right, r, rl);
	right[rl] = '\0';
	ut32 lw = 0;
	RzILOpBitVector *lhs = c55_cond_value(left, &lw);
	if (!lhs) {
		return NULL;
	}
	RzILOpBitVector *rhs = NULL;
	ut32 rw = 0;
	RzILOpBitVector *rv = c55_cond_value(right, &rw);
	if (rv) {
		if (rw < lw) {
			rv = is_unsigned ? UNSIGNED(lw, rv) : SIGNED(lw, rv);
		} else if (rw > lw) {
			lhs = is_unsigned ? UNSIGNED(rw, lhs) : SIGNED(rw, lhs);
			lw = rw;
		}
		rhs = rv;
	} else {
		ut64 imm = 0;
		if (!c55_parse_imm(right, &imm)) {
			rz_il_op_pure_free(lhs);
			return NULL;
		}
		rhs = UN(lw, imm);
	}
	switch (kind) {
	case 0: return EQ(lhs, rhs);
	case 1: return INV(EQ(lhs, rhs));
	case 2: return is_unsigned ? ULE(lhs, rhs) : SLE(lhs, rhs);
	case 3: return INV(is_unsigned ? ULT(lhs, rhs) : SLT(lhs, rhs));
	case 4: return is_unsigned ? ULT(lhs, rhs) : SLT(lhs, rhs);
	case 5: return is_unsigned ? UGT(lhs, rhs) : SGT(lhs, rhs);
	}
	rz_il_op_pure_free(lhs);
	rz_il_op_pure_free(rhs);
	return NULL;
}

/**
 * Lift "cmp[u] <A> <relop> <B>, tcN": evaluate the relational comparison and
 * write its boolean result into the test-control flag TC1 (ST0_55 bit 13) or
 * TC2 (bit 12). \p is_unsigned selects the unsigned relational operators (the
 * "cmpu" form) over the signed ones ("cmp"). <A> is a register or accumulator
 * half; <B> is another such value or an immediate. The two sides are width-
 * matched by extending the narrower one (zero-/sign-extend per signedness).
 * Returns NULL for any operand or destination shape that is not modelled,
 * preserving the correct-or-NULL contract.
 */
static RzAnalysisLiftedILOp c55_lift_cmp(const char *syntax, bool is_unsigned) {
	if (!syntax) {
		return NULL;
	}
	const char *s = strchr(syntax, ' ');
	if (!s) {
		return NULL;
	}
	while (*s == ' ') {
		s++;
	}
	const char *comma = strrchr(s, ',');
	if (!comma) {
		return NULL;
	}
	// destination flag (token after the last comma)
	const char *d = comma + 1;
	while (*d == ' ') {
		d++;
	}
	int bit = -1;
	if (!strcmp(d, "tc1")) {
		bit = 13;
	} else if (!strcmp(d, "tc2")) {
		bit = 12;
	} else {
		return NULL;
	}
	// comparison expression "A relop B" (everything before the comma)
	char expr[48];
	size_t el = (size_t)(comma - s);
	while (el > 0 && s[el - 1] == ' ') {
		el--;
	}
	if (el == 0 || el >= sizeof(expr)) {
		return NULL;
	}
	memcpy(expr, s, el);
	expr[el] = '\0';
	RzILOpBool *cond = c55_relexpr_bool(expr, is_unsigned);
	if (!cond) {
		return NULL;
	}
	// ST0_55 is 16-bit; set or clear the TC bit per the comparison result.
	ut32 mask = 1u << bit;
	return SETG("st0_55",
		ITE(cond,
			LOGOR(VARG("st0_55"), UN(16, mask)),
			LOGAND(VARG("st0_55"), UN(16, (~mask) & 0xffff))));
}

/**
 * "mov #K << #SHIFT, ACx": load the immediate, sign-extended from 16 bits and
 * shifted left by a compile-time amount, into a 40-bit accumulator. The
 * compiler uses this to build a constant's upper bits, typically paired with a
 * following "or #lo, ACx, ACx" (so "mov #0 << #16, AC1; or #0x8004, AC1, AC1"
 * materialises 0x8004). The "<imm> << #<n>" form is a single disassembly token
 * the structured operand parser leaves as OTHER, so it is matched on the
 * syntax string here. Returns NULL for non-accumulator destinations or shifts
 * the model cannot represent.
 */
static RzAnalysisLiftedILOp c55_lift_mov_shl(const char *syntax) {
	if (!syntax || strncmp(syntax, "mov ", 4)) {
		return NULL;
	}
	const char *shl = strstr(syntax, " << #");
	if (!shl) {
		return NULL;
	}
	char immbuf[48];
	size_t ilen = (size_t)(shl - (syntax + 4));
	if (ilen == 0 || ilen >= sizeof(immbuf)) {
		return NULL;
	}
	memcpy(immbuf, syntax + 4, ilen);
	immbuf[ilen] = '\0';
	const char *sh = shl + 5; // past " << #"
	const char *comma = strchr(sh, ',');
	if (!comma) {
		return NULL;
	}
	char shbuf[16];
	size_t slen = (size_t)(comma - sh);
	if (slen == 0 || slen >= sizeof(shbuf)) {
		return NULL;
	}
	memcpy(shbuf, sh, slen);
	shbuf[slen] = '\0';
	const char *rp = comma + 1;
	while (*rp == ' ') {
		rp++;
	}
	char regbuf[16];
	size_t rl = strlen(rp);
	if (rl == 0 || rl >= sizeof(regbuf)) {
		return NULL;
	}
	memcpy(regbuf, rp, rl + 1);
	ut64 k = 0, s = 0;
	if (!c55_parse_imm(immbuf, &k) || !c55_parse_imm(shbuf, &s) || s >= 40) {
		return NULL;
	}
	ut32 w = 0;
	const char *reg = c55_reg(regbuf, &w);
	if (!reg || w != 40) {
		return NULL;
	}
	// sign-extend the 16-bit immediate, shift, and truncate to 40 bits
	st64 sval = (k & 0x8000ULL) ? (st64)(k | 0xffffffffffff0000ULL) : (st64)(k & 0xffffULL);
	ut64 v = ((ut64)((ut64)sval << s)) & 0xffffffffffULL;
	return SETG(reg, UN(40, v));
}

/**
 * A-unit register move / modular add / sub: "amov SRC, DST", "aadd SRC, DST",
 * "asub SRC, DST". DST is a bound register (XAR 23-bit, AR/T 16-bit, or AC
 * 40-bit); SRC is a bound register or an immediate. amov assigns SRC to DST
 * (resized -- address registers hold unsigned addresses, so widening
 * zero-extends); aadd/asub compute DST +/- SRC at DST's width. A-unit pointer
 * arithmetic and the 16-bit ALU are plain modulo with no saturation, so the
 * result is exact at the bound width. An immediate is lifted only when it fits
 * the destination width, so an out-of-range constant (e.g. a 24-bit byte
 * constant moved into a 23-bit XAR) is left unlifted rather than truncated. SP /
 * XSP destinations are not handled here (SP has no fixed width in this model;
 * its arithmetic belongs with the deferred stack ops).
 */
typedef enum {
	C55_AMOV,
	C55_AADD,
	C55_ASUB
} C55AddrOp;
static RzAnalysisLiftedILOp c55_lift_addr(C55AddrOp kind, const C55Insn *in) {
	if (in->n_ops != 2) {
		return NULL;
	}
	const C55Operand *src = &in->ops[0];
	const C55Operand *dst = &in->ops[1];
	if (dst->kind != C55_OP_REG) {
		return NULL;
	}
	const ut32 w = dst->width;
	RzILOpBitVector *sval = NULL;
	if (src->kind == C55_OP_IMM) {
		if (w < 64 && src->imm >= (1ULL << w)) {
			return NULL; // constant does not fit the destination register
		}
		sval = UN(w, src->imm);
	} else if (src->kind == C55_OP_REG) {
		sval = c55_resize(VARG(src->reg), src->width, w, true);
	} else {
		return NULL;
	}
	switch (kind) {
	case C55_AMOV: return SETG(dst->reg, sval);
	case C55_AADD: return SETG(dst->reg, ADD(VARG(dst->reg), sval));
	case C55_ASUB: return SETG(dst->reg, SUB(VARG(dst->reg), sval));
	}
	rz_il_op_pure_free(sval);
	return NULL;
}

/**
 * "amar <mem>, DST": load the *address* the memory operand designates into the
 * address register DST, applying the operand's pointer side effect but no memory
 * access. In word-pointer mode an indirect "*arN" yields the base word address,
 * and an indexed "*arN(short(#K))" / "*sp(#K)" yields (base + sx(K)); the result
 * is resized to DST's width. Post-increment/decrement modes apply their XARn
 * +/- 1-word side effect (sequenced after the assignment). Absolute and other
 * memory modes, and non-register destinations, return NULL.
 */
static RzAnalysisLiftedILOp c55_lift_amar(const C55Insn *in) {
	// Form 1: "amar Smem, REG" -> REG = the computed word address of Smem, plus
	// the operand's post-modify side effect.
	if (in->n_ops == 2 && in->ops[1].kind == C55_OP_REG) {
		const C55Operand *mem = &in->ops[0];
		const C55Operand *dst = &in->ops[1];
		if (mem->kind != C55_OP_MEM || !mem->reg) {
			return NULL;
		}
		RzILOpBitVector *addr = NULL;
		switch (mem->amode) {
		case C55_AM_INDIRECT:
		case C55_AM_POSTINC:
		case C55_AM_POSTDEC:
			addr = UNSIGNED(24, VARG(mem->reg));
			break;
		case C55_AM_INDEXED:
			addr = ADD(UNSIGNED(24, VARG(mem->reg)), SN(24, mem->disp));
			break;
		default:
			return NULL;
		}
		addr = c55_resize(addr, 24, dst->width, true);
		RzAnalysisLiftedILOp set = SETG(dst->reg, addr);
		RzAnalysisLiftedILOp post = c55_mem_post_effect(mem);
		return post ? SEQ2(set, post) : set;
	}
	// Form 2: "amar Smem [, Smem ...]" with no register destination -> the
	// instruction only applies each operand's address-register post-modify; a
	// plain indirect modifies nothing and so lifts to nop.
	if (in->n_ops < 1) {
		return NULL;
	}
	RzAnalysisLiftedILOp seq = NULL;
	for (int i = 0; i < in->n_ops; i++) {
		if (in->ops[i].kind != C55_OP_MEM || !in->ops[i].reg) {
			return NULL;
		}
		RzAnalysisLiftedILOp post = c55_mem_post_effect(&in->ops[i]);
		if (post) {
			seq = seq ? SEQ2(seq, post) : post;
		}
	}
	return seq ? seq : NOP();
}

/**
 * "neg SRC, DST" / in-place "neg DST": two's-complement negation, modelled as
 * 0 - SRC at the operand width. Full-accumulator (40-bit) and 16-bit
 * register/half forms are handled; a half destination negates its 16-bit value
 * in place. SATD/M40 saturation is not modelled (matching the add/sub
 * convention), so the lift is exact for SATD = 0. Other shapes return NULL.
 */
static RzAnalysisLiftedILOp c55_lift_neg(const C55Insn *in) {
	const C55Operand *src;
	const C55Operand *dst;
	if (in->n_ops == 2) {
		src = &in->ops[0];
		dst = &in->ops[1];
	} else if (in->n_ops == 1) {
		src = dst = &in->ops[0];
	} else {
		return NULL;
	}
	if (src->kind == C55_OP_REG && dst->kind == C55_OP_REG && src->width == dst->width) {
		return SETG(dst->reg, SUB(UN(dst->width, 0), VARG(src->reg)));
	}
	bool dst16 = dst->kind == C55_OP_REGHALF || (dst->kind == C55_OP_REG && dst->width == 16);
	if (dst16) {
		RzILOpBitVector *v = c55_read16(src);
		if (!v) {
			return NULL;
		}
		return c55_write16(dst, SUB(UN(16, 0), v));
	}
	return NULL;
}

/**
 * Lift one already-decoded C55x+ op to IL. \p syntax is the decoded lowercase
 * mnemonic string (may be NULL).
 */
// Shift a 40-bit value left by an immediate ("#16" / "0x33") or a 16-bit
// register count ("t0"). Consumes \p v40; returns NULL (freeing it) for any
// other shift token.
static RzILOpBitVector *c55_shift40(RzILOpBitVector *v40, const char *sh) {
	ut32 w = 0;
	const char *rn = c55_reg(sh, &w);
	if (rn && w == 16) {
		return SHIFTL(IL_FALSE, v40, VARG(rn));
	}
	ut64 n = 0;
	if (c55_parse_imm(sh, &n)) {
		return SHIFTL(IL_FALSE, v40, UN(8, n & 0xff));
	}
	rz_il_op_pure_free(v40);
	return NULL;
}

// Accumulator ALU: add/sub/and/or/xor in the 2-operand ("OP src, ACdst" ->
// ACdst = ACdst OP src) and 3-operand ("OP src, ACsrc, ACdst" -> ACdst =
// ACsrc OP src) forms, where \p src is an accumulator or a 16-bit immediate,
// optionally shifted left ("src << #k" / "src << tN"). Arithmetic is 40-bit;
// the immediate is sign-extended for add/sub and zero-extended for the bitwise
// ops. Parses the raw syntax (the shifted source arrives as one C55_OP_OTHER
// token). Returns NULL for any other shape. This complements the dedicated
// 16-bit / simple-accumulator lifters, which are tried first.
static RzAnalysisLiftedILOp c55_lift_acc_alu(const char *syntax) {
	if (!syntax) {
		return NULL;
	}
	const char *sp = strchr(syntax, ' ');
	if (!sp) {
		return NULL;
	}
	size_t mlen = (size_t)(sp - syntax);
	char mn[8];
	if (mlen >= sizeof(mn)) {
		return NULL;
	}
	memcpy(mn, syntax, mlen);
	mn[mlen] = '\0';
	enum { OP_ADD,
		OP_SUB,
		OP_AND,
		OP_OR,
		OP_XOR } op;
	if (!strcmp(mn, "add")) {
		op = OP_ADD;
	} else if (!strcmp(mn, "sub")) {
		op = OP_SUB;
	} else if (!strcmp(mn, "and")) {
		op = OP_AND;
	} else if (!strcmp(mn, "or")) {
		op = OP_OR;
	} else if (!strcmp(mn, "xor")) {
		op = OP_XOR;
	} else {
		return NULL;
	}
	// split the (pre-"||") operand list by comma, up to 3
	char ops[3][48];
	int nops = 0;
	const char *p = sp + 1;
	const char *par = strstr(p, "||");
	const char *limit = par ? par : p + strlen(p);
	while (p < limit && nops < 3) {
		while (p < limit && *p == ' ') {
			p++;
		}
		const char *c = NULL;
		for (const char *q = p; q < limit; q++) {
			if (*q == ',') {
				c = q;
				break;
			}
		}
		const char *e = c ? c : limit;
		const char *te = e;
		while (te > p && te[-1] == ' ') {
			te--;
		}
		size_t L = (size_t)(te - p);
		if (L == 0 || L >= sizeof(ops[0])) {
			return NULL;
		}
		memcpy(ops[nops], p, L);
		ops[nops][L] = '\0';
		nops++;
		if (!c) {
			break;
		}
		p = c + 1;
	}
	if (nops < 2 || nops > 3) {
		return NULL;
	}
	ut32 dw = 0;
	const char *dst = c55_reg(ops[nops - 1], &dw);
	if (!dst || dw != 40) {
		return NULL;
	}
	const char *lhs = dst;
	if (nops == 3) {
		ut32 lw = 0;
		lhs = c55_reg(ops[1], &lw);
		if (!lhs || lw != 40) {
			return NULL;
		}
	}
	// source operand ops[0] = "<base> [<< <shift>]"
	char base[48];
	const char *shtok = NULL;
	char *shp = strstr(ops[0], " << ");
	if (shp) {
		size_t bl = (size_t)(shp - ops[0]);
		if (bl >= sizeof(base)) {
			return NULL;
		}
		memcpy(base, ops[0], bl);
		base[bl] = '\0';
		shtok = shp + 4;
	} else {
		if (strlen(ops[0]) >= sizeof(base)) {
			return NULL;
		}
		rz_str_ncpy(base, ops[0], sizeof(base));
	}
	bool is_arith = (op == OP_ADD || op == OP_SUB);
	RzILOpBitVector *src;
	ut32 bw = 0;
	const char *brn = c55_reg(base, &bw);
	if (brn && bw == 40) {
		src = VARG(brn);
	} else {
		ut64 imm = 0;
		if (!c55_parse_imm(base, &imm)) {
			return NULL;
		}
		src = is_arith ? SN(40, (st64)(st16)(ut16)imm) : UN(40, imm & 0xffff);
	}
	if (shtok) {
		src = c55_shift40(src, shtok);
		if (!src) {
			return NULL;
		}
	}
	RzILOpBitVector *res;
	switch (op) {
	case OP_ADD: res = ADD(VARG(lhs), src); break;
	case OP_SUB: res = SUB(VARG(lhs), src); break;
	case OP_AND: res = LOGAND(VARG(lhs), src); break;
	case OP_OR: res = LOGOR(VARG(lhs), src); break;
	default: res = LOGXOR(VARG(lhs), src); break;
	}
	return SETG(dst, res);
}

// abs / min / max on equal-width register operands (accumulator 40-bit, or T/AR
// 16-bit): "abs ACx" (1-op) or "OP src, dst" (2-op). \p kind: 0 = abs, 1 = min,
// 2 = max. Comparisons are signed. Returns NULL for mixed widths, non-register
// operands, or unexpected operand counts.
static RzAnalysisLiftedILOp c55_lift_minmaxabs(const C55Insn *in, int kind) {
	const C55Operand *s, *d;
	if (in->n_ops == 1) {
		s = d = &in->ops[0];
	} else if (in->n_ops == 2) {
		s = &in->ops[0];
		d = &in->ops[1];
	} else {
		return NULL;
	}
	if (s->kind != C55_OP_REG || d->kind != C55_OP_REG || s->width != d->width) {
		return NULL;
	}
	ut32 w = d->width;
	if (w != 40 && w != 16) {
		return NULL;
	}
	if (kind == 0) { // abs: (s < 0) ? -s : s
		return SETG(d->reg, ITE(SLT(VARG(s->reg), SN(w, 0)), SUB(SN(w, 0), VARG(s->reg)), VARG(s->reg)));
	}
	if (kind == 1) { // min: (s < d) ? s : d
		return SETG(d->reg, ITE(SLT(VARG(s->reg), VARG(d->reg)), VARG(s->reg), VARG(d->reg)));
	}
	// max: (s > d) ? s : d
	return SETG(d->reg, ITE(SGT(VARG(s->reg), VARG(d->reg)), VARG(s->reg), VARG(d->reg)));
}

// swap: exchange two equal-width registers via the temp-free XOR swap
// (a ^= b; b ^= a; a ^= b). Returns NULL for mixed widths / non-registers.
static RzAnalysisLiftedILOp c55_lift_swap(const C55Insn *in) {
	if (in->n_ops != 2) {
		return NULL;
	}
	const C55Operand *a = &in->ops[0], *b = &in->ops[1];
	if (a->kind != C55_OP_REG || b->kind != C55_OP_REG || a->width != b->width) {
		return NULL;
	}
	return SEQ3(
		SETG(a->reg, LOGXOR(VARG(a->reg), VARG(b->reg))),
		SETG(b->reg, LOGXOR(VARG(b->reg), VARG(a->reg))),
		SETG(a->reg, LOGXOR(VARG(a->reg), VARG(b->reg))));
}

// bset / bclr of a single bit in a status/other register: "bset #bit, REG" /
// "bclr #bit, REG" where #bit is a numeric bit index. Returns NULL for the
// named-bit form (e.g. "bset st0_acov0, st0_55") or non-register destinations.
static RzAnalysisLiftedILOp c55_lift_bitset(const C55Insn *in, bool set) {
	if (in->n_ops != 2 || in->ops[0].kind != C55_OP_IMM || in->ops[1].kind != C55_OP_REG) {
		return NULL;
	}
	ut32 w = in->ops[1].width;
	ut64 bit = in->ops[0].imm;
	if (bit >= w) {
		return NULL;
	}
	const char *r = in->ops[1].reg;
	if (set) {
		return SETG(r, LOGOR(VARG(r), UN(w, 1ULL << bit)));
	}
	ut64 wmask = (w >= 64) ? ~0ULL : ((1ULL << w) - 1);
	return SETG(r, LOGAND(VARG(r), UN(w, (~(1ULL << bit)) & wmask)));
}

// 40-bit signed value of a multiplicand operand (documented integer-mode model):
// a 16-bit register / accumulator low word (.l) / accumulator half, sign-extended;
// a 16-bit immediate, sign-extended; or a memory word, sign-extended (zero-extended
// under an uns() wrapper). Returns NULL for any other operand kind.
static RzILOpBitVector *c55_mul_val(const C55Operand *op) {
	switch (op->kind) {
	case C55_OP_IMM:
		return SN(40, (st64)(st16)(ut16)op->imm);
	case C55_OP_REG:
		if (op->width == 16) {
			return SIGNED(40, VARG(op->reg));
		}
		if (op->width == 40) {
			return SIGNED(40, CAST(16, IL_FALSE, VARG(op->reg))); // ACx.l
		}
		return NULL;
	case C55_OP_REGHALF: {
		RzILOpBitVector *v = c55_src16(op);
		return v ? SIGNED(40, v) : NULL;
	}
	case C55_OP_MEM: {
		int ab = op->access_bits ? op->access_bits : 16;
		RzILOpBitVector *l = LOADW(ab, c55_mem_byte_addr(op));
		return c55_resize(l, ab, 40, op->mem_uns);
	}
	default:
		return NULL;
	}
}

// One multiply-family operand: a decoded operand plus the two decorations that
// appear in this syntax -- a "tN=" memory side-load target and a ">> #k" right
// shift applied to the accumulator source operand.
typedef struct {
	C55Operand op;
	const char *sideload; // "tN=Smem": static T-register name to also receive the loaded word
	int shr; // ">> #k": arithmetic right-shift applied to this (accumulator) operand
	bool ok;
} C55MulArg;

static C55MulArg c55_parse_mul_arg(const char *tok) {
	C55MulArg a;
	memset(&a, 0, sizeof(a));
	char buf[80];
	if (strlen(tok) >= sizeof(buf)) {
		return a;
	}
	rz_str_ncpy(buf, tok, sizeof(buf));
	char *s = buf;
	// "tN=Smem" side-load prefix
	char *eq = strchr(s, '=');
	if (eq) {
		*eq = '\0';
		ut32 w = 0;
		const char *t = c55_reg(s, &w);
		if (!t || w != 16 || t[0] != 't') {
			return a;
		}
		a.sideload = t;
		s = eq + 1;
	}
	// ">> #k" accumulator pre-shift suffix
	char *sh = strstr(s, " >> ");
	if (sh) {
		const char *shtok = sh + 4;
		*sh = '\0';
		ut64 k = 0;
		if (!c55_parse_imm(shtok, &k)) {
			return a;
		}
		a.shr = (int)(k & 0x3f);
	}
	// trim trailing spaces
	size_t L = strlen(s);
	while (L > 0 && s[L - 1] == ' ') {
		s[--L] = '\0';
	}
	ut32 w = 0;
	const char *rn = c55_reg(s, &w);
	ut64 imm = 0;
	if (rn) {
		a.op.kind = C55_OP_REG;
		a.op.reg = rn;
		a.op.width = w;
	} else if (c55_parse_imm(s, &imm)) {
		a.op.kind = C55_OP_IMM;
		a.op.imm = imm;
	} else if (c55_parse_mem(s, &a.op)) {
		// filled
	} else {
		return a;
	}
	a.ok = true;
	return a;
}

// Multiply / multiply-accumulate (documented integer-mode model: FRCT = 0, no
// fractional <<1, no saturation). mpy* assigns the product; mac* adds it to the
// accumulator source; mas* subtracts it. An "r" suffix rounds the result to the
// upper word ((v + 0x8000) & ~0xffff). Multiplicand values come from c55_mul_val
// (accumulators contribute their low word .l). A leading "tN=Smem" also writes
// the loaded word to tN; memory post-modify side effects are applied last.
// Operand layout: dst is the last operand; for mac/mas a 4-operand form names a
// distinct accumulator source second-to-last, otherwise the destination doubles
// as the accumulator source. Unrepresented shapes return NULL.
static RzAnalysisLiftedILOp c55_lift_mul(const char *syntax) {
	if (!syntax) {
		return NULL;
	}
	const char *sp = strchr(syntax, ' ');
	if (!sp) {
		return NULL;
	}
	size_t mlen = (size_t)(sp - syntax);
	char mn[12];
	if (mlen >= sizeof(mn)) {
		return NULL;
	}
	memcpy(mn, syntax, mlen);
	mn[mlen] = '\0';
	int kind; // 0 = set (mpy), 1 = add (mac), 2 = sub (mas)
	if (!strncmp(mn, "mpy", 3)) {
		kind = 0;
	} else if (!strncmp(mn, "mac", 3)) {
		kind = 1;
	} else if (!strncmp(mn, "mas", 3)) {
		kind = 2;
	} else {
		return NULL;
	}
	bool round = strchr(mn + 3, 'r') != NULL;
	// split operands (first half only; "::" is handled by the parallel splitter)
	const char *p = sp + 1;
	const char *par = strstr(p, " :: ");
	const char *limit = par ? par : p + strlen(p);
	C55MulArg args[4];
	int n = 0;
	while (p < limit && n < 4) {
		while (p < limit && *p == ' ') {
			p++;
		}
		const char *c = NULL;
		for (const char *q = p; q < limit; q++) {
			if (*q == ',') {
				c = q;
				break;
			}
		}
		const char *e = c ? c : limit;
		const char *te = e;
		while (te > p && te[-1] == ' ') {
			te--;
		}
		char tok[80];
		size_t tl = (size_t)(te - p);
		if (tl == 0 || tl >= sizeof(tok)) {
			return NULL;
		}
		memcpy(tok, p, tl);
		tok[tl] = '\0';
		args[n] = c55_parse_mul_arg(tok);
		if (!args[n].ok) {
			return NULL;
		}
		n++;
		if (!c) {
			break;
		}
		p = c + 1;
	}
	if (n < 2) {
		return NULL;
	}
	// destination = last operand, must be an accumulator
	C55MulArg *dst = &args[n - 1];
	if (dst->op.kind != C55_OP_REG || dst->op.width != 40) {
		return NULL;
	}
	// identify multiplicands, and (for mac/mas) the accumulator source
	C55MulArg *m1, *m2, *accsrc = NULL;
	if (kind == 0) {
		if (n == 2) {
			m1 = &args[0];
			m2 = dst; // dst.l as the second multiplicand
		} else if (n == 3) {
			m1 = &args[0];
			m2 = &args[1];
		} else {
			return NULL;
		}
	} else {
		if (n == 3) {
			m1 = &args[0];
			m2 = &args[1];
			accsrc = dst;
		} else if (n == 4 && args[2].op.kind == C55_OP_REG && args[2].op.width == 40) {
			m1 = &args[0];
			m2 = &args[1];
			accsrc = &args[2];
		} else {
			return NULL;
		}
	}
	RzILOpBitVector *v1 = c55_mul_val(&m1->op);
	RzILOpBitVector *v2 = c55_mul_val(&m2->op);
	if (!v1 || !v2) {
		rz_il_op_pure_free(v1);
		rz_il_op_pure_free(v2);
		return NULL;
	}
	RzILOpBitVector *prod = MUL(v1, v2);
	RzILOpBitVector *res;
	if (kind == 0) {
		res = prod;
	} else {
		RzILOpBitVector *acc = VARG(accsrc->op.reg);
		if (accsrc->shr > 0) {
			acc = SHIFTR(MSB(VARG(accsrc->op.reg)), acc, UN(6, (ut64)accsrc->shr));
		}
		res = (kind == 1) ? ADD(acc, prod) : SUB(acc, prod);
	}
	if (round) {
		res = LOGAND(ADD(res, UN(40, 0x8000)), UN(40, 0xffffff0000ULL));
	}
	RzAnalysisLiftedILOp eff = SETG(dst->op.reg, res);
	// optional memory side-load into tN (load the same word again)
	for (int i = 0; i < n; i++) {
		if (args[i].sideload && args[i].op.kind == C55_OP_MEM) {
			int ab = args[i].op.access_bits ? args[i].op.access_bits : 16;
			RzILOpBitVector *l = LOADW(ab, c55_mem_byte_addr(&args[i].op));
			RzILOpBitVector *v = c55_resize(l, ab, 16, args[i].op.mem_uns);
			eff = SEQ2(SETG(args[i].sideload, v), eff);
		}
	}
	// memory post-modify side effects (after the access)
	for (int i = 0; i < n; i++) {
		if (args[i].op.kind == C55_OP_MEM) {
			RzAnalysisLiftedILOp post = c55_mem_post_effect(&args[i].op);
			if (post) {
				eff = SEQ2(eff, post);
			}
		}
	}
	return eff;
}

// Dual-memory accumulator arithmetic: "add Xmem, Ymem, ACx" / "sub Xmem, Ymem,
// ACx" -> ACx = sx(load X) +/- sx(load Y) (zero-extended under an uns() wrapper).
// 40-bit, no saturation. Memory post-modify side effects are applied. Returns
// NULL unless both sources are memory and the destination an accumulator.
static RzAnalysisLiftedILOp c55_lift_dualmem(const C55Insn *in, bool sub) {
	if (in->n_ops != 3) {
		return NULL;
	}
	const C55Operand *x = &in->ops[0], *y = &in->ops[1], *d = &in->ops[2];
	if (x->kind != C55_OP_MEM || y->kind != C55_OP_MEM || d->kind != C55_OP_REG || d->width != 40) {
		return NULL;
	}
	RzILOpBitVector *vx = c55_mul_val(x);
	RzILOpBitVector *vy = c55_mul_val(y);
	if (!vx || !vy) {
		rz_il_op_pure_free(vx);
		rz_il_op_pure_free(vy);
		return NULL;
	}
	RzAnalysisLiftedILOp eff = SETG(d->reg, sub ? SUB(vx, vy) : ADD(vx, vy));
	RzAnalysisLiftedILOp px = c55_mem_post_effect(x);
	RzAnalysisLiftedILOp py = c55_mem_post_effect(y);
	if (px) {
		eff = SEQ2(eff, px);
	}
	if (py) {
		eff = SEQ2(eff, py);
	}
	return eff;
}

// round / square (documented integer-mode model). "round ACx, ACy": ACy =
// (ACx + 0x8000) & ~0xffff (round to the upper word). "sqar ACx, ACy": ACy =
// ACx.l * ACx.l, the signed square of the low word; "sqrr" rounds that result.
// No saturation. Returns NULL for shapes other than two accumulator operands.
static RzAnalysisLiftedILOp c55_lift_round_sq(const C55Insn *in, int kind) {
	// kind: 0 = round, 1 = sqar (square), 2 = sqrr (square + round)
	if (in->n_ops != 2 || in->ops[0].kind != C55_OP_REG || in->ops[0].width != 40 ||
		in->ops[1].kind != C55_OP_REG || in->ops[1].width != 40) {
		return NULL;
	}
	const char *s = in->ops[0].reg, *d = in->ops[1].reg;
	RzILOpBitVector *v;
	if (kind == 0) {
		v = VARG(s);
	} else {
		v = MUL(SIGNED(40, CAST(16, IL_FALSE, VARG(s))), SIGNED(40, CAST(16, IL_FALSE, VARG(s))));
	}
	if (kind == 0 || kind == 2) {
		v = LOGAND(ADD(v, UN(40, 0x8000)), UN(40, 0xffffff0000ULL));
	}
	return SETG(d, v);
}

// Split the operand list of `syntax` (everything after the first space) into up
// to `max` comma-separated, space-trimmed tokens. Returns the token count.
static int c55_split_ops(const char *syntax, char out[][24], int max) {
	const char *s = strchr(syntax, ' ');
	if (!s) {
		return 0;
	}
	while (*s == ' ') {
		s++;
	}
	int n = 0;
	const char *p = s;
	while (n < max && *p) {
		const char *c = strchr(p, ',');
		const char *e = c ? c : p + strlen(p);
		const char *b = p;
		while (b < e && *b == ' ') {
			b++;
		}
		const char *te = e;
		while (te > b && te[-1] == ' ') {
			te--;
		}
		size_t l = (size_t)(te - b);
		if (l == 0 || l >= 24) {
			return n;
		}
		memcpy(out[n], b, l);
		out[n][l] = '\0';
		n++;
		if (!c) {
			break;
		}
		p = c + 1;
	}
	return n;
}

// cmpand / cmpor (+ unsigned cmpandu / cmporu): TCdst = (A relop B) AND/OR TCsrc,
// where TCsrc is a TC bit optionally negated with a leading '!'. Exact: the
// relational result and the bitwise TC combination are both modelled directly.
static RzAnalysisLiftedILOp c55_lift_cmpbit(const char *syntax, bool is_unsigned, bool is_and) {
	char t[3][24];
	if (c55_split_ops(syntax, t, 3) != 3) {
		return NULL;
	}
	bool neg = false;
	const char *srcname = t[1];
	if (srcname[0] == '!') {
		neg = true;
		srcname++;
	}
	const char *sreg, *dreg;
	int sbit, dbit;
	if (!c55_status_bit(srcname, &sreg, &sbit) || !c55_status_bit(t[2], &dreg, &dbit)) {
		return NULL;
	}
	RzILOpBool *cond = c55_relexpr_bool(t[0], is_unsigned);
	if (!cond) {
		return NULL;
	}
	RzILOpBool *tcsrc = c55_bit_bool(sreg, sbit);
	if (neg) {
		tcsrc = INV(tcsrc);
	}
	RzILOpBool *res = is_and ? AND(cond, tcsrc) : OR(cond, tcsrc);
	return c55_set_bit(dreg, dbit, res);
}

// rol / ror through a status bit: "<op> BitIn, Src, BitOut, Dst". BitIn/BitOut
// are carry/TC bits in ST0_55, Src/Dst accumulators. rol: Dst = (Src << 1) |
// BitIn, BitOut = MSB(Src); ror: Dst = (Src >> 1) | (BitIn << 39), BitOut =
// LSB(Src). Exact for the 40-bit rotate. (Src and Dst are distinct here, so the
// destination write and the bit-out update do not interfere.)
static RzAnalysisLiftedILOp c55_lift_rotate(const char *syntax, bool left) {
	char t[4][24];
	if (c55_split_ops(syntax, t, 4) != 4) {
		return NULL;
	}
	const char *binr, *boutr;
	int binbit, boutbit;
	if (!c55_status_bit(t[0], &binr, &binbit) || !c55_status_bit(t[2], &boutr, &boutbit)) {
		return NULL;
	}
	ut32 sw = 0, dw = 0;
	const char *src = c55_reg(t[1], &sw);
	const char *dst = c55_reg(t[3], &dw);
	if (!src || !dst || sw != 40 || dw != 40) {
		return NULL;
	}
	RzILOpBitVector *carin = c55_bit_val(binr, binbit, 40);
	RzILOpBitVector *rotated;
	RzILOpBool *bitout;
	if (left) {
		rotated = LOGOR(SHIFTL(IL_FALSE, VARG(src), UN(6, 1)), carin);
		bitout = MSB(VARG(src)); // bit 39 shifts out on a left rotate
	} else {
		rotated = LOGOR(SHIFTR(IL_FALSE, VARG(src), UN(6, 1)), SHIFTL(IL_FALSE, carin, UN(6, 39)));
		bitout = LSB(VARG(src)); // bit 0 shifts out on a right rotate
	}
	RzAnalysisLiftedILOp set_dst = SETG(dst, rotated);
	RzAnalysisLiftedILOp set_out = c55_set_bit(boutr, boutbit, bitout);
	return SEQ2(set_dst, set_out);
}

// Named-bit bset / bclr: "bset st0_acovN, st0_55" / "bclr ...". Sets or clears
// the named ST0_55 status bit. Exact.
static RzAnalysisLiftedILOp c55_lift_bitset_named(const char *syntax, bool set) {
	char t[2][24];
	if (c55_split_ops(syntax, t, 2) != 2) {
		return NULL;
	}
	const char *reg;
	int bit;
	if (!c55_status_bit(t[0], &reg, &bit) || strcmp(t[1], reg) != 0) {
		return NULL;
	}
	return c55_set_bit(reg, bit, set ? IL_TRUE : IL_FALSE);
}

// Build the byte effective address SP<<1 (word-pointer stack in data memory).
static RzILOpBitVector *c55_sp_byte_addr(void) {
	return MUL(UNSIGNED(24, VARG("sp")), UN(24, 2));
}

// psh / pop (documented stack model): SP is a 16-bit word pointer; the stack is
// in data memory at byte address SP<<1 and grows toward lower addresses. A push
// pre-decrements SP and stores; a pop loads and post-increments. Each operand is
// processed left to right at its natural width: an accumulator or dbl(ACx) uses
// 32 bits / 2 words (the low 32 bits of the accumulator; a popped accumulator is
// zero-extended into its guard bits), a 16-bit register or mmap(@reg) uses 16
// bits / 1 word. The pshboth/popboth dual-stack forms and the exact inter-operand
// ordering are NOT modelled here. Returns NULL for an operand shape outside this
// set.
static RzAnalysisLiftedILOp c55_lift_stack(const char *syntax, bool is_push) {
	char t[2][24];
	int n = c55_split_ops(syntax, t, 2);
	if (n < 1) {
		return NULL;
	}
	RzAnalysisLiftedILOp seq = NULL;
	for (int i = 0; i < n; i++) {
		char *tok = t[i];
		size_t L = strlen(tok);
		// Classify the operand into a base register plus a transfer "kind":
		//   0 = 16-bit register / mmap(@reg)     (1 word)
		//   1 = accumulator, 32-bit (dbl / bare) (2 words, guard preserved on pop)
		//   2 = xar, 32-bit (dbl / bare)         (2 words, written back as 23-bit)
		//   3/4/5 = accumulator .l / .h / .g sub-field (1 word)
		const char *reg = NULL;
		int kind = -1;
		ut32 w = 0;
		if (!strncmp(tok, "dbl(", 4) && L > 5 && tok[L - 1] == ')') {
			tok[L - 1] = '\0';
			reg = c55_reg(tok + 4, &w);
			if (!reg) {
				return NULL;
			}
			kind = (w == 40) ? 1 : (w == 23) ? 2
							 : -1;
		} else if (!strncmp(tok, "mmap(@", 6) && L > 7 && tok[L - 1] == ')') {
			tok[L - 1] = '\0';
			reg = c55_reg(tok + 6, &w);
			if (!reg || w != 16) {
				return NULL;
			}
			kind = 0;
		} else if (L > 3 && tok[L - 2] == '.') {
			char sub = tok[L - 1];
			tok[L - 2] = '\0';
			reg = c55_reg(tok, &w);
			if (!reg || w != 40) {
				return NULL;
			}
			kind = (sub == 'l') ? 3 : (sub == 'h') ? 4
				: (sub == 'g')                 ? 5
							       : -1;
		} else {
			reg = c55_reg(tok, &w);
			if (!reg) {
				return NULL;
			}
			kind = (w == 40) ? 1 : (w == 23) ? 2
				: (w == 16)              ? 0
							 : -1;
		}
		if (kind < 0) {
			return NULL;
		}
		int words = (kind == 1 || kind == 2) ? 2 : 1;
		RzAnalysisLiftedILOp eff;
		if (is_push) {
			RzILOpBitVector *val;
			switch (kind) {
			case 0: val = VARG(reg); break;
			case 1: val = CAST(32, IL_FALSE, VARG(reg)); break;
			case 2: val = UNSIGNED(32, VARG(reg)); break;
			case 3: val = CAST(16, IL_FALSE, VARG(reg)); break;
			case 4: val = CAST(16, IL_FALSE, SHIFTR(IL_FALSE, VARG(reg), UN(8, 16))); break;
			default: val = CAST(16, IL_FALSE, SHIFTR(IL_FALSE, VARG(reg), UN(8, 32))); break; // .g
			}
			eff = SEQ2(
				SETG("sp", SUB(VARG("sp"), UN(16, (ut64)words))),
				STOREW(c55_sp_byte_addr(), val));
		} else {
			RzILOpBitVector *load = LOADW(words == 2 ? 32 : 16, c55_sp_byte_addr());
			RzAnalysisLiftedILOp wr;
			switch (kind) {
			case 0: wr = SETG(reg, load); break;
			case 1: // restore 32 bits, preserve guard (39:32)
				wr = SETG(reg, LOGOR(LOGAND(VARG(reg), UN(40, 0xff00000000ULL)), UNSIGNED(40, load)));
				break;
			case 2: wr = SETG(reg, CAST(23, IL_FALSE, load)); break;
			case 3: wr = SETG(reg, LOGOR(LOGAND(VARG(reg), UN(40, 0xffffff0000ULL)), UNSIGNED(40, load))); break;
			case 4:
				wr = SETG(reg, LOGOR(LOGAND(VARG(reg), UN(40, 0xff0000ffffULL)), SHIFTL(IL_FALSE, UNSIGNED(40, load), UN(6, 16))));
				break;
			default: // .g : restore guard bits 39:32
				wr = SETG(reg, LOGOR(LOGAND(VARG(reg), UN(40, 0x00ffffffffULL)), SHIFTL(IL_FALSE, LOGAND(UNSIGNED(40, load), UN(40, 0xff)), UN(6, 32))));
				break;
			}
			eff = SEQ2(wr, SETG("sp", ADD(VARG("sp"), UN(16, (ut64)words))));
		}
		seq = seq ? SEQ2(seq, eff) : eff;
	}
	return seq;
}

// Successor register `delta` positions after `reg` (ac0->ac1, ar4->ar5, t0->t1),
// validated and returned in canonical form via c55_reg, or NULL if the result is
// not a bound register.
static const char *c55_reg_succ(const char *reg, int delta, ut32 *w) {
	size_t L = strlen(reg);
	size_t i = L;
	while (i > 0 && reg[i - 1] >= '0' && reg[i - 1] <= '9') {
		i--;
	}
	if (i == L || i >= 12) {
		return NULL;
	}
	int num = atoi(reg + i) + delta;
	if (num < 0 || num > 99) {
		return NULL;
	}
	char buf[16];
	memcpy(buf, reg, i);
	snprintf(buf + i, sizeof(buf) - i, "%d", num);
	return c55_reg(buf, w);
}

// swapp / swap4: exchange a register pair (swapp Rx,Ry swaps Rx<->Ry and
// Rx+1<->Ry+1) or quad (swap4 extends to +0..+3) using temp-free XOR swaps.
// Exact. Returns NULL if a successor is not a bound register or the two sides
// differ in width.
static RzAnalysisLiftedILOp c55_lift_swapp(const C55Insn *in, int count) {
	if (in->n_ops != 2 || in->ops[0].kind != C55_OP_REG || in->ops[1].kind != C55_OP_REG ||
		in->ops[0].width != in->ops[1].width) {
		return NULL;
	}
	RzAnalysisLiftedILOp seq = NULL;
	for (int k = 0; k < count; k++) {
		ut32 wa = 0, wb = 0;
		const char *a = (k == 0) ? in->ops[0].reg : c55_reg_succ(in->ops[0].reg, k, &wa);
		const char *b = (k == 0) ? in->ops[1].reg : c55_reg_succ(in->ops[1].reg, k, &wb);
		if (!a || !b) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		RzAnalysisLiftedILOp sw = SEQ3(
			SETG(a, LOGXOR(VARG(a), VARG(b))),
			SETG(b, LOGXOR(VARG(b), VARG(a))),
			SETG(a, LOGXOR(VARG(a), VARG(b))));
		seq = seq ? SEQ2(seq, sw) : sw;
	}
	return seq;
}

// satr: saturate a 40-bit accumulator to the signed 32-bit range and store it in
// the destination accumulator (documented model: 32-bit saturation, no rounding).
static RzAnalysisLiftedILOp c55_lift_satr(const C55Insn *in) {
	if (in->n_ops != 2 || in->ops[0].kind != C55_OP_REG || in->ops[0].width != 40 ||
		in->ops[1].kind != C55_OP_REG || in->ops[1].width != 40) {
		return NULL;
	}
	const char *s = in->ops[0].reg, *d = in->ops[1].reg;
	RzILOpBitVector *hi = SN(40, 0x7fffffffLL);
	RzILOpBitVector *lo = SN(40, -0x80000000LL);
	return SETG(d,
		ITE(SGT(VARG(s), SN(40, 0x7fffffffLL)), hi,
			ITE(SLT(VARG(s), SN(40, -0x80000000LL)), lo, VARG(s))));
}

// callcc / retcc-with-target: "callcc TARGET, COND" -> BRANCH(cond, jmp TARGET,
// nop). The return-linkage save is not modelled (as with the unconditional call).
static RzAnalysisLiftedILOp c55_lift_callcc(const char *syntax) {
	const char *s = strchr(syntax, ' ');
	if (!s) {
		return NULL;
	}
	while (*s == ' ') {
		s++;
	}
	const char *comma = strchr(s, ',');
	if (!comma) {
		return NULL;
	}
	char tgt[24];
	size_t tl = (size_t)(comma - s);
	while (tl > 0 && s[tl - 1] == ' ') {
		tl--;
	}
	if (tl == 0 || tl >= sizeof(tgt)) {
		return NULL;
	}
	memcpy(tgt, s, tl);
	tgt[tl] = '\0';
	ut64 target = 0;
	if (!c55_parse_imm(tgt, &target)) {
		return NULL;
	}
	const char *ce = comma + 1;
	while (*ce == ' ') {
		ce++;
	}
	RzILOpBool *cond = c55_relexpr_bool(ce, false);
	if (!cond) {
		return NULL;
	}
	return BRANCH(cond, JMP(UN(24, target & 0xffffff)), NOP());
}

// Lift a single (non-parallel) data-path instruction syntax to IL, or NULL if
// the form is not modelled. Factored out of the main entry so the "::" parallel
// splitter can lift each half independently. Control-only forms (handled from
// the analysis op fields) are not covered here.
static RzAnalysisLiftedILOp c55_lift_data(const char *syntax) {
	if (!syntax) {
		return NULL;
	}
	// "mov #K << #SHIFT, ACx" carries a shifted-immediate token the structured
	// operand parser cannot classify; match it on the syntax string first.
	if (!strncmp(syntax, "mov ", 4) && strstr(syntax, " << #")) {
		RzAnalysisLiftedILOp e = c55_lift_mov_shl(syntax);
		if (e) {
			return e;
		}
	}
	// Comparisons write a test-control flag (TC1/TC2), not a data register, and
	// their operand is a relational expression the structured model does not
	// classify, so dispatch them from the syntax ("cmpu" unsigned, "cmp" signed).
	if (!strncmp(syntax, "cmpu ", 5)) {
		RzAnalysisLiftedILOp e = c55_lift_cmp(syntax, true);
		if (e) {
			return e;
		}
	} else if (!strncmp(syntax, "cmp ", 4)) {
		RzAnalysisLiftedILOp e = c55_lift_cmp(syntax, false);
		if (e) {
			return e;
		}
	}
	C55Insn in;
	if (!c55_decode_insn(syntax, &in) || in.parallel || in.truncated) {
		return NULL;
	}
	RzAnalysisLiftedILOp e = NULL;
	if (!strcmp(in.mnem, "mov") || !strcmp(in.mnem, "copy")) {
		e = c55_lift_mov(&in);
	} else if (!strcmp(in.mnem, "and")) {
		e = c55_lift_bitop(C55_AND, &in);
		if (!e) {
			e = c55_lift_acc_alu(syntax);
		}
	} else if (!strcmp(in.mnem, "or")) {
		e = c55_lift_bitop(C55_OR, &in);
		if (!e) {
			e = c55_lift_acc_alu(syntax);
		}
	} else if (!strcmp(in.mnem, "xor")) {
		e = c55_lift_bitop(C55_XOR, &in);
		if (!e) {
			e = c55_lift_acc_alu(syntax);
		}
	} else if (!strcmp(in.mnem, "not")) {
		e = c55_lift_not(&in);
	} else if (!strcmp(in.mnem, "sfts")) {
		e = c55_lift_shift(true, &in);
	} else if (!strcmp(in.mnem, "sftl")) {
		e = c55_lift_shift(false, &in);
	} else if (!strcmp(in.mnem, "add")) {
		e = c55_lift_arith16(C55_ADD, &in);
		if (!e) {
			e = c55_lift_acarith(C55_ADD, &in);
		}
		if (!e) {
			e = c55_lift_acc_alu(syntax);
		}
		if (!e) {
			e = c55_lift_dualmem(&in, false);
		}
	} else if (!strcmp(in.mnem, "sub")) {
		e = c55_lift_arith16(C55_SUB, &in);
		if (!e) {
			e = c55_lift_acarith(C55_SUB, &in);
		}
		if (!e) {
			e = c55_lift_acc_alu(syntax);
		}
		if (!e) {
			e = c55_lift_dualmem(&in, true);
		}
	} else if (!strcmp(in.mnem, "neg")) {
		e = c55_lift_neg(&in);
	} else if (!strcmp(in.mnem, "abs")) {
		e = c55_lift_minmaxabs(&in, 0);
	} else if (!strcmp(in.mnem, "min")) {
		e = c55_lift_minmaxabs(&in, 1);
	} else if (!strcmp(in.mnem, "max")) {
		e = c55_lift_minmaxabs(&in, 2);
	} else if (!strcmp(in.mnem, "swap")) {
		e = c55_lift_swap(&in);
	} else if (!strcmp(in.mnem, "swapp")) {
		e = c55_lift_swapp(&in, 2);
	} else if (!strcmp(in.mnem, "swap4")) {
		e = c55_lift_swapp(&in, 4);
	} else if (!strcmp(in.mnem, "satr")) {
		e = c55_lift_satr(&in);
	} else if (!strcmp(in.mnem, "callcc")) {
		e = c55_lift_callcc(syntax);
	} else if ((!strcmp(in.mnem, "b") || !strcmp(in.mnem, "call")) &&
		in.n_ops == 1 && in.ops[0].kind == C55_OP_REG && in.ops[0].width == 40) {
		// Register-indirect branch / call: transfer to the low 24 bits of the
		// accumulator. The call return-linkage save is tracked separately.
		e = JMP(CAST(24, IL_FALSE, VARG(in.ops[0].reg)));
	} else if (!strcmp(in.mnem, "round")) {
		e = c55_lift_round_sq(&in, 0);
	} else if (!strcmp(in.mnem, "sqar")) {
		e = c55_lift_round_sq(&in, 1);
	} else if (!strcmp(in.mnem, "sqrr")) {
		e = c55_lift_round_sq(&in, 2);
	} else if (!strcmp(in.mnem, "bset")) {
		e = c55_lift_bitset(&in, true);
		if (!e) {
			e = c55_lift_bitset_named(syntax, true);
		}
	} else if (!strcmp(in.mnem, "bclr")) {
		e = c55_lift_bitset(&in, false);
		if (!e) {
			e = c55_lift_bitset_named(syntax, false);
		}
	} else if (!strcmp(in.mnem, "cmpand")) {
		e = c55_lift_cmpbit(syntax, false, true);
	} else if (!strcmp(in.mnem, "cmpandu")) {
		e = c55_lift_cmpbit(syntax, true, true);
	} else if (!strcmp(in.mnem, "cmpor")) {
		e = c55_lift_cmpbit(syntax, false, false);
	} else if (!strcmp(in.mnem, "cmporu")) {
		e = c55_lift_cmpbit(syntax, true, false);
	} else if (!strcmp(in.mnem, "rol")) {
		e = c55_lift_rotate(syntax, true);
	} else if (!strcmp(in.mnem, "ror")) {
		e = c55_lift_rotate(syntax, false);
	} else if (!strcmp(in.mnem, "psh")) {
		e = c55_lift_stack(syntax, true);
	} else if (!strcmp(in.mnem, "pop")) {
		e = c55_lift_stack(syntax, false);
	} else if (!strcmp(in.mnem, "amov")) {
		e = c55_lift_addr(C55_AMOV, &in);
	} else if (!strcmp(in.mnem, "aadd")) {
		e = c55_lift_addr(C55_AADD, &in);
	} else if (!strcmp(in.mnem, "asub")) {
		e = c55_lift_addr(C55_ASUB, &in);
	} else if (!strcmp(in.mnem, "amar")) {
		e = c55_lift_amar(&in);
	} else if (!strcmp(in.mnem, "rpt") || !strcmp(in.mnem, "rptcc") ||
		!strcmp(in.mnem, "rptb") || !strcmp(in.mnem, "rptblocal") ||
		!strcmp(in.mnem, "rptadd") || !strcmp(in.mnem, "rptsub")) {
		// Repeat-control: sets a hardware loop counter / active state that is not
		// part of the modelled register file and has no data-path effect, so it
		// lifts to nop (the repeated body is lifted on its own).
		e = NOP();
	} else if (!strncmp(in.mnem, "mpy", 3) || !strncmp(in.mnem, "mac", 3) ||
		!strncmp(in.mnem, "mas", 3)) {
		e = c55_lift_mul(syntax);
	}
	return e;
}

RZ_IPI RzAnalysisLiftedILOp tms320_c55x_plus_il_lift(RZ_NONNULL RzAnalysisOp *op, const char *syntax) {
	rz_return_val_if_fail(op, NULL);

	// A parallel pair is decoded as two separate ops; the second carries a
	// leading "||" marker. The architecture constrains the two slots of a pair
	// to be independent (no slot reads what the other writes in the same cycle),
	// so lifting the marked op on its own and letting the VM execute the pair in
	// sequence preserves the result. Strip the marker and lift the inner op.
	if (syntax) {
		while (syntax[0] == '|' && syntax[1] == '|') {
			syntax += 2;
			while (*syntax == ' ') {
				syntax++;
			}
		}
	}

	// xcc / xccpart: a conditional-execution qualifier. With a parallel op
	// ("xcc COND || OP") the op runs only when COND holds -- modelled as
	// BRANCH(cond, OP, nop). Standalone ("xcc COND") the qualifier gates the
	// *following* instruction, which per-instruction lifting cannot express, so
	// it lifts to nop: the gated instruction is lifted on its own and the VM
	// executes it unconditionally (a documented predication limitation).
	if (syntax && (!strncmp(syntax, "xcc ", 4) || !strncmp(syntax, "xccpart ", 8))) {
		const char *par = strstr(syntax, " || ");
		if (!par) {
			return NOP();
		}
		const char *cstart = strchr(syntax, ' ');
		while (*cstart == ' ') {
			cstart++;
		}
		char cond_s[64];
		size_t cl = (size_t)(par - cstart);
		if (cl < sizeof(cond_s)) {
			memcpy(cond_s, cstart, cl);
			cond_s[cl] = '\0';
			RzILOpBool *cond = strpbrk(cond_s, "=<>") ? c55_relexpr_bool(cond_s, false) : NULL;
			if (!cond) {
				const char *reg;
				int bit;
				if (c55_status_bit(cond_s, &reg, &bit)) {
					cond = c55_bit_bool(reg, bit);
				}
			}
			RzAnalysisLiftedILOp body = cond ? c55_lift_data(par + 4) : NULL;
			if (cond && body) {
				return BRANCH(cond, body, NOP());
			}
			rz_il_op_pure_free(cond);
			rz_il_op_effect_free(body);
		}
	}

	// "mov #K << #SHIFT, ACx" carries a shifted-immediate token the structured
	// operand parser cannot classify; match it on the syntax string first.
	if (syntax) {
		const char *par = strstr(syntax, " :: ");
		if (par) {
			// A "::" dual operation packs two independent data-path ops into one
			// instruction; lift each half on its own and sequence them. Both must
			// lift -- a half-modelled pair would drop an effect, so fall through
			// to NULL otherwise.
			char left[256], right[256];
			size_t ll = (size_t)(par - syntax);
			const char *r = par + 4;
			if (ll < sizeof(left) && strlen(r) < sizeof(right)) {
				memcpy(left, syntax, ll);
				left[ll] = '\0';
				rz_str_ncpy(right, r, sizeof(right));
				RzAnalysisLiftedILOp a = c55_lift_data(left);
				RzAnalysisLiftedILOp b = a ? c55_lift_data(right) : NULL;
				if (a && b) {
					return SEQ2(a, b);
				}
				rz_il_op_effect_free(a);
				rz_il_op_effect_free(b);
			}
		} else {
			RzAnalysisLiftedILOp e = c55_lift_data(syntax);
			if (e) {
				return e;
			}
		}
	}

	// Control-only forms via the analysis-resolved op fields.
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_NOP:
		return NOP();
	case RZ_ANALYSIS_OP_TYPE_JMP:
		return JMP(UN(24, (ut64)op->jump));
	case RZ_ANALYSIS_OP_TYPE_CJMP: {
		// bcc/bccu: branch to op->jump when the condition holds, else fall
		// through. Conditions are signed for bcc and unsigned for bccu.
		bool is_unsigned = syntax && !strncmp(syntax, "bccu", 4);
		RzILOpBool *cond = c55_lift_cond(syntax, is_unsigned);
		if (!cond) {
			return NULL; // condition form not modelled -> leave unlifted
		}
		return BRANCH(cond, JMP(UN(24, (ut64)op->jump)), NOP());
	}
	case RZ_ANALYSIS_OP_TYPE_CALL:
		// Models the control transfer to the callee. The return-address save
		// (stack / RETA) is intentionally not modelled here; rizin's call/return
		// analysis tracks linkage separately.
		return JMP(UN(24, (ut64)op->jump));
	default:
		return NULL; // not yet lifted
	}
}

#include <rz_il/rz_il_opbuilder_end.h>

/** IL configuration for C55x/C55x+: 24-bit program counter, little-endian. */
RZ_IPI RzAnalysisILConfig *tms320_c55x_plus_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(24, false, 24);
	if (!cfg) {
		return NULL;
	}
	cfg->reg_bindings = c55x_plus_il_regs;
	return cfg;
}

// ---- Plain C55x front-end ---------------------------------------------------
//
// The plain-C55x (C5500) disassembler emits the same integer-core semantics as
// C55x+ but with a different operand *syntax*: hex immediates use a trailing `h`
// (`#4Dh`) instead of a `0x` prefix, and accumulator halves are written
// `hi(acN)` / `lo(acN)` instead of `acN.h` / `acN.l`. Rather than duplicate the
// semantic lifter, the plain-C55x syntax is normalized to the C55x+ form and fed
// to the same `tms320_c55x_plus_il_lift`. Forms that do not normalize cleanly
// (register-indexed `*(arN+tM)`, shifted memory `*arN << #k`, etc.) simply fail
// to parse there and yield NULL, preserving the correct-or-NULL contract.

static bool c55x_is_hex(char c) {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

RZ_IPI void tms320_c55x_normalize_syntax(const char *in, char *out, size_t outsz) {
	size_t o = 0;
	if (outsz == 0) {
		return;
	}
	for (size_t i = 0; in && in[i] && o + 1 < outsz;) {
		char c = in[i];
		// hi(acN) / lo(acN) -> acN.h / acN.l
		if ((!strncmp(in + i, "hi(", 3) || !strncmp(in + i, "lo(", 3))) {
			char half = (in[i] == 'h') ? 'h' : 'l';
			const char *q = in + i + 3;
			const char *close = strchr(q, ')');
			// only rewrite a simple register operand (no nested parens)
			if (close && !memchr(q, '(', close - q)) {
				size_t inner = (size_t)(close - q);
				if (o + inner + 2 < outsz) {
					memcpy(out + o, q, inner);
					o += inner;
					out[o++] = '.';
					out[o++] = half;
					i = (size_t)(close - in) + 1;
					continue;
				}
			}
		}
		// #<hex>h  ->  #0x<hex>   (immediate with TI 'h' hex suffix)
		if (c == '#') {
			size_t j = i + 1;
			while (in[j] && c55x_is_hex(in[j])) {
				j++;
			}
			// require at least one hex digit, a trailing 'h', and a delimiter after
			if (j > i + 1 && in[j] == 'h' && !c55x_is_hex(in[j + 1])) {
				size_t ndig = j - (i + 1);
				if (o + ndig + 3 < outsz) {
					out[o++] = '#';
					out[o++] = '0';
					out[o++] = 'x';
					for (size_t k = i + 1; k < j; k++) {
						char d = in[k];
						out[o++] = (d >= 'A' && d <= 'F') ? (char)(d - 'A' + 'a') : d;
					}
					i = j + 1; // skip the 'h'
					continue;
				}
			}
		}
		out[o++] = c;
		i++;
	}
	out[o] = '\0';
}

/** Lift one decoded plain-C55x op to IL by normalizing its syntax to the C55x+
 * form and reusing the shared semantic lifter. A NULL syntax still lifts the
 * control-only forms (JMP/CALL/NOP) from the analysis-resolved op fields. */
RZ_IPI RzAnalysisLiftedILOp tms320_c55x_il_lift(RZ_NONNULL RzAnalysisOp *op, const char *syntax) {
	if (!syntax) {
		return tms320_c55x_plus_il_lift(op, NULL);
	}
	char norm[512];
	tms320_c55x_normalize_syntax(syntax, norm, sizeof(norm));
	return tms320_c55x_plus_il_lift(op, norm);
}
