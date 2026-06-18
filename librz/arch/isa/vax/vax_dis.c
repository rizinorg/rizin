// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file vax_dis.c
 * Clean-room VAX-11 instruction decoder and formatter.
 *
 * The opcode tables and operand templates below were assembled from the
 * publicly documented VAX architecture (the uniform "operand specifier"
 * encoding and the standard one/two byte opcode map). No GPL-licensed VAX
 * disassembler was consulted while writing this file.
 *
 * Operand templates are encoded as a flat string of (access, data-type)
 * character pairs:
 *   access:  r=read w=write m=modify a=address b=branch v=bit-field-base
 *   type:    b=byte w=word l=long q=quad o=octa f/d/g/h=floating
 */

#include <rz_types.h>
#include <rz_util.h>
#include "vax/vax.h"

typedef struct {
	const char *name;
	const char *ops;
} VaxOpInfo;

static const char *const vax_reg_names[16] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "ap", "fp", "sp", "pc"
};

/* Single-byte opcode map. NULL entries are reserved/undefined. */
static const VaxOpInfo vax_op_table[256] = {
	[0x00] = { "halt", "" },
	[0x01] = { "nop", "" },
	[0x02] = { "rei", "" },
	[0x03] = { "bpt", "" },
	[0x04] = { "ret", "" },
	[0x05] = { "rsb", "" },
	[0x06] = { "ldpctx", "" },
	[0x07] = { "svpctx", "" },
	[0x08] = { "cvtps", "rwabrwab" },
	[0x09] = { "cvtsp", "rwabrwab" },
	[0x0a] = { "index", "rlrlrlrlrlwl" },
	[0x0b] = { "crc", "abrlrwab" },
	[0x0c] = { "prober", "rbrwab" },
	[0x0d] = { "probew", "rbrwab" },
	[0x0e] = { "insque", "abab" },
	[0x0f] = { "remque", "abwl" },
	[0x10] = { "bsbb", "bb" },
	[0x11] = { "brb", "bb" },
	[0x12] = { "bneq", "bb" },
	[0x13] = { "beql", "bb" },
	[0x14] = { "bgtr", "bb" },
	[0x15] = { "bleq", "bb" },
	[0x16] = { "jsb", "ab" },
	[0x17] = { "jmp", "ab" },
	[0x18] = { "bgeq", "bb" },
	[0x19] = { "blss", "bb" },
	[0x1a] = { "bgtru", "bb" },
	[0x1b] = { "blequ", "bb" },
	[0x1c] = { "bvc", "bb" },
	[0x1d] = { "bvs", "bb" },
	[0x1e] = { "bgequ", "bb" },
	[0x1f] = { "blssu", "bb" },
	[0x20] = { "addp4", "rwabrwab" },
	[0x21] = { "addp6", "rwabrwabrwab" },
	[0x22] = { "subp4", "rwabrwab" },
	[0x23] = { "subp6", "rwabrwabrwab" },
	[0x24] = { "cvtpt", "rwababrwab" },
	[0x25] = { "mulp", "rwabrwabrwab" },
	[0x26] = { "cvttp", "rwababrwab" },
	[0x27] = { "divp", "rwabrwabrwab" },
	[0x28] = { "movc3", "rwabab" },
	[0x29] = { "cmpc3", "rwabab" },
	[0x2a] = { "scanc", "rwababrb" },
	[0x2b] = { "spanc", "rwababrb" },
	[0x2c] = { "movc5", "rwabrbrwab" },
	[0x2d] = { "cmpc5", "rwabrbrwab" },
	[0x2e] = { "movtc", "rwabrbabrwab" },
	[0x2f] = { "movtuc", "rwabrbabrwab" },
	[0x30] = { "bsbw", "bw" },
	[0x31] = { "brw", "bw" },
	[0x32] = { "cvtwl", "rwwl" },
	[0x33] = { "cvtwb", "rwwb" },
	[0x34] = { "movp", "rwabab" },
	[0x35] = { "cmpp3", "rwabab" },
	[0x36] = { "cvtpl", "rwabwl" },
	[0x37] = { "cmpp4", "rwabrwab" },
	[0x38] = { "editpc", "rwababab" },
	[0x39] = { "matchc", "rwabrwab" },
	[0x3a] = { "locc", "rbrwab" },
	[0x3b] = { "skpc", "rbrwab" },
	[0x3c] = { "movzwl", "rwwl" },
	[0x3d] = { "acbw", "rwrwmwbw" },
	[0x3e] = { "movaw", "awwl" },
	[0x3f] = { "pushaw", "aw" },
	[0x40] = { "addf2", "rfmf" },
	[0x41] = { "addf3", "rfrfwf" },
	[0x42] = { "subf2", "rfmf" },
	[0x43] = { "subf3", "rfrfwf" },
	[0x44] = { "mulf2", "rfmf" },
	[0x45] = { "mulf3", "rfrfwf" },
	[0x46] = { "divf2", "rfmf" },
	[0x47] = { "divf3", "rfrfwf" },
	[0x48] = { "cvtfb", "rfwb" },
	[0x49] = { "cvtfw", "rfww" },
	[0x4a] = { "cvtfl", "rfwl" },
	[0x4b] = { "cvtrfl", "rfwl" },
	[0x4c] = { "cvtbf", "rbwf" },
	[0x4d] = { "cvtwf", "rwwf" },
	[0x4e] = { "cvtlf", "rlwf" },
	[0x4f] = { "acbf", "rfrfmfbw" },
	[0x50] = { "movf", "rfwf" },
	[0x51] = { "cmpf", "rfrf" },
	[0x52] = { "mnegf", "rfwf" },
	[0x53] = { "tstf", "rf" },
	[0x54] = { "emodf", "rfrbrfwlwf" },
	[0x55] = { "polyf", "rfrwab" },
	[0x56] = { "cvtfd", "rfwd" },
	[0x58] = { "adawi", "rwmw" },
	[0x5c] = { "insqhi", "abaq" },
	[0x5d] = { "insqti", "abaq" },
	[0x5e] = { "remqhi", "aqwl" },
	[0x5f] = { "remqti", "aqwl" },
	[0x60] = { "addd2", "rdmd" },
	[0x61] = { "addd3", "rdrdwd" },
	[0x62] = { "subd2", "rdmd" },
	[0x63] = { "subd3", "rdrdwd" },
	[0x64] = { "muld2", "rdmd" },
	[0x65] = { "muld3", "rdrdwd" },
	[0x66] = { "divd2", "rdmd" },
	[0x67] = { "divd3", "rdrdwd" },
	[0x68] = { "cvtdb", "rdwb" },
	[0x69] = { "cvtdw", "rdww" },
	[0x6a] = { "cvtdl", "rdwl" },
	[0x6b] = { "cvtrdl", "rdwl" },
	[0x6c] = { "cvtbd", "rbwd" },
	[0x6d] = { "cvtwd", "rwwd" },
	[0x6e] = { "cvtld", "rlwd" },
	[0x6f] = { "acbd", "rdrdmdbw" },
	[0x70] = { "movd", "rdwd" },
	[0x71] = { "cmpd", "rdrd" },
	[0x72] = { "mnegd", "rdwd" },
	[0x73] = { "tstd", "rd" },
	[0x74] = { "emodd", "rdrbrdwlwd" },
	[0x75] = { "polyd", "rdrwab" },
	[0x76] = { "cvtdf", "rdwf" },
	[0x78] = { "ashl", "rbrlwl" },
	[0x79] = { "ashq", "rbrqwq" },
	[0x7a] = { "emul", "rlrlrlwq" },
	[0x7b] = { "ediv", "rlrqwlwl" },
	[0x7c] = { "clrq", "wq" },
	[0x7d] = { "movq", "rqwq" },
	[0x7e] = { "movaq", "aqwl" },
	[0x7f] = { "pushaq", "aq" },
	[0x80] = { "addb2", "rbmb" },
	[0x81] = { "addb3", "rbrbwb" },
	[0x82] = { "subb2", "rbmb" },
	[0x83] = { "subb3", "rbrbwb" },
	[0x84] = { "mulb2", "rbmb" },
	[0x85] = { "mulb3", "rbrbwb" },
	[0x86] = { "divb2", "rbmb" },
	[0x87] = { "divb3", "rbrbwb" },
	[0x88] = { "bisb2", "rbmb" },
	[0x89] = { "bisb3", "rbrbwb" },
	[0x8a] = { "bicb2", "rbmb" },
	[0x8b] = { "bicb3", "rbrbwb" },
	[0x8c] = { "xorb2", "rbmb" },
	[0x8d] = { "xorb3", "rbrbwb" },
	[0x8e] = { "mnegb", "rbwb" },
	[0x8f] = { "caseb", "rbrbrb" },
	[0x90] = { "movb", "rbwb" },
	[0x91] = { "cmpb", "rbrb" },
	[0x92] = { "mcomb", "rbwb" },
	[0x93] = { "bitb", "rbrb" },
	[0x94] = { "clrb", "wb" },
	[0x95] = { "tstb", "rb" },
	[0x96] = { "incb", "mb" },
	[0x97] = { "decb", "mb" },
	[0x98] = { "cvtbl", "rbwl" },
	[0x99] = { "cvtbw", "rbww" },
	[0x9a] = { "movzbl", "rbwl" },
	[0x9b] = { "movzbw", "rbww" },
	[0x9c] = { "rotl", "rbrlwl" },
	[0x9d] = { "acbb", "rbrbmbbw" },
	[0x9e] = { "movab", "abwl" },
	[0x9f] = { "pushab", "ab" },
	[0xa0] = { "addw2", "rwmw" },
	[0xa1] = { "addw3", "rwrwww" },
	[0xa2] = { "subw2", "rwmw" },
	[0xa3] = { "subw3", "rwrwww" },
	[0xa4] = { "mulw2", "rwmw" },
	[0xa5] = { "mulw3", "rwrwww" },
	[0xa6] = { "divw2", "rwmw" },
	[0xa7] = { "divw3", "rwrwww" },
	[0xa8] = { "bisw2", "rwmw" },
	[0xa9] = { "bisw3", "rwrwww" },
	[0xaa] = { "bicw2", "rwmw" },
	[0xab] = { "bicw3", "rwrwww" },
	[0xac] = { "xorw2", "rwmw" },
	[0xad] = { "xorw3", "rwrwww" },
	[0xae] = { "mnegw", "rwww" },
	[0xaf] = { "casew", "rwrwrw" },
	[0xb0] = { "movw", "rwww" },
	[0xb1] = { "cmpw", "rwrw" },
	[0xb2] = { "mcomw", "rwww" },
	[0xb3] = { "bitw", "rwrw" },
	[0xb4] = { "clrw", "ww" },
	[0xb5] = { "tstw", "rw" },
	[0xb6] = { "incw", "mw" },
	[0xb7] = { "decw", "mw" },
	[0xb8] = { "bispsw", "rw" },
	[0xb9] = { "bicpsw", "rw" },
	[0xba] = { "popr", "rw" },
	[0xbb] = { "pushr", "rw" },
	[0xbc] = { "chmk", "rw" },
	[0xbd] = { "chme", "rw" },
	[0xbe] = { "chms", "rw" },
	[0xbf] = { "chmu", "rw" },
	[0xc0] = { "addl2", "rlml" },
	[0xc1] = { "addl3", "rlrlwl" },
	[0xc2] = { "subl2", "rlml" },
	[0xc3] = { "subl3", "rlrlwl" },
	[0xc4] = { "mull2", "rlml" },
	[0xc5] = { "mull3", "rlrlwl" },
	[0xc6] = { "divl2", "rlml" },
	[0xc7] = { "divl3", "rlrlwl" },
	[0xc8] = { "bisl2", "rlml" },
	[0xc9] = { "bisl3", "rlrlwl" },
	[0xca] = { "bicl2", "rlml" },
	[0xcb] = { "bicl3", "rlrlwl" },
	[0xcc] = { "xorl2", "rlml" },
	[0xcd] = { "xorl3", "rlrlwl" },
	[0xce] = { "mnegl", "rlwl" },
	[0xcf] = { "casel", "rlrlrl" },
	[0xd0] = { "movl", "rlwl" },
	[0xd1] = { "cmpl", "rlrl" },
	[0xd2] = { "mcoml", "rlwl" },
	[0xd3] = { "bitl", "rlrl" },
	[0xd4] = { "clrl", "wl" },
	[0xd5] = { "tstl", "rl" },
	[0xd6] = { "incl", "ml" },
	[0xd7] = { "decl", "ml" },
	[0xd8] = { "adwc", "rlml" },
	[0xd9] = { "sbwc", "rlml" },
	[0xda] = { "mtpr", "rlrl" },
	[0xdb] = { "mfpr", "rlwl" },
	[0xdc] = { "movpsl", "wl" },
	[0xdd] = { "pushl", "rl" },
	[0xde] = { "moval", "alwl" },
	[0xdf] = { "pushal", "al" },
	[0xe0] = { "bbs", "rlvbbb" },
	[0xe1] = { "bbc", "rlvbbb" },
	[0xe2] = { "bbss", "rlvbbb" },
	[0xe3] = { "bbcs", "rlvbbb" },
	[0xe4] = { "bbsc", "rlvbbb" },
	[0xe5] = { "bbcc", "rlvbbb" },
	[0xe6] = { "bbssi", "rlvbbb" },
	[0xe7] = { "bbcci", "rlvbbb" },
	[0xe8] = { "blbs", "rlbb" },
	[0xe9] = { "blbc", "rlbb" },
	[0xea] = { "ffs", "rlrbvbwl" },
	[0xeb] = { "ffc", "rlrbvbwl" },
	[0xec] = { "cmpv", "rlrbvbrl" },
	[0xed] = { "cmpzv", "rlrbvbrl" },
	[0xee] = { "extv", "rlrbvbwl" },
	[0xef] = { "extzv", "rlrbvbwl" },
	[0xf0] = { "insv", "rlrlrbvb" },
	[0xf1] = { "acbl", "rlrlmlbw" },
	[0xf2] = { "aoblss", "rlmlbb" },
	[0xf3] = { "aobleq", "rlmlbb" },
	[0xf4] = { "sobgeq", "mlbb" },
	[0xf5] = { "sobgtr", "mlbb" },
	[0xf6] = { "cvtlb", "rlwb" },
	[0xf7] = { "cvtlw", "rlww" },
	[0xf8] = { "ashp", "rbrwabrbrwab" },
	[0xf9] = { "cvtlp", "rlrwab" },
	[0xfa] = { "callg", "abab" },
	[0xfb] = { "calls", "rlab" },
	[0xfc] = { "xfc", "" },
};

/* Two-byte opcodes escaped with the 0xFD prefix (G_ and H_ floating). */
static const VaxOpInfo vax_op_fd_table[256] = {
	[0x40] = { "addg2", "rgmg" },
	[0x41] = { "addg3", "rgrgwg" },
	[0x42] = { "subg2", "rgmg" },
	[0x43] = { "subg3", "rgrgwg" },
	[0x44] = { "mulg2", "rgmg" },
	[0x45] = { "mulg3", "rgrgwg" },
	[0x46] = { "divg2", "rgmg" },
	[0x47] = { "divg3", "rgrgwg" },
	[0x48] = { "cvtgb", "rgwb" },
	[0x49] = { "cvtgw", "rgww" },
	[0x4a] = { "cvtgl", "rgwl" },
	[0x4b] = { "cvtrgl", "rgwl" },
	[0x4c] = { "cvtbg", "rbwg" },
	[0x4d] = { "cvtwg", "rwwg" },
	[0x4e] = { "cvtlg", "rlwg" },
	[0x4f] = { "acbg", "rgrgmgbw" },
	[0x50] = { "movg", "rgwg" },
	[0x51] = { "cmpg", "rgrg" },
	[0x52] = { "mnegg", "rgwg" },
	[0x53] = { "tstg", "rg" },
	[0x54] = { "emodg", "rgrwrgwlwg" },
	[0x55] = { "polyg", "rgrwab" },
	[0x56] = { "cvtgh", "rgwh" },
	[0x60] = { "addh2", "rhmh" },
	[0x61] = { "addh3", "rhrhwh" },
	[0x62] = { "subh2", "rhmh" },
	[0x63] = { "subh3", "rhrhwh" },
	[0x64] = { "mulh2", "rhmh" },
	[0x65] = { "mulh3", "rhrhwh" },
	[0x66] = { "divh2", "rhmh" },
	[0x67] = { "divh3", "rhrhwh" },
	[0x68] = { "cvthb", "rhwb" },
	[0x69] = { "cvthw", "rhww" },
	[0x6a] = { "cvthl", "rhwl" },
	[0x6b] = { "cvtrhl", "rhwl" },
	[0x6c] = { "cvtbh", "rbwh" },
	[0x6d] = { "cvtwh", "rwwh" },
	[0x6e] = { "cvtlh", "rlwh" },
	[0x6f] = { "acbh", "rhrhmhbw" },
	[0x70] = { "movh", "rhwh" },
	[0x71] = { "cmph", "rhrh" },
	[0x72] = { "mnegh", "rhwh" },
	[0x73] = { "tsth", "rh" },
	[0x74] = { "emodh", "rhrwrhwlwh" },
	[0x75] = { "polyh", "rhrwab" },
	[0x76] = { "cvthg", "rhwg" },
	[0x7c] = { "clro", "wo" },
	[0x7d] = { "movo", "rowo" },
	[0x7e] = { "movao", "aowl" },
	[0x7f] = { "pushao", "ao" },
	[0x98] = { "cvtfh", "rfwh" },
	[0x99] = { "cvtfg", "rfwg" },
	[0xf6] = { "cvthf", "rhwf" },
	[0xf7] = { "cvthd", "rhwd" },
};

/** \brief Size in bytes of a value of the given VAX data type. */
RZ_API int rz_vax_dt_size(VaxDataType dt) {
	switch (dt) {
	case VAX_DT_B: return 1;
	case VAX_DT_W: return 2;
	case VAX_DT_L: return 4;
	case VAX_DT_Q: return 8;
	case VAX_DT_O: return 16;
	case VAX_DT_F: return 4;
	case VAX_DT_D: return 8;
	case VAX_DT_G: return 8;
	case VAX_DT_H: return 16;
	default: return 0;
	}
}

// Translate an operand-template access character (r/w/m/a/b/v) into a VaxAccess.
static VaxAccess vax_acc_from_char(char c) {
	switch (c) {
	case 'r': return VAX_AC_R;
	case 'w': return VAX_AC_W;
	case 'm': return VAX_AC_M;
	case 'a': return VAX_AC_A;
	case 'b': return VAX_AC_B;
	case 'v': return VAX_AC_V;
	default: return VAX_AC_NONE;
	}
}

// Translate an operand-template data-type character (b/w/l/q/o/f/d/g/h) into a VaxDataType.
static VaxDataType vax_dt_from_char(char c) {
	switch (c) {
	case 'b': return VAX_DT_B;
	case 'w': return VAX_DT_W;
	case 'l': return VAX_DT_L;
	case 'q': return VAX_DT_Q;
	case 'o': return VAX_DT_O;
	case 'f': return VAX_DT_F;
	case 'd': return VAX_DT_D;
	case 'g': return VAX_DT_G;
	case 'h': return VAX_DT_H;
	default: return VAX_DT_NONE;
	}
}

// Read n little-endian bytes at *pos (bounds-checked), advancing the cursor.
static bool vax_read_le(const ut8 *buf, int len, int *pos, int n, ut64 *out) {
	if (n <= 0 || *pos + n > len) {
		return false;
	}
	ut64 v = 0;
	for (int i = 0; i < n; i++) {
		v |= (ut64)buf[*pos + i] << (8 * i);
	}
	*pos += n;
	*out = v;
	return true;
}

// Sign-extend the low n bytes of v to a 64-bit signed value.
static st64 vax_sext(ut64 v, int n) {
	int bits = n * 8;
	if (bits >= 64) {
		return (st64)v;
	}
	ut64 m = (ut64)1 << (bits - 1);
	return (st64)((v ^ m) - m);
}

/**
 * \brief Decode a single operand specifier (and any index prefix) at \p pos.
 * \param o receives the decoded operand
 * \param buf instruction bytes
 * \param len number of valid bytes in \p buf
 * \param pos in/out cursor into \p buf, advanced past the operand
 * \param addr instruction address, used to resolve PC-relative targets
 * \param acc access class from the opcode template
 * \param dt data type from the opcode template (sets immediate width)
 * \return true on success, false on truncation or an invalid specifier
 */
static bool vax_decode_operand(VaxOperand *o, const ut8 *buf, int len, int *pos, ut64 addr, VaxAccess acc, VaxDataType dt) {
	o->access = acc;
	o->dt = dt;
	if (*pos >= len) {
		return false;
	}
	ut8 spec = buf[(*pos)++];
	ut8 m = spec >> 4;
	ut8 r = spec & 0xf;
	if (m == 4) {
		/* index prefix [Rx]; the base specifier follows */
		o->indexed = true;
		o->index_reg = r;
		if (*pos >= len) {
			return false;
		}
		spec = buf[(*pos)++];
		m = spec >> 4;
		r = spec & 0xf;
	}
	o->reg = r;
	ut64 v = 0;
	switch (m) {
	case 0:
	case 1:
	case 2:
	case 3:
		o->mode = VAX_AM_LITERAL;
		o->disp = spec & 0x3f;
		o->reg = 0;
		break;
	case 5:
		o->mode = VAX_AM_REG;
		break;
	case 6:
		o->mode = VAX_AM_REGDEF;
		break;
	case 7:
		o->mode = VAX_AM_AUTODEC;
		break;
	case 8:
		if (r == VAX_REG_PC) {
			int sz = rz_vax_dt_size(dt);
			if (sz < 1) {
				sz = 4;
			}
			if (!vax_read_le(buf, len, pos, sz, &v)) {
				return false;
			}
			o->mode = VAX_AM_IMMEDIATE;
			o->imm = v;
			o->disp = vax_sext(v, sz);
		} else {
			o->mode = VAX_AM_AUTOINC;
		}
		break;
	case 9:
		if (r == VAX_REG_PC) {
			if (!vax_read_le(buf, len, pos, 4, &v)) {
				return false;
			}
			o->mode = VAX_AM_ABSOLUTE;
			o->target = v;
			o->has_target = true;
		} else {
			o->mode = VAX_AM_AUTOINCDEF;
		}
		break;
	case 0xa:
	case 0xb:
		if (!vax_read_le(buf, len, pos, 1, &v)) {
			return false;
		}
		o->disp = vax_sext(v, 1);
		if (r == VAX_REG_PC) {
			o->mode = (m == 0xa) ? VAX_AM_BYTEREL : VAX_AM_BYTERELDEF;
			o->target = addr + (ut64)*pos + o->disp;
			o->has_target = true;
		} else {
			o->mode = (m == 0xa) ? VAX_AM_BYTEDISP : VAX_AM_BYTEDISPDEF;
		}
		break;
	case 0xc:
	case 0xd:
		if (!vax_read_le(buf, len, pos, 2, &v)) {
			return false;
		}
		o->disp = vax_sext(v, 2);
		if (r == VAX_REG_PC) {
			o->mode = (m == 0xc) ? VAX_AM_WORDREL : VAX_AM_WORDRELDEF;
			o->target = addr + (ut64)*pos + o->disp;
			o->has_target = true;
		} else {
			o->mode = (m == 0xc) ? VAX_AM_WORDDISP : VAX_AM_WORDDISPDEF;
		}
		break;
	case 0xe:
	case 0xf:
		if (!vax_read_le(buf, len, pos, 4, &v)) {
			return false;
		}
		o->disp = vax_sext(v, 4);
		if (r == VAX_REG_PC) {
			o->mode = (m == 0xe) ? VAX_AM_LONGREL : VAX_AM_LONGRELDEF;
			o->target = addr + (ut64)*pos + o->disp;
			o->has_target = true;
		} else {
			o->mode = (m == 0xe) ? VAX_AM_LONGDISP : VAX_AM_LONGDISPDEF;
		}
		break;
	default:
		o->mode = VAX_AM_INVALID;
		return false;
	}
	return true;
}

/**
 * \brief Decode a single VAX instruction.
 * \param inst output, zero-initialized by the function
 * \param buf instruction bytes
 * \param len number of valid bytes in \p buf
 * \param addr virtual address of the instruction (for PC-relative resolution)
 * \return the instruction length in bytes, or a value <= 0 on failure
 *
 * Handles the 0xFD escape page, immediate sizing, index prefixes, PC-relative
 * target resolution and consumption of the inline CASE displacement table.
 */
RZ_API int rz_vax_decode(RZ_NONNULL VaxInst *inst, RZ_NONNULL const ut8 *buf, int len, ut64 addr) {
	rz_return_val_if_fail(inst && buf, -1);
	memset(inst, 0, sizeof(*inst));
	if (len < 1) {
		return -1;
	}
	int pos = 0;
	ut8 b0 = buf[pos++];
	const VaxOpInfo *info;
	if (b0 == 0xfd) {
		if (pos >= len) {
			inst->size = pos;
			return pos;
		}
		ut8 b1 = buf[pos++];
		inst->opcode = 0xfd00 | b1;
		info = &vax_op_fd_table[b1];
	} else {
		inst->opcode = b0;
		info = &vax_op_table[b0];
	}
	if (!info->name) {
		inst->name = NULL;
		inst->size = pos;
		return pos;
	}
	inst->name = info->name;
	const char *p = info->ops;
	int nop = 0;
	while (p && p[0] && p[1] && nop < VAX_MAX_OPS) {
		VaxAccess acc = vax_acc_from_char(p[0]);
		VaxDataType dt = vax_dt_from_char(p[1]);
		p += 2;
		VaxOperand *o = &inst->ops[nop];
		if (acc == VAX_AC_B) {
			/* implicit branch displacement (not an operand specifier) */
			int sz = (dt == VAX_DT_W) ? 2 : 1;
			ut64 v = 0;
			if (!vax_read_le(buf, len, &pos, sz, &v)) {
				break;
			}
			o->access = acc;
			o->dt = dt;
			o->mode = VAX_AM_BRANCH;
			o->disp = vax_sext(v, sz);
			o->target = addr + (ut64)pos + o->disp;
			o->has_target = true;
			nop++;
			continue;
		}
		if (!vax_decode_operand(o, buf, len, &pos, addr, acc, dt)) {
			break;
		}
		nop++;
	}
	inst->n_ops = nop;
	/* CASEB/CASEW/CASEL embed a table of (limit + 1) word displacements. */
	if ((b0 == 0x8f || b0 == 0xaf || b0 == 0xcf) && nop == 3) {
		st64 limit = -1;
		const VaxOperand *lim = &inst->ops[2];
		if (lim->mode == VAX_AM_LITERAL) {
			limit = lim->disp;
		} else if (lim->mode == VAX_AM_IMMEDIATE) {
			limit = (st64)lim->imm;
		}
		if (limit >= 0 && limit < 512) {
			for (st64 i = 0; i <= limit; i++) {
				ut64 v = 0;
				if (!vax_read_le(buf, len, &pos, 2, &v)) {
					break;
				}
			}
		}
	}
	inst->size = pos;
	return pos;
}

// Append a signed displacement to sb in 0x-prefixed hex.
static void vax_format_disp(RzStrBuf *sb, st64 disp) {
	if (disp < 0) {
		rz_strbuf_appendf(sb, "-0x%" PFMT64x, (ut64)(-disp));
	} else {
		rz_strbuf_appendf(sb, "0x%" PFMT64x, (ut64)disp);
	}
}

// Append a single decoded operand to sb in conventional VAX syntax.
static void vax_format_operand(RzStrBuf *sb, const VaxOperand *o) {
	const char *reg = vax_reg_names[o->reg & 0xf];
	switch (o->mode) {
	case VAX_AM_LITERAL:
		rz_strbuf_appendf(sb, "$0x%" PFMT64x, (ut64)(o->disp & 0x3f));
		break;
	case VAX_AM_IMMEDIATE:
		rz_strbuf_appendf(sb, "$0x%" PFMT64x, o->imm);
		break;
	case VAX_AM_ABSOLUTE:
		rz_strbuf_appendf(sb, "*0x%" PFMT64x, o->target);
		break;
	case VAX_AM_REG:
		rz_strbuf_append(sb, reg);
		break;
	case VAX_AM_REGDEF:
		rz_strbuf_appendf(sb, "(%s)", reg);
		break;
	case VAX_AM_AUTODEC:
		rz_strbuf_appendf(sb, "-(%s)", reg);
		break;
	case VAX_AM_AUTOINC:
		rz_strbuf_appendf(sb, "(%s)+", reg);
		break;
	case VAX_AM_AUTOINCDEF:
		rz_strbuf_appendf(sb, "*(%s)+", reg);
		break;
	case VAX_AM_BYTEDISP:
	case VAX_AM_WORDDISP:
	case VAX_AM_LONGDISP:
		vax_format_disp(sb, o->disp);
		rz_strbuf_appendf(sb, "(%s)", reg);
		break;
	case VAX_AM_BYTEDISPDEF:
	case VAX_AM_WORDDISPDEF:
	case VAX_AM_LONGDISPDEF:
		rz_strbuf_append(sb, "*");
		vax_format_disp(sb, o->disp);
		rz_strbuf_appendf(sb, "(%s)", reg);
		break;
	case VAX_AM_BYTEREL:
	case VAX_AM_WORDREL:
	case VAX_AM_LONGREL:
	case VAX_AM_BRANCH:
		rz_strbuf_appendf(sb, "0x%" PFMT64x, o->target);
		break;
	case VAX_AM_BYTERELDEF:
	case VAX_AM_WORDRELDEF:
	case VAX_AM_LONGRELDEF:
		rz_strbuf_appendf(sb, "*0x%" PFMT64x, o->target);
		break;
	default:
		rz_strbuf_append(sb, "?");
		break;
	}
	if (o->indexed) {
		rz_strbuf_appendf(sb, "[%s]", vax_reg_names[o->index_reg & 0xf]);
	}
}

/** \brief Render a decoded instruction into \p sb (set to "invalid" for a NULL mnemonic). */
RZ_API void rz_vax_format(RZ_NONNULL const VaxInst *inst, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(inst && sb);
	if (!inst->name) {
		rz_strbuf_set(sb, "invalid");
		return;
	}
	rz_strbuf_set(sb, inst->name);
	for (int i = 0; i < inst->n_ops; i++) {
		rz_strbuf_append(sb, i == 0 ? " " : ",");
		vax_format_operand(sb, &inst->ops[i]);
	}
}

/** \brief Canonical lowercase name of a VAX general register (low 4 bits of \p reg). */
RZ_API const char *rz_vax_reg_name(int reg) {
	return vax_reg_names[reg & 0xf];
}
