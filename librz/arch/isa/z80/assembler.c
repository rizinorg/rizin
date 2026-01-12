// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 byteninjaa0 <sksohail.swaraj@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_types.h>
#include <rz_asm.h>
#include <string.h>
#include <rz_endian.h>

static void str_op(char *c) {
	if (IS_UPPER(c[0])) {
		c[0] += 0x20;
	}
}

static int z80_reg_idx(char r) {
	switch (r) {
	case 'b': return 0;
	case 'c': return 1;
	case 'd': return 2;
	case 'e': return 3;
	case 'h': return 4;
	case 'l': return 5;
	case ' ': return 6;
	case 'a': return 7;
	default: return -1;
	}
}

// Parse CB-prefixed rotate/shift instructions.
// Supports registers, [hl], and [ix+d]/[iy+d] memory forms.
static int z80_parse_cb1(ut8 *buf, const int minlen, char *buf_asm, ut8 base) {
	int i;
	if ((i = strlen(buf_asm)) < minlen) {
		return 0;
	}
	// It will check whether: "rlc a, [hl]" or "rlc [hl], a"
	char *left = strtok(buf_asm + (minlen - 1), ",");
	char *right = strtok(NULL, ",");
	if (right) {
		rz_str_trim(right);
	}
	rz_str_replace_in(buf_asm, strlen(buf_asm), "[ ", "[", true);
	rz_str_replace_in(buf_asm, strlen(buf_asm), " ]", "]", true);
	if (!strcmp(left, "[hl]") || (right && !strcmp(right, "[hl]"))) {
		buf[0] = 0xcb;
		buf[1] = base | 6;
		return 2;
	}
	// Mixed memory and register rlc [ix+0x00], a or rlc a, [ix+0x00]
	if (left && right) {
		bool left_is_mem = strstr(left, "[ix+") || strstr(left, "[iy+");
		bool right_is_mem = left_is_mem ? false : true;
		const char *mem = left_is_mem ? left : (right_is_mem ? right : NULL);
		const char *reg = left_is_mem ? right : left;

		if (mem && reg) {
			const char *plus = strchr(mem, '+');
			if (!plus)
				return 0;
			int disp = rz_num_get(NULL, plus + 1);
			bool is_ix = strstr(mem, "[ix+") != NULL;
			int reg_idx = z80_reg_idx(reg[0]);
			if (reg_idx == -1)
				return 0;
			buf[0] = is_ix ? 0xdd : 0xfd;
			buf[1] = 0xcb;
			buf[2] = (ut8)(disp & 0xff);
			buf[3] = base | reg_idx;
			return 4;
		}
	}
	int idx = z80_reg_idx(buf_asm[minlen - 1]);
	if (idx != -1) {
		buf[0] = 0xCB;
		buf[1] = base | idx;
		return 2;
	}
	// Only memory: rlc [ix+00] or [iy+00]
	if (strstr(left, "[ix+") || strstr(left, "[iy+")) {
		const char *plus = strchr(left, '+');
		if (!plus)
			return 0;
		int disp = rz_num_get(NULL, plus + 1);
		bool is_ix = strstr(left, "[ix+") != NULL;
		buf[0] = is_ix ? 0xdd : 0xfd;
		buf[1] = 0xcb;
		buf[2] = (ut8)(disp & 0xff);
		buf[3] = base | 6;
		return 4;
	}
	return 0;
}

// Parse CB-prefixed bit/set/res instructions.
// Handles bit number with register, [hl], or [ix+d]/[iy+d].
static int z80_parse_cb2(ut8 *buf, const int minlen, char *buf_asm, ut8 base) {
	int i;
	ut64 num;
	char *ptr, *reg;
	if ((i = strlen(buf_asm)) < minlen) {
		return 0;
	}
	rz_str_replace_in(buf_asm, (ut32)i, "[ ", "[", true);
	rz_str_replace_in(buf_asm, (ut32)i, " ]", "]", true);
	ptr = buf_asm + minlen - 1;
	while (*ptr == ' ')
		ptr++;
	reg = strchr(ptr, ',');
	if (!reg) {
		return 0;
	}
	reg[0] = '\0';
	num = rz_num_get(NULL, ptr);
	reg[0] = ',';
	reg++;
	while (*reg == ' ')
		reg++;
	if (*reg == '\0' || num > 7) {
		return 0;
	}
	if (!strncmp(reg, "[hl]", 4)) {
		buf[0] = 0xcb;
		buf[1] = base + (ut8)(num * 8) + 6;
		return 2;
	}
	if (!strncmp(reg, "[ix+", 4) || !strncmp(reg, "[iy+", 4)) {
		bool is_ix = (reg[1] == 'i' && reg[2] == 'x');
		const char *plus = strchr(reg, '+');
		if (!plus) {
			return 0;
		}
		int disp = rz_num_get(NULL, plus + 1);
		buf[0] = is_ix ? 0xdd : 0xfd;
		buf[1] = 0xcb;
		buf[2] = (ut8)(disp & 0xff);
		buf[3] = base + (ut8)(num * 8) + 6;
		return 4;
	}
	i = z80_reg_idx(*reg);
	if (i != -1) {
		buf[0] = 0xcb;
		buf[1] = base + (ut8)(num * 8) + (ut8)i;
		return 2;
	}
	return 0;
}

static int z80_parse_arith1(ut8 *buf, const int minlen, char *buf_asm, ut8 base, ut8 alt) {
	ut64 num;
	char *src;
	int i;
	buf[0] = base;
	src = strchr(buf_asm, ',');
	if (src) {
		src++; // skip past comma to get second operand
	} else {
		// No comma? Must be a one-operand form like "add [ix+0]"
		// So we assume implicit: add a, [ix+0]
		src = buf_asm + minlen - 1;
	}
	while (*src == ' ')
		src++;
	rz_str_replace_in(src, (ut32)strlen(src), "[ ", "[", true);
	rz_str_replace_in(src, (ut32)strlen(src), " ]", "]", true);
	if (!strncmp(src, "[i", 2)) {
		buf[0] = (src[2] == 'x') ? 0xdd : 0xfd;
		buf[1] = base + 6;
		num = rz_num_get(NULL, src + 4);
		buf[2] = (ut8)(num & 0xff);
		return 3;
	}
	if (!strncmp(src, "[hl]", 4)) {
		buf[0] |= 6;
		return 1;
	}
	if (!strncmp(src, "ixh", 3)) {
		buf[0] = 0xdd;
		buf[1] = base | 4;
		return 2;
	}
	if (!strncmp(src, "ixl", 3)) {
		buf[0] = 0xdd;
		buf[1] = base | 5;
		return 2;
	}
	if (!strncmp(src, "iyh", 3)) {
		buf[0] = 0xfd;
		buf[1] = base | 4;
		return 2;
	}
	if (!strncmp(src, "iyl", 3)) {
		buf[0] = 0xfd;
		buf[1] = base | 5;
		return 2;
	}
	i = z80_reg_idx(*src);
	if (i != -1) {
		buf[0] |= (ut8)i;
		return 1;
	}
	buf[0] = alt;
	num = rz_num_get(NULL, src);
	buf[1] = (ut8)(num & 0xff);
	return 2;
}

// Parse arithmetic instructions with one operand (add, sub, and, or, xor, cp).
// Supports registers, immediate values, and memory forms like [hl] and [ix+d]/[iy+d].
static int z80_parse_in_out(ut8 *buf, char *buf_asm, bool is_in) {
	rz_str_do_until_token(str_op, buf_asm, '\0');
	char *left = strtok(buf_asm + 3, ",");
	char *right = strtok(NULL, ",");
	if (!left)
		return 0;
	rz_str_trim(left);
	if (right)
		rz_str_trim(right);
	if (!right && !strcmp(left, "[c]")) {
		buf[0] = is_in ? 0xed : 0xd3;
		buf[1] = is_in ? 0x70 : 0x00; // fixed opcode for "in [c], 0"
		return 2;
	}
	bool left_is_mem = (left && !strncmp(left, "[c]", 3));
	bool right_is_mem = (right && !strncmp(right, "[c]", 3));
	// in r, [c]  or out [c], r
	if (left_is_mem || right_is_mem) {
		const char *reg = left_is_mem ? right : left;
		if (!reg)
			return 0;
		if (is_in) {
			// in reg, [c]
			if (reg[0] >= '0' && reg[0] <= '9') { // if reg is a number (like 0, 5, etc.)
				buf[0] = 0xed;
				buf[1] = 0x70; // fixed opcode for "out [c], 0"
				return 2;
			} else {
				int reg_idx = z80_reg_idx(reg[0]);
				if (reg_idx == -1 || reg_idx == 6)
					return 0;
				buf[0] = 0xed;
				buf[1] = 0x40 | (reg_idx << 3);
				return 2;
			}
		} else {
			// out [c], reg  or out reg, [c]
			if (reg[0] >= '0' && reg[0] <= '9') { // if reg is a number (like 0, 5, etc.)
				buf[0] = 0xed;
				buf[1] = 0x71; // fixed opcode for "out [c], 0"
				return 2;
			} else {
				int reg_idx = z80_reg_idx(reg[0]);
				if (reg_idx == -1 || reg_idx == 6)
					return 0;
				buf[0] = 0xed;
				buf[1] = 0x41 | (reg_idx << 3);
				return 2;
			}
		}
	}
	// in a, [nn]
	if (is_in && right && !strncmp(left, "a", 1) && right[0] == '[') {
		ut64 port = rz_num_get(NULL, right + 1);
		buf[0] = 0xdb;
		buf[1] = (ut8)(port & 0xff);
		return 2;
	}
	// out [nn], a
	if (!is_in && right && right[0] == 'a' && left[0] == '[') {
		ut64 port = rz_num_get(NULL, left + 1);
		buf[0] = 0xd3;
		buf[1] = (ut8)(port & 0xff);
		return 2;
	}
	return 0;
}

int z80Asm(RzAsm *a, RzAsmOp *op, const char *buf) {
	int mn_len, j, len = 1;
	ut32 mn = 0;
	ut64 num;
	size_t i;
	if (!a || !op || !buf) {
		return 0;
	}
	ut8 opbuf[4] = { 0 };
	rz_strbuf_set(&op->buf_asm, buf);
	char *buf_asm = rz_strbuf_get(&op->buf_asm);
	ut32 buf_len = strlen(buf);
	while (strstr(buf_asm, "  ")) {
		rz_str_replace_in(buf_asm, buf_len, "  ", " ", true);
	}
	rz_str_replace_in(buf_asm, buf_len, " ,", ",", true);
	mn_len = rz_str_do_until_token(str_op, buf_asm, ' ');
	if (mn_len < 2 || mn_len > 4) {
		return 0;
	}
	switch (mn_len) {
	case 2:
		mn = rz_read_be16(buf_asm);
		break;
	case 3:
		mn = rz_read_be24(buf_asm);
		break;
	case 4:
		mn = rz_read_be32(buf_asm);
		break;
	default:
		return 0;
	}
	switch (mn) {
	case 0x616463: // adc
		rz_str_replace_in(buf_asm, strlen(buf_asm), ", ", ",", true);
		if (strlen(buf_asm) < 5)
			return op->size = 0;
		if (!strcmp(buf_asm + 4, "hl,bc")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x4a;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "hl,de")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x5a;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "hl,hl")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x6a;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "hl,sp")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x7a;
			len = 2;
		} else {
			len = z80_parse_arith1(opbuf, 5, buf_asm, 0x88, 0xce);
		}
		break;
	case 0x616464: // add
		rz_str_replace_in(buf_asm, strlen(buf_asm), ", ", ",", true);
		if (strlen(buf_asm) < 5)
			return len = 0;
		if (buf_asm[4] == 's' && buf_asm[5] == 'p' && buf_asm[6] == ',' && buf_asm[7] != '\0') {
			opbuf[0] = 0xe8;
			num = rz_num_get(NULL, buf_asm + 7);
			opbuf[1] = (ut8)(num & 0xff);
			len = 2;
		} else if (!strcmp(buf_asm + 4, "hl,bc")) {
			opbuf[0] = 0x09;
		} else if (!strcmp(buf_asm + 4, "hl,de")) {
			opbuf[0] = 0x19;
		} else if (!strcmp(buf_asm + 4, "hl,hl")) {
			opbuf[0] = 0x29;
		} else if (!strcmp(buf_asm + 4, "hl,sp")) {
			opbuf[0] = 0x39;
		} else if (!strcmp(buf_asm + 4, "ix,bc")) {
			opbuf[0] = 0xdd;
			opbuf[1] = 0x09;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "ix,de")) {
			opbuf[0] = 0xdd;
			opbuf[1] = 0x19;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "ix,ix")) {
			opbuf[0] = 0xdd;
			opbuf[1] = 0x29;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "ix,sp")) {
			opbuf[0] = 0xdd;
			opbuf[1] = 0x39;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "iy,bc")) {
			opbuf[0] = 0xfd;
			opbuf[1] = 0x09;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "iy,de")) {
			opbuf[0] = 0xfd;
			opbuf[1] = 0x19;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "iy,iy")) {
			opbuf[0] = 0xfd;
			opbuf[1] = 0x29;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "iy,sp")) {
			opbuf[0] = 0xfd;
			opbuf[1] = 0x39;
			len = 2;
		} else {
			len = z80_parse_arith1(opbuf, 5, buf_asm, 0x80, 0xc6);
		}
		break;
	case 0x616e64: // and
		len = z80_parse_arith1(opbuf, 5, buf_asm, 0xa0, 0xe6);
		break;
	case 0x626974: // bit
		len = z80_parse_cb2(opbuf, 5, buf_asm, 0x40);
		break;
	case 0x63616c6c: // call
		if (strlen(buf_asm) < 6) {
			return len = 0;
		}
		char *p = strchr(buf_asm, ',');
		if (!p) {
			num = rz_num_get(NULL, buf_asm + 4);
			len = 3;
			opbuf[0] = 0xcd;
			opbuf[1] = (ut8)(num & 0xff);
			opbuf[2] = (ut8)((num >> 8) & 0xff);
		} else {
			char cond[3] = { 0 };
			char *cond_start = p;
			while (cond_start > buf_asm && *(cond_start - 1) != ' ') {
				cond_start--;
			}
			int cond_len = (int)(p - cond_start);
			if (cond_len <= 0 || cond_len > 2) {
				return op->size = 0;
			}
			strncpy(cond, cond_start, cond_len);
			cond[cond_len] = '\0';
			str_op(cond);
			const struct {
				const char *cond;
				ut8 opcode;
			} conds[] = {
				{ "nz", 0xc4 }, { "z", 0xcc }, { "nc", 0xd4 }, { "c", 0xdc },
				{ "po", 0xe4 }, { "pe", 0xec }, { "p", 0xf4 }, { "m", 0xfc }
			};
			bool found = false;
			for (size_t k = 0; k < sizeof(conds) / sizeof(conds[0]); k++) {
				if (!strcmp(cond, conds[k].cond)) {
					opbuf[0] = conds[k].opcode;
					found = true;
					break;
				}
			}
			if (!found) {
				return op->size = 0;
			}
			rz_str_replace_in(p, strlen(p), ", ", ",", true);
			if (!*p || !p[1]) {
				return op->size = 0;
			}
			num = rz_num_get(NULL, p + 1);
			opbuf[1] = (ut8)(num & 0xff);
			opbuf[2] = (ut8)((num >> 8) & 0xff);
			len = 3;
		}
		break;
	case 0x636366: // ccf
		opbuf[0] = 0x3f;
		break;
	case 0x6370: // cp
		len = z80_parse_arith1(opbuf, 4, buf_asm, 0xb8, 0xfe);
		break;
	case 0x637064: // cpd
		opbuf[0] = 0xed;
		opbuf[1] = 0xa9;
		len = 2;
		break;
	case 0x63706472: // cpdr
		opbuf[0] = 0xed;
		opbuf[1] = 0xb9;
		len = 2;
		break;
	case 0x637069: // cpi
		opbuf[0] = 0xed;
		opbuf[1] = 0xa1;
		len = 2;
		break;
	case 0x63706972: // cpir
		opbuf[0] = 0xed;
		opbuf[1] = 0xb1;
		len = 2;
		break;
	case 0x63706c: // cpl
		opbuf[0] = 0x2f;
		break;
	case 0x646161: // daa
		opbuf[0] = 0x27;
		break;
	case 0x646563: // dec
		if ((i = strlen(buf_asm)) < 5) {
			return op->size = 0;
		}
		rz_str_replace_in(buf_asm, (ut32)i, "[ ", "[", true);
		rz_str_replace_in(buf_asm, (ut32)i, " ]", "]", true);
		rz_str_do_until_token(str_op, buf_asm + 4, '\0');
		if (buf_asm[4] == 'b') {
			opbuf[0] = (buf_asm[5] == 'c') ? 0x0b : 5;
		} else if (buf_asm[4] == 'c') {
			opbuf[0] = 0x0d;
		} else if (buf_asm[4] == 'd') {
			opbuf[0] = (buf_asm[5] == 'e') ? 0x1b : 0x15;
		} else if (buf_asm[4] == 'e') {
			opbuf[0] = 0x1d;
		} else if (buf_asm[4] == 'h') {
			opbuf[0] = (buf_asm[5] == 'l') ? 0x2b : 0x25;
		} else if (buf_asm[4] == 'l') {
			opbuf[0] = 0x2d;
		} else if (buf_asm[4] == 'a') {
			opbuf[0] = 0x3d;
		} else if (buf_asm[4] == 's' && buf_asm[5] == 'p') {
			opbuf[0] = 0x3b;
		} else if (!strncmp(buf_asm + 4, "[hl]", 4)) {
			opbuf[0] = 0x35;
		} else if (buf_asm[4] == 'i') {
			if (buf_asm[5] == 'x' || buf_asm[5] == 'y') {
				opbuf[0] = (buf_asm[5] == 'x') ? 0xdd : 0xfd;
				if (buf_asm[6] == 'h') {
					opbuf[1] = 0x25;
				} else if (buf_asm[6] == 'l') {
					opbuf[1] = 0x2d;
				} else {
					opbuf[1] = 0x2b;
				}
				len = 2;
			}
		} else if (!strncmp(buf_asm + 4, "[i", 2)) {
			if (buf_asm[6] == 'x' || buf_asm[6] == 'y') {
				opbuf[0] = (buf_asm[6] == 'x') ? 0xdd : 0xfd;
				opbuf[1] = 0x35;
				num = rz_num_get(NULL, &buf_asm[8]);
				opbuf[2] = (ut8)(num & 0xff);
				len = 3;
			} else {
				op->size = 0;
			}
		} else {
			op->size = 0;
		}
		break;
	case 0x6469: // di
		opbuf[0] = 0xf3;
		break;
	case 0x646a6e7a: // djnz
		if (strlen(buf_asm) < 6) {
			return op->size = 0;
		}
		num = rz_num_get(NULL, buf_asm + 5);
		opbuf[0] = 0x10;
		opbuf[1] = (ut8)(num & 0xff);
		len = 2;
		break;
	case 0x6569: // ei
		opbuf[0] = 0xfb;
		break;
	case 0x6578: // ex
		rz_str_replace_in(buf_asm, strlen(buf_asm), ", ", ",", true);
		if (!strcmp(buf_asm + 3, "[sp],hl")) {
			opbuf[0] = 0xe3;
			len = 1;
		} else if (!strcmp(buf_asm + 3, "[sp],ix")) {
			opbuf[0] = 0xdd;
			opbuf[1] = 0xe3;
			len = 2;
		} else if (!strcmp(buf_asm + 3, "[sp],iy")) {
			opbuf[0] = 0xfd;
			opbuf[1] = 0xe3;
			len = 2;
		} else if (!strcmp(buf_asm + 3, "af,af")) {
			opbuf[0] = 0x08;
			len = 1;
		} else if (!strcmp(buf_asm + 3, "de,hl")) {
			opbuf[0] = 0xeb;
			len = 1;
		} else {
			op->size = 0;
		}
		break;
	case 0x657878: // exx
		opbuf[0] = 0xd9;
		len = 1;
		break;
	case 0x68616c74: // halt
		opbuf[0] = 0x76;
		break;
	case 0x696d: // im
		if (buf_asm[2] == ' ') {
			switch (buf_asm[3]) {
			case '0':
				opbuf[0] = 0xed;
				opbuf[1] = 0x46;
				len = 2;
				break;
			case '1':
				opbuf[0] = 0xed;
				opbuf[1] = 0x56;
				len = 2;
				break;
			case '2':
				opbuf[0] = 0xed;
				opbuf[1] = 0x5e;
				len = 2;
				break;
			default:
				op->size = 0;
				break;
			}
		} else {
			len = 0;
		}
		break;
	case 0x696e: // in
		len = z80_parse_in_out(opbuf, buf_asm, true);
		break;
	case 0x696e63: // inc
		if ((i = strlen(buf_asm)) < 5) {
			return op->size = 0;
		}
		rz_str_replace_in(buf_asm, (ut32)i, "[ ", "[", true);
		rz_str_replace_in(buf_asm, (ut32)i, " ]", "]", true);
		rz_str_do_until_token(str_op, buf_asm + 4, '\0');
		if (buf_asm[4] == 'b') {
			opbuf[0] = (buf_asm[5] == 'c') ? 3 : 4;
		} else if (buf_asm[4] == 'c') {
			opbuf[0] = 0x0c;
		} else if (buf_asm[4] == 'd') {
			opbuf[0] = (buf_asm[5] == 'e') ? 0x13 : 0x14;
		} else if (buf_asm[4] == 'e') {
			opbuf[0] = 0x1c;
		} else if (buf_asm[4] == 'h') {
			opbuf[0] = (buf_asm[5] == 'l') ? 0x23 : 0x24;
		} else if (buf_asm[4] == 'l') {
			opbuf[0] = 0x2c;
		} else if (buf_asm[4] == 'a') {
			opbuf[0] = 0x3c;
		} else if (buf_asm[4] == 's' && buf_asm[5] == 'p') {
			opbuf[0] = 0x33;
		} else if (!strncmp(buf_asm + 4, "[hl]", 4)) {
			opbuf[0] = 0x34;
		} else if (buf_asm[4] == 'i') {
			if (buf_asm[5] == 'x' || buf_asm[5] == 'y') {
				opbuf[0] = (buf_asm[5] == 'x') ? 0xdd : 0xfd;

				if (buf_asm[6] == 'h') {
					opbuf[1] = 0x24;
				} else if (buf_asm[6] == 'l') {
					opbuf[1] = 0x2c;
				} else {
					opbuf[1] = 0x23;
				}
				len = 2;
			}
		} else if (!strncmp(buf_asm + 4, "[i", 2)) {
			if (buf_asm[6] == 'x' || buf_asm[6] == 'y') {
				opbuf[0] = (buf_asm[6] == 'x') ? 0xdd : 0xfd;
				opbuf[1] = 0x34;
				num = rz_num_get(NULL, &buf_asm[8]);
				opbuf[2] = (ut8)(num & 0xff);
				len = 3;
			} else {
				len = 0;
			}
		} else {
			len = 0;
		}
		break;
	case 0x696e64: // ind
		opbuf[0] = 0xed;
		opbuf[1] = 0xaa;
		len = 2;
		break;
	case 0x696e6472: // indr
		opbuf[0] = 0xed;
		opbuf[1] = 0xba;
		len = 2;
		break;
	case 0x696e69: // ini
		opbuf[0] = 0xed;
		opbuf[1] = 0xa2;
		len = 2;
		break;
	case 0x696e6972: // inir
		opbuf[0] = 0xed;
		opbuf[1] = 0xb2;
		len = 2;
		break;
	case 0x6a70: // jp
		if (strlen(buf_asm) < 4)
			return op->size = 0;
		char *comma = strchr(buf_asm, ',');
		if (!comma) {
			if (!strncmp(buf_asm + 3, "[hl]", 4)) {
				opbuf[0] = 0xe9;
				len = 1;
			} else if (!strncmp(buf_asm + 3, "[ix]", 4)) {
				opbuf[0] = 0xdd;
				opbuf[1] = 0xe9;
				len = 2;
			} else if (!strncmp(buf_asm + 3, "[iy]", 4)) {
				opbuf[0] = 0xfd;
				opbuf[1] = 0xe9;
				len = 2;
			} else {
				// jp 0x1234
				num = rz_num_get(NULL, buf_asm + 3);
				opbuf[0] = 0xc3;
				opbuf[1] = (ut8)(num & 0xff);
				opbuf[2] = (ut8)((num & 0xff00) >> 8);
				len = 3;
			}
			break;
		}
		const struct {
			const char *cond;
			ut8 opcode;
		} cond_jumps[] = {
			{ "nz", 0xc2 },
			{ "z", 0xca },
			{ "nc", 0xd2 },
			{ "c", 0xda },
			{ "po", 0xe2 },
			{ "pe", 0xea },
			{ "p", 0xf2 },
			{ "m", 0xfa },
		};
		char cond_buf[4] = { 0 };
		strncpy(cond_buf, buf_asm + 3, comma - (buf_asm + 3));
		str_op(cond_buf); // Normalize
		bool matched = false;
		for (i = 0; i < sizeof(cond_jumps) / sizeof(cond_jumps[0]); i++) {
			if (!strcmp(cond_buf, cond_jumps[i].cond)) {
				opbuf[0] = cond_jumps[i].opcode;
				num = rz_num_get(NULL, comma + 1);
				opbuf[1] = (ut8)(num & 0xff);
				opbuf[2] = (ut8)((num & 0xff00) >> 8);
				len = 3;
				matched = true;
				break;
			}
		}
		if (!matched) {
			return op->size = 0;
		}
		break;
	case 0x6a72: // jr
		if (strlen(buf_asm) < 4)
			return op->size = 0;
		{
			char *p = strchr(buf_asm, (int)',');
			if (!p) {
				num = rz_num_get(NULL, &buf_asm[3]);
				len = 2;
				opbuf[0] = 0x18;
				opbuf[1] = (ut8)(num & 0xff);
			} else {
				str_op(p - 2);
				str_op(p - 1);
				if (*(p - 2) == 'n') {
					if (*(p - 1) == 'z')
						opbuf[0] = 0x20;
					else if (*(p - 1) == 'c')
						opbuf[0] = 0x30;
					else
						return op->size = 0;
				} else if (*(p - 2) == ' ') {
					if (*(p - 1) == 'z')
						opbuf[0] = 0x28;
					else if (*(p - 1) == 'c')
						opbuf[0] = 0x38;
					else
						return op->size = 0;
				} else {
					return op->size = 0;
				}
				rz_str_replace_in(p, strlen(p), ", ", ",", true);
				if (!p[1]) {
					return op->size = 0;
				}
				num = rz_num_get(NULL, p + 1);
				opbuf[1] = (ut8)(num & 0xff);
				len = 2;
			}
		}
		break;
	case 0x6c64: { // ld
		if (strlen(buf_asm) < 4) {
			len = 0;
			break;
		}
		rz_str_replace_in(buf_asm, strlen(buf_asm), ", ", ",", true);
		rz_str_replace_in(buf_asm, strlen(buf_asm), "[ ", "[", true);
		rz_str_replace_in(buf_asm, strlen(buf_asm), " ]", "]", true);
		char *comma = strchr(buf_asm + 3, ',');
		if (!comma) {
			len = 0;
			break;
		}
		char *dst = buf_asm + 3;
		char *src = comma + 1;
		*comma = '\0';
		rz_str_trim(dst);
		rz_str_trim(src);
		if (!strcmp(dst, "i") && !strcmp(src, "a")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x47;
			len = 2;
			break;
		}
		if (!strcmp(dst, "r") && !strcmp(src, "a")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x4f;
			len = 2;
			break;
		}
		if (!strcmp(dst, "a") && !strcmp(src, "i")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x57;
			len = 2;
			break;
		}
		if (!strcmp(dst, "a") && !strcmp(src, "r")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x5f;
			len = 2;
			break;
		}
		int d = z80_reg_idx(dst[0]);
		int s = z80_reg_idx(src[0]);
		if (d != -1 && s != -1) {
			opbuf[0] = 0x40 | (d << 3) | s;
			len = 1;
			break;
		}
		if (d != -1 && src[0] >= '0') {
			opbuf[0] = 0x06 | (d << 3);
			opbuf[1] = (ut8)(rz_num_get(NULL, src) & 0xff);
			len = 2;
			break;
		}
		if (!strcmp(src, "a") && dst[0] == '[') {
			ut16 nn = (ut16)rz_num_get(NULL, dst + 1);
			opbuf[0] = 0x32;
			opbuf[1] = nn & 0xff;
			opbuf[2] = nn >> 8;
			len = 3;
			break;
		}
		if (!strcmp(dst, "a") && src[0] == '[') {
			ut16 nn = (ut16)rz_num_get(NULL, src + 1);
			opbuf[0] = 0x3a;
			opbuf[1] = nn & 0xff;
			opbuf[2] = nn >> 8;
			len = 3;
			break;
		}
		len = 0;
		break;
	}
	case 0x6c6464: // ldd
		opbuf[0] = 0xed;
		opbuf[1] = 0xa8;
		len = 2;
		break;
	case 0x6c646472: // lddr
		opbuf[0] = 0xed;
		opbuf[1] = 0xb8;
		len = 2;
		break;
	case 0x6c6469: // ldi
		opbuf[0] = 0xed;
		opbuf[1] = 0xa0;
		len = 2;
		break;
	case 0x6c646972: // ldir
		opbuf[0] = 0xed;
		opbuf[1] = 0xb0;
		len = 2;
		break;
	case 0x6e6567: // neg
		opbuf[0] = 0xed;
		opbuf[1] = 0x44;
		len = 2;
		break;
	case 0x6e6f70: // nop
		opbuf[0] = 0x00;
		break;
	case 0x6f72: // or
		len = z80_parse_arith1(opbuf, 4, buf_asm, 0xb0, 0xf6);
		break;
	case 0x6f746472: // otdr
		opbuf[0] = 0xed;
		opbuf[1] = 0xbb;
		len = 2;
		break;
	case 0x6f746972: // otir
		opbuf[0] = 0xed;
		opbuf[1] = 0xb3;
		len = 2;
		break;
	case 0x6f7574: // out
		len = z80_parse_in_out(opbuf, buf_asm, false);
		break;
	case 0x6f757464: // outd
		opbuf[0] = 0xed;
		opbuf[1] = 0xab;
		len = 2;
		break;
	case 0x6f757469: // outi
		opbuf[0] = 0xed;
		opbuf[1] = 0xa3;
		len = 2;
		break;
	case 0x706f70: // pop
		if (strlen(buf_asm) < 6)
			return op->size = 0;
		str_op(&buf_asm[4]);
		str_op(&buf_asm[5]);
		if (buf_asm[4] == 'b' && buf_asm[5] == 'c') {
			opbuf[0] = 0xc1;
		} else if (buf_asm[4] == 'd' && buf_asm[5] == 'e') {
			opbuf[0] = 0xd1;
		} else if (buf_asm[4] == 'h' && buf_asm[5] == 'l') {
			opbuf[0] = 0xe1;
		} else if (buf_asm[4] == 'a' && buf_asm[5] == 'f') {
			opbuf[0] = 0xf1;
		} else if (buf_asm[4] == 'i' && buf_asm[5] == 'x') {
			opbuf[0] = 0xdd;
			opbuf[1] = 0xe1;
			len = 2;
		} else if (buf_asm[4] == 'i' && buf_asm[5] == 'y') {
			opbuf[0] = 0xfd;
			opbuf[1] = 0xe1;
			len = 2;
		} else {
			len = 0;
		}
		break;
	case 0x70757368: // push
		if (strlen(buf_asm) < 7) {
			return len = 0;
		}
		str_op(buf_asm + 5);
		str_op(buf_asm + 6);
		if (buf_asm[5] == 'b' && buf_asm[6] == 'c') {
			opbuf[0] = 0xc5;
		} else if (buf_asm[5] == 'd' && buf_asm[6] == 'e') {
			opbuf[0] = 0xd5;
		} else if (buf_asm[5] == 'h' && buf_asm[6] == 'l') {
			opbuf[0] = 0xe5;
		} else if (buf_asm[5] == 'a' && buf_asm[6] == 'f') {
			opbuf[0] = 0xf5;
		} else if (buf_asm[5] == 'i' && buf_asm[6] == 'x') {
			opbuf[0] = 0xdd;
			opbuf[1] = 0xe5;
			len = 2;
		} else if (buf_asm[5] == 'i' && buf_asm[6] == 'y') {
			opbuf[0] = 0xfd;
			opbuf[1] = 0xe5;
			len = 2;
		} else {
			len = 0;
		}
		break;
	case 0x726573: // res
		len = z80_parse_cb2(opbuf, 5, buf_asm, 0x80);
		break;
	case 0x726574: // ret
		if (!strncmp(buf_asm + 4, "c", 2)) {
			opbuf[0] = 0xD8;
		} else if (!strncmp(buf_asm + 4, "m", 2)) {
			opbuf[0] = 0xF8;
		} else if (!strncmp(buf_asm + 4, "nc", 2)) {
			opbuf[0] = 0xD0;
		} else if (!strncmp(buf_asm + 4, "nz", 2)) {
			opbuf[0] = 0xC0;
		} else if (!strncmp(buf_asm + 4, "p", 2)) {
			opbuf[0] = 0xF0;
		} else if (!strncmp(buf_asm + 4, "pe", 2)) {
			opbuf[0] = 0xE8;
		} else if (!strncmp(buf_asm + 4, "po", 2)) {
			opbuf[0] = 0xE0;
		} else if (!strncmp(buf_asm + 4, "z", 2)) {
			opbuf[0] = 0xC8;
		} else if (!*buf_asm + 4) { // plain "ret"
			opbuf[0] = 0xC9;
		} else {
			return op->size = 0;
		}
		break;
	case 0x72657469: // reti
		opbuf[0] = 0xed;
		opbuf[1] = 0x4d;
		len = 2;
		break;
	case 0x7265746E: // retn
		opbuf[0] = 0xed;
		opbuf[1] = 0x45;
		len = 2;
		break;
	case 0x726c: // rl
		len = z80_parse_cb1(opbuf, 4, buf_asm, 0x10);
		break;
	case 0x726c61: // rla
		opbuf[0] = 0x17;
		break;
	case 0x726c63: // rlc
		len = z80_parse_cb1(opbuf, 5, buf_asm, 0x00);
		break;
	case 0x726c6361: // rlca
		opbuf[0] = 0x07;
		break;
	case 0x726c64: // rld
		opbuf[0] = 0xed;
		opbuf[1] = 0x6f;
		len = 2;
		break;
	case 0x7272: // rr
		len = z80_parse_cb1(opbuf, 4, buf_asm, 0x18);
		break;
	case 0x727261: // rra
		opbuf[0] = 0x1f;
		break;
	case 0x727263: // rrc
		len = z80_parse_cb1(opbuf, 5, buf_asm, 0x08);
		break;
	case 0x72726361: // rrca
		opbuf[0] = 0x0f;
		len = 1;
		break;
	case 0x727264: // rrd
		opbuf[0] = 0xed;
		opbuf[1] = 0x67;
		len = 2;
		break;
	case 0x727374: // rst
		if (strlen(buf_asm) < 5) {
			return op->size = 0;
		}
		num = rz_num_get(NULL, &buf_asm[4]);
		if ((num & 7) || ((num / 8) > 7)) {
			return op->size = 0;
		}
		opbuf[0] = (ut8)((num & 0xff) + 0xc7);
		break;
	case 0x736263: // sbc
		rz_str_replace_in(buf_asm, strlen(buf_asm), ", ", ",", true);
		if (strlen(buf_asm) < 5)
			return op->size = 0;
		if (!strcmp(buf_asm + 4, "hl,bc")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x42;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "hl,de")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x52;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "hl,hl")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x62;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "hl,sp")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x72;
			len = 2;
		} else {
			len = z80_parse_arith1(opbuf, 5, buf_asm, 0x98, 0xde);
		}
		break;
	case 0x736366: // scf
		opbuf[0] = 0x37;
		break;
	case 0x736574: // set
		len = z80_parse_cb2(opbuf, 5, buf_asm, 0xc0);
		break;
	case 0x736c61: // sla
		len = z80_parse_cb1(opbuf, 5, buf_asm, 0x20);
		break;
	case 0x736c6c: // sll
		len = z80_parse_cb1(opbuf, 5, buf_asm, 0x30);
		break;
	case 0x737261: // sra
		len = z80_parse_cb1(opbuf, 5, buf_asm, 0x28);
		break;
	case 0x73726c: // srl
		opbuf[0] = 0xcb;
		len = z80_parse_cb1(opbuf, 5, buf_asm, 0x38);
		break;
	case 0x737562: // sub
		rz_str_replace_in(buf_asm, strlen(buf_asm), ", ", ",", true);
		if (strlen(buf_asm) < 5)
			return op->size = 0;
		if (!strcmp(buf_asm + 4, "hl,bc")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x4a;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "hl,de")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x5a;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "hl,hl")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x6a;
			len = 2;
		} else if (!strcmp(buf_asm + 4, "hl,sp")) {
			opbuf[0] = 0xed;
			opbuf[1] = 0x7a;
			len = 2;
		} else {
			len = z80_parse_arith1(opbuf, 5, buf_asm, 0x90, 0xd6);
		}
		break;
	case 0x786f72: // xor
		len = z80_parse_arith1(opbuf, 5, buf_asm, 0xa8, 0xee);
		break;
	default:
		len = 0;
		break;
	}
	rz_strbuf_setbin((&op->buf), opbuf, sizeof(ut8) * len);
	return op->size = len;
}
