#include <rz_util.h>
#include <rz_types.h>
#include <rz_asm.h>
#include <string.h>

static void str_op(char *c) {
	if ((c[0] <= 'Z') && (c[0] >= 'A')) {
		c[0] += 0x20;
	}
}

static int z80_reg_idx(char r) {
	const char *rstr = "bcdehl a";
	const char *ptr = strchr(rstr, r);
	return ptr ? (int)(size_t)(ptr - rstr) : -1;
}

static int z80_parse_arith1(ut8 *buf, const int minlen, char *buf_asm, ut8 base, ut8 alt) {
	ut64 num;
	char *src;

	buf[0] = base;

	src = strchr(buf_asm, ',');
	if (src) {
		src++;
		while (*src == ' ')
			src++;
	} else {
		src = buf_asm + minlen;
		while (*src == ' ')
			src++;
	}

	rz_str_replace_in(src, (ut32)strlen(src), "[ ", "[", true);
	rz_str_replace_in(src, (ut32)strlen(src), " ]", "]", true);

	if (!strncmp(src, "[i", 2)) {
		buf[0] = (src[2] == 'x') ? 0xdd : 0xfd;
		buf[1] = (base + 6);
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

	int i = z80_reg_idx(*src);
	if (i != -1) {
		buf[0] |= (ut8)i;
		return 1;
	}

	buf[0] = alt;
	num = rz_num_get(NULL, src);
	buf[1] = (ut8)(num & 0xff);
	return 2;
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
	for (j = 0; j < mn_len; j++) {
		mn = (mn << 8) | buf_asm[j];
	}
	switch (mn) {
	case 0x6e6f70: // nop
		opbuf[0] = 0x00;
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
				len = 0;
			}
		} else {
			len = 0;
		}

		break;
	case 0x726c6361: // rlca
		opbuf[0] = 0x07;
		break;
	case 0x72726361: // rrca
		opbuf[0] = 0xf0;
		break;
	case 0x73746f70: // stop
		opbuf[0] = 0x10;
		break;
	case 0x726c61: // rla
		opbuf[0] = 0x17;
		break;
	case 0x727261: // rra
		opbuf[0] = 0x1f;
		break;
	case 0x646161: // daa
		opbuf[0] = 0x27;
		break;
	case 0x63706c: // cpl
		opbuf[0] = 0x2f;
		break;
	case 0x616464: // "add"
		rz_str_replace_in(buf_asm, strlen(buf_asm), ", ", ",", true);
		if (strlen(buf_asm) < 5)
			return op->size = 0;

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
	case 0x616e64: // and
		len = z80_parse_arith1(opbuf, 5, buf_asm, 0xa0, 0xe6);
		break;
	case 0x786f72: // xor
		len = z80_parse_arith1(opbuf, 5, buf_asm, 0xa8, 0xee);
		break;
	case 0x6f72: // or
		len = z80_parse_arith1(opbuf, 4, buf_asm, 0xb0, 0xf6);
		break;
	case 0x6370: // cp
		len = z80_parse_arith1(opbuf, 4, buf_asm, 0xb8, 0xfe);
		break;
	case 0x736366: // scf
		opbuf[0] = 0x37;
		break;
	case 0x636366: // ccf
		opbuf[0] = 0x3f;
		break;
	case 0x68616c74: // halt
		opbuf[0] = 0x76;
		break;
	case 0x72657469: // reti
		opbuf[0] = 0xed;
		opbuf[1] = 0x4d;
		len = 2;
		break;
	case 0x6469: // di
		opbuf[0] = 0xf3;
		break;
	case 0x6569: // ei
		opbuf[0] = 0xfb;
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
	case 0x70757368: // push
		if (strlen(buf_asm) < 7) {
			return op->size = 0;
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
	default:
		len = 0;
		break;
	}
	memcpy(rz_strbuf_get(&op->buf), opbuf, sizeof(ut8) * len);
	return op->size = len;
}
