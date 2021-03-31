// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_main.h>
#include <rz_util.h>
#include <rz_util/rz_print.h>

// don't use fixed sized buffers
#define STDIN_BUFFER_SIZE 354096
static int rax(RNum *num, char *str, int len, int last, ut64 *flags, int *fm);

static int use_stdin(RNum *num, ut64 *flags, int *fm) {
	if (!flags) {
		return 0;
	}
	char *buf = calloc(1, STDIN_BUFFER_SIZE + 1);
	int l;
	if (!buf) {
		return 0;
	}
	if (!(*flags & (1 << 14))) {
		for (l = 0; l >= 0 && l < STDIN_BUFFER_SIZE; l++) {
			// make sure we don't read beyond boundaries
			int n = read(0, buf + l, STDIN_BUFFER_SIZE - l);
			if (n < 1) {
				break;
			}
			l += n;
			if (buf[l - 1] == 0) {
				l--;
				continue;
			}
			buf[n] = 0;
			// if (sflag && strlen (buf) < STDIN_BUFFER_SIZE) // -S
			buf[STDIN_BUFFER_SIZE] = '\0';
			if (!rax(num, buf, l, 0, flags, fm)) {
				break;
			}
			l = -1;
		}
	} else {
		l = 1;
	}
	if (l > 0) {
		rax(num, buf, l, 0, flags, fm);
	}
	free(buf);
	return 0;
}

static int format_output(RNum *num, char mode, const char *s, int force_mode, ut64 flags) {
	ut64 n = rz_num_math(num, s);
	char strbits[65];
	if (force_mode) {
		mode = force_mode;
	}
	if (flags & 2) {
		ut64 n2 = n;
		rz_mem_swapendian((ut8 *)&n, (ut8 *)&n2, 8);
		if (!(int)n) {
			n >>= 32;
		}
	}
	switch (mode) {
	case 'I':
		printf("%" PFMT64d "\n", n);
		break;
	case '0':
		printf("0x%" PFMT64x "\n", n);
		break;
	case 'F': {
		int n2 = (int)n;
		float *f = (float *)&n2;
		printf("%ff\n", *f);
	} break;
	case 'f': printf("%.01lf\n", num->fvalue); break;
	case 'l':
		RZ_STATIC_ASSERT(sizeof(float) == 4);
		float f = (float)num->fvalue;
		ut32 *p = (ut32 *)&f;
		printf("Fx%08x\n", *p);
		break;
	case 'O': printf("0%" PFMT64o "\n", n); break;
	case 'B':
		if (n) {
			rz_num_to_bits(strbits, n);
			printf("%sb\n", strbits);
		} else {
			printf("0b\n");
		}
		break;
	case 'T':
		if (n) {
			rz_num_to_trits(strbits, n);
			printf("%st\n", strbits);
		} else {
			printf("0t\n");
		}
		break;
	default:
		eprintf("Unknown output mode %d\n", mode);
		break;
	}
	return true;
}

static void print_ascii_table(void) {
	printf("%s", ret_ascii_table());
}

static int help(void) {
	printf(
		"  =[base]                      ;  rz_ax =10 0x46 -> output in base 10\n"
		"  int     ->  hex              ;  rz_ax 10\n"
		"  hex     ->  int              ;  rz_ax 0xa\n"
		"  -int    ->  hex              ;  rz_ax -77\n"
		"  -hex    ->  int              ;  rz_ax 0xffffffb3\n"
		"  int     ->  bin              ;  rz_ax b30\n"
		"  int     ->  ternary          ;  rz_ax t42\n"
		"  bin     ->  int              ;  rz_ax 1010d\n"
		"  ternary ->  int              ;  rz_ax 1010dt\n"
		"  float   ->  hex              ;  rz_ax 3.33f\n"
		"  hex     ->  float            ;  rz_ax Fx40551ed8\n"
		"  oct     ->  hex              ;  rz_ax 35o\n"
		"  hex     ->  oct              ;  rz_ax Ox12 (O is a letter)\n"
		"  bin     ->  hex              ;  rz_ax 1100011b\n"
		"  hex     ->  bin              ;  rz_ax Bx63\n"
		"  ternary ->  hex              ;  rz_ax 212t\n"
		"  hex     ->  ternary          ;  rz_ax Tx23\n"
		"  raw     ->  hex              ;  rz_ax -S < /binfile\n"
		"  hex     ->  raw              ;  rz_ax -s 414141\n"
		"  -l                           ;  append newline to output (for -E/-D/-r/..\n"
		"  -a      show ascii table     ;  rz_ax -a\n"
		"  -b      bin -> str           ;  rz_ax -b 01000101 01110110\n"
		"  -B      str -> bin           ;  rz_ax -B hello\n"
		"  -d      force integer        ;  rz_ax -d 3 -> 3 instead of 0x3\n"
		"  -e      swap endianness      ;  rz_ax -e 0x33\n"
		"  -D      base64 decode        ;\n"
		"  -E      base64 encode        ;\n"
		"  -f      floating point       ;  rz_ax -f 6.3+2.1\n"
		"  -F      stdin slurp code hex ;  rz_ax -F < shellcode.[c/py/js]\n"
		"  -h      help                 ;  rz_ax -h\n"
		"  -i      dump as C byte array ;  rz_ax -i < bytes\n"
		"  -I      IP address <-> LONG  ;  rz_ax -I 3530468537\n"
		"  -k      keep base            ;  rz_ax -k 33+3 -> 36\n"
		"  -K      randomart            ;  rz_ax -K 0x34 1020304050\n"
		"  -L      bin -> hex(bignum)   ;  rz_ax -L 111111111 # 0x1ff\n"
		"  -n      binary number        ;  rz_ax -n 0x1234 # 34120000\n"
		"  -o      octalstr -> raw      ;  rz_ax -o \\162 \\172 # rz\n"
		"  -N      binary number        ;  rz_ax -N 0x1234 # \\x34\\x12\\x00\\x00\n"
		"  -r      rz style output      ;  rz_ax -r 0x1234\n"
		"  -s      hexstr -> raw        ;  rz_ax -s 43 4a 50\n"
		"  -S      raw -> hexstr        ;  rz_ax -S < /bin/ls > ls.hex\n"
		"  -t      tstamp -> str        ;  rz_ax -t 1234567890\n"
		"  -x      hash string          ;  rz_ax -x linux osx\n"
		"  -u      units                ;  rz_ax -u 389289238 # 317.0M\n"
		"  -w      signed word          ;  rz_ax -w 16 0xffff\n"
		"  -v      version              ;  rz_ax -v\n");
	return true;
}

static int rax(RNum *num, char *str, int len, int last, ut64 *_flags, int *fm) {
	ut64 flags = *_flags;
	const char *nl = "";
	ut8 *buf;
	char *p, out_mode = (flags & 128) ? 'I' : '0';
	int i;
	if (!(flags & 4) || !len) {
		len = strlen(str);
	}
	if ((flags & 4)) {
		goto dotherax;
	}
	if (*str == '=') {
		int force_mode = 0;
		switch (atoi(str + 1)) {
		case 2: force_mode = 'B'; break;
		case 3: force_mode = 'T'; break;
		case 8: force_mode = 'O'; break;
		case 10: force_mode = 'I'; break;
		case 16: force_mode = '0'; break;
		case 0: force_mode = str[1]; break;
		}
		*fm = force_mode;
		return true;
	}
	if (*str == '-') {
		while (str[1] && str[1] != ' ') {
			switch (str[1]) {
			case 'l': break;
			case 'a': print_ascii_table(); return 0;
			case 's': flags ^= 1 << 0; break;
			case 'e': flags ^= 1 << 1; break;
			case 'S': flags ^= 1 << 2; break;
			case 'b': flags ^= 1 << 3; break;
			case 'B': flags ^= 1 << 17; break;
			case 'x': flags ^= 1 << 4; break;
			case 'k': flags ^= 1 << 5; break;
			case 'f': flags ^= 1 << 6; break;
			case 'd': flags ^= 1 << 7; break;
			case 'K': flags ^= 1 << 8; break;
			case 'n': flags ^= 1 << 9; break;
			case 'u': flags ^= 1 << 10; break;
			case 't': flags ^= 1 << 11; break;
			case 'E': flags ^= 1 << 12; break;
			case 'D': flags ^= 1 << 13; break;
			case 'F': flags ^= 1 << 14; break;
			case 'N': flags ^= 1 << 15; break;
			case 'w': flags ^= 1 << 16; break;
			case 'r': flags ^= 1 << 18; break;
			case 'L': flags ^= 1 << 19; break;
			case 'i': flags ^= 1 << 21; break;
			case 'o': flags ^= 1 << 22; break;
			case 'I': flags ^= 1 << 23; break;
			case 'v': return rz_main_version_print("rz_ax");
			case '\0':
				*_flags = flags;
				return !use_stdin(num, _flags, fm);
			default:
				/* not as complete as for positive numbers */
				out_mode = (flags ^ 32) ? '0' : 'I';
				if (str[1] >= '0' && str[1] <= '9') {
					if (str[2] == 'x') {
						out_mode = 'I';
					} else if (rz_str_endswith(str, "f")) {
						out_mode = 'l';
					}
					return format_output(num, out_mode, str, *fm, flags);
				}
				printf("Usage: rz-ax [options] [expr ...]\n");
				return help();
			}
			str++;
		}
		*_flags = flags;
		if (last) {
			return !use_stdin(num, _flags, fm);
		}
		return true;
	}
	*_flags = flags;
	if (!flags && rz_str_nlen(str, 2) == 1) {
		if (*str == 'q') {
			return false;
		}
		if (*str == 'h' || *str == '?') {
			help();
			return false;
		}
	}
dotherax:
	if (flags & 1) { // -s
		int n = ((strlen(str)) >> 1) + 1;
		buf = malloc(n);
		if (buf) {
			memset(buf, '\0', n);
			n = rz_hex_str2bin(str, (ut8 *)buf);
			if (n > 0) {
				fwrite(buf, n, 1, stdout);
			}
#if __EMSCRIPTEN__
			puts("");
#else
			if (nl && *nl) {
				puts("");
			}
#endif
			fflush(stdout);
			free(buf);
		}
		return true;
	}
	if (flags & (1 << 2)) { // -S
		for (i = 0; i < len; i++) {
			printf("%02x", (ut8)str[i]);
		}
		printf("\n");
		return true;
	} else if (flags & (1 << 3)) { // -b
		int i;
		ut8 buf[4096];
		const int n = rz_str_binstr2bin(str, buf, sizeof(buf));
		for (i = 0; i < n; i++) {
			printf("%c", buf[i]);
		}
		return true;
	} else if (flags & (1 << 4)) { // -x
		int h = rz_str_hash(str);
		printf("0x%x\n", h);
		return true;
	} else if (flags & (1 << 5)) { // -k
		out_mode = 'I';
	} else if (flags & (1 << 6)) { // -f
		out_mode = 'f';
	} else if (flags & (1 << 8)) { // -K
		int n = ((strlen(str)) >> 1) + 1;
		char *s = NULL;
		buf = (ut8 *)malloc(n);
		if (!buf) {
			return false;
		}
		ut32 *m = (ut32 *)buf;
		memset(buf, '\0', n);
		n = rz_hex_str2bin(str, (ut8 *)buf);
		if (n < 1 || !memcmp(str, "0x", 2)) {
			ut64 q = rz_num_math(num, str);
			s = rz_print_randomart((ut8 *)&q, sizeof(q), q);
			printf("%s\n", s);
			free(s);
		} else {
			s = rz_print_randomart((ut8 *)buf, n, *m);
			printf("%s\n", s);
			free(s);
		}
		free(m);
		return true;
	} else if (flags & (1 << 9)) { // -n
		ut64 n = rz_num_math(num, str);
		if (n >> 32) {
			/* is 64 bit value */
			if (flags & 1) {
				fwrite(&n, sizeof(n), 1, stdout);
			} else {
				int i;
				for (i = 0; i < 8; i++) {
					printf("%02x", (int)(n & 0xff));
					n >>= 8;
				}
				printf("\n");
			}
		} else {
			/* is 32 bit value */
			ut32 n32 = (ut32)n;
			if (flags & 1) {
				fwrite(&n32, sizeof(n32), 1, stdout);
			} else {
				int i;
				for (i = 0; i < 4; i++) {
					printf("%02x", n32 & 0xff);
					n32 >>= 8;
				}
				printf("\n");
			}
		}
		return true;
	} else if (flags & (1 << 17)) { // -B (bin -> str)
		int i = 0;
		// TODO: move to rz_util
		for (i = 0; i < strlen(str); i++) {
			ut8 ch = str[i];
			printf("%d%d%d%d"
			       "%d%d%d%d",
				ch & 128 ? 1 : 0,
				ch & 64 ? 1 : 0,
				ch & 32 ? 1 : 0,
				ch & 16 ? 1 : 0,
				ch & 8 ? 1 : 0,
				ch & 4 ? 1 : 0,
				ch & 2 ? 1 : 0,
				ch & 1 ? 1 : 0);
		}
		return true;
	} else if (flags & (1 << 16)) { // -w
		ut64 n = rz_num_math(num, str);
		if (n >> 31) {
			// is >32bit
			n = (st64)(st32)n;
		} else if (n >> 14) {
			n = (st64)(st16)n;
		} else if (n >> 7) {
			n = (st64)(st8)n;
		}
		printf("%" PFMT64d "\n", n);
		return true;
	} else if (flags & (1 << 15)) { // -N
		ut64 n = rz_num_math(num, str);
		if (n >> 32) {
			/* is 64 bit value */
			if (flags & 1) {
				fwrite(&n, sizeof(n), 1, stdout);
			} else {
				int i;
				for (i = 0; i < 8; i++) {
					printf("\\x%02x", (int)(n & 0xff));
					n >>= 8;
				}
				printf("\n");
			}
		} else {
			/* is 32 bit value */
			ut32 n32 = (ut32)n;
			if (flags & 1) {
				fwrite(&n32, sizeof(n32), 1, stdout);
			} else {
				int i;
				for (i = 0; i < 4; i++) {
					printf("\\x%02x", n32 & 0xff);
					n32 >>= 8;
				}
				printf("\n");
			}
		}
		return true;
	} else if (flags & (1 << 10)) { // -u
		char buf[8];
		rz_num_units(buf, sizeof(buf), rz_num_math(NULL, str));
		printf("%s\n", buf);
		return true;
	} else if (flags & (1 << 11)) { // -t
		RzList *split = rz_str_split_list(str, "GMT", 0);
		char *ts = rz_list_head(split)->data;
		const char *gmt = NULL;
		if (rz_list_length(split) >= 2 && strlen(rz_list_head(split)->n->data) > 2) {
			gmt = (const char *)rz_list_head(split)->n->data + 2;
		}
		ut32 n = rz_num_math(num, ts);
		RzPrint *p = rz_print_new();
		p->big_endian = RZ_SYS_ENDIAN;
		if (gmt) {
			p->datezone = rz_num_math(num, gmt);
		}
		rz_print_date_unix(p, (const ut8 *)&n, sizeof(ut32));
		rz_print_free(p);
		rz_list_free(split);
		return true;
	} else if (flags & (1 << 12)) { // -E
		const int n = strlen(str);
		/* http://stackoverflow.com/questions/4715415/base64-what-is-the-worst-possible-increase-in-space-usage */
		char *out = calloc(1, (n + 2) / 3 * 4 + 1); // ceil(n/3)*4 plus 1 for NUL
		if (out) {
			rz_base64_encode(out, (const ut8 *)str, n);
			printf("%s%s", out, nl);
			fflush(stdout);
			free(out);
		}
		return true;
	} else if (flags & (1 << 13)) { // -D
		const int n = strlen(str);
		ut8 *out = calloc(1, n / 4 * 3 + 1);
		if (out) {
			rz_base64_decode(out, str, n);
			printf("%s%s", out, nl);
			fflush(stdout);
			free(out);
		}
		return true;
	} else if (flags & 1 << 14) { // -F
		char *s = rz_stdin_slurp(NULL);
		if (s) {
			char *res = rz_hex_from_code(s);
			if (res) {
				printf("%s\n", res);
				fflush(stdout);
				free(res);
			} else {
				eprintf("Invalid input.\n");
			}
			free(s);
		}
		return false;
	} else if (flags & (1 << 18)) { // -r
		char *asnum, unit[8];
		char out[128];
		ut32 n32, s, a;
		double d;
		float f;
		ut64 n = rz_num_math(num, str);

		if (num->dbz) {
			eprintf("RNum ERROR: Division by Zero\n");
			return false;
		}
		n32 = (ut32)(n & UT32_MAX);
		asnum = rz_num_as_string(NULL, n, false);
		memcpy(&f, &n32, sizeof(f));
		memcpy(&d, &n, sizeof(d));

		/* decimal, hexa, octal */
		s = n >> 16 << 12;
		a = n & 0x0fff;
		rz_num_units(unit, sizeof(unit), n);
#if 0
		eprintf ("%" PFMT64d " 0x%" PFMT64x " 0%" PFMT64o
			" %s %04x:%04x ",
			n, n, n, unit, s, a);

		if (n >> 32) {
			eprintf ("%" PFMT64d " ", (st64) n);
		} else {
			eprintf ("%d ", (st32) n);
		}
		if (asnum) {
			eprintf ("\"%s\" ", asnum);
			free (asnum);
		}
		/* binary and floating point */
		rz_str_bits (out, (const ut8 *) &n, sizeof (n), NULL);
		eprintf ("%s %.01lf %ff %lf\n",
			out, num->fvalue, f, d);
#endif
		printf("hex     0x%" PFMT64x "\n", n);
		printf("octal   0%" PFMT64o "\n", n);
		printf("unit    %s\n", unit);
		printf("segment %04x:%04x\n", s, a);
		if (n >> 32) {
			printf("int64   %" PFMT64d "\n", (st64)n);
		} else {
			printf("int32   %d\n", (st32)n);
		}
		if (asnum) {
			printf("string  \"%s\"\n", asnum);
			free(asnum);
		}
		/* binary and floating point */
		rz_str_bits64(out, n);
		memcpy(&f, &n, sizeof(f));
		memcpy(&d, &n, sizeof(d));
		printf("binary  0b%s\n", out);
		printf("float:  %ff\n", f);
		printf("double: %lf\n", d);

		/* ternary */
		rz_num_to_trits(out, n);
		printf("trits   0t%s\n", out);

		return true;
	} else if (flags & (1 << 19)) { // -L
		rz_print_hex_from_bin(NULL, str);
		return true;
	} else if (flags & (1 << 21)) { // -i
		static const char start[] = "unsigned char buf[] = {";
		printf(start);
		/* reasonable amount of bytes per line */
		const int byte_per_col = 12;
		for (i = 0; i < len - 1; i++) {
			/* wrapping every N bytes */
			if (i % byte_per_col == 0) {
				printf("\n  ");
			}
			printf("0x%02x, ", (ut8)str[i]);
		}
		/* some care for the last element */
		if (i % byte_per_col == 0) {
			printf("\n  ");
		}
		printf("0x%02x\n", (ut8)str[len - 1]);
		printf("};\n");
		printf("unsigned int buf_len = %d;\n", len);
		return true;
	} else if (flags & (1 << 22)) { // -o
		// check -r
		// flags & (1 << 18)
		char *modified_str;

		// To distinguish octal values.
		if (*str != '0') {
			modified_str = rz_str_newf("0%s", str);
		} else {
			modified_str = rz_str_new(str);
		}

		ut64 n = rz_num_math(num, modified_str);
		free(modified_str);
		if (num->dbz) {
			eprintf("RNum ERROR: Division by Zero\n");
			return false;
		}

		char *asnum = rz_num_as_string(NULL, n, false);
		if (asnum) {
			printf("%s", asnum);
			free(asnum);
		} else {
			eprintf("No String Possible\n");
			return false;
		}
		return true;
	} else if (flags & (1 << 23)) { // -I
		if (strchr(str, '.')) {
			ut8 ip[4];
			sscanf(str, "%hhd.%hhd.%hhd.%hhd", ip, ip + 1, ip + 2, ip + 3);
			ut32 ip32 = ip[0] | (ip[1] << 8) | (ip[2] << 16) | (ip[3] << 24);
			printf("0x%08x\n", ip32);
		} else {
			ut32 ip32 = (ut32)rz_num_math(NULL, str);
			ut8 ip[4] = { ip32 & 0xff, (ip32 >> 8) & 0xff, (ip32 >> 16) & 0xff, ip32 >> 24 };
			printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
		}
		return true;
	}

	if (str[0] == '0' && (tolower(str[1]) == 'x')) {
		out_mode = (flags & 32) ? '0' : 'I';
	} else if (rz_str_startswith(str, "b")) {
		out_mode = 'B';
		str++;
	} else if (rz_str_startswith(str, "t")) {
		out_mode = 'T';
		str++;
	} else if (rz_str_startswith(str, "Fx")) {
		out_mode = 'F';
		*str = '0';
	} else if (rz_str_startswith(str, "Bx")) {
		out_mode = 'B';
		*str = '0';
	} else if (rz_str_startswith(str, "Tx")) {
		out_mode = 'T';
		*str = '0';
	} else if (rz_str_startswith(str, "Ox")) {
		out_mode = 'O';
		*str = '0';
	} else if (rz_str_endswith(str, "d")) {
		out_mode = 'I';
		str[strlen(str) - 1] = 'b';
		// TODO: Move print into format_output
	} else if (rz_str_endswith(str, "f")) {
		out_mode = 'l';
	} else if (rz_str_endswith(str, "dt")) {
		out_mode = 'I';
		str[strlen(str) - 2] = 't';
		str[strlen(str) - 1] = '\0';
	}
	while ((p = strchr(str, ' '))) {
		*p = 0;
		format_output(num, out_mode, str, *fm, flags);
		str = p + 1;
	}
	if (*str) {
		format_output(num, out_mode, str, *fm, flags);
	}
	return true;
}

RZ_API int rz_main_rz_ax(int argc, const char **argv) {
	int i, fm = 0;
	RNum *num = rz_num_new(NULL, NULL, NULL);
	if (argc == 1) {
		use_stdin(num, 0, &fm);
	} else {
		ut64 flags = 0;
		for (i = 1; i < argc; i++) {
			char *argv_i = strdup(argv[i]);
			rz_str_unescape(argv_i);
			rax(num, argv_i, 0, i == argc - 1, &flags, &fm);
			free(argv_i);
		}
	}
	rz_num_free(num);
	num = NULL;
	return 0;
}
