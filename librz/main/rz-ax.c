// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_main.h>
#include <rz_util.h>
#include <rz_util/rz_print.h>

#define RZ_AX_FLAG_HEX_TO_RAW           (1ull << 0) //  -s (hexstr -> raw)
#define RZ_AX_FLAG_SWAP_ENDIANNESS      (1ull << 1) //  -e (swap endianness)
#define RZ_AX_FLAG_RAW_TO_HEX           (1ull << 2) //  -S (raw -> hexstr)
#define RZ_AX_FLAG_BIN_TO_STR           (1ull << 3) //  -b (bin -> str)
#define RZ_AX_FLAG_STR_TO_DJB2          (1ull << 4) //  -x (str -> djb2 hash)
#define RZ_AX_FLAG_KEEP_BASE            (1ull << 5) //  -k (keep base)
#define RZ_AX_FLAG_FLOATING_POINT       (1ull << 6) //  -f (floating point)
#define RZ_AX_FLAG_FORCE_INTEGER        (1ull << 7) //  -d (force integer)
#define RZ_AX_FLAG_NUMBER_TO_HEX        (1ull << 9) //  -n (num -> hex)
#define RZ_AX_FLAG_UNITS                (1ull << 10) // -u (units)
#define RZ_AX_FLAG_TIMESTAMP_TO_STR     (1ull << 11) // -t (unix timestamp -> str)
#define RZ_AX_FLAG_BASE64_ENCODE        (1ull << 12) // -E (base64 encode)
#define RZ_AX_FLAG_BASE64_DECODE        (1ull << 13) // -D (base64 decode)
#define RZ_AX_FLAG_RAW_TO_LANGBYTES     (1ull << 14) // -F (raw -> C or JS or Python bytes)
#define RZ_AX_FLAG_NUMBER_TO_HEXSTR     (1ull << 15) // -N (num -> escaped hex string)
#define RZ_AX_FLAG_SIGNED_WORD          (1ull << 16) // -w (signed word)
#define RZ_AX_FLAG_STR_TO_BIN           (1ull << 17) // -B (str -> bin)
#define RZ_AX_FLAG_RIZIN_CMD            (1ull << 18) // -r (rizin commands)
#define RZ_AX_FLAG_BIN_TO_BIGNUM        (1ull << 19) // -L (bin -> hex(bignum))
#define RZ_AX_FLAG_DUMP_C_BYTES         (1ull << 21) // -i (dump as C byte array)
#define RZ_AX_FLAG_OCTAL_TO_RAW         (1ull << 22) // -o (octalstr -> raw)
#define RZ_AX_FLAG_IPADDR_TO_LONG       (1ull << 23) // -I (IP address <-> LONG)
#define RZ_AX_FLAG_SET_BITS             (1ull << 24) // -p (find position of set bits)
#define RZ_AX_FLAG_DOS_TIMESTAMP_TO_STR (1ull << 25) // -m (MS-DOS timestamp -> str)

#define has_flag(f, x) (f & x)

// don't use fixed sized buffers
#define STDIN_BUFFER_SIZE 354096
static int rax(RzNum *num, char *str, int len, int last, ut64 *flags, int *fm);

static int use_stdin(RzNum *num, ut64 *flags, int *fm) {
	if (!flags) {
		return 0;
	}
	char *buf = calloc(1, STDIN_BUFFER_SIZE + 1);
	int l;
	if (!buf) {
		return 0;
	}
	if (!(has_flag(*flags, RZ_AX_FLAG_RAW_TO_LANGBYTES))) {
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

static int format_output(RzNum *num, char mode, const char *s, int force_mode, ut64 flags) {
	ut64 n = rz_num_math(num, s);
	char strbits[65];
	if (force_mode) {
		mode = force_mode;
	}
	if (has_flag(flags, RZ_AX_FLAG_SWAP_ENDIANNESS)) {
		ut64 n2 = n;
		n = rz_swap_ut64(n2);
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

static void print_hex_from_base2(char *base2) {
	bool first = true;
	const int len = strlen(base2);
	if (len < 1) {
		return;
	}

	// we split each section by 8 bits and have bytes.
	ut32 bytes_size = (len >> 3) + (len & 7 ? 1 : 0);
	ut8 *bytes = calloc(bytes_size, sizeof(ut8));
	if (!bytes) {
		eprintf("cannot allocate %d bytes\n", bytes_size);
		return;
	}

	int c = len & 7;
	if (c) {
		// align counter to 8 bits
		c = 8 - c;
	}
	for (int i = 0, j = 0; i < len && j < bytes_size; i++, c++) {
		if (base2[i] != '1' && base2[i] != '0') {
			eprintf("invalid base2 number %c at char %d\n", base2[i], i);
			free(bytes);
			return;
		}
		// c & 7 is c % 8
		if (c > 0 && !(c & 7)) {
			j++;
		}
		bytes[j] <<= 1;
		bytes[j] |= base2[i] - '0';
	}

	printf("0x");
	for (int i = 0; i < bytes_size; ++i) {
		if (first) {
			if (i != (bytes_size - 1) && !bytes[i]) {
				continue;
			}
			printf("%x", bytes[i]);
			first = false;
		} else {
			printf("%02x", bytes[i]);
		}
	}
	printf("\n");
	free(bytes);
}

static void print_ascii_table(void) {
	printf("%s", ret_ascii_table());
}

static int help(void) {
	printf(
		"  =[base]                      ;  rz-ax =10 0x46 -> output in base 10\n"
		"  int     ->  hex              ;  rz-ax 10\n"
		"  hex     ->  int              ;  rz-ax 0xa\n"
		"  -int    ->  hex              ;  rz-ax -77\n"
		"  -hex    ->  int              ;  rz-ax 0xffffffb3\n"
		"  int     ->  bin              ;  rz-ax b30\n"
		"  int     ->  ternary          ;  rz-ax t42\n"
		"  bin     ->  int              ;  rz-ax 1010d\n"
		"  ternary ->  int              ;  rz-ax 1010dt\n"
		"  float   ->  hex              ;  rz-ax 3.33f\n"
		"  hex     ->  float            ;  rz-ax Fx40551ed8\n"
		"  oct     ->  hex              ;  rz-ax 35o\n"
		"  hex     ->  oct              ;  rz-ax Ox12 (O is a letter)\n"
		"  bin     ->  hex              ;  rz-ax 1100011b\n"
		"  hex     ->  bin              ;  rz-ax Bx63\n"
		"  ternary ->  hex              ;  rz-ax 212t\n"
		"  hex     ->  ternary          ;  rz-ax Tx23\n"
		"  raw     ->  hex              ;  rz-ax -S < /binfile\n"
		"  hex     ->  raw              ;  rz-ax -s 414141\n"
		"  -l                           ;  append newline to output (for -E/-D/-r/..\n"
		"  -a      show ascii table     ;  rz-ax -a\n"
		"  -b      bin -> str           ;  rz-ax -b 01000101 01110110\n"
		"  -B      str -> bin           ;  rz-ax -B hello\n"
		"  -d      force integer        ;  rz-ax -d 3 -> 3 instead of 0x3\n"
		"  -e      swap endianness      ;  rz-ax -e 0x33\n"
		"  -D      base64 decode        ;\n"
		"  -E      base64 encode        ;\n"
		"  -f      floating point       ;  rz-ax -f 6.3+2.1\n"
		"  -F      stdin slurp code hex ;  rz-ax -F < shellcode.[c/py/js]\n"
		"  -h      show this help       ;  rz-ax -h\n"
		"  -i      dump as C byte array ;  rz-ax -i < bytes\n"
		"  -I      IP address <-> LONG  ;  rz-ax -I 3530468537\n"
		"  -k      keep base            ;  rz-ax -k 33+3 -> 36\n"
		"  -L      bin -> hex(bignum)   ;  rz-ax -L 111111111 # 0x1ff\n"
		"  -n      int value -> hexpairs;  rz-ax -n 0x1234 # 34120000\n"
		"  -o      octalstr -> raw      ;  rz-ax -o \\162 \\172 # rz\n"
		"  -N      binary number        ;  rz-ax -N 0x1234 # \\x34\\x12\\x00\\x00\n"
		"  -r      rz style output      ;  rz-ax -r 0x1234\n"
		"  -s      hexstr -> raw        ;  rz-ax -s 43 4a 50\n"
		"  -S      raw -> hexstr        ;  rz-ax -S < /bin/ls > ls.hex\n"
		"  -t      Unix tstamp -> str   ;  rz-ax -t 1234567890\n"
		"  -m      MS-DOS tstamp -> str ;  rz-ax -m 1234567890\n"
		"  -x      hash string          ;  rz-ax -x linux osx\n"
		"  -u      units                ;  rz-ax -u 389289238 # 317.0M\n"
		"  -w      signed word          ;  rz-ax -w 16 0xffff\n"
		"  -v      version              ;  rz-ax -v\n"
		"  -p      position of set bits ;  rz-ax -p 0xb3\n");
	return true;
}

static int rax(RzNum *num, char *str, int len, int last, ut64 *_flags, int *fm) {
	ut64 flags = *_flags;
	const char *nl = "";
	ut8 *buf;
	char *p, out_mode = has_flag(flags, RZ_AX_FLAG_FORCE_INTEGER) ? 'I' : '0';
	int i;
	if (!has_flag(flags, RZ_AX_FLAG_RAW_TO_HEX) || !len) {
		len = strlen(str);
	}
	if (has_flag(flags, RZ_AX_FLAG_RAW_TO_HEX)) {
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
			case 's': flags ^= RZ_AX_FLAG_HEX_TO_RAW; break;
			case 'e': flags ^= RZ_AX_FLAG_SWAP_ENDIANNESS; break;
			case 'S': flags ^= RZ_AX_FLAG_RAW_TO_HEX; break;
			case 'b': flags ^= RZ_AX_FLAG_BIN_TO_STR; break;
			case 'B': flags ^= RZ_AX_FLAG_STR_TO_BIN; break;
			case 'p': flags ^= RZ_AX_FLAG_SET_BITS; break;
			case 'x': flags ^= RZ_AX_FLAG_STR_TO_DJB2; break;
			case 'k': flags ^= RZ_AX_FLAG_KEEP_BASE; break;
			case 'f': flags ^= RZ_AX_FLAG_FLOATING_POINT; break;
			case 'd': flags ^= RZ_AX_FLAG_FORCE_INTEGER; break;
			case 'n': flags ^= RZ_AX_FLAG_NUMBER_TO_HEX; break;
			case 'u': flags ^= RZ_AX_FLAG_UNITS; break;
			case 't': flags ^= RZ_AX_FLAG_TIMESTAMP_TO_STR; break;
			case 'E': flags ^= RZ_AX_FLAG_BASE64_ENCODE; break;
			case 'D': flags ^= RZ_AX_FLAG_BASE64_DECODE; break;
			case 'F': flags ^= RZ_AX_FLAG_RAW_TO_LANGBYTES; break;
			case 'N': flags ^= RZ_AX_FLAG_NUMBER_TO_HEXSTR; break;
			case 'w': flags ^= RZ_AX_FLAG_SIGNED_WORD; break;
			case 'r': flags ^= RZ_AX_FLAG_RIZIN_CMD; break;
			case 'L': flags ^= RZ_AX_FLAG_BIN_TO_BIGNUM; break;
			case 'i': flags ^= RZ_AX_FLAG_DUMP_C_BYTES; break;
			case 'o': flags ^= RZ_AX_FLAG_OCTAL_TO_RAW; break;
			case 'I': flags ^= RZ_AX_FLAG_IPADDR_TO_LONG; break;
			case 'm': flags ^= RZ_AX_FLAG_DOS_TIMESTAMP_TO_STR; break;
			case 'v': return rz_main_version_print("rz-ax");
			case '\0':
				*_flags = flags;
				return !use_stdin(num, _flags, fm);
			default:
				/* not as complete as for positive numbers */
				out_mode = (flags ^ RZ_AX_FLAG_KEEP_BASE) ? '0' : 'I';
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
	if (has_flag(flags, RZ_AX_FLAG_HEX_TO_RAW)) { // -s
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
	if (has_flag(flags, RZ_AX_FLAG_RAW_TO_HEX)) { // -S
		for (i = 0; i < len; i++) {
			printf("%02x", (ut8)str[i]);
		}
		printf("\n");
		return true;
	} else if (has_flag(flags, RZ_AX_FLAG_BIN_TO_STR)) { // -b
		int i;
		ut8 buf[4096];
		const int n = rz_str_binstr2bin(str, buf, sizeof(buf));
		for (i = 0; i < n; i++) {
			printf("%c", buf[i]);
		}
		return true;
	} else if (has_flag(flags, RZ_AX_FLAG_STR_TO_DJB2)) { // -x
		int h = rz_str_djb2_hash(str);
		printf("0x%x\n", h);
		return true;
	} else if (has_flag(flags, RZ_AX_FLAG_KEEP_BASE)) { // -k
		out_mode = 'I';
	} else if (has_flag(flags, RZ_AX_FLAG_FLOATING_POINT)) { // -f
		out_mode = 'f';
	} else if (has_flag(flags, RZ_AX_FLAG_NUMBER_TO_HEX)) { // -n
		ut64 n = rz_num_math(num, str);
		if (n >> 32) {
			/* is 64 bit value */
			if (has_flag(flags, RZ_AX_FLAG_HEX_TO_RAW)) {
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
			if (has_flag(flags, RZ_AX_FLAG_HEX_TO_RAW)) {
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
	} else if (has_flag(flags, RZ_AX_FLAG_STR_TO_BIN)) { // -B (bin -> str)
		int i = 0;
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
	} else if (has_flag(flags, RZ_AX_FLAG_SET_BITS)) { // -p (find position of set bits)
		ut64 n = rz_num_math(num, str);
		char strbits[65] = { 0 };
		int i = 0, set_bits_ctr = 0;
		rz_num_to_bits(strbits, n);
		rz_str_reverse(strbits); // because we count Right to Left
		char last_char = 0;
		while (strbits[i] != '\0') {
			if (strbits[i] == '1') {
				++set_bits_ctr;
				if (i == 0) {
					printf("[%d", i);
				} else if (strbits[i] == '1' && last_char == '0') {
					printf("[%d", i);
				}
			}
			if (strbits[i] == '0' && last_char == '1') {
				if (set_bits_ctr == 1) {
					printf("]: 1\n");
				} else if (strbits[i + 1] == '\0') {
					printf("-%d]: 1\n", i);
				} else
					printf("-%d]: 1\n", i - 1);
				set_bits_ctr = 0;
			} else if (strbits[i] == '1' && strbits[i + 1] == '\0') {
				if (set_bits_ctr == 1) {
					printf("]: 1\n");
				} else
					printf("-%d]: 1\n", i);
				set_bits_ctr = 0;
			}
			last_char = strbits[i];
			++i;
		}
		return true;
	} else if (has_flag(flags, RZ_AX_FLAG_SIGNED_WORD)) { // -w
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
	} else if (has_flag(flags, RZ_AX_FLAG_NUMBER_TO_HEXSTR)) { // -N
		ut64 n = rz_num_math(num, str);
		if (n >> 32) {
			/* is 64 bit value */
			if (has_flag(flags, RZ_AX_FLAG_HEX_TO_RAW)) {
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
			if (has_flag(flags, RZ_AX_FLAG_HEX_TO_RAW)) {
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
	} else if (has_flag(flags, RZ_AX_FLAG_UNITS)) { // -u
		char buf[8];
		rz_num_units(buf, sizeof(buf), rz_num_math(NULL, str));
		printf("%s\n", buf);
		return true;
	} else if (has_flag(flags, RZ_AX_FLAG_TIMESTAMP_TO_STR) || 
			has_flag(flags, RZ_AX_FLAG_DOS_TIMESTAMP_TO_STR)) { // -t, -m
		RzList *split = rz_str_split_list(str, "GMT", 0);
		RzListIter *head = rz_list_head(split);
		char *ts = rz_list_iter_get_data(head);
		const char *gmt = rz_list_iter_get_next_data(head);
		if (gmt && strlen(gmt) < 2) {
			gmt = NULL;
		}
		ut32 n = rz_num_math(num, ts);
		int timezone = (int)rz_num_math(num, gmt);
		n += timezone * (60 * 60);
		char * date = NULL;
		if (has_flag(flags, RZ_AX_FLAG_TIMESTAMP_TO_STR)) {
			date = rz_time_date_unix_to_string(n);
		}
		else { 
			date = rz_time_date_dos_to_string(n);
		}
		if (date != NULL)
		{
			printf("%s\n", date);
			fflush(stdout);
			free(date);
			rz_list_free(split);
			return true;
		}
		return false;
	} else if (has_flag(flags, RZ_AX_FLAG_BASE64_ENCODE)) { // -E
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
	} else if (has_flag(flags, RZ_AX_FLAG_BASE64_DECODE)) { // -D
		int n = strlen(str);
		ut8 *out = calloc(1, n / 4 * 3 + 1);
		if (out) {
			n = rz_base64_decode(out, str, n);
			fwrite(out, n, 1, stdout);
			fflush(stdout);
			free(out);
		}
		return true;
	} else if (has_flag(flags, RZ_AX_FLAG_RAW_TO_LANGBYTES)) { // -F
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
	} else if (has_flag(flags, RZ_AX_FLAG_RIZIN_CMD)) { // -r
		char *asnum, unit[8];
		char out[128];
		ut32 n32, s, a;
		double d;
		float f;
		ut64 n = rz_num_math(num, str);

		if (num->dbz) {
			eprintf("RzNum ERROR: Division by Zero\n");
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
	} else if (has_flag(flags, RZ_AX_FLAG_BIN_TO_BIGNUM)) { // -L
		print_hex_from_base2(str);
		return true;
	} else if (has_flag(flags, RZ_AX_FLAG_DUMP_C_BYTES)) { // -i
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
	} else if (has_flag(flags, RZ_AX_FLAG_OCTAL_TO_RAW)) { // -o
		// check -r
		char *modified_str;

		// To distinguish octal values.
		if (*str != '0') {
			modified_str = rz_str_newf("0%s", str);
		} else {
			modified_str = rz_str_dup(str);
		}

		ut64 n = rz_num_math(num, modified_str);
		free(modified_str);
		if (num->dbz) {
			eprintf("RzNum ERROR: Division by Zero\n");
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
	} else if (has_flag(flags, RZ_AX_FLAG_IPADDR_TO_LONG)) { // -I
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
		out_mode = (has_flag(flags, RZ_AX_FLAG_KEEP_BASE)) ? '0' : 'I';
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
	RzNum *num = rz_num_new(NULL, NULL, NULL);
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
