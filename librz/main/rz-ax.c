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
#define RZ_AX_FLAG_WIN_TIMESTAMP_TO_STR (1ull << 26) // -W (Win32 timestamp -> str)

#define has_flag(f, x)  (f & x)
#define is_timestamp(f) ((f & RZ_AX_FLAG_DOS_TIMESTAMP_TO_STR) || \
	(f & RZ_AX_FLAG_TIMESTAMP_TO_STR) || (f & RZ_AX_FLAG_WIN_TIMESTAMP_TO_STR))
// don't use fixed sized buffers
#define STDIN_BUFFER_SIZE 354096
static int rax(RzNum *num, char *str, int len, int last, ut64 *flags, int *fm);

// Flags whose operand is the raw stdin buffer, newlines included, rather
// than one expression per line.
#define RZ_AX_RAW_STDIN_FLAGS \
	(RZ_AX_FLAG_RAW_TO_HEX | RZ_AX_FLAG_BASE64_ENCODE | RZ_AX_FLAG_BASE64_DECODE | \
		RZ_AX_FLAG_STR_TO_DJB2 | RZ_AX_FLAG_DUMP_C_BYTES | RZ_AX_FLAG_STR_TO_BIN | \
		RZ_AX_FLAG_RAW_TO_LANGBYTES)

static int rax(RzNum *num, char *str, int len, int last, ut64 *flags, int *fm);

// Hand one stdin read to rax(). Conversions take one expression per line,
// so the chunk is split and the newlines dropped: a trailing newline would
// otherwise make `0xff` a compound expression rather than a bare literal,
// and print it in the wrong base.
static bool stdin_chunk(RzNum *num, char *buf, int len, ut64 *flags, int *fm, bool *quit) {
	if (*flags & RZ_AX_RAW_STDIN_FLAGS) {
		return rax(num, buf, len, 0, flags, fm);
	}
	char *line = buf;
	while (line < buf + len) {
		char *nl = strchr(line, '\n');
		if (nl) {
			*nl = '\0';
		}
		if (!strcmp(line, "q")) {
			*quit = true;
			return false;
		}
		if (*line && !rax(num, line, strlen(line), 0, flags, fm)) {
			return false;
		}
		if (!nl) {
			break;
		}
		line = nl + 1;
	}
	return true;
}

static int use_stdin(RzNum *num, ut64 *flags, int *fm) {
	if (!flags) {
		return 0;
	}
	char *buf = calloc(1, STDIN_BUFFER_SIZE + 1);
	int l;
	bool quit = false;
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
			buf[l] = 0;
			// if (sflag && strlen (buf) < STDIN_BUFFER_SIZE) // -S
			buf[STDIN_BUFFER_SIZE] = '\0';
			// `q` on its own line ends the session. Only stdin has one, so
			// on the command line `q` stays an ordinary (unresolvable) name.
			// The buffer itself must not be touched: the raw-input flags
			// (-S, -E) hash or encode it verbatim, newline included.
			if (!strcmp(buf, "q") || !strcmp(buf, "q\n")) {
				quit = true;
				break;
			}
			if (!stdin_chunk(num, buf, l, flags, fm, &quit)) {
				break;
			}
			l = -1;
		}
	} else {
		l = 1;
	}
	if (l > 0 && !quit) {
		stdin_chunk(num, buf, l, flags, fm, &quit);
	}
	free(buf);
	return 0;
}

// Sentinel force-mode meaning a preceding `=N` requested an unsupported base;
// the expression that follows must not be printed (the error was reported).
#define RZ_AX_INVALID_BASE (-1)

// Evaluate \p s, reporting any diagnostic on stderr. An identifier the
// evaluator cannot resolve folds to 0 but raises num->nc.errors; rz-ax has no
// flag or register context of its own, so a raised flag means the input was
// not a number rather than a lookup miss, and is reported as such.
// True when \p c is a valid digit for \p base (2, 3, 8, 10 or 16).
static bool is_digit_in_base(ut8 c, ut32 base) {
	ut8 v = 0;
	if (rz_hex_to_byte(&v, c)) {
		return false;
	}
	return v < base;
}

static bool rax_eval(RzNum *num, const char *s, RzNumValue *out) {
	rz_num_value_init(out);
	char *err = NULL;
	if (num) {
		num->nc.errors = 0;
	}
	if (!rz_num_math_value(num, s, out, &err)) {
		eprintf("rz-ax: %s\n", err ? err : "evaluation failed");
		free(err);
		rz_num_value_fini(out);
		return false;
	}
	free(err);
	if (num && num->nc.errors) {
		eprintf("rz-ax: cannot resolve '%s'\n", s);
		rz_num_value_fini(out);
		return false;
	}
	return true;
}

// rax_eval() narrowed to the 64 bits the single-width conversions work on.
static bool rax_eval_u64(RzNum *num, const char *s, ut64 *out) {
	RzNumValue v;
	if (!rax_eval(num, s, &v)) {
		return false;
	}
	*out = rz_num_value_to_ut64(&v);
	rz_num_value_fini(&v);
	return true;
}

static int format_output(RzNum *num, char mode, const char *s, int force_mode, ut64 flags) {
	if (force_mode == RZ_AX_INVALID_BASE) {
		return false;
	}
	RzNumValue v;
	if (!rax_eval(num, s, &v)) {
		return false;
	}

	if (force_mode) {
		mode = force_mode;
	}
	if (v.kind == RZ_NUM_KIND_FLOAT && mode == 'l') {
		// `Nf` asks for the compact 32-bit pattern, which the multi-line
		// float table below would not give.
		RZ_STATIC_ASSERT(sizeof(float) == 4);
		float f32 = (float)v.val.d;
		ut32 bits;
		memcpy(&bits, &f32, sizeof(bits));
		printf("Fx%08x\n", bits);
		rz_num_value_fini(&v);
		return true;
	}

	// Other format-flag modes have no sensible interpretation on a float
	// or a 1024-bit big number, so fall back to the multi-line
	// pretty-print.
	if (v.kind != RZ_NUM_KIND_UT64) {
		RzStrBuf *sb = rz_strbuf_new(NULL);
		if (sb) {
			rz_num_value_print(&v, sb);
			char *block = rz_strbuf_drain(sb);
			if (block) {
				printf("%s", block);
				free(block);
			}
		}
		rz_num_value_fini(&v);
		return true;
	}

	ut64 n = v.val.n;
	if (num) {
		num->value = n;
	}
	rz_num_value_fini(&v);

	char strbits[65];
	if (has_flag(flags, RZ_AX_FLAG_SWAP_ENDIANNESS)) {
		ut64 n2 = n;
		n = rz_swap_ut64(n2);
		if (!(int)n) {
			n >>= 32;
		}
		// The swapped value is no longer "the other base of the input",
		// so the bare-literal decimal toggle does not apply to it.
		if (mode == 'I' && !force_mode) {
			mode = '0';
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
	printf("%s", rz_get_ascii_table());
}

static int help(bool verbose) {
	printf(Color_CYAN "Usage:" Color_RESET " rz-ax [options] [expression ...]\n"
			  "\n"
			  "Converts numbers between bases and evaluates RzNum expressions.\n"
			  "Without an expression, reads one per line from stdin.\n");
#define CF Color_GREEN
#define CA Color_YELLOW
#define CR Color_RESET
	const char *conversions[] = {
		// clang-format off
		NULL, NULL, "int     -> hex",     "rz-ax 10",
		NULL, NULL, "hex     -> int",     "rz-ax 0xa",
		NULL, NULL, "-int    -> hex",     "rz-ax -77",
		NULL, NULL, "-hex    -> int",     "rz-ax 0xffffffb3",
		NULL, NULL, "int     -> bin",     "rz-ax b30",
		NULL, NULL, "int     -> ternary", "rz-ax t42",
		NULL, NULL, "int     -> oct",     "rz-ax Ox12",
		NULL, NULL, "bin     -> int",     "rz-ax 0b1010",
		NULL, NULL, "oct     -> int",     "rz-ax 0o17",
		NULL, NULL, "ternary -> int",     "rz-ax 0t212",
		NULL, NULL, "float   -> hex",     "rz-ax 3.33f",
		NULL, NULL, "hex     -> float",   "rz-ax Fx40551ed8",
		NULL, NULL, "hex     -> bin",     "rz-ax Bx63",
		NULL, NULL, "hex     -> ternary", "rz-ax Tx23",
		NULL, NULL, "raw     -> hex",     "rz-ax " CF "-S" CR " < /binfile",
		NULL, NULL, "hex     -> raw",     "rz-ax " CF "-s" CR " 414141",
		// clang-format on
	};
	const char *expressions[] = {
		// clang-format off
		NULL, NULL, "arithmetic",         "rz-ax '3 * (10 + 2)'",
		NULL, NULL, "bit-vector width",   "rz-ax 5u8+3u8",
		NULL, NULL, "automatic big number", "rz-ax 2**64",
		NULL, NULL, "built-in function",  "rz-ax min(0x10,0x20)",
		NULL, NULL, "variable binding",   "rz-ax 'x=10;x*4'",
		// clang-format on
	};
	const char *options[] = {
		// clang-format off
		"=N", "", "print the result in base N",  "rz-ax " CF "=" CA "10" CR " 0x46",
		"-a", "", "show the ascii table",        "rz-ax " CF "-a" CR,
		"-b", "", "bin -> str",                  "rz-ax " CF "-b" CR " 01000101 01110110",
		"-B", "", "str -> bin",                  "rz-ax " CF "-B" CR " hello",
		"-d", "", "print integers in base 10",   "rz-ax " CF "-d" CR " 3           # 3, not 0x3",
		"-D", "", "base64 decode",               "rz-ax " CF "-D" CR " cml6aW4=",
		"-e", "", "swap endianness",             "rz-ax " CF "-e" CR " 0x33",
		"-E", "", "base64 encode",               "rz-ax " CF "-E" CR " rizin",
		"-f", "", "keep the fractional part",    "rz-ax " CF "-f" CR " 6.3+2.1",
		"-F", "", "slurp code from stdin as hex", "rz-ax " CF "-F" CR " < shellcode.[c/py/js]",
		"-h", "", "show this help",              NULL,
		"-H", "", "show the long help",          "conversions, syntax, operators",
		"-i", "", "dump as a C byte array",      "rz-ax " CF "-i" CR " < bytes",
		"-I", "", "IP address <-> LONG",         "rz-ax " CF "-I" CR " 3530468537",
		"-k", "", "keep the input base",         "rz-ax " CF "-k" CR " 33+3       # 36",
		"-l", "", "append a newline to output",  "for " CF "-E" CR " / " CF "-D" CR " / " CF "-r" CR " / ...",
		"-L", "", "bin -> hex (big number)",     "rz-ax " CF "-L" CR " 111111111  # 0x1ff",
		"-m", "", "MS-DOS timestamp -> str",     "rz-ax " CF "-m" CR " 1234567890",
		"-n", "", "int -> hex pairs",            "rz-ax " CF "-n" CR " 0x1234     # 34120000",
		"-N", "", "int -> escaped raw bytes",    "rz-ax " CF "-N" CR " 0x1234     # \\x34\\x12\\x00\\x00",
		"-o", "", "octal str -> raw",            "rz-ax " CF "-o" CR " \\162 \\172   # rz",
		"-p", "", "positions of the set bits",   "rz-ax " CF "-p" CR " 0xb3",
		"-r", "", "rizin command output",        "rz-ax " CF "-r" CR " 0x1234",
		"-s", "", "hex str -> raw",              "rz-ax " CF "-s" CR " 43 4a 50",
		"-S", "", "raw -> hex str",              "rz-ax " CF "-S" CR " < /bin/ls > ls.hex",
		"-t", "", "Unix timestamp -> str",       "rz-ax " CF "-t" CR " 1234567890",
		"-u", "", "human readable units",        "rz-ax " CF "-u" CR " 389289238  # 371.3M",
		"-v", "", "show the version",            NULL,
		"-w", "", "sign-extend a signed word",   "rz-ax " CF "-w" CR " 16 0xffff",
		"-W", "", "Win32 timestamp -> str",      "rz-ax " CF "-W" CR " 1234567890",
		"-x", "", "djb2 hash of a string",       "rz-ax " CF "-x" CR " linux osx",
		// clang-format on
	};
#undef CF
#undef CA
#undef CR
	printf("\n" Color_CYAN "Options" Color_RESET "\n");
	rz_print_colored_help(options, RZ_ARRAY_SIZE(options), true);
	if (!verbose) {
		printf("\nRun " Color_GREEN "rz-ax -H" Color_RESET " for the conversion table, the expression\n"
		       "syntax and the operator list, or see the rz-ax(1) man page.\n");
		return true;
	}

	printf("\n" Color_CYAN "Conversions" Color_RESET "\n");
	rz_print_colored_help(conversions, RZ_ARRAY_SIZE(conversions), true);
	printf(" Trailing base suffixes (101b, 35o, 212t) still work but are\n"
	       " deprecated; prefer the 0b / 0o / 0t prefixes.\n");
	printf("\n" Color_CYAN "Expressions" Color_RESET "\n");
	rz_print_colored_help(expressions, RZ_ARRAY_SIZE(expressions), true);
	printf(" Quote an expression containing spaces so it stays a single\n"
	       " argument; otherwise every argument is converted on its own.\n");
	printf("\n" Color_CYAN "Operators" Color_RESET " (C precedence)\n"
	       "  **                power     (2**10; note ^ is XOR, not power)\n"
	       "  * / %%             multiply, divide, modulo\n"
	       "  sdiv smod         signed divide, signed modulo\n"
	       "  + -               add, subtract (unary - negates)\n"
	       "  << >>             logical shift left, right\n"
	       "  sar               arithmetic (sign-extending) shift right\n"
	       "  <<< >>>           rotate left, right\n"
	       "  & | ^ ~           and, or, xor, not\n"
	       "  < <= > >= == !=   comparisons, yielding 0 or 1\n"
	       "  ?:                ternary   (cond ? a : b)\n"
	       "\n" Color_CYAN "Literals" Color_RESET "\n"
	       "  0x 0o 0t 0b       hex, octal, ternary, binary\n"
	       "  uN                bit-vector of N bits   (5u8, 1u32, 3u1024)\n"
	       "  KiB MiB GiB ...   size units             (4KiB)\n"
	       "  fn(...)           built-ins: min max gcd sqrt log2 popcount clz ctz ...\n"
	       "\nSee the rz-ax(1) man page for the complete reference.\n");
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
		default:
			// A numeric but unsupported output base (=4, =7, ...) used to be
			// dropped silently, leaving the result in the default base. Report
			// it and mark the base invalid so the following expression is not
			// printed in a misleading base.
			eprintf("rz-ax: invalid output base '%s' (use =2, =3, =8, =10, or =16)\n", str + 1);
			*fm = RZ_AX_INVALID_BASE;
			return true;
		}
		*fm = force_mode;
		return true;
	}

	if (*str == '-') {
		while (str[1] && str[1] != ' ') {
			switch (str[1]) {
			case 'l': break;
			case 'h': return help(false);
			case 'H': return help(true);
			case 'a': print_ascii_table(); return true;
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
			case 'W': flags ^= RZ_AX_FLAG_WIN_TIMESTAMP_TO_STR; break;
			case 'v': {
				RzPath *sys_path = rz_path_new();
				if (!sys_path) {
					break;
				}
				rz_main_version_print(sys_path, "rz-ax");
				rz_path_free(sys_path);
				// Printing the version is not a conversion failure.
				return true;
			}
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
				return help(false);
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
		if (*str == 'h' || *str == '?') {
			return help(false);
		}
		if (*str == 'H') {
			return help(true);
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
		ut64 n = 0;
		if (!rax_eval_u64(num, str, &n)) {
			return false;
		}
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
		RzNumValue v;
		if (!rax_eval(num, str, &v)) {
			return false;
		}
		// Runs are reported over the value's own width, so a bit-vector
		// literal wider than 64 bits is covered in full.
		ut32 width = 64;
		if (v.kind == RZ_NUM_KIND_BITVECTOR && v.val.bv) {
			width = v.val.bv->len;
		}
		ut64 n = rz_num_value_to_ut64(&v);
		ut32 run_start = 0;
		bool in_run = false, any = false;
		for (ut32 i = 0; i <= width; i++) {
			bool set = false;
			if (i < width) {
				set = (v.kind == RZ_NUM_KIND_BITVECTOR && v.val.bv)
					? rz_bv_get(v.val.bv, i)
					: (i < 64 && ((n >> i) & 1));
			}
			if (set && !in_run) {
				run_start = i;
				in_run = true;
			} else if (!set && in_run) {
				if (run_start == i - 1) {
					printf("[%u]: 1\n", run_start);
				} else {
					printf("[%u-%u]: 1\n", run_start, i - 1);
				}
				in_run = false;
				any = true;
			}
		}
		if (!any) {
			printf("no bits set\n");
		}
		rz_num_value_fini(&v);
		return true;
	} else if (has_flag(flags, RZ_AX_FLAG_SIGNED_WORD)) { // -w
		ut64 n = 0;
		if (!rax_eval_u64(num, str, &n)) {
			return false;
		}
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
		RzNumValue v;
		if (!rax_eval(num, str, &v)) {
			return false;
		}
		// A bit-vector literal carries its own width, so emit exactly that
		// many bytes; a plain integer keeps the historical 4-or-8 choice.
		ut32 nbytes = 4;
		if (v.kind == RZ_NUM_KIND_BITVECTOR && v.val.bv) {
			nbytes = (v.val.bv->len + 7) / 8;
		} else if (rz_num_value_to_ut64(&v) >> 32) {
			nbytes = 8;
		}
		ut8 *bytes = calloc(nbytes, 1);
		if (!bytes) {
			rz_num_value_fini(&v);
			return false;
		}
		if (v.kind == RZ_NUM_KIND_BITVECTOR && v.val.bv) {
			for (ut32 i = 0; i < v.val.bv->len; i++) {
				if (rz_bv_get(v.val.bv, i)) {
					bytes[i / 8] |= 1 << (i % 8);
				}
			}
		} else {
			ut64 n = rz_num_value_to_ut64(&v);
			for (ut32 i = 0; i < nbytes; i++) {
				bytes[i] = (ut8)(n >> (8 * i));
			}
		}
		if (has_flag(flags, RZ_AX_FLAG_HEX_TO_RAW)) {
			fwrite(bytes, nbytes, 1, stdout);
		} else {
			for (ut32 i = 0; i < nbytes; i++) {
				printf("\\x%02x", bytes[i]);
			}
			printf("\n");
		}
		free(bytes);
		rz_num_value_fini(&v);
		return true;
	} else if (has_flag(flags, RZ_AX_FLAG_UNITS)) { // -u
		char buf[8];
		ut64 n = 0;
		if (!rax_eval_u64(num, str, &n)) {
			return false;
		}
		rz_num_units(buf, sizeof(buf), n);
		printf("%s\n", buf);
		return true;
	} else if (is_timestamp(flags)) { // -t, -m, -W
		RzList *split = rz_str_split_list(str, "GMT", 0);
		RzListIter *head = rz_list_head(split);
		rz_return_val_if_fail(head, false);
		char *ts = rz_list_val(head);
		const char *gmt = rz_list_iter_get_next_data(head);
		if (gmt && strlen(gmt) < 2) {
			gmt = NULL;
		}
		ut64 n = 0;
		if (!rax_eval_u64(num, ts, &n)) {
			return false;
		}
		ut64 tzv = 0;
		if (gmt && !rax_eval_u64(num, gmt, &tzv)) {
			return false;
		}
		int timezone = (int)tzv;
		n += timezone * (60 * 60);
		char *date = NULL;
		if (has_flag(flags, RZ_AX_FLAG_TIMESTAMP_TO_STR)) {
			date = rz_time_date_unix_to_string((ut32)n);
		} else if (has_flag(flags, RZ_AX_FLAG_DOS_TIMESTAMP_TO_STR)) {
			date = rz_time_date_dos_to_string((ut32)n);
		} else {
			date = rz_time_date_w32_to_string(n);
		}
		rz_list_free(split);
		if (date != NULL) {
			printf("%s\n", date);
			fflush(stdout);
			free(date);
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
		ut64 n = 0;
		if (!rax_eval_u64(num, str, &n)) {
			return false;
		}

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

		ut64 n = 0;
		bool eval_ok = rax_eval_u64(num, modified_str, &n);
		free(modified_str);
		if (!eval_ok) {
			return false;
		}
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
			ut64 ipv = 0;
			if (!rax_eval_u64(num, str, &ipv)) {
				return false;
			}
			ut32 ip32 = (ut32)ipv;
			ut8 ip[4] = { ip32 & 0xff, (ip32 >> 8) & 0xff, (ip32 >> 16) & 0xff, ip32 >> 24 };
			printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
		}
		return true;
	}

	// A bare literal in a non-decimal base prints as decimal, preserving the
	// rax2 "show the other base" conversion; everything else, including any
	// compound expression, keeps the default hex output so the radix stays
	// predictable for scripting.
	size_t prefix_len = 0;
	ut32 lit_base = 10;
	bool bare_literal = rz_num_base_prefix(str, &lit_base, &prefix_len) != RZ_NUM_BASE_PREFIX_NONE && str[prefix_len];
	for (const char *q = str + prefix_len; bare_literal && *q; q++) {
		if (!is_digit_in_base((ut8)*q, lit_base)) {
			bare_literal = false;
		}
	}
	const char *consumed_prefix = NULL;
	if (bare_literal) {
		out_mode = (has_flag(flags, RZ_AX_FLAG_KEEP_BASE)) ? '0' : 'I';
	} else if (rz_str_startswith(str, "b")) {
		out_mode = 'B';
		consumed_prefix = "b";
		str++;
	} else if (rz_str_startswith(str, "t")) {
		out_mode = 'T';
		consumed_prefix = "t";
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
	} else if (isdigit((ut8)str[0]) && rz_str_endswith(str, "d")) {
		out_mode = 'I';
		str[strlen(str) - 1] = 'b';
		// TODO: Move print into format_output
	} else if (isdigit((ut8)str[0]) && rz_str_endswith(str, "f")) {
		out_mode = 'l';
	} else if (isdigit((ut8)str[0]) && rz_str_endswith(str, "dt")) {
		out_mode = 'I';
		str[strlen(str) - 2] = 't';
		str[strlen(str) - 1] = '\0';
	}
	if (consumed_prefix && !*str) {
		// A lone output-mode prefix (`rz-ax b`, `rz-ax t`) has nothing to
		// convert; without this it printed nothing and exited 0.
		eprintf("rz-ax: missing value after '%s'\n", consumed_prefix);
		return false;
	}
	// The RzNum grammar accepts internal whitespace, so an argument like
	// "1 + 2" is a single expression. Try the whole space-containing string
	// first and only fall back to the historical "whitespace separates
	// independent values" splitting when that parse fails, so both
	// `rz-ax '1 + 2'` (-> 3) and `rz-ax '10 0x20'` (two values) keep working.
	if (strchr(str, ' ')) {
		RzNumValue probe;
		rz_num_value_init(&probe);
		char *whole_err = NULL;
		bool whole_ok = rz_num_math_value(num, str, &probe, &whole_err);
		rz_num_value_fini(&probe);
		if (whole_ok) {
			free(whole_err);
			return format_output(num, out_mode, str, *fm, flags);
		}
		// The whole string is not one expression. Only fall back to the
		// historical "whitespace separates independent values" splitting if
		// every piece parses on its own; otherwise this was a single bad
		// expression and its own diagnostic is the useful one, rather than
		// one error per fragment.
		bool split_ok = true;
		char *probe_str = rz_str_dup(str);
		if (probe_str) {
			char *tok = probe_str;
			char *sp = NULL;
			while (split_ok) {
				sp = strchr(tok, ' ');
				if (sp) {
					*sp = 0;
				}
				if (*tok) {
					RzNumValue piece;
					rz_num_value_init(&piece);
					char *piece_err = NULL;
					split_ok = rz_num_math_value(num, tok, &piece, &piece_err);
					rz_num_value_fini(&piece);
					free(piece_err);
				}
				if (!sp) {
					break;
				}
				tok = sp + 1;
			}
			free(probe_str);
		}
		if (!split_ok) {
			eprintf("rz-ax: %s\n", whole_err ? whole_err : "evaluation failed");
			free(whole_err);
			return false;
		}
		free(whole_err);
	}
	bool all_ok = true;
	while ((p = strchr(str, ' '))) {
		*p = 0;
		if (*str && !format_output(num, out_mode, str, *fm, flags)) {
			all_ok = false;
		}
		str = p + 1;
	}
	if (*str && !format_output(num, out_mode, str, *fm, flags)) {
		all_ok = false;
	}
	return all_ok;
}

RZ_API int rz_main_rz_ax(int argc, const char **argv) {
	int i, fm = 0;
	RzNum *num = rz_num_new(NULL, NULL, NULL);
	ut64 flags = 0;
	bool ok = true;
	if (argc == 1) {
		use_stdin(num, &flags, &fm);
	} else {
		for (i = 1; i < argc; i++) {
			char *argv_i = rz_str_dup(argv[i]);
			rz_str_unescape(argv_i);
			if (!rax(num, argv_i, 0, i == argc - 1, &flags, &fm)) {
				ok = false;
			}
			free(argv_i);
		}
	}
	rz_num_free(num);
	num = NULL;
	return ok ? 0 : 1;
}
