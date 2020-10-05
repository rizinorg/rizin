/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <rz_core.h>
#include <rz_main.h>

#ifdef _MSC_VER
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

enum {
	MODE_DIFF,
	MODE_DIFF_STRS,
	MODE_DIFF_IMPORTS,
	MODE_DIST,
	MODE_DIST_MYERS,
	MODE_DIST_LEVENSTEIN,
	MODE_CODE,
	MODE_GRAPH,
	MODE_COLS,
	MODE_COLSII
};

enum {
        GRAPH_DEFAULT_MODE,
        GRAPH_SDB_MODE,
        GRAPH_JSON_MODE,
        GRAPH_JSON_DIS_MODE,
        GRAPH_TINY_MODE,
        GRAPH_INTERACTIVE_MODE,
        GRAPH_DOT_MODE,
        GRAPH_STAR_MODE,
        GRAPH_GML_MODE
};

static bool zignatures = false;
static const char *file = NULL;
static const char *file2 = NULL;
static ut32 count = 0;
static int showcount = 0;
static int useva = true;
static int delta = 0;
static int showbare = false;
static int json_started = 0;
static int diffmode = 0;
static bool disasm = false;
static bool pdc = false;
static bool quiet = false;
static RzCore *core = NULL;
static const char *arch = NULL;
const char *runcmd = NULL;
static int bits = 0;
static int anal_all = 0;
static bool verbose = false;
static RzList *evals = NULL;

static RzCore *opencore(const char *f) {
	RzListIter *iter;
	const ut64 baddr = UT64_MAX;
	const char *e;
	RzCore *c = rz_core_new ();
	if (!c) {
		return NULL;
	}
	rz_core_loadlibs (c, RZ_CORE_LOADLIBS_ALL, NULL);
	rz_config_set_i (c->config, "io.va", useva);
	rz_config_set_i (c->config, "scr.interactive", false);
	rz_list_foreach (evals, iter, e) {
		rz_config_eval (c->config, e, false);
	}
	if (f) {
		RzCoreFile * rfile = NULL;
#if __WINDOWS__
		char *winf = rz_acp_to_utf8 (f);
		rfile = rz_core_file_open (c, winf, 0, 0);
		free (winf);
#else
		rfile = rz_core_file_open (c, f, 0, 0);
#endif

		if (!rfile) {
			rz_core_free (c);
			return NULL;
		}
		(void) rz_core_bin_load (c, NULL, baddr);
		(void) rz_core_bin_update_arch_bits (c);

		// force PA mode when working with raw bins
		if (rz_list_empty (rz_bin_get_sections (c->bin))) {
			rz_config_set_i (c->config, "io.va", false);
		}

		if (anal_all) {
			const char *cmd = "aac";
			switch (anal_all) {
			case 1: cmd = "aaa"; break;
			case 2: cmd = "aaaa"; break;
			}
			rz_core_cmd0 (c, cmd);
		}
		if (runcmd) {
			rz_core_cmd0 (c, runcmd);
		}
		// generate zignaturez?
		if (zignatures) {
			rz_core_cmd0 (c, "zg");
		}
		rz_cons_flush ();
	}
	// TODO: must enable io.va here if wanted .. rz_config_set_i (c->config, "io.va", va);
	return c;
}

static void readstr(char *s, int sz, const ut8 *buf, int len) {
	*s = 0;
	int last = RZ_MIN (len, sz);
	if (last < 1) {
		return;
	}
	s[sz - 1] = 0;
	while (*s && *s == '\n') {
		s++;
	}
	strncpy (s, (char *) buf, last);
}

static int cb(RzDiff *d, void *user, RzDiffOp *op) {
	int i; // , diffmode = (int)(size_t)user;
	char s[256] = {0};
	if (showcount) {
		count++;
		return 1;
	}
	switch (diffmode) {
	case 'U': // 'U' in theory never handled here
	case 'u':
		if (op->a_len > 0) {
			readstr (s, sizeof (s), op->a_buf, op->a_len);
			if (*s) {
				if (!quiet) {
					printf (Color_RED);
				}
				printf ("-0x%08"PFMT64x":", op->a_off);
				int len = op->a_len; // RZ_MIN (op->a_len, strlen (op->a_buf));
				for (i = 0; i < len; i++) {
					printf ("%02x ", op->a_buf[i]);
				}
				if (!quiet) {
					char *p = rz_str_escape ((const char*)op->a_buf);
					printf (" \"%s\"", p);
					free (p);
					printf (Color_RESET);
				}
				printf ("\n");
			}
		}
		if (op->b_len > 0) {
			readstr (s, sizeof (s), op->b_buf, op->b_len);
			if (*s) {
				if (!quiet) {
					printf (Color_GREEN);
				}
				printf ("+0x%08"PFMT64x":", op->b_off);
				for (i = 0; i < op->b_len; i++) {
					printf ("%02x ", op->b_buf[i]);
				}
				if (!quiet) {
					char *p = rz_str_escape((const char*)op->b_buf);
					printf (" \"%s\"", p);
					free (p);
					printf (Color_RESET);
				}
				printf ("\n");
			}
		}
		break;
	case 'r':
		if (disasm) {
			eprintf ("rzcmds (-r) + disasm (-D) not yet implemented\n");
		}
		if (op->a_len == op->b_len) {
			printf ("wx ");
			for (i = 0; i < op->b_len; i++) {
				printf ("%02x", op->b_buf[i]);
			}
			printf (" @ 0x%08"PFMT64x "\n", op->b_off);
		} else {
			if (op->a_len > 0) {
				printf ("r-%d @ 0x%08"PFMT64x "\n",
					op->a_len, op->a_off + delta);
			}
			if (op->b_len > 0) {
				printf ("r+%d @ 0x%08"PFMT64x "\n",
					op->b_len, op->b_off + delta);
				printf ("wx ");
				for (i = 0; i < op->b_len; i++) {
					printf ("%02x", op->b_buf[i]);
				}
				printf (" @ 0x%08"PFMT64x "\n", op->b_off + delta);
			}
			delta += (op->b_off - op->a_off);
		}
		return 1;
	case 'j':
		if (disasm) {
			eprintf ("JSON (-j) + disasm (-D) not yet implemented\n");
		}
		if (json_started) {
			printf (",\n");
		}
		json_started = 1;
		printf ("{\"offset\":%"PFMT64d ",", op->a_off);
		printf ("\"from\":\"");
		for (i = 0; i < op->a_len; i++) {
			printf ("%02x", op->a_buf[i]);
		}
		printf ("\", \"to\":\"");
		for (i = 0; i < op->b_len; i++) {
			printf ("%02x", op->b_buf[i]);
		}
		printf ("\"}"); // ,\n");
		return 1;
	case 0:
	default:
		if (disasm) {
			int i;
			printf ("--- 0x%08"PFMT64x "  ", op->a_off);
			if (!core) {
				core = opencore (file);
				if (arch) {
					rz_config_set (core->config, "asm.arch", arch);
				}
				if (bits) {
					rz_config_set_i (core->config, "asm.bits", bits);
				}
			}
			for (i = 0; i < op->a_len; i++) {
				printf ("%02x", op->a_buf[i]);
			}
			printf ("\n");
			if (core) {
				int len = RZ_MAX (4, op->a_len);
				RzAsmCode *ac = rz_asm_mdisassemble (core->rasm, op->a_buf, len);
				char *acbufasm = strdup (ac->assembly);
				if (quiet) {
					char *bufasm = rz_str_prefix_all (acbufasm, "- ");
					printf ("%s\n", bufasm);
					free (bufasm);
				} else {
					char *bufasm = rz_str_prefix_all (acbufasm, Color_RED"- ");
					printf ("%s"Color_RESET, bufasm);
					free (bufasm);
				}
				free (acbufasm);
				rz_asm_code_free (ac);
			}
		} else {
			printf ("0x%08"PFMT64x " ", op->a_off);
			for (i = 0; i < op->a_len; i++) {
				printf ("%02x", op->a_buf[i]);
			}
		}
		if (disasm) {
			int i;
			printf ("+++ 0x%08"PFMT64x "  ", op->b_off);
			if (!core) {
				core = opencore (NULL);
			}
			for (i = 0; i < op->b_len; i++) {
				printf ("%02x", op->b_buf[i]);
			}
			printf ("\n");
			if (core) {
				int len = RZ_MAX (4, op->b_len);
				RzAsmCode *ac = rz_asm_mdisassemble (core->rasm, op->b_buf, len);
				char *acbufasm = strdup (ac->assembly);
				if (quiet) {
					char *bufasm = rz_str_prefix_all (acbufasm, "+ ");
					printf ("%s\n", bufasm);
					free (bufasm);
					free (acbufasm);
				} else {
					char *bufasm = rz_str_prefix_all (acbufasm, Color_GREEN"+ ");
					printf ("%s\n" Color_RESET, bufasm);
					free (bufasm);
					free (acbufasm);
				}
				// rz_asm_code_free (ac);
			}
		} else {
			printf (" => ");
			for (i = 0; i < op->b_len; i++) {
				printf ("%02x", op->b_buf[i]);
			}
			printf (" 0x%08"PFMT64x "\n", op->b_off);
		}
		return 1;
	}
	return 0;
}

static ut64 gdiff_start = 0;

void print_bytes(const void *p, size_t len, bool big_endian) {
	size_t i;
	for (i = 0; i < len; i++) {
		ut8 ch = ((ut8*) p)[big_endian ? (len - i - 1) : i];
		if (write (1, &ch, 1) != 1) {
			break;
		}
	}
}

static int bcb(RzDiff *d, void *user, RzDiffOp *op) {
	ut64 offset_diff = op->a_off - gdiff_start;
	unsigned char opcode;
	unsigned short USAddr = 0;
	int IAddr = 0;
	unsigned char UCLen = 0;
	unsigned short USLen = 0;
	int ILen = 0;

	// we copy from gdiff_start to a_off
	if (offset_diff > 0) {

		// size for the position
		if (gdiff_start <= USHRT_MAX) {
			opcode = 249;
			USAddr = (unsigned short) gdiff_start;
		} else if (gdiff_start <= INT_MAX) {
			opcode = 252;
			IAddr = (int) gdiff_start;
		} else {
			opcode = 255;
		}

		// size for the length
		if (opcode != 255 && offset_diff <= UCHAR_MAX) {
			UCLen = (unsigned char) offset_diff;
		} else if (opcode != 255 && offset_diff <= USHRT_MAX) {
			USLen = (unsigned short) offset_diff;
			opcode += 1;
		} else if (opcode != 255 && offset_diff <= INT_MAX) {
			ILen = (int) offset_diff;
			opcode += 2;
		} else if (offset_diff > INT_MAX) {
			int times = offset_diff / INT_MAX;
			int max = INT_MAX;
			size_t i;
			for (i = 0; i < times; i++) {
				print_bytes (&opcode, sizeof (opcode), true);
				// XXX this is overflowingly wrong
				// XXX print_bytes (&gdiff_start + i * max, sizeof (gdiff_start), true);
				print_bytes (&max, sizeof (max), true);
			}
		}

		// print opcode for COPY
		print_bytes (&opcode, sizeof (opcode), true);

		// print position for COPY
		if (opcode <= 251) {
			print_bytes (&USAddr, sizeof (USAddr), true);
		} else if (opcode < 255) {
			print_bytes (&IAddr, sizeof (IAddr), true);
		} else {
			print_bytes (&gdiff_start, sizeof (gdiff_start), true);
		}

		// print length for COPY
		switch (opcode) {
		case 249:
		case 252:
			print_bytes (&UCLen, sizeof (UCLen), true);
			break;
		case 250:
		case 253:
			print_bytes (&USLen, sizeof (USLen), true);
			break;
		case 251:
		case 254:
		case 255:
			print_bytes (&ILen, sizeof (ILen), true);
			break;
		}
	}

	// we append data
	if (op->b_len <= 246) {
		ut8 data = op->b_len;
		(void) write (1, &data, 1);
	} else if (op->b_len <= USHRT_MAX) {
		USLen = (ut16) op->b_len;
		ut8 data = 247;
		(void) write (1, &data, 1);
		print_bytes (&USLen, sizeof (USLen), true);
	} else if (op->b_len <= INT_MAX) {
		ut8 data = 248;
		(void) write (1, &data, 1);
		ILen = (int) op->b_len;
		print_bytes (&ILen, sizeof (ILen), true);
	} else {
		// split into multiple DATA, because op->b_len is greater than INT_MAX
		int times = op->b_len / INT_MAX;
		int max = INT_MAX;
		size_t i;
		for (i = 0; i < times; i++) {
			ut8 data = 248;
			if (write (1, &data, 1) != 1) {
				break;
			}
			print_bytes (&max, sizeof (max), true);
			print_bytes (op->b_buf, max, false);
			op->b_buf += max;
		}
		op->b_len = op->b_len % max;

		// print the remaining size
		int remain_size = op->b_len;
		print_bytes(&remain_size, sizeof(remain_size), true);
	}
	print_bytes(op->b_buf, op->b_len, false);
	gdiff_start = op->b_off + op->b_len;
	return 0;
}

static int show_help(int v) {
	printf ("Usage: rz-diff [-abBcCdjrspOxuUvV] [-A[A]] [-g sym] [-m graph_mode][-t %%] [file] [file]\n");
	if (v) {
		printf (
			"  -a [arch]  specify architecture plugin to use (x86, arm, ..)\n"
			"  -A [-A]    run aaa or aaaa after loading each binary (see -C)\n"
			"  -b [bits]  specify register size for arch (16 (thumb), 32, 64, ..)\n"
			"  -B         output in binary diff (GDIFF)\n"
			"  -c         count of changes\n"
			"  -C         graphdiff code (columns: off-A, match-ratio, off-B) (see -A)\n"
			"  -d         use delta diffing\n"
			"  -D         show disasm instead of hexpairs\n"
			"  -e [k=v]   set eval config var value for all RzCore instances\n"
			"  -g [sym|off1,off2]   graph diff of given symbol, or between two offsets\n"
			"  -G [cmd]   run an rz command on every RzCore instance created\n"
			"  -i         diff imports of target files (see -u, -U and -z)\n"
			"  -j         output in json format\n"
			"  -n         print bare addresses only (diff.bare=1)\n"
                        "  -m [aditsjJ]  choose the graph output mode\n"
			"  -O         code diffing with opcode bytes only\n"
			"  -p         use physical addressing (io.va=0)\n"
			"  -q         quiet mode (disable colors, reduce output)\n"
			"  -r         output in radare commands\n"
			"  -s         compute edit distance (no substitution, Eugene W. Myers' O(ND) diff algorithm)\n"
			"  -ss        compute Levenshtein edit distance (substitution is allowed, O(N^2))\n"
			"  -S [name]  sort code diff (name, namelen, addr, size, type, dist) (only for -C or -g)\n"
			"  -t [0-100] set threshold for code diff (default is 70%%)\n"
			"  -x         show two column hexdump diffing\n"
			"  -X         show two column hexII diffing\n"
			"  -u         unified output (---+++)\n"
			"  -U         unified output using system 'diff'\n"
			"  -v         show version information\n"
			"  -V         be verbose (current only for -s)\n"
			"  -z         diff on extracted strings\n"
			"  -Z         diff code comparing zignatures\n\n"
                       "Graph Output formats: (-m [mode])\n"
		        "  <blank/a>  Ascii art\n"
	                "  s          rz commands\n"
		        "  d          Graphviz dot\n"
	                "  g          Graph Modelling Language (gml)\n"
		        "  j          json\n"
	                "  J          json with disarm\n"
		        "  k          SDB key-value\n"
	                "  t          Tiny ascii art\n"
		        "  i          Interactive ascii art\n");
	}
	return 1;
}

#define DUMP_CONTEXT 2
static void dump_cols(ut8 *a, int as, ut8 *b, int bs, int w) {
	ut32 sz = RZ_MIN (as, bs);
	ut32 i, j;
	int ctx = DUMP_CONTEXT;
	int pad = 0;
	if (!a || !b || as < 0 || bs < 0) {
		return;
	}
	switch (w) {
	case 8:
		rz_cons_printf ("  offset     0 1 2 3 4 5 6 7 01234567    0 1 2 3 4 5 6 7 01234567\n");
		break;
	case 16:
		rz_cons_printf ("  offset     "
			"0 1 2 3 4 5 6 7 8 9 A B C D E F 0123456789ABCDEF    "
			"0 1 2 3 4 5 6 7 8 9 A B C D E F 0123456789ABCDEF\n");
		break;
	default:
		eprintf ("Invalid column width\n");
		return;
	}
	rz_cons_break_push (NULL, NULL);
	for (i = 0; i < sz; i += w) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (i + w >= sz) {
			pad = w - sz + i;
			w = sz - i;
		}
		bool eq = !memcmp (a + i, b + i, w);
		if (eq) {
			ctx--;
			if (ctx == -1) {
				rz_cons_printf ("...\n");
				continue;
			}
			if (ctx < 0) {
				ctx = -1;
				continue;
			}
		} else {
			ctx = DUMP_CONTEXT;
		}
		rz_cons_printf (eq? Color_GREEN: Color_RED);
		rz_cons_printf ("0x%08x%c ", i, eq? ' ': '!');
		rz_cons_printf (Color_RESET);
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				rz_cons_printf (eq2? Color_GREEN: Color_RED);
			}
			rz_cons_printf ("%02x", a[i + j]);
			if (!eq) {
				rz_cons_printf (Color_RESET);
			}
		}
		for (j = 0; j < pad; j++) {
			rz_cons_printf ("  ");
		}
		rz_cons_printf (" ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				rz_cons_printf (eq2? Color_GREEN: Color_RED);
			}
			rz_cons_printf ("%c", IS_PRINTABLE (a[i + j])? a[i + j]: '.');
			if (!eq) {
				rz_cons_printf (Color_RESET);
			}
		}
		for (j = 0; j < pad; j++) {
			rz_cons_printf (" ");
		}
		rz_cons_printf ("   ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				rz_cons_printf (eq2? Color_GREEN: Color_RED);
			}
			rz_cons_printf ("%02x", b[i + j]);
			if (!eq) {
				rz_cons_printf (Color_RESET);
			}
		}
		for (j = 0; j < pad; j++) {
			rz_cons_printf ("  ");
		}
		rz_cons_printf (" ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				rz_cons_printf (eq2? Color_GREEN: Color_RED);
			}
			rz_cons_printf ("%c", IS_PRINTABLE (b[i + j])? b[i + j]: '.');
			if (!eq) {
				rz_cons_printf (Color_RESET);
			}
		}
		rz_cons_printf ("\n");
		rz_cons_flush ();
	}
	rz_cons_break_end ();
	rz_cons_printf ("\n"Color_RESET);
	rz_cons_flush ();
	if (as != bs) {
		rz_cons_printf ("...\n");
	}
}

static void dump_cols_hexii(ut8 *a, int as, ut8 *b, int bs, int w) {
	bool spacy = false;
	ut32 sz = RZ_MIN (as, bs);
	ut32 i, j;
	int ctx = DUMP_CONTEXT;
	int pad = 0;
	if (!a || !b || as < 0 || bs < 0) {
		return;
	}
	PrintfCallback p = rz_cons_printf;
	rz_cons_break_push (NULL, NULL);
	for (i = 0; i < sz; i += w) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (i + w >= sz) {
			pad = w - sz + i;
			w = sz - i;
		}
		bool eq = !memcmp (a + i, b + i, w);
		if (eq) {
			ctx--;
			if (ctx == -1) {
				rz_cons_printf ("...\n");
				continue;
			}
			if (ctx < 0) {
				ctx = -1;
				continue;
			}
		} else {
			ctx = DUMP_CONTEXT;
		}
		rz_cons_printf (eq? Color_GREEN: Color_RED);
		rz_cons_printf ("0x%08x%c ", i, eq? ' ': '!');
		rz_cons_printf (Color_RESET);
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				rz_cons_printf (eq2? Color_GREEN: Color_RED);
			}
			ut8 ch = a[i + j];
			if (spacy) {
				p (" ");
			}
			if (ch == 0x00) {
				p ("  ");
			} else if (ch == 0xff) {
				p ("##");
			} else if (IS_PRINTABLE (ch)) {
				p (".%c", ch);
			} else {
				p ("%02x", ch);
			}
			if (!eq) {
				rz_cons_printf (Color_RESET);
			}
		}
		for (j = 0; j < pad; j++) {
			rz_cons_printf ("  ");
		}
		for (j = 0; j < pad; j++) {
			rz_cons_printf (" ");
		}
		rz_cons_printf ("   ");
		for (j = 0; j < w; j++) {
			bool eq2 = a[i + j] == b[i + j];
			if (!eq) {
				rz_cons_printf (eq2? Color_GREEN: Color_RED);
			}
			ut8 ch = b[i + j];
			if (spacy) {
				p (" ");
			}
			if (ch == 0x00) {
				p ("  ");
			} else if (ch == 0xff) {
				p ("##");
			} else if (IS_PRINTABLE (ch)) {
				p (".%c", ch);
			} else {
				p ("%02x", ch);
			}
			if (!eq) {
				rz_cons_printf (Color_RESET);
			}
		}
		for (j = 0; j < pad; j++) {
			rz_cons_printf ("  ");
		}
		rz_cons_printf ("\n");
		rz_cons_flush ();
	}
	rz_cons_break_end ();
	rz_cons_printf ("\n"Color_RESET);
	rz_cons_flush ();
	if (as != bs) {
		rz_cons_printf ("...\n");
	}
}

static void handle_sha256(const ut8 *block, int len) {
	int i = 0;
	RzHash *ctx = rz_hash_new (true, RZ_HASH_SHA256);
	const ut8 *c = rz_hash_do_sha256 (ctx, block, len);
	if (!c) {
		rz_hash_free (ctx);
		return;
	}
	for (i = 0; i < RZ_HASH_SIZE_SHA256; i++) {
		printf ("%02x", c[i]);
	}
	rz_hash_free (ctx);
}

static ut8 *slurp(RzCore **c, const char *file, size_t *sz) {
	RzIODesc *d;
	RzIO *io;
	if (c && file && strstr (file, "://")) {
		ut8 *data = NULL;
		ut64 size;
		if (!*c) {
			*c = opencore (NULL);
		}
		if (!*c) {
			eprintf ("opencore failed\n");
			return NULL;
		}
		io = (*c)->io;
		d = rz_io_open (io, file, 0, 0);
		if (!d) {
			return NULL;
		}
		size = rz_io_size (io);
		if (size > 0 && size < ST32_MAX) {
			data = calloc (1, size);
			if (rz_io_read_at (io, 0, data, size)) {
				if (sz) {
					*sz = size;
				}
			} else {
				eprintf ("slurp: read error\n");
				RZ_FREE (data);
			}
		} else {
			eprintf ("slurp: Invalid file size\n");
		}
		rz_io_desc_close (d);
		return data;
	}
	return (ut8 *) rz_file_slurp (file, sz);
}

static int import_cmp(const RBinImport *a, const RBinImport *b) {
	return strcmp (a->name, b->name);
}

static ut8 *get_imports(RzCore *c, int *len) {
	RzListIter *iter;
	RBinImport *str, *old = NULL;
	ut8 *buf, *ptr;

	if (!c || !len) {
		return NULL;
	}

	RzList *list = rz_bin_get_imports (c->bin);
	rz_list_sort (list, (RzListComparator) import_cmp);

	*len = 0;

	rz_list_foreach (list, iter, str) {
		if (!old || (old && import_cmp (old, str) != 0)) {
			*len += strlen (str->name) + 1;
			old = str;
		}
	}
	ptr = buf = malloc (*len + 1);
	if (!ptr) {
		return NULL;
	}

	old = NULL;

	rz_list_foreach (list, iter, str) {
		if (old && !import_cmp (old, str)) {
			continue;
		}
		int namelen = strlen (str->name);
		memcpy (ptr, str->name, namelen);
		ptr += namelen;
		*ptr++ = '\n';
		old = str;
	}
	*ptr = 0;

	*len = strlen ((const char *) buf);
	return buf;
}

static int bs_cmp(const RBinString *a, const RBinString *b) {
	int diff = a->length - b->length;
	return diff == 0? strncmp (a->string, b->string, a->length): diff;
}

static ut8 *get_strings(RzCore *c, int *len) {
	RzList *list = rz_bin_get_strings (c->bin);
	RzListIter *iter;
	RBinString *str, *old = NULL;
	ut8 *buf, *ptr;

	rz_list_sort (list, (RzListComparator) bs_cmp);

	*len = 0;

	rz_list_foreach (list, iter, str) {
		if (!old || (old && bs_cmp (old, str) != 0)) {
			*len += str->length + 1;
			old = str;
		}
	}

	ptr = buf = malloc (*len + 1);
	if (!ptr) {
		return NULL;
	}

	old = NULL;

	rz_list_foreach (list, iter, str) {
		if (old && bs_cmp (old, str) == 0) {
			continue;
		}
		memcpy (ptr, str->string, str->length);
		ptr += str->length;
		*ptr++ = '\n';
		old = str;
	}
	*ptr = 0;

	*len = strlen ((const char *) buf);
	return buf;
}

static char *get_graph_commands(RzCore *c, ut64 off) {
        bool tmp_html = rz_cons_singleton ()->is_html;
        rz_cons_singleton ()->is_html = false;
        rz_cons_push ();
        rz_core_anal_graph (c, off, RZ_CORE_ANAL_GRAPHBODY | RZ_CORE_ANAL_GRAPHDIFF |  RZ_CORE_ANAL_STAR);
        const char *static_str = rz_cons_get_buffer ();
        char *retstr = strdup (static_str? static_str: "");
        rz_cons_pop ();
        rz_cons_echo (NULL);
        rz_cons_singleton ()->is_html = tmp_html;
        return retstr;
}

static void __generate_graph (RzCore *c, ut64 off) {
        rz_return_if_fail (c);
        char *ptr = get_graph_commands (c, off);
	char *str = ptr;
        rz_cons_break_push (NULL, NULL);
        if (str) {
                for (;;) {
                        if (rz_cons_is_breaked ()) {
                                break;
                        }
                        char *eol = strchr (ptr, '\n');
                        if (eol) {
                                *eol = '\0';
                        }
                        if (*ptr) {
                                char *p = strdup (ptr);
                                if (!p) {
                                        free (str);
                                        return;
                                }
                                rz_core_cmd0 (c, p);
                                free (p);
                        }
                        if (!eol) {
                                break;
                        }
                        ptr = eol + 1;
                }
		free (str);
        }
        rz_cons_break_pop ();
}

static void __print_diff_graph(RzCore *c, ut64 off, int gmode) {
        int opts = RZ_CORE_ANAL_GRAPHBODY | RZ_CORE_ANAL_GRAPHDIFF;
        int use_utf8 = rz_config_get_i (c->config, "scr.utf8");
        rz_agraph_reset(c->graph);
        switch (gmode) {
        case GRAPH_DOT_MODE:
                rz_core_anal_graph (c, off, opts);
                break;
        case GRAPH_STAR_MODE:
                rz_core_anal_graph (c, off, opts |  RZ_CORE_ANAL_STAR);
                break;
        case GRAPH_TINY_MODE:
                __generate_graph (c, off);
                rz_core_agraph_print (c, use_utf8, "t");
                break;
        case GRAPH_INTERACTIVE_MODE:
                __generate_graph (c, off);
                rz_core_agraph_print (c, use_utf8, "v");
                rz_cons_reset_colors ();
                break;
        case GRAPH_SDB_MODE:
                __generate_graph (c, off);
                rz_core_agraph_print (c, use_utf8, "k");
                break;
        case GRAPH_GML_MODE:
                __generate_graph (c, off);
                rz_core_agraph_print (c, use_utf8, "g");
                break;
        case GRAPH_JSON_MODE:
                rz_core_anal_graph (c, off, opts | RZ_CORE_ANAL_JSON);
                break;
        case GRAPH_JSON_DIS_MODE:
                rz_core_anal_graph (c, off, opts | RZ_CORE_ANAL_JSON | RZ_CORE_ANAL_JSON_FORMAT_DISASM);
                break;
        case GRAPH_DEFAULT_MODE:
        default:
                __generate_graph (c, off);
                rz_core_agraph_print (c, use_utf8, "");
                rz_cons_reset_colors ();
        break;
        }
}

RZ_API int rz_main_rz_diff(int argc, const char **argv) {
	const char *columnSort = NULL;
	const char *addr = NULL;
	RzCore *c = NULL, *c2 = NULL;
	RzDiff *d;
	ut8 *bufa = NULL, *bufb = NULL;
	int o, /*diffmode = 0,*/ delta = 0;
	ut64 sza = 0, szb = 0;
	int mode = MODE_DIFF;
	int gmode = GRAPH_DEFAULT_MODE;
	int diffops = 0;
	int threshold = -1;
	double sim = 0.0;
	evals = rz_list_newf (NULL);

	RzGetopt opt;
	rz_getopt_init (&opt, argc, argv, "Aa:b:BCDe:npg:m:G:OijrhcdsS:uUvVxXt:zqZ");
	while ((o = rz_getopt_next (&opt)) != -1) {
		switch (o) {
		case 'a':
			arch = opt.arg;
			break;
		case 'A':
			anal_all++;
			break;
		case 'b':
			bits = atoi (opt.arg);
			break;
		case 'B':
			diffmode = 'B';
			break;
		case 'e':
			rz_list_append (evals, (void*)opt.arg);
			break;
		case 'p':
			useva = false;
			break;
		case 'r':
			diffmode = 'r';
			break;
		case 'g':
			mode = MODE_GRAPH;
			addr = opt.arg;
			break;
		case 'm':{
		        const char *tmp = opt.arg;
		        switch(tmp[0]) {
	                case 'i': gmode = GRAPH_INTERACTIVE_MODE; break;
	                case 'k': gmode = GRAPH_SDB_MODE; break;
	                case 'j': gmode = GRAPH_JSON_MODE; break;
	                case 'J': gmode = GRAPH_JSON_DIS_MODE; break;
	                case 't': gmode = GRAPH_TINY_MODE; break;
	                case 'd': gmode = GRAPH_DOT_MODE; break;
	                case 's': gmode = GRAPH_STAR_MODE; break;
	                case 'g': gmode = GRAPH_GML_MODE; break;
	                case 'a':
                        default: gmode = GRAPH_DEFAULT_MODE; break;
		        }
		}       break;
		case 'G':
			runcmd = opt.arg;
			break;
		case 'c':
			showcount = 1;
			break;
		case 'C':
			mode = MODE_CODE;
			break;
		case 'i':
			mode = MODE_DIFF_IMPORTS;
			break;
		case 'n':
			showbare = true;
			break;
		case 'O':
			diffops = 1;
			break;
		case 't':
			threshold = atoi (opt.arg);
			printf ("%s\n", opt.arg);
			break;
		case 'd':
			delta = 1;
			break;
		case 'D':
			if (disasm) {
				pdc = true;
				disasm = false;
				mode = MODE_CODE;
			} else {
				disasm = true;
			}
			break;
		case 'h':
			return show_help (1);
		case 's':
			if (mode == MODE_DIST) {
				mode = MODE_DIST_LEVENSTEIN;
			} else if (mode == MODE_DIST_LEVENSTEIN) {
				mode = MODE_DIST_MYERS;
			} else {
				mode = MODE_DIST;
			}
			break;
		case 'S':
			columnSort = opt.arg;
			break;
		case 'x':
			mode = MODE_COLS;
			break;
		case 'X':
			mode = MODE_COLSII;
			break;
		case 'u':
			diffmode = 'u';
			break;
		case 'U':
			diffmode = 'U';
			break;
		case 'v':
			return rz_main_version_print ("rz_diff");
		case 'q':
			quiet = true;
			break;
		case 'V':
			verbose = true;
			break;
		case 'j':
			diffmode = 'j';
			break;
		case 'z':
			mode = MODE_DIFF_STRS;
			break;
		case 'Z':
			zignatures = true;
			break;
		default:
			return show_help (0);
		}
	}

	if (argc < 3 || opt.ind + 2 > argc) {
		return show_help (0);
	}
	file = (opt.ind < argc)? argv[opt.ind]: NULL;
	file2 = (opt.ind + 1 < argc)? argv[opt.ind + 1]: NULL;

	if (RZ_STR_ISEMPTY (file) || RZ_STR_ISEMPTY(file2)) {
		eprintf ("Cannot open empty path\n");
		return 1;
	}

	switch (mode) {
	case MODE_GRAPH:
	case MODE_CODE:
	case MODE_DIFF_STRS:
	case MODE_DIFF_IMPORTS:
		c = opencore (file);
		if (!c) {
			eprintf ("Cannot open '%s'\n", rz_str_get (file));
		}
		c2 = opencore (file2);
		if (!c || !c2) {
			eprintf ("Cannot open '%s'\n", rz_str_get (file2));
			return 1;
		}
		c->c2 = c2;
		c2->c2 = c;
		rz_core_parse_rizinrc (c);
		if (arch) {
			rz_config_set (c->config, "asm.arch", arch);
			rz_config_set (c2->config, "asm.arch", arch);
		}
		if (bits) {
			rz_config_set_i (c->config, "asm.bits", bits);
			rz_config_set_i (c2->config, "asm.bits", bits);
		}
		if (columnSort) {
			rz_config_set (c->config, "diff.sort", columnSort);
			rz_config_set (c2->config, "diff.sort", columnSort);
		}
		rz_config_set_i (c->config, "diff.bare", showbare);
		rz_config_set_i (c2->config, "diff.bare", showbare);
		rz_anal_diff_setup_i (c->anal, diffops, threshold, threshold);
		rz_anal_diff_setup_i (c2->anal, diffops, threshold, threshold);
		if (pdc) {
			if (!addr) {
				//addr = "entry0";
				addr = "main";
			}
			/* should be in mode not in bool pdc */
			rz_config_set_i (c->config, "scr.color", COLOR_MODE_DISABLED);
			rz_config_set_i (c2->config, "scr.color", COLOR_MODE_DISABLED);

			ut64 addra = rz_num_math (c->num, addr);
			bufa = (ut8 *) rz_core_cmd_strf (c, "af;pdc @ 0x%08"PFMT64x, addra);
			sza = (ut64)strlen ((const char *) bufa);

			ut64 addrb = rz_num_math (c2->num, addr);
			bufb = (ut8 *) rz_core_cmd_strf (c2, "af;pdc @ 0x%08"PFMT64x, addrb);
			szb = (ut64)strlen ((const char *) bufb);
			mode = MODE_DIFF;
		} else if (mode == MODE_GRAPH) {
			int depth = rz_config_get_i (c->config, "anal.depth");
			if (depth < 1) {
				depth = 64;
			}
			char *words = strdup (addr? addr: "0");
			char *second = strchr (words, ',');
			if (second) {
				*second++ = 0;
				ut64 off = rz_num_math (c->num, words);
				// define the same function at each offset
				rz_core_anal_fcn (c, off, UT64_MAX, RZ_ANAL_REF_TYPE_NULL, depth);
				rz_core_anal_fcn (c2, rz_num_math (c2->num, second),
					UT64_MAX, RZ_ANAL_REF_TYPE_NULL, depth);
				rz_core_gdiff (c, c2);
				__print_diff_graph (c, off, gmode);
			} else {
				rz_core_anal_fcn (c, rz_num_math (c->num, words),
					UT64_MAX, RZ_ANAL_REF_TYPE_NULL, depth);
				rz_core_anal_fcn (c2, rz_num_math (c2->num, words),
					UT64_MAX, RZ_ANAL_REF_TYPE_NULL, depth);
				rz_core_gdiff (c, c2);
				__print_diff_graph (c, rz_num_math (c->num, addr), gmode);
			}
			free (words);
		} else if (mode == MODE_CODE) {
			if (zignatures) {
				rz_core_cmd0 (c, "z~?");
				rz_core_cmd0 (c2, "z~?");
				rz_core_zdiff (c, c2);
			} else {
				rz_core_gdiff (c, c2);
				rz_core_diff_show (c, c2);
			}
		} else if (mode == MODE_DIFF_IMPORTS) {
			int sz;
			bufa = get_imports (c, &sz);
			sza = sz;
			bufb = get_imports (c2, &sz);
			szb = sz;
		} else if (mode == MODE_DIFF_STRS) {
			int sz;
			bufa = get_strings (c, &sz);
			sza = sz;
			bufb = get_strings (c2, &sz);
			szb = sz;
		}
		if (mode == MODE_CODE || mode == MODE_GRAPH) {
			rz_cons_flush ();
		}
		rz_core_free (c);
		rz_core_free (c2);

		if (mode == MODE_CODE || mode == MODE_GRAPH) {
			return 0;
		}
		break;
	default: {
		size_t fsz;
		bufa = slurp (&c, file, &fsz);
		sza = fsz;
		if (!bufa) {
			eprintf ("rz_diff: Cannot open %s\n", rz_str_get (file));
			return 1;
		}
		bufb = slurp (&c, file2, &fsz);
		szb = fsz;
		if (!bufb) {
			eprintf ("rz_diff: Cannot open: %s\n", rz_str_get (file2));
			free (bufa);
			return 1;
		}
		if (sza != szb) {
			eprintf ("File size differs %"PFMT64u" vs %"PFMT64u"\n", (ut64)sza, (ut64)szb);
		}
		break;
	}
	}

	// initialize RzCons
	(void)rz_cons_new ();

	switch (mode) {
	case MODE_COLSII:
		if (!c && !rz_list_empty (evals)) {
			c = opencore (NULL);
		}
		dump_cols_hexii (bufa, (int)sza, bufb, (int)szb, (rz_cons_get_size (NULL) > 112)? 16: 8);
		break;
	case MODE_COLS:
		if (!c && !rz_list_empty (evals)) {
			c = opencore (NULL);
		}
		dump_cols (bufa, (int)sza, bufb, (int)szb, (rz_cons_get_size (NULL) > 112)? 16: 8);
		break;
	case MODE_DIFF:
	case MODE_DIFF_STRS:
	case MODE_DIFF_IMPORTS:
		d = rz_diff_new ();
		rz_diff_set_delta (d, delta);
		if (diffmode == 'j') {
			printf ("{\"files\":[{\"filename\":\"%s\", \"size\":%"PFMT64u", \"sha256\":\"", file, sza);
			handle_sha256 (bufa, (int)sza);
			printf ("\"},\n{\"filename\":\"%s\", \"size\":%"PFMT64u", \"sha256\":\"", file2, szb);
			handle_sha256 (bufb, (int)szb);
			printf ("\"}],\n");
			printf ("\"changes\":[");
		}
		if (diffmode == 'B') {
			(void) write (1, "\xd1\xff\xd1\xff\x04", 5);
		}
		if (diffmode == 'U') {
			char *res = rz_diff_buffers_unified (d, bufa, (int)sza, bufb, (int)szb);
			if (res) {
				printf ("%s", res);
				free (res);
			}
		} else if (diffmode == 'B') {
			rz_diff_set_callback (d, &bcb, 0);
			rz_diff_buffers (d, bufa, (ut32)sza, bufb, (ut32)szb);
			(void) write (1, "\x00", 1);
		} else {
			rz_diff_set_callback (d, &cb, 0); // (void *)(size_t)diffmode);
			rz_diff_buffers (d, bufa, (ut32)sza, bufb, (ut32)szb);
		}
		if (diffmode == 'j') {
			printf ("]\n");
		}
		rz_diff_free (d);
		break;
	case MODE_DIST:
	case MODE_DIST_MYERS:
	case MODE_DIST_LEVENSTEIN:
		{
			RzDiff *d = rz_diff_new ();
			if (d) {
				d->verbose = verbose;
				if (mode == MODE_DIST_LEVENSTEIN) {
					d->type = 'l';
				} else if (mode == MODE_DIST_MYERS) {
					d->type = 'm';
				} else {
					d->type = 0;
				}
				rz_diff_buffers_distance (d, bufa, (ut32)sza, bufb, (ut32)szb, &count, &sim);
				rz_diff_free (d);
			}
		}
		printf ("similarity: %.3f\n", sim);
		printf ("distance: %d\n", count);
		break;
	}
	rz_cons_free ();

	if (diffmode == 'j' && showcount) {
		printf (",\"count\":%d}\n", count);
	} else if (showcount && diffmode != 'j') {
		printf ("%d\n", count);
	} else if (!showcount && diffmode == 'j') {
		printf ("}\n");
	}
	free (bufa);
	free (bufb);

	return 0;
}
