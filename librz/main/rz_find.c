/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <stdio.h>
#include <stdlib.h>

#include <rz_main.h>
#include <rz_types.h>
#include <rz_search.h>
#include <rz_util.h>
#include <rz_util/rz_print.h>
#include <rz_cons.h>
#include <rz_lib.h>
#include <rz_io.h>

// XXX kill those globals
static bool showstr = false;
static bool rad = false;
static bool identify = false;
static bool quiet = false;
static bool hexstr = false;
static bool widestr = false;
static bool nonstop = false;
static bool json = false;
static int mode = RZ_SEARCH_STRING;
static int align = 0;
static ut8 *buf = NULL;
static ut64 bsize = 4096;
static ut64 from = 0LL, to = -1;
static ut64 cur = 0;
static RPrint *pr = NULL;
static RzList *keywords;
static const char *mask = NULL;
static const char *curfile = NULL;
static const char *comma = "";

static int hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	int delta = addr - cur;
	if (cur > addr && (cur - addr == kw->keyword_length - 1)) {
		// This case occurs when there is hit in search left over
		delta = cur - addr;
	}
	if (delta < 0 || delta >= bsize) {
		eprintf ("Invalid delta\n");
		return 0;
	}
	char _str[128];
	char *str = _str;
	*_str = 0;
	if (showstr) {
		if (widestr) {
			str = _str;
			int i, j = 0;
			for (i = delta; buf[i] && i < sizeof (_str); i++) {
				char ch = buf[i];
				if (ch == '"' || ch == '\\') {
					ch = '\'';
				}
				if (!IS_PRINTABLE (ch)) {
					break;
				}
				str[j++] = ch;
				i++;
				if (j > 80) {
					strcpy (str + j, "...");
					j += 3;
					break;
				}
				if (buf[i]) {
					break;
				}
			}
			str[j] = 0;
		} else {
			size_t i;
			for (i = 0; i < sizeof (_str); i++) {
				char ch = buf[delta + i];
				if (ch == '"' || ch == '\\') {
					ch = '\'';
				}
				if (!ch || !IS_PRINTABLE (ch)) {
					break;
				}
				str[i] = ch;
			}
			str[i] = 0;
		}
	} else {
		size_t i;
		for (i = 0; i < sizeof (_str); i++) {
			char ch = buf[delta + i];
			if (ch == '"' || ch == '\\') {
				ch = '\'';
			}
			if (!ch || !IS_PRINTABLE (ch)) {
				break;
			}
			str[i] = ch;
		}
		str[i] = 0;
	}
	if (json) {
		const char *type = "string";
		printf ("%s{\"offset\":%"PFMT64d",\"type\":\"%s\",\"data\":\"%s\"}", comma, addr, type, str);
		comma = ",";
	} else if (rad) {
		printf ("f hit%d_%d 0x%08"PFMT64x" ; %s\n", 0, kw->count, addr, curfile);
	} else {
		if (showstr) {
			printf ("0x%"PFMT64x" %s\n", addr, str);
		} else {
			printf ("0x%"PFMT64x"\n", addr);
			if (pr) {
				rz_print_hexdump (pr, addr, (ut8*)buf + delta, 78, 16, 1, 1);
				rz_cons_flush ();
			}
		}
	}
	return 1;
}

static int show_help(const char *argv0, int line) {
	printf ("Usage: %s [-mXnzZhqv] [-a align] [-b sz] [-f/t from/to] [-[e|s|S] str] [-x hex] -|file|dir ..\n", argv0);
	if (line) {
		return 0;
	}
	printf (
	" -a [align] only accept aligned hits\n"
	" -b [size]  set block size\n"
	" -e [regex] search for regex matches (can be used multiple times)\n"
	" -f [from]  start searching from address 'from'\n"
	" -F [file]  read the contents of the file and use it as keyword\n"
	" -h         show this help\n"
	" -i         identify filetype (r2 -nqcpm file)\n"
	" -j         output in JSON\n"
	" -m         magic search, file-type carver\n"
	" -M [str]   set a binary mask to be applied on keywords\n"
	" -n         do not stop on read errors\n"
	" -r         print using radare commands\n"
	" -s [str]   search for a specific string (can be used multiple times)\n"
	" -S [str]   search for a specific wide string (can be used multiple times). Assumes str is UTF-8.\n"
	" -t [to]    stop search at address 'to'\n"
	" -q         quiet - do not show headings (filenames) above matching contents (default for searching a single file)\n"
	" -v         print version and exit\n"
	" -x [hex]   search for hexpair string (909090) (can be used multiple times)\n"
	" -X         show hexdump of search results\n"
	" -z         search for zero-terminated strings\n"
	" -Z         show string found on each search hit\n"
	);
	return 0;
}

static int rafind_open_file(const char *file, const ut8 *data, int datalen) {
	RzListIter *iter;
	RzSearch *rs = NULL;
	const char *kw;
	bool last = false;
	int ret, result = 0;

	buf = NULL;
	if (!quiet) {
		printf ("File: %s\n", file);
	}

	char *efile = rz_str_escape_sh (file);

	if (identify) {
		char *cmd = rz_str_newf ("rizin -e search.show=false -e search.maxhits=1 -nqcpm \"%s\"", efile);
		rz_sandbox_system (cmd, 1);
		free (cmd);
		free (efile);
		return 0;
	}

	RzIO *io = rz_io_new ();
	if (!io) {
		free (efile);
		return 1;
	}

	if (!rz_io_open_nomap (io, file, RZ_PERM_R, 0)) {
		eprintf ("Cannot open file '%s'\n", file);
		result = 1;
		goto err;
	}

	if (data) {
		rz_io_write_at (io, 0, data, datalen);
	}

	rs = rz_search_new (mode);
	if (!rs) {
		result = 1;
		goto err;
	}

	buf = calloc (1, bsize);
	if (!buf) {
		eprintf ("Cannot allocate %"PFMT64d" bytes\n", bsize);
		result = 1;
		goto err;
	}
	rs->align = align;
	rz_search_set_callback (rs, &hit, buf);
	if (to == -1) {
		to = rz_io_size (io);
	}

	if (!rz_cons_new ()) {
		result = 1;
		goto err;
	}

	if (mode == RZ_SEARCH_STRING) {
		/* TODO: implement using api */
		rz_sys_cmdf ("rz_bin -q%szzz \"%s\"", json? "j": "", efile);
		goto done;
	}
	if (mode == RZ_SEARCH_MAGIC) {
		/* TODO: implement using api */
		char *tostr = (to && to != UT64_MAX)?
			rz_str_newf ("-e search.to=%"PFMT64d, to): strdup ("");
		char *cmd = rz_str_newf ("rizin"
			" -e search.in=range"
			" -e search.align=%d"
			" -e search.from=%"PFMT64d
			" %s -qnc/m%s \"%s\"",
			align, from, tostr, json? "j": "", efile);
		rz_sandbox_system (cmd, 1);
		free (cmd);
		free (tostr);
		goto done;
	}
	if (mode == RZ_SEARCH_ESIL) {
		rz_list_foreach (keywords, iter, kw) {
			rz_sys_cmdf ("rizin -qc \"/E %s\" \"%s\"", kw, efile);
		}
		goto done;
	}
	if (mode == RZ_SEARCH_KEYWORD) {
		rz_list_foreach (keywords, iter, kw) {
			if (hexstr) {
				if (mask) {
					rz_search_kw_add (rs, rz_search_keyword_new_hex (kw, mask, NULL));
				} else {
					rz_search_kw_add (rs, rz_search_keyword_new_hexmask (kw, NULL));
				}
			} else if (widestr) {
				rz_search_kw_add (rs, rz_search_keyword_new_wide (kw, mask, NULL, 0));
			} else {
				rz_search_kw_add (rs, rz_search_keyword_new_str (kw, mask, NULL, 0));
			}
		}
	} else if (mode == RZ_SEARCH_STRING) {
		rz_search_kw_add (rs, rz_search_keyword_new_hexmask ("00", NULL)); //XXX
	}

	curfile = file;
	rz_search_begin (rs);
	(void)rz_io_seek (io, from, RZ_IO_SEEK_SET);
	result = 0;
	for (cur = from; !last && cur < to; cur += bsize) {
		if ((cur + bsize) > to) {
			bsize = to - cur;
			last = true;
		}
		ret = rz_io_pread_at (io, cur, buf, bsize);
		if (ret == 0) {
			if (nonstop) {
				continue;
			}
			result = 1;
			break;
		}
		if (ret != bsize && ret > 0) {
			bsize = ret;
		}

		if (rz_search_update (rs, cur, buf, ret) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x"\n", cur);
			break;
		}
	}
done:
	rz_cons_free ();
err:
	free (buf);
	free (efile);
	rz_search_free (rs);
	rz_io_free (io);
	return result;
}
static int rafind_open_dir(const char *dir);

static int rafind_open(const char *file) {
	if (!strcmp (file, "-")) {
		int sz = 0;
		ut8 *buf = (ut8 *)rz_stdin_slurp (&sz);
		char *ff = rz_str_newf ("malloc://%d", sz);
		int res = rafind_open_file (ff, buf, sz);
		free (ff);
		free (buf);
		return res;
	}
	return rz_file_is_directory (file)
		? rafind_open_dir (file)
		: rafind_open_file (file, NULL, -1);
}

static int rafind_open_dir(const char *dir) {
	RzListIter *iter;
	char *fullpath;
	char *fname = NULL;

	RzList *files = rz_sys_dir (dir);

	if (files) {
		rz_list_foreach (files, iter, fname) {
			/* Filter-out unwanted entries */
			if (*fname == '.') {
				continue;
			}
			fullpath = rz_str_newf ("%s"RZ_SYS_DIR"%s", dir, fname);
			(void)rafind_open (fullpath);
			free (fullpath);
		}
		rz_list_free (files);
	}
	return 0;
}

RZ_API int rz_main_rz_find(int argc, const char **argv) {
	int c;
	const char *file = NULL;

	keywords = rz_list_newf (NULL);
	RzGetopt opt;
	rz_getopt_init (&opt, argc, argv, "a:ie:b:jmM:s:S:x:Xzf:F:t:E:rqnhvZ");
	while ((c = rz_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			align = rz_num_math (NULL, opt.arg);
			break;
		case 'r':
			rad = true;
			break;
		case 'i':
			identify = true;
			break;
		case 'j':
			json = true;
			break;
		case 'n':
			nonstop = 1;
			break;
		case 'm':
			mode = RZ_SEARCH_MAGIC;
			break;
		case 'e':
			mode = RZ_SEARCH_REGEXP;
			hexstr = 0;
			rz_list_append (keywords, (void*)opt.arg);
			break;
		case 'E':
			mode = RZ_SEARCH_ESIL;
			rz_list_append (keywords, (void*)opt.arg);
			break;
		case 's':
			mode = RZ_SEARCH_KEYWORD;
			hexstr = 0;
			widestr = 0;
			rz_list_append (keywords, (void*)opt.arg);
			break;
		case 'S':
			mode = RZ_SEARCH_KEYWORD;
			hexstr = 0;
			widestr = 1;
			rz_list_append (keywords, (void*)opt.arg);
			break;
		case 'b':
			bsize = rz_num_math (NULL, opt.arg);
			break;
		case 'M':
			// XXX should be from hexbin
			mask = opt.arg;
			break;
		case 'f':
			from = rz_num_math (NULL, opt.arg);
			break;
		case 'F':
			{
				size_t data_size;
				char *data = rz_file_slurp (opt.arg, &data_size);
				if (!data) {
					eprintf ("Cannot slurp '%s'\n", opt.arg);
					return 1;
				}
				char *hexdata = rz_hex_bin2strdup ((ut8*)data, data_size);
				if (hexdata) {
					mode = RZ_SEARCH_KEYWORD;
					hexstr = true;
					widestr = false;
					rz_list_append (keywords, (void*)hexdata);
				}
				free (data);
			}
			break;
		case 't':
			to = rz_num_math (NULL, opt.arg);
			break;
		case 'x':
			mode = RZ_SEARCH_KEYWORD;
			hexstr = 1;
			widestr = 0;
			rz_list_append (keywords, (void*)opt.arg);
			break;
		case 'X':
			pr = rz_print_new ();
			break;
		case 'q':
			quiet = true;
			break;
		case 'v':
			return rz_main_version_print ("rz_find");
		case 'h':
			return show_help(argv[0], 0);
		case 'z':
			mode = RZ_SEARCH_STRING;
			break;
		case 'Z':
			showstr = true;
			break;
		default:
			return show_help (argv[0], 1);
		}
	}
	if (opt.ind == argc) {
		return show_help (argv[0], 1);
	}
	/* Enable quiet mode if searching just a single file */
	if (opt.ind + 1 == argc && RZ_STR_ISNOTEMPTY (argv[opt.ind]) && !rz_file_is_directory (argv[opt.ind])) {
		quiet = true;
	}
	if (json) {
		printf ("[");
	}
	for (; opt.ind < argc; opt.ind++) {
		file = argv[opt.ind];

		if (RZ_STR_ISEMPTY(file)) {
			eprintf ("Cannot open empty path\n");
			return 1;
		}

		rafind_open (file);
	}
	if (json) {
		printf ("]\n");
	}
	return 0;
}
