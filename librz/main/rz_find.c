// SPDX-License-Identifier: LGPL-3.0-only

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

typedef struct {
	bool showstr;
	bool rad;
	bool identify;
	bool quiet;
	bool hexstr;
	bool widestr;
	bool nonstop;
	bool json;
	int mode;
	int align;
	ut8 *buf;
	ut64 bsize;
	ut64 from;
	ut64 to;
	ut64 cur;
	RzPrint *pr;
	RzList *keywords;
	const char *mask;
	const char *curfile;
	const char *comma;
} RzfindOptions;

static void rzfind_options_fini(RzfindOptions *ro) {
	free (ro->buf);
	rz_list_free (ro->keywords);
}

static void rzfind_options_init(RzfindOptions *ro) {
	memset (ro, 0, sizeof (RzfindOptions));
	ro->mode = RZ_SEARCH_STRING;
	ro->bsize = 4096;
	ro->to = UT64_MAX;
	ro->keywords = rz_list_newf (NULL);
}

static int rzfind_open(RzfindOptions *ro, const char *file);

static int hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	RzfindOptions *ro = (RzfindOptions*)user;
	int delta = addr - ro->cur;
	if (ro->cur > addr && (ro->cur - addr == kw->keyword_length - 1)) {
		// This case occurs when there is hit in search left over
		delta = ro->cur - addr;
	}
	if (delta < 0 || delta >= ro->bsize) {
		eprintf ("Invalid delta\n");
		return 0;
	}
	char _str[128];
	char *str = _str;
	*_str = 0;
	if (ro->showstr) {
		if (ro->widestr) {
			str = _str;
			int i, j = 0;
			for (i = delta; ro->buf[i] && i < sizeof (_str); i++) {
				char ch = ro->buf[i];
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
				if (ro->buf[i]) {
					break;
				}
			}
			str[j] = 0;
		} else {
			size_t i;
			for (i = 0; i < sizeof (_str); i++) {
				char ch = ro->buf[delta + i];
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
			char ch = ro->buf[delta + i];
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
	if (ro->json) {
		const char *type = "string";
		printf ("%s{\"offset\":%"PFMT64d",\"type\":\"%s\",\"data\":\"%s\"}",
			ro->comma, addr, type, str);
		ro->comma = ",";
	} else if (ro->rad) {
		printf ("f hit%d_%d 0x%08"PFMT64x" ; %s\n", 0, kw->count, addr, ro->curfile);
	} else {
		if (ro->showstr) {
			printf ("0x%"PFMT64x" %s\n", addr, str);
		} else {
			printf ("0x%"PFMT64x"\n", addr);
			if (ro->pr) {
				rz_print_hexdump (ro->pr, addr, (ut8*)ro->buf + delta, 78, 16, 1, 1);
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
	" -i         identify filetype (rizin -nqcpm file)\n"
	" -j         output in JSON\n"
	" -m         magic search, file-type carver\n"
	" -M [str]   set a binary mask to be applied on keywords\n"
	" -n         do not stop on read errors\n"
	" -r         print using rizin commands\n"
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

static int rzfind_open_file(RzfindOptions *ro, const char *file, const ut8 *data, int datalen) {
	RzListIter *iter;
	RzSearch *rs = NULL;
	const char *kw;
	bool last = false;
	int ret, result = 0;

	ro->buf = NULL;
	if (!ro->quiet) {
		printf ("File: %s\n", file);
	}

	char *efile = rz_str_escape_sh (file);

	if (ro->identify) {
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

	rs = rz_search_new (ro->mode);
	if (!rs) {
		result = 1;
		goto err;
	}

	ro->buf = calloc (1, ro->bsize);
	if (!ro->buf) {
		eprintf ("Cannot allocate %"PFMT64d" bytes\n", ro->bsize);
		result = 1;
		goto err;
	}
	rs->align = ro->align;
	rz_search_set_callback (rs, &hit, ro);
	if (ro->to == -1) {
		ro->to = rz_io_size (io);
	}

	if (!rz_cons_new ()) {
		result = 1;
		goto err;
	}

	if (ro->mode == RZ_SEARCH_STRING) {
		/* TODO: implement using api */
		rz_sys_cmdf ("rz-bin -q%szzz \"%s\"", ro->json? "j": "", efile);
		goto done;
	}
	if (ro->mode == RZ_SEARCH_MAGIC) {
		/* TODO: implement using api */
		char *tostr = (ro->to && ro->to != UT64_MAX)?
			rz_str_newf ("-e search.to=%"PFMT64d, ro->to): strdup ("");
		rz_sys_cmdf ("rizin"
			" -e search.in=range"
			" -e search.align=%d"
			" -e search.from=%"PFMT64d
			" %s -qnc/m%s \"%s\"",
			ro->align, ro->from, tostr, ro->json? "j": "", efile);
		free (tostr);
		goto done;
	}
	if (ro->mode == RZ_SEARCH_ESIL) {
		/* TODO: implement using api */
		rz_list_foreach (ro->keywords, iter, kw) {
			rz_sys_cmdf ("rizin -qc \"/E %s\" \"%s\"", kw, efile);
		}
		goto done;
	}
	if (ro->mode == RZ_SEARCH_KEYWORD) {
		rz_list_foreach (ro->keywords, iter, kw) {
			if (ro->hexstr) {
				if (ro->mask) {
					rz_search_kw_add (rs, rz_search_keyword_new_hex (kw, ro->mask, NULL));
				} else {
					rz_search_kw_add (rs, rz_search_keyword_new_hexmask (kw, NULL));
				}
			} else if (ro->widestr) {
				rz_search_kw_add (rs, rz_search_keyword_new_wide (kw, ro->mask, NULL, 0));
			} else {
				rz_search_kw_add (rs, rz_search_keyword_new_str (kw, ro->mask, NULL, 0));
			}
		}
	} else if (ro->mode == RZ_SEARCH_STRING) {
		rz_search_kw_add (rs, rz_search_keyword_new_hexmask ("00", NULL)); //XXX
	}

	ro->curfile = file;
	rz_search_begin (rs);
	(void)rz_io_seek (io, ro->from, RZ_IO_SEEK_SET);
	result = 0;
	for (ro->cur = ro->from; !last && ro->cur < ro->to; ro->cur += ro->bsize) {
		if ((ro->cur + ro->bsize) > ro->to) {
			ro->bsize = ro->to - ro->cur;
			last = true;
		}
		ret = rz_io_pread_at (io, ro->cur, ro->buf, ro->bsize);
		if (ret == 0) {
			if (ro->nonstop) {
				continue;
			}
			result = 1;
			break;
		}
		if (ret != ro->bsize && ret > 0) {
			ro->bsize = ret;
		}

		if (rz_search_update (rs, ro->cur, ro->buf, ret) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x"\n", ro->cur);
			break;
		}
	}
done:
	rz_cons_free ();
err:
	free (efile);
	rz_search_free (rs);
	rz_io_free (io);
	rzfind_options_fini (ro);
	return result;
}

static int rzfind_open_dir(RzfindOptions *ro, const char *dir) {
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
			(void)rzfind_open (ro, fullpath);
			free (fullpath);
		}
		rz_list_free (files);
	}
	return 0;
}

static int rzfind_open(RzfindOptions *ro, const char *file) {
	if (!strcmp (file, "-")) {
		int sz = 0;
		ut8 *buf = (ut8 *)rz_stdin_slurp (&sz);
		if (!buf) {
			return 0;
		}
		char *ff = rz_str_newf ("malloc://%d", sz);
		int res = rzfind_open_file (ro, ff, buf, sz);
		free (ff);
		free (buf);
		return res;
	}
	return rz_file_is_directory (file)
		? rzfind_open_dir (ro, file)
		: rzfind_open_file (ro, file, NULL, -1);
}

RZ_API int rz_main_rz_find(int argc, const char **argv) {
	RzfindOptions ro;
	rzfind_options_init (&ro);

	int c;
	const char *file = NULL;

	RzGetopt opt;
	rz_getopt_init (&opt, argc, argv, "a:ie:b:jmM:s:S:x:Xzf:F:t:E:rqnhvZ");
	while ((c = rz_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			ro.align = rz_num_math (NULL, opt.arg);
			break;
		case 'r':
			ro.rad = true;
			break;
		case 'i':
			ro.identify = true;
			break;
		case 'j':
			ro.json = true;
			break;
		case 'n':
			ro.nonstop = 1;
			break;
		case 'm':
			ro.mode = RZ_SEARCH_MAGIC;
			break;
		case 'e':
			ro.mode = RZ_SEARCH_REGEXP;
			ro.hexstr = 0;
			rz_list_append (ro.keywords, (void*)opt.arg);
			break;
		case 'E':
			ro.mode = RZ_SEARCH_ESIL;
			rz_list_append (ro.keywords, (void*)opt.arg);
			break;
		case 's':
			ro.mode = RZ_SEARCH_KEYWORD;
			ro.hexstr = false;
			ro.widestr = false;
			rz_list_append (ro.keywords, (void*)opt.arg);
			break;
		case 'S':
			ro.mode = RZ_SEARCH_KEYWORD;
			ro.hexstr = false;
			ro.widestr = true;
			rz_list_append (ro.keywords, (void*)opt.arg);
			break;
		case 'b':
			ro.bsize = rz_num_math (NULL, opt.arg);
			break;
		case 'M':
			// XXX should be from hexbin
			ro.mask = opt.arg;
			break;
		case 'f':
			ro.from = rz_num_math (NULL, opt.arg);
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
					ro.mode = RZ_SEARCH_KEYWORD;
					ro.hexstr = true;
					ro.widestr = false;
					rz_list_append (ro.keywords, (void*)hexdata);
				}
				free (data);
			}
			break;
		case 't':
			ro.to = rz_num_math (NULL, opt.arg);
			break;
		case 'x':
			ro.mode = RZ_SEARCH_KEYWORD;
			ro.hexstr = 1;
			ro.widestr = 0;
			rz_list_append (ro.keywords, (void*)opt.arg);
			break;
		case 'X':
			ro.pr = rz_print_new ();
			break;
		case 'q':
			ro.quiet = true;
			break;
		case 'v':
			return rz_main_version_print ("rz_find");
		case 'h':
			return show_help(argv[0], 0);
		case 'z':
			ro.mode = RZ_SEARCH_STRING;
			break;
		case 'Z':
			ro.showstr = true;
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
		ro.quiet = true;
	}
	if (ro.json) {
		printf ("[");
	}
	for (; opt.ind < argc; opt.ind++) {
		file = argv[opt.ind];

		if (RZ_STR_ISEMPTY(file)) {
			eprintf ("Cannot open empty path\n");
			return 1;
		}
		rzfind_open (&ro, file);
	}
	if (ro.json) {
		printf ("]\n");
	}
	return 0;
}
