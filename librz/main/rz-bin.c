// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_types.h>
#include <rz_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <rz_main.h>
#include "../../librz/bin/pdb/pdb_downloader.h"

static int rabin_show_help(int v) {
	printf("Usage: rz-bin [-AcdeEghHiIjlLMqrRsSUvVxzZ] [-@ at] [-a arch] [-b bits] [-B addr]\n"
	       "              [-C F:C:D] [-f str] [-m addr] [-n str] [-N m:M] [-P[-P] pdb]\n"
	       "              [-o str] [-O str] [-k query] [-D lang symname] file\n");
	if (v) {
		printf(
			" -@ [addr]       show section, symbol or import at addr\n"
			" -A              list sub-binaries and their arch-bits pairs\n"
			" -a [arch]       set arch (x86, arm, .. or <arch>_<bits>)\n"
			" -b [bits]       set bits (32, 64 ...)\n"
			" -B [addr]       override base address (pie bins)\n"
			" -c              list classes\n"
			" -cc             list classes in header format\n"
			" -C [fmt:C:D]    create [elf,mach0,pe] with Code and Data hexpairs (see -a)\n"
			" -d              show debug/dwarf information\n"
			" -D lang name    demangle symbol name (-D all for bin.demangle=true)\n"
			" -e              entrypoint\n"
			" -ee             constructor/destructor entrypoints\n"
			" -E              globally exportable symbols\n"
			" -f [str]        select sub-bin named str\n"
			" -F [binfmt]     force to use that bin plugin (ignore header check)\n"
			" -g              same as -SMZIHVResizcld -SS -SSS -ee (show all info)\n"
			" -G [addr]       load address . offset to header\n"
			" -h              this help message\n"
			" -H              header fields\n"
			" -i              imports (symbols imported from libraries)\n"
			" -I              binary info\n"
			" -j              output in json\n"
			" -k [sdb-query]  run sdb query. for example: '*'\n"
			" -K [algo]       calculate checksums (md5, sha1, ..)\n"
			" -l              linked libraries\n"
			" -L [plugin]     list supported bin plugins or plugin details\n"
			" -m [addr]       show source line at addr\n"
			" -M              main (show address of main symbol)\n"
			" -n [str]        show section, symbol or import named str\n"
			" -N [min:max]    force min:max number of chars per string (see -z and -zz)\n"
			" -o [str]        output file/folder for write operations (out by default)\n"
			" -O [str]        write/extract operations (-O help)\n"
			" -p              show physical addresses\n"
			" -P              show debug/pdb information\n"
			" -PP             download pdb file for binary\n"
			" -q              be quiet, just show fewer data\n"
			" -qq             show less info (no offset/size for -z for ex.)\n"
			" -Q              show load address used by dlopen (non-aslr libs)\n"
			" -r              rizin output\n"
			" -R              relocations\n"
			" -s              symbols\n"
			" -S              sections\n"
			" -SS             segments\n"
			" -SSS            sections mapping to segments\n"
			" -t              display file hashes\n"
			" -T              display file signature\n"
			" -u              unfiltered (no rename duplicated symbols/sections)\n"
			" -U              resoUrces\n"
			" -v              display version and quit\n"
			" -V              Show binary version information\n"
			" -w              display try/catch blocks\n"
			" -x              extract bins contained in file\n"
			" -X [fmt] [f] .. package in fat or zip the given files and bins contained in file\n"
			" -z              strings (from data section)\n"
			" -zz             strings (from raw bins [e bin.rawstr=1])\n"
			" -zzz            dump raw strings to stdout (for huge files)\n"
			" -Z              guess size of binary program\n");
	}
	if (v) {
		printf("Environment:\n"
		       " RZ_BIN_LANG:      e bin.lang         # assume lang for demangling\n"
		       " RZ_BIN_NOPLUGINS: # do not load shared plugins (speedup loading)\n"
		       " RZ_BIN_DEMANGLE=0:e bin.demangle     # do not demangle symbols\n"
		       " RZ_BIN_MAXSTRBUF: e bin.maxstrbuf    # specify maximum buffer size\n"
		       " RZ_BIN_STRFILTER: e bin.str.filter   # rizin -qc 'e bin.str.filter=?"
		       "?' -\n"
		       " RZ_BIN_STRPURGE:  e bin.str.purge    # try to purge false positives\n"
		       " RZ_BIN_DEBASE64:  e bin.debase64     # try to debase64 all strings\n"
		       " RZ_BIN_DMNGLRCMD: e bin.demanglercmd # try to purge false positives\n"
		       " RZ_BIN_PDBSERVER: e pdb.server       # use alternative PDB server\n"
		       " RZ_BIN_SYMSTORE:  e pdb.symstore     # path to downstream symbol store\n"
		       " RZ_BIN_PREFIX:    e bin.prefix       # prefix symbols/sections/relocs with a specific string\n"
		       " RZ_CONFIG:        # sdb config file\n");
	}
	return 1;
}

static char *stdin_gets(bool liberate) {
	static char *stdin_buf = NULL;
#define STDIN_BUF_SIZE 96096
	if (liberate) {
		free(stdin_buf);
		stdin_buf = NULL;
		return NULL;
	}
	if (!stdin_buf) {
		/* XXX: never freed. leaks! */
		stdin_buf = malloc(STDIN_BUF_SIZE);
		if (!stdin_buf) {
			return NULL;
		}
	}
	memset(stdin_buf, 0, STDIN_BUF_SIZE);
	if (!fgets(stdin_buf, STDIN_BUF_SIZE, stdin)) {
		return NULL;
	}
	if (feof(stdin)) {
		return NULL;
	}
	return strdup(stdin_buf);
}

static void __sdb_prompt(Sdb *sdb) {
	char *line;
	for (; (line = stdin_gets(false));) {
		sdb_query(sdb, line);
		free(line);
	}
}

static bool isBinopHelp(const char *op) {
	if (!op) {
		return false;
	}
	if (!strcmp(op, "help")) {
		return true;
	}
	if (!strcmp(op, "?")) {
		return true;
	}
	if (!strcmp(op, "h")) {
		return true;
	}
	return false;
}

static bool extract_binobj(const RzBinFile *bf, RzBinXtrData *data, int idx) {
	ut64 bin_size = data ? data->size : 0;
	ut8 *bytes;
	const char *xtr_type = "";
	char *arch = "unknown";
	int bits = 0, nb;
	char *libname = NULL;
	const char *filename = bf ? bf->file : NULL;
	char *path = NULL, *ptr = NULL;
	bool res = false;

	if (!bf || !data || !filename) {
		return false;
	}
	if (data->metadata) {
		arch = data->metadata->arch;
		bits = data->metadata->bits;
		libname = data->metadata->libname;
		xtr_type = data->metadata->xtr_type;
	}
	if (!strcmp(xtr_type, "fat") && bin_size == bf->size && bin_size) {
		eprintf("This is not a fat bin\n");
		return false;
	}
	bytes = malloc(bin_size);
	if (!bytes) {
		eprintf("error: BinFile buffer is empty\n");
		return false;
	}
	nb = rz_buf_read_at(data->buf, 0, bytes, bin_size);
	if (nb <= 0) {
		eprintf("Couldn't read xtrdata\n");
		return false;
	}
	if (!arch) {
		arch = "unknown";
	}
	path = strdup(filename);
	if (!path) {
		return false;
	}
	ptr = (char *)rz_file_basename(path);
	char *outpath = rz_str_newf("%s.fat", ptr);
	if (!outpath || !rz_sys_mkdirp(outpath)) {
		free(path);
		free(outpath);
		eprintf("Error creating dir structure\n");
		return false;
	}

	char *outfile = libname
		? rz_str_newf("%s/%s.%s.%s_%i.%d", outpath, ptr, arch, libname, bits, idx)
		: rz_str_newf("%s/%s.%s_%i.%d", outpath, ptr, arch, bits, idx);

	if (!outfile || !rz_file_dump(outfile, bytes, bin_size, 0)) {
		eprintf("Error extracting %s\n", outfile);
		res = false;
	} else {
		printf("%s created (%" PFMT64d ")\n", outfile, bin_size);
		res = true;
	}

	free(outfile);
	free(outpath);
	free(path);
	free(bytes);
	return res;
}

static int rabin_extract(RzBin *bin, int all) {
	RzBinXtrData *data = NULL;
	int res = false;
	RzBinFile *bf = rz_bin_cur(bin);

	if (!bf) {
		return res;
	}
	if (all) {
		int idx = 0;
		RzListIter *iter;
		rz_list_foreach (bf->xtr_data, iter, data) {
			res = extract_binobj(bf, data, idx++);
			if (!res) {
				break;
			}
		}
	} else {
		data = rz_list_get_n(bf->xtr_data, 0);
		if (!data) {
			return res;
		}
		res = extract_binobj(bf, data, 0);
	}
	return res;
}

static int rabin_dump_symbols(RzBin *bin, int len) {
	RzList *symbols = rz_bin_get_symbols(bin);
	if (!symbols) {
		return false;
	}

	RzListIter *iter;
	RzBinSymbol *symbol;
	int olen = len;
	rz_list_foreach (symbols, iter, symbol) {
		if (symbol->size && (olen > symbol->size || !olen)) {
			len = symbol->size;
		} else if (!symbol->size && !olen) {
			len = 32;
		} else {
			len = olen;
		}
		ut8 *buf = calloc(1, len);
		if (!buf) {
			return false;
		}
		char *ret = malloc((len * 2) + 1);
		if (!ret) {
			free(buf);
			return false;
		}
		if (rz_buf_read_at(bin->cur->buf, symbol->paddr, buf, len) == len) {
			rz_hex_bin2str(buf, len, ret);
			printf("%s %s\n", symbol->name, ret);
		} else {
			eprintf("Cannot read from buffer\n");
		}
		free(buf);
		free(ret);
	}
	return true;
}

static bool __dumpSections(RzBin *bin, const char *scnname, const char *output, const char *file) {
	RzList *sections;
	RzListIter *iter;
	RzBinSection *section;
	ut8 *buf;
	char *ret;
	int r;

	if (!(sections = rz_bin_get_sections(bin))) {
		return false;
	}

	rz_list_foreach (sections, iter, section) {
		if (!strcmp(scnname, section->name)) {
			if (!(buf = malloc(section->size))) {
				return false;
			}
			if ((section->size * 2) + 1 < section->size) {
				free(buf);
				return false;
			}
			if (!(ret = malloc(section->size * 2 + 1))) {
				free(buf);
				return false;
			}
			if (section->paddr > rz_buf_size(bin->cur->buf) ||
				section->paddr + section->size > rz_buf_size(bin->cur->buf)) {
				free(buf);
				free(ret);
				return false;
			}
			r = rz_buf_read_at(bin->cur->buf, section->paddr,
				buf, section->size);
			if (r < 1) {
				free(buf);
				free(ret);
				return false;
			}
			//it does mean the user specified an output file
			if (strcmp(output, file)) {
				rz_file_dump(output, buf, section->size, 0);
			} else {
				rz_hex_bin2str(buf, section->size, ret);
				printf("%s\n", ret);
			}
			free(buf);
			free(ret);
			break;
		}
	}
	return true;
}

static int rabin_do_operation(RzBin *bin, const char *op, int rad, const char *output, const char *file) {
	char *arg = NULL, *ptr = NULL, *ptr2 = NULL;
	bool rc = true;

	/* Implement alloca with fixed-size buffer? */
	if (!(arg = strdup(op))) {
		return false;
	}
	if ((ptr = strchr(arg, '/'))) {
		*ptr++ = 0;
		if ((ptr2 = strchr(ptr, '/'))) {
			ptr2[0] = '\0';
			ptr2++;
		}
	}
	if (!output) {
		output = file;
	}
	RzBinFile *bf = rz_bin_cur(bin);
	if (bf) {
		RzBuffer *nb = rz_buf_new_with_buf(bf->buf);
		rz_buf_free(bf->buf);
		bf->buf = nb;
	}

	switch (arg[0]) {
	case 'd':
		if (!ptr) {
			goto _rabin_do_operation_error;
		}
		switch (*ptr) {
		case 's': {
			ut64 a = ptr2 ? rz_num_math(NULL, ptr2) : 0;
			if (!rabin_dump_symbols(bin, a)) {
				goto error;
			}
		} break;
		case 'S':
			if (!ptr2) {
				goto _rabin_do_operation_error;
			}
			if (!__dumpSections(bin, ptr2, output, file)) {
				goto error;
			}
			break;
		default:
			goto _rabin_do_operation_error;
		}
		break;
	case 'C': {
		RzBinFile *cur = rz_bin_cur(bin);
		RzBinPlugin *plg = rz_bin_file_cur_plugin(cur);
		if (!plg && cur) {
			// are we in xtr?
			if (cur->xtr_data) {
				// load the first one
				RzBinXtrData *xtr_data = rz_list_get_n(cur->xtr_data, 0);
				RzBinObjectLoadOptions obj_opts = {
					.baseaddr = UT64_MAX,
					.loadaddr = rz_bin_get_laddr(bin)
				};
				if (xtr_data && !xtr_data->loaded && !rz_bin_file_object_new_from_xtr_data(bin, cur, &obj_opts, xtr_data)) {
					break;
				}
			}
			plg = rz_bin_file_cur_plugin(cur);
			if (!plg) {
				break;
			}
		}
		if (plg && plg->signature) {
			char *sign = plg->signature(cur, rad == RZ_MODE_JSON);
			if (sign) {
				rz_cons_println(sign);
				rz_cons_flush();
				free(sign);
			}
		}
	} break;
	default:
	_rabin_do_operation_error:
		eprintf("Unknown operation. use -O help\n");
		goto error;
	}
	if (!rc) {
		eprintf("Cannot dump :(\n");
	}
	free(arg);
	return true;
error:
	free(arg);
	return false;
}

static int rabin_show_srcline(RzBin *bin, ut64 at) {
	char *srcline;
	if (at != UT64_MAX && (srcline = rz_bin_addr2text(bin, at, true))) {
		printf("%s\n", srcline);
		free(srcline);
		return true;
	}
	return false;
}

/* bin callback */
static int __lib_bin_cb(RzLibPlugin *pl, void *user, void *data) {
	struct rz_bin_plugin_t *hand = (struct rz_bin_plugin_t *)data;
	RzBin *bin = user;
	rz_bin_plugin_add(bin, hand);
	return true;
}

static int __lib_bin_dt(RzLibPlugin *pl, void *p, void *u) {
	return true;
}

/* binxtr callback */
static int __lib_bin_xtr_cb(RzLibPlugin *pl, void *user, void *data) {
	struct rz_bin_xtr_plugin_t *hand = (struct rz_bin_xtr_plugin_t *)data;
	RzBin *bin = user;
	//printf(" * Added (dis)assembly plugin\n");
	rz_bin_xtr_add(bin, hand);
	return true;
}

static int __lib_bin_xtr_dt(RzLibPlugin *pl, void *p, void *u) {
	return true;
}

/* binldr callback */
static int __lib_bin_ldr_cb(RzLibPlugin *pl, void *user, void *data) {
	struct rz_bin_ldr_plugin_t *hand = (struct rz_bin_ldr_plugin_t *)data;
	RzBin *bin = user;
	//printf(" * Added (dis)assembly plugin\n");
	rz_bin_ldr_add(bin, hand);
	return true;
}

static int __lib_bin_ldr_dt(RzLibPlugin *pl, void *p, void *u) {
	return true;
}

static char *__demangleAs(RzBin *bin, int type, const char *file) {
	bool syscmd = bin ? bin->demanglercmd : false;
	char *res = NULL;
	switch (type) {
	case RZ_BIN_NM_CXX: res = rz_bin_demangle_cxx(NULL, file, 0); break;
	case RZ_BIN_NM_JAVA: res = rz_bin_demangle_java(file); break;
	case RZ_BIN_NM_OBJC: res = rz_bin_demangle_objc(NULL, file); break;
	case RZ_BIN_NM_SWIFT: res = rz_bin_demangle_swift(file, syscmd); break;
	case RZ_BIN_NM_MSVC: res = rz_bin_demangle_msvc(file); break;
	case RZ_BIN_NM_RUST: res = rz_bin_demangle_rust(NULL, file, 0); break;
	default:
		eprintf("Unsupported demangler\n");
		break;
	}
	return res;
}

static void __listPlugins(RzBin *bin, const char *plugin_name, PJ *pj, int rad) {
	int format = 0;
	RzCmdStateOutput state = { 0 };
	if (rad == RZ_MODE_JSON) {
		format = 'j';
		state.mode = RZ_OUTPUT_MODE_JSON;
		state.d.pj = pj_new();
	} else if (rad) {
		format = 'q';
		state.mode = RZ_OUTPUT_MODE_QUIET;
	} else {
		state.mode = RZ_OUTPUT_MODE_STANDARD;
	}
	bin->cb_printf = (PrintfCallback)printf;
	if (plugin_name) {
		rz_bin_list_plugin(bin, plugin_name, pj, format);
	} else {
		rz_core_bin_plugins_print(bin, &state);
		switch (state.mode) {
		case RZ_OUTPUT_MODE_JSON: {
			rz_cons_print(pj_string(state.d.pj));
			rz_cons_flush();
			pj_free(state.d.pj);
			break;
		}
		default: {
			rz_cons_flush();
			break;
		}
		}
	}
}

RZ_API int rz_main_rz_bin(int argc, const char **argv) {
	RzBin *bin = NULL;
	const char *name = NULL;
	const char *file = NULL;
	const char *output = NULL;
	int rad = 0;
	ut64 laddr = UT64_MAX;
	ut64 baddr = UT64_MAX;
	const char *do_demangle = NULL;
	const char *query = NULL;
	int c, bits = 0, actions = 0;
	char *create = NULL;
	bool va = true;
	ut64 action = RZ_BIN_REQ_UNK;
	char *tmp, *ptr, *arch_name = NULL;
	const char *arch = NULL;
	const char *forcebin = NULL;
	const char *chksum = NULL;
	const char *op = NULL;
	RzCoreFile *fh = NULL;
	RzCoreBinFilter filter;
	int xtr_idx = 0; // load all files if extraction is necessary.
	int rawstr = 0;
	int fd = -1;
	RzCore core = { 0 };
	ut64 at = UT64_MAX;
	int result = 0;

	rz_core_init(&core);
	bin = core.bin;

	if (!(tmp = rz_sys_getenv("RZ_BIN_NOPLUGINS"))) {
		char *homeplugindir = rz_str_home(RZ_HOME_PLUGINS);
		char *plugindir = rz_str_rz_prefix(RZ_PLUGINS);
		char *extrasdir = rz_str_rz_prefix(RZ_EXTRAS);
		char *bindingsdir = rz_str_rz_prefix(RZ_BINDINGS);
		RzLib *l = rz_lib_new(NULL, NULL);
		rz_lib_add_handler(l, RZ_LIB_TYPE_BIN, "bin plugins",
			&__lib_bin_cb, &__lib_bin_dt, bin);
		rz_lib_add_handler(l, RZ_LIB_TYPE_BIN_XTR, "bin xtr plugins",
			&__lib_bin_xtr_cb, &__lib_bin_xtr_dt, bin);
		rz_lib_add_handler(l, RZ_LIB_TYPE_BIN_LDR, "bin ldr plugins",
			&__lib_bin_ldr_cb, &__lib_bin_ldr_dt, bin);
		/* load plugins everywhere */
		char *path = rz_sys_getenv(RZ_LIB_ENV);
		if (path && *path) {
			rz_lib_opendir(l, path);
		}
		rz_lib_opendir(l, homeplugindir);
		rz_lib_opendir(l, plugindir);
		rz_lib_opendir(l, extrasdir);
		rz_lib_opendir(l, bindingsdir);
		free(homeplugindir);
		free(plugindir);
		free(extrasdir);
		free(bindingsdir);
		free(path);
		rz_lib_free(l);
	}
	free(tmp);

	if ((tmp = rz_sys_getenv("RZ_CONFIG"))) {
		Sdb *config_sdb = sdb_new(NULL, tmp, 0);
		if (config_sdb) {
			rz_config_unserialize(core.config, config_sdb, NULL);
			sdb_free(config_sdb);
		} else {
			eprintf("Cannot open file specified in RZ_CONFIG\n");
		}
		free(tmp);
	}
	if ((tmp = rz_sys_getenv("RZ_BIN_DMNGLRCMD"))) {
		rz_config_set(core.config, "cmd.demangle", tmp);
		free(tmp);
	}
	if ((tmp = rz_sys_getenv("RZ_BIN_LANG"))) {
		rz_config_set(core.config, "bin.lang", tmp);
		free(tmp);
	}
	if ((tmp = rz_sys_getenv("RZ_BIN_DEMANGLE"))) {
		rz_config_set(core.config, "bin.demangle", tmp);
		free(tmp);
	}
	if ((tmp = rz_sys_getenv("RZ_BIN_MAXSTRBUF"))) {
		rz_config_set(core.config, "bin.maxstrbuf", tmp);
		free(tmp);
	}
	if ((tmp = rz_sys_getenv("RZ_BIN_STRFILTER"))) {
		rz_config_set(core.config, "bin.str.filter", tmp);
		free(tmp);
	}
	if ((tmp = rz_sys_getenv("RZ_BIN_STRPURGE"))) {
		rz_config_set(core.config, "bin.str.purge", tmp);
		free(tmp);
	}
	if ((tmp = rz_sys_getenv("RZ_BIN_DEBASE64"))) {
		rz_config_set(core.config, "bin.debase64", tmp);
		free(tmp);
	}
	if ((tmp = rz_sys_getenv("RZ_BIN_PDBSERVER"))) {
		rz_config_set(core.config, "pdb.server", tmp);
		free(tmp);
	}

#define is_active(x) (action & (x))
#define set_action(x) \
	{ \
		actions++; \
		action |= (x); \
	}
#define unset_action(x) action &= ~x
	RzGetopt opt;
	rz_getopt_init(&opt, argc, argv, "DjgAf:F:a:B:G:b:cC:k:K:dD:Mm:n:N:@:isSVIHeEUlRwO:o:pPqQrTtvLhuxXzZ");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'g':
			set_action(RZ_BIN_REQ_CLASSES);
			set_action(RZ_BIN_REQ_IMPORTS);
			set_action(RZ_BIN_REQ_SYMBOLS);
			set_action(RZ_BIN_REQ_SECTIONS);
			set_action(RZ_BIN_REQ_SEGMENTS);
			set_action(RZ_BIN_REQ_SECTIONS_MAPPING);
			set_action(RZ_BIN_REQ_STRINGS);
			set_action(RZ_BIN_REQ_SIZE);
			set_action(RZ_BIN_REQ_INFO);
			set_action(RZ_BIN_REQ_FIELDS);
			set_action(RZ_BIN_REQ_DWARF);
			set_action(RZ_BIN_REQ_ENTRIES);
			set_action(RZ_BIN_REQ_INITFINI);
			set_action(RZ_BIN_REQ_MAIN);
			set_action(RZ_BIN_REQ_LIBS);
			set_action(RZ_BIN_REQ_RELOCS);
			set_action(RZ_BIN_REQ_VERSIONINFO);
			break;
		case 'V': set_action(RZ_BIN_REQ_VERSIONINFO); break;
		case 'T': set_action(RZ_BIN_REQ_SIGNATURE); break;
		case 't': set_action(RZ_BIN_REQ_HASHES); break;
		case 'w': set_action(RZ_BIN_REQ_TRYCATCH); break;
		case 'q':
			rad = (rad & RZ_MODE_SIMPLE ? RZ_MODE_SIMPLEST : RZ_MODE_SIMPLE);
			break;
		case 'j': rad = RZ_MODE_JSON; break;
		case 'A': set_action(RZ_BIN_REQ_LISTARCHS); break;
		case 'a': arch = opt.arg; break;
		case 'C':
			set_action(RZ_BIN_REQ_CREATE);
			create = strdup(opt.arg);
			break;
		case 'u': bin->filter = 0; break;
		case 'k': query = opt.arg; break;
		case 'K': chksum = opt.arg; break;
		case 'c':
			if (is_active(RZ_BIN_REQ_CLASSES)) {
				rad = RZ_MODE_CLASSDUMP;
			} else {
				set_action(RZ_BIN_REQ_CLASSES);
			}
			break;
		case 'f': arch_name = strdup(opt.arg); break;
		case 'F': forcebin = opt.arg; break;
		case 'b': bits = rz_num_math(NULL, opt.arg); break;
		case 'm':
			at = rz_num_math(NULL, opt.arg);
			set_action(RZ_BIN_REQ_SRCLINE);
			break;
		case 'i':
			set_action(RZ_BIN_REQ_IMPORTS);
			break;
		case 's':
			set_action(RZ_BIN_REQ_SYMBOLS);
			break;
		case 'S':
			if (is_active(RZ_BIN_REQ_SEGMENTS)) {
				action &= ~RZ_BIN_REQ_SEGMENTS;
				action |= RZ_BIN_REQ_SECTIONS_MAPPING;
			} else if (is_active(RZ_BIN_REQ_SECTIONS)) {
				action &= ~RZ_BIN_REQ_SECTIONS;
				action |= RZ_BIN_REQ_SEGMENTS;
			} else {
				set_action(RZ_BIN_REQ_SECTIONS);
			}
			break;
		case 'z':
			if (is_active(RZ_BIN_REQ_STRINGS)) {
				if (rawstr) {
					/* rawstr mode 2 means that we are not going */
					/* to store them just dump'm all to stdout */
					rawstr = 2;
				} else {
					rawstr = 1;
				}
			} else {
				set_action(RZ_BIN_REQ_STRINGS);
			}
			break;
		case 'Z': set_action(RZ_BIN_REQ_SIZE); break;
		case 'I': set_action(RZ_BIN_REQ_INFO); break;
		case 'H':
			set_action(RZ_BIN_REQ_FIELDS);
			break;
		case 'd': set_action(RZ_BIN_REQ_DWARF); break;
		case 'P':
			if (is_active(RZ_BIN_REQ_PDB)) {
				set_action(RZ_BIN_REQ_PDB_DWNLD);
			} else {
				set_action(RZ_BIN_REQ_PDB);
			}
			break;
		case 'D':
			if (argv[opt.ind] && argv[opt.ind + 1] &&
				(!argv[opt.ind + 1][0] || !strcmp(argv[opt.ind + 1], "all"))) {
				rz_config_set(core.config, "bin.lang", argv[opt.ind]);
				rz_config_set(core.config, "bin.demangle", "true");
				opt.ind += 2;
			} else {
				do_demangle = argv[opt.ind];
			}
			break;
		case 'e':
			if (action & RZ_BIN_REQ_ENTRIES) {
				action &= ~RZ_BIN_REQ_ENTRIES;
				action |= RZ_BIN_REQ_INITFINI;
			} else {
				set_action(RZ_BIN_REQ_ENTRIES);
			}
			break;
		case 'E': set_action(RZ_BIN_REQ_EXPORTS); break;
		case 'U': set_action(RZ_BIN_REQ_RESOURCES); break;
		case 'Q': set_action(RZ_BIN_REQ_DLOPEN); break;
		case 'M': set_action(RZ_BIN_REQ_MAIN); break;
		case 'l': set_action(RZ_BIN_REQ_LIBS); break;
		case 'R': set_action(RZ_BIN_REQ_RELOCS); break;
		case 'x': set_action(RZ_BIN_REQ_EXTRACT); break;
		case 'X': set_action(RZ_BIN_REQ_PACKAGE); break;
		case 'O':
			op = opt.arg;
			set_action(RZ_BIN_REQ_OPERATION);
			if (*op == 'c') {
				rz_sys_setenv("RZ_BIN_CODESIGN_VERBOSE", "1");
			}
			if (isBinopHelp(op)) {
				printf("Usage: iO [expression]:\n"
				       " d/s/1024          dump symbols\n"
				       " d/S/.text         dump section\n"
				       " c                 show Codesign data\n"
				       " C                 show LDID entitlements\n");
				rz_core_fini(&core);
				return 0;
			}
			if (opt.ind == argc) {
				eprintf("Missing filename\n");
				rz_core_fini(&core);
				return 1;
			}
			break;
		case 'o': output = opt.arg; break;
		case 'p': va = false; break;
		case 'r': rad = true; break;
		case 'v':
			rz_core_fini(&core);
			return rz_main_version_print("rz-bin");
		case 'L':
			set_action(RZ_BIN_REQ_LISTPLUGINS);
			break;
		case 'G':
			laddr = rz_num_math(NULL, opt.arg);
			if (laddr == UT64_MAX) {
				va = false;
			}
			break;
		case 'B':
			baddr = rz_num_math(NULL, opt.arg);
			break;
		case '@':
			at = rz_num_math(NULL, opt.arg);
			if (at == 0LL && *opt.arg != '0') {
				at = UT64_MAX;
			}
			break;
		case 'n':
			name = opt.arg;
			break;
		case 'N':
			tmp = strchr(opt.arg, ':');
			rz_config_set(core.config, "bin.minstr", opt.arg);
			if (tmp) {
				rz_config_set(core.config, "bin.maxstr", tmp + 1);
			}
			break;
		case 'h':
			rz_core_fini(&core);
			return rabin_show_help(1);
		default:
			action |= RZ_BIN_REQ_HELP;
			break;
		}
	}

	PJ *pj = NULL;
	if (rad == RZ_MODE_JSON) {
		pj = pj_new();
		if (!pj) {
			return 1;
		}
	}

	if (is_active(RZ_BIN_REQ_LISTPLUGINS)) {
		const char *plugin_name = NULL;
		if (opt.ind < argc) {
			plugin_name = argv[opt.ind];
		}
		__listPlugins(bin, plugin_name, pj, rad);
		if (rad == RZ_MODE_JSON) {
			rz_cons_println(pj_string(pj));
			rz_cons_flush();
			pj_free(pj);
		}
		rz_core_fini(&core);
		return 0;
	}

	if (do_demangle) {
		char *res = NULL;
		int type;
		if ((argc - opt.ind) < 2) {
			rz_core_fini(&core);
			return rabin_show_help(0);
		}
		type = rz_bin_demangle_type(do_demangle);
		file = argv[opt.ind + 1];
		if (!strcmp(file, "-")) {
			for (;;) {
				file = stdin_gets(false);
				if (!file || !*file) {
					break;
				}
				res = __demangleAs(bin, type, file);
				if (!res) {
					eprintf("Unknown lang to demangle. Use: cxx, java, objc, swift\n");
					rz_core_fini(&core);
					return 1;
				}
				if (res && *res) {
					printf("%s\n", res);
				} else if (file && *file) {
					printf("%s\n", file);
				}
				RZ_FREE(res);
				RZ_FREE(file);
			}
			stdin_gets(true);
		} else {
			res = __demangleAs(bin, type, file);
			if (res && *res) {
				printf("%s\n", res);
				free(res);
				rz_core_fini(&core);
				return 0;
			} else {
				printf("%s\n", file);
			}
		}
		free(res);
		//eprintf ("%s\n", file);
		rz_core_fini(&core);
		return 1;
	}
	file = argv[opt.ind];

	if (file && !*file) {
		eprintf("Cannot open empty path\n");
		rz_core_fini(&core);
		return 1;
	}

	if (!query) {
		if (action & RZ_BIN_REQ_HELP || action == RZ_BIN_REQ_UNK || !file) {
			rz_core_fini(&core);
			return rabin_show_help(0);
		}
	}
	if (arch) {
		ptr = strchr(arch, '_');
		if (ptr) {
			*ptr = '\0';
			bits = rz_num_math(NULL, ptr + 1);
		}
	}
	if (action & RZ_BIN_REQ_CREATE) {
		// TODO: move in a function outside
		RzBuffer *b;
		int datalen, codelen;
		ut8 *data = NULL, *code = NULL;
		char *p2, *p = strchr(create, ':');
		if (!p) {
			eprintf("Invalid format for -C flag. Use 'format:codehexpair:datahexpair'\n");
			rz_core_fini(&core);
			return 1;
		}
		*p++ = 0;
		p2 = strchr(p, ':');
		if (p2) {
			// has data
			*p2++ = 0;
			data = malloc(strlen(p2) + 1);
			datalen = rz_hex_str2bin(p2, data);
			if (datalen < 0) {
				datalen = -datalen;
			}
		} else {
			data = NULL;
			datalen = 0;
		}
		code = malloc(strlen(p) + 1);
		if (!code) {
			rz_core_fini(&core);
			return 1;
		}
		codelen = rz_hex_str2bin(p, code);
		RzBinArchOptions opts;
		rz_bin_arch_options_init(&opts, arch, bits);
		b = rz_bin_create(bin, create, code, codelen, data, datalen, &opts);
		if (b) {
			ut64 tmpsz;
			const ut8 *tmp = rz_buf_data(b, &tmpsz);
			if (rz_file_dump(file, tmp, tmpsz, 0)) {
				eprintf("Dumped %" PFMT64d " bytes in '%s'\n",
					tmpsz, file);
				(void)rz_file_chmod(file, "+x", 0);
			} else {
				eprintf("Error dumping into a.out\n");
			}
			rz_buf_free(b);
		} else {
			eprintf("Cannot create binary for this format '%s'.\n", create);
		}
		rz_core_fini(&core);
		return 0;
	}
	if (rawstr == 2) {
		unset_action(RZ_BIN_REQ_STRINGS);
	}
	rz_config_set_i(core.config, "bin.rawstr", rawstr);

	if (!file) {
		eprintf("Missing file.\n");
		rz_core_fini(&core);
		return 1;
	}

	if (file && *file && action & RZ_BIN_REQ_DLOPEN) {
#if __UNIX__
		int child = rz_sys_fork();
		if (child == -1) {
			rz_core_fini(&core);
			return 1;
		}
		if (child == 0) {
			return waitpid(child, NULL, 0);
		}
#endif
		void *addr = rz_lib_dl_open(file);
		if (addr) {
			eprintf("%s is loaded at 0x%" PFMT64x "\n", file, (ut64)(size_t)(addr));
			rz_lib_dl_close(addr);
			rz_core_fini(&core);
			return 0;
		}
		eprintf("Cannot open the '%s' library\n", file);
		rz_core_fini(&core);
		return 0;
	}
	if (action & RZ_BIN_REQ_PACKAGE) {
		RzList *files = rz_list_newf(NULL);
		const char *format = argv[opt.ind];
		const char *file = argv[opt.ind + 1];
		int i, rc = 0;

		if (opt.ind + 3 > argc) {
			eprintf("Usage: rz-bin -X [fat|zip] foo.zip a b c\n");
			rz_core_fini(&core);
			return 1;
		}

		eprintf("FMT %s\n", format);
		eprintf("PKG %s\n", file);
		for (i = opt.ind + 2; i < argc; i++) {
			eprintf("ADD %s\n", argv[i]);
			rz_list_append(files, (void *)argv[i]);
		}
		RzBuffer *buf = rz_bin_package(core.bin, format, file, files);
		/* TODO: return bool or something to catch errors\n") */
		if (buf) {
			bool ret = rz_buf_dump(buf, file);
			rz_buf_free(buf);
			if (!ret) {
				rc = 1;
			}
		}
		rz_core_fini(&core);
		rz_list_free(files);
		return rc;
	}

	if (file && *file) {
		if ((fh = rz_core_file_open(&core, file, RZ_PERM_R, 0))) {
			fd = rz_io_fd_get_current(core.io);
			if (fd == -1) {
				eprintf("rz_core: Cannot open file '%s'\n", file);
				rz_core_file_close(fh);
				rz_core_fini(&core);
				return 1;
			}
		} else {
			eprintf("rz_core: Cannot open file '%s'\n", file);
			rz_core_fini(&core);
			return 1;
		}
	}
	bin->minstrlen = rz_config_get_i(core.config, "bin.minstr");
	bin->maxstrbuf = rz_config_get_i(core.config, "bin.maxstrbuf");

	rz_bin_force_plugin(bin, forcebin);
	rz_bin_load_filter(bin, action);

	RzBinOptions bo;
	rz_bin_options_init(&bo, fd, baddr, laddr, false, rawstr);
	bo.xtr_idx = xtr_idx;

	RzBinFile *bf = rz_bin_open(bin, file, &bo);
	if (!bf) {
		eprintf("rz-bin: Cannot open file\n");
		rz_core_file_close(fh);
		rz_core_fini(&core);
		return 1;
	}
	/* required to automatically select a sub-bin when not specified */
	(void)rz_core_bin_update_arch_bits(&core);

	if (baddr != UT64_MAX) {
		rz_bin_set_baddr(bin, baddr);
	}
	if (rawstr == 2) {
		bf->strmode = rad;
		rz_bin_dump_strings(bf, bin->minstrlen, bf->rawstr);
	}
	if (query) {
		if (rad) {
			rz_core_bin_export_info(&core, RZ_MODE_RIZINCMD);
			rz_cons_flush();
		} else {
			if (!strcmp(query, "-")) {
				__sdb_prompt(bin->cur->sdb);
			} else {
				sdb_query(bin->cur->sdb, query);
			}
		}
		rz_core_file_close(fh);
		rz_core_fini(&core);
		return 0;
	}
#define isradjson (rad == RZ_MODE_JSON && actions > 0)
#define run_action(n, x, y) \
	{ \
		if (action & (x)) { \
			if (isradjson) \
				pj_k(pj, n); \
			if (!rz_core_bin_info(&core, y, pj, rad, va, &filter, chksum)) { \
				if (isradjson) \
					pj_b(pj, false); \
			}; \
		} \
	}
	core.bin = bin;
	bin->cb_printf = rz_cons_printf;
	filter.offset = at;
	filter.name = name;
	rz_cons_new()->context->is_interactive = false;

	if (isradjson) {
		pj_o(pj);
	}
	// List fatmach0 sub-binaries, etc
	if (action & RZ_BIN_REQ_LISTARCHS || ((arch || bits || arch_name) && !rz_bin_select(bin, arch, bits, arch_name))) {
		if (rad == RZ_MODE_SIMPLEST || rad == RZ_MODE_SIMPLE) {
			RzCmdStateOutput state = {.mode = RZ_OUTPUT_MODE_QUIET};
			rz_core_bin_archs_print(bin, &state);
		} else if (rad == RZ_MODE_JSON) {
			RzCmdStateOutput state = {.mode = RZ_OUTPUT_MODE_JSON, .d.pj = pj_new()};
			if (!state.d.pj) {
				rz_core_file_close(fh);
				rz_core_fini(&core);
				return 1;
			}
			rz_core_bin_archs_print(bin, &state);
			rz_cons_printf("%s\n", pj_string(state.d.pj));
			pj_free(state.d.pj);
		} else {
			RzCmdStateOutput state = {.mode = RZ_OUTPUT_MODE_TABLE, .d.t = rz_table_new()};
			if (!state.d.t) {
				rz_core_file_close(fh);
				rz_core_fini(&core);
				return 1;
			}
			rz_core_bin_archs_print(bin, &state);
			char *s = rz_table_tostring(state.d.t);
			rz_cons_printf("%s", s);
			free(s);
		}
		free(arch_name);
	}
	if (action & RZ_BIN_REQ_PDB_DWNLD) {
		SPDBOptions pdbopts;
		pdbopts.user_agent = (char *)rz_config_get(core.config, "pdb.useragent");
		pdbopts.symbol_server = (char *)rz_config_get(core.config, "pdb.server");
		pdbopts.extract = rz_config_get_i(core.config, "pdb.extract");

		if ((tmp = rz_sys_getenv("RZ_BIN_SYMSTORE"))) {
			rz_config_set(core.config, "pdb.symstore", tmp);
			RZ_FREE(tmp);
		}
		pdbopts.symbol_store_path = (char *)rz_config_get(core.config, "pdb.symstore");
		result = rz_bin_pdb_download(&core, pj, isradjson, &pdbopts);
	}

	if ((tmp = rz_sys_getenv("RZ_BIN_PREFIX"))) {
		rz_config_set(core.config, "bin.prefix", tmp);
		free(tmp);
	}

	run_action("sections", RZ_BIN_REQ_SECTIONS, RZ_CORE_BIN_ACC_SECTIONS);
	run_action("segments", RZ_BIN_REQ_SEGMENTS, RZ_CORE_BIN_ACC_SEGMENTS);
	run_action("entries", RZ_BIN_REQ_ENTRIES, RZ_CORE_BIN_ACC_ENTRIES);
	run_action("initfini", RZ_BIN_REQ_INITFINI, RZ_CORE_BIN_ACC_INITFINI);
	run_action("main", RZ_BIN_REQ_MAIN, RZ_CORE_BIN_ACC_MAIN);
	run_action("imports", RZ_BIN_REQ_IMPORTS, RZ_CORE_BIN_ACC_IMPORTS);
	run_action("classes", RZ_BIN_REQ_CLASSES, RZ_CORE_BIN_ACC_CLASSES);
	run_action("symbols", RZ_BIN_REQ_SYMBOLS, RZ_CORE_BIN_ACC_SYMBOLS);
	run_action("exports", RZ_BIN_REQ_EXPORTS, RZ_CORE_BIN_ACC_EXPORTS);
	run_action("resources", RZ_BIN_REQ_RESOURCES, RZ_CORE_BIN_ACC_RESOURCES);
	run_action("strings", RZ_BIN_REQ_STRINGS, RZ_CORE_BIN_ACC_STRINGS);
	run_action("info", RZ_BIN_REQ_INFO, RZ_CORE_BIN_ACC_INFO);
	run_action("fields", RZ_BIN_REQ_FIELDS, RZ_CORE_BIN_ACC_FIELDS);
	run_action("header", RZ_BIN_REQ_HEADER, RZ_CORE_BIN_ACC_HEADER);
	run_action("libs", RZ_BIN_REQ_LIBS, RZ_CORE_BIN_ACC_LIBS);
	run_action("relocs", RZ_BIN_REQ_RELOCS, RZ_CORE_BIN_ACC_RELOCS);
	run_action("dwarf", RZ_BIN_REQ_DWARF, RZ_CORE_BIN_ACC_DWARF);
	run_action("pdb", RZ_BIN_REQ_PDB, RZ_CORE_BIN_ACC_PDB);
	run_action("size", RZ_BIN_REQ_SIZE, RZ_CORE_BIN_ACC_SIZE);
	run_action("versioninfo", RZ_BIN_REQ_VERSIONINFO, RZ_CORE_BIN_ACC_VERSIONINFO);
	run_action("sections", RZ_BIN_REQ_SIGNATURE, RZ_CORE_BIN_ACC_SIGNATURE);
	run_action("hashes", RZ_BIN_REQ_HASHES, RZ_CORE_BIN_ACC_HASHES);
	run_action("sections mapping", RZ_BIN_REQ_SECTIONS_MAPPING, RZ_CORE_BIN_ACC_SECTIONS_MAPPING);
	if (action & RZ_BIN_REQ_SRCLINE) {
		rabin_show_srcline(bin, at);
	}
	if (action & RZ_BIN_REQ_EXTRACT) {
		if (bf->xtr_data) {
			rabin_extract(bin, (!arch && !arch_name && !bits));
		} else {
			eprintf(
				"Cannot extract bins from '%s'. No supported "
				"plugins found!\n",
				bin->file);
		}
	}
	if (op && action & RZ_BIN_REQ_OPERATION) {
		rabin_do_operation(bin, op, rad, output, file);
	}
	if (isradjson) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
	}
	pj_free(pj);
	rz_cons_flush();
	rz_core_file_close(fh);
	rz_core_fini(&core);

	return result;
}
