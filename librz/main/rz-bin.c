// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_demangler.h>
#include <rz_types.h>
#include <rz_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <rz_main.h>
#include "../../librz/bin/pdb/pdb_downloader.h"

static void start_state(RzCmdStateOutput *state) {
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(state->d.pj);
	}
}

static void end_state(RzCmdStateOutput *state) {
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(state->d.pj);
		const char *s = pj_string(state->d.pj);
		if (s) {
			rz_cons_printf("%s\n", s);
		}
	}
}

static bool add_footer(RzCmdStateOutput *main_state, RzCmdStateOutput *state) {
	if (state->mode == RZ_OUTPUT_MODE_TABLE) {
		char *s = rz_table_tostring(state->d.t);
		if (!s) {
			return false;
		}
		rz_cons_printf("%s\n", s);
		free(s);
	} else if (state->mode == RZ_OUTPUT_MODE_JSON) {
		const char *state_json = pj_string(state->d.pj);
		pj_raw(main_state->d.pj, state_json);
	}
	rz_cmd_state_output_free(state);
	return true;
}

static RzCmdStateOutput *add_header(RzCmdStateOutput *main_state, RzOutputMode mode, const char *header) {
	RzCmdStateOutput *state = RZ_NEW(RzCmdStateOutput);
	rz_cmd_state_output_init(state, mode);
	if (mode == RZ_OUTPUT_MODE_TABLE || mode == RZ_OUTPUT_MODE_STANDARD) {
		rz_cons_printf("[%c%s]\n", toupper(header[0]), header + 1);
	} else if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_k(main_state->d.pj, header);
	}
	return state;
}

static void classes_as_source_print(RzCore *core, RzCmdStateOutput *state) {
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (bf) {
		rz_core_bin_class_as_source_print(core, bf, NULL);
	}
}

static RzOutputMode rad2outputmode(int rad) {
	switch (rad) {
	case RZ_MODE_JSON:
		return RZ_OUTPUT_MODE_JSON;
	case RZ_MODE_SIMPLE:
		return RZ_OUTPUT_MODE_QUIET;
	case RZ_MODE_SIMPLEST:
		return RZ_OUTPUT_MODE_QUIETEST;
	case RZ_MODE_RIZINCMD:
		return RZ_OUTPUT_MODE_RIZIN;
	case RZ_MODE_PRINT:
	default:
		return RZ_OUTPUT_MODE_STANDARD;
	}
}

static ut32 actions2mask(ut64 action) {
	ut32 res = 0;
	if (action & RZ_BIN_REQ_SECTIONS) {
		res |= RZ_CORE_BIN_ACC_SECTIONS;
	}
	if (action & RZ_BIN_REQ_SEGMENTS) {
		res |= RZ_CORE_BIN_ACC_SEGMENTS;
	}
	if (action & RZ_BIN_REQ_ENTRIES) {
		res |= RZ_CORE_BIN_ACC_ENTRIES;
	}
	if (action & RZ_BIN_REQ_INITFINI) {
		res |= RZ_CORE_BIN_ACC_INITFINI;
	}
	if (action & RZ_BIN_REQ_MAIN) {
		res |= RZ_CORE_BIN_ACC_MAIN;
	}
	if (action & RZ_BIN_REQ_IMPORTS) {
		res |= RZ_CORE_BIN_ACC_IMPORTS;
	}
	if (action & RZ_BIN_REQ_CLASSES) {
		res |= RZ_CORE_BIN_ACC_CLASSES;
	}
	if (action & RZ_BIN_REQ_SYMBOLS) {
		res |= RZ_CORE_BIN_ACC_SYMBOLS;
	}
	if (action & RZ_BIN_REQ_EXPORTS) {
		res |= RZ_CORE_BIN_ACC_EXPORTS;
	}
	if (action & RZ_BIN_REQ_RESOURCES) {
		res |= RZ_CORE_BIN_ACC_RESOURCES;
	}
	if (action & RZ_BIN_REQ_STRINGS) {
		res |= RZ_CORE_BIN_ACC_STRINGS;
	}
	if (action & RZ_BIN_REQ_INFO) {
		res |= RZ_CORE_BIN_ACC_INFO;
	}
	if (action & RZ_BIN_REQ_FIELDS) {
		res |= RZ_CORE_BIN_ACC_FIELDS;
	}
	if (action & RZ_BIN_REQ_HEADER) {
		res |= RZ_CORE_BIN_ACC_HEADER;
	}
	if (action & RZ_BIN_REQ_LIBS) {
		res |= RZ_CORE_BIN_ACC_LIBS;
	}
	if (action & RZ_BIN_REQ_RELOCS) {
		res |= RZ_CORE_BIN_ACC_RELOCS;
	}
	if (action & RZ_BIN_REQ_DWARF) {
		res |= RZ_CORE_BIN_ACC_DWARF;
	}
	if (action & RZ_BIN_REQ_PDB) {
		res |= RZ_CORE_BIN_ACC_PDB;
	}
	if (action & RZ_BIN_REQ_SIZE) {
		res |= RZ_CORE_BIN_ACC_SIZE;
	}
	if (action & RZ_BIN_REQ_VERSIONINFO) {
		res |= RZ_CORE_BIN_ACC_VERSIONINFO;
	}
	if (action & RZ_BIN_REQ_SIGNATURE) {
		res |= RZ_CORE_BIN_ACC_SIGNATURE;
	}
	if (action & RZ_BIN_REQ_SECTIONS_MAPPING) {
		res |= RZ_CORE_BIN_ACC_SECTIONS_MAPPING;
	}
	if (action & RZ_BIN_REQ_BASEFIND) {
		res |= RZ_CORE_BIN_ACC_BASEFIND;
	}
	return res;
}

static int rzbin_show_help(int v) {
	printf("%s%s%s", Color_CYAN, "Usage: ", Color_RESET);
	printf("rz-bin [-AcdeEghHiIjlLMqrRsSUvVxzZ] [-@ at] [-a arch] [-b bits] [-B addr]\n"
	       "              [-C F:C:D] [-f str] [-m addr] [-n str] [-N m:M] [-P pdb]\n"
	       "              [-o str] [-O str] [-k query] [-D lang symname] file\n");
	if (v) {
		const char *options[] = {
			// clang-format off
			"-@",           "[addr]",       "Show section, symbol, or import at the given address",
			"-A",           "",             "List sub-binaries and their arch-bits pairs",
			"-a",           "[arch]",       "Set arch (x86, arm, .. or <arch>_<bits>)",
			"-b",           "[bits]",       "Set bits (32, 64 ...)",
			"-B",           "[addr]",       "Override base address (pie bins)",
			"-c",           "",             "List classes",
			"-cc",          "",             "List classes in header format",
			"-C",           "[fmt:C:D]",    "Create [elf,mach0,pe] with Code and Data hexpairs (see -a)",
			"-d",           "",             "Show debug/dwarf information",
			"-dd",          "",             "Load debug/dwarf information from debuginfod server",
			"-D",           "lang name",    "Demangle symbol name (-D all for bin.demangle=true)z",
			"-e",           "",             "Entrypoint",
			"-ee",          "",             "Constructor/destructor entrypoints",
			"-E",           "",             "Globally exportable symbols",
			"-f",           "[str]",        "Select sub-bin named str",
			"-F",           "[binfmt]",     "Force to use that bin plugin (ignore header check)",
			"-g",           "",             "Same as -SMZIHVResizcld -SS -SSS -ee (show all info)",
			"-G",           "[addr]",       "Load address . offset to header",
			"-h",           "",             "Show this help",
			"-H",           "",             "Header fields",
			"-i",           "",             "Import (symbols imported from libraries)",
			"-I",           "",             "Binary info",
			"-j",           "",             "Output in JSON",
			"-k",           "[sdb-query]",  "Run sdb query. for example: '*'",
			"-K",           "[algo]",       "Calculate checksums (md5, sha1, ..)",
			"-l",           "",             "Linked libraries",
			"-L",           "[plugin]",     "List supported bin plugins or plugin details",
			"-m",           "[addr]",       "Show source line at addr",
			"-M",           "",             "Main (show address of main symbol)",
			"-n",           "[str]",        "Show section, symbol or import named str",
			"-N",           "[min:max]",    "Force min:max number of chars per string (see -z and -zz)",
			"-o",           "[str]",        "Output file/folder for write operations (out by default)",
			"-O",           "[str]",        "Write/extract operations (-O help)",
			"-p",           "",             "Show physical addresses",
			"-P",           "",             "Show debug/pdb information",
			"-PP",          "",             "Download pdb file for binary",
			"-q",           "",             "Quiet mode, just show fewer data",
			"-qq",          "",             "Show less info (no offset/size for -z for ex.)",
			"-Q",           "",             "Show load address used by dlopen (non-aslr libs)",
			"-r",           "",             "Show output in rizin format",
			"-R",           "",             "Show relocations",
			"-s",           "",             "Symbols",
			"-S",           "",             "Sections",
			"-SS",          "",             "Segments",
			"-SSS",         "",             "Sections mapping to segments",
			"-T",           "",             "Display file signature",
			"-u",           "",             "Unfiltered (no rename duplicated symbols/sections)",
			"-U",           "",             "Resources",
			"-v",           "",             "Show version information",
			"-V",           "",             "Show binary version information",
			"-w",           "",             "Display try/catch blocks",
			"-x",           "",             "Extract bins contained in file",
			"-X",           "[fmt] [f] ..", "Package in fat or zip the given files and bins contained in file",
			"-Y",           "[fw file]",    "Calculate all the possibles base address candidates of a firmware bin",
			"-z",           "",             "Show strings (from data section)",
			"-zz",          "",             "Show strings (from raw strings from bin)",
			"-zzz",         "",             "Dump raw strings to stdout (for huge files)",
			"-Z",           "",             "Guess size of binary program",
			// clang-format on
		};
		size_t maxOptionAndArgLength = 0;
		for (int i = 0; i < sizeof(options) / sizeof(options[0]); i += 3) {
			size_t optionLength = strlen(options[i]);
			size_t argLength = strlen(options[i + 1]);
			size_t totalLength = optionLength + argLength;
			if (totalLength > maxOptionAndArgLength) {
				maxOptionAndArgLength = totalLength;
			}
		}
		for (int i = 0; i < sizeof(options) / sizeof(options[0]); i += 3) {
			if (i + 1 < sizeof(options) / sizeof(options[0])) {
				rz_print_colored_help_option(options[i], options[i + 1], options[i + 2], maxOptionAndArgLength);
			}
		}
	}
	if (v) {
		printf("Environment:\n"
		       " RZ_BIN_CODESIGN_VERBOSE:                               # make code signatures verbose\n"
		       " RZ_BIN_DEBASE64:         e bin.debase64                # try to debase64 all strings\n"
		       " RZ_BIN_DEBUGINFOD_URLS:  e bin.dbginfo.debuginfod_urls # use alternative debuginfod server\n"
		       " RZ_BIN_DEMANGLE=0:       e bin.demangle                # do not demangle symbols\n"
		       " RZ_BIN_LANG:             e bin.lang                    # assume lang for demangling\n"
		       " RZ_BIN_MAXSTRBUF:        e str.search.buffer_size      # specify maximum buffer size\n"
		       " RZ_BIN_PDBSERVER:        e pdb.server                  # use alternative PDB server\n"
		       " RZ_BIN_PREFIX:           e bin.prefix                  # prefix symbols/sections/relocs with a specific string\n"
		       " RZ_BIN_STRFILTER:        e bin.str.filter              # rizin -qc 'e bin.str.filter=?"
		       "?' -\n"
		       " RZ_BIN_STRPURGE:         e bin.str.purge               # try to purge false positives\n"
		       " RZ_BIN_SYMSTORE:         e pdb.symstore                # path to downstream PDB symbol store\n"
		       " RZ_CONFIG:                                             # config file\n"
		       " RZ_NOPLUGINS:                                          # do not load shared plugins (speedup loading)\n");
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

static int rzbin_extract(RzBin *bin, int all) {
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

static int rzbin_dump_symbols(RzBin *bin, int len) {
	RzBinObject *o = rz_bin_cur_object(bin);
	RzPVector *symbols = o ? (RzPVector *)rz_bin_object_get_symbols(o) : NULL;
	if (!symbols) {
		return false;
	}

	void **iter;
	RzBinSymbol *symbol;
	int olen = len;
	rz_pvector_foreach (symbols, iter) {
		symbol = *iter;
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
	void **iter;
	RzBinSection *section;
	ut8 *buf;
	char *ret;
	int r;

	RzBinObject *obj = rz_bin_cur_object(bin);
	const RzPVector *sections = obj ? rz_bin_object_get_sections_all(obj) : NULL;
	if (!sections) {
		return false;
	}

	rz_pvector_foreach (sections, iter) {
		section = *iter;
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
			// it does mean the user specified an output file
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

static int rzbin_do_operation(RzBin *bin, const char *op, int rad, const char *output, const char *file) {
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
			goto _rzbin_do_operation_error;
		}
		switch (*ptr) {
		case 's': {
			ut64 a = ptr2 ? rz_num_math(NULL, ptr2) : 0;
			if (!rzbin_dump_symbols(bin, a)) {
				goto error;
			}
		} break;
		case 'S':
			if (!ptr2) {
				goto _rzbin_do_operation_error;
			}
			if (!__dumpSections(bin, ptr2, output, file)) {
				goto error;
			}
			break;
		default:
			goto _rzbin_do_operation_error;
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
	_rzbin_do_operation_error:
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

static int rzbin_show_srcline(RzBin *bin, ut64 at) {
	rz_return_val_if_fail(bin, false);
	char *srcline;
	RzDebugInfoOption option = { 0 };
	option.file = true;
	option.abspath = true;
	RzBinObject *o = rz_bin_cur_object(bin);
	if (!o) {
		return false;
	}
	RzBinSourceLineInfo *sl = o->lines;
	if (at == UT64_MAX || !sl) {
		return false;
	}
	srcline = rz_bin_source_line_addr2text(sl, at, option);
	printf("%s\n", srcline);
	free(srcline);
	return true;
}

/* bin callback */
static bool lib_demangler_cb(RzLibPlugin *pl, void *user, void *data) {
	return rz_demangler_plugin_add(user, (RzDemanglerPlugin *)data);
}

static bool lib_demangler_dt(RzLibPlugin *pl, void *user, void *data) {
	return rz_demangler_plugin_del(user, (RzDemanglerPlugin *)data);
}

static bool lib_bin_cb(RzLibPlugin *pl, void *user, void *data) {
	return rz_bin_plugin_add(user, (RzBinPlugin *)data);
}

static bool lib_bin_dt(RzLibPlugin *pl, void *user, void *data) {
	return rz_bin_plugin_del(user, (RzBinPlugin *)data);
}

/* binxtr callback */
static bool lib_bin_xtr_cb(RzLibPlugin *pl, void *user, void *data) {
	return rz_bin_xtr_plugin_add(user, (RzBinXtrPlugin *)data);
}

static bool lib_bin_xtr_dt(RzLibPlugin *pl, void *user, void *data) {
	return rz_bin_xtr_plugin_del(user, (RzBinXtrPlugin *)data);
}

static void __listPlugins(RzBin *bin, const char *plugin_name, PJ *pj, int rad) {
	int format = 0;
	RzCmdStateOutput state = { 0 };
	if (rad == RZ_MODE_JSON) {
		format = 'j';
		rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_JSON);
	} else if (rad) {
		format = 'q';
		rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_QUIET);
	} else {
		rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STANDARD);
	}
	bin->cb_printf = (PrintfCallback)printf;
	if (plugin_name) {
		rz_bin_list_plugin(bin, plugin_name, pj, format);
	} else {
		rz_core_bin_plugins_print(bin, &state);
		rz_cmd_state_output_print(&state);
		rz_cmd_state_output_fini(&state);
		rz_cons_flush();
	}
}

static bool print_demangler_info(const RzDemanglerPlugin *plugin, RzDemanglerFlag flags, void *user) {
	(void)user;
	printf("%-6s %-12s %s\n", plugin->language, plugin->license, plugin->author);
	return true;
}

static void print_string(RzBinFile *bf, RzBinString *string, PJ *pj, int mode) {
	rz_return_if_fail(bf && string);

	ut64 vaddr;
	RzBinSection *s = rz_bin_get_section_at(bf->o, string->paddr, false);
	if (s) {
		string->vaddr = s->vaddr + (string->paddr - s->paddr);
	}
	vaddr = bf->o ? rz_bin_object_get_vaddr(bf->o, string->paddr, string->vaddr) : UT64_MAX;
	const char *type_string = rz_str_enc_as_string(string->type);
	const char *section_name = s ? s->name : "";

	switch (mode) {
	case RZ_MODE_JSON:
		pj_o(pj);
		pj_kn(pj, "vaddr", vaddr);
		pj_kn(pj, "paddr", string->paddr);
		pj_kn(pj, "ordinal", string->ordinal);
		pj_kn(pj, "size", string->size);
		pj_kn(pj, "length", string->length);
		pj_ks(pj, "section", section_name);
		pj_ks(pj, "type", type_string);
		pj_ks(pj, "string", string->string);
		pj_end(pj);
		break;
	case RZ_MODE_SIMPLEST:
		printf("%s\n", string->string);
		break;
	case RZ_MODE_SIMPLE:
		printf("0x%" PFMT64x " %u %u %s\n", vaddr, string->size, string->length, string->string);
		break;
	case RZ_MODE_PRINT:
		printf("%03u 0x%08" PFMT64x " 0x%08" PFMT64x " %u %u (%s) %s %s\n",
			string->ordinal, string->paddr, vaddr,
			string->length, string->size,
			section_name, type_string, string->string);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_API int rz_main_rz_bin(int argc, const char **argv) {
	RzBin *bin = NULL;
	const char *name = NULL;
	const char *file = NULL;
	const char *output = NULL;
	int out_mode = RZ_MODE_PRINT;
	ut64 laddr = UT64_MAX;
	ut64 baddr = UT64_MAX;
	const char *do_demangle = NULL;
	const char *query = NULL;
	int c, bits = 0, actions = 0;
	char *create = NULL;
	ut64 action = RZ_BIN_REQ_UNK;
	char *tmp, *ptr, *arch_name = NULL;
	const char *arch = NULL;
	const char *forcebin = NULL;
	const char *chksum = NULL;
	const char *op = NULL;
	RzCoreFile *fh = NULL;
	RzCoreBinFilter filter;
	int xtr_idx = 0; // load all files if extraction is necessary.
	bool rawstr = false;
	int fd = -1;
	RzCore core = { 0 };
	ut64 at = UT64_MAX;
	int result = 0;

	rz_core_init(&core);
	bin = core.bin;
	if (!(tmp = rz_sys_getenv("RZ_NOPLUGINS"))) {
		char *homeplugindir = rz_path_home_prefix(RZ_PLUGINS);
		char *plugindir = rz_path_system(RZ_PLUGINS);
		char *extraplugindir = rz_path_extra(RZ_PLUGINS);
		RzLib *l = rz_lib_new(NULL, NULL);
		rz_lib_add_handler(l, RZ_LIB_TYPE_DEMANGLER, "demangler plugins",
			&lib_demangler_cb, &lib_demangler_dt, bin->demangler);
		rz_lib_add_handler(l, RZ_LIB_TYPE_BIN, "bin plugins",
			&lib_bin_cb, &lib_bin_dt, bin);
		rz_lib_add_handler(l, RZ_LIB_TYPE_BIN_XTR, "bin xtr plugins",
			&lib_bin_xtr_cb, &lib_bin_xtr_dt, bin);
		/* load plugins everywhere */
		char *path = rz_sys_getenv(RZ_LIB_ENV);
		if (!RZ_STR_ISEMPTY(path)) {
			rz_lib_opendir(l, path, false);
		}
		rz_lib_opendir(l, homeplugindir, false);
		rz_lib_opendir(l, plugindir, false);
		if (extraplugindir) {
			rz_lib_opendir(l, extraplugindir, false);
		}
		free(homeplugindir);
		free(plugindir);
		free(extraplugindir);
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
	if ((tmp = rz_sys_getenv("RZ_BIN_LANG"))) {
		rz_config_set(core.config, "bin.lang", tmp);
		free(tmp);
	}
	if ((tmp = rz_sys_getenv("RZ_BIN_DEMANGLE"))) {
		rz_config_set(core.config, "bin.demangle", tmp);
		free(tmp);
	}
	if ((tmp = rz_sys_getenv("RZ_BIN_MAXSTRBUF"))) {
		if (rz_num_is_valid_input(NULL, tmp)) {
			ut64 value = rz_num_math(NULL, tmp);
			rz_config_set_i(core.config, "str.search.buffer_size", value);
		}
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
	rz_getopt_init(&opt, argc, argv, "DjgAf:F:a:B:G:b:cC:k:K:dD:Mm:n:N:@:isSVIHeEUlRwO:o:pPqQrTvLhuxYXzZ");
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
		case 'w': set_action(RZ_BIN_REQ_TRYCATCH); break;
		case 'q':
			out_mode = (out_mode & RZ_MODE_SIMPLE ? RZ_MODE_SIMPLEST : RZ_MODE_SIMPLE);
			break;
		case 'j': out_mode = RZ_MODE_JSON; break;
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
				action &= ~RZ_BIN_REQ_CLASSES;
				action |= RZ_BIN_REQ_CLASSES_SOURCES;
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
				rawstr = true;
			} else {
				set_action(RZ_BIN_REQ_STRINGS);
			}
			break;
		case 'Z': set_action(RZ_BIN_REQ_SIZE); break;
		case 'I': set_action(RZ_BIN_REQ_INFO); break;
		case 'H':
			set_action(RZ_BIN_REQ_FIELDS);
			break;
		case 'd':
			if (is_active(RZ_BIN_REQ_DWARF)) {
				set_action(RZ_BIN_REQ_DEBUGINFOD);
				break;
			} else {
				set_action(RZ_BIN_REQ_DWARF);
				break;
			}
		case 'P':
			if (is_active(RZ_BIN_REQ_PDB)) {
				action &= ~RZ_BIN_REQ_PDB;
				action |= RZ_BIN_REQ_PDB_DWNLD;
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
		case 'Y': set_action(RZ_BIN_REQ_BASEFIND); break;
		case 'x': set_action(RZ_BIN_REQ_EXTRACT); break;
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
		case 'p': core.io->va = false; break;
		case 'r': out_mode = RZ_MODE_RIZINCMD; break;
		case 'v':
			rz_core_fini(&core);
			return rz_main_version_print("rz-bin");
		case 'L':
			set_action(RZ_BIN_REQ_LISTPLUGINS);
			break;
		case 'G':
			laddr = rz_num_math(NULL, opt.arg);
			if (laddr == UT64_MAX) {
				core.io->va = false;
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
		case 'N': {
			tmp = strchr(opt.arg, ':');
			size_t value = rz_num_math(NULL, opt.arg);
			rz_config_set_i(core.config, "str.search.min_length", value);
			if (tmp) {
				value = rz_num_math(NULL, tmp + 1);
				rz_config_set_i(core.config, "str.search.buffer_size", value);
			}
			break;
		}
		case 'h':
			rz_core_fini(&core);
			return rzbin_show_help(1);
		default:
			action |= RZ_BIN_REQ_HELP;
			break;
		}
	}

	if (is_active(RZ_BIN_REQ_LISTPLUGINS)) {
		const char *plugin_name = NULL;
		if (opt.ind < argc) {
			plugin_name = argv[opt.ind];
		}
		PJ *pj = pj_new();
		if (!pj) {
			rz_core_fini(&core);
			return 1;
		}
		__listPlugins(bin, plugin_name, pj, out_mode);
		if (out_mode == RZ_MODE_JSON) {
			rz_cons_println(pj_string(pj));
			rz_cons_flush();
		}
		rz_core_fini(&core);
		return 0;
	}

	if (do_demangle) {
		int ret_num = 1;
		char *res = NULL;
		const RzDemanglerPlugin *plugin = NULL;
		if ((argc - opt.ind) < 2) {
			rz_core_fini(&core);
			return rzbin_show_help(0);
		}
		file = argv[opt.ind + 1];
		plugin = rz_demangler_plugin_get(bin->demangler, do_demangle);
		if (!plugin) {
			printf("Language '%s' is unsupported\nList of supported languages:\n", do_demangle);
			rz_demangler_plugin_iterate(bin->demangler, (RzDemanglerIter)print_demangler_info, NULL);
			rz_core_fini(&core);
			return 1;
		}
		RzDemanglerFlag dflags = rz_demangler_get_flags(bin->demangler);
		if (!strcmp(file, "-")) {
			for (;;) {
				file = stdin_gets(false);
				if (!file || !*file) {
					break;
				}
				res = rz_demangler_plugin_demangle(plugin, file, dflags);
				if (RZ_STR_ISNOTEMPTY(res)) {
					printf("%s\n", res);
					ret_num = 0;
				} else if (file && *file) {
					printf("%s\n", file);
				}
				RZ_FREE(res);
				RZ_FREE(file);
			}
			stdin_gets(true);
		} else {
			res = rz_demangler_plugin_demangle(plugin, file, dflags);
			if (RZ_STR_ISNOTEMPTY(res)) {
				printf("%s\n", res);
				ret_num = 0;
			} else {
				printf("%s\n", file);
			}
		}
		free(res);
		rz_core_fini(&core);
		return ret_num;
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
			return rzbin_show_help(0);
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
	if (rawstr) {
		unset_action(RZ_BIN_REQ_STRINGS);
	}

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
		void *addr = rz_sys_dlopen(file);
		if (addr) {
			eprintf("%s is loaded at 0x%" PFMT64x "\n", file, (ut64)(size_t)(addr));
			rz_sys_dlclose(addr);
			rz_core_fini(&core);
			return 0;
		}
		eprintf("Cannot open the '%s' library\n", file);
		rz_core_fini(&core);
		return 0;
	}

	if (RZ_STR_ISNOTEMPTY(file)) {
		if ((fh = rz_core_file_open(&core, file, RZ_PERM_R, 0))) {
			fd = rz_io_fd_get_current(core.io);
			if (fd == -1) {
				eprintf("rz_core: Cannot open file '%s'\n", file);
				result = 1;
				goto err;
			}
		} else {
			eprintf("rz_core: Cannot open file '%s'\n", file);
			rz_core_fini(&core);
			return 1;
		}
	}

	rz_bin_force_plugin(bin, forcebin);
	rz_bin_load_filter(bin, action);

	RzBinOptions bo;
	rz_bin_options_init(&bo, fd, baddr, laddr, false);
	bo.obj_opts.elf_load_sections = rz_config_get_b(core.config, "elf.load.sections");
	bo.obj_opts.elf_checks_sections = rz_config_get_b(core.config, "elf.checks.sections");
	bo.obj_opts.elf_checks_segments = rz_config_get_b(core.config, "elf.checks.segments");
	bo.obj_opts.big_endian = rz_config_get_b(core.config, "cfg.bigendian");
	bo.xtr_idx = xtr_idx;

	RzBinFile *bf = rz_bin_open(bin, file, &bo);
	if (!bf) {
		/* Try opening as a binary file */
		bo.pluginname = "any";
		RZ_LOG_INFO("Treating input file as a binary file...\n");

		bf = rz_bin_open(bin, file, &bo);
		if (!bf) {
			RZ_LOG_ERROR("rz-bin: Cannot open file\n");
			result = 1;
			goto err;
		}
	}
	/* required to automatically select a sub-bin when not specified */
	(void)rz_core_bin_update_arch_bits(&core);

	if (baddr != UT64_MAX) {
		rz_bin_set_baddr(bin, baddr);
	}

	if (rawstr) {
		PJ *pj = NULL;
		if (out_mode == RZ_MODE_JSON) {
			pj = pj_new();
			if (!pj) {
				eprintf("rz-bin: Cannot allocate buffer for json array\n");
				result = 1;
				goto err;
			}
			pj_a(pj);
		}
		RzBinStringSearchOpt opt = bin->str_search_cfg;
		// enforce raw binary search
		opt.mode = RZ_BIN_STRING_SEARCH_MODE_RAW_BINARY;
		RzPVector *vec = rz_bin_file_strings(bf, &opt);
		void **it;
		RzBinString *string;
		rz_pvector_foreach (vec, it) {
			string = *it;
			print_string(bf, string, pj, out_mode);
		}
		rz_pvector_free(vec);
		if (pj) {
			pj_end(pj);
			printf("%s", pj_string(pj));
			pj_free(pj);
		}
	} else if (bf && bf->o) {
		rz_bin_object_reset_strings(bin, bf, bf->o);
	}
	if (query) {
		if (out_mode) {
			rz_core_bin_export_info(&core, RZ_MODE_RIZINCMD);
			rz_cons_flush();
		} else {
			if (!strcmp(query, "-")) {
				__sdb_prompt(bin->cur->sdb);
			} else {
				sdb_query(bin->cur->sdb, query);
			}
		}
		result = 0;
		goto err;
	}
#define ismodejson (out_mode == RZ_MODE_JSON && actions > 0)
#define run_action(n, x, y) \
	if (action & (x)) { \
		RzCmdStateOutput *st = add_header(&state, mode, n); \
		y(&core, st); \
		add_footer(&state, st); \
	}

	core.bin = bin;
	bin->cb_printf = rz_cons_printf;
	filter.offset = at;
	filter.name = name;
	RzList *chksum_list = NULL;
	if (RZ_STR_ISNOTEMPTY(chksum)) {
		chksum_list = rz_str_split_duplist_n(chksum, ",", 0, true);
		if (!chksum_list) {
			result = 1;
			goto err;
		}
	}
	rz_cons_new()->context->is_interactive = false;

	RzCmdStateOutput state;
	RzOutputMode mode = rad2outputmode(out_mode);
	if (!rz_cmd_state_output_init(&state, mode)) {
		result = 1;
		goto chksum_err;
	}
	start_state(&state);

	// List fatmach0 sub-binaries, etc
	if (action & RZ_BIN_REQ_LISTARCHS || ((arch || bits || arch_name) && !rz_bin_select(bin, arch, bits, arch_name))) {
		RzCmdStateOutput *st = add_header(&state, mode == RZ_OUTPUT_MODE_STANDARD ? RZ_OUTPUT_MODE_TABLE : mode, "archs");
		rz_core_bin_archs_print(bin, st);
		add_footer(&state, st);
		free(arch_name);
	}
	if (action & RZ_BIN_REQ_PDB_DWNLD) {
		SPDBOptions pdbopts;
		pdbopts.symbol_server = (char *)rz_config_get(core.config, "pdb.server");
		pdbopts.extract = rz_config_get_i(core.config, "pdb.extract");

		if ((tmp = rz_sys_getenv("RZ_BIN_SYMSTORE"))) {
			rz_config_set(core.config, "pdb.symstore", tmp);
			RZ_FREE(tmp);
		}
		pdbopts.symbol_store_path = (char *)rz_config_get(core.config, "pdb.symstore");
		result = rz_bin_pdb_download(core.bin, state.mode == RZ_OUTPUT_MODE_JSON ? state.d.pj : NULL, ismodejson, &pdbopts);
	}
	if (action & RZ_BIN_REQ_DEBUGINFOD) {
		rz_config_set_b(core.config, "bin.dbginfo.debuginfod", true);
		if ((tmp = rz_sys_getenv("RZ_BIN_DEBUGINFOD_URLS"))) {
			if (RZ_STR_ISNOTEMPTY(tmp)) {
				rz_config_set(core.config, "bin.dbginfo.debuginfod_urls", tmp);
			}
			free(tmp);
		}
	}

	if ((tmp = rz_sys_getenv("RZ_BIN_PREFIX"))) {
		rz_config_set(core.config, "bin.prefix", tmp);
		free(tmp);
	}

	ut32 mask = actions2mask(action);
	rz_core_bin_print(&core, bf, mask, &filter, &state, chksum_list);

	run_action("classes source", RZ_BIN_REQ_CLASSES_SOURCES, classes_as_source_print);
	if (action & RZ_BIN_REQ_SRCLINE) {
		rzbin_show_srcline(bin, at);
	}
	if (action & RZ_BIN_REQ_EXTRACT) {
		if (bf->xtr_data) {
			rzbin_extract(bin, (!arch && !arch_name && !bits));
		} else {
			eprintf(
				"Cannot extract bins from '%s'. No supported "
				"plugins found!\n",
				bin->file);
		}
	}
	if (op && action & RZ_BIN_REQ_OPERATION) {
		rzbin_do_operation(bin, op, out_mode, output, file);
	}
	end_state(&state);
	rz_cmd_state_output_fini(&state);

	rz_cons_flush();

chksum_err:
	rz_list_free(chksum_list);
err:
	rz_core_file_close(fh);
	rz_core_fini(&core);

	return result;
}
