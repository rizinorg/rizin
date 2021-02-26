// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include "rz_analysis.h"
#include "rz_cons.h"
#include "rz_core.h"
#include <sdb.h>
#include "core_private.h"

static const char *help_msg_t[] = {
	"Usage: t", "", "# cparse types commands",
	"t", "", "List all loaded types",
	"tj", "", "List all loaded types as json",
	"t", " <type>", "Show type in 'pf' syntax",
	"t*", "", "List types info in rizin commands",
	"t-", " <name>", "Delete types by its name",
	"t-*", "", "Remove all types",
	"tc", " [type.name]", "List all/given types in C output format",
	"te", "[?]", "List all loaded enums",
	"td", "[?] <string>", "Load types from string",
	"tf", "", "List all loaded functions signatures",
	"tk", " <sdb-query>", "Perform sdb query",
	"tl", "[?]", "Show/Link type to an address",
	"tn", "[?] [-][addr]", "manage noreturn function attributes and marks",
	"to", " -", "Open cfg.editor to load types",
	"to", " <path>", "Load types from C header file",
	"toe", " [type.name]", "Open cfg.editor to edit types",
	"tos", " <path>", "Load types from parsed Sdb database",
	"touch", " <file>", "Create or update timestamp in file",
	"tp", "  <type> [addr|varname]", "cast data at <address> to <type> and print it (XXX: type can contain spaces)",
	"tpv", " <type> @ [value]", "Show offset formatted for given type",
	"tpx", " <type> <hexpairs>", "Show value for type with specified byte sequence (XXX: type can contain spaces)",
	"ts", "[?]", "Print loaded struct types",
	"tu", "[?]", "Print loaded union types",
	"tx", "[f?]", "Type xrefs",
	"tt", "[?]", "List all loaded typedefs",
	NULL
};

static const char *help_msg_tcc[] = {
	"Usage: tfc", "[-name]", "# type function calling conventions",
	"tcc", "", "List all calling convcentions",
	"tcc", " r0 pascal(r0,r1,r2)", "Show signature for the 'pascal' calling convention",
	"tcc", "-pascal", "Remove the pascal cc",
	"tcc-*", "", "Unregister all the calling conventions",
	"tcck", "", "List calling conventions in k=v",
	"tccl", "", "List the cc signatures",
	"tccj", "", "List them in JSON",
	"tcc*", "", "List them as rizin commands",
	NULL
};

static const char *help_msg_t_minus[] = {
	"Usage: t-", " <type>", "Delete type by its name",
	NULL
};

static const char *help_msg_tf[] = {
	"Usage: tf[...]", "", "",
	"tf", "", "List all function definitions loaded",
	"tf", " <name>", "Show function signature",
	"tfc", " <name>", "Show function signature in C syntax",
	"tfcj", " <name>", "Same as above but in JSON",
	"tfj", "", "List all function definitions in JSON",
	"tfj", " <name>", "Show function signature in JSON",
	NULL
};

static const char *help_msg_to[] = {
	"Usage: to[...]", "", "",
	"to", " -", "Open cfg.editor to load types",
	"to", " <path>", "Load types from C header file",
	"tos", " <path>", "Load types from parsed Sdb database",
	"touch", " <file>", "Create or update timestamp in file",
	NULL
};

static const char *help_msg_tp[] = {
	"Usage: tp[...]", "", "",
	"tp", "  <type> [addr|varname]", "cast data at <address> to <type> and print it (XXX: type can contain spaces)",
	"tpv", " <type> @ [value]", "Show offset formatted for given type",
	"tpx", " <type> <hexpairs>", "Show value for type with specified byte sequence (XXX: type can contain spaces)",
	NULL
};

static const char *help_msg_tc[] = {
	"Usage: tc[...]", " [cctype]", "",
	"tc", " [type.name]", "List all/given loaded types in C output format with newlines",
	"tcd", "", "List all loaded types in C output format without newlines",
	"tcc", "?", "Manage calling conventions types",
	"tc?", "", "show this help",
	NULL
};

static const char *help_msg_td[] = {
	"Usage:", "td \"[...]\"", "",
	"td", "[string]", "Load types from string",
	NULL
};

static const char *help_msg_te[] = {
	"Usage: te[...]", "", "",
	"te", "", "List all loaded enums",
	"te", " <enum>", "Print all values of enum for given name",
	"tej", "", "List all loaded enums in json",
	"tej", " <enum>", "Show enum in json",
	"te", " <enum> <value>", "Show name for given enum number",
	"teb", " <enum> <name>", "Show matching enum bitfield for given name",
	"tec", "<name>", "List all/given loaded enums in C output format with newlines",
	"ted", "", "List all loaded enums in C output format without newlines",
	"te?", "", "show this help",
	NULL
};

static const char *help_msg_tt[] = {
	"Usage: tt[...]", "", "",
	"tt", "", "List all loaded typedefs",
	"tt", " <typename>", "Show name for given type alias",
	"ttj", "", "Show typename and type alias in json",
	"ttc", "<name>", "Show typename and type alias in C output format",
	"tt?", "", "show this help",
	NULL
};

static const char *help_msg_tl[] = {
	"Usage: tl[...]", "[typename] [[=] address]", "# Type link commands",
	"tl", "", "list all links.",
	"tll", "", "list all links in readable format.",
	"tllj", "", "list all links in readable JSON format.",
	"tl", " [typename]", "link a type to current address.",
	"tl", " [typename] = [address]", "link type to given address.",
	"tls", " [address]", "show link at given address.",
	"tl-*", "", "delete all links.",
	"tl-", " [address]", "delete link at given address.",
	"tl*", "", "list all links in rizin command format.",
	"tlj", "", "list all links in JSON format.",
	NULL
};

static const char *help_msg_tn[] = {
	"Usage:", "tn [-][0xaddr|symname]", " manage no-return marks",
	"tn[a]", " 0x3000", "stop function analysis if call/jmp to this address",
	"tn[n]", " sym.imp.exit", "same as above but for flag/fcn names",
	"tn-", " 0x3000 sym.imp.exit ...", "remove some no-return references",
	"tn-*", "", "remove all no-return references",
	"tn", "", "list them all",
	NULL
};

static const char *help_msg_ts[] = {
	"Usage: ts[...]", " [type]", "",
	"ts", "", "List all loaded structs",
	"ts", " [type]", "Show pf format string for given struct",
	"tsj", "", "List all loaded structs in json",
	"tsj", " [type]", "Show pf format string for given struct in json",
	"ts*", "", "Show pf.<name> format string for all loaded structs",
	"ts*", " [type]", "Show pf.<name> format string for given struct",
	"tsc", "<name>", "List all/given loaded structs in C output format with newlines",
	"tsd", "", "List all loaded structs in C output format without newlines",
	"tss", " [type]", "Display size of struct",
	"ts", "[?]", "show this help",
	NULL
};

static const char *help_msg_tu[] = {
	"Usage: tu[...]", "", "",
	"tu", "", "List all loaded unions",
	"tu", " [type]", "Show pf format string for given union",
	"tuj", "", "List all loaded unions in json",
	"tuj", " [type]", "Show pf format string for given union in json",
	"tu*", "", "Show pf.<name> format string for all loaded unions",
	"tu*", " [type]", "Show pf.<name> format string for given union",
	"tuc", "<name>", "List all/given loaded unions in C output format with newlines",
	"tud", "", "List all loaded unions in C output format without newlines",
	"tu?", "", "show this help",
	NULL
};

static void types_cc_print_all(RzCore *core, RzOutputMode mode) {
	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_core_analysis_calling_conventions_print(core);
	} break;
	case RZ_OUTPUT_MODE_JSON: {
		RzList *list = rz_core_analysis_calling_conventions(core);
		RzListIter *iter;
		const char *cc;
		PJ *pj = pj_new();
		pj_a(pj);
		rz_list_foreach (list, iter, cc) {
			char *ccexpr = rz_analysis_cc_get(core->analysis, cc);
			// TODO: expose this as an object, not just an array of strings
			pj_s(pj, ccexpr);
			free(ccexpr);
		}
		pj_end(pj);
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
		rz_list_free(list);
	} break;
	case RZ_OUTPUT_MODE_LONG: {
		RzList *list = rz_core_analysis_calling_conventions(core);
		RzListIter *iter;
		const char *cc;
		rz_list_foreach (list, iter, cc) {
			char *ccexpr = rz_analysis_cc_get(core->analysis, cc);
			rz_cons_printf("%s\n", ccexpr);
			free(ccexpr);
		}
		rz_list_free(list);
	} break;
	case RZ_OUTPUT_MODE_RIZIN: {
		RzList *list = rz_core_analysis_calling_conventions(core);
		RzListIter *iter;
		const char *cc;
		rz_list_foreach (list, iter, cc) {
			char *ccexpr = rz_analysis_cc_get(core->analysis, cc);
			rz_cons_printf("tcc \"%s\"\n", ccexpr);
			free(ccexpr);
		}
		rz_list_free(list);
	} break;
	case RZ_OUTPUT_MODE_SDB:
		rz_core_kuery_print(core, "analysis/cc/*");
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

static void types_cc_print(RzCore *core, const char *cc, RzOutputMode mode) {
	rz_return_if_fail(cc);
	if (strchr(cc, '(')) {
		if (!rz_analysis_cc_set(core->analysis, cc)) {
			eprintf("Invalid syntax in cc signature.");
		}
	} else {
		const char *ccname = rz_str_trim_head_ro(cc);
		char *result = rz_analysis_cc_get(core->analysis, ccname);
		if (result) {
			if (mode == RZ_OUTPUT_MODE_JSON) {
				PJ *pj = rz_core_pj_new(core);
				pj_a(pj);
				pj_ks(pj, "cc", result);
				pj_end(pj);
				rz_cons_println(pj_string(pj));
				pj_free(pj);
			} else {
				rz_cons_printf("%s\n", result);
			}
			free(result);
		}
	}
}

static void __core_cmd_tcc(RzCore *core, const char *input) {
	switch (*input) {
	case '?':
		rz_core_cmd_help(core, help_msg_tcc);
		break;
	case '-':
		if (input[1] == '*') {
			sdb_reset(core->analysis->sdb_cc);
		} else {
			rz_analysis_cc_del(core->analysis, rz_str_trim_head_ro(input + 1));
		}
		break;
	case 0:
		types_cc_print_all(core, RZ_OUTPUT_MODE_STANDARD);
		break;
	case 'j':
		types_cc_print_all(core, RZ_OUTPUT_MODE_JSON);
		break;
	case 'l':
		types_cc_print_all(core, RZ_OUTPUT_MODE_LONG);
		break;
	case '*':
		types_cc_print_all(core, RZ_OUTPUT_MODE_RIZIN);
		break;
	case 'k':
		types_cc_print_all(core, RZ_OUTPUT_MODE_SDB);
		break;
	case ' ':
		types_cc_print(core, input + 1, RZ_OUTPUT_MODE_STANDARD);
		break;
	}
}

static void type_show_format(RzCore *core, const char *name, RzOutputMode mode) {
	const char *isenum = sdb_const_get(core->analysis->sdb_types, name, 0);
	if (isenum && !strcmp(isenum, "enum")) {
		eprintf("IS ENUM\n");
	} else {
		char *fmt = rz_type_format(core->analysis->sdb_types, name);
		if (fmt) {
			rz_str_trim(fmt);
			switch (mode) {
			case RZ_OUTPUT_MODE_JSON: {
				PJ *pj = pj_new();
				if (!pj) {
					return;
				}
				pj_o(pj);
				pj_ks(pj, "name", name);
				pj_ks(pj, "format", fmt);
				pj_end(pj);
				rz_cons_printf("%s", pj_string(pj));
				pj_free(pj);
			} break;
			case RZ_OUTPUT_MODE_RIZIN: {
				rz_cons_printf("pf.%s %s\n", name, fmt);
			} break;
			case RZ_OUTPUT_MODE_STANDARD: {
				// FIXME: Not really a standard format
				// We should think about better representation by default here
				rz_cons_printf("pf %s\n", fmt);
			} break;
			default:
				break;
			}
			free(fmt);
		} else {
			eprintf("Cannot find '%s' type\n", name);
		}
	}
}

static void noreturn_del(RzCore *core, const char *s) {
	RzListIter *iter;
	char *k;
	RzList *list = rz_str_split_duplist(s, " ", 0);
	rz_list_foreach (list, iter, k) {
		rz_analysis_noreturn_drop(core->analysis, k);
	}
	rz_list_free(list);
}

static void cmd_type_noreturn(RzCore *core, const char *input) {
	switch (input[0]) {
	case '-': // "tn-"
		if (input[1] == '*') {
			RzList *noretl = rz_core_analysis_noreturn(core);
			RzListIter *iter;
			char *name;
			rz_list_foreach (noretl, iter, name) {
				rz_analysis_noreturn_drop(core->analysis, name);
			}
		} else {
			char *s = strdup(rz_str_trim_head_ro(input + 1));
			noreturn_del(core, s);
			free(s);
		}
		break;
	case ' ': // "tn"
	{
		const char *arg = rz_str_trim_head_ro(input + 1);
		ut64 n = rz_num_math(core->num, arg);
		if (n) {
			rz_analysis_noreturn_add(core->analysis, arg, n);
		} else {
			rz_analysis_noreturn_add(core->analysis, arg, UT64_MAX);
		}
	} break;
	case 'a': // "tna"
		if (input[1] == ' ') {
			rz_analysis_noreturn_add(core->analysis, NULL,
				rz_num_math(core->num, input + 1));
		} else {
			rz_core_cmd_help(core, help_msg_tn);
		}
		break;
	case 'n': // "tnn"
		if (input[1] == ' ') {
			/* do nothing? */
			rz_analysis_noreturn_add(core->analysis, rz_str_trim_head_ro(input + 2), UT64_MAX);
		} else {
			rz_core_cmd_help(core, help_msg_tn);
		}
		break;
	case '*':
	case 'r': // "tn*"
		rz_core_analysis_noreturn_print(core, RZ_OUTPUT_MODE_RIZIN);
		break;
	case 'j': // "tnj"
		rz_core_analysis_noreturn_print(core, RZ_OUTPUT_MODE_JSON);
		break;
	case 0: // "tn"
		rz_core_analysis_noreturn_print(core, RZ_OUTPUT_MODE_STANDARD);
		break;
	default:
	case '?':
		rz_core_cmd_help(core, help_msg_tn);
		break;
	}
}

static Sdb *TDB_ = NULL; // HACK

static bool stdifstruct(void *user, const char *k, const char *v) {
	rz_return_val_if_fail(TDB_, false);
	if (!strcmp(v, "struct") && !rz_str_startswith(k, "typedef")) {
		return true;
	}
	if (!strcmp(v, "typedef")) {
		const char *typedef_key = sdb_fmt("typedef.%s", k);
		const char *type = sdb_const_get(TDB_, typedef_key, NULL);
		if (type && rz_str_startswith(type, "struct")) {
			return true;
		}
	}
	return false;
}

/*!
 * \brief print the data types details in JSON format
 * \param TDB pointer to the sdb for types
 * \param filter a callback function for the filtering
 * \return 1 if success, 0 if failure
 */
static int print_struct_union_list_json(Sdb *TDB, SdbForeachCallback filter) {
	PJ *pj = pj_new();
	if (!pj) {
		return 0;
	}
	SdbList *l = sdb_foreach_list_filter(TDB, filter, true);
	SdbListIter *it;
	SdbKv *kv;

	pj_a(pj); // [
	ls_foreach (l, it, kv) {
		const char *k = sdbkv_key(kv);
		if (!k || !*k) {
			continue;
		}
		pj_o(pj); // {
		pj_ks(pj, "type", k); // key value pair of string and string
		pj_end(pj); // }
	}
	pj_end(pj); // ]

	rz_cons_println(pj_string(pj));
	pj_free(pj);
	ls_free(l);
	return 1;
}

static void print_struct_union_in_c_format(Sdb *TDB, SdbForeachCallback filter, const char *arg, bool multiline) {
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list_filter(TDB, filter, true);
	const char *space = "";
	bool match = false;

	ls_foreach (l, iter, kv) {
		if (name && !strcmp(sdbkv_value(kv), name)) {
			continue;
		}
		free(name);
		int n;
		name = strdup(sdbkv_key(kv));
		if (name && (arg && *arg)) {
			if (!strcmp(arg, name)) {
				match = true;
			} else {
				continue;
			}
		}
		rz_cons_printf("%s %s {%s", sdbkv_value(kv), name, multiline ? "\n" : "");
		char *p, *var = rz_str_newf("%s.%s", sdbkv_value(kv), name);
		for (n = 0; (p = sdb_array_get(TDB, var, n, NULL)); n++) {
			char *var2 = rz_str_newf("%s.%s", var, p);
			if (var2) {
				char *val = sdb_array_get(TDB, var2, 0, NULL);
				if (val) {
					char *arr = sdb_array_get(TDB, var2, 2, NULL);
					int arrnum = atoi(arr);
					free(arr);
					if (multiline) {
						rz_cons_printf("\t%s", val);
						if (p && p[0] != '\0') {
							rz_cons_printf("%s%s", strstr(val, " *") ? "" : " ", p);
							if (arrnum) {
								rz_cons_printf("[%d]", arrnum);
							}
						}
						rz_cons_println(";");
					} else {
						rz_cons_printf("%s%s %s", space, val, p);
						if (arrnum) {
							rz_cons_printf("[%d]", arrnum);
						}
						rz_cons_print(";");
						space = " ";
					}
					free(val);
				}
				free(var2);
			}
			free(p);
		}
		free(var);
		rz_cons_println("};");
		space = "";
		if (match) {
			break;
		}
	}
	free(name);
	ls_free(l);
}

static void print_enum_in_c_format(Sdb *TDB, const char *arg, bool multiline) {
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(TDB, true);
	const char *separator = "";
	bool match = false;
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "enum")) {
			if (!name || strcmp(sdbkv_value(kv), name)) {
				free(name);
				name = strdup(sdbkv_key(kv));
				if (name && (arg && *arg)) {
					if (!strcmp(arg, name)) {
						match = true;
					} else {
						continue;
					}
				}
				rz_cons_printf("%s %s {%s", sdbkv_value(kv), name, multiline ? "\n" : "");
				{
					RzList *list = rz_type_get_enum(TDB, name);
					if (list && !rz_list_empty(list)) {
						RzListIter *iter;
						RTypeEnum *member;
						separator = multiline ? "\t" : "";
						rz_list_foreach (list, iter, member) {
							rz_cons_printf("%s%s = %" PFMT64u, separator, member->name, rz_num_math(NULL, member->val));
							separator = multiline ? ",\n\t" : ", ";
						}
					}
					rz_list_free(list);
				}
				rz_cons_println(multiline ? "\n};" : "};");
				if (match) {
					break;
				}
			}
		}
	}
	free(name);
	ls_free(l);
}

static bool printkey_cb(void *user, const char *k, const char *v) {
	rz_cons_println(k);
	return true;
}

// maybe dupe?. should return char *instead of print for reusability
static void printFunctionTypeC(RzCore *core, const char *input) {
	Sdb *TDB = core->analysis->sdb_types;
	char *res = sdb_querys(TDB, NULL, -1, sdb_fmt("func.%s.args", input));
	const char *name = rz_str_trim_head_ro(input);
	int i, args = sdb_num_get(TDB, sdb_fmt("func.%s.args", name), 0);
	const char *ret = sdb_const_get(TDB, sdb_fmt("func.%s.ret", name), 0);
	if (!ret) {
		ret = "void";
	}
	if (!ret || !name) {
		// missing function name specified
		return;
	}

	rz_cons_printf("%s %s (", ret, name);
	for (i = 0; i < args; i++) {
		char *type = sdb_get(TDB, sdb_fmt("func.%s.arg.%d", name, i), 0);
		char *name = strchr(type, ',');
		if (name) {
			*name++ = 0;
		}
		rz_cons_printf("%s%s %s", i == 0 ? "" : ", ", type, name);
	}
	rz_cons_printf(");\n");
	free(res);
}

static void printFunctionType(RzCore *core, const char *input) {
	Sdb *TDB = core->analysis->sdb_types;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	char *res = sdb_querys(TDB, NULL, -1, sdb_fmt("func.%s.args", input));
	const char *name = rz_str_trim_head_ro(input);
	int i, args = sdb_num_get(TDB, sdb_fmt("func.%s.args", name), 0);
	pj_ks(pj, "name", name);
	const char *ret_type = sdb_const_get(TDB, sdb_fmt("func.%s.ret", name), 0);
	pj_ks(pj, "ret", ret_type ? ret_type : "void");
	pj_k(pj, "args");
	pj_a(pj);
	for (i = 0; i < args; i++) {
		char *type = sdb_get(TDB, sdb_fmt("func.%s.arg.%d", name, i), 0);
		if (!type) {
			continue;
		}
		char *name = strchr(type, ',');
		if (name) {
			*name++ = 0;
		}
		pj_o(pj);
		pj_ks(pj, "type", type);
		if (name) {
			pj_ks(pj, "name", name);
		} else {
			pj_ks(pj, "name", "(null)");
		}
		pj_end(pj);
	}
	pj_end(pj);
	pj_end(pj);
	rz_cons_printf("%s", pj_string(pj));
	pj_free(pj);
	free(res);
}

static bool printfunc_json_cb(void *user, const char *k, const char *v) {
	printFunctionType((RzCore *)user, k);
	return true;
}

static bool stdiffunc(void *p, const char *k, const char *v) {
	return !strncmp(v, "func", strlen("func") + 1);
}

static bool stdifunion(void *p, const char *k, const char *v) {
	return !strncmp(v, "union", strlen("union") + 1);
}

static bool sdbdeletelink(void *p, const char *k, const char *v) {
	RzCore *core = (RzCore *)p;
	if (!strncmp(k, "link.", strlen("link."))) {
		rz_type_del(core->analysis->sdb_types, k);
	}
	return true;
}

static bool stdiflink(void *p, const char *k, const char *v) {
	return !strncmp(k, "link.", strlen("link."));
}

static bool print_link_cb(void *p, const char *k, const char *v) {
	rz_cons_printf("0x%s = %s\n", k + strlen("link."), v);
	return true;
}

static bool print_link_json_cb(void *p, const char *k, const char *v) {
	rz_cons_printf("{\"0x%s\":\"%s\"}", k + strlen("link."), v);
	return true;
}

static bool print_link_r_cb(void *p, const char *k, const char *v) {
	rz_cons_printf("tl %s = 0x%s\n", v, k + strlen("link."));
	return true;
}

static bool print_link_readable_cb(void *p, const char *k, const char *v) {
	RzCore *core = (RzCore *)p;
	char *fmt = rz_type_format(core->analysis->sdb_types, v);
	if (!fmt) {
		eprintf("Can't fint type %s", v);
		return 1;
	}
	rz_cons_printf("(%s)\n", v);
	rz_core_cmdf(core, "pf %s @ 0x%s\n", fmt, k + strlen("link."));
	return true;
}

static bool print_link_readable_json_cb(void *p, const char *k, const char *v) {
	RzCore *core = (RzCore *)p;
	char *fmt = rz_type_format(core->analysis->sdb_types, v);
	if (!fmt) {
		eprintf("Can't fint type %s", v);
		return true;
	}
	rz_cons_printf("{\"%s\":", v);
	rz_core_cmdf(core, "pfj %s @ 0x%s\n", fmt, k + strlen("link."));
	rz_cons_printf("}");
	return true;
}

static bool stdiftype(void *p, const char *k, const char *v) {
	return !strncmp(v, "type", strlen("type") + 1);
}

static bool print_typelist_r_cb(void *p, const char *k, const char *v) {
	rz_cons_printf("tk %s=%s\n", k, v);
	return true;
}

static bool print_type_c(RzCore *core, const char *ctype) {
	Sdb *TDB = core->analysis->sdb_types;
	const char *type = rz_str_trim_head_ro(ctype);
	const char *name = type ? strchr(type, '.') : NULL;
	if (name && type) {
		name++; // skip the '.'
		if (rz_str_startswith(type, "struct")) {
			print_struct_union_in_c_format(TDB, stdifstruct, name, true);
		} else if (rz_str_startswith(type, "union")) {
			print_struct_union_in_c_format(TDB, stdifunion, name, true);
		} else if (rz_str_startswith(type, "enum")) {
			print_enum_in_c_format(TDB, name, true);
		} else if (rz_str_startswith(type, "typedef")) {
			rz_core_list_typename_alias_c(core, name);
		} else if (rz_str_startswith(type, "func")) {
			printFunctionTypeC(core, name);
		}
		return true;
	}
	return false;
}

static bool print_typelist_json_cb(void *p, const char *k, const char *v) {
	RzCore *core = (RzCore *)p;
	PJ *pj = pj_new();
	pj_o(pj);
	Sdb *sdb = core->analysis->sdb_types;
	char *sizecmd = rz_str_newf("type.%s.size", k);
	char *size_s = sdb_querys(sdb, NULL, -1, sizecmd);
	char *formatcmd = rz_str_newf("type.%s", k);
	char *format_s = sdb_querys(sdb, NULL, -1, formatcmd);
	rz_str_trim(format_s);
	pj_ks(pj, "type", k);
	pj_ki(pj, "size", size_s ? atoi(size_s) : -1);
	pj_ks(pj, "format", format_s);
	pj_end(pj);
	rz_cons_printf("%s", pj_string(pj));
	pj_free(pj);
	free(size_s);
	free(format_s);
	free(sizecmd);
	free(formatcmd);
	return true;
}

static void print_keys(Sdb *TDB, RzCore *core, SdbForeachCallback filter, SdbForeachCallback printfn_cb, bool json) {
	SdbList *l = sdb_foreach_list_filter(TDB, filter, true);
	SdbListIter *it;
	SdbKv *kv;
	const char *comma = "";

	if (json) {
		rz_cons_printf("[");
	}
	ls_foreach (l, it, kv) {
		const char *k = sdbkv_key(kv);
		if (!k || !*k) {
			continue;
		}
		if (json) {
			rz_cons_printf("%s", comma);
			comma = ",";
		}
		printfn_cb(core, sdbkv_key(kv), sdbkv_value(kv));
	}
	if (json) {
		rz_cons_printf("]\n");
	}
	ls_free(l);
}

static void typesList(RzCore *core, int mode) {
	switch (mode) {
	case 1:
	case '*':
		print_keys(core->analysis->sdb_types, core, NULL, print_typelist_r_cb, false);
		break;
	case 'j':
		print_keys(core->analysis->sdb_types, core, stdiftype, print_typelist_json_cb, true);
		break;
	default:
		print_keys(core->analysis->sdb_types, core, stdiftype, printkey_cb, false);
		break;
	}
}

static void set_offset_hint(RzCore *core, RzAnalysisOp *op, const char *type, ut64 laddr, ut64 at, int offimm) {
	char *res = rz_type_get_struct_memb(core->analysis->sdb_types, type, offimm);
	const char *cmt = ((offimm == 0) && res) ? res : type;
	if (offimm > 0) {
		// set hint only if link is present
		char *query = sdb_fmt("link.%08" PFMT64x, laddr);
		if (res && sdb_const_get(core->analysis->sdb_types, query, 0)) {
			rz_analysis_hint_set_offset(core->analysis, at, res);
		}
	} else if (cmt && rz_analysis_op_ismemref(op->type)) {
		rz_meta_set_string(core->analysis, RZ_META_TYPE_VARTYPE, at, cmt);
	}
}

static bool typedef_info(RzCore *core, const char *name) {
	const char *istypedef;
	Sdb *TDB = core->analysis->sdb_types;
	istypedef = sdb_const_get(TDB, name, 0);
	if (istypedef && !strncmp(istypedef, "typedef", 7)) {
		const char *q = sdb_fmt("typedef.%s", name);
		const char *res = sdb_const_get(TDB, q, 0);
		if (res) {
			rz_cons_println(res);
		} else {
			return false;
		}
	} else {
		eprintf("This is not an typedef\n");
		return false;
	}
	return true;
}

RZ_API void rz_core_list_loaded_typedefs(RzCore *core, RzOutputMode mode) {
	PJ *pj = NULL;
	Sdb *TDB = core->analysis->sdb_types;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj = pj_new();
		if (!pj) {
			return;
		}
		pj_o(pj);
	}
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(TDB, true);
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "typedef")) {
			if (!name || strcmp(sdbkv_value(kv), name)) {
				free(name);
				name = strdup(sdbkv_key(kv));
				if (mode == RZ_OUTPUT_MODE_STANDARD) {
					rz_cons_println(name);
				} else {
					const char *q = sdb_fmt("typedef.%s", name);
					const char *res = sdb_const_get(TDB, q, 0);
					pj_ks(pj, name, res);
				}
			}
		}
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
	free(name);
	ls_free(l);
}

RZ_API void rz_core_list_typename_alias_c(RzCore *core, const char *typedef_name) {
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	Sdb *TDB = core->analysis->sdb_types;
	SdbList *l = sdb_foreach_list(TDB, true);
	bool match = false;
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "typedef")) {
			if (!name || strcmp(sdbkv_value(kv), name)) {
				free(name);
				name = strdup(sdbkv_key(kv));
				if (name && (typedef_name && *typedef_name)) {
					if (!strcmp(typedef_name, name)) {
						match = true;
					} else {
						continue;
					}
				}
				const char *q = sdb_fmt("typedef.%s", name);
				const char *res = sdb_const_get(TDB, q, 0);
				if (res) {
					rz_cons_printf("%s %s %s;\n", sdbkv_value(kv), res, name);
				}
				if (match) {
					break;
				}
			}
		}
	}
	free(name);
	ls_free(l);
}

RZ_API int rz_core_get_stacksz(RzCore *core, ut64 from, ut64 to) {
	int stack = 0, maxstack = 0;
	ut64 at = from;

	if (from >= to) {
		return 0;
	}
	const int mininstrsz = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = RZ_MAX(1, mininstrsz);
	while (at < to) {
		RzAnalysisOp *op = rz_core_analysis_op(core, at, RZ_ANALYSIS_OP_MASK_BASIC);
		if (!op || op->size <= 0) {
			at += minopcode;
			continue;
		}
		if ((op->stackop == RZ_ANALYSIS_STACK_INC) && RZ_ABS(op->stackptr) < 8096) {
			stack += op->stackptr;
			if (stack > maxstack) {
				maxstack = stack;
			}
		}
		at += op->size;
		rz_analysis_op_free(op);
	}
	return maxstack;
}

static void set_retval(RzCore *core, ut64 at) {
	RzAnalysis *analysis = core->analysis;
	RzAnalysisHint *hint = rz_analysis_hint_get(analysis, at);
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(analysis, at, 0);

	if (!hint || !fcn || !fcn->name) {
		goto beach;
	}
	if (hint->ret == UT64_MAX) {
		goto beach;
	}
	const char *cc = rz_analysis_cc_func(core->analysis, fcn->name);
	const char *regname = rz_analysis_cc_ret(analysis, cc);
	if (regname) {
		RzRegItem *reg = rz_reg_get(analysis->reg, regname, -1);
		if (reg) {
			rz_reg_set_value(analysis->reg, reg, hint->ret);
		}
	}
beach:
	rz_analysis_hint_free(hint);
	return;
}

RZ_API void rz_core_link_stroff(RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	RzListIter *it;
	RzAnalysisOp aop = { 0 };
	bool ioCache = rz_config_get_i(core->config, "io.cache");
	bool stack_set = false;
	bool resolved = false;
	const char *varpfx;
	int dbg_follow = rz_config_get_i(core->config, "dbg.follow");
	Sdb *TDB = core->analysis->sdb_types;
	RzAnalysisEsil *esil;
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");
	const char *pc_name = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	const char *sp_name = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
	RzRegItem *pc = rz_reg_get(core->analysis->reg, pc_name, -1);

	if (!fcn) {
		return;
	}
	if (!(esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
		return;
	}
	rz_analysis_esil_setup(esil, core->analysis, 0, 0, 0);
	int i, ret, bsize = RZ_MAX(64, core->blocksize);
	const int mininstrsz = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	const int maxinstrsz = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
	const int minopcode = RZ_MAX(1, mininstrsz);
	ut8 *buf = malloc(bsize);
	if (!buf) {
		free(buf);
		rz_analysis_esil_free(esil);
		return;
	}
	rz_reg_arena_push(core->analysis->reg);
	rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_ALL, true);
	ut64 spval = rz_reg_getv(esil->analysis->reg, sp_name);
	if (spval) {
		// reset stack pointer to initial value
		RzRegItem *sp = rz_reg_get(esil->analysis->reg, sp_name, -1);
		ut64 curpc = rz_reg_getv(esil->analysis->reg, pc_name);
		int stacksz = rz_core_get_stacksz(core, fcn->addr, curpc);
		if (stacksz > 0) {
			rz_reg_arena_zero(esil->analysis->reg); // clear prev reg values
			rz_reg_set_value(esil->analysis->reg, sp, spval + stacksz);
		}
	} else {
		// initialize stack
		rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
		stack_set = true;
	}
	rz_config_set_i(core->config, "io.cache", 1);
	rz_config_set_i(core->config, "dbg.follow", 0);
	ut64 oldoff = core->offset;
	rz_cons_break_push(NULL, NULL);
	// TODO: The algorithm can be more accurate if blocks are followed by their jmp/fail, not just by address
	rz_list_sort(fcn->bbs, bb_cmpaddr);
	rz_list_foreach (fcn->bbs, it, bb) {
		ut64 at = bb->addr;
		ut64 to = bb->addr + bb->size;
		rz_reg_set_value(esil->analysis->reg, pc, at);
		for (i = 0; at < to; i++) {
			if (rz_cons_is_breaked()) {
				goto beach;
			}
			if (at < bb->addr) {
				break;
			}
			if (i >= (bsize - maxinstrsz)) {
				i = 0;
			}
			if (!i) {
				rz_io_read_at(core->io, at, buf, bsize);
			}
			ret = rz_analysis_op(core->analysis, &aop, at, buf + i, bsize - i, RZ_ANALYSIS_OP_MASK_VAL);
			if (ret <= 0) {
				i += minopcode;
				at += minopcode;
				rz_analysis_op_fini(&aop);
				continue;
			}
			i += ret - 1;
			at += ret;
			int index = 0;
			if (aop.ireg) {
				index = rz_reg_getv(esil->analysis->reg, aop.ireg) * aop.scale;
			}
			int j, src_imm = -1, dst_imm = -1;
			ut64 src_addr = UT64_MAX;
			ut64 dst_addr = UT64_MAX;
			for (j = 0; j < 3; j++) {
				if (aop.src[j] && aop.src[j]->reg && aop.src[j]->reg->name) {
					src_addr = rz_reg_getv(esil->analysis->reg, aop.src[j]->reg->name) + index;
					src_imm = aop.src[j]->delta;
				}
			}
			if (aop.dst && aop.dst->reg && aop.dst->reg->name) {
				dst_addr = rz_reg_getv(esil->analysis->reg, aop.dst->reg->name) + index;
				dst_imm = aop.dst->delta;
			}
			RzAnalysisVar *var = rz_analysis_get_used_function_var(core->analysis, aop.addr);
			if (false) { // src_addr != UT64_MAX || dst_addr != UT64_MAX) {
				//  if (src_addr == UT64_MAX && dst_addr == UT64_MAX) {
				rz_analysis_op_fini(&aop);
				continue;
			}
			char *slink = rz_type_link_at(TDB, src_addr);
			char *vlink = rz_type_link_at(TDB, src_addr + src_imm);
			char *dlink = rz_type_link_at(TDB, dst_addr);
			//TODO: Handle register based arg for struct offset propgation
			if (vlink && var && var->kind != 'r') {
				if (rz_type_kind(TDB, vlink) == RZ_TYPE_UNION) {
					varpfx = "union";
				} else {
					varpfx = "struct";
				}
				// if a var addr matches with struct , change it's type and name
				// var int local_e0h --> var struct foo
				if (strcmp(var->name, vlink) && !resolved) {
					resolved = true;
					rz_analysis_var_set_type(var, varpfx);
					rz_analysis_var_rename(var, vlink, false);
				}
			} else if (slink) {
				set_offset_hint(core, &aop, slink, src_addr, at - ret, src_imm);
			} else if (dlink) {
				set_offset_hint(core, &aop, dlink, dst_addr, at - ret, dst_imm);
			}
			if (rz_analysis_op_nonlinear(aop.type)) {
				rz_reg_set_value(esil->analysis->reg, pc, at);
				set_retval(core, at - ret);
			} else {
				rz_core_esil_step(core, UT64_MAX, NULL, NULL, false);
			}
			free(dlink);
			free(vlink);
			free(slink);
			rz_analysis_op_fini(&aop);
		}
	}
beach:
	rz_io_cache_reset(core->io, core->io->cached); // drop cache writes
	rz_config_set_i(core->config, "io.cache", ioCache);
	rz_config_set_i(core->config, "dbg.follow", dbg_follow);
	if (stack_set) {
		rz_core_analysis_esil_init_mem_del(core, NULL, UT64_MAX, UT32_MAX);
	}
	rz_core_seek(core, oldoff, true);
	rz_analysis_esil_free(esil);
	rz_reg_arena_pop(core->analysis->reg);
	rz_core_regs2flags(core);
	rz_cons_break_pop();
	free(buf);
}

static void print_all_union_format(RzCore *core, Sdb *TDB) {
	SdbList *l = sdb_foreach_list_filter(TDB, stdifunion, true);
	SdbListIter *it;
	SdbKv *kv;
	ls_foreach (l, it, kv) {
		type_show_format(core, sdbkv_key(kv), RZ_OUTPUT_MODE_RIZIN);
	}
	ls_free(l);
}

static void type_list_c_all(RzCore *core) {
	Sdb *TDB = core->analysis->sdb_types;
	// TODO: Change the logic maybe?
	//eprintf("Specify the type");
	//return RZ_CMD_STATUS_ERROR;
	rz_core_cmd0(core, "tfc");
	// List all unions in the C format with newlines
	print_struct_union_in_c_format(TDB, stdifunion, NULL, true);
	// List all structures in the C format with newlines
	rz_core_cmd0(core, "tsc");
	// List all typedefs in the C format with newlines
	rz_core_list_typename_alias_c(core, NULL);
	// List all enums in the C format with newlines
	rz_core_cmd0(core, "tec");
}

static void type_list_c_all_nl(RzCore *core) {
	Sdb *TDB = core->analysis->sdb_types;
	print_struct_union_in_c_format(TDB, stdifunion, NULL, false);
	rz_core_cmd0(core, "tsd;ttc;ted");
}

static void type_define(RzCore *core, const char *type) {
	// Add trailing semicolon to force the valid C syntax
	// It allows us to skip the trailing semicolon in the input
	// to reduce the unnecessary typing
	char *tmp = rz_str_newf("%s;", type);
	if (!tmp) {
		return;
	}
	char *error_msg = NULL;
	char *out = rz_parse_c_string(core->analysis, tmp, &error_msg);
	free(tmp);
	if (out) {
		rz_analysis_save_parsed_type(core->analysis, out);
		free(out);
	}
	if (error_msg) {
		eprintf("%s", error_msg);
		free(error_msg);
	}
}

RZ_IPI int rz_cmd_type(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	Sdb *TDB = core->analysis->sdb_types;
	char *res;
	TDB_ = TDB; // HACK

	switch (input[0]) {
	case 'n': // "tn"
		cmd_type_noreturn(core, input + 1);
		break;
	// t [typename] - show given type in C syntax
	case 'u': { // "tu"
		switch (input[1]) {
		case '?':
			rz_core_cmd_help(core, help_msg_tu);
			break;
		case '*':
			if (input[2] == ' ') {
				type_show_format(core, rz_str_trim_head_ro(input + 2), RZ_OUTPUT_MODE_RIZIN);
			} else {
				print_all_union_format(core, TDB);
			}
			break;
		case 'j': // "tuj"
			if (input[2]) {
				type_show_format(core, rz_str_trim_head_ro(input + 2), RZ_OUTPUT_MODE_JSON);
				rz_cons_newline();
			} else {
				print_struct_union_list_json(TDB, stdifunion);
			}
			break;
		case 'c': // "tuc"
			print_struct_union_in_c_format(TDB, stdifunion, rz_str_trim_head_ro(input + 2), true);
			break;
		case 'd': // "tud"
			print_struct_union_in_c_format(TDB, stdifunion, rz_str_trim_head_ro(input + 2), false);
			break;
		case ' ': // "tu "
			type_show_format(core, rz_str_trim_head_ro(input + 1), RZ_OUTPUT_MODE_STANDARD);
			break;
		case 0:
			print_keys(TDB, core, stdifunion, printkey_cb, false);
			break;
		}
	} break;
	case 'k': // "tk"
		res = (input[1] == ' ')
			? sdb_querys(TDB, NULL, -1, input + 2)
			: sdb_querys(TDB, NULL, -1, "*");
		if (res) {
			rz_cons_print(res);
			free(res);
		}
		break;
	case 'c': // "tc"
		switch (input[1]) {
		case 'c': // "tcc" -- calling conventions
			__core_cmd_tcc(core, input + 2);
			break;
		case '?': //"tc?"
			rz_core_cmd_help(core, help_msg_tc);
			break;
		case ' ':
			print_type_c(core, input + 1);
			break;
		case '*':
			rz_core_cmd0(core, "ts*");
			break;
		case 0:
			type_list_c_all(core);
			break;
		case 'd':
			type_list_c_all_nl(core);
			break;
		default:
			rz_core_cmd_help(core, help_msg_tc);
			break;
		}
		break;
	case 's': { // "ts"
		switch (input[1]) {
		case '?':
			rz_core_cmd_help(core, help_msg_ts);
			break;
		case '*':
			if (input[2] == ' ') {
				type_show_format(core, rz_str_trim_head_ro(input + 2), RZ_OUTPUT_MODE_RIZIN);
			} else {
				SdbList *l = sdb_foreach_list_filter(TDB, stdifstruct, true);
				SdbListIter *it;
				SdbKv *kv;

				ls_foreach (l, it, kv) {
					type_show_format(core, sdbkv_key(kv), RZ_OUTPUT_MODE_RIZIN);
				}
				ls_free(l);
			}
			break;
		case ' ':
			type_show_format(core, rz_str_trim_head_ro(input + 1), RZ_OUTPUT_MODE_STANDARD);
			break;
		case 's':
			if (input[2] == ' ') {
				rz_cons_printf("%" PFMT64u "\n", (rz_type_get_bitsize(TDB, input + 3) / 8));
			} else {
				rz_core_cmd_help(core, help_msg_ts);
			}
			break;
		case 0:
			print_keys(TDB, core, stdifstruct, printkey_cb, false);
			break;
		case 'c': // "tsc"
			print_struct_union_in_c_format(TDB, stdifstruct, rz_str_trim_head_ro(input + 2), true);
			break;
		case 'd': // "tsd"
			print_struct_union_in_c_format(TDB, stdifstruct, rz_str_trim_head_ro(input + 2), false);
			break;
		case 'j': // "tsj"
			// TODO: current output is a bit poor, will be good to improve
			if (input[2]) {
				type_show_format(core, rz_str_trim_head_ro(input + 2), RZ_OUTPUT_MODE_JSON);
				rz_cons_newline();
			} else {
				print_struct_union_list_json(TDB, stdifstruct);
			}
			break;
		}
	} break;
	case 'e': { // "te"
		char *res = NULL, *temp = strchr(input, ' ');
		Sdb *TDB = core->analysis->sdb_types;
		char *name = temp ? strdup(temp + 1) : NULL;
		char *member_name = name ? strchr(name, ' ') : NULL;

		if (member_name) {
			*member_name++ = 0;
		}
		if (name && (rz_type_kind(TDB, name) != RZ_TYPE_ENUM)) {
			eprintf("%s is not an enum\n", name);
			free(name);
			break;
		}
		switch (input[1]) {
		case '?':
			rz_core_cmd_help(core, help_msg_te);
			break;
		case 'j': // "tej"
			if (input[2] == 0) { // "tej"
				char *name = NULL;
				SdbKv *kv;
				SdbListIter *iter;
				SdbList *l = sdb_foreach_list(TDB, true);
				PJ *pj = pj_new();
				pj_o(pj);
				ls_foreach (l, iter, kv) {
					if (!strcmp(sdbkv_value(kv), "enum")) {
						if (!name || strcmp(sdbkv_value(kv), name)) {
							free(name);
							name = strdup(sdbkv_key(kv));
							pj_k(pj, name);
							{
								RzList *list = rz_type_get_enum(TDB, name);
								if (list && !rz_list_empty(list)) {
									pj_o(pj);
									RzListIter *iter;
									RTypeEnum *member;
									rz_list_foreach (list, iter, member) {
										pj_kn(pj, member->name, rz_num_math(NULL, member->val));
									}
									pj_end(pj);
								}
								rz_list_free(list);
							}
						}
					}
				}
				pj_end(pj);
				rz_cons_printf("%s\n", pj_string(pj));
				pj_free(pj);
				free(name);
				ls_free(l);
			} else { // "tej ENUM"
				RzListIter *iter;
				PJ *pj = pj_new();
				RTypeEnum *member;
				pj_o(pj);
				if (member_name) {
					res = rz_type_enum_member(TDB, name, NULL, rz_num_math(core->num, member_name));
					// NEVER REACHED
				} else {
					RzList *list = rz_type_get_enum(TDB, name);
					if (list && !rz_list_empty(list)) {
						pj_ks(pj, "name", name);
						pj_k(pj, "values");
						pj_o(pj);
						rz_list_foreach (list, iter, member) {
							pj_kn(pj, member->name, rz_num_math(NULL, member->val));
						}
						pj_end(pj);
						pj_end(pj);
					}
					rz_cons_printf("%s\n", pj_string(pj));
					pj_free(pj);
					rz_list_free(list);
				}
			}
			break;
		case 'b': // "teb"
			res = rz_type_enum_member(TDB, name, member_name, 0);
			break;
		case 'c': // "tec"
			print_enum_in_c_format(TDB, rz_str_trim_head_ro(input + 2), true);
			break;
		case 'd':
			print_enum_in_c_format(TDB, rz_str_trim_head_ro(input + 2), false);
			break;
		case ' ':
			if (member_name) {
				res = rz_type_enum_member(TDB, name, NULL, rz_num_math(core->num, member_name));
			} else {
				RzList *list = rz_type_get_enum(TDB, name);
				RzListIter *iter;
				RTypeEnum *member;
				rz_list_foreach (list, iter, member) {
					rz_cons_printf("%s = %s\n", member->name, member->val);
				}
				rz_list_free(list);
			}
			break;
		case '\0': {
			char *name = NULL;
			SdbKv *kv;
			SdbListIter *iter;
			SdbList *l = sdb_foreach_list(TDB, true);
			ls_foreach (l, iter, kv) {
				if (!strcmp(sdbkv_value(kv), "enum")) {
					if (!name || strcmp(sdbkv_value(kv), name)) {
						free(name);
						name = strdup(sdbkv_key(kv));
						rz_cons_println(name);
					}
				}
			}
			free(name);
			ls_free(l);
		} break;
		}
		free(name);
		if (res) {
			rz_cons_println(res);
		} else if (member_name) {
			eprintf("Invalid enum member\n");
		}
	} break;
	case ' ':
		type_show_format(core, input + 1, RZ_OUTPUT_MODE_STANDARD);
		break;
	// t* - list all types in 'pf' syntax
	case 'j': // "tj"
	case '*': // "t*"
	case 0: // "t"
		typesList(core, input[0]);
		break;
	case 'o': // "to"
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_to);
			break;
		}
		if (input[1] == ' ') {
			const char *dir = rz_config_get(core->config, "dir.types");
			const char *filename = input + 2;
			char *homefile = NULL;
			if (*filename == '~') {
				if (filename[1] && filename[2]) {
					homefile = rz_str_home(filename + 2);
					filename = homefile;
				}
			}
			if (!strcmp(filename, "-")) {
				char *tmp = rz_core_editor(core, "*.h", "");
				if (tmp) {
					char *error_msg = NULL;
					char *out = rz_parse_c_string(core->analysis, tmp, &error_msg);
					if (out) {
						//		rz_cons_strcat (out);
						rz_analysis_save_parsed_type(core->analysis, out);
						free(out);
					}
					if (error_msg) {
						fprintf(stderr, "%s", error_msg);
						free(error_msg);
					}
					free(tmp);
				}
			} else {
				char *error_msg = NULL;
				char *out = rz_parse_c_file(core->analysis, filename, dir, &error_msg);
				if (out) {
					//rz_cons_strcat (out);
					rz_analysis_save_parsed_type(core->analysis, out);
					free(out);
				}
				if (error_msg) {
					fprintf(stderr, "%s", error_msg);
					free(error_msg);
				}
			}
			free(homefile);
		} else if (input[1] == 'u') {
			// "tou" "touch"
			char *arg = strchr(input, ' ');
			if (arg) {
				rz_file_touch(arg + 1);
			} else {
				eprintf("Usage: touch [filename]");
			}
		} else if (input[1] == 's') {
			const char *dbpath = input + 3;
			if (rz_file_exists(dbpath)) {
				Sdb *db_tmp = sdb_new(0, dbpath, 0);
				sdb_merge(TDB, db_tmp);
				sdb_close(db_tmp);
				sdb_free(db_tmp);
			}
		} else if (input[1] == 'e') { // "toe"
			char *str = rz_core_cmd_strf(core, "tc %s", input + 2);
			char *tmp = rz_core_editor(core, "*.h", str);
			if (tmp) {
				char *error_msg = NULL;
				char *out = rz_parse_c_string(core->analysis, tmp, &error_msg);
				if (out) {
					// remove previous types and save new edited types
					sdb_reset(TDB);
					rz_parse_c_reset(core->parser);
					rz_analysis_save_parsed_type(core->analysis, out);
					free(out);
				}
				if (error_msg) {
					eprintf("%s\n", error_msg);
					free(error_msg);
				}
				free(tmp);
			}
			free(str);
		}
		break;
	// td - parse string with cparse engine and load types from it
	case 'd': // "td"
		if (input[1] == '?') {
			// TODO #7967 help refactor: move to detail
			rz_core_cmd_help(core, help_msg_td);
			rz_cons_printf("Note: The td command should be put between double quotes\n"
				       "Example: td \"struct foo {int bar;int cow;};\""
				       "\nt");

		} else if (input[1] == ' ') {
			type_define(core, input + 2);
		} else {
			eprintf("Invalid use of td. See td? for help\n");
		}
		break;
	case 'x': {
		char *type, *type2;
		RzListIter *iter, *iter2;
		RzAnalysisFunction *fcn;
		switch (input[1]) {
		case '.': // "tx." type xrefs
		case 'f': // "txf" type xrefs
		{
			ut64 addr = core->offset;
			if (input[2] == ' ') {
				addr = rz_num_math(core->num, input + 2);
			}
			fcn = rz_analysis_get_function_at(core->analysis, addr);
			if (fcn) {
				RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
				rz_list_foreach (uniq, iter, type) {
					rz_cons_println(type);
				}
				rz_list_free(uniq);
			} else {
				eprintf("cannot find function at 0x%08" PFMT64x "\n", addr);
			}
		} break;
		case 0: // "tx"
			rz_list_foreach (core->analysis->fcns, iter, fcn) {
				RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
				if (rz_list_length(uniq)) {
					rz_cons_printf("%s: ", fcn->name);
				}
				rz_list_foreach (uniq, iter2, type) {
					rz_cons_printf("%s%s", type, iter2->n ? "," : "\n");
				}
			}
			break;
		case 'g': // "txg"
		{
			rz_list_foreach (core->analysis->fcns, iter, fcn) {
				RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
				if (rz_list_length(uniq)) {
					rz_cons_printf("agn %s\n", fcn->name);
				}
				rz_list_foreach (uniq, iter2, type) {
					char *myType = strdup(type);
					rz_str_replace_ch(myType, ' ', '_', true);
					rz_cons_printf("agn %s\n", myType);
					rz_cons_printf("age %s %s\n", myType, fcn->name);
					free(myType);
				}
			}
		} break;
		case 'l': // "txl"
		{
			RzList *uniqList = rz_list_newf(free);
			rz_list_foreach (core->analysis->fcns, iter, fcn) {
				RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
				rz_list_foreach (uniq, iter2, type) {
					if (!rz_list_find(uniqList, type, (RzListComparator)strcmp)) {
						rz_list_push(uniqList, strdup(type));
					}
				}
			}
			rz_list_sort(uniqList, (RzListComparator)strcmp);
			rz_list_foreach (uniqList, iter, type) {
				rz_cons_printf("%s\n", type);
			}
			rz_list_free(uniqList);
		} break;
		case 't':
		case ' ': // "tx " -- show which function use given type
			type = (char *)rz_str_trim_head_ro(input + 2);
			rz_list_foreach (core->analysis->fcns, iter, fcn) {
				RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
				rz_list_foreach (uniq, iter2, type2) {
					if (!strcmp(type2, type)) {
						rz_cons_printf("%s\n", fcn->name);
						break;
					}
				}
			}
			break;
		default:
			eprintf("Usage: tx[flg] [...]\n");
			eprintf(" txf | tx.      list all types used in this function\n");
			eprintf(" txf 0xaddr     list all types used in function at 0xaddr\n");
			eprintf(" txl            list all types used by any function\n");
			eprintf(" txg            render the type xrefs graph (usage .txg;aggv)\n");
			eprintf(" tx int32_t     list functions names using this type\n");
			eprintf(" txt int32_t    same as 'tx type'\n");
			eprintf(" tx             list functions and the types they use\n");
			break;
		}
	} break;
	// ta: moved to analysis hints (aht)- just for tail, at the moment
	// tl - link a type to an address
	case 'l': // "tl"
		switch (input[1]) {
		case '?':
			rz_core_cmd_help(core, help_msg_tl);
			break;
		case ' ': {
			char *type = strdup(input + 2);
			char *ptr = strchr(type, '=');
			ut64 addr = core->offset;

			if (ptr) {
				*ptr++ = 0;
				rz_str_trim(ptr);
				if (ptr && *ptr) {
					addr = rz_num_math(core->num, ptr);
				} else {
					eprintf("tl: Address is unvalid\n");
					free(type);
					break;
				}
			}
			rz_str_trim(type);
			char *tmp = sdb_get(TDB, type, 0);
			if (tmp && *tmp) {
				rz_type_set_link(TDB, type, addr);
				RzList *fcns = rz_analysis_get_functions_in(core->analysis, core->offset);
				if (rz_list_length(fcns) > 1) {
					eprintf("Multiple functions found in here.\n");
				} else if (rz_list_length(fcns) == 1) {
					RzAnalysisFunction *fcn = rz_list_first(fcns);
					rz_core_link_stroff(core, fcn);
				} else {
					eprintf("Cannot find any function here\n");
				}
				rz_list_free(fcns);
				free(tmp);
			} else {
				eprintf("unknown type %s\n", type);
			}
			free(type);
			break;
		}
		case 's': {
			char *ptr = rz_str_trim_dup(input + 2);
			ut64 addr = rz_num_math(NULL, ptr);
			const char *query = sdb_fmt("link.%08" PFMT64x, addr);
			const char *link = sdb_const_get(TDB, query, 0);
			if (link) {
				print_link_readable_cb(core, query, link);
			}
			free(ptr);
			break;
		}
		case '-':
			switch (input[2]) {
			case '*':
				sdb_foreach(TDB, sdbdeletelink, core);
				break;
			case ' ': {
				const char *ptr = input + 3;
				ut64 addr = rz_num_math(core->num, ptr);
				rz_type_unlink(TDB, addr);
				break;
			}
			}
			break;
		case '*':
			print_keys(TDB, core, stdiflink, print_link_r_cb, false);
			break;
		case 'l':
			switch (input[2]) {
			case 'j':
				print_keys(TDB, core, stdiflink, print_link_readable_json_cb, true);
				break;
			default:
				print_keys(TDB, core, stdiflink, print_link_readable_cb, false);
				break;
			}
			break;
		case 'j':
			print_keys(TDB, core, stdiflink, print_link_json_cb, true);
			break;
		case '\0':
			print_keys(TDB, core, stdiflink, print_link_cb, false);
			break;
		}
		break;
	case 'p': // "tp"
		if (input[1] == '?') { // "tp?"
			rz_core_cmd_help(core, help_msg_tp);
		} else if (input[1] == 'v') { // "tpv"
			const char *type_name = rz_str_trim_head_ro(input + 2);
			char *fmt = rz_type_format(TDB, type_name);
			if (fmt && *fmt) {
				ut64 val = core->offset;
				rz_core_cmdf(core, "pf %s @v:0x%08" PFMT64x "\n", fmt, val);
			} else {
				eprintf("Usage: tpv [type] @ [value]\n");
			}
		} else if (input[1] == ' ' || input[1] == 'x' || !input[1]) {
			char *tmp = strdup(input);
			char *type_begin = strchr(tmp, ' ');
			if (type_begin) {
				rz_str_trim(type_begin);
				const char *type_end = rz_str_rchr(type_begin, NULL, ' ');
				int type_len = (type_end)
					? (int)(type_end - type_begin)
					: strlen(type_begin);
				char *type = strdup(type_begin);
				if (!type) {
					free(tmp);
					break;
				}
				snprintf(type, type_len + 1, "%s", type_begin);
				const char *arg = (type_end) ? type_end + 1 : NULL;
				char *fmt = rz_type_format(TDB, type);
				if (!fmt) {
					eprintf("Cannot find '%s' type\n", type);
					free(tmp);
					free(type);
					break;
				}
				if (input[1] == 'x' && arg) { // "tpx"
					rz_core_cmdf(core, "pf %s @x:%s", fmt, arg);
					// eprintf ("pf %s @x:%s", fmt, arg);
				} else {
					ut64 addr = arg ? rz_num_math(core->num, arg) : core->offset;
					ut64 original_addr = addr;
					if (!addr && arg) {
						RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, -1);
						if (fcn) {
							RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, arg);
							if (var) {
								addr = rz_analysis_var_addr(var);
							}
						}
					}
					if (addr != UT64_MAX) {
						rz_core_cmdf(core, "pf %s @ 0x%08" PFMT64x, fmt, addr);
					} else if (original_addr == 0) {
						rz_core_cmdf(core, "pf %s @ 0x%08" PFMT64x, fmt, original_addr);
					}
				}
				free(fmt);
				free(type);
			} else {
				eprintf("Usage: tp?\n");
			}
			free(tmp);
		} else { // "tp"
			eprintf("Usage: tp?\n");
		}
		break;
	case '-': // "t-"
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_t_minus);
		} else if (input[1] == '*') {
			sdb_reset(TDB);
			rz_parse_c_reset(core->parser);
		} else {
			const char *name = rz_str_trim_head_ro(input + 1);
			if (*name) {
				rz_analysis_remove_parsed_type(core->analysis, name);
			} else {
				eprintf("Invalid use of t- . See t-? for help.\n");
			}
		}
		break;
	// tv - get/set type value linked to a given address
	case 'f': // "tf"
		switch (input[1]) {
		case 0: // "tf"
			print_keys(TDB, core, stdiffunc, printkey_cb, false);
			break;
		case 'c': // "tfc"
			if (input[2] == ' ') {
				printFunctionTypeC(core, input + 3);
			}
			break;
		case 'j': // "tfj"
			if (input[2] == ' ') {
				printFunctionType(core, input + 2);
				rz_cons_newline();
			} else {
				print_keys(TDB, core, stdiffunc, printfunc_json_cb, true);
			}
			break;
		case ' ': {
			char *res = sdb_querys(TDB, NULL, -1, sdb_fmt("~~func.%s", input + 2));
			if (res) {
				rz_cons_printf("%s", res);
				free(res);
			}
			break;
		}
		default:
			rz_core_cmd_help(core, help_msg_tf);
			break;
		}
		break;
	case 't': { // "tt"
		RzOutputMode mode;
		if (input[1] == 'j') { // "ttj"
			mode = RZ_OUTPUT_MODE_JSON;
			rz_core_list_loaded_typedefs(core, mode);
			break;
		}
		if (input[1] == 'c') { // "ttc"
			rz_core_list_typename_alias_c(core, input + 2);
			break;
		}
		if (input[1] == '?') { // "tt?"
			rz_core_cmd_help(core, help_msg_tt);
			break;
		}
		if (!input[1]) { // "tt"
			rz_core_list_loaded_typedefs(core, RZ_OUTPUT_MODE_STANDARD);
			break;
		}
		char *s = strdup(input + 2);
		typedef_info(core, s);
		free(s);
	} break;
	case '?':
		rz_core_cmd_help(core, help_msg_t);
		break;
	}
	return true;
}

RZ_IPI RzCmdStatus rz_type_cc_list_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *cc = argc > 1 ? argv[1] : NULL;
	if (cc) {
		types_cc_print(core, cc, mode);
	} else {
		types_cc_print_all(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_cc_del_handler(RzCore *core, int argc, const char **argv) {
	const char *cc = argc > 1 ? argv[1] : NULL;
	rz_analysis_cc_del(core->analysis, cc);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_cc_del_all_handler(RzCore *core, int argc, const char **argv) {
	sdb_reset(core->analysis->sdb_cc);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_c_handler(RzCore *core, int argc, const char **argv) {
	const char *ctype = argc > 1 ? argv[1] : NULL;
	if (!ctype) {
		type_list_c_all(core);
		return RZ_CMD_STATUS_OK;
	}
	if (!print_type_c(core, ctype)) {
		eprintf("Wrong type syntax");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_c_nl_handler(RzCore *core, int argc, const char **argv) {
	type_list_c_all_nl(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_define_handler(RzCore *core, int argc, const char **argv) {
	const char *type = argc > 1 ? argv[1] : NULL;
	type_define(core, type);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_kuery_handler(RzCore *core, int argc, const char **argv) {
	const char *query = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	char *output = NULL;
	if (query) {
		output = sdb_querys(TDB, NULL, -1, query);
	} else {
		output = sdb_querys(TDB, NULL, -1, "*");
	}
	if (!output) {
		eprintf("Cannot find anything matching your query");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(output);
	free(output);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_noreturn_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *name = argc > 1 ? argv[1] : NULL;
	if (name) {
		ut64 n = rz_num_math(core->num, name);
		if (n) {
			rz_analysis_noreturn_add(core->analysis, name, n);
		} else {
			rz_analysis_noreturn_add(core->analysis, name, UT64_MAX);
		}
	} else {
		rz_core_analysis_noreturn_print(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_noreturn_del_handler(RzCore *core, int argc, const char **argv) {
	for (int i = 1; i < argc; i++) {
		rz_analysis_noreturn_drop(core->analysis, argv[i]);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_noreturn_del_all_handler(RzCore *core, int argc, const char **argv) {
	RzList *noretl = rz_core_analysis_noreturn(core);
	RzListIter *iter;
	char *name;
	rz_list_foreach (noretl, iter, name) {
		rz_analysis_noreturn_drop(core->analysis, name);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_typedef_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	if (typename) {
		if (!typedef_info(core, typename)) {
			eprintf("Can't find typedef");
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		rz_core_list_loaded_typedefs(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_typedef_c_handler(RzCore *core, int argc, const char **argv) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	if (!typename) {
		rz_core_list_typename_alias_c(core, NULL);
		return RZ_CMD_STATUS_OK;
	}
	rz_core_list_typename_alias_c(core, typename);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_union_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	if (typename) {
		type_show_format(core, typename, mode);
	} else {
		if (mode == RZ_OUTPUT_MODE_RIZIN) {
			print_all_union_format(core, TDB);
		} else if (mode == RZ_OUTPUT_MODE_JSON) {
			print_struct_union_list_json(TDB, stdifunion);
		} else {
			print_keys(TDB, core, stdifunion, printkey_cb, false);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_union_c_handler(RzCore *core, int argc, const char **argv) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	print_struct_union_in_c_format(TDB, stdifunion, typename, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_union_c_nl_handler(RzCore *core, int argc, const char **argv) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	print_struct_union_in_c_format(TDB, stdifunion, typename, false);
	return RZ_CMD_STATUS_OK;
}
