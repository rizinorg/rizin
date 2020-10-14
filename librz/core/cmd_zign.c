/* radare - LGPL - Copyright 2009-2020 - pancake, nibble */

#include <rz_core.h>
#include <rz_anal.h>
#include <rz_sign.h>
#include <rz_list.h>
#include <rz_cons.h>
#include <rz_util.h>

static const char *help_msg_z[] = {
	"Usage:", "z[*j-aof/cs] [args] ", "# Manage zignatures",
	"z", "", "show zignatures",
	"z.", "", "find matching zignatures in current offset",
	"zb", "[?][n=5]", "search for best match",
	"z*", "", "show zignatures in radare format",
	"zq", "", "show zignatures in quiet mode",
	"zj", "", "show zignatures in json format",
	"zk", "", "show zignatures in sdb format",
	"z-", "zignature", "delete zignature",
	"z-", "*", "delete all zignatures",
	"za", "[?]", "add zignature",
	"zg", "", "generate zignatures (alias for zaF)",
	"zo", "[?]", "manage zignature files",
	"zf", "[?]", "manage FLIRT signatures",
	"z/", "[?]", "search zignatures",
	"zc", "[?]", "compare current zignspace zignatures with another one",
	"zs", "[?]", "manage zignspaces",
	"zi", "", "show zignatures matching information",
	NULL
};

static const char *help_msg_zb[] = {
	"Usage:", "zb[r?] [args]", "# search for closest matching signatures",
	"zb ", "[n]", "find n closest matching zignatures to function at current offset",
	"zbr ", "zigname [n]", "search for n most similar functions to zigname",
	NULL
};

static const char *help_msg_z_slash[] = {
	"Usage:", "z/[*] ", "# Search signatures (see 'e?search' for options)",
	"z/ ", "", "search zignatures on range and flag matches",
	"z/* ", "", "search zignatures on range and output radare commands",
	NULL
};

static const char *help_msg_za[] = {
	"Usage:", "za[fF?] [args] ", "# Add zignature",
	"za ", "zigname type params", "add zignature",
	"zaf ", "[fcnname] [zigname]", "create zignature for function",
	"zaF ", "", "generate zignatures for all functions",
	"za?? ", "", "show extended help",
	NULL
};

static const char *help_msg_zf[] = {
	"Usage:", "zf[dsz] filename ", "# Manage FLIRT signatures",
	"zfd ", "filename", "open FLIRT file and dump",
	"zfs ", "filename", "open FLIRT file and scan",
	"zfs ", "/path/**.sig", "recursively search for FLIRT files and scan them (see dir.depth)",
	"zfz ", "filename", "open FLIRT file and get sig commands (zfz flirt_file > zignatures.sig)",
	NULL
};

static const char *help_msg_zo[] = {
	"Usage:", "zo[zs] filename ", "# Manage zignature files (see dir.zigns)",
	"zo ", "filename", "load zinatures from sdb file",
	"zoz ", "filename", "load zinatures from gzipped sdb file",
	"zos ", "filename", "save zignatures to sdb file (merge if file exists)",
	NULL
};

static const char *help_msg_zs[] = {
	"Usage:", "zs[+-*] [namespace] ", "# Manage zignspaces",
	"zs", "", "display zignspaces",
	"zs ", "zignspace", "select zignspace",
	"zs ", "*", "select all zignspaces",
	"zs-", "zignspace", "delete zignspace",
	"zs-", "*", "delete all zignspaces",
	"zs+", "zignspace", "push previous zignspace and set",
	"zs-", "", "pop to the previous zignspace",
	"zsr ", "newname", "rename selected zignspace",
	NULL
};

static const char *help_msg_zc[] = {
	"Usage:", "zc[n!] other_space ", "# Compare zignspaces, match >= threshold (e zign.diff.*)",
	"zc", " other_space", "compare all current space with other_space",
	"zcn", " other_space", "compare current space with zigns with same name on other_space",
	"zcn!", " other_space", "same as above but show the ones not matching",
	NULL
};

static void cmd_zign_init(RzCore *core, RzCmdDesc *parent) {
	DEPRECATED_DEFINE_CMD_DESCRIPTOR (core, z);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR (core, zb);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR_SPECIAL (core, z/, z_slash);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR (core, za);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR (core, zf);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR (core, zo);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR (core, zs);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR (core, zc);
}

#if 0
static char *getFcnComments(RzCore *core, RzAnalFunction *fcn) {
	// XXX this is slow as hell on big binaries
	char *r = rz_core_cmd_strf (core, "CCf* @ 0x%08"PFMT64x, fcn->addr);
	if (r && *r) {
		return r;
	}
	//
	return NULL;
}
#endif

static void addFcnZign(RzCore *core, RzAnalFunction *fcn, const char *name) {
	char *ptr = NULL;
	char *zignspace = NULL;
	char *zigname = NULL;
	const RSpace *curspace = rz_spaces_current (&core->anal->zign_spaces);
	int len = 0;

	if (name) {
		zigname = rz_str_new (name);
	} else {
		// If the user has set funtion names containing a single ':' then we assume
		// ZIGNSPACE:FUNCTION, and for now we only support the 'zg' command
		if ((ptr = strchr (fcn->name, ':')) != NULL) {
			len = ptr - fcn->name;
			zignspace = rz_str_newlen (fcn->name, len);
			rz_spaces_push (&core->anal->zign_spaces, zignspace);
		} else if (curspace) {
			zigname = rz_str_newf ("%s:", curspace->name);
		}
		zigname = rz_str_appendf (zigname, "%s", fcn->name);
	}

	// create empty item
	RzSignItem *it = rz_sign_item_new ();
	if (!it) {
		free (zigname);
		return;
	}
	// add sig types info to item
	it->name = zigname; // will be free'd when item is free'd
	it->space = rz_spaces_current (&core->anal->zign_spaces);
	rz_sign_addto_item (core->anal, it, fcn, RZ_SIGN_GRAPH);
	rz_sign_addto_item (core->anal, it, fcn, RZ_SIGN_BYTES);
	rz_sign_addto_item (core->anal, it, fcn, RZ_SIGN_XREFS);
	rz_sign_addto_item (core->anal, it, fcn, RZ_SIGN_REFS);
	rz_sign_addto_item (core->anal, it, fcn, RZ_SIGN_VARS);
	rz_sign_addto_item (core->anal, it, fcn, RZ_SIGN_TYPES);
	rz_sign_addto_item (core->anal, it, fcn, RZ_SIGN_BBHASH);
	rz_sign_addto_item (core->anal, it, fcn, RZ_SIGN_OFFSET);
	rz_sign_addto_item (core->anal, it, fcn, RZ_SIGN_NAME);

	/* rz_sign_add_addr (core->anal, zigname, fcn->addr); */

	// commit the item to anal
	rz_sign_add_item (core->anal, it);

	/*
	XXX this is very slow and poorly tested
	char *comments = getFcnComments (core, fcn);
	if (comments) {
		rz_sign_add_comment (core->anal, zigname, comments);
	}
	*/

	rz_sign_item_free (it); // causes zigname to be free'd
	if (zignspace) {
		rz_spaces_pop (&core->anal->zign_spaces);
		free (zignspace);
	}
}

static bool addCommentZign(RzCore *core, const char *name, RzList *args) {
	if (rz_list_length (args) != 1) {
		eprintf ("Invalid number of arguments\n");
		return false;
	}
	const char *comment = (const char *)rz_list_get_top (args);
	return rz_sign_add_comment (core->anal, name, comment);
}

static bool addNameZign(RzCore *core, const char *name, RzList *args) {
	if (rz_list_length (args) != 1) {
		eprintf ("Invalid number of arguments\n");
		return false;
	}
	const char *realname = (const char *)rz_list_get_top (args);
	return rz_sign_add_name (core->anal, name, realname);
}

static bool addGraphZign(RzCore *core, const char *name, RzList *args) {
	RzSignGraph graph = { .cc = -1, .nbbs = -1, .edges = -1, .ebbs = -1, .bbsum = 0 };

	char *ptr;
	RzListIter *iter;
	rz_list_foreach (args, iter, ptr) {
		if (rz_str_startswith (ptr, "cc=")) {
			graph.cc = atoi (ptr + 3);
		} else if (rz_str_startswith (ptr, "nbbs=")) {
			graph.nbbs = atoi (ptr + 5);
		} else if (rz_str_startswith (ptr, "edges=")) {
			graph.edges = atoi (ptr + 6);
		} else if (rz_str_startswith (ptr, "ebbs=")) {
			graph.ebbs = atoi (ptr + 5);
		} else if (rz_str_startswith (ptr, "bbsum=")) {
			graph.bbsum = atoi (ptr + 6);
		} else {
			return false;
		}
	}
	return rz_sign_add_graph (core->anal, name, graph);
}

static bool addHashZign(RzCore *core, const char *name, int type, RzList *args) {
	if (rz_list_length (args) != 1) {
		eprintf ("error: invalid syntax\n");
		return false;
	}
	const char *hash = (const char *)rz_list_get_top (args);
	int len = strlen (hash);
	if (!len) {
		return false;
	}
	return rz_sign_add_hash (core->anal, name, type, hash, len);
}

static bool addBytesZign(RzCore *core, const char *name, int type, RzList *args) {
	ut8 *mask = NULL, *bytes = NULL, *sep = NULL;
	int size = 0;
	bool retval = true;

	if (rz_list_length (args) != 1) {
		eprintf ("error: invalid syntax\n");
		return false;
	}

	const char *hexbytes = (const char *)rz_list_get_top (args);
	if ((sep = (ut8 *)strchr (hexbytes, ':'))) {
		size_t blen = sep - (ut8 *)hexbytes;
		sep++;
		if (!blen || (blen & 1) || strlen ((char *)sep) != blen) {
			eprintf ("error: cannot parse hexpairs\n");
			return false;
		}
		bytes = calloc (1, blen + 1);
		mask = calloc (1, blen + 1);
		memcpy (bytes, hexbytes, blen);
		memcpy (mask, sep, blen);
		size = rz_hex_str2bin ((char*) bytes, bytes);
		if (size != blen / 2 || rz_hex_str2bin ((char*)mask, mask) != size) {
			eprintf ("error: cannot parse hexpairs\n");
			retval = false;
			goto out;
		}
	} else {
		size_t blen = strlen (hexbytes) + 4;
		bytes = malloc (blen);
		mask = malloc (blen);

		size = rz_hex_str2binmask (hexbytes, bytes, mask);
		if (size <= 0) {
			eprintf ("error: cannot parse hexpairs\n");
			retval = false;
			goto out;
		}
	}

	switch (type) {
	case RZ_SIGN_BYTES:
		retval = rz_sign_add_bytes (core->anal, name, size, bytes, mask);
		break;
	case RZ_SIGN_ANAL:
		retval = rz_sign_add_anal (core->anal, name, size, bytes, 0);
		break;
	}

out:
	free (bytes);
	free (mask);

	return retval;
}

static bool addOffsetZign(RzCore *core, const char *name, RzList *args) {
	if (rz_list_length (args) != 1) {
		eprintf ("error: invalid syntax\n");
		return false;
	}
	const char *offstr = (const char *)rz_list_get_top (args);
	if (!offstr) {
		return false;
	}
	ut64 offset = rz_num_get (core->num, offstr);
	return rz_sign_add_addr (core->anal, name, offset);
}

static bool addZign(RzCore *core, const char *name, int type, RzList *args) {
	switch (type) {
	case RZ_SIGN_BYTES:
	case RZ_SIGN_ANAL:
		return addBytesZign (core, name, type, args);
	case RZ_SIGN_GRAPH:
		return addGraphZign (core, name, args);
	case RZ_SIGN_COMMENT:
		return addCommentZign (core, name, args);
	case RZ_SIGN_NAME:
		return addNameZign (core, name, args);
	case RZ_SIGN_OFFSET:
		return addOffsetZign (core, name, args);
	case RZ_SIGN_REFS:
		return rz_sign_add_refs (core->anal, name, args);
	case RZ_SIGN_XREFS:
		return rz_sign_add_xrefs (core->anal, name, args);
	case RZ_SIGN_VARS:
		return rz_sign_add_vars (core->anal, name, args);
	case RZ_SIGN_TYPES:
		return rz_sign_add_types (core->anal, name, args);
	case RZ_SIGN_BBHASH:
		return addHashZign (core, name, type, args);
	default:
		eprintf ("error: unknown zignature type\n");
	}

	return false;
}

static int cmdAdd(void *data, const char *input) {
	RzCore *core = (RzCore *)data;

	switch (*input) {
	case ' ':
		{
			bool retval = true;
			char *args = rz_str_trim_dup (input + 1);
			if (!args) {
				return false;
			}
			RzList *lst = rz_str_split_list (args, " ", 0);
			if (!lst) {
				goto out_case_manual;
			}
			if (rz_list_length (lst) < 3) {
				eprintf ("Usage: za zigname type params\n");
				retval = false;
				goto out_case_manual;
			}
			char *zigname = rz_list_pop_head (lst);
			char *type_str = rz_list_pop_head (lst);
			if (strlen (type_str) != 1) {
				eprintf ("Usage: za zigname type params\n");
				retval = false;
				goto out_case_manual;
			}

			if (!addZign (core, zigname, type_str[0], lst)) {
				retval = false;
				goto out_case_manual;
			}

out_case_manual:
			rz_list_free (lst);
			free (args);
			return retval;
		}
		break;
	case 'f': // "zaf"
		{
			RzAnalFunction *fcni = NULL;
			RzListIter *iter = NULL;
			const char *fcnname = NULL, *zigname = NULL;
			char *args = NULL;
			int n = 0;
			bool retval = true;

			args = rz_str_trim_dup (input + 1);
			n = rz_str_word_set0 (args);

			if (n > 2) {
				eprintf ("Usage: zaf [fcnname] [zigname]\n");
				retval = false;
				goto out_case_fcn;
			}

			switch (n) {
			case 2:
				zigname = rz_str_word_get0 (args, 1);
			case 1:
				fcnname = rz_str_word_get0 (args, 0);
			}

			rz_cons_break_push (NULL, NULL);
			rz_list_foreach (core->anal->fcns, iter, fcni) {
				if (rz_cons_is_breaked ()) {
					break;
				}
				if ((!fcnname && core->offset == fcni->addr) ||
					(fcnname && !strcmp (fcnname, fcni->name))) {
					addFcnZign (core, fcni, zigname);
					break;
				}
			}
			rz_cons_break_pop ();

out_case_fcn:
			free (args);
			return retval;
		}
		break;
	case 'F':
		{
			RzAnalFunction *fcni = NULL;
			RzListIter *iter = NULL;
			int count = 0;

			rz_cons_break_push (NULL, NULL);
			rz_list_foreach (core->anal->fcns, iter, fcni) {
				if (rz_cons_is_breaked ()) {
					break;
				}
				addFcnZign (core, fcni, NULL);
				count++;
			}
			rz_cons_break_pop ();
			eprintf ("generated zignatures: %d\n", count);
		}
		break;
	case '?':
		if (input[1] == '?') {
			// TODO #7967 help refactor: move to detail
			rz_cons_printf ("Adding Zignatures (examples and documentation)\n\n"
				"Zignature types:\n"
				"  a: bytes pattern (anal mask)\n"
				"  b: bytes pattern\n"
				"  c: base64 comment\n"
				"  n: real function name\n"
				"  g: graph metrics\n"
				"  o: original offset\n"
				"  r: references\n"
				"  x: cross references\n"
				"  h: bbhash (hashing of fcn basic blocks)\n"
				"  v: vars (and args)\n"
				"Bytes patterns:\n"
				"  bytes can contain '..' (dots) to specify a binary mask\n\n"
				"Graph metrics:\n"
				"  cc:    cyclomatic complexity\n"
				"  edges: number of edges\n"
				"  nbbs:  number of basic blocks\n"
				"  ebbs:  number of end basic blocks\n\n"
				"Examples:\n"
				"  za foo b 558bec..e8........\n"
				"  za foo a e811223344\n"
				"  za foo g cc=2 nbbs=3 edges=3 ebbs=1\n"
				"  za foo g nbbs=3 edges=3\n"
				"  za foo v b-32 b-48 b-64\n"
				"  za foo o 0x08048123\n"
				"  za foo c this is a comment (base64?)\n"
				"  za foo r sym.imp.strcpy sym.imp.sprintf sym.imp.strlen\n"
				"  za foo h 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae\n");
		} else {
			rz_core_cmd_help (core, help_msg_za);
		}
		break;
	default:
		eprintf ("Usage: za[fF?] [args]\n");
		return false;
	}

	return true;
}

static int cmdOpen(void *data, const char *input) {
	RzCore *core = (RzCore *)data;

	switch (*input) {
	case ' ':
		if (input[1]) {
			return rz_sign_load (core->anal, input + 1);
		}
		eprintf ("Usage: zo filename\n");
		return false;
	case 's':
		if (input[1] == ' ' && input[2]) {
			return rz_sign_save (core->anal, input + 2);
		}
		eprintf ("Usage: zos filename\n");
		return false;
	case 'z':
		if (input[1] == ' ' && input[2]) {
			return rz_sign_load_gz (core->anal, input + 2);
		}
		eprintf ("Usage: zoz filename\n");
		return false;
	case '?':
		rz_core_cmd_help (core, help_msg_zo);
		break;
	default:
		eprintf ("Usage: zo[zs] filename\n");
		return false;
	}

	return true;
}

static int cmdSpace(void *data, const char *input) {
	RzCore *core = (RzCore *) data;
	RSpaces *zs = &core->anal->zign_spaces;

	switch (*input) {
	case '+':
		if (!input[1]) {
			eprintf ("Usage: zs+zignspace\n");
			return false;
		}
		rz_spaces_push (zs, input + 1);
		break;
	case 'r':
		if (input[1] != ' ' || !input[2]) {
			eprintf ("Usage: zsr newname\n");
			return false;
		}
		rz_spaces_rename (zs, NULL, input + 2);
		break;
	case '-':
		if (input[1] == '\x00') {
			rz_spaces_pop (zs);
		} else if (input[1] == '*') {
			rz_spaces_unset (zs, NULL);
		} else {
			rz_spaces_unset (zs, input + 1);
		}
		break;
	case 'j':
	case '*':
	case '\0':
		spaces_list (zs, input[0]);
		break;
	case ' ':
		if (!input[1]) {
			eprintf ("Usage: zs zignspace\n");
			return false;
		}
		rz_spaces_set (zs, input + 1);
		break;
	case '?':
		rz_core_cmd_help (core, help_msg_zs);
		break;
	default:
		eprintf ("Usage: zs[+-*] [namespace]\n");
		return false;
	}

	return true;
}

static int cmdFlirt(void *data, const char *input) {
	RzCore *core = (RzCore *)data;

	switch (*input) {
	case 'd':
		// TODO
		if (input[1] != ' ') {
			eprintf ("Usage: zfd filename\n");
			return false;
		}
		rz_sign_flirt_dump (core->anal, input + 2);
		break;
	case 's':
		// TODO
		if (input[1] != ' ') {
			eprintf ("Usage: zfs filename\n");
			return false;
		}
		int depth = rz_config_get_i (core->config, "dir.depth");
		char *file;
		RzListIter *iter;
		RzList *files = rz_file_globsearch (input + 2, depth);
		rz_list_foreach (files, iter, file) {
			rz_sign_flirt_scan (core->anal, file);
		}
		rz_list_free (files);
		break;
	case 'z':
		// TODO
		break;
	case '?':
		rz_core_cmd_help (core, help_msg_zf);
		break;
	default:
		eprintf ("Usage: zf[dsz] filename\n");
		return false;
	}
	return true;
}

struct ctxSearchCB {
	RzCore *core;
	bool rad;
	int count;
	const char *prefix;
};

static void apply_name(RzCore *core, RzAnalFunction *fcn, RzSignItem *it, bool rad) {
	rz_return_if_fail (core && fcn && it && it->name);
	const char *name = it->realname? it->realname: it->name;
	if (rad) {
		char *tmp = rz_name_filter2 (name);
		if (tmp) {
			rz_cons_printf ("\"afn %s @ 0x%08" PFMT64x "\"\n", tmp, fcn->addr);
			free (tmp);
		}
		return;
	}
	RzFlagItem *flag = rz_flag_get (core->flags, fcn->name);
	if (flag && flag->space && strcmp (flag->space->name, RZ_FLAGS_FS_FUNCTIONS)) {
		rz_flag_rename (core->flags, flag, name);
	}
	rz_anal_function_rename (fcn, name);
	if (core->anal->cb.on_fcn_rename) {
		core->anal->cb.on_fcn_rename (core->anal, core->anal->user, fcn, name);
	}
}

static void apply_types(RzCore *core, RzAnalFunction *fcn, RzSignItem *it) {
	rz_return_if_fail (core && fcn && it && it->name);
	if (!it->types) {
		return;
	}
	const char *name = it->realname? it->realname: it->name;
	RzListIter *iter;
	char *type;
	char *start = rz_str_newf ("func.%s.", name);
	size_t startlen = strlen (start);
	char *alltypes = NULL;
	rz_list_foreach (it->types, iter, type) {
		if (strncmp (start, type, startlen)) {
			eprintf ("Unexpected type: %s\n", type);
			free (alltypes);
			free (start);
			return;
		}
		if (!(alltypes = rz_str_appendf (alltypes, "%s\n", type))) {
			free (alltypes);
			free (start);
			return;
		}
	}
	rz_str_remove_char (alltypes, '"');
	rz_anal_save_parsed_type (core->anal, alltypes);
	free (start);
	free (alltypes);
}

static void apply_flag(RzCore *core, RzSignItem *it, ut64 addr, int size, int count, const char *prefix, bool rad) {
	const char *zign_prefix = rz_config_get (core->config, "zign.prefix");
	char *name = rz_str_newf ("%s.%s.%s_%d", zign_prefix, prefix, it->name, count);
	if (name) {
		if (rad) {
			char *tmp = rz_name_filter2 (name);
			if (tmp) {
				rz_cons_printf ("f %s %d @ 0x%08" PFMT64x "\n", tmp, size, addr);
				free (tmp);
			}
		} else {
			rz_flag_set (core->flags, name, addr, size);
		}
		free (name);
	}
}

static int searchHitCB(RzSignItem *it, RzSearchKeyword *kw, ut64 addr, void *user) {
	struct ctxSearchCB *ctx = (struct ctxSearchCB *)user;
	apply_flag (ctx->core, it, addr, kw->keyword_length, kw->count, ctx->prefix, ctx->rad);
	RzAnalFunction *fcn = rz_anal_get_fcn_in (ctx->core->anal, addr, 0);
	// TODO: create fcn if it does not exist
	if (fcn) {
		apply_name (ctx->core, fcn, it, ctx->rad);
		apply_types (ctx->core, fcn, it);
	}
	ctx->count++;
	return 1;
}

static int fcnMatchCB(RzSignItem *it, RzAnalFunction *fcn, void *user) {
	struct ctxSearchCB *ctx = (struct ctxSearchCB *)user;
	// TODO(nibble): use one counter per metric zign instead of ctx->count
	ut64 sz = rz_anal_function_realsize (fcn);
	apply_flag (ctx->core, it, fcn->addr, sz, ctx->count, ctx->prefix, ctx->rad);
	apply_name (ctx->core, fcn, it, ctx->rad);
	apply_types (ctx->core, fcn, it);
	ctx->count++;
	return 1;
}

static bool searchRange(RzCore *core, ut64 from, ut64 to, bool rad, struct ctxSearchCB *ctx) {
	ut8 *buf = malloc (core->blocksize);
	ut64 at;
	int rlen;
	bool retval = true;
	int minsz = rz_config_get_i (core->config, "zign.minsz");

	if (!buf) {
		return false;
	}
	RzSignSearch *ss = rz_sign_search_new ();
	ss->search->align = rz_config_get_i (core->config, "search.align");
	rz_sign_search_init (core->anal, ss, minsz, searchHitCB, ctx);

	rz_cons_break_push (NULL, NULL);
	for (at = from; at < to; at += core->blocksize) {
		if (rz_cons_is_breaked ()) {
			retval = false;
			break;
		}
		rlen = RZ_MIN (core->blocksize, to - at);
		if (!rz_io_is_valid_offset (core->io, at, 0)) {
			retval = false;
			break;
		}
		(void)rz_io_read_at (core->io, at, buf, rlen);
		if (rz_sign_search_update (core->anal, ss, &at, buf, rlen) == -1) {
			eprintf ("search: update read error at 0x%08" PFMT64x "\n", at);
			retval = false;
			break;
		}
	}
	rz_cons_break_pop ();
	free (buf);
	rz_sign_search_free (ss);

	return retval;
}

static bool searchRange2(RzCore *core, RzSignSearch *ss, ut64 from, ut64 to, bool rad, struct ctxSearchCB *ctx) {
	ut8 *buf = malloc (core->blocksize);
	ut64 at;
	int rlen;
	bool retval = true;

	if (!buf) {
		return false;
	}
	rz_cons_break_push (NULL, NULL);
	for (at = from; at < to; at += core->blocksize) {
		if (rz_cons_is_breaked ()) {
			retval = false;
			break;
		}
		rlen = RZ_MIN (core->blocksize, to - at);
		if (!rz_io_is_valid_offset (core->io, at, 0)) {
			retval = false;
			break;
		}
		(void)rz_io_read_at (core->io, at, buf, rlen);
		if (rz_sign_search_update (core->anal, ss, &at, buf, rlen) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x"\n", at);
			retval = false;
			break;
		}
	}
	rz_cons_break_pop ();
	free (buf);

	return retval;
}

static bool search(RzCore *core, bool rad, bool only_func) {
	RzList *list;
	RzListIter *iter;
	RzAnalFunction *fcni = NULL;
	RzIOMap *map;
	bool retval = true;
	int hits = 0;

	struct ctxSearchCB bytes_search_ctx = { core, rad, 0, "bytes" };
	struct ctxSearchCB graph_match_ctx = { core, rad, 0, "graph" };
	struct ctxSearchCB offset_match_ctx = { core, rad, 0, "offset" };
	struct ctxSearchCB refs_match_ctx = { core, rad, 0, "refs" };
	struct ctxSearchCB hash_match_ctx = { core, rad, 0, "bbhash" };
	struct ctxSearchCB types_match_ctx = { core, rad, 0, "types" };

	const char *zign_prefix = rz_config_get (core->config, "zign.prefix");
	int mincc = rz_config_get_i (core->config, "zign.mincc");
	const char *mode = rz_config_get (core->config, "search.in");
	bool useBytes = rz_config_get_i (core->config, "zign.bytes");
	bool useGraph = rz_config_get_i (core->config, "zign.graph");
	bool useOffset = rz_config_get_i (core->config, "zign.offset");
	bool useRefs = rz_config_get_i (core->config, "zign.refs");
	bool useHash = rz_config_get_i (core->config, "zign.hash");
	bool useTypes = rz_config_get_i (core->config, "zign.types");
	int maxsz = rz_config_get_i (core->config, "zign.maxsz");

	if (rad) {
		rz_cons_printf ("fs+%s\n", zign_prefix);
	} else {
		if (!rz_flag_space_push (core->flags, zign_prefix)) {
			eprintf ("error: cannot create flagspace\n");
			return false;
		}
	}

	// Bytes search
	if (useBytes && !only_func) {
		list = rz_core_get_boundaries_prot (core, -1, mode, "search");
		if (!list) {
			return false;
		}
		rz_list_foreach (list, iter, map) {
			eprintf ("[+] searching 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", map->itv.addr, rz_itv_end (map->itv));
			retval &= searchRange (core, map->itv.addr, rz_itv_end (map->itv), rad, &bytes_search_ctx);
		}
		rz_list_free (list);
	}

	// Function search
	// TODO (oxcabe): Refactor big conditional
	if (useGraph || useOffset || useRefs || useHash || (useBytes && only_func) || useTypes) {
		eprintf ("[+] searching function metrics\n");
		rz_cons_break_push (NULL, NULL);
		int count = 0;

		RzSignSearch *ss = NULL;

		if (useBytes && only_func) {
			ss = rz_sign_search_new ();
			ss->search->align = rz_config_get_i (core->config, "search.align");
			int minsz = rz_config_get_i (core->config, "zign.minsz");
			rz_sign_search_init (core->anal, ss, minsz, searchHitCB, &bytes_search_ctx);
		}

		rz_list_foreach (core->anal->fcns, iter, fcni) {
			if (rz_cons_is_breaked ()) {
				break;
			}
			if (useGraph) {
				rz_sign_match_graph (core->anal, fcni, mincc, fcnMatchCB, &graph_match_ctx);
			}
			if (useOffset) {
				rz_sign_match_addr (core->anal, fcni, fcnMatchCB, &offset_match_ctx);
			}
			if (useRefs) {
				rz_sign_match_refs (core->anal, fcni, fcnMatchCB, &refs_match_ctx);
			}
			if (useHash) {
				rz_sign_match_hash (core->anal, fcni, fcnMatchCB, &hash_match_ctx);
			}
			if (useBytes && only_func) {
				eprintf ("Matching func %d / %d (hits %d)\n", count, rz_list_length (core->anal->fcns), bytes_search_ctx.count);
				int fcnlen = rz_anal_function_realsize (fcni);
				int len = RZ_MIN (core->io->addrbytes * fcnlen, maxsz);
				retval &= searchRange2 (core, ss, fcni->addr, fcni->addr + len, rad, &bytes_search_ctx);
			}
			if (useTypes) {
				rz_sign_match_types (core->anal, fcni, fcnMatchCB, &types_match_ctx);
			}
			count ++;
#if 0
TODO: add useXRefs, useName
#endif
		}
		rz_cons_break_pop ();
		rz_sign_search_free (ss);
	}

	if (rad) {
		rz_cons_printf ("fs-\n");
	} else {
		if (!rz_flag_space_pop (core->flags)) {
			eprintf ("error: cannot restore flagspace\n");
			return false;
		}
	}

	hits = bytes_search_ctx.count + graph_match_ctx.count +
		offset_match_ctx.count + refs_match_ctx.count + hash_match_ctx.count + types_match_ctx.count;
	eprintf ("hits: %d\n", hits);

	return retval;
}

static void print_possible_matches(RzList *list) {
	RzListIter *itr;
	RzSignCloseMatch *row;
	rz_list_foreach (list, itr, row) {
		// total score
		if (row->bscore > 0.0 && row->gscore > 0.0) {
			rz_cons_printf ("%02.5lf  ", row->score);
		}
		if (row->bscore > 0.0) {
			rz_cons_printf ("%02.5lf B  ", row->bscore);
		}
		if (row->gscore > 0.0) {
			rz_cons_printf ("%02.5lf G  ", row->gscore);
		}
		rz_cons_printf (" %s\n", row->item->name);
	}
}

static RzSignItem *item_frm_signame(RzAnal *a, const char *signame) {
	// example zign|*|sym.unlink_blk
	const RSpace *space = rz_spaces_current (&a->zign_spaces);
	char *k = rz_str_newf ("zign|%s|%s", space? space->name: "*", signame);
	char *value = sdb_querys (a->sdb_zigns, NULL, 0, k);
	if (!value) {
		free (k);
		return NULL;
	}

	RzSignItem *it = rz_sign_item_new ();
	if (!it) {
		free (k);
		free (value);
		return NULL;
	}

	if (!rz_sign_deserialize (a, it, k, value)) {
		rz_sign_item_free (it);
		it = NULL;
	}
	free (k);
	free (value);
	return it;
}

static double get_zb_threshold(RzCore *core) {
	const char *th = rz_config_get (core->config, "zign.threshold");
	double thresh = rz_num_get_float (NULL, th);
	if (thresh < 0.0 || thresh > 1.0) {
		eprintf ("Invalid zign.threshold %s, using 0.0\n", th);
		thresh = 0.0;
	}
	return thresh;
}

static bool bestmatch_fcn(RzCore *core, const char *input) {
	rz_return_val_if_fail (input && core, false);

	char *argv = rz_str_new (input);
	if (!argv) {
		return false;
	}

	int count = 5;
	char *zigname = strtok (argv, " ");
	if (!zigname) {
		eprintf ("Need a signature\n");
		free (argv);
		return false;
	}
	char *cs = strtok (NULL, " ");
	if (cs) {
		if ((count = atoi (cs)) <= 0) {
			free (argv);
			eprintf ("Invalid count\n");
			return false;
		}
		if (strtok (NULL, " ")) {
			free (argv);
			eprintf ("Too many parameters\n");
			return false;
		}
	}
	RzSignItem *it = item_frm_signame (core->anal, zigname);
	if (!it) {
		eprintf ("Couldn't get signature for %s\n", zigname);
		free (argv);
		return false;
	}
	free (argv);

	if (!rz_config_get_i (core->config, "zign.bytes")) {
		rz_sign_bytes_free (it->bytes);
		it->bytes = NULL;
	}
	if (!rz_config_get_i (core->config, "zign.graph")) {
		rz_sign_graph_free (it->graph);
		it->graph = NULL;
	}

	double thresh = get_zb_threshold (core);
	RzList *list = rz_sign_find_closest_fcn (core->anal, it, count, thresh);
	rz_sign_item_free (it);

	if (list) {
		print_possible_matches (list);
		rz_list_free (list);
		return true;
	}
	return false;
}

static bool bestmatch_sig(RzCore *core, const char *input) {
	rz_return_val_if_fail (input && core, false);
	int count = 5;
	if (!RZ_STR_ISEMPTY (input)) {
		count = atoi (input);
		if (count <= 0) {
			eprintf ("[!!] invalid number %s\n", input);
			return false;
		}
	}

	RzAnalFunction *fcn = rz_anal_get_fcn_in (core->anal, core->offset, 0);
	if (!fcn) {
		eprintf ("No function at 0x%08" PFMT64x "\n", core->offset);
		return false;
	}

	RzSignItem *item = rz_sign_item_new ();
	if (!item) {
		return false;
	}

	if (rz_config_get_i (core->config, "zign.bytes")) {
		rz_sign_addto_item (core->anal, item, fcn, RZ_SIGN_BYTES);
		RzSignBytes *b = item->bytes;
		int minsz = rz_config_get_i (core->config, "zign.minsz");
		if (b && b->size < minsz) {
			eprintf ("Warning: Function signature is too small (%d < %d) See e zign.minsz", b->size, minsz);
			rz_sign_item_free (item);
			return false;
		}
	}
	if (rz_config_get_i (core->config, "zign.graph")) {
		rz_sign_addto_item (core->anal, item, fcn, RZ_SIGN_GRAPH);
	}

	double th = get_zb_threshold (core);
	bool found = false;
	if (item->graph || item->bytes) {
		rz_cons_break_push (NULL, NULL);
		RzList *list = rz_sign_find_closest_sig (core->anal, item, count, th);
		if (list) {
			found = true;
			print_possible_matches (list);
			rz_list_free (list);
		}
		rz_cons_break_pop ();
	} else {
		eprintf ("Warning: no signatures types available for testing\n");
	}

	rz_sign_item_free (item);
	return found;
}

static bool bestmatch(void *data, const char *input) {
	rz_return_val_if_fail (data && input, false);
	RzCore *core = (RzCore *)data;
	switch (input[0]) {
	case 'r':
		input++;
		return bestmatch_fcn (core, input);
		break;
	case ' ':
		input++;
	case '\x00':
		return bestmatch_sig (core, input);
		break;
	case '?':
	default:
		rz_core_cmd_help (core, help_msg_zb);
		return false;
	}
}

static int cmdCompare(void *data, const char *input) {
	int result = true;
	RzCore *core = (RzCore *) data;
	const char *raw_bytes_thresh = rz_config_get (core->config, "zign.diff.bthresh");
	const char *raw_graph_thresh = rz_config_get (core->config, "zign.diff.gthresh");
	RzSignOptions *options = rz_sign_options_new (raw_bytes_thresh, raw_graph_thresh);

	switch (*input) {
	case ' ':
		if (!input[1]) {
			eprintf ("Usage: zc other_space\n");
			result = false;
			break;
		}
		result = rz_sign_diff (core->anal, options, input + 1);
		break;
	case 'n':
		switch (input[1]) {
		case ' ':
			if (!input[2]) {
				eprintf ("Usage: zcn other_space\n");
				result = false;
				break;
			}
			result = rz_sign_diff_by_name (core->anal, options, input + 2, false);
			break;
		case '!':
			if (input[2] != ' ' || !input[3]) {
				eprintf ("Usage: zcn! other_space\n");
				result = false;
				break;
			}
			result = rz_sign_diff_by_name (core->anal, options, input + 3, true);
			break;
		default:
			eprintf ("Usage: zcn! other_space\n");
			result = false;
		}
		break;
	case '?':
		rz_core_cmd_help (core, help_msg_zc);
		break;
	default:
		eprintf ("Usage: zc[?n!] other_space\n");
		result = false;
	}

	rz_sign_options_free (options);

	return result;
}

static int cmdCheck(void *data, const char *input) {
	RzCore *core = (RzCore *) data;
	RzSignSearch *ss;
	RzListIter *iter;
	RzAnalFunction *fcni = NULL;
	ut64 at = core->offset;
	bool retval = true;
	bool rad = input[0] == '*';
	int hits = 0;

	struct ctxSearchCB bytes_search_ctx = { core, rad, 0, "bytes" };
	struct ctxSearchCB graph_match_ctx = { core, rad, 0, "graph" };
	struct ctxSearchCB offset_match_ctx = { core, rad, 0, "offset" };
	struct ctxSearchCB refs_match_ctx = { core, rad, 0, "refs" };
	struct ctxSearchCB hash_match_ctx = { core, rad, 0, "bbhash" };
	struct ctxSearchCB types_match_ctx = { core, rad, 0, "types" };

	const char *zign_prefix = rz_config_get (core->config, "zign.prefix");
	int minsz = rz_config_get_i (core->config, "zign.minsz");
	int mincc = rz_config_get_i (core->config, "zign.mincc");
	bool useBytes = rz_config_get_i (core->config, "zign.bytes");
	bool useGraph = rz_config_get_i (core->config, "zign.graph");
	bool useOffset = rz_config_get_i (core->config, "zign.offset");
	bool useRefs = rz_config_get_i (core->config, "zign.refs");
	bool useHash = rz_config_get_i (core->config, "zign.hash");
	bool useTypes = rz_config_get_i (core->config, "zign.types");

	if (rad) {
		rz_cons_printf ("fs+%s\n", zign_prefix);
	} else {
		if (!rz_flag_space_push (core->flags, zign_prefix)) {
			eprintf ("error: cannot create flagspace\n");
			return false;
		}
	}

	// Bytes search
	if (useBytes) {
		eprintf ("[+] searching 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", at, at + core->blocksize);
		ss = rz_sign_search_new ();
		rz_sign_search_init (core->anal, ss, minsz, searchHitCB, &bytes_search_ctx);
		if (rz_sign_search_update (core->anal, ss, &at, core->block, core->blocksize) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x"\n", at);
			retval = false;
		}
		rz_sign_search_free (ss);
	}

	// Function search
	if (useGraph || useOffset || useRefs || useHash || useTypes) {
		eprintf ("[+] searching function metrics\n");
		rz_cons_break_push (NULL, NULL);
		rz_list_foreach (core->anal->fcns, iter, fcni) {
			if (rz_cons_is_breaked ()) {
				break;
			}
			if (fcni->addr == core->offset) {
				if (useGraph) {
					rz_sign_match_graph (core->anal, fcni, mincc, fcnMatchCB, &graph_match_ctx);
				}
				if (useOffset) {
					rz_sign_match_addr (core->anal, fcni, fcnMatchCB, &offset_match_ctx);
				}
				if (useRefs){
					rz_sign_match_refs (core->anal, fcni, fcnMatchCB, &refs_match_ctx);
				}
				if (useHash){
					rz_sign_match_hash (core->anal, fcni, fcnMatchCB, &hash_match_ctx);
				}
				if (useTypes) {
					rz_sign_match_types (core->anal, fcni, fcnMatchCB, &types_match_ctx);
				}
				break;
			}
		}
		rz_cons_break_pop ();
	}

	if (rad) {
		rz_cons_printf ("fs-\n");
	} else {
		if (!rz_flag_space_pop (core->flags)) {
			eprintf ("error: cannot restore flagspace\n");
			return false;
		}
	}

	hits = bytes_search_ctx.count + graph_match_ctx.count +
		offset_match_ctx.count + refs_match_ctx.count + hash_match_ctx.count;
	eprintf ("hits: %d\n", hits);

	return retval;
}

static int cmdSearch(void *data, const char *input) {
	RzCore *core = (RzCore *) data;

	switch (*input) {
	case 0:
	case '*':
		return search (core, input[0] == '*', false);
	case 'f':
		switch (input[1]) {
		case 0:
		case '*':
			return search (core, input[1] == '*', true);
		default:
			eprintf ("Usage: z/[f*]\n");
			return false;
		}
	case '?':
		rz_core_cmd_help (core, help_msg_z_slash);
		break;
	default:
		eprintf ("Usage: z/[*]\n");
		return false;
	}
	return true;
}

static int cmdInfo(void *data, const char *input) {
	if (!data || !input) {
		return false;
	}
	RzCore *core = (RzCore *) data;
	rz_flag_space_push (core->flags, RZ_FLAGS_FS_SIGNS);
	rz_flag_list (core->flags, *input, input[0] ? input + 1: "");
	rz_flag_space_pop (core->flags);
	return true;
}

static int cmd_zign(void *data, const char *input) {
	RzCore *core = (RzCore *) data;
	const char *arg = input + 1;

	switch (*input) {
	case '\0':
	case '*':
	case 'q':
	case 'j': // "zj"
		rz_sign_list (core->anal, *input);
		break;
	case 'k': // "zk"
		rz_core_cmd0 (core, "k anal/zigns/*");
		break;
	case '-': // "z-"
		rz_sign_delete (core->anal, arg);
		break;
	case '.': // "z."
		return cmdCheck (data, arg);
	case 'b': // "zb"
		return bestmatch (data, arg);
	case 'o': // "zo"
		return cmdOpen (data, arg);
	case 'g': // "zg"
		return cmdAdd (data, "F");
	case 'a': // "za"
		return cmdAdd (data, arg);
	case 'f': // "zf"
		return cmdFlirt (data, arg);
	case '/': // "z/"
		return cmdSearch (data, arg);
	case 'c': // "zc"
		return cmdCompare (data, arg);
	case 's': // "zs"
		return cmdSpace (data, arg);
	case 'i': // "zi"
		return cmdInfo (data, arg);
	case '?': // "z?"
		rz_core_cmd_help (core, help_msg_z);
		break;
	default:
		rz_core_cmd_help (core, help_msg_z);
		return false;
	}

	return true;
}
