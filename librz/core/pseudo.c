/* radare - LGPL - Copyright 2015-2017 - pancake */

#include <rz_core.h>
#define TYPE_NONE 0
#define TYPE_STR 1
#define TYPE_SYM 2
#define IS_ALPHA(x) (IS_UPPER(x) || IS_LOWER(x))
#define IS_STRING(x,y) ((x)+3<end && *(x) == 's' && *((x)+1) == 't' && *((x)+2) == 'r' && *((x)+3) == '.')
#define IS_SYMBOL(x,y) ((x)+3<end && *(x) == 's' && *((x)+1) == 'y' && *((x)+2) == 'm' && *((x)+3) == '.')

typedef struct _find_ctx {
	char *comment;
	char *left;
	char *right;
	char *linebegin;
	int leftlen;
	int rightlen;
	int leftpos;
	int leftcolor;
	int commentcolor;
	int rightcolor;
	int linecount;
	int type;
} RFindCTX;

static void find_and_change (char* in, int len) {
	// just to avoid underflows.. len can't be < then len(padding).
	if (!in || len < 1) {
		return;
	}
	char *end;
	RFindCTX ctx = {0};
	end = in + len;
//	type = TYPE_NONE;
	for (ctx.linebegin = in; in < end; in++) {
		if (*in == '\n' || !*in) {
			if (ctx.type == TYPE_SYM && ctx.linecount < 1) {
				ctx.linecount++;
				ctx.linebegin = in + 1;
				continue;
			}
			if (ctx.type != TYPE_NONE && ctx.right && ctx.left && ctx.rightlen > 0 && ctx.leftlen > 0) {
				char* copy = NULL;
				if (ctx.leftlen > ctx.rightlen) {
					// if new string is o
					copy = (char*) malloc (ctx.leftlen);
					if (copy) {
						memmove (copy, ctx.left, ctx.leftlen);
						memmove (ctx.left, ctx.right, ctx.rightlen);
						memset (ctx.left + ctx.rightlen, ' ', ctx.leftlen - ctx.rightlen);
						memmove (ctx.comment - ctx.leftlen + ctx.rightlen, ctx.comment, ctx.right - ctx.comment);
						memmove (ctx.right - ctx.leftlen + ctx.rightlen, copy, ctx.leftlen);
					}
				} else if (ctx.leftlen < ctx.rightlen) {
					if (ctx.linecount < 1) {
						copy = (char*) malloc (ctx.rightlen);
						if (copy) {
							// ###LEFTLEN### ### RIGHT
							// backup ctx.right+len into copy
							memcpy (copy, ctx.right, ctx.rightlen);
							// move string into
							memcpy (ctx.right + ctx.rightlen - ctx.leftlen, ctx.left, ctx.leftlen);
							memmove (ctx.comment + ctx.rightlen - ctx.leftlen, ctx.comment, ctx.right - ctx.comment);
							memmove (ctx.left + ctx.rightlen - ctx.leftlen, copy, ctx.rightlen);
						}
					} else {
//						copy = (char*) malloc (ctx.linebegin - ctx.left);
//						if (copy) {
//							memcpy (copy, ctx.left, ctx.linebegin - ctx.left);
						memset (ctx.right - ctx.leftpos, ' ', ctx.leftpos);
						*(ctx.right - ctx.leftpos - 1) = '\n';
//							memcpy (ctx.comment + 3, copy, ctx.linebegin - ctx.left);
						memset (ctx.left, ' ', ctx.leftlen);
						memset (ctx.linebegin - ctx.leftlen, ' ', ctx.leftlen);
//						}
					}
				} else if (ctx.leftlen == ctx.rightlen) {
					copy = (char*) malloc (ctx.leftlen);
					if (copy) {
						memcpy (copy, ctx.right, ctx.leftlen);
						memcpy (ctx.right, ctx.left, ctx.leftlen);
						memcpy (ctx.left, copy, ctx.leftlen);
					}
				}
				free (copy);
			}
			memset (&ctx, 0, sizeof (ctx));
			ctx.linebegin = in + 1;
		} else if (!ctx.comment && *in == ';' && in[1] == ' ') {
			ctx.comment = in - 1;
			ctx.comment[1] = '/';
			ctx.comment[2] = '/';
			while (!IS_WHITESPACE (*(ctx.comment - ctx.commentcolor))) {
				ctx.commentcolor++;
			}
			ctx.commentcolor--;
		} else if (!ctx.comment && ctx.type == TYPE_NONE) {
			if (IS_STRING (in, ctx)) {
				ctx.type = TYPE_STR;
				ctx.left = in;
				while (!IS_WHITESPACE (*(ctx.left - ctx.leftcolor))) {
					ctx.leftcolor++;
				}
				ctx.leftcolor--;
				ctx.leftpos = ctx.left - ctx.linebegin;
			} else if (IS_SYMBOL (in, ctx)) {
				ctx.type = TYPE_SYM;
				ctx.left = in;
				while (!IS_WHITESPACE (*(ctx.left - ctx.leftcolor))) {
					ctx.leftcolor++;
				}
				ctx.leftcolor--;
				ctx.leftpos = ctx.left - ctx.linebegin;
			}
		} else if (ctx.type == TYPE_STR) {
			if (!ctx.leftlen && ctx.left && IS_WHITESPACE (*in)) {
				ctx.leftlen = in - ctx.left;
			} else if (ctx.comment && *in == '"' && in[-1] != '\\') {
				if (!ctx.right) {
					ctx.right = in;
					while (!IS_WHITESPACE (*(ctx.right - ctx.rightcolor))) {
						ctx.rightcolor++;
					}
					ctx.rightcolor--;
				} else {
					ctx.rightlen = in - ctx.right + 1;
				}
			}
		} else if (ctx.type == TYPE_SYM) {
			if (!ctx.leftlen && ctx.left && IS_WHITESPACE (*in)) {
				ctx.leftlen = in - ctx.left + 3;
			} else if (ctx.comment && *in == '(' && IS_ALPHA (in[-1]) && !ctx.right) {
				// ok so i've found a function written in this way:
				// type = [const|void|int|float|double|short|long]
				// type fcn_name (type arg1, type arg2, ...)
				// right now 'in' points at '(', but the function name is before, so i'll go back
				// till a space is found
				// 'int print(const char*, ...)'
				//           ^
				ctx.right = in - 1;
				while (IS_ALPHA (*ctx.right) || *ctx.right == '_' || *ctx.right == '*') {
					ctx.right--;
				}
				// 'int print(const char*, ...)'
				//     ^
				// right now 'in' points at ' ' before 'p' , but there can be a return value
				// like 'int' in 'int print(const char*, ...)'.
				// so to find for example 'int' we have to go back till a space is found.
				// if a non alpha is found, then we can cut from the function name
				if (*ctx.right == ' ') {
					ctx.right--;
					while (IS_ALPHA (*ctx.right) || *ctx.right == '_' || *ctx.right == '*') {
						ctx.right--;
					}
					// moving forward since it points now to non alpha.
					ctx.right++;
				}
				while (!IS_WHITESPACE (*(ctx.right - ctx.rightcolor))) {
					ctx.rightcolor++;
				}
				ctx.rightcolor--;
			} else if (ctx.comment && *in == ')' && in[1] != '\'') {
				ctx.rightlen = in - ctx.right + 1;
			}
		}
	}
}

RZ_API int rz_core_pseudo_code(RzCore *core, const char *input) {
	const char *cmdPdc = rz_config_get (core->config, "cmd.pdc");
	if (cmdPdc && *cmdPdc && !strstr (cmdPdc, "pdc")) {
		if (strstr (cmdPdc, "!*") || strstr (cmdPdc, "#!")) {
			if (!strcmp (input, "*")) {
				input = " -r2";
			} else if (!strcmp (input, "=")) {
				input = " -a";
			} else if (!strcmp (input, "?")) {
				input = " -h";
			}
		}
		return rz_core_cmdf (core, "%s%s", cmdPdc, input);
	}

	Sdb *db;
	ut64 queuegoto = 0LL;
	const char *blocktype = "else";
	RzAnalFunction *fcn = rz_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	RConfigHold *hc = rz_config_hold_new (core->config);
	if (!hc) {
		return false;
	}
	rz_config_hold_i (hc, "asm.pseudo", "asm.decode", "asm.lines", "asm.bytes", "asm.stackptr", NULL);
	rz_config_hold_i (hc, "asm.offset", "asm.flags", "asm.lines.fcn", "asm.comments", NULL);
	rz_config_hold_i (hc, "asm.functions", "asm.section", "asm.cmt.col", "asm.filter", NULL);
	rz_config_hold_i (hc, "scr.color", "emu.str", "asm.emu", "emu.write", NULL);
	rz_config_hold_i (hc, "io.cache", NULL);
	if (!fcn) {
		eprintf ("Cannot find function in 0x%08"PFMT64x"\n", core->offset);
		rz_config_hold_free (hc);
		return false;
	}
	rz_config_set_i (core->config, "scr.color", 0);
	rz_config_set_i (core->config, "asm.stackptr", 0);
	rz_config_set_i (core->config, "asm.pseudo", 1);
	rz_config_set_i (core->config, "asm.decode", 0);
	rz_config_set_i (core->config, "asm.filter", 1);
	rz_config_set_i (core->config, "asm.lines", 0);
	rz_config_set_i (core->config, "asm.bytes", 0);
	rz_config_set_i (core->config, "asm.offset", 0);
	rz_config_set_i (core->config, "asm.flags", 0);
	rz_config_set_i (core->config, "asm.emu", 1);
	rz_config_set_i (core->config, "emu.str", 1);
	rz_config_set_i (core->config, "emu.write", 1);
	rz_config_set_i (core->config, "asm.lines.fcn", 0);
	rz_config_set_i (core->config, "asm.comments", 1);
	rz_config_set_i (core->config, "asm.functions", 0);
	rz_config_set_i (core->config, "asm.tabs", 0);
	rz_config_set_i (core->config, "asm.section", 0);
	rz_config_set_i (core->config, "asm.cmt.col", 30);
	rz_config_set_i (core->config, "io.cache", 1);
	rz_core_cmd0 (core, "aeim");

	db = sdb_new0 ();
	// walk all basic blocks
	// define depth level for each block
	// use it for indentation
	// asm.pseudo=true
	// asm.decode=true
	RzAnalBlock *bb = rz_list_first (fcn->bbs);
	char indentstr[1024] = {0};
	int n_bb = rz_list_length (fcn->bbs);
	rz_cons_printf ("function %s () {", fcn->name);
	int indent = 1;
	int nindent = 1;
	RzList *visited = rz_list_newf (NULL);
	rz_cons_printf ("\n    //  %d basic blocks\n", n_bb);
	do {
#define I_TAB 4
#define K_MARK(x) sdb_fmt("mark.%"PFMT64x,x)
#define K_ELSE(x) sdb_fmt("else.%"PFMT64x,x)
#define K_INDENT(x) sdb_fmt("loc.%"PFMT64x,x)
#define SET_INDENT(x) { (x) = (x)>0?(x):1; memset (indentstr, ' ', (x)*I_TAB); indentstr [((x)*I_TAB)-2] = 0; }
		if (!bb) {
			break;
		}
		rz_list_append (visited, bb);
		rz_cons_push ();
		bool html = rz_config_get_i (core->config, "scr.html");
		rz_config_set_i (core->config, "scr.html", 0);
		char *code = rz_core_cmd_str (core, sdb_fmt ("pD %d @ 0x%08"PFMT64x"\n", bb->size, bb->addr));
		rz_cons_pop ();
		rz_config_set_i (core->config, "scr.html", html);
		if (indent * I_TAB + 2 >= sizeof (indentstr)) {
			indent = (sizeof (indentstr) / I_TAB) - 4;
		}
		SET_INDENT (indent);
		code = rz_str_prefix_all (code, indentstr);
		if (!code) {
			eprintf ("No code here\n");
			break;
		}
		int len = strlen (code);
		code[len - 1] = 0; // chop last newline
		find_and_change (code, len);
		if (!sdb_const_get (db, K_MARK (bb->addr), 0)) {
			bool mustprint = !queuegoto || queuegoto != bb->addr;
			if (mustprint) {
				if (queuegoto) {
					rz_cons_printf ("\n%s  goto loc_0x%llx",
						indentstr, queuegoto);
					queuegoto = 0LL;
				}
				rz_cons_printf ("\n%s  loc_0x%llx:\n", indentstr, bb->addr);
				indentstr[(indent * I_TAB) - 2] = 0;
				rz_cons_printf ("\n%s", code);
				free (code);
				sdb_num_set (db, K_MARK (bb->addr), 1, 0);
			}
		}
		if (sdb_const_get (db, K_INDENT (bb->addr), 0)) {
			// already analyzed, go pop and continue
			// XXX check if can't pop
			//eprintf ("%s// 0x%08llx already analyzed\n", indentstr, bb->addr);
			ut64 addr = sdb_array_pop_num (db, "indent", NULL);
			if (addr == UT64_MAX) {
				int i;
				nindent = 1;
				for (i = indent; i != nindent; i--) {
					SET_INDENT (i);
					rz_cons_printf ("\n%s}", indentstr);
				}
				rz_cons_printf ("\n%sreturn;\n", indentstr);
				RzAnalBlock *nbb = rz_anal_bb_from_offset (core->anal, bb->fail);
				if (rz_list_contains (visited, nbb)) {
					nbb = rz_anal_bb_from_offset (core->anal, bb->jump);
					if (rz_list_contains (visited, nbb)) {
						nbb = NULL;
					}
				}
				if (!nbb) {
					break;
				}
				bb = nbb;
				indent--;
				continue;
			}
			if (sdb_num_get (db, K_ELSE (bb->addr), 0)) {
				if (!strcmp (blocktype, "else")) {
					rz_cons_printf ("\n%s } %s {", indentstr, blocktype);
				} else {
					rz_cons_printf ("\n%s } %s (?);", indentstr, blocktype);
				}
			} else {
				rz_cons_printf ("\n%s}", indentstr);
			}
			if (addr != bb->addr) {
				queuegoto = addr;
				// rz_cons_printf ("\n%s  goto loc_0x%llx", indentstr, addr);
			}
			bb = rz_anal_bb_from_offset (core->anal, addr);
			if (!bb) {
				eprintf ("failed block\n");
				break;
			}
			//eprintf ("next is %llx\n", addr);
			nindent = sdb_num_get (db, K_INDENT (addr), NULL);
			if (indent > nindent && !strcmp (blocktype, "else")) {
				int i;
				for (i = indent; i != nindent; i--) {
					SET_INDENT (i);
					rz_cons_printf ("\n%s }", indentstr);
				}
			}
			indent = nindent;
		} else {
			sdb_set (db, K_INDENT (bb->addr), "passed", 0);
			if (bb->jump != UT64_MAX) {
				int swap = 1;
				// TODO: determine which branch take first
				ut64 jump = swap ? bb->jump : bb->fail;
				ut64 fail = swap ? bb->fail : bb->jump;
				// if its from another function chop it!
				RzAnalFunction *curfcn = rz_anal_get_fcn_in (core->anal, jump, R_ANAL_FCN_TYPE_NULL);
				if (curfcn != fcn) {
					// chop that branch
					rz_cons_printf ("\n  // chop\n");
					// break;
				}
				if (sdb_get (db, K_INDENT (jump), 0)) {
					// already tracekd
					if (!sdb_get (db, K_INDENT (fail), 0)) {
						bb = rz_anal_bb_from_offset (core->anal, fail);
					}
				} else {
					bb = rz_anal_bb_from_offset (core->anal, jump);
					if (!bb) {
						eprintf ("failed to retrieve block at 0x%"PFMT64x"\n", jump);
						break;
					}
					if (fail != UT64_MAX) {
						// do not push if already pushed
						indent++;
						if (sdb_get (db, K_INDENT (bb->fail), 0)) {
							/* do nothing here */
							eprintf ("BlockAlready 0x%"PFMT64x"\n", bb->addr);
						} else {
							// rz_cons_printf (" { RADICAL %llx\n", bb->addr);
							sdb_array_push_num (db, "indent", fail, 0);
							sdb_num_set (db, K_INDENT (fail), indent, 0);
							sdb_num_set (db, K_ELSE (fail), 1, 0);
							SET_INDENT (indent);
							rz_cons_printf ("\n%s {", indentstr);
						}
					} else {
						rz_cons_printf ("\n%s do", indentstr);
						sdb_array_push_num (db, "indent", jump, 0);
						sdb_num_set (db, K_INDENT (jump), indent, 0);
						sdb_num_set (db, K_ELSE (jump), 1, 0);
						if (jump <= bb->addr) {
							blocktype = "while";
						} else {
							blocktype = "else";
						}
						rz_cons_printf ("\n%s {", indentstr);
						indent++;
					}
				}
			} else {
				ut64 addr = sdb_array_pop_num (db, "indent", NULL);
				if (addr == UT64_MAX) {
					rz_cons_printf ("\n(break)\n");
					break;
				}
				bb = rz_anal_bb_from_offset (core->anal, addr);
				nindent = sdb_num_get (db, K_INDENT (addr), NULL);
				if (indent > nindent) {
					int i;
					for (i = indent; i != nindent; i--) {
						SET_INDENT (i);
						rz_cons_printf ("\n%s}", indentstr);
					}
				}
				if (nindent != indent) {
					rz_cons_printf ("\n%s} else {\n", indentstr);
				}
				indent = nindent;
			}
		}
		//n_bb --;
	} while (n_bb > 0);
	rz_list_free (visited);
	rz_cons_printf ("\n}\n");
	rz_config_hold_restore (hc);
	rz_config_hold_free (hc);
	sdb_free (db);
	return true;
}
