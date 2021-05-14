// SPDX-FileCopyrightText: 2010-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_analysis.h>
#include <rz_list.h>
#include <rz_util.h>
#include <rz_core.h>

RZ_API bool rz_core_gdiff_function_1_file(RzCore *c, ut64 addr, ut64 addr2) {
	RzList *la, *lb;
	RzAnalysisFunction *fa = rz_analysis_get_function_at(c->analysis, addr);
	RzAnalysisFunction *fb = rz_analysis_get_function_at(c->analysis, addr2);
	if (!fa || !fb) {
		return false;
	}
	RzAnalysisBlock *bb;
	RzListIter *iter;
	rz_list_foreach (fa->bbs, iter, bb) {
		rz_analysis_diff_fingerprint_bb(c->analysis, bb);
	}
	rz_list_foreach (fb->bbs, iter, bb) {
		rz_analysis_diff_fingerprint_bb(c->analysis, bb);
	}
	la = rz_list_new();
	rz_list_append(la, fa);
	lb = rz_list_new();
	rz_list_append(lb, fb);
	rz_analysis_diff_fcn(c->analysis, la, lb);
	rz_list_free(la);
	rz_list_free(lb);
	return true;
}

RZ_API bool rz_core_gdiff_function_2_files(RzCore *c, RzCore *c2, ut64 addr, ut64 addr2) {
	RzList *la, *lb;
	RzAnalysisFunction *fa = rz_analysis_get_function_at(c->analysis, addr);
	RzAnalysisFunction *fb = rz_analysis_get_function_at(c2->analysis, addr2);
	if (!fa || !fb) {
		eprintf("cannot get functions at 0x%" PFMT64x " or at 0x%" PFMT64x "\n", addr, addr2);
		return false;
	}
	RzAnalysisBlock *bb;
	RzListIter *iter;
	rz_list_foreach (fa->bbs, iter, bb) {
		if (rz_analysis_diff_fingerprint_bb(c->analysis, bb) < 0) {
			eprintf("cannot fingerprint 0x%" PFMT64x "\n", addr);
			return false;
		}
	}
	rz_list_foreach (fb->bbs, iter, bb) {
		if (rz_analysis_diff_fingerprint_bb(c2->analysis, bb) < 0) {
			eprintf("cannot fingerprint 0x%" PFMT64x "\n", addr2);
			return false;
		}
	}

	rz_analysis_diff_fingerprint_fcn(c->analysis, fa);
	rz_analysis_diff_fingerprint_fcn(c2->analysis, fb);

	la = rz_list_new();
	rz_list_append(la, fa);
	lb = rz_list_new();
	rz_list_append(lb, fb);
	rz_analysis_diff_fcn(c->analysis, la, lb);
	rz_list_free(la);
	rz_list_free(lb);
	return true;
}

/* Fingerprint functions and blocks, then diff. */
RZ_API bool rz_core_gdiff(RzCore *c, RzCore *c2) {
	RzCore *cores[2] = { c, c2 };
	RzAnalysisFunction *fcn;
	RzAnalysisBlock *bb;
	RzListIter *iter, *iter2;
	int i;

	if (!c || !c2) {
		return false;
	}
	for (i = 0; i < 2; i++) {
		/* remove strings */
		rz_list_foreach_safe (cores[i]->analysis->fcns, iter, iter2, fcn) {
			if (!strncmp(fcn->name, "str.", 4)) {
				rz_analysis_function_delete(fcn);
			}
		}
		/* Fingerprint fcn bbs (functions basic-blocks) */
		rz_list_foreach (cores[i]->analysis->fcns, iter, fcn) {
			rz_list_foreach (fcn->bbs, iter2, bb) {
				rz_analysis_diff_fingerprint_bb(cores[i]->analysis, bb);
			}
		}
		/* Fingerprint fcn */
		rz_list_foreach (cores[i]->analysis->fcns, iter, fcn) {
			rz_analysis_diff_fingerprint_fcn(cores[i]->analysis, fcn);
		}
	}
	/* Diff functions */
	rz_analysis_diff_fcn(cores[0]->analysis, cores[0]->analysis->fcns, cores[1]->analysis->fcns);

	return true;
}

/* copypasta from rz_diff */
static void diffrow(ut64 addr, const char *name, ut32 size, int maxnamelen,
	int digits, ut64 addr2, const char *name2, ut32 size2,
	double dist, bool is_new, bool bare, bool color) {

	const char *type = NULL;
	const char *prefix = NULL;
	const char *suffix = color ? Color_RESET : "";

	if (dist == 1.0) {
		prefix = color ? Color_BGREEN : "";
		type = color ? Color_BGREEN "MATCH  " Color_RESET : "MATCH  ";
	} else if (dist >= 0.5) {
		prefix = color ? Color_BYELLOW : "";
		type = color ? Color_BYELLOW "SIMILAR" Color_RESET : "SIMILAR";
	} else if (is_new) {
		dist = 0.0;
		prefix = color ? Color_BBLUE : "";
		type = color ? Color_BBLUE "NEW    " Color_RESET : "NEW    ";
	} else {
		prefix = color ? Color_BRED : "";
		type = color ? Color_BRED "UNMATCH" Color_RESET : "UNMATCH";
	}

	if (bare) {
		if (addr2 == UT64_MAX || !name2) {
			printf("0x%016" PFMT64x " | %7s (%s%f%s)\n", addr, type, prefix, dist, suffix);
		} else {
			printf("0x%016" PFMT64x " | %7s (%s%f%s) | 0x%016" PFMT64x "\n", addr, type, prefix, dist, suffix, addr2);
		}
	} else {
		if (addr2 == UT64_MAX || !name2) {
			printf("%*s %*d 0x%016" PFMT64x " | %7s (%s%f%s)\n",
				maxnamelen, name, digits, size, addr, type, prefix, dist, suffix);
		} else {
			printf("%*s %*d 0x%016" PFMT64x " | %7s (%s%f%s) | 0x%016" PFMT64x "  %*d %s\n",
				maxnamelen, name, digits, size, addr, type, prefix, dist, suffix, addr2,
				digits, size2, name2);
		}
	}
}

RZ_API void rz_core_diff_show(RzCore *c, RzCore *c2, bool json) {
	bool color = rz_config_get_i(c->config, "scr.color") > 0 || rz_config_get_i(c2->config, "scr.color") > 0;
	bool bare = rz_config_get_b(c->config, "diff.bare") || rz_config_get_b(c2->config, "diff.bare");
	bool is_new = false;
	RzList *fcns = rz_analysis_get_fcns(c->analysis);
	RzListIter *iter;
	RzAnalysisFunction *f;
	int maxnamelen = 0;
	ut64 maxsize = 0;
	int digits = 1;
	int len;
	PJ *pj = NULL;

	if (json) {
		pj = pj_new();
		if (!pj) {
			eprintf("cannot alocate json\n");
			return;
		}
		pj_a(pj);
	}

	rz_list_foreach (fcns, iter, f) {
		if (f->name && (len = strlen(f->name)) > maxnamelen) {
			maxnamelen = len;
		}
		if (rz_analysis_function_linear_size(f) > maxsize) {
			maxsize = rz_analysis_function_linear_size(f);
		}
	}
	fcns = rz_analysis_get_fcns(c2->analysis);
	rz_list_foreach (fcns, iter, f) {
		if (f->name && (len = strlen(f->name)) > maxnamelen) {
			maxnamelen = len;
		}
		if (rz_analysis_function_linear_size(f) > maxsize) {
			maxsize = rz_analysis_function_linear_size(f);
		}
	}
	while (maxsize > 9) {
		maxsize /= 10;
		digits++;
	}

	fcns = rz_analysis_get_fcns(c->analysis);
	if (rz_list_empty(fcns)) {
		eprintf("functions list is empty. analyze the binary first\n");
		return;
	}
	rz_list_sort(fcns, c->analysis->columnSort);

	rz_list_foreach (fcns, iter, f) {
		switch (f->type) {
		case RZ_ANALYSIS_FCN_TYPE_FCN:
		case RZ_ANALYSIS_FCN_TYPE_SYM:
			switch (f->diff->type) {
			case RZ_ANALYSIS_DIFF_TYPE_MATCH:
			case RZ_ANALYSIS_DIFF_TYPE_UNMATCH:
				is_new = false;
				break;
			default:
				is_new = true;
			}
			if (json) {
				double dist = f->diff->dist;
				pj_o(pj);
				pj_kd(pj, "distance", f->diff->dist);
				pj_ks(pj, "type", dist >= 1.0 ? "MATCH" : (dist >= 0.5 ? "SIMILAR" : (is_new ? "NEW" : "UNMATCH")));
				if (f->name) {
					pj_ko(pj, "original");
					pj_ks(pj, "name", f->name);
					pj_kn(pj, "addr", f->addr);
					pj_kn(pj, "size", rz_analysis_function_linear_size(f));
					pj_end(pj);
				}
				if (f->diff->name) {
					pj_ko(pj, "modified");
					pj_ks(pj, "name", f->diff->name);
					pj_kn(pj, "addr", f->diff->addr);
					pj_kn(pj, "size", f->diff->size);
					pj_end(pj);
				}
				pj_end(pj);
			} else {
				diffrow(f->addr, f->name, rz_analysis_function_linear_size(f), maxnamelen, digits,
					f->diff->addr, f->diff->name, f->diff->size,
					f->diff->dist, is_new, bare, color);
			}
			break;
		}
	}
	fcns = rz_analysis_get_fcns(c2->analysis);
	rz_list_sort(fcns, c2->analysis->columnSort);
	rz_list_foreach (fcns, iter, f) {
		switch (f->type) {
		case RZ_ANALYSIS_FCN_TYPE_FCN:
		case RZ_ANALYSIS_FCN_TYPE_SYM:
			if (f->diff->type == RZ_ANALYSIS_DIFF_TYPE_NULL) {
				if (json) {
					pj_o(pj);
					pj_kd(pj, "distance", 0.0);
					pj_ks(pj, "type", "NEW");
					if (f->name) {
						pj_ko(pj, "original");
						pj_ks(pj, "name", f->name);
						pj_kn(pj, "addr", f->addr);
						pj_kn(pj, "size", rz_analysis_function_linear_size(f));
						pj_end(pj);
					}
					if (f->diff->name) {
						pj_ko(pj, "modified");
						pj_ks(pj, "name", f->diff->name);
						pj_kn(pj, "addr", f->diff->addr);
						pj_kn(pj, "size", f->diff->size);
						pj_end(pj);
					}
					pj_end(pj);
				} else {
					diffrow(f->addr, f->name, rz_analysis_function_linear_size(f), maxnamelen,
						digits, f->diff->addr, f->diff->name, f->diff->size,
						0.0, true, bare, color);
				}
			}
			break;
		}
	}

	if (json) {
		pj_end(pj);
		printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
}

static const char *diff_color(RzAnalysisBlock *bbi) {
	if (!bbi->diff) {
		return "white";
	}

	switch (bbi->diff->type) {
	case RZ_ANALYSIS_DIFF_TYPE_MATCH:
		return "lightgray";
	case RZ_ANALYSIS_DIFF_TYPE_UNMATCH:
		return bbi->diff->dist >= 0.5 ? "yellow" : "red";
	default:
		return "turquoise";
	}
}

static char *cons_color_code(const char *k) {
	if (!rz_cons_singleton()) {
		return NULL;
	}
	RzColor rcolor = rz_cons_pal_get(k);
	return rz_cons_rgb_tostring(rcolor.r, rcolor.g, rcolor.b);
}

static void print_color_node(RzCore *core, RzAnalysisBlock *bbi) {
	bool color_current = rz_config_get_i(core->config, "graph.gv.current");
	char *pal_curr = cons_color_code("graph.current");
	bool current = rz_analysis_block_contains(bbi, core->offset);

	if (current && color_current) {
		printf("\t\"0x%08" PFMT64x "\" ", bbi->addr);
		printf("\t[fillcolor=%s style=filled shape=box];\n", pal_curr ? pal_curr : "white");
	}
	free(pal_curr);
}

static int graph_construct_nodes(RzCore *core, RzCore *core2, RzAnalysisFunction *fcn, PJ *pj) {
	char addr_a[32], addr_b[32];

	RzAnalysisBlock *bbi;
	RzListIter *iter;
	int is_json = pj != NULL;
	const char *font = rz_config_get(core->config, "graph.font");
	int nodes = 0;

	snprintf(addr_a, sizeof(addr_a), "0x%08" PFMT64x, fcn->addr);
	snprintf(addr_b, sizeof(addr_b), "0x%08" PFMT64x, fcn->diff->addr);

	const char *norig = fcn->name ? fcn->name : addr_a;
	const char *nmodi = fcn->diff->name ? fcn->diff->name : addr_b;

	rz_list_foreach (fcn->bbs, iter, bbi) {
		if (is_json) {
			RzDebugTracepoint *t = rz_debug_trace_get(core->dbg, bbi->addr);
			ut8 *buf = malloc(bbi->size);
			pj_o(pj);
			pj_kn(pj, "offset", bbi->addr);
			pj_kn(pj, "size", bbi->size);
			if (bbi->jump != UT64_MAX) {
				pj_kn(pj, "jump", bbi->jump);
			}
			if (bbi->fail != -1) {
				pj_kn(pj, "fail", bbi->fail);
			}
			if (bbi->switch_op) {
				RzAnalysisSwitchOp *op = bbi->switch_op;
				pj_k(pj, "switchop");
				pj_o(pj);
				pj_kn(pj, "offset", op->addr);
				pj_kn(pj, "defval", op->def_val);
				pj_kn(pj, "maxval", op->max_val);
				pj_kn(pj, "minval", op->min_val);
				pj_k(pj, "cases");
				pj_a(pj);
				RzAnalysisCaseOp *case_op;
				RzListIter *case_iter;
				rz_list_foreach (op->cases, case_iter, case_op) {
					pj_o(pj);
					pj_kn(pj, "offset", case_op->addr);
					pj_kn(pj, "value", case_op->value);
					pj_kn(pj, "jump", case_op->jump);
					pj_end(pj);
				}
				pj_end(pj);
				pj_end(pj);
			}
			if (t) {
				pj_k(pj, "trace");
				pj_o(pj);
				pj_ki(pj, "count", t->count);
				pj_ki(pj, "times", t->times);
				pj_end(pj);
			}
			pj_kn(pj, "colorize", bbi->colorize);
			pj_k(pj, "ops");
			pj_a(pj);
			if (buf) {
				rz_io_read_at(core->io, bbi->addr, buf, bbi->size);
				rz_core_print_disasm_json(core, bbi->addr, buf, bbi->size, 0, pj);
				free(buf);
			} else {
				eprintf("cannot allocate %" PFMT64u " byte(s)\n", bbi->size);
			}
			pj_end(pj);
			pj_end(pj);
			continue;
		} else {
			const char *fillcolor = diff_color(bbi);
			nodes++;
			RzConfigHold *hc = rz_config_hold_new(core->config);
			rz_config_hold_i(hc, "scr.color", "scr.utf8", "asm.offset", "asm.lines",
				"asm.cmt.right", "asm.lines.fcn", "asm.bytes", "asm.comments", NULL);
			rz_config_set_i(core->config, "scr.utf8", 0);
			rz_config_set_i(core->config, "asm.offset", 0);
			rz_config_set_i(core->config, "asm.lines", 0);
			rz_config_set_i(core->config, "asm.cmt.right", 0);
			rz_config_set_i(core->config, "asm.lines.fcn", 0);
			rz_config_set_i(core->config, "asm.bytes", 0);
			rz_config_set_i(core->config, "asm.comments", 0);
			rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);

			char *original = rz_core_cmd_strf(core, "pdb @ 0x%08" PFMT64x, bbi->addr);

			if (bbi->diff && bbi->diff->type == RZ_ANALYSIS_DIFF_TYPE_UNMATCH) {
				RzConfig *oc = core2->config;
				core2->config = core->config;

				char *modified = rz_core_cmd_strf(core2, "pdb @ 0x%08" PFMT64x, bbi->diff->addr);


				RzDiff *dff = rz_diff_lines_new(original, modified, NULL);
				char *diffstr = rz_diff_unified_text(dff, norig, nmodi, false, false);
				rz_diff_free(dff);

				rz_str_replace_char(diffstr, '"', '\'');
				diffstr = rz_str_replace(diffstr, "\n", "\\l", 1);
				printf("\t\"0x%08" PFMT64x "\" [fillcolor=\"%s\","
				       "color=\"black\", fontname=\"%s\","
				       " label=\"%s\", URL=\"%s/0x%08" PFMT64x "\"]\n",
					bbi->addr, fillcolor, font, diffstr, fcn->name,
					bbi->addr);
				free(diffstr);
				free(modified);
				core2->config = oc;
			} else {
				rz_str_replace_char(original, '"', '\'');
				original = rz_str_replace(original, "\n", "\\l", 1);
				printf("\t\"0x%08" PFMT64x "\" [fillcolor=\"%s\","
				       "color=\"black\", fontname=\"%s\","
				       " label=\"%s\", URL=\"%s/0x%08" PFMT64x "\"]\n",
					bbi->addr, fillcolor, font, original, fcn->name, bbi->addr);
			}
			free(original);
			rz_config_set_i(core->config, "scr.color", 1);
			rz_config_hold_restore(hc);
			rz_config_hold_free(hc);
		}
	}
	return nodes;
}

static int graph_construct_edges(RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bbi;
	RzListIter *iter;
	char *pal_jump = cons_color_code("graph.true");
	char *pal_fail = cons_color_code("graph.false");
	char *pal_trfa = cons_color_code("graph.trufae");
	int nodes = 0;
	rz_list_foreach (fcn->bbs, iter, bbi) {
		if (bbi->jump != UT64_MAX) {
			nodes++;
			printf("\t\"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" [color=\"%s\"];\n",
				bbi->addr, bbi->jump,
				bbi->fail != -1 ? pal_jump : pal_trfa);
			print_color_node(core, bbi);
		}
		if (bbi->fail != -1) {
			nodes++;
			printf("\t\"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" [color=\"%s\"];\n",
				bbi->addr, bbi->fail, pal_fail);
			print_color_node(core, bbi);
		}
		if (bbi->switch_op) {
			RzAnalysisCaseOp *caseop;
			RzListIter *iter;

			if (bbi->fail != UT64_MAX) {
				printf("\t\"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" [color=\"%s\"];\n",
					bbi->addr, bbi->fail, pal_fail);
				print_color_node(core, bbi);
			}
			rz_list_foreach (bbi->switch_op->cases, iter, caseop) {
				nodes++;
				printf("\t\"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" [color2=\"%s\"];\n",
					caseop->addr, caseop->jump, pal_fail);
				print_color_node(core, bbi);
			}
		}
	}
	free(pal_jump);
	free(pal_fail);
	free(pal_trfa);
	return nodes;
}

static int draw_graph_nodes(RzCore *core, RzCore *core2, RzAnalysisFunction *fcn, PJ *pj) {
	rz_return_val_if_fail(fcn && fcn->bbs, -1);
	int nodes = 0;

	if (pj) {
		char *fcn_name_escaped = rz_str_escape_utf8_for_json(fcn->name, -1);
		pj_o(pj);
		pj_ks(pj, "name", rz_str_get_null(fcn_name_escaped));
		free(fcn_name_escaped);
		pj_kn(pj, "offset", fcn->addr);
		pj_ki(pj, "ninstr", fcn->ninstr);
		pj_ki(pj, "nargs",
			rz_analysis_var_count(core->analysis, fcn, 'r', 1) +
				rz_analysis_var_count(core->analysis, fcn, 's', 1) +
				rz_analysis_var_count(core->analysis, fcn, 'b', 1));
		pj_ki(pj, "nlocals",
			rz_analysis_var_count(core->analysis, fcn, 'r', 0) +
				rz_analysis_var_count(core->analysis, fcn, 's', 0) +
				rz_analysis_var_count(core->analysis, fcn, 'b', 0));
		pj_kn(pj, "size", rz_analysis_function_linear_size(fcn));
		pj_ki(pj, "stack", fcn->maxstack);
		pj_ks(pj, "type", rz_analysis_fcntype_tostring(fcn->type));
		pj_k(pj, "blocks");
		pj_a(pj);
	}
	nodes += graph_construct_nodes(core, core2, fcn, pj);
	if (!pj) {
		nodes += graph_construct_edges(core, fcn);
	}
	if (pj) {
		pj_end(pj);
		pj_end(pj);
	}
	return nodes;
}

RZ_API bool rz_core_diff_show_function(RzCore *core, RzCore *core2, ut64 addr1, int opts) {
	const char *font = rz_config_get(core->config, "graph.font");
	int is_json = opts & RZ_CORE_ANALYSIS_JSON;

	int nodes = 0;
	PJ *pj = NULL;
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, addr1);
	if (!fcn) {
		eprintf("cannot get functions at 0x%" PFMT64x "\n", addr1);
		return false;
	}

	if (!is_json) {
		const char *gv_edge = rz_config_get(core->config, "graph.gv.edge");
		const char *gv_node = rz_config_get(core->config, "graph.gv.node");
		const char *gv_spline = rz_config_get(core->config, "graph.gv.spline");
		if (!gv_edge || !*gv_edge) {
			gv_edge = "arrowhead=\"normal\"";
		}
		if (!gv_node || !*gv_node) {
			gv_node = "fillcolor=gray style=filled shape=box";
		}
		if (!gv_spline || !*gv_spline) {
			gv_spline = "splines=\"ortho\"";
		}
		printf("digraph code {\n"
		       "\tgraph [bgcolor=azure fontsize=8 fontname=\"%s\" %s];\n"
		       "\tnode [%s];\n"
		       "\tedge [%s];\n",
			font, gv_spline, gv_node, gv_edge);
	} else {
		pj = pj_new();
		if (!pj) {
			return false;
		}
		pj_a(pj);
	}
	nodes += draw_graph_nodes(core, core2, fcn, pj);
	if (nodes < 1 && !is_json) {
		printf("\t\"0x%08" PFMT64x "\";\n", addr1);
	}
	if (is_json) {
		pj_end(pj);
		printf("%s\n", pj_string(pj));
		pj_free(pj);
	} else {
		printf("}\n");
	}
	return true;
}