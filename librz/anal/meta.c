/* radare - LGPL - Copyright 2008-2020 - nibble, pancake, thestr4ng3r */

#include <rz_anal.h>
#include <rz_core.h>

static bool item_matches_filter(RzAnalMetaItem *item, RzAnalMetaType type, R_NULLABLE const RSpace *space) {
	return (type == R_META_TYPE_ANY || item->type == type)
		   && (!space || item->space == space);
}

typedef struct {
	RzAnalMetaType type;
	const RSpace *space;

	RIntervalNode *node;
} FindCtx;

static bool find_node_cb(RIntervalNode *node, void *user) {
	FindCtx *ctx = user;
	if (item_matches_filter (node->data, ctx->type, ctx->space)) {
		ctx->node = node;
		return false;
	}
	return true;
}

static RIntervalNode *find_node_at(RzAnal *anal, RzAnalMetaType type, R_NULLABLE const RSpace *space, ut64 addr) {
	FindCtx ctx = {
		.type = type,
		.space = space,
		.node = NULL
	};
	rz_interval_tree_all_at (&anal->meta, addr, find_node_cb, &ctx);
	return ctx.node;
}

static RIntervalNode *find_node_in(RzAnal *anal, RzAnalMetaType type, R_NULLABLE const RSpace *space, ut64 addr) {
	FindCtx ctx = {
		.type = type,
		.space = space,
		.node = NULL
	};
	rz_interval_tree_all_in (&anal->meta, addr, true, find_node_cb, &ctx);
	return ctx.node;
}

typedef struct {
	RzAnalMetaType type;
	const RSpace *space;

	RPVector/*RIntervalNode*/ *result;
} CollectCtx;

static bool collect_nodes_cb(RIntervalNode *node, void *user) {
	CollectCtx *ctx = user;
	if (item_matches_filter (node->data, ctx->type, ctx->space)) {
		rz_pvector_push (ctx->result, node);
	}
	return true;
}

static RPVector *collect_nodes_at(RzAnal *anal, RzAnalMetaType type, R_NULLABLE const RSpace *space, ut64 addr) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = rz_pvector_new (NULL)
	};
	if (!ctx.result) {
		return NULL;
	}
	rz_interval_tree_all_at (&anal->meta, addr, collect_nodes_cb, &ctx);
	return ctx.result;
}

static RPVector *collect_nodes_in(RzAnal *anal, RzAnalMetaType type, R_NULLABLE const RSpace *space, ut64 addr) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = rz_pvector_new (NULL)
	};
	if (!ctx.result) {
		return NULL;
	}
	rz_interval_tree_all_in (&anal->meta, addr, true, collect_nodes_cb, &ctx);
	return ctx.result;
}

static RPVector *collect_nodes_intersect(RzAnal *anal, RzAnalMetaType type, R_NULLABLE const RSpace *space, ut64 start, ut64 end) {
	CollectCtx ctx = {
		.type = type,
		.space = space,
		.result = rz_pvector_new (NULL)
	};
	if (!ctx.result) {
		return NULL;
	}
	rz_interval_tree_all_intersect (&anal->meta, start, end, true, collect_nodes_cb, &ctx);
	return ctx.result;
}

static bool meta_set(RzAnal *a, RzAnalMetaType type, int subtype, ut64 from, ut64 to, const char *str) {
	if (to < from) {
		return false;
	}
	RSpace *space = rz_spaces_current (&a->meta_spaces);
	RIntervalNode *node = find_node_at (a, type, space, from);
	RzAnalMetaItem *item = node ? node->data : R_NEW0 (RzAnalMetaItem);
	if (!item) {
		return false;
	}
	item->type = type;
	item->subtype = subtype;
	item->space = space;
	free (item->str);
	item->str = str ? strdup (str) : NULL;
	if (str && !item->str) {
		if (!node) { // If we just created this
			free (item);
		}
		return false;
	}
	if (!node) {
		rz_interval_tree_insert (&a->meta, from, to, item);
	} else if (node->end != to) {
		rz_interval_tree_resize (&a->meta, node, from, to);
	}
	return true;
}

RZ_API bool rz_meta_set_string(RzAnal *a, RzAnalMetaType type, ut64 addr, const char *s) {
	return meta_set (a, type, 0, addr, addr, s);
}

RZ_API const char *rz_meta_get_string(RzAnal *a, RzAnalMetaType type, ut64 addr) {
	RIntervalNode *node = find_node_at (a, type, rz_spaces_current (&a->meta_spaces), addr);
	if (!node) {
		return NULL;
	}
	RzAnalMetaItem *item = node->data;
	return item->str;
}


static void del(RzAnal *a, RzAnalMetaType type, const RSpace *space, ut64 addr, ut64 size) {
	RPVector *victims = NULL;
	if (size == UT64_MAX) {
		// delete everything
		victims = rz_pvector_new (NULL);
		if (!victims) {
			return;
		}
		RIntervalTreeIter it;
		RzAnalMetaItem *item;
		rz_interval_tree_foreach (&a->meta, it, item) {
			if (item_matches_filter (item, type, space)) {
				rz_pvector_push (victims, rz_interval_tree_iter_get (&it));
			}
		}
	} else {
		ut64 end = size ? addr + size - 1 : addr;
		if (end < addr) {
			end = UT64_MAX;
		}
		victims = collect_nodes_intersect (a, type, space, addr, end);
		if (!victims) {
			return;
		}
	}
	void **it;
	rz_pvector_foreach (victims, it) {
		rz_interval_tree_delete (&a->meta, *it, true);
	}
	rz_pvector_free (victims);
}

RZ_API void rz_meta_del(RzAnal *a, RzAnalMetaType type, ut64 addr, ut64 size) {
	del (a, type, rz_spaces_current (&a->meta_spaces), addr, size);
}

RZ_API bool rz_meta_set(RzAnal *a, RzAnalMetaType type, ut64 addr, ut64 size, const char *str) {
	return rz_meta_set_with_subtype (a, type, 0, addr, size, str);
}

RZ_API bool rz_meta_set_with_subtype(RzAnal *m, RzAnalMetaType type, int subtype, ut64 addr, ut64 size, const char *str) {
	rz_return_val_if_fail (m && size, false);
	ut64 end = addr + size - 1;
	if (end < addr) {
		end = UT64_MAX;
	}
	return meta_set (m, type, subtype, addr, end, str);
}

RZ_API RzAnalMetaItem *rz_meta_get_at(RzAnal *a, ut64 addr, RzAnalMetaType type, R_OUT R_NULLABLE ut64 *size) {
	RIntervalNode *node = find_node_at (a, type, rz_spaces_current (&a->meta_spaces), addr);
	if (node && size) {
		*size = rz_meta_item_size (node->start, node->end);
	}
	return node ? node->data : NULL;
}

RZ_API RIntervalNode *rz_meta_get_in(RzAnal *a, ut64 addr, RzAnalMetaType type) {
	return find_node_in (a, type, rz_spaces_current (&a->meta_spaces), addr);
}

RZ_API RPVector/*<RIntervalNode<RMetaItem> *>*/ *rz_meta_get_all_at(RzAnal *a, ut64 at) {
	return collect_nodes_at (a, R_META_TYPE_ANY, rz_spaces_current (&a->meta_spaces), at);
}

RZ_API RPVector *rz_meta_get_all_in(RzAnal *a, ut64 at, RzAnalMetaType type) {
	return collect_nodes_in (a, type, rz_spaces_current (&a->meta_spaces), at);
}

RZ_API RPVector *rz_meta_get_all_intersect(RzAnal *a, ut64 start, ut64 size, RzAnalMetaType type) {
	rz_return_val_if_fail (size, NULL);
	ut64 end = start + size - 1;
	if (end < start) {
		end = UT64_MAX;
	}
	return collect_nodes_intersect (a, type, rz_spaces_current (&a->meta_spaces), start, end);
}

RZ_API const char *rz_meta_type_to_string(int type) {
	// XXX: use type as '%c'
	switch (type) {
	case R_META_TYPE_DATA: return "Cd";
	case R_META_TYPE_CODE: return "Cc";
	case R_META_TYPE_STRING: return "Cs";
	case R_META_TYPE_FORMAT: return "Cf";
	case R_META_TYPE_MAGIC: return "Cm";
	case R_META_TYPE_HIDE: return "Ch";
	case R_META_TYPE_COMMENT: return "CCu";
	case R_META_TYPE_RUN: return "Cr"; // not in C? help
	case R_META_TYPE_HIGHLIGHT: return "ecHi"; // not in C?
	case R_META_TYPE_VARTYPE: return "Ct";
	}
	return "# unknown meta # ";
}

RZ_API void rz_meta_print(RzAnal *a, RzAnalMetaItem *d, ut64 start, ut64 size, int rad, PJ *pj, bool show_full) {
	rz_return_if_fail (!(rad == 'j' && !pj)); // rad == 'j' => pj != NULL
	char *pstr, *base64_str;
	RzCore *core = a->coreb.core;
	bool esc_bslash = core ? core->print->esc_bslash : false;
	if (rz_spaces_current (&a->meta_spaces) &&
	    rz_spaces_current (&a->meta_spaces) != d->space) {
		return;
	}
	char *str = NULL;
	if (d->str) {
		if (d->type == R_META_TYPE_STRING) {
			if (d->subtype == R_STRING_ENC_UTF8) {
				str = rz_str_escape_utf8 (d->str, false, esc_bslash);
			} else {
				if (!d->subtype) {  /* temporary legacy workaround */
					esc_bslash = false;
				}
				str = rz_str_escape_latin1 (d->str, false, esc_bslash, false);
			}
		} else {
			str = rz_str_escape (d->str);
		}
	}
	if (str || d->type == R_META_TYPE_DATA) {
		if (d->type == R_META_TYPE_STRING && !*str) {
			free (str);
			return;
		}
		if (!str) {
			pstr = "";
		} else if (d->type == 'f') {
			pstr = str;
		} else if (d->type == 's') {
			pstr = str;
		} else if (d->type == 't') {
			// Sanitize (don't escape) Ct comments so we can see "char *", etc.
			free (str);
			str = strdup (d->str);
			rz_str_sanitize (str);
			pstr = str;
		} else if (d->type != 'C') {
			rz_name_filter (str, 0);
			pstr = str;
		} else {
			pstr = d->str;
		}
//		rz_str_sanitize (str);
		switch (rad) {
		case 'j':
			pj_o (pj);
			pj_kn (pj, "offset", start);
			pj_ks (pj, "type", rz_meta_type_to_string (d->type));

			if (d->type == 'H') {
				pj_k (pj, "color");
				ut8 r = 0, g = 0, b = 0, A = 0;
				const char *esc = strchr (d->str, '\x1b');
				if (esc) {
					rz_cons_rgb_parse (esc, &r, &g, &b, &A);
					char *rgb_str = rz_cons_rgb_tostring (r, g, b);
					base64_str = rz_base64_encode_dyn (rgb_str, -1);
					if (d->type == 's' && base64_str) {
						pj_s (pj, base64_str);
						free (base64_str);
					} else {
						pj_s (pj, rgb_str);
					}
					free (rgb_str);
				} else {
					pj_s (pj, str);
				}
			} else {
				pj_k (pj, "name");
				if (d->type == 's' && (base64_str = rz_base64_encode_dyn (d->str, -1))) {
					pj_s (pj, base64_str);
				} else {
					pj_s (pj, str);
				}
			}
			if (d->type == 'd') {
				pj_kn (pj, "size", size);
			} else if (d->type == 's') {
				const char *enc;
				switch (d->subtype) {
				case R_STRING_ENC_UTF8:
					enc = "utf8";
					break;
				case 0:  /* temporary legacy encoding */
					enc = "iz";
					break;
				default:
					enc = "latin1";
				}
				pj_ks (pj, "enc", enc);
				pj_kb (pj, "ascii", rz_str_is_ascii (d->str));
			}

			pj_end (pj);
			break;
		case 0:
		case 1:
		case '*':
		default:
			switch (d->type) {
			case R_META_TYPE_COMMENT:
				{
				const char *type = rz_meta_type_to_string (d->type);
				char *s = sdb_encode ((const ut8*)pstr, -1);
				if (!s) {
					s = strdup (pstr);
				}
				if (rad) {
					if (!strcmp (type, "CCu")) {
						a->cb_printf ("%s base64:%s @ 0x%08"PFMT64x"\n",
							type, s, start);
					} else {
						a->cb_printf ("%s %s @ 0x%08"PFMT64x"\n",
							type, pstr, start);
					}
				} else {
					if (!strcmp (type, "CCu")) {
						char *mys = rz_str_escape (pstr);
						a->cb_printf ("0x%08"PFMT64x" %s \"%s\"\n",
								start, type, mys);
						free (mys);
					} else {
						a->cb_printf ("0x%08"PFMT64x" %s \"%s\"\n",
								start, type, pstr);
					}
				}
				free (s);
				}
				break;
			case R_META_TYPE_STRING:
				if (rad) {
					char cmd[] = "Cs#";
					switch (d->subtype) {
					case 'a':
					case '8':
						cmd[2] = d->subtype;
						break;
					default:
						cmd[2] = 0;
					}
					a->cb_printf ("%s %"PFMT64u" @ 0x%08"PFMT64x" # %s\n",
							cmd, size, start, pstr);
				} else {
					const char *enc;
					switch (d->subtype) {
					case '8':
						enc = "utf8";
						break;
					default:
						enc = rz_str_is_ascii (d->str) ? "ascii" : "latin1";
					}
					if (show_full) {
						a->cb_printf ("0x%08"PFMT64x" %s[%"PFMT64u"] \"%s\"\n",
						              start, enc, size, pstr);
					} else {
						a->cb_printf ("%s[%"PFMT64u"] \"%s\"\n",
						              enc, size, pstr);
					}
				}
				break;
			case R_META_TYPE_HIDE:
			case R_META_TYPE_DATA:
				if (rad) {
					a->cb_printf ("%s %"PFMT64u" @ 0x%08"PFMT64x"\n",
							rz_meta_type_to_string (d->type),
							size, start);
				} else {
					if (show_full) {
						const char *dtype = d->type == 'h' ? "hidden" : "data";
						a->cb_printf ("0x%08" PFMT64x " %s %s %"PFMT64u"\n",
						              start, dtype,
						              rz_meta_type_to_string (d->type), size);
					} else {
						a->cb_printf ("%"PFMT64u"\n", size);
					}
				}
				break;
			case R_META_TYPE_MAGIC:
			case R_META_TYPE_FORMAT:
				if (rad) {
					a->cb_printf ("%s %"PFMT64u" %s @ 0x%08"PFMT64x"\n",
							rz_meta_type_to_string (d->type),
							size, pstr, start);
				} else {
					if (show_full) {
						const char *dtype = d->type == 'm' ? "magic" : "format";
						a->cb_printf ("0x%08" PFMT64x " %s %"PFMT64u" %s\n",
						              start, dtype, size, pstr);
					} else {
						a->cb_printf ("%"PFMT64u" %s\n", size, pstr);
					}
				}
				break;
			case R_META_TYPE_VARTYPE:
				if (rad) {
					a->cb_printf ("%s %s @ 0x%08"PFMT64x"\n",
						rz_meta_type_to_string (d->type), pstr, start);
				} else {
					a->cb_printf ("0x%08"PFMT64x" %s\n", start, pstr);
				}
				break;
			case R_META_TYPE_HIGHLIGHT:
				{
					ut8 r = 0, g = 0, b = 0, A = 0;
					const char *esc = strchr (d->str, '\x1b');
					rz_cons_rgb_parse (esc, &r, &g, &b, &A);
					a->cb_printf ("%s rgb:%02x%02x%02x @ 0x%08"PFMT64x"\n",
						rz_meta_type_to_string (d->type), r, g, b, start);
					// TODO: d->size
				}
				break;
			default:
				if (rad) {
					a->cb_printf ("%s %"PFMT64u" 0x%08"PFMT64x" # %s\n",
						rz_meta_type_to_string (d->type),
						size, start, pstr);
				} else {
					// TODO: use b64 here
					a->cb_printf ("0x%08"PFMT64x" array[%"PFMT64u"] %s %s\n",
						start, size,
						rz_meta_type_to_string (d->type), pstr);
				}
				break;
			}
			break;
		}
		if (str) {
			free (str);
		}
	}
}

RZ_API void rz_meta_print_list_at(RzAnal *a, ut64 addr, int rad) {
	RPVector *nodes = collect_nodes_at (a, R_META_TYPE_ANY, rz_spaces_current (&a->meta_spaces), addr);
	if (!nodes) {
		return;
	}
	void **it;
	rz_pvector_foreach (nodes, it) {
		RIntervalNode *node = *it;
		rz_meta_print (a, node->data, node->start, rz_meta_node_size (node), rad, NULL, true);
	}
	rz_pvector_free (nodes);
}

static void print_meta_list(RzAnal *a, int type, int rad, ut64 addr) {
	PJ *pj = NULL;
	if (rad == 'j') {
		pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_a (pj);
	}

	RzAnalFunction *fcn = NULL;
	if (addr != UT64_MAX) {
		fcn = rz_anal_get_fcn_in (a, addr, 0);
		if (!fcn) {
			goto beach;
		}
	}

	RIntervalTreeIter it;
	RzAnalMetaItem *item;
	rz_interval_tree_foreach (&a->meta, it, item) {
		RIntervalNode *node = rz_interval_tree_iter_get (&it);
		if (type != R_META_TYPE_ANY && item->type != type) {
			continue;
		}
		if (fcn && !rz_anal_function_contains (fcn, node->start)) {
			continue;
		}
		rz_meta_print (a, item, node->start, rz_meta_node_size (node), rad, pj, true);
	}

beach:
	if (pj) {
		pj_end (pj);
		rz_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

RZ_API void rz_meta_print_list_all(RzAnal *a, int type, int rad) {
	print_meta_list (a, type, rad, UT64_MAX);
}

RZ_API void rz_meta_print_list_in_function(RzAnal *a, int type, int rad, ut64 addr) {
	print_meta_list (a, type, rad, addr);
}

RZ_API void rz_meta_rebase(RzAnal *anal, ut64 diff) {
	if (!diff) {
		return;
	}
	RIntervalTree old = anal->meta;
	rz_interval_tree_init (&anal->meta, old.free);
	RIntervalTreeIter it;
	RzAnalMetaItem *item;
	rz_interval_tree_foreach (&old, it, item) {
		RIntervalNode *node = rz_interval_tree_iter_get (&it);
		ut64 newstart = node->start + diff;
		ut64 newend = node->end + diff;
		if (newend < newstart) {
			// Can't rebase this
			newstart = node->start;
			newend = node->end;
		}
		rz_interval_tree_insert (&anal->meta, newstart, newend, item);
	}
	old.free = NULL;
	rz_interval_tree_fini (&old);
}

RZ_API void rz_meta_space_unset_for(RzAnal *a, const RSpace *space) {
	del (a, R_META_TYPE_ANY, space, 0, UT64_MAX);
}

RZ_API ut64 rz_meta_get_size(RzAnal *a, RzAnalMetaType type) {
	ut64 sum = 0;
	RIntervalTreeIter it;
	RzAnalMetaItem *item;
	RIntervalNode *prev = NULL;
	rz_interval_tree_foreach (&a->meta, it, item) {
		RIntervalNode *node = rz_interval_tree_iter_get (&it);
		if (type != R_META_TYPE_ANY && item->type != type) {
			continue;
		}
		ut64 start = R_MAX (prev ? prev->end : 0, node->start);
		sum += node->end - start + 1;
		prev = node;
	}
	return sum;
}

RZ_API int rz_meta_space_count_for(RzAnal *a, const RSpace *space) {
	int r = 0;
	RIntervalTreeIter it;
	RzAnalMetaItem *item;
	rz_interval_tree_foreach (&a->meta, it, item) {
		if (item->space == space) {
			r++;
		}
	}
	return r;
}

RZ_API void rz_meta_set_data_at(RzAnal *a, ut64 addr, ut64 wordsz) {
	rz_return_if_fail (wordsz);
	rz_meta_set (a, R_META_TYPE_DATA, addr, wordsz, NULL);
}
