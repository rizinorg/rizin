// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_anal.h>
#include <rz_cons.h>

#if 0
DICT
====

refs
  10 -> 20 C
  16 -> 10 J
  20 -> 10 C

xrefs
  20 -> [ 10 C ]
  10 -> [ 16 J, 20 C ]

10: call 20
16: jmp 10
20: call 10
#endif

// XXX: is it possible to have multiple type for the same (from, to) pair?
//      if it is, things need to be adjusted

static RzAnalRef *rz_anal_ref_new(ut64 addr, ut64 at, ut64 type) {
	RzAnalRef *ref = RZ_NEW (RzAnalRef);
	if (ref) {
		ref->addr = addr;
		ref->at = at;
		ref->type = (type == -1)? RZ_ANAL_REF_TYPE_CODE: type;
	}
	return ref;
}

static void rz_anal_ref_free(void *ref) {
	free (ref);
}

RZ_API RzList *rz_anal_ref_list_new(void) {
	return rz_list_newf (rz_anal_ref_free);
}

static void xrefs_ht_free(HtUPKv *kv) {
	ht_up_free (kv->value);
}

static void xrefs_ref_free(HtUPKv *kv) {
	rz_anal_ref_free (kv->value);
}

static bool appendRef(void *u, const ut64 k, const void *v) {
	RzList *list = (RzList *)u;
	RzAnalRef *ref = (RzAnalRef *)v;
	RzAnalRef *cloned = rz_anal_ref_new (ref->addr, ref->at, ref->type);
	if (cloned) {
		rz_list_append (list, cloned);
		return true;
	}
	return false;
}

static bool mylistrefs_cb(void *list, const ut64 k, const void *v) {
	HtUP *ht = (HtUP *)v;
	ht_up_foreach (ht, appendRef, list);
	return true;
}

static int ref_cmp(const RzAnalRef *a, const RzAnalRef *b) {
	if (a->at < b->at) {
		return -1;
	}
	if (a->at > b->at) {
		return 1;
	}
	if (a->addr < b->addr) {
		return -1;
	}
	if (a->addr > b->addr) {
		return 1;
	}
	return 0;
}

static void sortxrefs(RzList *list) {
	rz_list_sort (list, (RzListComparator)ref_cmp);
}

static void listxrefs(HtUP *m, ut64 addr, RzList *list) {
	if (addr == UT64_MAX) {
		ht_up_foreach (m, mylistrefs_cb, list);
	} else {
		bool found;
		HtUP *d = ht_up_find (m, addr, &found);
		if (!found) {
			return;
		}

		ht_up_foreach (d, appendRef, list);
	}
}

static void setxref(HtUP *m, ut64 from, ut64 to, int type) {
	bool found;
	HtUP *ht = ht_up_find (m, from, &found);
	if (!found) {
		ht = ht_up_new (NULL, xrefs_ref_free, NULL);
		if (!ht) {
			return;
		}
		ht_up_insert (m, from, ht);
	}
	RzAnalRef *ref = rz_anal_ref_new (to, from, type);
	if (ref) {
		ht_up_update (ht, to, ref);
	}
}

// set a reference from FROM to TO and a cross-reference(xref) from TO to FROM.
RZ_API int rz_anal_xrefs_set(RzAnal *anal, ut64 from, ut64 to, const RzAnalRefType type) {
	if (!anal || from == to) {
		return false;
	}
	if (anal->iob.is_valid_offset) {
		if (!anal->iob.is_valid_offset (anal->iob.io, from, 0)) {
			return false;
		}
		if (!anal->iob.is_valid_offset (anal->iob.io, to, 0)) {
			return false;
		}
	}
	setxref (anal->dict_xrefs, to, from, type);
	setxref (anal->dict_refs, from, to, type);
	return true;
}

RZ_API int rz_anal_xrefs_deln(RzAnal *anal, ut64 from, ut64 to, const RzAnalRefType type) {
	if (!anal) {
		return false;
	}
	ht_up_delete (anal->dict_refs, from);
	ht_up_delete (anal->dict_xrefs, to);
	return true;
}

RZ_API int rz_anal_xref_del(RzAnal *anal, ut64 from, ut64 to) {
	bool res = false;
	res |= rz_anal_xrefs_deln (anal, from, to, RZ_ANAL_REF_TYPE_NULL);
	res |= rz_anal_xrefs_deln (anal, from, to, RZ_ANAL_REF_TYPE_CODE);
	res |= rz_anal_xrefs_deln (anal, from, to, RZ_ANAL_REF_TYPE_CALL);
	res |= rz_anal_xrefs_deln (anal, from, to, RZ_ANAL_REF_TYPE_DATA);
	res |= rz_anal_xrefs_deln (anal, from, to, RZ_ANAL_REF_TYPE_STRING);
	return res;
}

RZ_API int rz_anal_xrefs_from(RzAnal *anal, RzList *list, const char *kind, const RzAnalRefType type, ut64 addr) {
	listxrefs (anal->dict_refs, addr, list);
	sortxrefs (list);
	return true;
}

RZ_API RzList *rz_anal_xrefs_get(RzAnal *anal, ut64 to) {
	RzList *list = rz_anal_ref_list_new ();
	if (!list) {
		return NULL;
	}
	listxrefs (anal->dict_xrefs, to, list);
	sortxrefs (list);
	if (rz_list_empty (list)) {
		rz_list_free (list);
		list = NULL;
	}
	return list;
}

RZ_API RzList *rz_anal_refs_get(RzAnal *anal, ut64 from) {
	RzList *list = rz_anal_ref_list_new ();
	if (!list) {
		return NULL;
	}
	listxrefs (anal->dict_refs, from, list);
	sortxrefs (list);
	if (rz_list_empty (list)) {
		rz_list_free (list);
		list = NULL;
	}
	return list;
}

RZ_API RzList *rz_anal_xrefs_get_from(RzAnal *anal, ut64 to) {
	RzList *list = rz_anal_ref_list_new ();
	if (!list) {
		return NULL;
	}
	listxrefs (anal->dict_refs, to, list);
	sortxrefs (list);
	if (rz_list_empty (list)) {
		rz_list_free (list);
		list = NULL;
	}
	return list;
}

RZ_API void rz_anal_xrefs_list(RzAnal *anal, int rad) {
	RzListIter *iter;
	RzAnalRef *ref;
	PJ *pj = NULL;
	RzList *list = rz_anal_ref_list_new();
	listxrefs (anal->dict_refs, UT64_MAX, list);
	sortxrefs (list);
	if (rad == 'j') {
		pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_a (pj);
	}
	rz_list_foreach (list, iter, ref) {
		int t = ref->type ? ref->type: ' ';
		switch (rad) {
		case '*':
			anal->cb_printf ("ax%c 0x%"PFMT64x" 0x%"PFMT64x"\n", t, ref->addr, ref->at);
			break;
		case '\0':
			{
				char *name = anal->coreb.getNameDelta (anal->coreb.core, ref->at);
				if (name) {
					rz_str_replace_ch (name, ' ', 0, true);
					anal->cb_printf ("%40s", name);
					free (name);
				} else {
					anal->cb_printf ("%40s", "?");
				}
				anal->cb_printf (" 0x%"PFMT64x" -> %9s -> 0x%"PFMT64x, ref->at, rz_anal_xrefs_type_tostring (t), ref->addr);
				name = anal->coreb.getNameDelta (anal->coreb.core, ref->addr);
				if (name) {
					rz_str_replace_ch (name, ' ', 0, true);
					anal->cb_printf (" %s\n", name);
					free (name);
				} else {
					anal->cb_printf ("\n");
				}
			}
			break;
		case 'q':
			anal->cb_printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x"  %s\n", ref->at, ref->addr, rz_anal_xrefs_type_tostring (t));
			break;
		case 'j':
			{
				pj_o (pj);
				char *name = anal->coreb.getNameDelta (anal->coreb.core, ref->at);
				if (name) {
					rz_str_replace_ch (name, ' ', 0, true);
					pj_ks (pj, "name", name);
					free (name);
				}
				pj_kn (pj, "from", ref->at);
				pj_ks (pj, "type", rz_anal_xrefs_type_tostring (t));
				pj_kn (pj, "addr", ref->addr);
				name = anal->coreb.getNameDelta (anal->coreb.core, ref->addr);
				if (name) {
					rz_str_replace_ch (name, ' ', 0, true);
					pj_ks (pj, "refname", name);
					free (name);
				}
				pj_end (pj);
			}
			break;
		default:
			break;
		}
	}
	if (rad == 'j') {
		pj_end (pj);
		anal->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
	rz_list_free (list);
}

RZ_API const char *rz_anal_xrefs_type_tostring(RzAnalRefType type) {
	switch (type) {
	case RZ_ANAL_REF_TYPE_CODE:
		return "CODE";
	case RZ_ANAL_REF_TYPE_CALL:
		return "CALL";
	case RZ_ANAL_REF_TYPE_DATA:
		return "DATA";
	case RZ_ANAL_REF_TYPE_STRING:
		return "STRING";
	case RZ_ANAL_REF_TYPE_NULL:
	default:
		return "UNKNOWN";
	}
}

RZ_API RzAnalRefType rz_anal_xrefs_type(char ch) {
	switch (ch) {
	case RZ_ANAL_REF_TYPE_CODE:
	case RZ_ANAL_REF_TYPE_CALL:
	case RZ_ANAL_REF_TYPE_DATA:
	case RZ_ANAL_REF_TYPE_STRING:
	case RZ_ANAL_REF_TYPE_NULL:
		return (RzAnalRefType)ch;
	default:
		return RZ_ANAL_REF_TYPE_NULL;
	}
}

RZ_API bool rz_anal_xrefs_init(RzAnal *anal) {
	ht_up_free (anal->dict_refs);
	anal->dict_refs = NULL;
	ht_up_free (anal->dict_xrefs);
	anal->dict_xrefs = NULL;

	HtUP *tmp = ht_up_new (NULL, xrefs_ht_free, NULL);
	if (!tmp) {
		return false;
	}
	anal->dict_refs = tmp;

	tmp = ht_up_new (NULL, xrefs_ht_free, NULL);
	if (!tmp) {
		ht_up_free (anal->dict_refs);
		anal->dict_refs = NULL;
		return false;
	}
	anal->dict_xrefs = tmp;
	return true;
}

static bool count_cb(void *user, const ut64 k, const void *v) {
	(*(ut64 *)user) += ((HtUP *)v)->count;
	return true;
}

RZ_API ut64 rz_anal_xrefs_count(RzAnal *anal) {
	ut64 ret = 0;
	ht_up_foreach (anal->dict_xrefs, count_cb, &ret);
	return ret;
}

static RzList *fcn_get_refs(RzAnalFunction *fcn, HtUP *ht) {
	RzListIter *iter;
	RzAnalBlock *bb;
	RzList *list = rz_anal_ref_list_new ();
	if (!list) {
		return NULL;
	}
	rz_list_foreach (fcn->bbs, iter, bb) {
		int i;

		for (i = 0; i < bb->ninstr; i++) {
			ut64 at = bb->addr + rz_anal_bb_offset_inst (bb, i);
			listxrefs (ht, at, list);
		}
	}
	sortxrefs (list);
	return list;
}

RZ_API RzList *rz_anal_function_get_refs(RzAnalFunction *fcn) {
	rz_return_val_if_fail (fcn, NULL);
	return fcn_get_refs (fcn, fcn->anal->dict_refs);
}

RZ_API RzList *rz_anal_function_get_xrefs(RzAnalFunction *fcn) {
	rz_return_val_if_fail (fcn, NULL);
	return fcn_get_refs (fcn, fcn->anal->dict_xrefs);
}

RZ_API const char *rz_anal_ref_type_tostring(RzAnalRefType t) {
	switch (t) {
	case RZ_ANAL_REF_TYPE_NULL:
		return "null";
	case RZ_ANAL_REF_TYPE_CODE:
		return "code";
	case RZ_ANAL_REF_TYPE_CALL:
		return "call";
	case RZ_ANAL_REF_TYPE_DATA:
		return "data";
	case RZ_ANAL_REF_TYPE_STRING:
		return "string";
	}
	return "unknown";
}
