// SPDX-FileCopyrightText: 2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_core.h>

static bool matchBytes(RzSignItem *a, RzSignItem *b) {
	if (a->bytes && b->bytes) {
		if (a->bytes->size == b->bytes->size) {
			return !memcmp(a->bytes->bytes, b->bytes->bytes, b->bytes->size);
		}
	}
	return false;
}

static bool matchGraph(RzSignItem *a, RzSignItem *b) {
	if (a->graph && b->graph) {
		if (a->graph->cc != b->graph->cc) {
			return false;
		}
		if (a->graph->nbbs != b->graph->nbbs) {
			return false;
		}
		if (a->graph->ebbs != b->graph->ebbs) {
			return false;
		}
		if (a->graph->edges != b->graph->edges) {
			return false;
		}
		if (a->graph->bbsum != b->graph->bbsum) {
			return false;
		}
		return true;
	}
	return false;
}

RZ_API int rz_core_zdiff(RzCore *c, RzCore *c2) {
	if (!c || !c2) {
		return false;
	}
	////////// moove this into analysis/sign
	SdbList *a = sdb_foreach_list(c->analysis->sdb_zigns, false);
	SdbList *b = sdb_foreach_list(c2->analysis->sdb_zigns, false);

	eprintf("Diff %d %d\n", (int)ls_length(a), (int)ls_length(b));
	SdbListIter *iter;
	SdbKv *kv;
	RzList *la = rz_list_new();
	ls_foreach (a, iter, kv) {
		RzSignItem *it = rz_sign_item_new();
		if (rz_sign_deserialize(c->analysis, it, kv->base.key, kv->base.value)) {
			rz_list_append(la, it);
		} else {
			rz_sign_item_free(it);
		}
	}
	RzList *lb = rz_list_new();
	ls_foreach (b, iter, kv) {
		RzSignItem *it = rz_sign_item_new();
		if (rz_sign_deserialize(c2->analysis, it, kv->base.key, kv->base.value)) {
			rz_list_append(lb, it);
		} else {
			rz_sign_item_free(it);
		}
	}
	//////////
	RzListIter *itr;
	RzListIter *itr2;
	RzSignItem *si;
	RzSignItem *si2;

	// do the sign diff here
	rz_list_foreach (la, itr, si) {
		//eprintf ("-- %s\n", si->name);
		if (strstr(si->name, "imp.")) {
			continue;
		}
		rz_list_foreach (lb, itr2, si2) {
			if (strstr(si2->name, "imp.")) {
				continue;
			}
			if (matchBytes(si, si2)) {
				eprintf("0x%08" PFMT64x " 0x%08" PFMT64x " B %s\n", si->addr, si2->addr, si->name);
			}
			if (matchGraph(si, si2)) {
				eprintf("0x%08" PFMT64x " 0x%08" PFMT64x " G %s\n", si->addr, si2->addr, si->name);
			}
		}
	}

	/* Diff functions */
	// rz_analysis_diff_fcn (cores[0]->analysis, cores[0]->analysis->fcns, cores[1]->analysis->fcns);

	return true;
}
