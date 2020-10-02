/* rizin - LGPL - Copyright 2018-2019 - pancake */

#include <rz_core.h>

#if 0

TODO:

- add more methods to "undo according to some conditions"
- undo all comments in current offfset
#endif

RZ_API RzCoreUndo *rz_core_undo_new(ut64 offset, const char *action, const char *revert) {
	RzCoreUndo *cu = RZ_NEW (RzCoreUndo);
	if (cu) {
		cu->action = strdup (action);
		cu->revert = strdup (revert);
		cu->tstamp = rz_time_now ();
		cu->offset = offset;
	}
	return cu;
}

RZ_API void rz_core_undo_free(RzCoreUndo *cu) {
	if (cu) {
		free (cu->action);
		free (cu->revert);
	}
	free (cu);
}

RZ_API void rz_core_undo_push(RzCore *core, RzCoreUndo *cu) {
	rz_list_append (core->undos, cu);
}

RZ_API void rz_core_undo_pop(RzCore *core) {
	RzCoreUndo *undo = rz_list_pop (core->undos);
	if (undo) {
		rz_core_cmd0 (core, undo->revert);
		rz_core_undo_free (undo);
	}
}

RZ_API bool rz_core_undo_condition(RzCoreUndo *cu, RzCoreUndoCondition *cond) {
	if (!cond) {
		return true;
	}
	bool mustPrint = false;
	if (cond->addr != UT64_MAX) {
		mustPrint = (cu->offset == cond->addr);
	}
	if (cond->minstamp) {
		mustPrint = (cu->tstamp >= cond->minstamp);
	}
	if (cond->glob) {
		mustPrint = rz_str_glob (cu->action, cond->glob);
	}
	return mustPrint;
}

RZ_API void rz_core_undo_print(RzCore *core, int mode, RzCoreUndoCondition *cond) {
	RzCoreUndo *cu;
	RzListIter *iter;
	if (mode) {
		rz_list_foreach (core->undos, iter, cu) {
			if (rz_core_undo_condition (cu, cond)) {
				rz_cons_printf ("%s @ 0x%"PFMT64x"\n", cu->revert, cu->offset);
			}
		}
	} else {
		rz_list_foreach (core->undos, iter, cu) {
			rz_cons_printf ("0x%08"PFMT64x" %"PFMT64d"  %s (revert: %s)\n",
				cu->offset, cu->tstamp, cu->action, cu->revert);
		}
	}
}
