/* radare - LGPL - Copyright 2009-2018 - pancake, maijin, thestr4ng3r */

#include "rz_anal.h"

RZ_API char *rz_anal_rtti_demangle_class_name(RzAnal *anal, const char *name) {
	RVTableContext context;
	rz_anal_vtable_begin (anal, &context);
	if (context.abi == RZ_ANAL_CPP_ABI_MSVC) {
		return rz_anal_rtti_msvc_demangle_class_name (&context, name);
	}
	return rz_anal_rtti_itanium_demangle_class_name (&context, name);
}

RZ_API void rz_anal_rtti_print_at_vtable(RzAnal *anal, ut64 addr, int mode) {
	bool use_json = mode == 'j';
	if (use_json) {
		rz_cons_print ("[");
	}

	RVTableContext context;
	rz_anal_vtable_begin (anal, &context);
	if (context.abi == RZ_ANAL_CPP_ABI_MSVC) {
		rz_anal_rtti_msvc_print_at_vtable (&context, addr, mode, false);
	} else {
		rz_anal_rtti_itanium_print_at_vtable (&context, addr, mode);
	}

	if (use_json) {
		rz_cons_print ("]\n");
	}
}

RZ_API void rz_anal_rtti_print_all(RzAnal *anal, int mode) {
	RVTableContext context;
	rz_anal_vtable_begin (anal, &context);

	bool use_json = mode == 'j';
	if (use_json) {
		rz_cons_print ("[");
	}

	rz_cons_break_push (NULL, NULL);
	RzList *vtables = rz_anal_vtable_search (&context);
	RzListIter *vtableIter;
	RVTableInfo *table;

	if (vtables) {
		bool comma = false;
		bool success = false;
		rz_list_foreach (vtables, vtableIter, table) {
			if (rz_cons_is_breaked ()) {
				break;
			}
			if (use_json && success) {
				rz_cons_print (",");
				comma = true;
			}
			if (context.abi == RZ_ANAL_CPP_ABI_MSVC) {
				success = rz_anal_rtti_msvc_print_at_vtable (&context, table->saddr, mode, true);
			} else {
				success = rz_anal_rtti_itanium_print_at_vtable (&context, table->saddr, mode);
			}
			if (success) {
				comma = false;
				if (!use_json) {
					rz_cons_print ("\n");
				}
			}
		}
		if (use_json && !success && comma) {
			// drop last comma if necessary
			rz_cons_drop (1);
		}
	}
	rz_list_free (vtables);

	if (use_json) {
		rz_cons_print ("]\n");
	}

	rz_cons_break_pop ();
}

RZ_API void rz_anal_rtti_recover_all(RzAnal *anal) {
	RVTableContext context;
	rz_anal_vtable_begin (anal, &context);

	rz_cons_break_push (NULL, NULL);
	RzList *vtables = rz_anal_vtable_search (&context);
	if (vtables) {
		if (context.abi == RZ_ANAL_CPP_ABI_MSVC) {
			rz_anal_rtti_msvc_recover_all (&context, vtables);
		} else {
			rz_anal_rtti_itanium_recover_all (&context, vtables);
		}
	}
	rz_list_free (vtables);
	rz_cons_break_pop ();
}
