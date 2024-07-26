#include <z3.h>
#include <rz_core.h>

/**
   \brief Create a variable using the given name and type.
*/
RZ_API Z3_ast mk_var(Z3_context ctx, const char *name, Z3_sort ty) {
	Z3_symbol s = Z3_mk_string_symbol(ctx, name);
	return Z3_mk_const(ctx, s, ty);
}

/**
   \brief Create a boolean variable using the given name.
*/
RZ_API Z3_ast mk_bool_var(Z3_context ctx, const char *name) {
	Z3_sort ty = Z3_mk_bool_sort(ctx);
	return mk_var(ctx, name, ty);
}

/**
   \brief Create an integer variable using the given name.
*/
RZ_API Z3_ast mk_int_var(Z3_context ctx, const char *name) {
	Z3_sort ty = Z3_mk_int_sort(ctx);
	return mk_var(ctx, name, ty);
}

/**
   \brief Create a Z3 integer node using a C int.
*/
RZ_API Z3_ast mk_int(Z3_context ctx, int v) {
	Z3_sort ty = Z3_mk_int_sort(ctx);
	return Z3_mk_int(ctx, v, ty);
}

/**
   \brief Create a real variable using the given name.
*/
Z3_ast mk_real_var(Z3_context ctx, const char *name) {
	Z3_sort ty = Z3_mk_real_sort(ctx);
	return mk_var(ctx, name, ty);
}

/**
   \brief Create the unary function application: <tt>(f x)</tt>.
*/
static Z3_ast mk_unary_app(Z3_context ctx, Z3_func_decl f, Z3_ast x) {
	Z3_ast args[1] = { x };
	return Z3_mk_app(ctx, f, 1, args);
}

/**
   \brief Create the binary function application: <tt>(f x y)</tt>.
*/
static Z3_ast mk_binary_app(Z3_context ctx, Z3_func_decl f, Z3_ast x, Z3_ast y) {
	Z3_ast args[2] = { x, y };
	return Z3_mk_app(ctx, f, 2, args);
}

RZ_API Z3_solver mk_solver(Z3_context ctx) {
	Z3_solver s = Z3_mk_solver(ctx);
	Z3_solver_inc_ref(ctx, s);
	return s;
}

/**
   \brief Display a symbol in the given output stream.
*/
void display_symbol(Z3_context c, Z3_symbol s) {
	switch (Z3_get_symbol_kind(c, s)) {
	case Z3_INT_SYMBOL:
		rz_cons_printf("#%d", Z3_get_symbol_int(c, s));
		break;
	case Z3_STRING_SYMBOL:
		rz_cons_printf("%s", Z3_get_symbol_string(c, s));
		break;
	default:
		break;
	}
}

/**
   \brief Display the given type.
*/
void display_sort(Z3_context c, Z3_sort ty) {
	switch (Z3_get_sort_kind(c, ty)) {
	case Z3_UNINTERPRETED_SORT:
		display_symbol(c, Z3_get_sort_name(c, ty));
		break;
	case Z3_BOOL_SORT:
		rz_cons_printf("bool");
		break;
	case Z3_INT_SORT:
		rz_cons_printf("int");
		break;
	case Z3_REAL_SORT:
		rz_cons_printf("real");
		break;
	case Z3_BV_SORT:
		rz_cons_printf("bv%d", Z3_get_bv_sort_size(c, ty));
		break;
	case Z3_ARRAY_SORT:
		rz_cons_printf("[");
		display_sort(c, Z3_get_array_sort_domain(c, ty));
		rz_cons_printf("->");
		display_sort(c, Z3_get_array_sort_range(c, ty));
		rz_cons_printf("]");
		break;
	case Z3_DATATYPE_SORT:
		if (Z3_get_datatype_sort_num_constructors(c, ty) != 1) {
			rz_cons_printf("%s", Z3_sort_to_string(c, ty));
			break;
		}
		{
			unsigned num_fields = Z3_get_tuple_sort_num_fields(c, ty);
			unsigned i;
			rz_cons_printf("(");
			for (i = 0; i < num_fields; i++) {
				Z3_func_decl field = Z3_get_tuple_sort_field_decl(c, ty, i);
				if (i > 0) {
					rz_cons_printf(", ");
				}
				display_sort(c, Z3_get_range(c, field));
			}
			rz_cons_printf(")");
			break;
		}
	default:
		rz_cons_printf("unknown[");
		display_symbol(c, Z3_get_sort_name(c, ty));
		rz_cons_printf("]");
		break;
	}
}

/**
   \brief Custom ast pretty printer.

   This function demonstrates how to use the API to navigate terms.
*/
void display_ast(Z3_context c, Z3_ast v) {
	switch (Z3_get_ast_kind(c, v)) {
	case Z3_NUMERAL_AST: {
		Z3_sort t;
		rz_cons_printf("%s", Z3_get_numeral_string(c, v));
		t = Z3_get_sort(c, v);
		rz_cons_printf(":");
		display_sort(c, t);
		break;
	}
	case Z3_APP_AST: {
		unsigned i;
		Z3_app app = Z3_to_app(c, v);
		unsigned num_fields = Z3_get_app_num_args(c, app);
		Z3_func_decl d = Z3_get_app_decl(c, app);
		rz_cons_printf("%s", Z3_func_decl_to_string(c, d));
		if (num_fields > 0) {
			rz_cons_printf("[");
			for (i = 0; i < num_fields; i++) {
				if (i > 0) {
					rz_cons_printf(", ");
				}
				display_ast(c, Z3_get_app_arg(c, app, i));
			}
			rz_cons_printf("]");
		}
		break;
	}
	case Z3_QUANTIFIER_AST: {
		rz_cons_printf("quantifier");
		break;
	}
	default:
		rz_cons_printf("#unknown");
	}
}

/**
   \brief Custom function interpretations pretty printer.
*/
void display_function_interpretations(Z3_context c, Z3_model m) {
	unsigned num_functions, i;

	rz_cons_printf("function interpretations:\n");

	num_functions = Z3_model_get_num_funcs(c, m);
	for (i = 0; i < num_functions; i++) {
		Z3_func_decl fdecl;
		Z3_symbol name;
		Z3_ast func_else;
		unsigned num_entries = 0, j;
		Z3_func_interp_opt finterp;

		fdecl = Z3_model_get_func_decl(c, m, i);
		finterp = Z3_model_get_func_interp(c, m, fdecl);
		Z3_func_interp_inc_ref(c, finterp);
		name = Z3_get_decl_name(c, fdecl);
		display_symbol(c, name);
		rz_cons_printf(" = {");
		if (finterp)
			num_entries = Z3_func_interp_get_num_entries(c, finterp);
		for (j = 0; j < num_entries; j++) {
			unsigned num_args, k;
			Z3_func_entry fentry = Z3_func_interp_get_entry(c, finterp, j);
			Z3_func_entry_inc_ref(c, fentry);
			if (j > 0) {
				rz_cons_printf(", ");
			}
			num_args = Z3_func_entry_get_num_args(c, fentry);
			rz_cons_printf("(");
			for (k = 0; k < num_args; k++) {
				if (k > 0) {
					rz_cons_printf(", ");
				}
				display_ast(c, Z3_func_entry_get_arg(c, fentry, k));
			}
			rz_cons_printf("|->");
			display_ast(c, Z3_func_entry_get_value(c, fentry));
			rz_cons_printf(")");
			Z3_func_entry_dec_ref(c, fentry);
		}
		if (num_entries > 0) {
			rz_cons_printf(", ");
		}
		rz_cons_printf("(else|->");
		func_else = Z3_func_interp_get_else(c, finterp);
		display_ast(c, func_else);
		rz_cons_printf(")}\n");
		Z3_func_interp_dec_ref(c, finterp);
	}
}

/**
   \brief Custom model pretty printer.
*/
void display_model(Z3_context c, Z3_model m) {
	unsigned num_constants;
	unsigned i;

	if (!m)
		return;

	num_constants = Z3_model_get_num_consts(c, m);
	for (i = 0; i < num_constants; i++) {
		Z3_symbol name;
		Z3_func_decl cnst = Z3_model_get_const_decl(c, m, i);
		Z3_ast a, v;
		name = Z3_get_decl_name(c, cnst);
		display_symbol(c, name);
		rz_cons_printf(" = ");
		a = Z3_mk_app(c, cnst, 0, 0);
		v = a;
		bool ok = Z3_model_eval(c, m, a, 1, &v);
		display_ast(c, v);
		rz_cons_printf("\n");
	}
	display_function_interpretations(c, m);
}

/**
   \brief Similar to #check, but uses #display_model instead of #Z3_model_to_string.
*/
RZ_API void check2(Z3_context ctx, Z3_solver s, Z3_lbool expected_result) {
	Z3_model m = 0;
	Z3_lbool result = Z3_solver_check(ctx, s);
	switch (result) {
	case Z3_L_FALSE:
		rz_cons_printf("unsat\n");
		break;
	case Z3_L_UNDEF:
		rz_cons_printf("unknown\n");
		rz_cons_printf("potential model:\n");
		m = Z3_solver_get_model(ctx, s);
		if (m)
			Z3_model_inc_ref(ctx, m);
		display_model(ctx, m);
		break;
	case Z3_L_TRUE:
		rz_cons_printf("sat\n");
		m = Z3_solver_get_model(ctx, s);
		if (m)
			Z3_model_inc_ref(ctx, m);
		display_model(ctx, m);
		break;
	}
	if (result != expected_result) {
	}
	if (m)
		Z3_model_dec_ref(ctx, m);
}

RZ_API void del_solver(Z3_context ctx, Z3_solver s) {
	Z3_solver_dec_ref(ctx, s);
}

void error_handler(Z3_context c, Z3_error_code e) {
	rz_cons_printf("Error code: %d\n", e);
}

Z3_context mk_context_custom(Z3_config cfg, Z3_error_handler err) {
	Z3_context ctx;

	Z3_set_param_value(cfg, "model", "true");
	ctx = Z3_mk_context(cfg);
	Z3_set_error_handler(ctx, err);

	return ctx;
}

RZ_API Z3_context mk_context() {
	Z3_config cfg;
	Z3_context ctx;
	cfg = Z3_mk_config();
	ctx = mk_context_custom(cfg, error_handler);
	Z3_del_config(cfg);
	return ctx;
}
