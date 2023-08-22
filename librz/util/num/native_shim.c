// SPDX-FileCopyrightText: 2024 Rizin contributors
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file native_shim.c
 *
 * Build-machine (native) variant of the RzNum tree-sitter entry points.
 *
 * When cross-compiling, librz_util is also built natively so that the
 * build-time sdb_gen tool can run. That tool never evaluates RzNum
 * expressions, so the native build deliberately leaves out the
 * tree-sitter based evaluator (num/evaluator.c and friends)
 * and, with it, the whole tree-sitter dependency. unum.c still links
 * against two of the evaluator's symbols, though, so this small shim
 * provides them with behaviour that is correct for the native build:
 *
 *   - rz_num_math_value() reports a parse error, which makes
 *     rz_num_math_ut64() fall back to the legacy rz_num_calc()
 *     evaluator. The native build therefore keeps full numeric
 *     behaviour through the legacy path.
 *
 *   - rz_num_value_store_free() is identical to the real one; the
 *     variable store is never populated here (nothing creates it
 *     without the evaluator), so it is only ever called with NULL.
 *
 * The regular, non-cross build never compiles this file: it uses the
 * real implementations in num/.
 */

#include <rz_util.h>

RZ_API bool rz_num_math_value(RZ_NULLABLE RzNum *num, RZ_NONNULL const char *expr,
	RZ_OUT RZ_NONNULL RzNumValue *out_value, RZ_OUT RZ_NULLABLE char **error_msg) {
	rz_return_val_if_fail(expr && out_value, false);
	(void)num;
	// Signal a parse failure so callers fall back to the legacy parser.
	out_value->err = RZ_NUM_ERR_PARSE;
	if (error_msg) {
		*error_msg = NULL;
	}
	return false;
}

RZ_API void rz_num_value_store_free(RZ_NULLABLE HtSP *store) {
	ht_sp_free(store);
}
