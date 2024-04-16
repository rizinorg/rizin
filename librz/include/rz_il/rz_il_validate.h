// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VALIDATE_H
#define RZ_IL_VALIDATE_H

#include <rz_il/rz_il_vm.h>

/**
 * \file
 * \brief Validation/Type Checking of RzIL Code
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef char *RzILValidateReport;

/**
 * Global context for validation, defining:
 *  * all global variables with their sorts
 *  * all mems with their key and value lengths
 * Validation can only be performes when this context is known,
 * as for example the type of a var op referring to a global var
 * depends on this.
 */
typedef struct rz_il_validate_global_context_t RzILValidateGlobalContext;

RZ_API RzILValidateGlobalContext *rz_il_validate_global_context_new_empty(ut32 pc_len);
RZ_API void rz_il_validate_global_context_add_var(RzILValidateGlobalContext *ctx, RZ_NONNULL const char *name, RzILSortPure sort);
RZ_API void rz_il_validate_global_context_add_mem(RzILValidateGlobalContext *ctx, RzILMemIndex idx, ut32 key_len, ut32 val_len);
RZ_API RzILValidateGlobalContext *rz_il_validate_global_context_new_from_vm(RZ_NONNULL RzILVM *vm);
RZ_API void rz_il_validate_global_context_free(RzILValidateGlobalContext *ctx);
RZ_API bool rz_il_validate_pure(RZ_NULLABLE RzILOpPure *op, RZ_NONNULL RzILValidateGlobalContext *ctx,
	RZ_NULLABLE RZ_OUT RzILSortPure *sort_out, RZ_NULLABLE RZ_OUT RzILValidateReport *report_out);
RZ_API bool rz_il_validate_effect(RZ_NULLABLE RzILOpEffect *op, RZ_NONNULL RzILValidateGlobalContext *ctx,
	RZ_NULLABLE RZ_OUT HtSP /*<const char *, RzILSortPure *>*/ **local_var_sorts_out,
	RZ_NULLABLE RZ_OUT RzILTypeEffect *type_out,
	RZ_NULLABLE RZ_OUT RzILValidateReport *report_out);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_VALIDATE_H
