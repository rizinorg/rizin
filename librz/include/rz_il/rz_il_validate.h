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

typedef struct rz_il_validate_context_t RzILValidateContext;

RZ_API RzILValidateContext *rz_il_validate_context_new_from_vm(RzILVM *vm);
RZ_API void rz_il_validate_context_free(RzILValidateContext *ctx);
RZ_API bool rz_il_validate_pure(RZ_NULLABLE RzILOpPure *op, RZ_NULLABLE RZ_OUT RzILSortPure *sort_out, RZ_NULLABLE RZ_OUT RzILValidateReport *report_out);
RZ_API bool rz_il_validate_effect(RZ_NULLABLE RzILOpEffect *op, RZ_NULLABLE RZ_OUT RzILValidateReport *report_out);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_VALIDATE_H
