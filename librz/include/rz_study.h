// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_STUDY
#define RZ_STUDY

#ifdef __cplusplus
extern "C" {
#endif

#include <rz_arch.h>
#include <rz_io.h>
#include <rz_types.h>

RZ_API bool rz_study_abstract_interpretation(RzAnalysis *analysis, RzIO *io);

#ifdef __cplusplus
}
#endif
#endif // RZ_STUDY
