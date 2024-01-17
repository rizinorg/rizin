// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "arch_helper.h"

#define rz_analysis_plugin_tms320 rz_analysis_plugin_tms320c64x

#include "analysis_tms320c64x.c"
#include "analysis_tms320.c"
#include "asm_tms320c64x.c"

RZ_ARCH_PLUGIN_DEFINE_DEPRECATED(tms320c64x);
