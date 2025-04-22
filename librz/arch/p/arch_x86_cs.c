// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <deprecated_arch_helper.h>

#include "analysis/analysis_x86_cs.c"
#include "asm/asm_x86_cs.c"
#include "parse/parse_x86_pseudo.c"

RZ_ARCH_WITH_PARSE_PLUGIN_DEFINE_DEPRECATED(x86_cs);
