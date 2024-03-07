// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <deprecated_arch_helper.h>

#include "analysis/analysis_6502.c"
#include "asm/asm_6502.c"
#include "parse/parse_6502_pseudo.c"

RZ_ARCH_WITH_PARSE_PLUGIN_DEFINE_DEPRECATED(6502);
