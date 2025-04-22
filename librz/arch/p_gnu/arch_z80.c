// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <deprecated_arch_helper.h>

#include "../isa_gnu/z80/z80.c"
#include "../isa_gnu/z80/z80asm.c"

#include "analysis/analysis_z80_gnu.c"
#include "asm/asm_z80_gnu.c"
#include "parse/parse_z80_gnu.c"

RZ_ARCH_WITH_PARSE_PLUGIN_DEFINE_DEPRECATED(z80_gnu);
