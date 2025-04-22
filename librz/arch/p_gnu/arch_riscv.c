// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <deprecated_arch_helper.h>

#include "../isa_gnu/riscv/riscv-opc.c"
#include <riscv/riscv.h>
#include "../isa_gnu/riscv/riscv.c"

#include "analysis/analysis_riscv_gnu.c"
#include "asm/asm_riscv_gnu.c"
#include "parse/parse_riscv_gnu.c"

RZ_ARCH_WITH_PARSE_PLUGIN_DEFINE_DEPRECATED(riscv_gnu);
