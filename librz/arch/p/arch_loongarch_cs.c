// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <deprecated_arch_helper.h>

#include <capstone/capstone.h>
#include <capstone/loongarch.h>
#include <loongarch/loongarch.inc>

#include "analysis/analysis_loongarch_cs.c"
#include "asm/asm_loongarch_cs.c"

RZ_ARCH_PLUGIN_DEFINE_DEPRECATED(loongarch_cs);
