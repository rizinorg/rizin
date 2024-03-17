// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"
#include <rz_util/ht_uu.h>

#ifndef _INCLUDE_ELF_DYNAMIC_H_
#define _INCLUDE_ELF_DYNAMIC_H_

struct rz_bin_elf_dt_dynamic_t {
	HtUU *info;
	RzVector /*<ut64>*/ dt_needed;
};

#endif
