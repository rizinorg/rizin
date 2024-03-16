// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#ifndef _INCLUDE_STRTAB_H_
#define _INCLUDE_STRTAB_H_

struct rz_bin_elf_strtab {
	char *data;
	size_t size;
};

#endif
