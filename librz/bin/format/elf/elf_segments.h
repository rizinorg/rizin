// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LPGL-3.0-only

#include "elf.h"

#ifndef _INCLUDE_ELF_SEGMENTS_H_
#define _INCLUDE_ELF_SEGMENTS_H_

struct rz_bin_elf_dt_segments_t {
	RzVector *segments; // RzBinElfSegment
};

#endif
