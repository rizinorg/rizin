// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RL78_H
#define RL78_H

#include "rl78_instr.h"

#include <rz_util.h>
#include <rz_types.h>

bool rl78_dis(RL78Instr RZ_OUT *instr, size_t RZ_OUT *bytes_read,
	const ut8 *buf, size_t buf_len);

#endif
