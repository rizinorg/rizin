// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_REG_PRIVATE_H
#define RZ_REG_PRIVATE_H

#include <rz_reg.h>

RZ_IPI void rz_reg_free_internal(RZ_NULLABLE RzReg *reg, bool keep_arenas);

#endif
