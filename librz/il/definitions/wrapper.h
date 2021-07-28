// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CORE_THEORY_VM_WRAPPER_H
#define CORE_THEORY_VM_WRAPPER_H

#include "bitvector.h"
#include "effect.h"
#include "bool.h"
#include "vm_defines.h"
#include "mem.h"

BitVector val_cast_to_bitv(RzILVal val);
Bool val_cast_to_bool(RzILVal val);

RzILVal bitv_cast_to_val(BitVector bv);
RzILVal bool_cast_to_val(Bool b);

#endif //CORE_THEORY_VM_WRAPPER_H
