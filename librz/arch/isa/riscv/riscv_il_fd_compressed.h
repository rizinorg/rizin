#ifndef RISCV_IL_FD_COMPRESSED_H
#define RISCV_IL_FD_COMPRESSED_H

#include "riscv/riscv_il_base.h"
#include "riscv_il_f.h"
#include "riscv_il_d.h"

DEFINE_ALIAS_LIFTER(c_fld, fld)
DEFINE_ALIAS_LIFTER(c_fldsp, fld)
DEFINE_ALIAS_LIFTER(c_fsd, fsd)
DEFINE_ALIAS_LIFTER(c_fsdsp, fsd)
#include <rz_il/rz_il_opbuilder_begin.h>

#endif // RISCV_IL_FD_COMPRESSED_H