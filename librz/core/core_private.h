#ifndef RZ_CORE_PRIVATE_INCLUDE_H_
#define RZ_CORE_PRIVATE_INCLUDE_H_

#include <rz_types.h>
#include <rz_core.h>

RZ_IPI int rz_core_analysis_set_reg(RzCore *core, const char *regname, ut64 val);
RZ_IPI void rz_core_analysis_esil_init(RzCore *core);
RZ_IPI bool rz_core_debug_reg_list(RzCore *core, int type, int size, PJ *pj, int rad, const char *use_color);
RZ_IPI void rz_core_debug_regs2flags(RzCore *core, int bits);
RZ_IPI void rz_core_regs2flags(RzCore *core);

#endif