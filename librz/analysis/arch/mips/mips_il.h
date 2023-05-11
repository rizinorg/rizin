#ifndef MIPS_IL_H_
#define MIPS_IL_H_

#include <rz_analysis.h>
#include <capstone/capstone.h>

RZ_IPI RzILOpEffect *mips32_il(RZ_NONNULL cs_insn *insn);
RZ_IPI RzAnalysisILConfig *mips32_il_config();

#endif // MIPS_IL_H_
