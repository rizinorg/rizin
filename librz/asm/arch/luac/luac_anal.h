#ifndef BUILD_LUAC_ANAL_H
#define BUILD_LUAC_ANAL_H

#include <rz_types.h>
#include <rz_analysis.h>

int lua_anal_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len);
int lua54_anal_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len);

// lua common load function


#endif //BUILD_LUAC_ANAL_H
