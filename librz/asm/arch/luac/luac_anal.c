#include "luac_anal.h"

#include "luac_anal.h"

int lua_anal_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len){
        // switch version here ?
	return lua54_anal_op(analysis, op, addr, data, len);
}

