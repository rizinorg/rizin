#include <rz_analysis.h>

RZ_API RzAnalysisRzil *rz_analysis_rzil_new() {
        RzAnalysisRzil *rzil = RZ_NEW0(RzAnalysisRzil);
        if (!rzil) {
                return NULL;
        }
        rzil->vm = RZ_NEW0(struct rz_il_vm_t);
        if (!rzil->vm) {
                free(rzil);
                return NULL;
        }
        return rzil;
}

RZ_API void rz_analysis_rzil_cleanup(RzAnalysisRzil *rzil, RzAnalysis *analysis) {
        if (rzil->vm) {
                rz_il_vm_close(rzil->vm);
                rzil->vm = NULL;
        }
	if (analysis && analysis->cur && analysis->cur->rzil_fini) {
		analysis->cur->rzil_fini(rzil);
	}
        free(rzil);
}

RZ_API bool rz_analysis_rzil_set_pc(RzAnalysisRzil *rzil, ut64 addr) {
	if (rzil) {
		rzil->pc_addr = addr;
		return true;
	}
	return false;
}

RZ_API bool rz_analysis_rzil_setup(RzAnalysisRzil *rzil, RzAnalysis *analysis, int romem, int stats, int nonull) {
	rz_return_val_if_fail(rzil, false);

	rzil->cb.reg_read = NULL;
	rzil->cb.mem_read = NULL;

	// init the esil mem read only
	rz_analysis_rzil_mem_ro(rzil, romem);
	rz_analysis_rzil_stats(rzil, stats);

	// set up op types
	// TODO change analsis->cur and add `rzil_init`
	//      as `esil_init` in analysis_plugin
	if (analysis && analysis->cur && analysis->cur->rzil_init) {
		analysis->cur->rzil_init(rzil);
	}

	return true;
}

RZ_API void rz_analysis_set_rzil_op(RzAnalysisRzil *rzil, ut64 addr, RzPVector *oplist) {
	BitVector bv_addr = rz_il_ut64_addr_to_bv(addr);
	rz_il_vm_store_opcodes_to_addr(rzil->vm, bv_addr, oplist);
	rz_il_free_bv_addr(bv_addr);
}
