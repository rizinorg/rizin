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

RZ_API void rz_analysis_rzil_free(RzAnalysisRzil *rzil) {
        if (rzil->vm) {
                rz_il_vm_close(rzil->vm);
                rzil->vm = NULL;
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
}

