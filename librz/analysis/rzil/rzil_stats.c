#include <rz_analysis.h>

static int hook_flag_read(RzAnalysisRzil *rzil, const char *flag, ut64 *num) {
        sdb_array_add(rzil->stats, "flg.read", flag, 0);
        return 0;
}

static int hook_command(RzAnalysisRzil *rzil, const char *op) {
        sdb_array_add(rzil->stats, "ops.list", op, 0);
        return 0;
}

static int hook_mem_read(RzAnalysisRzil *rzil, ut64 addr, ut8 *buf, int len) {
        sdb_array_add_num(rzil->stats, "mem.read", addr, 0);
        return 0;
}

static int hook_mem_write(RzAnalysisRzil *rzil, ut64 addr, const ut8 *buf, int len) {
        sdb_array_add_num(rzil->stats, "mem.write", addr, 0);
        return 0;
}

static int hook_reg_read(RzAnalysisRzil *rzil, const char *name, ut64 *res, int *size) {
        const char *key = (*name >= '0' && *name <= '9') ? "num.load" : "reg.read";
        sdb_array_add(rzil->stats, key, name, 0);
        return 0;
}

static int hook_reg_write(RzAnalysisRzil *rzil, const char *name, ut64 *val) {
        sdb_array_add(rzil->stats, "reg.write", name, 0);
        return 0;
}

static int hook_NOP_mem_write(RzAnalysisRzil *rzil, ut64 addr, const ut8 *buf, int len) {
        eprintf("NOP WRITE AT 0x%08" PFMT64x "\n", addr);
        return 1; // override
}

RZ_API void rz_analysis_rzil_mem_ro(RzAnalysisRzil *rzil, int mem_readonly) {
	if (mem_readonly) {
		rzil->cb.hook_mem_write = hook_NOP_mem_write;
	} else {
		rzil->cb.hook_mem_write = NULL;
	}
}

RZ_API void rz_analysis_rzil_stats(RzAnalysisRzil *rzil, int enable) {
	if (enable) {
		if (rzil->stats) {
			sdb_reset(rzil->stats);
		} else {
			rzil->stats = sdb_new0();
		}
		// reset
		rzil->cb.reg_read = hook_reg_read;
                rzil->cb.hook_mem_read = hook_mem_read;
                rzil->cb.hook_mem_write = hook_mem_write;
                rzil->cb.hook_reg_write = hook_reg_write;
                rzil->cb.hook_flag_read = hook_flag_read;
                rzil->cb.hook_command = hook_command;
	} else {
                rzil->cb.hook_mem_write = NULL;
                rzil->cb.hook_flag_read = NULL;
                rzil->cb.hook_command = NULL;
                sdb_free(rzil->stats);
                rzil->stats = NULL;
	}
}
