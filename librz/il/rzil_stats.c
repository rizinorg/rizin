#include <rz_analysis.h>

static int hook_flag_read(RzILVM vm, const char *flag, ut64 *num) {
        sdb_array_add(vm->stats, "flg.read", flag, 0);
        return 0;
}

static int hook_command(RzILVM vm, const char *op) {
        sdb_array_add(vm->stats, "ops.list", op, 0);
        return 0;
}

static int hook_mem_read(RzILVM vm, ut64 addr, ut8 *buf, int len) {
        sdb_array_add_num(vm->stats, "mem.read", addr, 0);
        return 0;
}

static int hook_mem_write(RzILVM vm, ut64 addr, const ut8 *buf, int len) {
        sdb_array_add_num(vm->stats, "mem.write", addr, 0);
        return 0;
}

static int hook_reg_read(RzILVM vm, const char *name, ut64 *res, int *size) {
        const char *key = (*name >= '0' && *name <= '9') ? "num.load" : "reg.read";
        sdb_array_add(vm->stats, key, name, 0);
        return 0;
}

static int hook_reg_write(RzILVM vm, const char *name, ut64 *val) {
        sdb_array_add(vm->stats, "reg.write", name, 0);
        return 0;
}

static int hook_NOP_mem_write(RzILVM vm, ut64 addr, const ut8 *buf, int len) {
        eprintf("NOP WRITE AT 0x%08" PFMT64x "\n", addr);
        return 1; // override
}

RZ_API void rz_analysis_rzil_mem_ro(RzILVM vm, int mem_readonly) {
	if (mem_readonly) {
		vm->cb.hook_mem_write = hook_NOP_mem_write;
	} else {
		vm->cb.hook_mem_write = NULL;
	}
}

RZ_API void rz_analysis_rzil_stats(RzILVM vm, int enable) {
	if (enable) {
		if (vm->stats) {
			sdb_reset(vm->stats);
		} else {
			vm->stats = sdb_new0();
		}
		// reset
		vm->cb.reg_read = hook_reg_read;
                vm->cb.hook_mem_read = hook_mem_read;
                vm->cb.hook_mem_write = hook_mem_write;
                vm->cb.hook_reg_write = hook_reg_write;
                vm->cb.hook_flag_read = hook_flag_read;
                vm->cb.hook_command = hook_command;
	} else {
                vm->cb.hook_mem_write = NULL;
                vm->cb.hook_flag_read = NULL;
                vm->cb.hook_command = NULL;
                sdb_free(vm->stats);
                vm->stats = NULL;
	}
}
