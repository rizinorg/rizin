OBJ_RISCV=analysis_riscv.o

STATIC_OBJ+=${OBJ_RISCV}
TARGET_RISCV=analysis_riscv.${EXT_SO}

ALL_TARGETS+=${TARGET_RISCV}

${TARGET_RISCV}: ${OBJ_RISCV}
	${CC} $(call libname,analysis_RISCV) ${LDFLAGS} ${CFLAGS} -o analysis_riscv.${EXT_SO} ${OBJ_RISCV}
