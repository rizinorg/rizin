OBJ_6502=analysis_6502.o

STATIC_OBJ+=${OBJ_6502}
TARGET_6502=analysis_6502.${EXT_SO}

ALL_TARGETS+=${TARGET_6502}

${TARGET_6502}: ${OBJ_6502}
	${CC} $(call libname,analysis_6502) ${LDFLAGS} ${CFLAGS} -o analysis_6502.${EXT_SO} ${OBJ_6502}
