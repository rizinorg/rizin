OBJ_6502_CS=analysis_6502_cs.o

STATIC_OBJ+=${OBJ_6502_CS}
TARGET_6502_CS=analysis_6502_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_6502_CS}

${TARGET_6502_CS}: ${OBJ_6502_CS}
	${CC} $(call libname,analysis_6502_cs) ${LDFLAGS} ${CFLAGS} -o analysis_6502_cs.${EXT_SO} ${OBJ_6502_CS}
