OBJ_MALBOLGE=analysis_malbolge.o

STATIC_OBJ+=${OBJ_MALBOLGE}
TARGET_MALBOLGE=analysis_malbolge.${EXT_SO}

ALL_TARGETS+=${TARGET_MALBOLGE}

${TARGET_MALBOLGE}: ${OBJ_MALBOLGE}
	${CC} $(call libname,analysis_malbolge) ${LDFLAGS} ${CFLAGS} -o analysis_malbolge.${EXT_SO} ${OBJ_MALBOLGE}
