OBJ_NULL=analysis_null.o

STATIC_OBJ+=${OBJ_NULL}
TARGET_NULL=analysis_null.${EXT_SO}

ALL_TARGETS+=${TARGET_NULL}

${TARGET_NULL}: ${OBJ_NULL}
	${CC} $(call libname,analysis_null) ${LDFLAGS} \
		${CFLAGS} -o analysis_null.${EXT_SO} ${OBJ_NULL}
