OBJ_I4004=analysis_i4004.o

STATIC_OBJ+=${OBJ_I4004}
TARGET_I4004=analysis_i4004.${EXT_SO}

ALL_TARGETS+=${TARGET_I4004}

${TARGET_I4004}: ${OBJ_I4004}
	${CC} $(call libname,analysis_i4004) ${CFLAGS} -o analysis_i4004.${EXT_SO} ${OBJ_I4004}
