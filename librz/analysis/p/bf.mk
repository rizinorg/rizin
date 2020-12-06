OBJ_BF=analysis_bf.o

STATIC_OBJ+=${OBJ_BF}
TARGET_BF=analysis_bf.${EXT_SO}

ALL_TARGETS+=${TARGET_BF}

${TARGET_BF}: ${OBJ_BF}
	${CC} $(call libname,analysis_bf) ${LDFLAGS} ${CFLAGS} -o analysis_bf.${EXT_SO} ${OBJ_BF}
