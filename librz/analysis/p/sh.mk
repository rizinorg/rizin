OBJ_SH=analysis_sh.o

STATIC_OBJ+=${OBJ_SH}
TARGET_SH=analysis_sh.${EXT_SO}

ALL_TARGETS+=${TARGET_SH}

${TARGET_SH}: ${OBJ_SH}
	${CC} $(call libname,analysis_sh) ${LDFLAGS} \
		${CFLAGS} -o analysis_sh.${EXT_SO} ${OBJ_SH}
