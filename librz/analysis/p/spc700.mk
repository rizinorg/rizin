OBJ_spc700=analysis_spc700.o

STATIC_OBJ+=${OBJ_spc700}
TARGET_spc700=analysis_spc700.${EXT_SO}

ALL_TARGETS+=${TARGET_spc700}

${TARGET_spc700}: ${OBJ_spc700}
	${CC} $(call libname,analysis_spc700) ${LDFLAGS} ${CFLAGS} -o analysis_spc700.${EXT_SO} ${OBJ_spc700}
