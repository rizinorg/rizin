OBJ_ARC=analysis_arc.o

STATIC_OBJ+=${OBJ_ARC}
TARGET_ARC=analysis_arc.${EXT_SO}

ALL_TARGETS+=${TARGET_ARC}

${TARGET_ARC}: ${OBJ_ARC}
	${CC} $(call libname,analysis_arc) ${LDFLAGS} ${CFLAGS} -o analysis_arc.${EXT_SO} ${OBJ_ARC}
