OBJ_TRICORE=analysis_tricore.o

STATIC_OBJ+=${OBJ_TRICORE}
TARGET_TRICORE=analysis_tricore.${EXT_SO}

ALL_TARGETS+=${TARGET_TRICORE}

${TARGET_TRICORE}: ${OBJ_TRICORE}
	${CC} $(call libname,analysis_tricore) ${LDFLAGS} ${CFLAGS} \
		-o $(TARGET_TRICORE) $(OBJ_TRICORE)