OBJ_CRIS=analysis_cris.o

STATIC_OBJ+=$(OBJ_CRIS)
TARGET_CRIS=analysis_cris.${EXT_SO}

ALL_TARGETS+=${TARGET_CRIS}

${TARGET_CRIS}: ${OBJ_CRIS}
	${CC} ${CFLAGS} $(call libname,analysis_cris) \
		-o analysis_cris.${EXT_SO} ${OBJ_CRIS}
