OBJ_SNES=analysis_snes.o

STATIC_OBJ+=${OBJ_SNES}
TARGET_SNES=analysis_snes.${EXT_SO}

ALL_TARGETS+=${TARGET_SNES}

${TARGET_SNES}: ${OBJ_SNES}
	${CC} $(call libname,analysis_snes) ${LDFLAGS} ${CFLAGS} -o analysis_snes.${EXT_SO} ${OBJ_SNES}
