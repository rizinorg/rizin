OBJ_SPARC=analysis_sparc_gnu.o

STATIC_OBJ+=${OBJ_SPARC}
TARGET_SPARC=analysis_sparc_gnu.${EXT_SO}

ALL_TARGETS+=${TARGET_SPARC}

${TARGET_SPARC}: ${OBJ_SPARC}
	${CC} $(call libname,analysis_sparc_gnu) ${CFLAGS} -o analysis_sparc_gnu.${EXT_SO} ${OBJ_SPARC}
