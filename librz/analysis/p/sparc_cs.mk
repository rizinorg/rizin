OBJ_SPARC_CS=analysis_sparc_cs.o

include ${CURDIR}capstone.mk

STATIC_OBJ+=$(OBJ_SPARC_CS)
TARGET_SPARC_CS=analysis_sparc_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_SPARC_CS}

${TARGET_SPARC_CS}: ${OBJ_SPARC_CS}
	${CC} ${CFLAGS} $(call libname,analysis_sparc_cs) $(CS_CFLAGS) \
		-o analysis_sparc_cs.${EXT_SO} ${OBJ_SPARC_CS} $(CS_LDFLAGS)
