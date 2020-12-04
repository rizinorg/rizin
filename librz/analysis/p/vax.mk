OBJ_VAX=analysis_vax.o

STATIC_OBJ+=${OBJ_VAX}
TARGET_VAX=analysis_vax.${EXT_SO}

ALL_TARGETS+=${TARGET_VAX}

${TARGET_VAX}: ${OBJ_VAX}
	${CC} $(call libname,analysis_vax) ${CFLAGS} -o analysis_vax.${EXT_SO} ${OBJ_VAX}
