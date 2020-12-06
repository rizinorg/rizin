OBJ_I8080=analysis_i8080.o

STATIC_OBJ+=${OBJ_I8080}
TARGET_I8080=analysis_i8080.${EXT_SO}

ALL_TARGETS+=${TARGET_I8080}

${TARGET_I8080}: ${OBJ_I8080}
	${CC} $(call libname,analysis_z80) ${LDFLAGS} ${CFLAGS} -o analysis_i8080.${EXT_SO} ${OBJ_I8080}
