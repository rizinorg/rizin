OBJ_NIOS2=analysis_nios2.o

STATIC_OBJ+=${OBJ_NIOS2}
TARGET_NIOS2=analysis_nios2.${EXT_SO}

ALL_TARGETS+=${TARGET_NIOS2}

${TARGET_NIOS2}: ${OBJ_NIOS2}
	${CC} $(call libname,analysis_nios2) ${LDFLAGS} ${CFLAGS} \
		-o analysis_nios2.${EXT_SO} ${OBJ_NIOS2}
