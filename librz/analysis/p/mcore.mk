OBJ_MCORE=analysis_mcore.o ../../asm/arch/mcore/mcore.o

STATIC_OBJ+=${OBJ_MCORE}

TARGET_MCORE=analysis_mcore.${EXT_SO}

ALL_TARGETS+=${TARGET_MCORE}

${TARGET_MCORE}: ${OBJ_MCORE}
	${CC} ${CFLAGS} $(call libname,analysis_mcore) $(CS_LDFLAGS) \
		-o analysis_mcore.${EXT_SO} ${OBJ_MCORE}
