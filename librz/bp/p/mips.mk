OBJ_MIPS=bp_mips.o

STATIC_OBJ+=${OBJ_MIPS}
TARGET_MIPS=bp_mips.${EXT_SO}

ALL_TARGETS+=${TARGET_MIPS}

${TARGET_MIPS}: ${OBJ_MIPS}
	${CC} $(call libname,bp_mips) ${CFLAGS} -o ${TARGET_MIPS} ${OBJ_MIPS}
