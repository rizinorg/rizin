OBJ_X86=asm_gas.o

STATIC_OBJ+=${OBJ_X86}
TARGET_X86=asm_gas.${EXT_SO}

ALL_TARGETS+=${TARGET_X86}

${TARGET_X86}: ${OBJ_X86}
	${CC} $(call libname,asm_gas) ${LDFLAGS} ${CFLAGS} -o ${TARGET_X86} ${OBJ_X86}
