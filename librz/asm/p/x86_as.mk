OBJ_X86_AS=asm_x86_as.o

STATIC_OBJ+=${OBJ_X86_AS}
TARGET_X86_AS=asm_x86_as.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_X86_AS}

${TARGET_X86_AS}: ${OBJ_X86_AS}
	${CC} $(call libname,asm_x86_nasm) ${LDFLAGS} ${CFLAGS} -o ${TARGET_X86_AS} ${OBJ_X86_AS}
endif
