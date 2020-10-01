OBJ_X86_NZ=asm_x86_nz.o

STATIC_OBJ+=${OBJ_X86_NZ}
TARGET_X86_NZ=asm_x86_nz.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_X86_NZ}

${TARGET_X86_NZ}: ${OBJ_X86_NZ}
	${CC} $(call libname,asm_x86_nz) ${LDFLAGS} ${CFLAGS} -o ${TARGET_X86_NZ} ${OBJ_X86_NZ}
endif
