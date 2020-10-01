OBJ_Z80=asm_z80.o

STATIC_OBJ+=${OBJ_Z80}
TARGET_Z80=asm_z80.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_Z80}

${TARGET_Z80}: ${OBJ_Z80}
	${CC} $(call libname,asm_z80) ${LDFLAGS} ${CFLAGS} -o ${TARGET_Z80} ${OBJ_Z80}
endif
