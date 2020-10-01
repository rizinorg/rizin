OBJ_8051=asm_8051.o
OBJ_8051+=../arch/8051/8051_disas.o
OBJ_8051+=../arch/8051/8051_ass.o
CFLAGS+=-I./arch/8051/

STATIC_OBJ+=${OBJ_8051}
TARGET_8051=asm_8051.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_8051}

${TARGET_8051}: ${OBJ_8051}
	${CC} $(call libname,asm_8051) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_8051} ${OBJ_8051}
endif
