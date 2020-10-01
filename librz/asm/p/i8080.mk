OBJ_i8080=asm_i8080.o

STATIC_OBJ+=${OBJ_i8080}
TARGET_i8080=asm_i8080.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_i8080}

${TARGET_i8080}: ${OBJ_i8080}
	${CC} $(call libname,asm_i8080) ${LDFLAGS} ${CFLAGS} -o ${TARGET_i8080} ${OBJ_i8080}
endif
