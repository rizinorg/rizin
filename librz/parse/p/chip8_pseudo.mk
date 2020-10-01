OBJ_CHIP8PSEUDO+=parse_chip8_pseudo.o

TARGET_CHIP8PSEUDO=parse_chip8_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_CHIP8PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibrz_util
LIBDEPS+=-L../../flag -llibrz_flag
else
LIBDEPS=-L../../util -lrz_util
LIBDEPS+=-L../../flag -lrz_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_CHIP8PSEUDO}
${TARGET_CHIP8PSEUDO}: ${OBJ_CHIP8PSEUDO}
	${CC} $(call libname,parse_chip8_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_CHIP8PSEUDO} ${OBJ_CHIP8PSEUDO}
endif
