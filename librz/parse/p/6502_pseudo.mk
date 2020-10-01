OBJ_6502PSEUDO+=parse_6502_pseudo.o

TARGET_6502PSEUDO=parse_6502_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_6502PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibrz_util
LIBDEPS+=-L../../flag -llibrz_flag
else
LIBDEPS=-L../../util -lrz_util
LIBDEPS+=-L../../flag -lrz_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_6502PSEUDO}
${TARGET_6502PSEUDO}: ${OBJ_6502PSEUDO}
	${CC} $(call libname,parse_6502_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_6502PSEUDO} ${OBJ_6502PSEUDO}
endif
