OBJ_X86PSEUDO+=parse_x86_pseudo.o

TARGET_X86PSEUDO=parse_x86_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_X86PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibrz_util
LIBDEPS+=-L../../flag -llibrz_flag
LDFLAGS+=-L../../reg -llibrz_reg
LDFLAGS+=-L../../cons -llibrz_cons
else
LIBDEPS=-L../../util -lrz_util
LIBDEPS+=-L../../flag -lrz_flag
LDFLAGS+=-L../../reg -lrz_reg
LDFLAGS+=-L../../cons -lrz_cons
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_X86PSEUDO}
${TARGET_X86PSEUDO}: ${OBJ_X86PSEUDO}
	${CC} $(call libname,parse_x86_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_X86PSEUDO} ${OBJ_X86PSEUDO}
endif
