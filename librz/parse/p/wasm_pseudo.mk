OBJ_WASMPSEUDO+=parse_wasm_pseudo.o

TARGET_WASMPSEUDO=parse_wasm_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_WASMPSEUDO}

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
ALL_TARGETS+=${TARGET_WASMPSEUDO}
${TARGET_WASMPSEUDO}: ${OBJ_WASMPSEUDO}
	${CC} $(call libname,parse_wasm_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_WASMPSEUDO} ${OBJ_WASMPSEUDO}
endif
