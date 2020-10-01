OBJ_M68KPSEUDO+=parse_m68k_pseudo.o

TARGET_M68KPSEUDO=parse_m68k_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_M68KPSEUDO}
STATIC_OBJ+=${OBJ_M68KPSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibrz_util
LIBDEPS+=-L../../flag -llibrz_flag
else
LIBDEPS=-L../../util -lrz_util
LIBDEPS+=-L../../flag -lrz_flag
endif

include $(STOP)/zip/deps.mk

${TARGET_M68KPSEUDO}: ${OBJ_M68KPSEUDO}
	${CC} $(call libname,parse_m68k_pseudo) ${LIBDEPS} \
		${LDFLAGS_SHARED} ${CFLAGS} -o ${TARGET_M68KPSEUDO} ${OBJ_M68KPSEUDO} $(LINK)
