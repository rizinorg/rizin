OBJ_BFDBG=io_bfdbg.o

STATIC_OBJ+=${OBJ_BFDBG}
TARGET_BFDBG=io_bfdbg.${EXT_SO}
ALL_TARGETS+=${TARGET_BFDBG}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../cons/librz_cons.a
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L../../cons -lrz_cons
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_BFDBG}: ${OBJ_BFDBG}
	${CC_LIB} ../debug/p/bfvm.c $(call libname,io_bfdbg) ${CFLAGS} -o ${TARGET_BFDBG} ${OBJ_BFDBG} ${LINKFLAGS}
