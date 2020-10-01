OBJ_DEFAULT=io_default.o

STATIC_OBJ+=${OBJ_DEFAULT}
TARGET_DEFAULT=io_default.${EXT_SO}
ALL_TARGETS+=${TARGET_DEFAULT}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_DEFAULT}: ${OBJ_DEFAULT}
	${CC_LIB} $(call libname,io_default) ${CFLAGS} -o ${TARGET_DEFAULT} ${OBJ_DEFAULT} ${LINKFLAGS}
