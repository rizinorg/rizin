OBJ_GZIP=io_gzip.o

STATIC_OBJ+=${OBJ_GZIP}
TARGET_GZIP=io_gzip.${EXT_SO}
ALL_TARGETS+=${TARGET_GZIP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_GZIP}: ${OBJ_GZIP}
	${CC_LIB} $(call libname,io_gzip) ${CFLAGS} -o ${TARGET_GZIP} ${OBJ_GZIP} ${LINKFLAGS}
