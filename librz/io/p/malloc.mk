OBJ_MALLOC=io_malloc.o

STATIC_OBJ+=${OBJ_MALLOC}
TARGET_MALLOC=io_malloc.${EXT_SO}
ALL_TARGETS+=${TARGET_MALLOC}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_MALLOC}: ${OBJ_MALLOC}
	${CC_LIB} $(call libname,io_malloc) ${CFLAGS} -o ${TARGET_MALLOC} \
		${LDFLAGS} ${OBJ_MALLOC} ${LINKFLAGS}
