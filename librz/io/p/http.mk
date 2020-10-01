OBJ_HTTP=io_http.o

STATIC_OBJ+=${OBJ_HTTP}
TARGET_HTTP=io_http.${EXT_SO}
ALL_TARGETS+=${TARGET_HTTP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
LINKFLAGS+=../../io/librz_socket.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L../../socket -lrz_socket
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_HTTP}: ${OBJ_HTTP}
	${CC_LIB} $(call libname,io_http) ${CFLAGS} -o ${TARGET_HTTP} ${OBJ_HTTP} ${LINKFLAGS}
