OBJ_TCP=io_tcp.o

STATIC_OBJ+=${OBJ_TCP}
TARGET_TCP=io_tcp.${EXT_SO}
ALL_TARGETS+=${TARGET_TCP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
LINKFLAGS+=../../io/librz_socket.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L../../socket -lrz_socket
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_TCP}: ${OBJ_TCP}
	${CC_LIB} $(call libname,io_tcp) ${CFLAGS} -o ${TARGET_TCP} ${OBJ_TCP} ${LINKFLAGS}
