OBJ_IODBG=io_debug.o

STATIC_OBJ+=${OBJ_IODBG}
TARGET_IODBG=io_debug.${EXT_SO}

ALL_TARGETS+=${TARGET_IODBG}


ifeq (${WITHPIC},0)
LINKFLAGS=../../socket/librz_socket.a
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS=-L../../socket -lrz_socket
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L.. -lrz_io 
endif
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LINKFLAGS+=${SSL_LDFLAGS}
endif

${TARGET_IODBG}: ${OBJ_IODBG}
	${CC} $(call libname,io_debug) ${CFLAGS} ${LDFLAGS_LIB} $(LDFLAGS) \
		${LINKFLAGS} ${LDFLAGS_LINKPATH}.. ${OBJ_IODBG} -L.. -lrz_io
