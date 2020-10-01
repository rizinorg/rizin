OBJ_R2PIPE=io_rzpipe.o

STATIC_OBJ+=${OBJ_R2PIPE}
TARGET_R2PIPE=io_rzpipe.${EXT_SO}
ALL_TARGETS+=${TARGET_R2PIPE}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
LINKFLAGS+=../../io/librz_socket.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L../../socket -lrz_socket
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_R2PIPE}: ${OBJ_R2PIPE}
	${CC_LIB} $(call libname,io_rzpipe) ${CFLAGS} \
		-o ${TARGET_R2PIPE} ${OBJ_R2PIPE} ${LINKFLAGS}
