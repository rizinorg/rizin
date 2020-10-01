OBJ_R2WEB=io_rzweb.o

STATIC_OBJ+=${OBJ_R2WEB}
TARGET_R2WEB=io_rzweb.${EXT_SO}
ALL_TARGETS+=${TARGET_R2WEB}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
LINKFLAGS+=../../io/librz_socket.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L../../socket -lrz_socket
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_R2WEB}: ${OBJ_R2WEB}
	${CC_LIB} $(call libname,io_rzweb) ${CFLAGS} -o ${TARGET_R2WEB} ${OBJ_R2WEB} ${LINKFLAGS}
