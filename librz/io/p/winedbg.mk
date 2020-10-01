OBJ_WINEDBG=io_winedbg.o

STATIC_OBJ+=${OBJ_WINEDBG}
TARGET_WINEDBG=io_winedbg.${EXT_SO}
ALL_TARGETS+=${TARGET_WINEDBG}

include $(LIBR)/socket/deps.mk

ifeq (${WITHPIC},0)
LINKFLAGS=../../socket/librz_socket.a
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS=-L../../socket -lrz_socket
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_WINEDBG}: ${OBJ_WINEDBG}
	${CC} $(call libname,io_winedbg) ${OBJ_WINEDBG} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
