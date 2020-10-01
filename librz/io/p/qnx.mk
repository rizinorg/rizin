OBJ_QNX=io_qnx.o

STATIC_OBJ+=${OBJ_QNX}
TARGET_QNX=io_qnx.${EXT_SO}
ALL_TARGETS+=${TARGET_QNX}

LIB_PATH=$(SHLR)/qnx/
CFLAGS+=-I$(SHLR)/qnx/include/
LDFLAGS+=$(SHLR)/qnx/lib/libqnxr.$(EXT_AR)

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
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LINKFLAGS+=${SSL_LDFLAGS}
endif

${TARGET_QNX}: ${OBJ_QNX}
	${CC} $(call libname,io_qnx) ${OBJ_QNX} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
