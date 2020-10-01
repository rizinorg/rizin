OBJ_BOCHS=io_bochs.o

STATIC_OBJ+=${OBJ_BOCHS}
TARGET_BOCHS=io_bochs.${EXT_SO}
ALL_TARGETS+=${TARGET_BOCHS}

LIB_PATH=$(SHLR)/bochs/
CFLAGS+=-I$(SHLR)/bochs/include/
LDFLAGS+=$(SHLR)/bochs/lib/libbochs.$(EXT_AR)

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

${TARGET_BOCHS}: ${OBJ_BOCHS}
	${CC} $(call libname,io_bochs) ${OBJ_BOCHS} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
