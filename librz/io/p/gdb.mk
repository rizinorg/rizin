OBJ_GDB=io_gdb.o

STATIC_OBJ+=${OBJ_GDB}
TARGET_GDB=io_gdb.${EXT_SO}
ALL_TARGETS+=${TARGET_GDB}

LIB_PATH=$(SHLR)/gdb/
CFLAGS+=-I$(SHLR)/gdb/include/
LDFLAGS+=$(SHLR)/gdb/lib/libgdbr.$(EXT_AR)

include $(LIBR)/socket/deps.mk

ifeq (${WITHPIC},0)
LINKFLAGS=../../socket/librz_socket.a
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../cons/librz_cons.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS=-L../../socket -lrz_socket
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L../../cons -lrz_cons
LINKFLAGS+=-L.. -lrz_io
endif
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LINKFLAGS+=${SSL_LDFLAGS}
endif

${TARGET_GDB}: ${OBJ_GDB}
	${CC} $(call libname,io_gdb) ${OBJ_GDB} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
