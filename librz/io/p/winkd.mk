OBJ_WINKD=io_winkd.o

STATIC_OBJ+=${OBJ_WINKD}
TARGET_WINKD=io_winkd.${EXT_SO}
ALL_TARGETS+=${TARGET_WINKD}

LIB_PATH=$(SHLR)/winkd
CFLAGS+=-I$(SHLR)/winkd
LDFLAGS+=$(SHLR)/winkd/librz_winkd.$(EXT_AR)

ifeq (${WITHPIC},0)
LINKFLAGS=../../util/librz_util.a
LINKFLAGS+= ../../util/librz_socket.a
LINKFLAGS+= ../../util/librz_hash.a
LINKFLAGS+=../../util/librz_crypto.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS=-L../../util -lrz_util
LINKFLAGS+=-L../../socket -lrz_socket
LINKFLAGS+=-L../../hash -lrz_hash
LINKFLAGS+=-L../../crypto -lrz_crypto
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_WINKD}: ${OBJ_WINKD}
	${CC} $(call libname,io_winkd) ${OBJ_WINKD} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
