CFLAGS+=-I$(SHLR)/gdb/include/
LIB_PATH=$(SHRL)/gdb/

ifeq (${OSTYPE},windows)
LDFLAGS+=-lwsock32
endif
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif

-include ../../global.mk
-include ../../../global.mk

-include $(STOP)/gdb/deps.mk
LDFLAGS+=$(LINK)
LDFLAGS+=-L$(LTOP)/util -lrz_util
LDFLAGS+=-L$(LTOP)/cons -lrz_cons
LDFLAGS+=-L$(LTOP)/parse -lrz_parse
LDFLAGS+=-L$(LTOP)/socket -lrz_socket
LDFLAGS+=-L$(LTOP)/anal -lrz_anal
LDFLAGS+=-L$(LTOP)/reg -lrz_reg
LDFLAGS+=-L$(LTOP)/bp -lrz_bp
LDFLAGS+=-L$(LTOP)/io -lrz_io

OBJ_GDB=debug_gdb.o

STATIC_OBJ+=${OBJ_GDB}
TARGET_GDB=debug_gdb.${EXT_SO}

ALL_TARGETS+=${TARGET_GDB}

${TARGET_GDB}: ${OBJ_GDB}
	${CC} $(call libname,debug_gdb) ${OBJ_GDB} ${CFLAGS} ${LDFLAGS} \
		-L.. -lrz_debug
