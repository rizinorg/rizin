#include ../../config.mk
#BINDEPS=rz_reg rz_bp rz_util rz_io rz_anal

CFLAGS+=-I$(SHLR)/qnx/include/
LIB_PATH=$(SHRL)/qnx/

ifeq (${OSTYPE},windows)
LDFLAGS+=-lwsock32
endif
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif

-include ../../global.mk
-include ../../../global.mk

-include $(STOP)/qnx/deps.mk

LDFLAGS+=-L$(LTOP)/util -lrz_util
LDFLAGS+=-L$(LTOP)/cons -lrz_cons
LDFLAGS+=-L$(LTOP)/parse -lrz_parse
LDFLAGS+=-L$(LTOP)/anal -lrz_anal
LDFLAGS+=-L$(LTOP)/reg -lrz_reg
LDFLAGS+=-L$(LTOP)/bp -lrz_bp
LDFLAGS+=-L$(LTOP)/io -lrz_io

OBJ_QNX=debug_qnx.o

STATIC_OBJ+=${OBJ_QNX}
TARGET_QNX=debug_qnx.${EXT_SO}

ALL_TARGETS+=${TARGET_QNX}

${TARGET_QNX}: ${OBJ_QNX}
	${CC} $(call libname,debug_qnx) ${OBJ_QNX} ${CFLAGS} ${LDFLAGS}
