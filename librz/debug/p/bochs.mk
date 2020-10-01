#include ../../config.mk
#BINDEPS=rz_reg rz_bp rz_util rz_io rz_anal

CFLAGS+=-I$(SHLR)/bochs/include/
LIB_PATH=$(SHRL)/bochs/

ifeq (${OSTYPE},windows)
LDFLAGS+=-lwsock32
endif
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif

-include ../../global.mk
-include ../../../global.mk
-include $(STOP)/bochs/deps.mk
LDFLAGS+=-L$(LTOP)/util -lrz_util
LDFLAGS+=-L$(LTOP)/cons -lrz_cons
LDFLAGS+=-L$(LTOP)/parse -lrz_parse
LDFLAGS+=-L$(LTOP)/anal -lrz_anal
LDFLAGS+=-L$(LTOP)/reg -lrz_reg
LDFLAGS+=-L$(LTOP)/bp -lrz_bp
LDFLAGS+=-L$(LTOP)/io -lrz_io

OBJ_BOCHS=debug_bochs.o

STATIC_OBJ+=${OBJ_BOCHS}
TARGET_BOCHS=debug_bochs.${EXT_SO}

ALL_TARGETS+=${TARGET_BOCHS}

${TARGET_BOCHS}: ${OBJ_BOCHS}
	${CC} $(call libname,debug_bochs) ${OBJ_BOCHS} ${CFLAGS} ${LDFLAGS}
