CFLAGS+=-I$(SHLR)/winkd/
LIB_PATH=$(SHLR)/winkd/

-include ../../global.mk
-include ../../../global.mk
LDFLAGS+=-L$(LTOP)/util -lrz_util
LDFLAGS+=-L$(LTOP)/cons -lrz_cons
LDFLAGS+=-L$(LTOP)/parse -lrz_parse
LDFLAGS+=-L$(LTOP)/anal -lrz_anal
LDFLAGS+=-L$(LTOP)/reg -lrz_reg
LDFLAGS+=-L$(LTOP)/bp -lrz_bp
LDFLAGS+=-L$(LTOP)/io -lrz_io

include $(STOP)/winkd/deps.mk

OBJ_WINKD=debug_winkd.o

STATIC_OBJ+=${OBJ_WINKD}
TARGET_WINKD=debug_winkd.${EXT_SO}

ALL_TARGETS+=${TARGET_WINKD}

${TARGET_WINKD}: ${OBJ_WINKD}
	${CC} $(call libname,debug_winkd) ${OBJ_WINKD} ${CFLAGS} ${LDFLAGS}
