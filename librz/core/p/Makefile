include ../../config.mk
include ../../../mk/platform.mk
include ../../../shlr/zip/deps.mk

CFLAGS+=-I../../include -Wall -shared
CFLAGS+=${PIC_CFLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
CFLAGS+=-L../../util -lrz_util -L../../reg -lrz_reg -L.. -lrz_core
CFLAGS+=-L../../cons -lrz_cons -L../../bin -lrz_bin
CFLAGS+=-L../../parse -lrz_parse -L../../io -lrz_io
CFLAGS+=-L../../magic -lrz_magic -L../../hash -lrz_hash
CFLAGS+=-L../../config -lrz_config
CFLAGS+=-L../../anal -lrz_anal -L../../egg -lrz_egg -L../../flag -lrz_flag
CFLAGS+=-L../../syscall -lrz_syscall -L../../socket -lrz_socket -L../../search -lrz_search
CFLAGS+= -L../../lang -lrz_lang -L../../debug -lrz_debug
CFLAGS+=-L../../bp -lrz_bp -L../../reg -lrz_reg -L../../asm -lrz_asm

LDFLAGS+=$(STOP)/sdb/src/libsdb.a

include $(STOP)/java/deps.mk
include $(STOP)/gdb/deps.mk
include $(STOP)/winkd/deps.mk

LDFLAGS+=${LINK}

ifeq ($(WITHPIC),1)
all: ${ALL_TARGETS}

ALL_TARGETS=
PLUGS=java.mk a2f.mk
include $(PLUGS)

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d

.PHONY: all clean foo mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
