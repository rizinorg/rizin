BINR_PROGRAM=1
include ../../librz/config.mk
include ../../shlr/zip/deps.mk
include ../../shlr/sdb.mk

ifeq (,$(findstring tcc,${CC}))
CFLAGS+=-pie
endif
CFLAGS+=-I$(LTOP)/include

ifeq (${COMPILER},emscripten)
LINK+=$(SHLR)/librz_shlr.a
LINK+=$(SHLR)/sdb/src/libsdb.a
include $(SHLR)/capstone.mk
CFLAGS+= -s SIDE_MODULE=1
#CFLAGS+=-s ERROR_ON_UNDEFINED_SYMBOLS=0
#EXT_EXE=.js
#EXT_EXE=.html
EXT_EXE=.bc
#EXT_EXE=.wasm
endif

ifeq ($(USE_RPATH),1)
LDFLAGS+=-Wl,-rpath "${LIBDIR}"
endif

OBJ+=${BIN}.o
BEXE=${BIN}${EXT_EXE}

LDFLAGS+=${DL_LIBS}
ifneq (${ANDROID},1)
ifneq (${OSTYPE},windows)
ifneq (${OSTYPE},linux)
ifneq ($(CC),cccl)
LDFLAGS+=-lpthread
endif
endif
endif
endif

REAL_LDFLAGS=$(subst -shared,,$(LDFLAGS))

ifeq ($(ISLIB),1)
BEXE=$(BIN).$(EXT_SO)
REAL_LDFLAGS+=-shared
endif
#--------------------#
# Rules for programs #
#--------------------#

LDFLAGS+=-lm
# For some reason w32 builds contain -shared in LDFLAGS. boo!

ifneq ($(BIN)$(BINS),)

ifeq ($(OSTYPE),linux)
LDFLAGS+=-static
endif

all: ${BEXE} ${BINS}

ifeq ($(WITH_LIBRZ),1)
${BINS}: ${OBJS}
	${CC} ${CFLAGS} $@.c ${OBJS} ../../librz/librz.a -o $@ $(LDFLAGS)

${BEXE}: ${OBJ} ${SHARED_OBJ}
ifeq ($(CC),emcc)
	emcc $(BIN).c ../../shlr/librz_shlr.a ../../shlr/capstone/libcapstone.a ../../librz/librz.a ../../shlr/gdb/lib/libgdbr.a ../../shlr/zip/librz.a -I ../../librz/include -o $(BIN).js
else
	${CC} ${CFLAGS} $+ -L.. -o $@ ../../librz/librz.a $(LDFLAGS)
endif
else

${BINS}: ${OBJS}
ifneq ($(SILENT),)
	@echo CC $@
endif
	${CC} ${CFLAGS} $@.c ${OBJS} ${REAL_LDFLAGS} $(LINK) -o $@

# -static fails because -ldl -lpthread static-gcc ...
${BEXE}: ${OBJ} ${SHARED_OBJ}
ifneq ($(SILENT),)
	@echo LD $@
endif
	${CC} ${CFLAGS} $+ -L.. -o $@ $(REAL_LDFLAGS) $(LINK)
endif
endif

# Dummy myclean rule that can be overridden by the t/ Makefile
# TODO: move to config.mk ? it must be a precondition
myclean:

clean:: myclean
	-rm -f ${OBJS} ${OBJ} ${BEXE}

mrproper: clean
	-rm -f *.d

install:
	cd ../.. && ${MAKE} install

.PHONY: all clean myclean mrproper install
