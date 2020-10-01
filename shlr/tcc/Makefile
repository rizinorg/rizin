include ../../librz/config.mk
include ../../config-user.mk
include ../../mk/platform.mk
include ../../mk/${COMPILER}.mk
OFILES=libtcc.o tccgen.o tccpp.o

CFLAGS+=${PIC_CFLAGS}

LDFLAGS+=-L../../librz/util
LIBS+=-lrz_util
CFLAGS+=-I../../librz/include

CFLAGS+=-fstrict-aliasing
CFLAGS+=-I../../librz/include
CFLAGS+=-Wall -g
LDFLAGS+=-shared
ifeq (${OSNAME},darwin)
SOEXT?=dylib
else
ifeq ($(CC),cccl)
EXT_AR=lib
SOEXT?=dll
else
EXT_AR=a
SOEXT?=so
endif
endif
LIBNAME=librz_tcc.${SOEXT}

include ../../shlr/sdb.mk

all: ${LIBNAME} librz_tcc.$(EXT_AR)

${LIBNAME}: ${OFILES}
	${CC} $(CFLAGS) -o ${LIBNAME} ${LDFLAGS} ${LIBS} ${OFILES}

librz_tcc.$(EXT_AR): ${OFILES}
	rm -f librz_tcc.$(EXT_AR)
	${AR} q librz_tcc.$(EXT_AR) ${OFILES}
	${RANLIB} librz_tcc.$(EXT_AR)

clean:
	rm -f ${LIBNAME} *.o *.$(EXT_AR)
