include ../../librz/config.mk
include ../../config-user.mk
include ../../mk/platform.mk
include ../../mk/${COMPILER}.mk

CFLAGS+=${PIC_CFLAGS}

ifneq (,$(findstring cygwin,${OSTYPE}))
CFLAGS+=-D__CYGWIN__=1
EXT_SO=dll
SOVER=${EXT_SO}
LDFLAGS+=-shared
LDFLAGS_SHARED?=-shared
else
ifneq (,$(findstring mingw32,${OSTYPE}))
CFLAGS+=-DMINGW32=1
EXT_SO=dll
SOVER=${EXT_SO}
LDFLAGS+=-shared
LDFLAGS_SHARED?=-shared
else
ifneq (,$(findstring mingw64,${OSTYPE})$(findstring msys,${OSTYPE}))
LDFLAGS+=-shared
LFDLAGS_SHARE?=-shared
endif
endif
endif

CFLAGS+=-I../../librz/include
LIBAR=librz_ar.${EXT_AR}
LDFLAGS+=-L../../librz/util
LIBS=-lrz_util

include ../../shlr/sdb.mk

OFILES=ar.o

all: ${LIBAR}

%.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

${LIBAR}: $(OFILES)
	rm -f $(LIBAR)
	$(AR) q $(LIBAR) $(OFILES)
	$(RANLIB) $(LIBAR)

clean:
	rm -f $(OBJS) ${LIBAR} $(OFILES)
