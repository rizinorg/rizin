include ../../librz/config.mk
include ../../config-user.mk
include ../../mk/platform.mk
include ../../mk/${COMPILER}.mk

CFLAGS+=${PIC_CFLAGS}

LDFLAGS+=-shared
LFDLAGS_SHARE?=-shared

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
