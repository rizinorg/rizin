include ../../librz/config.mk
include ../../config-user.mk
include ../../mk/platform.mk
include ../../mk/${COMPILER}.mk

CFLAGS+=${PIC_CFLAGS}

CFLAGS+=-I../../librz/include
LIBAR=librz_winkd.${EXT_AR}
LDFLAGS+=-L../../librz/crypto  -lrz_crypto
LDFLAGS+=-L../../librz/hash -lrz_hash
LDFLAGS+=-L../../librz/socket -lrz_socket
LDFLAGS+=-L../../librz/util -lrz_util

include ../../shlr/sdb.mk

OFILES=transport.o kd.o winkd.o iob_pipe.o iob_net.o

all: ${LIBAR}

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

${LIBAR}: $(OFILES)
	rm -f ${LIBAR}
	${AR} q ${LIBAR} ${OFILES}
	${RANLIB} ${LIBAR}

clean:
	rm -f $(OBJS) ${LIBAR} $(OFILES)
