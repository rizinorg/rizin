include ../../global.mk
include $(LTOP)/config.mk

NAME=rz_magic
RZ_DEPS=rz_util
PCLIBS=@LIBMAGIC@
CFLAGS+=-I.
OBJS=apprentice.o ascmagic.o fsmagic.o funcs.o is_tar.o magic.o softmagic.o

include deps.mk

include $(LTOP)/rules.mk

libfile.a:
	${CC} -c ${CFLAGS} ${SRC}
	${AR} q libfile.a *.o
	${RANLIB} libfile.a

BIN=file${EXT_EXE}
${BIN}:
	${CC} -I../include ${CFLAGS} ${SRC} file.c -o ${BIN}
