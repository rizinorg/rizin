OBJ_ZIP=io_zip.o

STATIC_OBJ+=${OBJ_ZIP}
TARGET_ZIP=io_zip.${EXT_SO}
ALL_TARGETS+=${TARGET_ZIP}

CFLAGS+=-I../../shlr/zip/include 

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L.. -lrz_io
endif
#LINKFLAGS+=../../../shlr/zip/librz.a

${TARGET_ZIP}: ${OBJ_ZIP}
	${CC_LIB} $(call libname,io_zip) ${CFLAGS} -o ${TARGET_ZIP} ${OBJS} ${LINKFLAGS}
