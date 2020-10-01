OBJ_MMAP=io_mmap.o

STATIC_OBJ+=${OBJ_MMAP}
TARGET_MMAP=io_mmap.${EXT_SO}
ALL_TARGETS+=${TARGET_MMAP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_MMAP}: ${OBJ_MMAP}
	${CC_LIB} $(call libname,io_mmap) ${CFLAGS} -o ${TARGET_MMAP} ${OBJ_MMAP} ${LINKFLAGS}
