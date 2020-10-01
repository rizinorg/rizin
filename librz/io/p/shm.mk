OBJ_SHM=io_shm.o

STATIC_OBJ+=${OBJ_SHM}
TARGET_SHM=io_shm.${EXT_SO}
ALL_TARGETS+=${TARGET_SHM}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_SHM}: ${OBJ_SHM}
	${CC_LIB} $(call libname,io_shm) ${CFLAGS} $(LDFLAGS) \
		-o ${TARGET_SHM} ${OBJ_SHM} ${LINKFLAGS}
