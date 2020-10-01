OBJ_MACH=io_mach.o

STATIC_OBJ+=${OBJ_MACH}
TARGET_MACH=io_mach.${EXT_SO}
ALL_TARGETS+=${TARGET_MACH}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_MACH}: ${OBJ_MACH}
	${CC_LIB} $(call libname,io_mach) ${CFLAGS} $(LDFLAGS) \
		-o ${TARGET_MACH} ${OBJ_MACH} ${LINKFLAGS}
