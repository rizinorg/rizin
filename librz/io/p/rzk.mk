OBJ_RZK = io_rzk.o
ifeq ($(OSTYPE),$(filter $(OSTYPE),gnulinux android))
OBJ_RZK += io_rzk_linux.o
endif
ifeq (${OSTYPE},$(filter $(OSTYPE),windows mingw32 mingw64 cygwin))
OBJ_RZK += io_rzk_windows.o
endif

STATIC_OBJ+=${OBJ_RZK}
TARGET_RZK=io_rzk.${EXT_SO}
ALL_TARGETS+=${TARGET_RZK}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/librz_util.a
LINKFLAGS+=../../io/librz_io.a
else
LINKFLAGS+=-L../../util -lrz_util
LINKFLAGS+=-L.. -lrz_io
endif

${TARGET_RZK}: ${OBJ_RZK}
	${CC} $(call libname,io_rzk) ${CFLAGS} -o ${TARGET_RZK} ${OBJ_RZK} ${LINKFLAGS}
