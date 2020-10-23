include ../config.mk

NAME=rz_io
RZ_DEPS+=rz_util
RZ_DEPS+=rz_socket
RZ_DEPS+=rz_hash
RZ_DEPS+=rz_cons
RZ_DEPS+=rz_crypto
STATIC_OBJS=$(subst ..,p/..,$(subst io_,p/io_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS}
OBJS+=io.o io_plugin.o io_map.o io_desc.o io_cache.o p_cache.o undo.o ioutils.o io_fd.o

CFLAGS+=-Wall -DRZ_PLUGIN_INCORE

include ../socket/deps.mk
include $(SHLR)/ar/deps.mk
include $(SHLR)/zip/deps.mk
include $(SHLR)/gdb/deps.mk
include $(SHLR)/qnx/deps.mk

ifeq ($(USE_PTRACE_WRAP),1)
include $(SHLR)/ptrace-wrap/deps.mk
OBJS+=$(PTRACEWRAP_OBJS)
endif

## only for shm_open
#ifeq (${OSTYPE},gnulinux)
#  LDFLAGS+=-lrt
#endif

ifeq (${BUILD_OS},dragonfly)
  LDFLAGS+=-lkvm
endif

.PHONY: pre
pre: librz_io.${EXT_SO} librz_io.${EXT_AR}
	@${MAKE} -C p

include ${STATIC_IO_PLUGINS}
include $(LTOP)/rules.mk
