ISPPC=$(shell uname -m | grep Power)

ifeq ($(ISPPC),)
BIN=librz
ISLIB=1
BINDEPS=rz_core rz_parse rz_search rz_cons rz_config
BINDEPS+=rz_bin rz_debug rz_anal rz_reg rz_bp rz_io
BINDEPS+=rz_lang rz_asm rz_syscall rz_hash rz_crypto
BINDEPS+=rz_magic rz_socket rz_flag rz_util rz_egg rz_fs

include ../rules.mk

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
endif
ifeq ($(OSTYPE),gnulinux)
LDFLAGS+=-Wl,-soname,librz.${EXT_SO}.${LIBVERSION}
endif
include ../../librz/socket/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk
include ../../shlr/rizin-shell-parser-deps.mk

clean::
	rm -f $(BIN).$(EXT_SO) $(BIN).o
else
all:
	@echo Cant build preloaded lib in old Macs
endif
