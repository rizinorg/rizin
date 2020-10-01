BIN=rz-hash

BINDEPS=rz_main

include ../rules.mk

ifeq ($(OSTYPE),android)
LDFLAGS+=-lm
endif

include ../../librz/socket/deps.mk
include ../../librz/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/ar/deps.mk

LDFLAGS+=$(LINK)
