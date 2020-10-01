BIN=rz-find

BINDEPS=rz_search rz_io rz_asm rz_anal rz_reg rz_cons rz_lang rz_crypto
BINDEPS+=rz_socket rz_parse rz_util rz_syscall rz_flag rz_hash rz_main

include ../rules.mk

include ../../librz/socket/deps.mk
include ../../librz/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk
LDFLAGS+=$(LINK)
