BIN=rz-diff

BINDEPS=rz_core rz_config rz_cons rz_search rz_anal
BINDEPS+=rz_bin rz_debug rz_io rz_asm rz_hash rz_fs rz_crypto
BINDEPS+=rz_socket rz_flag rz_lang rz_reg rz_bp rz_parse
BINDEPS+=rz_syscall rz_magic rz_util rz_parse rz_egg rz_main

include ../rules.mk

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
endif

include ../../librz/socket/deps.mk
include ../../librz/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk

LDFLAGS+=$(LINK)
