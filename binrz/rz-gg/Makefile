BIN=rz-gg
BINDEPS=rz_egg rz_syscall rz_asm
BINDEPS+=rz_core rz_hash rz_debug rz_config rz_bp rz_crypto rz_cons
BINDEPS+=rz_lang rz_parse rz_anal rz_reg rz_flag rz_crypto
BINDEPS+=rz_bin rz_search rz_io rz_socket
BINDEPS+=rz_magic rz_util rz_main

include ../rules.mk
include ../../librz/main/deps.mk
include ../../shlr/ar/deps.mk
include ../../librz/socket/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/java/deps.mk
include ../../shlr/capstone.mk
include ../../shlr/qnx/deps.mk

LDFLAGS+=$(LINK)
