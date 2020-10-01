BIN=rz_bin
BINDEPS=rz_magic rz_core rz_bin rz_egg rz_cons rz_main
BINDEPS+=rz_config rz_io rz_flag rz_asm
BINDEPS+=rz_debug rz_hash rz_lang rz_anal rz_parse rz_bp rz_reg
BINDEPS+=rz_search rz_syscall rz_socket rz_fs rz_magic rz_crypto rz_util

include ../rules.mk

include ../../librz/socket/deps.mk
include ../../librz/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/java/deps.mk
include ../../shlr/grub/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk
include ../../shlr/capstone.mk

LDFLAGS+=$(LINK)
