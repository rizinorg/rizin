MAIN_LINK_ALL=1

ifeq ($(MAIN_LINK_ALL),1)
R2DEPS=rz_config rz_cons rz_io rz_util rz_flag rz_asm rz_core
R2DEPS+=rz_debug rz_hash rz_bin rz_lang rz_io rz_anal rz_parse rz_bp rz_egg
R2DEPS+=rz_reg rz_search rz_syscall rz_socket rz_fs rz_magic rz_crypto
else
# only works
WITH_LIBS=0
WITH_LIBR=1
endif
