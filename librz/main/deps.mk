MAIN_LINK_ALL=1

ifeq ($(MAIN_LINK_ALL),1)
RZ_DEPS=rz_config rz_cons rz_io rz_util rz_flag rz_asm rz_core
RZ_DEPS+=rz_debug rz_hash rz_bin rz_lang rz_io rz_analysis rz_parse rz_bp rz_egg
RZ_DEPS+=rz_reg rz_search rz_syscall rz_socket rz_magic rz_crypto
else
# only works
WITH_LIBS=0
WITH_LIBRZ=1
endif
