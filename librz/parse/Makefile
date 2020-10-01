include ../config.mk

NAME=rz_parse
R2DEPS=rz_flag rz_util rz_syscall rz_reg
# indirect dependencies
R2DEPS+=rz_cons

LINK+=$(STOP)/tcc/librz_tcc.a
CFLAGS+=-I$(STOP)/tcc/

LINK+=$(STOP)/mpc/libmpc.a
CFLAGS+=-I$(STOP)/mpc/

include $(SHLR)/zip/deps.mk

foo:
	@for TARGET in pre librz_parse.${EXT_SO} \
	librz_parse.${EXT_AR} plugins bins ; do \
	    ${MAKE} $$TARGET ; done

CFLAGS+=-DR2_PLUGIN_INCORE
-include ${STATIC_PARSE_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst parse_,p/parse_,$(STATIC_OBJ)))
OBJS=parse.o filter.o code.o ctype.o ${STATIC_OBJS}

pre:

bins:
#	@cd t && ${MAKE} all

plugins:
	@cd p && ${MAKE} all

include ../rules.mk
