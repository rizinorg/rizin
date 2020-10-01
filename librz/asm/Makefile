include ../../global.mk

NAME=rz_asm
R2DEPS=rz_syscall rz_lang rz_util rz_parse
R2DEPS+=rz_flag rz_cons rz_reg
CFLAGS+=-DR2_PLUGIN_INCORE -Iarch/include -Iarch -I../../shlr
CURDIR=p/

include $(TOP)/librz/config.mk

include p/capstone.mk
LDFLAGS+=${CS_LDFLAGS}
include $(STOP)/java/deps.mk
include $(STOP)/capstone.mk

.PHONY: all plugins

EXTRA_CLEAN=doclean

all: plugins

doclean:
	@cd d && ${MAKE} clean
	@cd p && ${MAKE} clean
	rm -f `find arch/| grep '\.o$$'`

plugins: ${LIBSO} ${LIBAR}
	${MAKE} -C d all
	${MAKE} -C p all

include ${STATIC_ASM_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst asm_,p/asm_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS} asm.o acode.o aop.o
OBJS+=${SHARED2_OBJ}

include $(TOP)/librz/rules.mk
