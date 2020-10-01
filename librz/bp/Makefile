include ../config.mk

NAME=rz_bp
R2DEPS+=rz_util

CFLAGS+=-DR2_PLUGIN_INCORE

.PHONY: pre
pre: librz_bp.${EXT_SO} librz_bp.${EXT_AR}
	${MAKE} -C p

include ${STATIC_BP_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst bp_,p/bp_,$(STATIC_OBJ)))
OBJS=bp.o bp_watch.o bp_io.o bp_plugin.o bp_traptrace.o ${STATIC_OBJS}

include ../rules.mk
