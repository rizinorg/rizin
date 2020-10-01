include ../config.mk

NAME=rz_egg
R2DEPS=rz_asm rz_syscall rz_util rz_parse rz_reg rz_lang
R2DEPS+=rz_flag rz_cons

OBJS=egg.o egg_lang.o
OBJS+=emit_x86.o
OBJS+=emit_arm.o
OBJS+=emit_x64.o
OBJS+=emit_trace.o
OBJS+=egg_Cfile.o

all: ${LIBSO} ${LIBAR}

P=p/
include ${STATIC_EGG_PLUGINS}
include $(STOP)/java/deps.mk

ifneq (${STATIC_OBJ},)
OBJS+=$(subst ..,${P}..,$(subst egg_,${P}egg_,$(STATIC_OBJ)))
endif

include ../rules.mk
