include ../config.mk

NAME=rz_core

RZ_DEPS=rz_config rz_cons rz_io rz_util rz_flag rz_asm
RZ_DEPS+=rz_debug rz_hash rz_bin rz_lang rz_io rz_analysis rz_parse rz_bp rz_egg
RZ_DEPS+=rz_reg rz_search rz_syscall rz_socket rz_magic rz_crypto

OBJS=core.o cmd.o cfile.o cconfig.o visual.o cio.o yank.o libs.o agraph.o
OBJS+=fortune.o hack.o vasm.o cbin.o rtr.o cmd_api.o cmd_descs.o cdebug.o
OBJS+=carg.o canalysis.o cautocmpl.o project.o gdiff.o casm.o disasm.o cplugin.o
OBJS+=vmenus.o vmenus_graph.o vmenus_zigns.o zdiff.o
OBJS+=task.o panels.o vmarks.o analysis_tp.o analysis_objc.o blaze.o
OBJS+=cannotated_code.o serialize_core.o seek.o

CFLAGS+=-I../../shlr/heap/include
CFLAGS+=-I../../shlr/tree-sitter/lib/include -I../../shlr/rizin-shell-parser/src/tree_parser
CFLAGS+=-DRZ_PLUGIN_INCORE -I../../shlr
LDFLAGS+=${DL_LIBS}
LDFLAGS+=${CLOCK_LDFLAGS}

ifeq ($(shell uname),OpenBSD)
LDFLAGS+=-lpthread
endif

ifeq ($(USE_LIB_MAGIC),1)
LDFLAGS+=${LIBMAGIC}
endif

ifeq ($(HAVE_LIBUV),1)
CFLAGS+=${LIBUV_CFLAGS}
LDFLAGS+=${LIBUV_LDFLAGS}
endif

first:: all

include ${STATIC_CORE_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/core/p/,$(STATIC_OBJ))
OBJS+=$(STATIC_OBJS)

include $(TOP)/shlr/gdb/deps.mk
include $(TOP)/shlr/rizin-shell-parser-deps.mk
include $(LTOP)/rules.mk

cmd.o: cmd_hash.c cmd_debug.c cmd_zign.c cmd_project.c \
	cmd_open.c cmd_meta.c cmd_macro.c cmd_magic.c cmd_eval.c \
	cmd_seek.c cmd_print.c cmd_help.c cmd_analysis.c cmd_search.c cmd_plugins.c \
	cmd_cmp.c cmd_write.c cmd_egg.c cmd_info.c cmd_type.c cmd_flag.c \
	cmd_search_rop.c

rtr.o: rtr_http.c rtr_shell.c
