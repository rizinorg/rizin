LINK+=$(STOP)/gdb/lib/libgdbr.$(EXT_AR)
LDFLAGS+=-lrz_cons
include $(LIBRZ)/socket/deps.mk
