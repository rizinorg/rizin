include ../../config-user.mk
BIN=rz_agent
BINDEPS=rz_socket rz_cons rz_util rz_main

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
endif
include ../../librz/main/deps.mk

include ../rules.mk

LDFLAGS+=$(LINK)
