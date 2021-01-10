ifeq ($(OSTYPE),auto)
OSTYPE=$(shell uname | tr 'A-Z' 'a-z')
endif
ifneq (,$(findstring windows,${OSTYPE}))
PIC_CFLAGS=
CFLAGS+=-DUNICODE -D_UNICODE
else
PIC_CFLAGS=-fPIC
endif
