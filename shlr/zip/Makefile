NAME=rz
LIBAR=librz.$(EXT_AR)

include ../../config-user.mk
include ../../librz/config.mk
include ../../mk/platform.mk
include ../../mk/$(COMPILER).mk
include ../../shlr/sdb.mk

ifeq ($(USE_LIB_ZIP),1)
all:
	rm -f librz.$(EXT_AR)
else

LIBAR=librz.$(EXT_AR)
RANLIB?=ranlib

all: $(LIBAR)

$(LIBAR): zip/librz_zip.$(EXT_AR)
	@echo ${CC_AR} zlib/*.o zip/*.o
	${CC_AR} zlib/*.o zip/*.o
	@echo $(RANLIB) librz.$(EXT_AR)
	$(RANLIB) librz.$(EXT_AR)

zip/librz_zip.$(EXT_AR): zlib/librz_z.$(EXT_AR)
	$(MAKE) -C zip

zlib/librz_z.$(EXT_AR):
	$(MAKE) -C zlib

clean:
	$(MAKE) -C zlib clean
	$(MAKE) -C zip clean
	rm -f *.$(EXT_AR) *.${EXT_SO} zlib/*.$(EXT_AR) zip/*.$(EXT_AR)
endif
