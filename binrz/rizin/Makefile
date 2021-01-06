BIN=rizin
BINDEPS=rz_core rz_parse rz_search rz_cons rz_config
BINDEPS+=rz_bin rz_debug rz_analysis rz_reg rz_bp rz_io
BINDEPS+=rz_lang rz_asm rz_syscall rz_hash rz_main
BINDEPS+=rz_magic rz_socket rz_flag rz_egg rz_crypto rz_util

include ../../config-user.mk

# Apple Sign #
CERTID?=org.rizinorg.rizin
BUNDLE=org.rizinorg.rizin
MACSDK=macosx10.10
ENTITL=rizin.xcent
#ENTITL=rizin_ios.xml
#CFLAGS+=-flto
#LDFLAGS+=-flto

CFLAGS_INCLUDES+=-I$(SHLR)/sdb/src
CFLAGS_INCLUDES+=-I$(LIBRZ)/include

ifeq (${COMPILER},emscripten)
# https://kripken.github.io/emscripten-site/docs/optimizing/Optimizing-Code.html
# -s INLINING_LIMIT=1
# --memory-init-file 0
CFLAGS+=-s EXPORTED_FUNCTIONS='["_r_core_new", "_r_core_free", "_r_cmd_str"]'
CFLAGS+=-s EXTRA_EXPORTED_RUNTIME_METHODS='["cwrap", "addOnInit"]'
CFLAGS+=-s TOTAL_MEMORY=33554432
CFLAGS+=-s ALLOW_MEMORY_GROWTH=1
CFLAGS+=-s ABORTING_MALLOC=0
#CFLAGS+=-Oz --memory-init-file 0
endif

FOOD_LIBS=$(addprefix ../../librz/,$(subst rz_,,$(BINDEPS)))
SIGN_LIBS=$(addsuffix /librz_*.dylib,$(FOOD_LIBS))

include ../rules.mk
#IOS_CERTID?=org.rizinorg.rizin

ios:
	$(MAKE) -C ../../librz/io
	$(MAKE) -C ../../librz/debug
	rm -f rizin
	$(MAKE)
	$(MAKE) ios-sign

ifeq ($(shell uname),Darwin)
sign: macos-sign
else
sign: ios-sign
endif

ios-sign iossign:
	xcrun --sdk iphoneos codesign \
		-s- --entitlements rizin_ios.xml rizin
	# -f -s "$$IOS_CERTID" --entitlements rizin_ios.xml rizin
	#ldid -Srizin_ios.xml rizin

ios_sdk_sign:
	-codesign -s- --entitlements rizin_ios.xml rizin

macos-sign macossign:
	rm -f rizin
	${CC} rizin.c ${CFLAGS_INCLUDES} ${CFLAGS} ${LDFLAGS} ${LINK} -o rizin \
		-sectcreate __TEXT __info_plist Info.plist \
		-framework Security -framework CoreFoundation
	#xcrun --sdk $(MACSDK) codesign -f -s ${CERTID} --entitlements rizin_macos.xml rizin
	codesign -dvvv --deep -f -s ${CERTID} -i ${BUNDLE} --entitlements rizin_macos.xml rizin
	#sudo chown root:_developer rizin
#	sudo chown root:procmod rizin
	#sudo chmod g+s rizin
#	sudo chmod 4755 rizin

macos-sign-libs:
	for LIB in ${SIGN_LIBS} ; do \
		echo Signing $$LIB ; \
		codesign -f -s ${CERTID} $$LIB ; \
	done
#	xcrun --sdk $(MACSDK) codesign -f -s ${CERTID} --entitlements $(ENTITL) rizin
#	xcrun --sdk $(MACSDK) codesign -f -s ${CERTID} rizin
#	codesign -dvvv -s $(XNUCERT) ./rizin
#	sudo chown root:procmod rizin
#	sudo chmod g+s rizin

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
LDFLAGS+=../../shlr/capstone/libcapstone.a
endif

include ../../librz/socket/deps.mk
include ../../librz/magic/deps.mk
include ../../librz/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/java/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk
include ../../shlr/yxml/deps.mk
include ../../shlr/sdb.mk
LDFLAGS+=$(LINK)
