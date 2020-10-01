include ../global.mk
include config.mk
include ../config-user.mk
include ../mk/platform.mk
include ../mk/${COMPILER}.mk
include ${SHLR}/zip/deps.mk

DESTDIR:=$(DESTDIR)
PREFIX?=${PWD}/../prefix
OBJCOPY?=objcopy

S=$
B=`
PWD=$(shell pwd)

include libs.mk

.PHONY: $(LIBS)

all:
ifneq ($(LIBS0),)
	$(MAKE) $(LIBS0)
endif
ifneq ($(LIBS1),)
	$(MAKE) $(LIBS1)
endif
ifneq ($(LIBS2),)
	$(MAKE) $(LIBS2)
endif
ifneq ($(LIBS3),)
	$(MAKE) $(LIBS3)
endif
ifneq ($(LIBS4),)
	$(MAKE) $(LIBS4)
endif
ifneq ($(LIBS5),)
	$(MAKE) $(LIBS5)
endif
ifneq ($(LIBS6),)
	$(MAKE) $(LIBS6)
endif
ifneq ($(LIBS7),)
	$(MAKE) $(LIBS7)
endif
ifneq ($(LIBS8),)
	$(MAKE) $(LIBS8)
endif
ifeq ($(WITH_LIBR),1)
	$(MAKE) librz.${EXT_AR}
	$(MAKE) librz.${EXT_SO}
endif

ifeq ($(WITH_LIBR),1)

ifeq ($(CC),emcc)
MLFLAGS=
else
ifeq ($(OSTYPE),darwin)
MLFLAGS+=-install_name @rpath/librz.dylib
endif
ifeq ($(OSTYPE),ios)
MLFLAGS+=-install_name @rpath/librz.dylib
MLFLAGS+=-fembed-bitcode
endif
endif
LDFLAGS+=${SSL_LDFLAGS}
# XXX version-script only works with shlib as output
#ifeq ($(OSTYPE),linux)
#PLFLAGS+=--version-script ./ld.script
#endif
# from env: ALFLAGS+=$(ALFLAGS)

# ${PARTIALLD} $(ALFLAGS) $(MLFLAGS) $(PLFLAGS) -o .librz/$$(basename $${LIB}.a).o $${LIB}
.librz: $(wildcard */librz_*.${EXT_AR}) ../shlr/librz_shlr.${EXT_AR}
	rm -rf .librz
	mkdir -p .librz
	for LIB in $^ ; do \
		${PARTIALLD} $(ALFLAGS) $(MLFLAGS) $(PLFLAGS) -o .librz/$$(basename $${LIB}.a).o $${LIB} ; \
	done
ifeq ($(OSTYPE),linux)
	for LIB in .librz/* ; do $(OBJCOPY) --localize-hidden $$LIB ; done
endif
ifeq ($(OSTYPE),gnulinux)
	for LIB in .librz/* ; do $(OBJCOPY) --localize-hidden $$LIB ; done
endif
ifeq ($(OSTYPE),android)
	for LIB in .librz/* ; do $(OBJCOPY) --localize-hidden $$LIB ; done
endif
ifeq ($(OSTYPE),bsd)
	for LIB in .librz/* ; do $(OBJCOPY) --localize-hidden $$LIB ; done
endif

_libr.${EXT_AR}: .librz
	-${AR} -rs $@ .librz/*.o

# this code should be in do-ar-sh not inlined here..

.librz: $(wildcard */librz_*.${EXT_AR}) ../shlr/librz_shlr.${EXT_AR}
	rm -rf .librz
	mkdir -p .librz
	-for LIB in $^ ; do \
		BN=`basename $$LIB` ; \
		mkdir -p .librz/$$BN ; \
		echo "( cd .librz/$$BN ; pwd ; du -hs ../../$$LIB; ${AR} -x ../../$$LIB )" ; \
		( cd .librz/$$BN ; pwd ; du -hs ../../$$LIB; ${AR} -x ../../$$LIB ) ; \
	done

librz.${EXT_AR}: .librz
	-${AR} -rs $@ .librz/*/*.o

ifeq (1,$(WITH_GPL))
E+=../shlr/grub/libgrubfs.${EXT_AR}
endif
E+=../shlr/yxml/libyxml.${EXT_AR}
E+=../shlr/ar/librz_ar.${EXT_AR}
E+=../shlr/winkd/librz_winkd.${EXT_AR}
E+=../shlr/qnx/lib/libqnxr.${EXT_AR}
E+=../shlr/bochs/lib/libbochs.${EXT_AR}
E+=../shlr/rizin-shell-parser/libshell-parser.${EXT_AR}
E+=../shlr/tree-sitter/libtree-sitter.${EXT_AR}
#ifeq ($(COMPILER),ios-sdk)
#E+=../shlr/sdb/src/libsdb.${EXT_AR}
#endif
#ifneq ($(OSTYPE),android)
#E+=../shlr/sdb/src/libsdb.${EXT_AR}
#endif

ifeq ($(USE_CAPSTONE),1)
E+=$(CAPSTONE_LDFLAGS)
else
E+=../shlr/capstone/libcapstone.${EXT_AR}
endif

ifeq ($(OSTYPE),darwin)
librz_LDFLAGS=-dynamiclib -shared
else
librz_LDFLAGS=-shared
endif

librz.${EXT_SO}: .librz
ifeq (${COMPILER},emscripten)
	echo nothing to do here
else
	$(CC) -fvisibility=hidden $(MLFLAGS) ${LINK} ${CFLAGS} ${CPPFLAGS} ${LDFLAGS} $(librz_LDFLAGS) -o librz.${EXT_SO}  \
		.librz/*/*.o \
		../shlr/gdb/lib/libgdbr.${EXT_AR} ../shlr/java/librz_java.${EXT_AR} \
		../shlr/librz_shlr.${EXT_AR} ../shlr/mpc/libmpc.${EXT_AR} $(E) \
		../librz/util/librz_util.${EXT_AR}
endif

else

# WITH_LIBR=0

librz.${EXT_SO}:
	$(MAKE) librz.${EXT_SO} WITH_LIBR=1

librz.${EXT_AR}:
	$(MAKE) librz.${EXT_AR} WITH_LIBR=1
endif

../shlr/librz_shlr.${EXT_AR}:
	$(MAKE) -C ../shlr librz_shlr.${EXT_AR}

$(LIBS):
	@echo "DIR $@"
	@$(MAKE) -C $@

pkgcfg:
	@for lib in ${LIBS}; do $(MAKE) -C $${lib} pkgcfg; done
	$(MAKE) -C asm pkgcfg NAME=librz R2DEPS="rz_`echo ${LIBS}|sed -e 's, , rz_,g'`"
	# TODO: Magically generate librz.pc.acr here using LIBS and so :)

install-pkgconfig:
	${INSTALL_DIR} "${DESTDIR}${LIBDIR}/pkgconfig"
	for FILE in ../pkgcfg/*.pc ; do \
		rm -f "${DESTDIR}${LIBDIR}/pkgconfig/$$FILE" ; \
		${INSTALL_DATA} $$FILE "${DESTDIR}${LIBDIR}/pkgconfig" ; done

install-includes:
	@-rm -f "${DESTDIR}${INCLUDEDIR}/librz/sflib"
	@-rm -f "${DESTDIR}${INCLUDEDIR}/librz"
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/librz"
	(cd include && for FILE in *.h ; do ${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/librz" ; done)
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/librz/sflib"
	(cd include/sflib && for DIR in * ; do \
		${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/librz/sflib/$$DIR" ; \
		for FILE in $$DIR/*.h ; do \
			${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/librz/sflib/$$FILE" ; \
		done ; \
	done)
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/librz/sdb"
	(cd ../shlr/sdb/src && for FILE in *.h ; do \
		${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/librz/sdb/$$FILE" ; \
	done)
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/librz/rz_util"
	(cd include/rz_util && for FILE in * ; do \
		${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/librz/rz_util/$$FILE" ; done)
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/librz/rz_crypto"
	(cd include/rz_crypto && for FILE in * ; do \
		${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/librz/rz_crypto/$$FILE" ; done)

symstall install-symlink:
	@cd .. && \
	mkdir -p "${DESTDIR}${BINDIR}" \
		"${DESTDIR}${INCLUDEDIR}" \
		"${DESTDIR}${LIBDIR}/pkgconfig" \
		"${DESTDIR}${LIBDIR}/rizin/${VERSION}" ; \
	rm -rf "${DESTDIR}${INCLUDEDIR}/librz" && ln -fs "${PWD}/include" "${DESTDIR}${INCLUDEDIR}/librz" ; \
	rm -rf "${DESTDIR}${INCLUDEDIR}/librz/sdb" && ln -fs "${PWD}/../shlr/sdb/src" "${DESTDIR}${INCLUDEDIR}/librz/sdb" ; \
	$(MAKE) install-pkgconfig-symlink ; \
	$(foreach lib,${LIBS}, \
	  ln -fs "${PWD}/$(lib)/librz_$(lib).${EXT_SO}" \
		"${DESTDIR}${LIBDIR}/librz_$(lib).${EXT_SO}" ; \
	  ln -fs "${PWD}/$(lib)/librz_$(lib).${EXT_SO}" \
		"${DESTDIR}${LIBDIR}/$(call libname-version,librz_$(lib).${EXT_SO},${LIBVERSION})" ; \
	  ln -fs "${PWD}/$(lib)/librz_$(lib).${EXT_AR}" "${DESTDIR}${LIBDIR}/librz_$(lib).${EXT_AR}" ; \
	  $(foreach module,$(wildcard $(lib)/p/*.${EXT_SO}), \
	    ln -fs "${PWD}/$(module)" "${DESTDIR}${LIBDIR}/rizin/${VERSION}/" ; \
	  ) \
	) \
	cd "${DESTDIR}${LIBDIR}/rizin" ; rm -f last ; ln -fs "${VERSION}" last

install: install-includes install-pkgconfig
	# TODO :Use INSTALL_DATA_DIR instead of mkdir
	# libraries
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}"
	@$(foreach lib,$(shell find * -type f -iname "*.${EXT_SO}" | grep -vE '^librz\.${EXT_SO}$$' | grep -v '(lib|parse)/t/' | grep lib | grep -v /bin/ | grep -v /p/), \
	  echo " ${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION})"; \
	  rm -f "${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION})"; \
	  ${INSTALL_LIB} "$(lib)" "${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION})"; \
	  ( cd "${DESTDIR}${LIBDIR}" ; ln -fs "$(call libpath-to-name-version,$(lib),${LIBVERSION})" "$(call libpath-to-name,$(lib))" ) ; \
	)
	lib=librz.$(EXT_SO) ; if [ -f "$$lib" ]; then \
	  ${INSTALL_LIB} "$$lib" "${DESTDIR}${LIBDIR}/$$lib"; \
	fi
	# object archives
	@for FILE in `find * -type f -iname "*.${EXT_AR}" | grep -v fs/p` ; do \
	  echo " ${DESTDIR}${LIBDIR}/$$FILE"; ${INSTALL_DATA} $$FILE "${DESTDIR}${LIBDIR}" ; done || true
	# plugins
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}/rizin/${VERSION}"
	@for FILE in `find */p -perm -u+x -type f | grep -v exe | grep -v dll | grep ${EXT_SO}`; \
	  do echo " ${DESTDIR}${LIBDIR}/rizin/${VERSION}/$$FILE"; \
	  ${INSTALL_LIB} "$$FILE" "${DESTDIR}${LIBDIR}/rizin/${VERSION}" ; done
	cd "${DESTDIR}${LIBDIR}/rizin" ; ln -fs "${VERSION}" last

deinstall uninstall:
	# libraries
	-@for FILE in `find * | grep -e '\.${EXT_SO}$$' | grep -v 'lib/t' | grep lib` ; do \
	FILE=`echo $$FILE | awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${LIBDIR}/$$FILE" ; rm -f "${DESTDIR}${LIBDIR}/$$FILE" ; done
	# object archives
	-@for FILE in `find * | grep -e '\.${EXT_AR}$$'` ; do \
	FILE=`echo $$FILE | awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${LIBDIR}/$$FILE" ; rm -f "${DESTDIR}${LIBDIR}/$$FILE" ; done
	# includes
	-if [ -h "${DESTDIR}${INCLUDEDIR}/librz" ]; then \
		rm -f "${DESTDIR}${INCLUDEDIR}/librz" ; \
	else \
		(cd include && for FILE in * ; do rm -f "${DESTDIR}${INCLUDEDIR}/librz/$$FILE" ; done) ; \
	fi
	# programs
	-@for FILE in `find */t -perm -u+x -type f | grep 2`; do \
	FILE=`echo $$FILE|awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${BINDIR}/$$FILE" ; rm -f "${DESTDIR}${BINDIR}/$$FILE" ; done
	# plugins
	-@for FILE in `find */p -perm -u+x -type f`; do \
	FILE="${DESTDIR}${LIBDIR}/rizin/${VERSION}/`echo $$FILE|awk -F / '{ print $$NF; }'`"; \
	echo $$FILE ; rm -f $$FILE ; done
	rm -rf "${DESTDIR}${LIBDIR}/rizin/${VERSION}"
	rm -f "${DESTDIR}${LIBDIR}/pkgconfig/librz.pc"
	rm -f "${DESTDIR}${LIBDIR}/pkgconfig/rz_"*.pc
	# test programs
	rm -rf "${DESTDIR}${BINDIR}/librz-test"
	# TODO: use for FILE in LIBS (like in binrz/Makefile)
	rm -rf "${DESTDIR}${INCLUDEDIR}/librz"
	rm -rf "${DESTDIR}${LIBDIR}/librz_*.so.${LIBVERSION}"
	rm -rf "${DESTDIR}${LIBDIR}/librz_*.so.0"
	rm -rf "${DESTDIR}${LIBDIR}/librz_*.so"
	rm -rf "${DESTDIR}${LIBDIR}/librz_*.${EXT_AR}"
	rm -rf "${DESTDIR}${LIBDIR}/librz.so"*
	rm -rf "${DESTDIR}${LIBDIR}/librz.${EXT_AR}"
	rm -rf "${DESTDIR}${LIBDIR}/librz.so"*
	rm -rf "${DESTDIR}${LIBDIR}/librz.${EXT_AR}"
	rm -rf "${DESTDIR}${DATADIR}/doc/rizin"
	@echo librz aka rizin has been uninstalled from PREFIX=${DESTDIR}${PREFIX}

clean:
	for LIB in ${LIBS}; do ( cd $${LIB} && $(MAKE) clean ); done
	rm -rf .librz librz.${LIB_SO} librz.${LIB_AR}

mrproper:
	rm -rf .librz librz.${LIB_SO} librz.${LIB_AR}
	for LIB in ${LIBS}; do ( cd $${LIB} && $(MAKE) mrproper ); done

.PHONY: sloc mrproper clean pkgcfg install deinstall uninstall librz
.PHONY: install-includes install-pkgconfig install-symlink all
