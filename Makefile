-include config-user.mk
include global.mk

PREVIOUS_RELEASE=`git log --tags --simplify-by-decoration --pretty='format:%d'|head -n1|cut -d ' ' -f3 |sed -e 's,),,'`

B=$(DESTDIR)$(BINDIR)
L=$(DESTDIR)$(LIBDIR)
MESON?=meson
PYTHON?=python
R2R=test
R2BINS=$(shell cd binrz ; echo r*2 rz_agent rz-pm r2-indent rz_test)
ifdef SOURCE_DATE_EPOCH
BUILDSEC=$(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "+__%H:%M:%S" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "+__%H:%M:%S" 2>/dev/null || date -u "+__%H:%M:%S")
else
BUILDSEC=$(shell date "+__%H:%M:%S")
endif
DATADIRS=librz/cons/d librz/flag/d librz/bin/d librz/asm/d librz/syscall/d librz/magic/d librz/anal/d
USE_ZIP=YES
ZIP=zip

R2VC=$(shell git rev-list --all --count 2>/dev/null)
ifeq ($(R2VC),)
# release
R2VC=0
endif

STRIP?=strip
ifneq ($(shell xz --help 2>/dev/null | grep improve),)
TAR=tar -cvf
TAREXT=tar.xz
CZ=xz -f
else
TAR=bsdtar cvf
TAREXT=tar.gz
CZ=gzip -f
endif
PWD=$(shell pwd)

# For echo without quotes
Q='
ESC=
ifeq ($(BUILD_OS),windows)
ifeq ($(OSTYPE),mingw32)
ifneq (,$(findstring mingw32-make,$(MAKE)))
ifneq ($(APPVEYOR),True)
	Q=
	ESC=^
	LC_ALL=C
	export LC_ALL
endif
endif
endif
endif

all: plugins.cfg librz/include/rz_version.h
	${MAKE} -C shlr sdbs
	${MAKE} -C shlr/zip
	${MAKE} -C librz/util
	${MAKE} -C librz/socket
	${MAKE} -C shlr
	${MAKE} -C librz
	${MAKE} -C binrz

#.PHONY: librz/include/rz_version.h
GIT_TAP=$(shell git describe --tags --match "[0-9]*" 2>/dev/null || echo $(VERSION))
GIT_TIP=$(shell git rev-parse HEAD 2>/dev/null || echo HEAD)
R2_VER=$(shell grep VERSION configure.acr | head -n1 | awk '{print $$2}')
ifdef SOURCE_DATE_EPOCH
GIT_NOW=$(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u "+%Y-%m-%d")
else
GIT_NOW=$(shell date "+%Y-%m-%d")
endif

librz/include/rz_version.h:
	@echo Generating rz_version.h file
	@echo $(Q)#ifndef R_VERSION_H$(Q) > $@.tmp
	@echo $(Q)#define R_VERSION_H 1$(Q) >> $@.tmp
	@echo $(Q)#define R2_VERSION_COMMIT $(R2VC)$(Q) >> $@.tmp
	@echo $(Q)#define R2_VERSION $(ESC)"$(R2_VERSION)$(ESC)"$(Q) >> $@.tmp
	@echo $(Q)#define R2_VERSION_MAJOR $(R2_VERSION_MAJOR)$(Q) >> $@.tmp
	@echo $(Q)#define R2_VERSION_MINOR $(R2_VERSION_MINOR)$(Q) >> $@.tmp
	@echo $(Q)#define R2_VERSION_PATCH $(R2_VERSION_PATCH)$(Q) >> $@.tmp
	@echo $(Q)#define R2_VERSION_NUMBER $(R2_VERSION_NUMBER)$(Q) >> $@.tmp
	@echo $(Q)#define R2_GITTAP $(ESC)"$(GIT_TAP)$(ESC)"$(Q) >> $@.tmp
	@echo $(Q)#define R2_GITTIP $(ESC)"$(GIT_TIP)$(ESC)"$(Q) >> $@.tmp
	@echo $(Q)#define R2_BIRTH $(ESC)"$(GIT_NOW)$(BUILDSEC)$(ESC)"$(Q) >> $@.tmp
	@echo $(Q)#endif$(Q) >> $@.tmp
	@mv -f $@.tmp $@
	@rm -f $@.tmp

plugins.cfg:
	@if [ ! -e config-user.mk ]; then echo ; \
	echo "  Please, run ./configure first" ; echo ; exit 1 ; fi
	$(SHELL) ./configure-plugins

w32:
	sys/mingw32.sh

depgraph.png:
	cd librz ; perl depgraph.pl dot | dot -Tpng -o../depgraph.png

android:
	@if [ -z "$(NDK_ARCH)" ]; then echo "Set NDK_ARCH=[arm|arm64|mips|x86]" ; false; fi
	sys/android-${NDK_ARCH}.sh

w32dist:
	${MAKE} windist WINBITS=w32

w64dist:
	${MAKE} windist WINBITS=w64

WINDIST=${WINBITS}dist
ZIPNAME?=rizin-${WINBITS}-${VERSION}.zip

C=$(shell printf "\033[32m")
R=$(shell printf "\033[0m")
windist:
	@echo "${C}[WINDIST] Installing binaries and libraries${R}"
	[ -n "${WINBITS}" ] || exit 1
	rm -rf "rizin-${WINBITS}-${VERSION}" "${WINDIST}"
	mkdir "${WINDIST}"
	for FILE in `find librz | grep -e dll$$`; do cp "$$FILE" "${WINDIST}" ; done
	for FILE in `find binrz | grep -e exe$$`; do cp "$$FILE" "${WINDIST}" ; done
	rm -f "${WINDIST}/plugin.dll"
	@echo "${C}[WINDIST] Picking plugins from libraries${R}"
	mkdir -p "${WINDIST}/libs"
	mv "${WINDIST}/"lib*.dll "${WINDIST}/libs"
	mkdir -p "${WINDIST}/plugins"
	mv ${WINDIST}/*.dll "${WINDIST}/plugins"
	mv ${WINDIST}/libs/* "${WINDIST}"
	@echo "${C}[WINDIST] Do not include plugins for now${R}"
	rm -rf "${WINDIST}/libs"
	rm -rf ${WINDIST}/plugins/*
	@echo "${C}[WINDIST] Copying web interface${R}"
	mkdir -p "${WINDIST}/www"
	cp -rf shlr/www/* "${WINDIST}/www"
	mkdir -p "${WINDIST}/share/rizin/${VERSION}/magic"
	cp -f librz/magic/d/default/* "${WINDIST}/share/rizin/${VERSION}/magic"
	mkdir -p "${WINDIST}/share/rizin/${VERSION}/syscall"
	cp -f librz/syscall/d/*.sdb "${WINDIST}/share/rizin/${VERSION}/syscall"
	mkdir -p "${WINDIST}/share/rizin/${VERSION}/sysregs"
	cp -f librz/sysregs/d/*.sdb "${WINDIST}/share/rizin/${VERSION}/sysregs"
	mkdir -p "${WINDIST}/share/rizin/${VERSION}/fcnsign"
	cp -f librz/anal/d/*.sdb "${WINDIST}/share/rizin/${VERSION}/fcnsign"
	mkdir -p "${WINDIST}/share/rizin/${VERSION}/opcodes"
	cp -f librz/asm/d/*.sdb "${WINDIST}/share/rizin/${VERSION}/opcodes"
	mkdir -p "${WINDIST}/share/rizin/${VERSION}/flag"
	cp -f librz/flag/d/*.r2 "${WINDIST}/share/rizin/${VERSION}/flag"
	mkdir -p "${WINDIST}/share/doc/rizin"
	mkdir -p "${WINDIST}/include/librz/sdb"
	mkdir -p "${WINDIST}/include/librz/rz_util"
	@echo "${C}[WINDIST] Copying development files${R}"
	cp -f shlr/sdb/src/*.h "${WINDIST}/include/librz/sdb/"
	cp -f librz/include/rz_util/*.h "${WINDIST}/include/librz/rz_util/"
	cp -f librz/include/*.h "${WINDIST}/include/librz"
	#mkdir -p "${WINDIST}/include/librz/sflib"
	@cp -f doc/fortunes.* "${WINDIST}/share/doc/rizin"
	@mkdir -p "${WINDIST}/share/rizin/${VERSION}/format/dll"
	@cp -f librz/bin/d/elf32 "${WINDIST}/share/rizin/${VERSION}/format"
	@cp -f librz/bin/d/elf64 "${WINDIST}/share/rizin/${VERSION}/format"
	@cp -f librz/bin/d/elf_enums "${WINDIST}/share/rizin/${VERSION}/format"
	@cp -f librz/bin/d/pe32 "${WINDIST}/share/rizin/${VERSION}/format"
	@cp -f librz/bin/d/trx "${WINDIST}/share/rizin/${VERSION}/format"
	@cp -f librz/bin/d/dll/*.sdb "${WINDIST}/share/rizin/${VERSION}/format/dll"
	@mkdir -p "${WINDIST}/share/rizin/${VERSION}/cons"
	@cp -PRpf librz/cons/d/* "${WINDIST}/share/rizin/${VERSION}/cons"
	@mkdir -p "${WINDIST}/share/rizin/${VERSION}/hud"
	@cp -f doc/hud "${WINDIST}/share/rizin/${VERSION}/hud/main"
	@mv "${WINDIST}" "rizin-${WINBITS}-${VERSION}"
	@rm -f "rizin-${WINBITS}-${VERSION}.zip"
ifneq ($(USE_ZIP),NO)
	$(ZIP) -r "${ZIPNAME}" "rizin-${WINBITS}-${VERSION}"
endif

clean: 
	rm -f librz/librz.a librz/librz.dylib librz/include/rz_version.h
	rm -rf librz/.librz
	for DIR in shlr librz binrz ; do $(MAKE) -C "$$DIR" clean ; done
	-rm -f `find . -type f -name '*.d'`
	rm -f `find . -type f -name '*.o'`
	rm -f config-user.mk plugins.cfg librz/config.h
	rm -f librz/include/rz_userconf.h librz/config.mk
	rm -f pkgcfg/*.pc

distclean mrproper: clean
	rm -f `find . -type f -iname '*.d'`

pkgcfg:
	cd librz && ${MAKE} pkgcfg

install-man:
	mkdir -p "${DESTDIR}${MANDIR}/man1"
	mkdir -p "${DESTDIR}${MANDIR}/man7"
	for FILE in man/*.1 ; do ${INSTALL_MAN} "$$FILE" "${DESTDIR}${MANDIR}/man1" ; done
	cd "${DESTDIR}${MANDIR}/man1" && ln -fs rizin.1 r2.1
	for FILE in man/*.7 ; do ${INSTALL_MAN} "$$FILE" "${DESTDIR}${MANDIR}/man7" ; done

install-man-symlink:
	mkdir -p "${DESTDIR}${MANDIR}/man1"
	mkdir -p "${DESTDIR}${MANDIR}/man7"
	for FILE in $(shell cd man && ls *.1) ; do \
		ln -fs "${PWD}/man/$$FILE" "${DESTDIR}${MANDIR}/man1/$$FILE" ; done
	cd "${DESTDIR}${MANDIR}/man1" && ln -fs rizin.1 r2.1
	for FILE in *.7 ; do \
		ln -fs "${PWD}/man/$$FILE" "${DESTDIR}${MANDIR}/man7/$$FILE" ; done

install-doc:
	mkdir -p "${DESTDIR}${DOCDIR}"
	${INSTALL_DIR} "${DESTDIR}${DOCDIR}"
	@echo ${DOCDIR}
	for FILE in doc/* ; do \
		if [ -f $$FILE ]; then ${INSTALL_DATA} $$FILE "${DESTDIR}${DOCDIR}" || true ; fi; \
	done

install-doc-symlink:
	mkdir -p "${DESTDIR}${DOCDIR}"
	${INSTALL_DIR} "${DESTDIR}${DOCDIR}"
	for FILE in $(shell cd doc ; ls) ; do \
		ln -fs "$(PWD)/doc/$$FILE" "${DESTDIR}${DOCDIR}" ; done

install love: install-doc install-man install-www install-pkgconfig
	cd librz && ${MAKE} install
	cd binrz && ${MAKE} install
	cd shlr && ${MAKE} install
	for DIR in ${DATADIRS} ; do $(MAKE) -C "$$DIR" install ; done
	cd "$(DESTDIR)$(LIBDIR)/rizin/" ;\
		rm -f last ; ln -fs $(VERSION) last
	cd "$(DESTDIR)$(DATADIR)/rizin/" ;\
		rm -f last ; ln -fs $(VERSION) last
	rm -rf "${DESTDIR}${DATADIR}/rizin/${VERSION}/hud"
	mkdir -p "${DESTDIR}${DATADIR}/rizin/${VERSION}/hud"
	mkdir -p "${DESTDIR}${BINDIR}"
	#${INSTALL_SCRIPT} "${PWD}/sys/indent.sh" "${DESTDIR}${BINDIR}/r2-indent"
	#${INSTALL_SCRIPT} "${PWD}/sys/r1-docker.sh" "${DESTDIR}${BINDIR}/rz-docker"
	cp -f doc/hud "${DESTDIR}${DATADIR}/rizin/${VERSION}/hud/main"
	mkdir -p "${DESTDIR}${DATADIR}/rizin/${VERSION}/"
	$(SHELL) sys/ldconfig.sh
	$(SHELL) ./configure-plugins --rm-static $(DESTDIR)$(LIBDIR)/rizin/last/

install-www:
	rm -rf "${DESTDIR}${WWWROOT}"
	rm -rf "${DESTDIR}${LIBDIR}/rizin/${VERSION}/www" # old dir
	mkdir -p "${DESTDIR}${WWWROOT}"
	cp -rf shlr/www/* "${DESTDIR}${WWWROOT}"

symstall-www:
	rm -rf "${DESTDIR}${WWWROOT}"
	rm -rf "${DESTDIR}${LIBDIR}/rizin/${VERSION}/www" # old dir
	mkdir -p "${DESTDIR}${WWWROOT}"
	for FILE in $(shell cd shlr/www ; ls) ; do \
		ln -fs "$(PWD)/shlr/www/$$FILE" "$(DESTDIR)$(WWWROOT)" ; done

install-pkgconfig pkgconfig-install:
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}/pkgconfig"
	for FILE in $(shell cd pkgcfg ; ls *.pc) ; do \
		cp -f "$(PWD)/pkgcfg/$$FILE" "${DESTDIR}${LIBDIR}/pkgconfig/$$FILE" ; done

install-pkgconfig-symlink pkgconfig-symstall symstall-pkgconfig:
	mkdir -p "${DESTDIR}${LIBDIR}/pkgconfig"
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}/pkgconfig"
	for FILE in $(shell cd pkgcfg ; ls *.pc) ; do \
		ln -fs "$(PWD)/pkgcfg/$$FILE" "${DESTDIR}${LIBDIR}/pkgconfig/$$FILE" ; done

symstall-sdb:
	for DIR in ${DATADIRS} ; do (\
		cd "$$DIR" ; \
		echo "$$DIR" ; \
		${MAKE} install-symlink ); \
	done

symstall install-symlink: install-man-symlink install-doc-symlink install-pkgconfig-symlink symstall-www symstall-sdb
	cd librz && ${MAKE} install-symlink
	cd binrz && ${MAKE} install-symlink
	cd shlr && ${MAKE} install-symlink
	mkdir -p "${DESTDIR}${BINDIR}"
	ln -fs "${PWD}/sys/indent.sh" "${DESTDIR}${BINDIR}/r2-indent"
	ln -fs "${PWD}/sys/rz-docker.sh" "${DESTDIR}${BINDIR}/rz-docker"
	mkdir -p "${DESTDIR}${DATADIR}/rizin/${VERSION}/hud"
	ln -fs "${PWD}/doc/hud" "${DESTDIR}${DATADIR}/rizin/${VERSION}/hud/main"
	#mkdir -p "${DESTDIR}${DATADIR}/rizin/${VERSION}/flag"
	#ln -fs $(PWD)/librz/flag/d/tags.r2 "${DESTDIR}${DATADIR}/rizin/${VERSION}/flag/tags.r2"
	cd "$(DESTDIR)$(LIBDIR)/rizin/" ;\
		rm -f last ; ln -fs $(VERSION) last
	cd "$(DESTDIR)$(DATADIR)/rizin/" ;\
		rm -f last ; ln -fs $(VERSION) last
	mkdir -p "${DESTDIR}${DATADIR}/rizin/${VERSION}/"
	$(SHELL) sys/ldconfig.sh
	$(SHELL) ./configure-plugins --rm-static $(DESTDIR)/$(LIBDIR)/rizin/last/

deinstall uninstall:
	rm -f $(DESTDIR)$(BINDIR)/r2-indent
	rm -f $(DESTDIR)$(BINDIR)/rz-docker
	cd librz && ${MAKE} uninstall
	cd binrz && ${MAKE} uninstall
	cd shlr && ${MAKE} uninstall
	cd librz/syscall/d && ${MAKE} uninstall
	cd librz/anal/d && ${MAKE} uninstall
	@echo
	@echo "Run 'make purge' to also remove installed files from previous versions of r2"
	@echo

purge-doc:
	rm -rf "${DESTDIR}${DOCDIR}"
	cd man ; for FILE in *.1 ; do rm -f "${DESTDIR}${MANDIR}/man1/$$FILE" ; done
	rm -f "${DESTDIR}${MANDIR}/man1/r2.1"

user-wrap=echo "\#!/bin/sh" > ~/bin/"$1" \
; echo "${PWD}/env.sh '${PREFIX}' '$1' \"\$$@\"" >> ~/bin/"$1" \
; chmod +x ~/bin/"$1" ;

user-install:
	mkdir -p ~/bin
	$(foreach mod,$(R2BINS),$(call user-wrap,$(mod)))
	cd ~/bin ; ln -fs rizin r2

user-uninstall:
	$(foreach mod,$(R2BINS),rm -f ~/bin/"$(mod)")
	rm -f ~/bin/r2
	-rmdir ~/bin

purge-dev:
	rm -f "${DESTDIR}${LIBDIR}/librz_"*".${EXT_AR}"
	rm -f "${DESTDIR}${LIBDIR}/pkgconfig/rz_"*.pc
	rm -rf "${DESTDIR}${INCLUDEDIR}/librz"
	rm -f "${DESTDIR}${LIBDIR}/rizin/${VERSION}/-"*

# required for EXT_SO
include librz/config.mk

strip:
	#-for FILE in ${R2BINS} ; do ${STRIP} -s "${DESTDIR}${BINDIR}/$$FILE" 2> /dev/null ; done
ifeq ($(HOST_OS),darwin)
	-${STRIP} -STxX "${DESTDIR}${LIBDIR}/librz_"*".${EXT_SO}"
else
	-${STRIP} -s "${DESTDIR}${LIBDIR}/librz_"*".${EXT_SO}"
endif

purge: purge-doc purge-dev user-uninstall
	for FILE in ${R2BINS} ; do rm -f "${DESTDIR}${BINDIR}/$$FILE" ; done
	rm -f "${DESTDIR}${BINDIR}/rz_gg-cc"
	rm -f "${DESTDIR}${BINDIR}/r2"
	rm -f "${DESTDIR}${LIBDIR}/librz_"*
	rm -f "${DESTDIR}${LIBDIR}/librz"*".${EXT_SO}"
	rm -rf "${DESTDIR}${LIBDIR}/rizin"
	rm -rf "${DESTDIR}${INCLUDEDIR}/librz"
	rm -rf "${DESTDIR}${DATADIR}/rizin"

system-purge: purge
	sys/purge.sh

R2V=rizin-${VERSION}

v ver version:
	@echo CURRENT=${VERSION}
	@echo PREVIOUS=${PREVIOUS_RELEASE}

dist:
	rm -rf $(R2V)
	git clone . $(R2V)
	-cd $(R2V) && [ ! -f config-user.mk -o configure -nt config-user.mk ] && ./configure "--prefix=${PREFIX}"
	cd $(R2V) ; git log $$(git show-ref | grep ${PREVIOUS_RELEASE} | awk '{print $$1}')..HEAD > ChangeLog
	$(MAKE) -C $(R2V)/shlr capstone-sync
	FILES=`cd $(R2V); git ls-files | sed -e "s,^,$(R2V)/,"` ; \
	CS_FILES=`cd $(R2V)/shlr/capstone ; git ls-files | grep -v pdf | grep -v xcode | grep -v msvc | grep -v suite | grep -v bindings | grep -v tests | sed -e "s,^,$(R2V)/shlr/capstone/,"` ; \
	${TAR} "rizin-${VERSION}.tar" $${FILES} $${CS_FILES} "$(R2V)/ChangeLog" ; \
	${CZ} "rizin-${VERSION}.tar"

olddist:
	-[ configure -nt config-user.mk ] && ./configure "--prefix=${PREFIX}"
	#git log $$(git show-ref `git tag |tail -n1`)..HEAD > ChangeLog
	git log $$(git show-ref | grep ${PREVIOUS_RELEASE} | awk '{print $$1}')..HEAD > ChangeLog
	cd shlr && ${MAKE} capstone-sync
	$(MAKE) -R capstone.ps
	DIR=`basename "$$PWD"` ; \
	FILES=`git ls-files | sed -e "s,^,rizin-${VERSION}/,"` ; \
	CS_FILES=`cd shlr/capstone ; git ls-files | grep -v pdf | grep -v xcode | grep -v msvc | grep -v suite | grep -v bindings | grep -v tests | sed -e "s,^,rizin-${VERSION}/shlr/capstone/,"` ; \
	cd .. && mv "$${DIR}" "rizin-${VERSION}" && \
	${TAR} "rizin-${VERSION}.tar" $${FILES} $${CS_FILES} "rizin-${VERSION}/ChangeLog" ; \
	${CZ} "rizin-${VERSION}.tar" ; \
	mv "rizin-${VERSION}" "$${DIR}"

shot:
	DATE=`date '+%Y%m%d'` ; \
	FILES=`git ls-files | sed -e "s,^,rizin-${DATE}/,"` ; \
	cd .. && mv rizin "rizin-$${DATE}" && \
	${TAR} "rizin-$${DATE}.tar" $${FILES} ;\
	${CZ} "rizin-$${DATE}.tar" ;\
	mv "rizin-$${DATE}" rizin && \
	scp "rizin-$${DATE}.${TAREXT}" \
		radare.org:/srv/http/rizinorg/get/shot

tests:
	$(MAKE) -C $(R2R)

macos-sign:
	$(MAKE) -C binrz/rizin macos-sign

macos-sign-libs:
	$(MAKE) -C binrz/rizin macos-sign-libs

osx-pkg:
	sys/osx-pkg.sh $(VERSION)

quality:
	./sys/shellcheck.sh

menu nconfig:
	./sys/menu.sh || true

meson:
	@echo "[ Meson R2 Building ]"
	$(PYTHON) sys/meson.py --prefix="${PREFIX}" --shared

meson-install:
	DESTDIR="$(DESTDIR)" ninja -C build install

meson-symstall: symstall-sdb
	@echo "[ Meson symstall (not stable) ]"
	ln -fs $(PWD)/binrz/rz_pm/rz-pm ${B}/rz-pm
	ln -fs $(PWD)/build/binrz/rz_asm/rz_asm ${B}/rz_asm
	ln -fs $(PWD)/build/binrz/rz_run/rz_run ${B}/rz_run
	ln -fs $(PWD)/build/binrz/rizin/rizin ${B}/rizin
	ln -fs $(PWD)/build/binrz/rz_hash/rz_hash ${B}/rz_hash
	ln -fs $(PWD)/build/binrz/rz_bin/rz_bin ${B}/rz_bin
	ln -fs $(PWD)/build/binrz/rizin/rizin ${B}/rizin
	ln -fs $(PWD)/build/binrz/rz_gg/rz_gg ${B}/rz_gg
	cd $(B) && ln -fs rizin r2
	ln -fs $(PWD)/build/librz/util/librz_util.$(EXT_SO) ${L}/librz_util.$(EXT_SO)
	ln -fs $(PWD)/build/librz/bp/librz_bp.$(EXT_SO) ${L}/librz_bp.$(EXT_SO)
	ln -fs $(PWD)/build/librz/syscall/librz_syscall.$(EXT_SO) ${L}/librz_syscall.$(EXT_SO)
	ln -fs $(PWD)/build/librz/cons/librz_cons.$(EXT_SO) ${L}/librz_cons.$(EXT_SO)
	ln -fs $(PWD)/build/librz/search/librz_search.$(EXT_SO) ${L}/librz_search.$(EXT_SO)
	ln -fs $(PWD)/build/librz/magic/librz_magic.$(EXT_SO) ${L}/librz_magic.$(EXT_SO)
	ln -fs $(PWD)/build/librz/flag/librz_flag.$(EXT_SO) ${L}/librz_flag.$(EXT_SO)
	ln -fs $(PWD)/build/librz/reg/librz_reg.$(EXT_SO) ${L}/librz_reg.$(EXT_SO)
	ln -fs $(PWD)/build/librz/bin/librz_bin.$(EXT_SO) ${L}/librz_bin.$(EXT_SO)
	ln -fs $(PWD)/build/librz/config/librz_config.$(EXT_SO) ${L}/librz_config.$(EXT_SO)
	ln -fs $(PWD)/build/librz/parse/librz_parse.$(EXT_SO) ${L}/librz_parse.$(EXT_SO)
	ln -fs $(PWD)/build/librz/lang/librz_lang.$(EXT_SO) ${L}/librz_lang.$(EXT_SO)
	ln -fs $(PWD)/build/librz/asm/librz_asm.$(EXT_SO) ${L}/librz_asm.$(EXT_SO)
	ln -fs $(PWD)/build/librz/anal/librz_anal.$(EXT_SO) ${L}/librz_anal.$(EXT_SO)
	ln -fs $(PWD)/build/librz/egg/librz_egg.$(EXT_SO) ${L}/librz_egg.$(EXT_SO)
	ln -fs $(PWD)/build/librz/fs/librz_fs.$(EXT_SO) ${L}/librz_fs.$(EXT_SO)
	ln -fs $(PWD)/build/librz/debug/librz_debug.$(EXT_SO) ${L}/librz_debug.$(EXT_SO)
	ln -fs $(PWD)/build/librz/core/librz_core.$(EXT_SO) ${L}/librz_core.$(EXT_SO)

meson-uninstall:
	ninja -C build uninstall
	$(MAKE) uninstall

meson-clean:
	rm -rf build
	rm -rf build_sdb

MESON_FILES=$(shell find build/librz build/binrz -type f | grep -v @)
meson-symstall-experimental:
	for a in $(MESON_FILES) ; do echo ln -fs "$(PWD)/$$a" "$(PWD)/$$(echo $$a|sed -e s,build/,,)" ; done
	$(MAKE) symstall

shlr/capstone:
	$(MAKE) -C shlr capstone

.PHONY: meson meson-install

include ${MKPLUGINS}

.PHONY: all clean install symstall uninstall deinstall strip
.PHONY: librz binrz install-man w32dist tests dist shot pkgcfg depgraph.png love
.PHONY: purge system-purge
.PHONY: shlr/capstone
