PREFIX?=/usr
DESTDIR?=/

BINS=rz-bin rz-run rz-asm rz-gg rz-hash rz-ax rz-find rz-diff
BINS2=rizin ${BINS}

SOURCES= main.c rz-bin.c rizin.c rz-diff.c rz-find.c
SOURCES+=rz-hash.c rz-run.c rz-asm.c rz-ax.c rz-gg.c

include ../../config-user.mk

SHLR=../../shlr

ifeq (${ANDROID},1)
LDFLAGS+=-lm
else
ifneq (${OSTYPE},linux)
LDFLAGS+=-lpthread
LDFLAGS+=-ldl
endif
endif
ifeq ($(USE_LTO),1)
LDFLAGS+=-flto
endif

CFLAGS+=-I../../librz/include/
CFLAGS+=-I$(SHLR)/spp

LDFLAGS+=-L../../librz/main -lrz_main
LDFLAGS+=-L../../librz/io -lrz_io
LDFLAGS+=-L../../librz/bp -lrz_bp
LDFLAGS+=-L../../librz/socket -lrz_socket
LDFLAGS+=-L../../librz/bin -lrz_bin
LDFLAGS+=-L../../librz/reg -lrz_reg
LDFLAGS+=-L../../librz/asm -lrz_asm
LDFLAGS+=-L../../librz/lang -lrz_lang
LDFLAGS+=-L../../librz/egg -lrz_egg
LDFLAGS+=-L../../librz/core -lrz_core
LDFLAGS+=-L../../librz/anal -lrz_anal
LDFLAGS+=-L../../librz/crypto -lrz_crypto
LDFLAGS+=-L../../librz/flag -lrz_flag
LDFLAGS+=-L../../librz/parse -lrz_parse
LDFLAGS+=-L../../librz/magic -lrz_magic
LDFLAGS+=-L../../librz/syscall -lrz_syscall
LDFLAGS+=-L../../librz/util -lrz_util
LDFLAGS+=-L../../librz/cons -lrz_cons
LDFLAGS+=-L../../librz/hash -lrz_hash
LDFLAGS+=-L../../librz/debug -lrz_debug
LDFLAGS+=-L../../librz/search -lrz_search
LDFLAGS+=-L../../librz/config -lrz_config
LDFLAGS+=${LINK}

include ../../librz/config.mk
include ../../librz/socket/deps.mk
include ../../librz/magic/deps.mk
include ../../librz/main/deps.mk
include ../../shlr/sdb.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/java/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk
include ../../shlr/sdb.mk
include ../../shlr/capstone.mk
include ../../shlr/rizin-shell-parser-deps.mk

all: symlinks

symlinks: build
	for FILE in ${BINS} ; do \
		ln -fs rizin $$FILE ; \
	done

clean:
	mv main.c main.k
	rm -f *.[ch]
	mv main.k main.c

build:
	mv main.c main.k
	rm -f *.[ch]
	mv main.k main.c
	for FILE in ${BINS2} ; do cp ../$$FILE/*.[ch] . ; done
	rm -f rwx.c xorhex.c rsc2.c
	for FILE in ${BINS2} ; do \
		mv $${FILE}.c _$${FILE}.c ;\
		sed -e "s,^int main,int $${FILE}_main,g" _$${FILE}.c > $${FILE}.c ; \
		rm -f _$${FILE} ; \
	done
	rm -f _*
	${CC} -o rizin ${SOURCES} ${CFLAGS} ${LDFLAGS}
	mv main.c main.k
	rm -f *.[ch]
	mv main.k main.c

install:
	mkdir -p "${DESTDIR}${BINDIR}"
	for FILE in ${BINS2} ; do \
		rm -f "${DESTDIR}${BINDIR}/$$FILE" ; \
		cp -PRpf "$$FILE" "${DESTDIR}${BINDIR}/$$FILE" ; \
	done

