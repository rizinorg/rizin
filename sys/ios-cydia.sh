#!/bin/sh


set -x
STOW=0
fromscratch=1 # 1
onlymakedeb=0
static=1


gcc -v 2> /dev/null
if [ $? = 0 ]; then
	export HOST_CC=gcc
fi
if [ -z "${CPU}" ]; then
	export CPU=arm64
	#export CPU=armv7
fi
if [ -z "${PACKAGE}" ]; then
	PACKAGE=rizin
fi

export BUILD=1

if [ ! -d sys/ios-include/mach/vm_behavior.h  ]; then
(
	cd sys && \
	wget -c https://lolcathost.org/b/ios-include.tar.gz && \
	tar xzvf ios-include.tar.gz
)
fi

. sys/ios-env.sh
if [ "${STOW}" = 1 ]; then
PREFIX=/private/var/rizin
else
PREFIX=/usr
fi

makeDeb() {
	make -C binrz ios-sdk-sign
	rm -rf /tmp/r2ios
	make install DESTDIR=/tmp/r2ios
	rm -rf /tmp/r2ios/${PREFIX}/share/rizin/*/www/enyo/node_modules
	( cd /tmp/r2ios && tar czvf ../r2ios-${CPU}.tar.gz ./* )
	rm -rf sys/cydia/rizin/root
	mkdir -p sys/cydia/rizin/root
	sudo tar xpzvf /tmp/r2ios-${CPU}.tar.gz -C sys/cydia/rizin/root
	rm -f sys/cydia/rizin/root/${PREFIX}/lib/*.{a,dylib,dSYM}
	if [ "$static" = 1 ]; then
	(
		rm -f sys/cydia/rizin/root/${PREFIX}/bin/*
		cp -f binrz/blob/rizin sys/cydia/rizin/root/${PREFIX}/bin
		cd sys/cydia/rizin/root/${PREFIX}/bin
		for a in r2 rz_bin rz_run rz_asm rz_gg rz_hash rz_ax rz_find rz_diff ; do ln -fs rizin $a ; done
	)
		echo "Signing rizin"
		ldid2 -Sbinr/rizin/rizin_ios.xml sys/cydia/rizin/root/usr/bin/rizin
	else
		for a in sys/cydia/rizin/root/usr/bin/* sys/cydia/rizin/root/usr/lib/*.dylib ; do
			echo "Signing $a"
			ldid2 -Sbinr/rizin/rizin_ios.xml $a
		done
	fi
if [ "${STOW}" = 1 ]; then
	(
		cd sys/cydia/rizin/root/
		mkdir -p usr/bin
		# stow
		echo "Stowing ${PREFIX} into /usr..."
		for a in `cd ./${PREFIX}; ls` ; do
			if [ -d "./${PREFIX}/$a" ]; then
				mkdir -p "usr/$a"
				for b in `cd ./${PREFIX}/$a; ls` ; do
					echo ln -fs "${PREFIX}/$a/$b" usr/$a/$b
					ln -fs "${PREFIX}/$a/$b" usr/$a/$b
				done
			fi
		done
	)
else
	echo "No need to stow anything"
fi
	( cd sys/cydia/rizin ; sudo make clean ; sudo make PACKAGE=${PACKAGE} )
}

if [ "$1" = makedeb ]; then
	onlymakedeb=1
fi

if [ $onlymakedeb = 1 ]; then
	makeDeb
else
	RV=0
	if [ $fromscratch = 1 ]; then
		make clean
		cp -f plugins.ios.cfg plugins.cfg
		if [ "$static" = 1 ]; then
			./configure --prefix="${PREFIX}" --with-ostype=darwin --without-libuv \
			--with-compiler=ios-sdk --target=arm-unknown-darwin --with-librz
		else
			./configure --prefix="${PREFIX}" --with-ostype=darwin --without-libuv \
			--with-compiler=ios-sdk --target=arm-unknown-darwin
		fi
		RV=$?
	fi
	if [ $RV = 0 ]; then
		time make -j4 || exit 1
		if [ "$static" = 1 ]; then
			ls -l librz/util/librz_util.a || exit 1
			ls -l librz/flag/librz_flag.a || exit 1
			rm -f librz/*/*.dylib
			(
			cd binrz ; make clean ; 
			cd blob ; make USE_LTO=1
			xcrun --sdk iphoneos strip rizin
			)
		fi
		if [ $? = 0 ]; then
			makeDeb
		fi
	fi
fi
