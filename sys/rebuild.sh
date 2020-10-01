#!/bin/sh

# Requires GNU Make, but some distros probably don't have the gmake symlink.
[ -z "$MAKE" ] && MAKE=make

while : ; do
	if [ -f sys/rebuild.sh ]; then
		break
	fi
	cd ..
	if [ "`pwd`" = / ]; then
		echo "Cant find sys/rebuild.sh"
		exit 1
	fi
done

Rebuild() {
	cd "$1" || exit 1
	$MAKE clean
	$MAKE -j8 || exit 1
	cd -
}

Build() {
	cd "$1" || exit 1
	$MAKE -j8 || exit 1
	cd -
}

RebuildIOSDebug() {
	Rebuild librz/debug
	# Rebuild librz/util
	# Rebuild librz/core
	Rebuild binrz/rizin
	$MAKE -C binrz/rizin ios-sign
	if [ -n "${IOSIP}" ]; then
		scp binrz/rizin/rizin root@"${IOSIP}:."
	else
		echo "Set IOSIP environment variable to scp the rizin program"
	fi
}

RebuildSpp() {
	Rebuild shlr/spp
	Rebuild librz/util
	Rebuild librz/lang
}

RebuildJava() {
	Rebuild shlr/java
	Rebuild librz/asm
	Rebuild librz/anal
	Rebuild librz/bin
	Rebuild librz/core
}

RebuildCapstone() {
	if [ ! -d shlr/capstone ]; then
		make -C shlr capstone
	fi
	Rebuild shlr/capstone
	Rebuild librz/asm
	Rebuild librz/anal
}

RebuildSdb() {
	Rebuild shlr/sdb
	Rebuild librz/util
}

RebuildFs() {
	Rebuild shlr/grub
	Rebuild librz/fs
}

RebuildBin() {
	Rebuild librz/bin
	Rebuild librz/core
}

RebuildGdb() {
	Rebuild shlr/gdb
	Rebuild librz/io
	Rebuild librz/debug
}

RebuildWinkd() {
	Rebuild shlr/winkd
	Rebuild librz/io
	Rebuild librz/debug
}

RebuildZip() {
	Rebuild shlr/zip
	Rebuild librz/io
}

RebuildTcc() {
	Rebuild shlr/tcc
	Rebuild librz/parse
}

case "$1" in
grub|fs)RebuildFs; ;;
bin)    RebuildBin ; ;;
gdb)    RebuildGdb ; ;;
winkd)  RebuildWinkd ; ;;
sdb)    RebuildSdb ; ;;
spp)    RebuildSpp ; ;;
tcc)    RebuildTcc ; ;;
bin)    RebuildBin ; ;;
zip)    RebuildZip ; ;;
java)   RebuildJava ; ;;
iosdbg) RebuildIOSDebug ; ;;
capstone|cs) RebuildCapstone ; ;;
*)
	echo "Usage: sys/rebuild.sh [gdb|java|capstone|sdb|iosdbg|cs|sdb|bin]"
	;;
esac
