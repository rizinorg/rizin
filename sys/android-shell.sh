#!/bin/sh
# android shell

if [ -n "$1" ]; then
	NDK_ARCH="$1"
	shift
fi
export ANDROID=1
ARCH=${NDK_ARCH}
case "${NDK_ARCH}" in
mips64)
	export NDK_ARCH
	AR=mips64el-linux-android-ar
	RANLIB=mips64el-linux-android-ranlib
	;;
mips)
	export NDK_ARCH
	AR=mipsel-linux-android-ar
	RANLIB=mipsel-linux-android-ranlib
	;;
x64)
	NDK_ARCH=x86_64
	export NDK_ARCH
	;;
x86|x86_64)
	export NDK_ARCH
	;;
aarch64|arm64)
	NDK_ARCH=aarch64
	export NDK_ARCH
	AR=aarch64-linux-android-ar
	ARCH=arm64
	RANLIB=aarch64-linux-android-ranlib
	;;
arm)
	export NDK_ARCH
	AR=arm-linux-androideabi-ar
	RANLIB=arm-linux-androideabi-ranlib
	;;
local)
	export ANDROID=1
	;;
*)
	echo "Usage: $0 [arm64|arm|mips|mips64|x86|x64]"
	exit 1
	;;
esac

LANG=C
export LANG
ROOT=`dirname $0`
OS=`uname|tr 'A-Z' 'a-z'`
[ "${OS}" = macosx ] && OS=darwin

if [ ! -x /work ]; then
	echo "Building android locally with NDK instead of dockcross..."
	# TODO: autodetect
	if [ -f ~/.rzandroidrc ]; then
		. ~/.rzandroidrc
		echo "Using data from ${HOME}/.rzandroidrc.."
	else
		#[ -z "${SDK}" ] && SDK="${HOME}/Downloads/android-sdk-${OS}"
		if [ -z "${NDK}" ]; then
			# Checking if Android NDK is installed with macOS's brew
			D=/usr/local/Caskroom/android-ndk/
			if [ -d "${D}" ]; then
				for a in $(cd "$D" && ls) ; do
					N="$D/$a/android-ndk-r$a"
					if [ -f "$N/README.md" ]; then
						NDK="$N"
						break
					fi
				done
			fi
		fi
		if [ -z "${NDK}" ]; then
			if [ "`uname`" = "Darwin" ]; then
				NDK="${HOME}/Library/Android/sdk/ndk-bundle/"
			else
				NDK="${HOME}/Downloads/android-ndk-r7b"
			fi
		fi
		[ -z "${NDK}" ] && NDK="${HOME}/Downloads/android-ndk-r7b"
	fi
fi

echo ROOT=$ROOT
echo NDK=$NDK
echo NDK_ARCH=$NDK_ARCH

echo "Building the standalone NDK toolchain..."
${NDK}/build/tools/make_standalone_toolchain.py --arch=${ARCH} --install-dir=/tmp/ndk/ --api=28 --force
(
cd /tmp/ndk/bin/ && \
ln -fs clang ndk-gcc && \
ln -fs clang++ ndk-g++
)
if [ "${BUILD}" != 0 ]; then
	if [ ! -d "${NDK}" ]; then
		echo "Cannot find Android NDK ${NDK}" >&2
		echo "echo NDK=/path/to/ndk  > ~/.rzandroidrc" >&2
		exit 1
	fi
	PATH=/tmp/ndk/bin:$PATH
	export PATH
	export CFLAGS
	export NDK
	export NDK_ARCH
	[ -z "${SHELL}" ] && SHELL=sh
	SHELL=sh
	CC=ndk-gcc
	CXX=ndk-g++
	PS1="[rizin-android-${NDK_ARCH}]> "
	export CC
	export CXX
	export PS1
	export AR
	export RANLIB
	A=$@
	if [ -n "$A" ]; then
		${SHELL} -c "$A"
	else
		${SHELL}
	fi
fi
