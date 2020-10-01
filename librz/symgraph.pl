#!/bin/sh

t="/tmp/symgraph"
rm -rf "$t"
mkdir -p "$t/b" "$t/l"
if [ "`uname`" = Darwin ]; then
	SO=dylib
else
	SO=so
fi

dolib() {
	rz_bin -i $1/libr_$1.${SO} | grep -v mports | cut -d = -f 6 > $t/l/$1.i
	rz_bin -s $1/libr_$1.${SO} | grep -v xports | cut -d = -f 6 > $t/l/$1.s
}

dobin() {
	rz_bin -i ../binrz/$1/$1 | grep -v mports | cut -d = -f 9 > $t/b/$1.i
#	rz_bin -s ../binrz/$1/$1 | cut -d = -f 8 > $t/b/$1.s
}

LIBS="anal asm bin bp config cons crypto debug diff flags hash io lang parse reg search socket syscall util core"
for a in $LIBS ; do
	dolib ${a}
done
BINS="rz_bin rz_asm rizin rz_ax ranal2 rz_hash rz_diff rz_find rz_agent"
for a in $BINS ; do
	dobin ${a}
done

cat $t/l/*.i $t/l/*.s $t/b/*.i | sort | uniq -c | sort -n | grep r_
