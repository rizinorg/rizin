#!/bin/sh
FILES="
librz/util/mem.c
librz/util/base64.c
librz/util/name.c
librz/util/idpool.c
librz/util/stack.c
librz/util/slist.c
librz/util/log.c
librz/util/cache.c
librz/util/print.c

librz/asm/p/asm_bf.c

librz/hash/calc.c
librz/hash/crc16.c
librz/hash/luhn.c
librz/hash/xxhash.c
librz/hash/md4.c
librz/hash/adler32.c
librz/hash/hash.c
librz/hash/sha2.c

librz/reg/reg.c
librz/reg/arena.c
librz/reg/double.c
librz/reg/cond.c
librz/reg/value.c
librz/reg/profile.c

librz/include/r_list.h
librz/include/r_reg.h
librz/include/r_util.h

librz/anal/var.c
librz/anal/fcn.c
librz/anal/cycles.c
librz/anal/esil.c
librz/anal/data.c
librz/anal/flirt.c
librz/anal/p/anal_arc.c

librz/config/config.c
librz/config/callback.c
librz/config/t/test.c

librz/fs/fs.c
librz/fs/file.c

librz/bin/bin.c
librz/bin/bin_write.c
librz/bin/dbginfo.c
librz/bin/filter.c
librz/bin/format/objc/mach0_classes.c

librz/cons/hud.c
librz/cons/2048.c
librz/cons/utf8.c
librz/cons/grep.c
librz/cons/line.c
librz/cons/canvas.c
librz/cons/editor.c

librz/core/file.c
librz/core/yank.c
librz/core/blaze.c
librz/core/cmd_egg.c

shlr/tcc/tccgen.c
shlr/tcc/libtcc.c
shlr/tcc/tccpp.c

binrz/rizin/rizin.c
binrz/rz_bin/rz_bin.c
binrz/rz_diff/rz_diff.c
binrz/rz_asm/rz_asm.c
binrz/rz_ax/rz_ax.c
"

chk() {
	if [ -z "$2" ]; then
		return 0
	fi
	echo "$1" | grep -q "$2"
}

case "$1" in
help|-h)
	echo "Usage. sys/indent-whitelist.sh [--fix] [regex]"
	;;
--fix)
	for f in $FILES ; do
		chk $f $2 || continue
		rz_pm -r sys/indent.sh -i $f
	done
	;;
*)
	for f in $FILES ; do
		chk $f $1 || continue
		rz_pm -r sys/indent.sh -u $f
	done
esac
