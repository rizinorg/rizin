#!/bin/sh
cd $HOME/prg/rizin
IFS=:
for a in $PATH ; do
	if [ -x "$a/rizin" ]; then
		D=$(dirname `readlink /usr/local/bin/rizin`)
		cd "$D/../.."
		if [ -d librz/include ]; then
			git grep "$1" librz/include | grep -v '#include' | less -p "$1" -R
			exit 0
		fi
	fi
done
echo "Cant find r2"
