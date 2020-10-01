#!/bin/bash

if [ -z "$BASH" ]; then
	autoload bashcompinit
	bashcompinit
fi

_rz () {
	local cur
	COMPREPLY=()
	cur=${COMP_WORDS[COMP_CWORD]}
	prv=${COMP_WORDS[COMP_CWORD-1]}
	case "$prv" in
	-a)
		COMPREPLY=( $(compgen -W "$(rz_asm -qL)" -- $cur))
		return 0
		;;
	-b)
		COMPREPLY=( $(compgen -W "8 16 32 64" -- $cur ))
		return 0
		;;
	-k)
		COMPREPLY=( $(compgen -W "$(r2 -qc 'e asm.os=?' --)" -- $cur ))
		return 0
		;;
	-e)
		COMPREPLY=( $(compgen -W "$(r2 -qceq --)" -- $cur ))
		return 0
		;;
	-F)
		COMPREPLY=( $(compgen -W "$(rz_bin -qL)" -- $cur ))
		return 0
		;;
	-H)
		COMPREPLY=( $(compgen -W "$(r2 -H |cut -d = -f 1)" -- $cur))
		return 0
		;;
	-p)
		COMPREPLY=( $(compgen -W "$(r2 -p?)" -- $cur ))
		return 0
		;;
	-D)
		COMPREPLY=( $(compgen -W "$(r2 -D?)" -- $cur ))
		return 0
		;;
	esac

	case "$cur" in
	-*)
		COMPREPLY=( $( compgen -W '-0 -a -A -b -B -c -C -d -D -e -f -F -h -hh -H -i -I -k -l -L -m -M -n -nn -N -o -q -p -P -R -s -S -t -u -v -V -w -z -zz' -- $cur))
		;;
	*)
		COMPREPLY=( $(compgen -f -- $cur))
		;;
	esac

	return 0
}

complete -F _rz -o filenames r2
complete -F _rz -o filenames rizin

_rz_asm () {
	local cur
	COMPREPLY=()
	cur=${COMP_WORDS[COMP_CWORD]}
	prv=${COMP_WORDS[COMP_CWORD-1]}
	case "$prv" in
	-a)
		COMPREPLY=( $(compgen -W "$(rz_asm -qL)" -- $cur))
		return 0
		;;
	-b)
		COMPREPLY=( $(compgen -W "8 16 32 64" -- $cur ))
		return 0
		;;
	-c)
		# TODO. grab -a and get asm.cpu=? output
		return 0
		;;
	-k)
		COMPREPLY=( $(compgen -W "$(r2 -qc 'e asm.os=?' --)" -- $cur ))
		return 0
		;;
	-s)
		COMPREPLY=( $(compgen -W "$(rz_asm -s?)" -- $cur ))
		return 0
		;;
	esac

	case "$cur" in
	-*)
		COMPREPLY=( $( compgen -W '-a -A -b -c -C -d -D -e -E -f -F -h -i -k-l -L -o -O -s -B -v -w -q' -- $cur))
		;;
	*)
		COMPREPLY=( $(compgen -f -- $cur))
		;;
	esac

	return 0
}

complete -F _rz_asm -o filenames rz_asm

_rz_bin () {
	local cur
	COMPREPLY=()
	cur=${COMP_WORDS[COMP_CWORD]}
	prv=${COMP_WORDS[COMP_CWORD-1]}
	case "$prv" in
	-a)
		COMPREPLY=( $(compgen -W "$(rz_asm -qL)" -- $cur))
		return 0
		;;
	-b)
		COMPREPLY=( $(compgen -W "8 16 32 64" -- $cur ))
		return 0
		;;
	-c)
		# TODO. grab -a and get asm.cpu=? output
		return 0
		;;
	-k)
		COMPREPLY=( $(compgen -W "$(r2 -qc 'e asm.os=?' --)" -- $cur ))
		return 0
		;;
	-s)
		COMPREPLY=( $(compgen -W "$(r2 -qc 'e asm.syntax=?' --)" -- $cur ))
		return 0
		;;
	esac

	case "$cur" in
	-*)
		COMPREPLY=( $( compgen -W '-a -A -b -c -C -d -D -e -E -f -F -h -i -k-l -L -o -O -s -B -v -w -q' -- $cur))
		;;
	*)
		COMPREPLY=( $(compgen -f -- $cur))
		;;
	esac

	return 0
}

complete -F _rz_bin -o filenames rz_bin

_rz_find () {
	local cur
	COMPREPLY=()
	cur=${COMP_WORDS[COMP_CWORD]}
	case "$cur" in
	-*)
		COMPREPLY=( $( compgen -W '-a -b -e -f -h -m -M -n -r -s -S -t -v -x -X -z -Z' -- $cur))
		;;
	*)
		COMPREPLY=( $(compgen -f -- $cur))
		;;
	esac

	return 0
}

complete -F _rz_find -o filenames rz_find

_rz_diff() {
	local cur
	COMPREPLY=()
	cur=${COMP_WORDS[COMP_CWORD]}
	prv=${COMP_WORDS[COMP_CWORD-1]}
	case "$prv" in
	-a)
		COMPREPLY=( $(compgen -W "$(rz_asm -qL)" -- $cur))
		return 0
		;;
	-b)
		COMPREPLY=( $(compgen -W "8 16 32 64" -- $cur ))
		return 0
		;;
	esac
	case "$cur" in
	-*)
		COMPREPLY=( $( compgen -W '-a -A -AA -AAA -b -c -C -d -D -g -j -n -O -p -r -s -ss -S -t -x -v -V' -- $cur))
		;;
	*)
		COMPREPLY=( $(compgen -f -- $cur))
		;;
	esac

	return 0
}

complete -F _rz_diff -o filenames rz_diff
