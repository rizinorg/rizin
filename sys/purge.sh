#!/bin/sh

if [ -z "${MAKE}" ]; then
	 MAKE=make
	gmake --help >/dev/null 2>&1
	[ $? = 0 ] && MAKE=gmake
fi

echo "All files related to current and previous installations 
of r2 (including libraries) will be deleted. Continue? (y/n) "
read answer
case "$answer" in
y|Y)
    if [ -x /usr/bin/apt-get ] ; then
	    sudo apt-get remove rizin
	    sudo apt-get remove librizin-common
	    sudo apt-get remove --auto-remove librizin-common
	    sudo apt-get purge librizin-common
	    sudo apt-get purge --auto-remove librizin-common
	    sudo apt-get remove librizin
	    sudo apt-get remove --auto-remove librizin
	    sudo apt-get purge librizin
	    sudo apt-get purge --auto-remove librizin
    fi
    # TODO: support brew
    # TODO: support archlinux
    # TODO: support gentoo
    exit 0
esac

echo "Aborting."
exit 1
