#!/bin/sh
cd `dirname $PWD/$0`/..
if [ -d rizin-bindings ]; then
	cd rizin-bindings
	git pull
else
	URL=`doc/repo BINDINGS`
	if [ -z "$URL" ]; then
		echo "No BINDINGS URL in doc/repo"
		exit 1
	fi
	git clone $URL rizin-bindings
fi
