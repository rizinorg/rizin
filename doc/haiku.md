r2 for Haiku
============

To compile for Haiku run configure in this way:

	HOST_CC=gcc-x86 CC=gcc-x86 ./configure --with-ostype=haiku --prefix=/boot/home/Apps/rizin

And then..

	HOST_CC=gcc-x86 make
	make install
	mv /boot/home/Apps/rizin/bin/* /boot/home/Apps/rizin/
	rmdir /boot/home/Apps/rizin/bin/

To install r2-bindings you will need to install r2, valac, valabind and swig
and copy/link libs to rizin/lib


TODO
====

* Add debugging support
