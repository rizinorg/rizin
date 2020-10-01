OpenBSD build instructions
==========================

This document aims to explain the steps needed to build r2 and r2b-python on OpenBSD.

* Note that `make` (from GNU) is named `gmake`
* Stuff is installed in /usr/local
* clang (or gcc) is named cc and clang++ (or g++) is c++
* valabind is not packaged in the ports

Radare2 Dependencies:
---------------------

	doas pkg_add git gcc gmake pkgconf

	git clone https://github.com/rizinorg/rizin
	cd rizin
	sys/install.sh /usr/local

Python Swig Bindings Dependencies:
----------------------------------

	doas pkg_add pkgconf vala

	git clone https://github.com/radare/valabind
	cd valabind
	gmake
	doas gmake install PREFIX=/usr/local

Building Python Swig Bindings:
------------------------------

	git clone https://github.com/rizinorg/rizin-bindings
	cd rizin-bindings
	export CC=cc
	export CXX=c++
	export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
	./configure --prefix=/usr/local
	cd python
	gmake CC=$CC CXX=$CXX
	doas gmake install
