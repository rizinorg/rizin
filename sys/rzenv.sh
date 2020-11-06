#!/bin/sh
# Sets up env for programs that use rizin libs, and rizin is installed in a
# non-standard location.

export PKG_CONFIG_PATH="`rizin -H RZ_LIBDIR`/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
export LD_LIBRARY_PATH="`rizin -H RZ_LIBDIR`${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
