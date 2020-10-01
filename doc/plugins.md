LIBR PLUGINS
============

Plugins must be configured using the root ./configure-plugins script.

Libraries can be compiled:
  - as shared libraries (so, dylib, dll)    (DEFAULT)
  - as static libraries (a, lib, ..)

        ./configure-plugins --enable-shared --enable-dynamic

R2_LIBR_PLUGINS environment variable is honored as another search path for plugins

Plugins can be:
  - not compiled
  - compiled as shared
  - compiled as static (inside the related library)

        librz/plugins/shared
        librz/plugins/static

the configure-plugins script will regenerate the required Makefiles
to build this stuff as defined.

PD: This is not implemented :)

--pancake
