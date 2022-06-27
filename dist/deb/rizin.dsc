Format: 1.0
Source: rizin
Binary: rizin, librizin-dev, rizin-common
Architecture: any all
Version: 0.4.0-1
Maintainer: RizinOrg <info@rizin.re>
Homepage: https://rizin.re/
Standards-Version: 4.5.1
Vcs-Browser: https://github.com/rizinorg/rizin
Vcs-Git: https://github.com/rizinorg/rizin
Build-Depends: debhelper (>= 12), meson (>= 0.55.0), ninja-build, pkg-config, python3, python3-setuptools
Package-List:
 rizin deb devel optional arch=any
 rizin-common deb devel optional arch=all
 librizin-dev deb libdevel optional arch=any
