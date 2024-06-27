Packaging
=========

Thank you for taking the time to package Rizin!

There are some things to consider when packaging Rizin for your distribution.
We will look at each step below.

Releases vs Git content
--------------

If you package a Rizin Release, you will find the tarball with all
dependencies used by Rizin in the
[Release page](https://github.com/rizinorg/rizin/releases) and you can go to
the next step in this document.

If you want to package a particular git version, keep in mind that Rizin uses
meson subprojects to track versions of dependencies. Subprojects are usually
downloaded during the meson setup step, however, if you can't download
additional code while building the package for your distribution you can
pre-download everything with the following command:
```
$ git clone https://github.com/rizinorg/rizin
$ cd rizin
$ meson subprojects download
```
If you want to prepare a special tarball to use within your distribution,
have a look at [`meson dist`](https://mesonbuild.com/Creating-releases.html).

See [BUILDING.md][] for more details.

Building
--------

Rizin uses the `meson` build system. Command line flags passed to meson can
change how Rizin is built.

First, we suggest you use the options `-Dpackager_version=<package-version>`
and `-Dpackager=<packager>` to help us track the version of Rizin users are
using, because these options are used when you run `rizin -v`. In this way
when a user reports an issue and provides his `rizin -v` output, we know
how Rizin was built. Below, you can see an example of how rizin uses the
additional information:
```
rizin 0.2.0-git @ linux-x86-64, package: 0.2.0-git (rizinorg)
commit: 84d2892e7210dc3ced88ae006ba5a9502f4847c8, build: 2021-01-29__09:35:03
```

Then, to define the base install location for Rizin use the `--prefix` flag when
invoking `meson`. For system installs it is common to use `/usr`. If in doubt,
check your distributions packaging guidelines.

If you do not use `/usr` as a prefix, you may want to use `-Dlocal=disabled` to
avoid `RPATH` in the installed binaries.

If you want to specify different directories for binaries, libraries, header
files, etc., you may want to look at `--bindir`, `--libdir`, `--includedir` or
check `meson setup --help` for more options. For extra control over the
directories used by Rizin, have a look at options `rizin_sdb`,
etc. in [meson_options.txt][].

Rizin uses the Capstone disassembly engine and supports versions 3, 4, and 5.
By default, we use a custom version of Capstone based on v5 and statically link
it into the Rizin executables.  Some distributions might prefer that a system
version of Capstone be dynamically linked at runtime. To do this, use the
`-Duse_sys_capstone=enabled` command line option when running `meson`.

You can override the version of Capstone Rizin will use by setting
`use_capstone_version` to one of `v4`, `v5` or `next`.

There are more bundled dependencies that can be swapped out for system versions.
At the time of writing, these are:
* `use_sys_magic`
* `use_sys_libzip`
* `use_sys_lzma`
* `use_sys_zlib`
* `use_sys_lz4`
* `use_sys_libzstd`
* `use_sys_xxhash`
* `use_sys_openssl`
* `use_sys_libmspack`
* `use_sys_pcre2`
* `use_sys_tree_sitter`
* `use_sys_softfloat`

See [meson_options.txt][] for a complete list of compile-time options.

Once you are happy with the flags you have passed to `meson` to configure your
build, you need to actually compile Rizin using `ninja`. You can do this with
`ninja -C build`.

See [BUILDING.md][] for more details.

Packaging
---------

The final step is creating a package from the build outputs. To do this it may
be required to invoke `DESTDIR=$PKGDIR ninja -C build install` based on the
distribution you are targeting.

Recall in the building step how we defined a `--prefix` to choose where the
software was going to be installed? If we just ran `ninja -C build install`
then we would install the software into that prefix, `/usr` using
the example above. That isn't what we want when we are packaging software for
distributions! Defining `DESTDIR` allows us to choose a base location to install
to that isn't our system root. It could be something as simple as `rizin` which
would mean that `ninja` would actually copy our files to `./rizin/usr/**`.

There are files we want to include in the package that aren't installed using
`ninja` so we need to add these by hand.

To do this, we can use `install` to create directories with the desired attributes
and copy the files in.

For example:

```sh
install -dm644 "${destdir}/usr/share/doc/rizin"
cp -r doc/* "${destdir}/usr/share/doc/rizin"
```

Will create a directory `${destdir}/usr/share/doc/rizin`, set the attributes to
`644`, and copy the docs files into that new directory. See
https://wiki.archlinux.org/index.php/File_permissions_and_attributes for more
information about attributes and permissions.

Licenses
--------

As Rizin is trying to use SPDX, if your package needs license/copyright
information, you can use the [REUSE Software](https://reuse.software/) to
extract the license/copyright of all files in the repository.

Examples
--------

Arch Linux [PKGBUILD](https://gitlab.archlinux.org/archlinux/packaging/packages/rizin/-/blob/main/PKGBUILD?ref_type=heads)

Compatibility
-------------

Try to create packages that do not conflict with existing `radare2` packages.
This may require removing some shared files from the Rizin package (like the
esil man page).

Existing packages
-----------------

OSX: execute `dist/osx/build_osx_package.sh` on a MacOS system to create a .pkg installer in the base directory, named `rizin-${VERSION}.pkg`.
Windows installer: execute `dist/windows/build_windows_installer.ps1` Powershell script on a Windows system to create a .exe installer in `dist/windows/Output`, named `rizin.exe`.


[BUILDING.md]: https://github.com/rizinorg/rizin/blob/dev/BUILDING.md
[meson_options.txt]: https://github.com/rizinorg/rizin/blob/dev/meson_options.txt
