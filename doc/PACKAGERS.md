Packaging
=========

Thank you for taking the time to package Rizin!

There are some things to consider when packaging Rizin for your distribution.
We will look at each step below.

Cloning Source
--------------

Rizin uses git submodules to track versions of dependencies. You can check out
the Rizin source and all dependencies using
`git clone --recursive https://github.com/rizinorg/rizin`.

If you change branches run `git submodule update --init --recursive` to ensure
you are tracking the correct versions of the submodules.

Building
--------

Rizin uses the `meson` build system. Command line flags passed to meson can
change how Rizin is built.

To define the base install location for Rizin use the `--prefix` flag when
invoking `meson`. For system installs it is common to use `/usr`. If in doubt
check your distributions packaging guidelines.

Rizin uses the Capstone disassembly engine and supports versions 3, 4, and 5.
By default we pull version 4 and statically link it into the Rizin executables.
Some distributions might prefer that a system version of Capstone be
dynamically linked at runtime. To do this, use the `-Duse_sys_capstone=true`
command line option when running `meson`. See `capstone.md` for more details.

Once you are happy with the flags you have passed to `meson` to configure your
build you need to actually compile Rizin using `ninja`. You can do this with
`ninja -C build`.  The `-C` flag tells `ninja` to change into the directory
`build` before building. If you do not specify a `target` the default target of
`all` will be used.

Packaging
---------

The final step is creating a package from the build outputs. To do this we will
invoke `DESTDIR=$PKGDIR ninja -C build install`.

Recall in the building step how we defined a `--prefix` to choose where the
software was going to be installed? If we just ran `ninja -C build install`
then we would install the software into that prefix which would be `/usr` using
the example above. That isn't what we want when we are packaging software for
distribution! Defining `DESTDIR` allows us to choose a base location to install
to that isn't our system root. It could be something as simple as `rizin` which
would mean that `ninja` would actually copy our files to `./rizin/usr/**`.

There are files we want to include in the package that aren't installed using
`ninja` so we need to add these by hand.

To do this we can use `install` to create directories with the desired attributes
and copy the files in.

For example:

```sh
install -dm644 "${pkgdir}/usr/share/doc/rizin"
cp -r doc/* "${pkgdir}/usr/share/doc/rizin"
```

Will create a directory `${pkgdir}/usr/share/doc/rizin`, set the attributes to
`644`, and copy the docs files into that new directory. See
https://wiki.archlinux.org/index.php/File_permissions_and_attributes for more
information about attributes and permissions.

Examples
--------

Arch Linux [PKGBUILD](https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=rizin-git)

Compatibility
-------------

Try to create packages that do not conflict with existing `radare2` packages.
This may require removing some shared files from the Rizin package (like the
esil man page).
