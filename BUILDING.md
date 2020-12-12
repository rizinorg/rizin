# Clone the Rizin project and keep it updated

Rizin uses submodules, so make sure to clone them as well. The first time you
download Rizin you can use:
```
$ git clone --recurse-submodules https://github.com/rizinorg/rizin
```
or:
```
$ git clone https://github.com/rizinorg/rizin
$ cd rizin
$ git submodule init
$ git submodule update
```

After that, use `git pull --recurse-submodules` to update both the Rizin
codebase and submodules, or `git submodule update` to just update the
submodules.

# Build

Rizin uses [`meson`](https://mesonbuild.com/) to build. As not all systems have
a version of `meson` that is recent enough, we suggest to install it directly
from `pip` with `pip install meson`. If necessary, also install `ninja` with
`pip install ninja`.

## *NIX systems

### Build system-wide, in `/usr/local`

This is the default configuration and it allows you to install your built Rizin
version while keeping, if provided, the Rizin version shipped by your
distribution in `/usr`.

```
$ meson build
$ ninja -C build # or `meson compile -C build`
$ sudo ninja -C build install # or `meson install -C build`
```

NOTE: when `--prefix=/usr` is not used, meson will set `RPATH` to ensure that
libraries can be found on the system without having to deal with
`LD_LIBRARY_PATH` or ld settings. This is done to ensure a simple
installation process out-of-the-box, but if you don't want this behaviour and
you know what you are doing, you can still use `-Dlocal=disabled` to avoid
using `RPATH`.

### Build system-wide, in `/usr`

If your system does not already provide rizin in `/usr/bin`, you want to package
Rizin on your preferred distribution or you just prefer to have Rizin together
with all other binaries on your system, you can also install it system-wide in
`/usr`.

```
$ meson --prefix=/usr build
$ ninja -C build
$ sudo ninja -C build install
```

This kind of installation is not recommended if your system provides Rizin as
a package or if you don't want to mess with software provided by your
distribution.


### Build user-wide, in `~/.local`

You are not forced to install Rizin in your system, you can just make it
available for your current user, without requiring you to have `sudo` access to
the machine (or if you don't trust our build scripts enough).

```
$ meson --prefix=~/.local build
$ ninja -C build
$ ninja -C build install
```

The `install` step will install rizin in `~/.local/bin`, so make sure to add it
to your `PATH` variable (e.g. `export PATH=$PATH:~/.local/bin`).

NOTE: meson will set `RPATH` to ensure that libraries can be found on the
system without having to deal with `LD_LIBRARY_PATH` or ld settings. This is
done to ensure a simple installation process out-of-the-box, but if you don't
want this behaviour and you know what you are doing, you can still use
`-Dlocal=disabled` to avoid using `RPATH`.

## Windows

The building steps on Windows are the same as on *NIX systems, however you
will have to run the following commands from the Visual Studio Developer
shell (search for "x64 Native Tools Command Prompt for VS 2019" or similar).
To install Meson on Windows, follow instructions
[here](https://mesonbuild.com/Getting-meson.html).

```
$ meson --prefix=%CD%\rizin-install build
$ ninja -C build
$ ninja -C build install
```

You can run rizin from `%CD%\rizin-install\bin`. If you don't specify any
`--prefix`, meson will install rizin directly under `C:\`.

## Build with ASAN/UBSAN

Use `-Db_sanitize=address,undefined` during the setup phase.

```
$ meson -Db_sanitize=address,undefined build
```

## Build fully-static binaries

It may be useful to run Rizin just by using a single file, which can be copied
on other systems if necessary.

```
$ CFLAGS="-static" meson --default-library=static build
```

## Cross-compilation for Android

You can cross-compile rizin from your main machine to target your Android
device. First download and install the Android NDK from
[https://developer.android.com/ndk](https://developer.android.com/ndk).

Then you can use meson to cross-compile, however you have to provide a
configuration file that specifies all the necessary information meson needs to
know to correctly cross-compile.

You can find an
[example](https://github.com/rizinorg/rizin/blob/dev/.github/meson-android-aarch64.ini)
of such a file in our codebase, but you should adjust it to match your system.

To make the deployment and usage of the rizin tools easier from within your
Android device, we suggest to compile statically and by using the *blob*
feature, which will produce just one executable and link all the other tools to
that only tool, similar to how busybox works.

```
$ CFLAGS="-static" LDFLAGS="-static" meson --buildtype release --default-library static --prefix=/tmp/android-dir -Dblob=true build --cross-file ./cross-compile-conf.ini
$ ninja -C build
$ ninja -C build install
```

At this point you can find everything under `/tmp/android-dir` and you can copy
files to your Android device.

# Build with acr/Makefile (deprecated)

Rizin also support compilation with configure+make, however this is not
suggested and it is going to be removed in future releases.

To compile use:
```
$ ./configure --prefix=/usr
$ make
$ sudo make install
```

# Uninstall

If Rizin was installed using `meson`, you can run the following command from the
same build directory where you had previously installed Rizin:

```
$ ninja -C uninstall
```

If you had compiled Rizin using `configure` and `make` (**deprecated**), use:

```
$ sudo make uninstall
```

Furthermore, if you had installed Rizin using a distribution package, use the
corresponding package manager's method for removing a package to uninstall Rizin.

# Update

Firstly, use `git pull --recurse-submodules` to update both the Rizin
codebase and its submodules to the latest version.

To re-build Rizin after you have updated your source code, you can use:
```
$ ninja -C build # or `meson compile -C build`
$ sudo ninja -C build install # or `meson install -C build`
```

If you are a developer, it might not be necessary to run the `install` step
(the second step from above) every time you build Rizin. You can directly use
`rizin` from `./build/binrz/rizin/rizin.`
