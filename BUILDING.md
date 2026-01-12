# Clone the Rizin project and keep it updated

The first time you download Rizin you can use:
```
$ git clone https://github.com/rizinorg/rizin
```

After that, use `git pull` to update the Rizin codebase.

# Build

Rizin uses [`meson`](https://mesonbuild.com/) to build. As not all systems have
a version of `meson` that is recent enough, we suggest to install it directly
from `pip` with `pip install meson`. If necessary, also install `ninja` with
`pip install ninja`.

If you are trying to build Rizin to create a package for a distribution,
take a look at [doc/PACKAGERS.md][].

## Note about debugging

Unless you are interested in debugging Rizin, it is a good idea to pass the `--buildtype=release` flag to `meson` for increased performance and to prevent the buggy `mspdbsrv.exe` process from [blocking/breaking the building process](https://social.msdn.microsoft.com/Forums/en-US/9e58b7d1-a47d-4a76-943a-4f35090616e8/link-fatal-error-lnk1318?forum=vclanguage) when generating `PDB` files in Windows. See the first table in the [Running Meson Documentation](https://mesonbuild.com/Running-Meson.html#configuring-the-build-directory) for other build types.

## *NIX systems

### Build system-wide, in `/usr/local`

This is the default configuration and it allows you to install your built Rizin
version while keeping, if provided, the Rizin version shipped by your
distribution in `/usr`.

```
$ meson --buildtype=release build
$ ninja -C build                # or `meson compile -C build`
$ sudo ninja -C build install   # or `sudo meson install -C build`
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
$ meson --buildtype=release --prefix=/usr build
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
$ meson --buildtype=release --prefix=~/.local build
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
[here](https://mesonbuild.com/Getting-meson.html). If using PowerShell, 
replace `%CD%` with `$((Get-Item .).FullName)`

```
$ meson --buildtype=release --prefix=%CD%\rizin-install build
$ ninja -C build
$ ninja -C build install
```

You can run rizin from `.\rizin-install\bin`. If you don't specify any
`--prefix`, meson will install rizin directly under `C:\`.

## Build with ASAN/UBSAN

Use `-Db_sanitize=address,undefined` during the setup phase.

```
$ meson --buildtype=release -Db_sanitize=address,undefined build
```

*Note*: Due to [a bug](https://github.com/google/sanitizers/issues/1716) in ASAN,
ASAN built binaries will crash or endlessly loop randomly, and only report
`AddressSanitizer:DEADLYSIGNAL`.
This also effects the build of Rizin, because we run an ASAN compiled binary (`sdb`)
during the build.
If this binary stays in an endless loop of `AddressSanitizer:DEADLYSIGNAL`,
the build will hang up and fill up your memory.

To fix this, you need to lower the size of the random offset applied
to VMA base addresses with:

```sh
sudo sysctl vm.mmap_rnd_bits=28
```

## Build fully-static binaries

It may be useful to run Rizin just by using a single file, which can be
copied on other systems if necessary. On *NIX systems, this adds the classic
`-static` flag to the linker, while on Windows it uses `/MT`.

```
$ meson --buildtype=release --default-library=static -Dstatic_runtime=true build
```

## Build and generate coverage report

Use `-Db_coverage=true` during the setup phase.

```
$ meson -Db_coverage=true --buildtype=debug build
```

Run the command you need the coverage for.

```sh
# For example the ARM asm tests
rz-test test/db/asm/arm*
```

Generate the coverage report as HTML with `gcovr`.

```bash
# Install gcovr via pip or any other way
pip install gcovr
mkdir cov_report
cd cov_report
# Generate coverage report for each directory and file
gcovr -r .. --html-nested coverage.html
```

Open `coverage.html` in your browser and explore.

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

More examples are in the [doc/examples/cross_builds/](https://github.com/rizinorg/rizin/blob/dev/doc/examples/cross_builds/) directory.

To make the deployment and usage of the rizin tools easier from within your
Android device, we suggest to compile statically and by using the *blob*
feature, which will produce just one executable and link all the other tools to
that only tool, similar to how busybox works.

```
$ meson --buildtype release --default-library static --prefix=/tmp/android-dir -Dblob=true build -Dstatic_runtime=true --cross-file ./cross-compile-conf.ini
$ ninja -C build
$ ninja -C build install
```

At this point you can find everything under `/tmp/android-dir` and you can copy
files to your Android device.

## Compile 32-bit Rizin on 64-bit machine

Whenever you want to build Rizin for a different system/architecture than the
one you are using for building, you are effectively cross-compiling and you
should provide a full configuration file to tell meson what is the target
machine.

Even to compile a 32-bit version of Rizin on a 64-bit machine, you should use
a configuration file like the following:

```
[binaries]
c = '/usr/bin/gcc'
cpp = '/usr/bin/g++'
ar = '/usr/bin/gcc-ar'
strip = '/usr/bin/strip'
pkgconfig = '/usr/bin/i686-redhat-linux-gnu-pkg-config'
llvm-config = '/usr/bin/llvm-config-32'

[built-in options]
c_args = ['-m32']
c_link_args = ['-m32']
cpp_args = ['-m32']
cpp_link_args = ['-m32']

[host_machine]
system = 'linux'
cpu_family = 'x86'
cpu = 'i686'
endian = 'little'
```

Alternatively, if your distribution provide specific compiler tools for the
i686 architecture, you can use a configuration similar to this:

```
[binaries]
c = '/usr/bin/i686-linux-gnu-gcc'
cpp = '/usr/bin/i686-linux-gnu-g++'
ar = '/usr/bin/i686-linux-gnu-gcc-ar'
strip = '/usr/bin/i686-linux-gnu-strip'
pkgconfig = '/usr/bin/i686-linux-gnu-pkg-config'

[host_machine]
system = 'linux'
cpu_family = 'x86'
cpu = 'i686'
endian = 'little'
```

Of course, you might have to adjust some settings depending on your system
and you should double check that you have installed all the necessary 32-bit
libraries and tools. Once you have checked everything, you can setup the
build directory with:

```
$ meson build --cross-file ./rizin-i386.ini
```

# Uninstall

If Rizin was installed using `meson`, you can run the following command from the
same build directory where you had previously installed Rizin:

```
$ sudo ninja -C uninstall # `sudo` may not be required based on how you configured the `build` directory with meson the first time
```

Furthermore, if you had installed Rizin using a distribution package, use the
corresponding package manager's method for removing a package to uninstall Rizin.

# Update

Firstly, use `git pull` to update the Rizin codebase to the latest version.

To re-build Rizin after you have updated your source code, you can use:
```
$ ninja -C build # or `meson compile -C build`
$ sudo ninja -C build install # or `sudo meson install -C build`. `sudo` may not be required based on how you configured the `build` directory with meson the first time
```

If you are a developer, it might not be necessary to run the `install` step
(the second step from above) every time you build Rizin. You can directly use
`rizin` from `./build/binrz/rizin/rizin`

If you encounter issues while re-building Rizin, try to remove the existing
build directory (e.g. `rm -r ./build`) and clean the subproject files
downloaded by meson (e.g. `git clean -dxff subprojects/`). Note that changing
a `meson.build` file does *not* guarantee a full rebuild.

[doc/PACKAGERS.md]: https://github.com/rizinorg/rizin/blob/dev/doc/PACKAGERS.md
