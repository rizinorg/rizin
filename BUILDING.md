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

As not all systems look for libraries in `/usr/local` subdirectories, you may
have to set `LD_LIBRARY_PATH` to the proper path (e.g. `/usr/local/lib64` or
`/usr/local/lib`). Otherwise, if you don't want to change your `LD_LIBRARY_PATH`
you can use `meson -Dlocal=true build` in the first step to use `RPATH` and make
sure the rizin binary can find its libraries by itself.

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

This kind of installation usually does not require any change to
`LD_LIBRARY_PATH` and it should work out of the box.


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
to your `PATH` variable. As most systems don't look for libraries in
`~/.local/lib`/`~/.local/lib64`, you will have to set `LD_LIBRARY_PATH`
accordingly or, if you prefer, use `meson -Dlocal=true --prefix=~/.local build`
instead of just `meson --prefix=~/.local build`.

## Windows

The building steps on Windows are the same as on *NIX systems, however you will
have to run the following commands from the Visual Studio Developer Powershell
(on Visual Studio Community 2019 you can find it under Tools > Command Line >
Developer Powershell). To install Meson on Windows, follow instructions
[here](https://mesonbuild.com/Getting-meson.html). We also suggest to compile
Rizin statically, to avoid dealing with libraries when running the Rizin
binaries.

```
$ meson --prefix=$PWD\rizin-install --default-library=static -Dstatic_runtime=true build
$ ninja -C build
$ ninja -C build install
```

You can run rizin from `$PWD\rizin-install\bin`.

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

# Build with acr/Makefile (deprecated)

Rizin also support compilation with configure+make, however this is not
suggested and it is going to be removed in future releases.

To compile use:
```
$ ./configure --prefix=/usr
$ make
$ sudo make install
```
