How to Build for Windows
========================

You can follow the [r2book](https://radare.gitbooks.io/rizinbook/content/first_steps/windows_compilation.html) for a more complete guide.

Native
---------------

You will need:

* Python 3
* Meson (pip3 install meson)
* Visual Studio 2015 (or later)

	
First, call `vcvarsall.bat` with your architecture (x86, x64, arm) to setup the compilation environment.

	cd rizin	
	python3 sys\meson.py --release --backend vs2019 --shared --install --prefix="%cd%\rizin_dist" --webui

You can change `--backend` to your VS version (`vs2015`, `vs2017`), `ninja` buildsystem is also supported.

For XP support, append `--xp` to the command (not compatible with VS2019).

You can then add `rizin_dist` to your PATH to make rizin accessible from everywhere.

Crosscompilation
----------------

As building with mingw is no longer officially supported in rizin, crosscompilation isn't (easily) possible.

You can check the official [Meson documentation](https://mesonbuild.com/Cross-compilation.html).

Good luck.
