# Install Rizin
Here you can find instructions to install Rizin on some common systems. If your
system is not listed here, we likely do not pre-compiled Rizin for it, but you
can still build it yourself by following the instructions in
[BUILDING.md](./BUILDING.md).

## Linux
We first suggest to look into your distribution repositories to check if Rizin
is already packaged there. If it is, install it from there, otherwise we have
repositories setup on [OBS](https://openbuildservice.org/) for some common
distributions.

Visit the web page
[https://software.opensuse.org/package/rizin](https://software.opensuse.org/download/package?package=rizin&project=home%3ARizinOrg)
and look for your system / version, if supported. Follow the instructions for
your distribution to install the repository.

## Windows
We provide two different ways to use Rizin on your Windows machine: an installer
and zip file containing all the necessary files. You can choose the method you
like the most. Both files can be found attached to the GitHub release at
https://github.com/rizinorg/rizin/releases/.

The installer is named as `rizin_installer-<version>-x86_64.exe` and it allows
you to install Rizin either system-wide or just for the current user.

The zip file contains statically compiled binaries and it is named
`rizin-windows-static-<version>.zip`. Files within the zip file can be extracted
anywhere because Rizin is compiled in a "portable" way, allowing moving the
whole directory anywhere.

## MacOS
On MacOS systems you can install Rizin in one of three ways.

Bear in mind the formula offered by Homebrew and the port offered by MacPorts
are not provided by Rizin: they are offered and actively maintained and updated
by their respective communities. Rizin *might* help with maintenance and fixes
in a punctual fashion, but it cannot guarantee these two installation methods
offer the latest available version.

You can always find the latest version in the package offered on the GitHub
release.

### Homebrew
Rizin offers a Homebrew [formula](https://formulae.brew.sh/formula/rizin)
through which you can install Rizin with a single command:

    brew install rizin

### MacPorts
Rizin offers a MacPorts [port](https://ports.macports.org/port/rizin/) too.
We can leverage it by running:

    sudo port install rizin

### Package file
Rizin can also be installed through .pkg files attached to the
GitHub release at https://github.com/rizinorg/rizin/releases/.

It is named as `rizin-macos-<version>.pkg`.

## Android
Statically compiled binaries for some common architectures where Android runs
are compiled and attached to all releases. We currently support aarch64, arm,
and x86_64. You can find the artifacts on the GitHub releases at
https://github.com/rizinorg/rizin/releases/.

Those files are named as `rizin-<version>-android-<architecture>.tar.gz`. Files
within the archive can be extracted anywhere on your Android device because
Rizin is compiled in a "portable" way, allowing moving the whole directory
anywhere.

## Others
If you are interested in providing Rizin in your distribution/system or in
adding support for other distribution formats (e.g. snap, flatpak, etc.),
please let us know and we would be glad to help you.
