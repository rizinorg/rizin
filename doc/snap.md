Installing the snap package of rizin
======================================
rizin is also available as a snap package and can be installed on a system that supports snap packages. See [Installing snapd](https://snapcraft.io/docs/installing-snapd) to setup your system to support snap packages. 

Status of snap package support
------------------------------
Currently, rizin is available as a _beta_ snap package that works in _devmode_ security confinement (developer mode). Refer back to this section for updated instructions when rizin is out of _beta/devmode_. 

Currently, you need to prepend `rizin.` to each command you want to run. For example, use `rizin.rz_bin` to run `rz_bin`. 

Snap packages that work in _devmode_ security confinement do not appear in search results, when you search for them in the Snap Store. To find information about this snap package, run `snap info rizin`. See the section below on this.

Installing rizin
-----------------
This command installs the `rizin` snap package from the _beta_ channel, using the _devmode_ (developer mode) security confinement type. The _devmode_ security confinement disables any restrictions that are applied to typical snap packages. _devmode_ makes a package to work similar to APT and RPM packages. 

    $ sudo snap install rizin --channel=beta --devmode
    
Running commands
----------------

Currently, the rizin commands can be invoked with the following names: 

- `rizin` or `rizin.rizin`: The `r2`/`rizin` command.
- `rizin.rz_pm` : The `rz_pm` command.
- `rizin.rz_agent` : The `rz_agent` command.
- `rizin.rz_find` : The `rz_find` command.
- `rizin.rz_hash` : The `rz_hash` command.
- `rizin.rz_asm` : The `rz_asm` command.
- `rizin.rz_bin` : The `rz_bin` command.
- `rizin.rz_diff` : The `rz_diff` command.
- `rizin.rz_gg` : The `rz_gg` command.
- `rizin.rz_run` : The `rz_run` command.
- `rizin.rz_ax` : The `rz_ax` command.
- `rizin.rz_sign` : The `rz_sign` command.

Getting info about the rizin snap package
-------------------------------------------

Run the following command to get info about the rizin snap package. You can see the list of available commands and how to invoke them. There are packages in the `beta` and `edge` channels, currently with rizin 4.5.0. The build number in this example is 5, and is an ascending number that characterises each new build. We have installed radare 4.5.0 from build 5, using the _devmode_ security confinement. We are _tracking_ the `beta` channel. Since the installed build number is the same as the build number in the channel that we are tracking, we are already running the latest available version.

```
$ snap info rizin
...
description: |
  Radare2 (also known as r2) is a complete framework for reverse-engineering 
  and analyzing binaries; composed of a set of small utilities 
  that can be used together or independently from the command line. 
  Built around a disassembler for computer software which generates 
  assembly language source code from machine-executable code, 
  it supports a variety of executable formats for different processors 
  and operating systems.

commands:
  - rizin.rz_agent
  - rizin.rz_pm
  - rizin.rz_bin
  - rizin.rizin
  - rizin.rz_diff
  - rizin.rz_find
  - rizin.rz_gg
  - rizin.rz_hash
  - rizin.rz_run
  - rizin.rz_sign
  - rizin.rz_asm
  - rizin.rz_ax
snap-id:      ceuTRkmV5T8oTHt2psXxLRma25xfBrfS
tracking:     latest/beta
refresh-date: today at 12:51 EEST
channels:
  latest/stable:    –
  latest/candidate: –
  latest/beta:      4.5.0 2020-07-23 (5) 15MB devmode
  latest/edge:      4.5.0 2020-07-23 (5) 15MB devmode
installed:          4.5.0            (5) 15MB devmode
```

Updating rizin
----------------

The snap packages that are installed in _devmode_ are not updated automatically.
You can update manually: 

    $ sudo snap refresh rizin

See the section above on how to get info about the rizin snap package and how to determine whether there is an updated version available. 

Uninstalling rizin
--------------------
Run the following command to uninstall the snap package of rizin:

    $ sudo snap remove rizin

Supported architectures
=======================
The rizin snap package is currently available for the following architectures:

1. `amd64`
1. `i386`
1. `arm64`
1. `armhf`
1. `ppc64el`
1. `s390x`

Troubleshooting
---------------

- _error: snap "rizin" is not available on stable_: When installing the snap package of rizin, you currently need to specify the _beta_ channel. Append `--channel=beta` on the installation command line.
- _error: The publisher of snap "rizin" has indicated that they do not consider this revision to be of production quality_: When installing the snap package of rizin, you currently need to specify the _devmode_ confinement. Append `--devmode` on the installation command line. 
- _How can I download the snap package for offline use?_: Use the command `snap download rizin --channel=beta`. You can then run `sudo snap install` to install the `.snap` package that was just downloaded. 
- _Do I need to use "sudo" with snap commands?_: You need to prepend `sudo` when you run most snap commands that perform privileged actions. However, if you log in into the Snap Store using `sudo snap login`, then you do not need anymore to prepend `sudo`.

