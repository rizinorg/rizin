# Introduction

Rizin is a fork of the radare2 reverse engineering framework with a focus on
usability, working features and code cleanliness.

Rizin is portable and it can be used to analyze binaries, disassemble code,
debug programs, as a forensics tool, as a scriptable command-line hexadecimal
editor able to open disk files, and much more!

To learn more on Rizin you may want to read the
[official Rizin book](https://book.rizin.re).

# How to install

You can find the latest release binaries for Android, Debian, Ubuntu, MacOS,
Windows [here](https://github.com/radareorg/radare2/releases/latest). If we
don't provide a released binary for your system, you can still build Rizin
yourself.

# How to build

Use `meson` to compile and install Rizin. Please make sure to get an updated
`meson` (e.g. get it with `pip install meson` if your system does not provide
one that is at least version 0.50.1).

Clone this repository and make sure to clone the submodules as well:
```
$ git clone --recurse-submodules https://github.com/rizinorg/rizin
```

Then compile and install with:
```
$ meson build
$ meson compile -C build
$ meson install -C build
$ rizin
Usage: rizin [-ACdfLMnNqStuvwzX] [-P patch] [-p prj] [-a arch] [-b bits] [-i file]
             [-s addr] [-B baddr] [-m maddr] [-c cmd] [-e k=v] file|pid|-|--|=
```

NOTE: You may have to add `LD_LIBRARY_PATH=/usr/local/lib64` or
`LD_LIBRARY_PATH=/usr/local/lib` based on your system to make sure rizin will
find the installed libraries.

Please have a look at [BUILDING.md][] for more information about building Rizin.

# Contributing

We very much welcome any kind of contributions, from typos, to documentation, to
refactoring, up to completely new features you may think of. Before
contributing, we would like you to read the file [CONTRIBUTING.md][]. so that we
can all be on the same page.

## Tests

Look at [test/README.md][].

# Supported features

## Supported Operating Systems

Windows (since XP), GNU/Linux, GNU/Darwin, GNU/Hurd, Apple's {Mac,i,iPad,watch}OS,
[Dragonfly|Net|Free|Open]BSD, Android, QNX, Solaris, Haiku, FirefoxOS.

## Supported Architectures

i386, x86-64, ARM, MIPS, PowerPC, SPARC, RISC-V, SH, m68k, m680x, AVR,
XAP, System Z, XCore, CR16, HPPA, ARC, Blackfin, Z80, H8/300, V810,
V850, CRIS, XAP, PIC, LM32, 8051, 6502, i4004, i8080, Propeller,
Tricore, CHIP-8, LH5801, T8200, GameBoy, SNES, SPC700, MSP430, Xtensa,
NIOS II, Java, Dalvik, WebAssembly, MSIL, EBC, TMS320 (c54x, c55x,
c55+, c66), Hexagon, Brainfuck, Malbolge, whitespace, DCPU16, LANAI,
MCORE, mcs96, RSP, SuperH-4, VAX.

## Supported File Formats

ELF, Mach-O, Fatmach-O, PE, PE+, MZ, COFF, OMF, TE, XBE, BIOS/UEFI,
Dyldcache, DEX, ART, CGC, Java class, Android boot image, Plan9 executable,
ZIMG, MBN/SBL bootloader, ELF coredump, MDMP (Windows minidump),
WASM (WebAssembly binary), Commodore VICE emulator, QNX,
Game Boy (Advance), Nintendo DS ROMs and Nintendo 3DS FIRMs, various filesystems.

## Scripting

We provide a way to interact with Rizin from Python/Haskell/OCaml languages
through [rzpipe](https://github.com/rizinorg/rizin-rzpipe). Other languages
although not currently supported could be easily added.

# Community

Website: [https://www.rizin.re/](https://www.rizin.re/)

IRC: irc.freenode.net #rizin

[CONTRIBUTING.md]: https://github.com/rizinorg/rizin/blob/dev/CONTRIBUTING.md
[test/README.md]: https://github.com/rizinorg/rizin/blob/dev/test/README.md
[BUILDING.md]: https://github.com/rizinorg/rizin/blob/dev/BUILDING.md
[DEVELOPERS.md]: https://github.com/rizinorg/rizin/blob/dev/DEVELOPERS.md
