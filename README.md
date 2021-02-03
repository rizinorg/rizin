<img width="150" height="150" align="left" style="float: left; margin: 0 10px 0 0;" alt="Rizin logo" src="https://raw.githubusercontent.com/rizinorg/rizin/dev/doc/img/rizin.svg?sanitize=true">

# Rizin

Rizin is a fork of the radare2 reverse engineering framework with a focus on
usability, working features and code cleanliness.

Rizin is portable and it can be used to analyze binaries, disassemble code,
debug programs, as a forensics tool, as a scriptable command-line hexadecimal
editor able to open disk files, and much more!

To learn more on Rizin you may want to read the
[official Rizin book](https://book.rizin.re).

# How to install

You can find the latest release binaries for Android, Debian, Ubuntu, MacOS,
Windows [here](https://github.com/rizinorg/rizin/releases/latest). If we
don't provide a released binary for your system, you can still build Rizin
yourself.

# How to build

Use `meson` to compile and install Rizin. Please make sure to get an updated
`meson` (e.g. get it with `pip install meson` if your system does not provide
one that is at least version 0.55.0).

Clone this repository:
```
$ git clone https://github.com/rizinorg/rizin
```

Then compile and install with:
```
$ meson build
$ ninja -C build
$ sudo ninja -C build install
```

Now you can use `rizin`:
```
$ rizin --
 -- Thank you for using rizin. Have a nice night!
[0x00000000]>

```

To uninstall rizin, execute `sudo ninja -C build uninstall`.


Please have a look at [BUILDING.md][] for more information about building Rizin.

# Contributing

We very much welcome any kind of contributions, from typos, to documentation, to
refactoring, up to completely new features you may think of. Before
contributing, we would like you to read the file [CONTRIBUTING.md][], so that we
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
MCORE, mcs96, RSP, SuperH-4, VAX, AMD Am29000.

## Supported File Formats

ELF, Mach-O, Fatmach-O, PE, PE+, MZ, COFF, OMF, TE, XBE, BIOS/UEFI,
Dyldcache, DEX, ART, CGC, Java class, Android boot image, Plan9 executable,
ZIMG, MBN/SBL bootloader, ELF coredump, MDMP (Windows minidump),
WASM (WebAssembly binary), Commodore VICE emulator, QNX,
Game Boy (Advance), Nintendo DS ROMs and Nintendo 3DS FIRMs.

## Scripting

We provide a way to interact with Rizin from Python, Haskell, OCaml,
Ruby, Rust, and Go languages through [rzpipe](https://github.com/rizinorg/rz-pipe).
Other languages although not currently supported could be easily added.

# Community

Our website and blog: [https://www.rizin.re/](https://www.rizin.re/)

Join our [Mattermost](https://im.rizin.re) community to discuss Rizin, its
development, and general topics related to the project.

We also provide the following partial bridges to other messaging platforms:
- [Telegram](https://t.me/rizinorg)
- IRC: irc.freenode.net 
  - Community - [#rizin](https://webchat.freenode.net/?channels=#rizin)
  - Developers - [#rizindev](https://webchat.freenode.net/?channels=#rizindev)

[CONTRIBUTING.md]: https://github.com/rizinorg/rizin/blob/dev/CONTRIBUTING.md
[test/README.md]: https://github.com/rizinorg/rizin/blob/dev/test/README.md
[BUILDING.md]: https://github.com/rizinorg/rizin/blob/dev/BUILDING.md
[DEVELOPERS.md]: https://github.com/rizinorg/rizin/blob/dev/DEVELOPERS.md
