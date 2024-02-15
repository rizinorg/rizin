<img width="150" height="150" align="left" style="float: left; margin: 0 10px 0 0;" alt="Rizin logo" src="https://raw.githubusercontent.com/rizinorg/rizin/dev/doc/img/rizin.svg?sanitize=true">

# Rizin

Rizin is a fork of the radare2 reverse engineering framework with a focus on
usability, working features and code cleanliness.

Rizin is portable and it can be used to analyze binaries, disassemble code,
debug programs, as a forensic tool, as a scriptable command-line hexadecimal
editor able to open disk files, and much more!

To learn more on Rizin, read the
[official Rizin book](https://book.rizin.re). 

# Table of Contents

1. [Rizin](#rizin)
2. [How to Install](#how-to-install)
3. [How to Build](#how-to-build)
4. [Contributing](#contributing)
    - [Tests](#tests)
5. [Supported Features](#supported-features)
    - [Supported Operating Systems](#supported-operating-systems)
    - [Supported Architectures](#supported-architectures)
    - [Supported File Formats](#supported-file-formats)
    - [Usage](#usage)
    - [Tools](#tools)
    - [Scripting](#scripting)
6. [Community](#community)
7. [Credits](#credits)
8. [License](#license)

# How to install

Look at [install instructions](https://rizin.re/install/) on our web page. This will show installation instructions
for the supported operating system.

# How to build

Use `meson` to compile and install Rizin. Please make sure to get an updated
`meson` (e.g. get it with `pip install meson` if your system does not provide
one that is at least version `0.55.0`).

Fork the repository, then clone the repository:
```
$ git clone "url of the forked repo"
```

Then compile and install with:
```
$ meson setup build
$ meson compile -C build
$ sudo meson install -C build
```

Now you can use `rizin`:
```
$ rizin
 -- Thank you for using rizin. Have a nice night!
[0x00000000]>

```

To uninstall rizin, execute `sudo ninja -C build uninstall`.


Please have a look at the [BUILDING.md][] for more information about building Rizin and for alternative methods.

# Contributing

We very much welcome any kind of contributions, from typos, to documentation, to
refactoring, up to completely new features you may think of. However, before contributing, we would like you to read the [CONTRIBUTING.md][] file so that we
can all be on the same page.

## Tests

Rizin utilizes both regression and unit tests. To see more information on the usage and writing of the tests, take a look at [test/README.md][].

# Supported features

## Supported Operating Systems

Windows 7 and higher, Apple macOS/iOS/iPadOS, GNU/Linux,
[Dragonfly|Net|Free|Open]BSD, Android, QNX, Solaris/Illumos, Haiku,
GNU/Darwin, GNU/Hurd.

## Supported Architectures

i386, x86-64, ARM/ARM64, RISC-V, PowerPC, MIPS, AVR, SPARC, System Z (S390),
SuperH, m68k, m680x, XAP, XCore, CR16, HPPA, ARC, Blackfin, Z80, H8/300,
Renesas (V810, V850, RL78), CRIS, XAP, PIC, LM32, 8051, 6502, i4004, i8080, Propeller,
Tricore, CHIP-8, LH5801, T8200, GameBoy, SNES, SPC700, MSP430, Xtensa,
NIOS II, TMS320 (c54x, c55x, c55+, c64x), Hexagon, DCPU16, LANAI,
MCORE, mcs96, RSP, C-SKY(MCore), VAX, AMD Am29000.

There is also support for the following bytecode formats:

Dalvik, EBC, Java, Lua, Python, WebAssembly, Brainfuck, Malbolge

## Supported File Formats

ELF, Mach-O, Fatmach-O, PE, PE+, MZ, COFF, OMF, NE, LE, LX, TE, XBE, BIOS/UEFI,
Dyldcache, DEX, ART, CGC, ELF, Java class, Android boot image, Plan9 executable,
ZIMG, MBN/SBL bootloader, ELF coredump, MDMP (Windows minidump), DMP (Windows pagedump),
WASM (WebAssembly binary), Commodore VICE emulator, QNX,
Game Boy (Advance), Nintendo DS ROMs and Nintendo 3DS FIRMs.

## Usage

To learn more about the basics of utilizing Rizin, check out the "First Steps" section of the 
[official Rizin book](https://book.rizin.re). Here, you will be able to learn about the different 
commands and features that are availabe when using `rizin`.

## Tools

Apart from the main tool `rizin`, there are also other tools tailored for specific purposes and 
useful for shell scripting or as separate standalone tools:

- `rz-bin` - provides all kind of information about binary formats
- `rz-asm` - a command-line assembler and disassemblers
- `rz-diff` - a tool to compare two binaries as raw data or analyzed executables
- `rz-hash` - allows to calculate different hashes or even encrypt data
- `rz-gg` - a small "eggs" code generator useful for exploitation purposes
- `rz-find` - binary analog of `find` tool, allowing to search patterns and bit masks
- `rz-sign` - tool to create, convert and parse FLIRT signatures
- `rz-ax` - a calculator and number format converter
- `rz-run` - a tool that allows to specify running environment and arguments for debugged file

To learn more about each tool and their usages, take a look at the 
[official Rizin book](https://book.rizin.re) and scroll down the table of contents until you find the "Command Line Tools" section.

## Scripting

We provide a way to interact with Rizin from Python, Haskell, OCaml,
Ruby, Rust, and Go languages through [rzpipe](https://github.com/rizinorg/rz-pipe).
Other languages although not currently supported could be easily added. Interact with the community if you would like to see other languages!

# Community

Our website and blog: [https://www.rizin.re/](https://www.rizin.re/)

Join our [Mattermost](https://im.rizin.re) community to discuss Rizin, its
development, and general topics related to the project.

We also provide the following partial bridges to other messaging platforms:
- [Telegram](https://t.me/rizinorg)
- IRC: [irc.libera.chat:6697 with TLS support](ircs://irc.libera.chat:6697)
  - Community - [#rizin](https://web.libera.chat/#rizin)
  - Developers - [#rizindev](https://web.libera.chat/#rizindev)

[CONTRIBUTING.md]: https://github.com/rizinorg/rizin/blob/dev/CONTRIBUTING.md
[test/README.md]: https://github.com/rizinorg/rizin/blob/dev/test/README.md
[BUILDING.md]: https://github.com/rizinorg/rizin/blob/dev/BUILDING.md
[DEVELOPERS.md]: https://github.com/rizinorg/rizin/blob/dev/DEVELOPERS.md

# Credits
<!-- add collaborators and team members, linking the github or other types of media -->

# License
<!-- add a license here if applicable? -->
