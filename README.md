<img width="140" height="140" align="left"
style="float:left; margin:0 16px 0 0;"
alt="Rizin logo"
src="https://raw.githubusercontent.com/rizinorg/rizin/dev/doc/img/rizin.svg?sanitize=true">

# Rizin
### A modern reverse-engineering framework 🧠🔍

**Rizin** is an open-source reverse-engineering framework, born as a fork of radare2,
with a strong focus on **usability**, **clean design**, and **maintainability**.

It can be used to analyze binaries, disassemble code, debug programs,
perform forensic analysis, and work as a scriptable command-line
hexadecimal editor.

📖 **Learn more:** [Official Rizin Book](https://book.rizin.re)

# How to install

Look at [install instructions](https://rizin.re/install/) on our web page.

# How to build

Use `meson` to compile and install Rizin. Please make sure to get an updated
`meson` (e.g. get it with `pip install meson` if your system does not provide
one that is at least version `0.55.0`).

Clone this repository:
```
$ git clone https://github.com/rizinorg/rizin
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


Please have a look at [BUILDING.md][] for more information about building Rizin.

# Contributing

We welcome contributions of all kinds — from typo fixes and documentation improvements to refactoring and entirely new features.
Before contributing, please read [CONTRIBUTING.md][] to ensure we’re all aligned.

## Tests

Details on how to run the test suite and add new tests are available in  
[test/README.md][].


# Supported features

## Supported Operating Systems

Windows 7 and higher, Apple macOS/iOS/iPadOS, GNU/Linux,
[Dragonfly|Net|Free|Open]BSD, Android, QNX, Solaris/Illumos, Haiku,
GNU/Darwin, GNU/Hurd.

## Supported Architectures

**Native architectures**

i386, x86-64, ARM / ARM64, RISC-V, PowerPC, MIPS, AVR, SPARC, System Z (S390),  
SuperH, m68k, m680x, XAP, XCore, CR16, HPPA, ARC, Blackfin, Z80, H8/300,  
Renesas (V810, V850, RL78), CRIS, PIC, LM32, 8051, 6502, i4004, i8080,  
Propeller, Tricore, CHIP-8, LH5801, T8200, GameBoy, SNES, SPC700, MSP430,  
Xtensa, NIOS II, TMS320 (c54x, c55x, c55+, c64x), Hexagon, DCPU16, LANAI,  
MCORE, mcs96, RSP, C-SKY (MCore), VAX, AMD Am29000.

**Bytecode architectures**

Dalvik, EBC, Java, Lua, Python, WebAssembly, Brainfuck, Malbolge.


## Supported File Formats

ELF, Mach-O, Fat Mach-O, PE, PE+, MZ, COFF, OMF, NE, LE, LX, TE, XBE, BIOS / UEFI,  
Dyldcache, DEX, ART, CGC, Java class files, Android boot images,  
Plan 9 executables, ZIMG, MBN / SBL bootloaders, ELF core dumps,  
MDMP (Windows minidump), DMP (Windows pagedump),  
WASM (WebAssembly binaries), Commodore VICE emulator formats, QNX,  
Game Boy (Advance), Nintendo DS ROMs, Nintendo 3DS FIRMs.

## Tools

In addition to the main `rizin` shell, the project provides several specialized
tools designed for scripting, automation, and standalone use:

- **`rz-bin`** — inspect and extract information from binary formats
- **`rz-asm`** — command-line assembler and disassembler
- **`rz-diff`** — compare binaries as raw data or analyzed executables
- **`rz-hash`** — calculate hashes and perform basic cryptographic operations
- **`rz-gg`** — lightweight shellcode (“eggs”) generator for exploitation
- **`rz-find`** — binary equivalent of the `find` tool for pattern and mask searching
- **`rz-sign`** — create, convert, and parse FLIRT signatures
- **`rz-ax`** — calculator and number format conversion utility
- **`rz-run`** — configure and control the runtime environment of debugged programs


## Scripting

Rizin can be scripted and controlled via **rzpipe**, with bindings available for:

**Python • Haskell • OCaml • Ruby • Rust • Go**

👉 https://github.com/rizinorg/rz-pipe

Additional language bindings can be added with minimal effort.

---

## 🌍 Community

Stay connected with the Rizin community and development:

🌐 **Website & Blog**  
https://www.rizin.re/

💬 **Mattermost**  
Join discussions about Rizin, development, and reverse engineering:  
https://im.rizin.re

🔗 **Other Platforms**
- **Telegram**: https://t.me/rizinorg
- **IRC (Libera, TLS)**: ircs://irc.libera.chat:6697  
  - [#rizin](https://web.libera.chat/#rizin) — community  
  - [#rizindev](https://web.libera.chat/#rizindev) — developers
---

[CONTRIBUTING.md]: https://github.com/rizinorg/rizin/blob/dev/CONTRIBUTING.md  
[test/README.md]: https://github.com/rizinorg/rizin/blob/dev/test/README.md  
[BUILDING.md]: https://github.com/rizinorg/rizin/blob/dev/BUILDING.md  
[DEVELOPERS.md]: https://github.com/rizinorg/rizin/blob/dev/DEVELOPERS.md
