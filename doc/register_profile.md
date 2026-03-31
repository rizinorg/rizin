# Architecture Register Profile

Plugins define the registers of an architecture in a big register profile string.

Here an example:

```c
      // A comment
      "# RSI     preserved source\n"
      // Alias definitions
      "=PC	rip\n" // A register alias
      "=SP	rsp\n"
      "=BP	rbp\n"
      "=A0	rcx\n"
      "=A1	rdx\n"
      // ...
      // Register definitions
      "gpr	rax	.64	80	0\n" // A GPR register
      "gpr	eax	.32	80	0\n"
      "gpr	ax	.16	80	0\n"
      // ...
      "seg	cs	.64	136	0\n" // A segment register
      "flg	rflags	.64	144	0	c1p.a.zstido.n.rv\n" // A flag register
      "flg	eflags	.32	144	0	c1p.a.zstido.n.rv\n"
      // ...
```

Alias and register definitions are required. A single definition is on each new line.

You can find the parsing code in `librz/reg/profile.c`.

## Syntax

**Alias**

A register alias string is of the following form:

```
=<alias>  <real-name>
```

Some alias:
- `PC`: Program Counter
- `BP`: Base Pointer
- `SP`: Stack Pointer
- `A0-A9`: Argument registers 0-9
- `R0-R9`: Return registers 0-9

Check out the `RzRegisterId` enumeration for more alias.

**Registers**

A register definition string is of the following form:

```
<(<sub-type>@)main-type>  <name>  <(.)size>  <byte offset(.<bit offset>)>  <(.)packed>  (<# comment> OR <flags>)
```

_Tokens_

- Elements in "()" are optional.
- Each "<...>" token is separated by tab or space characters.

| Token | Meaning | Note |
|-------|---------|------|
| sub-type/main-type | Main-types and sub-types can be `GPR`, `FPU` and some more (see `rz_reg.h::RzRegisterType`). The main type always defines to which group/arena the register belongs. ||
| name | Can be any string, as long as it doesn't contain blank character '\s'. ||
| size | Size of the register as a decimal. If it is prefixed with a `'.'` it is interpreted as bits. Otherwise as bytes. ||
| byte/bit offset | The offset from the start of the register profile. The register content is written at this offset. If two registers overlap or share the same offset, they will update same data. | This behavior does not work with RzIL currently! The RzIL VM will only use the first of two overlapping registers! If you implement RzIL for an architecture, you cannot let the registers overlap. |
| packed | Size of the register when it is packed. This is a decimal. If it is prefixed with a `'.'` it is interpreted as bits. Otherwise as bytes. ||
| Comment or flags | Only one of them is possible. Comments are prefixed with a `#`. Flag bits encoded in the register can be any string without a blank character. ||
