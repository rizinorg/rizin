# `pf` -- print format

The `pf` command in Rizin formats raw bytes through a small domain-specific
language. This document is the reference for the language; the implementation
lives in `librz/type/pf_parser.c` and the public API is `<rz_pf.h>`.

## Quick examples

```text
pf "x4 magic"               # 32-bit hex LE named "magic"
pf "x4d4 magic count"       # two fields back-to-back, two names
pf "[8]c text"              # repeat: 8-char array named "text"
pf "?(_ELF32_HEADER) hdr"   # nested struct from typedb, named "hdr"
pf "z[2] s"                 # length-prefixed string (2-byte LE prefix)
pf "G uuid"                 # 16-byte GUID (Microsoft mixed-endian default)
pf "B4(R=1,W=2,X=4) perm"   # inline bitfield, three flag bits
pf "V(t=u1,l=u2,d=mytab)"   # TLV record dispatched via the mytab table
```

A `pf` format string has two halves separated by the first ASCII space: the
**spec** (left of the space, describes the wire-format) and the **names**
(right of the space, names each field for display). Within either half,
whitespace is not significant; specs and names use specific delimiters.

## Spec grammar

The spec is read left-to-right. Each token contributes one field to the
output. The token shape determines the field type.

### Sized integers

`{x,d,u,o,b,X,D,U,O,B}{1,2,4,8}`

- `x` -- hex, lowercase letter => little-endian
- `X` -- hex, uppercase letter => big-endian
- `d` / `D` -- signed decimal (LE / BE)
- `u` / `U` -- unsigned decimal (LE / BE)
- `o` / `O` -- octal (LE / BE)
- `b` / `B` -- binary (LE / BE)

The digit suffix selects the byte width: 1, 2, 4, or 8 bytes. Examples:

```text
x1   1-byte hex          d4   4-byte signed decimal
x2   2-byte hex LE       D4   4-byte signed decimal BE
u8   8-byte unsigned     b1   1-byte binary
```

### Floats

`f{2,4,8}` / `F{2,4,8}` -- IEEE-754 half / single / double, LE / BE.

Bare `f` / `F` is accepted but deprecated; use `f4` / `F8` explicitly.

### Strings

`z[(encoding)][prefix]`

- `z` -- NUL-terminated string in the default encoding (UTF-8).
- `z(<name>)` -- encoding override. The name is parsed by
  `rz_str_enc_string_as_type`; supported names are:
  - `guess` -- heuristic detection (default fallback)
  - `ascii` / `8bit` -- single-byte passthrough (use for Latin-1)
  - `utf8`, `mutf8` -- UTF-8 / Modified UTF-8
  - `utf16le`, `utf16be`, `utf32le`, `utf32be` -- UTF-16/32
  - `ibm037`, `ibm290` -- IBM code pages
  - `ebcdices`, `ebcdicuk`, `ebcdicus` -- EBCDIC variants (Spain, UK, US)
  - `settings` -- use the active console string encoding
- `z[N]` -- length-prefixed string. `N` is the prefix byte width (1, 2, 4, 8).
  The prefix is read in the field's current endianness; the body bytes follow
  immediately.
- `s` -- pointer to a NUL-terminated string. The pointer is the field's size
  (defaults to 8 bytes on 64-bit, 4 bytes on 32-bit); the string body is read
  via the I/O callback.

Legacy `Z` (UTF-16 LE zstring) and `w` (2-byte hex LE) are accepted with a
deprecation warning; use `z(utf16le)` and `x2`.

### Timestamps

`t(format)`

`format` is one of:

| Name       | Width  | Description                            |
|------------|--------|----------------------------------------|
| `unix32`   | 4 B    | Unix seconds since 1970 (32-bit)       |
| `unix64`   | 8 B    | Unix seconds since 1970 (64-bit)       |
| `unixms`   | 8 B    | Unix milliseconds                      |
| `unixus`   | 8 B    | Unix microseconds                      |
| `unixns`   | 8 B    | Unix nanoseconds                       |
| `filetime` | 8 B    | Windows FILETIME (100-ns ticks, 1601)  |
| `dos`      | 4 B    | DOS date|time (16+16)                  |
| `hfs`      | 4 B    | HFS+ seconds since 1904-01-01          |
| `oletime`  | 8 B    | OLE automation date (double, days)     |
| `webkit`   | 8 B    | WebKit microseconds since 1601         |
| `cocoa`    | 8 B    | Cocoa NSDate (double, seconds, 2001)   |

Aliases: `ntfs` maps to `filetime`.

Bare `t` / `T` and `t4` / `t8` are accepted with a deprecation warning. The
canonical form is `t(format)`.

### Composites

- `?` -- nested struct. The typename comes from `?(typename)` in the spec or
  `(typename)fieldname` in the names list. The named format must already
  exist in the typedb (e.g. registered via `pfn`).
- `E` -- enum. Behaves like a `u4` lookup against a typedb enum specified via
  `(enumname)fieldname` in the names list. `E1` / `E2` / `E4` / `E8` to use a
  different scalar width.
- `B` -- bitfield. Two flavours:
  - Typed: `B4 (perm) flags` -- `perm` resolved via the typedb.
  - Inline: `B4(R=1,W=2,X=4)` -- flags declared inline in parens. The presence
    of `=` inside the parens is the discriminator.
- `G[(layout)]` -- 16-byte GUID. Layouts:
  - `ms` (default) -- Microsoft mixed-endian (D1 LE u32, D2/D3 LE u16, D4 raw)
  - `be` -- RFC 4122 big-endian network order
  - `le` -- all little-endian
- `V[(...)]` -- TLV record. Parameters in parens:
  - `t=<type>` -- tag scalar (default `u1`)
  - `l=<type>` -- length scalar (default `u2`)
  - `e=le|be` -- default endianness for tag and length
  - `h=v|l|a` -- whether `len` covers (`v`)alue only, (`l`)+value, or (`a`)ll
    including tag+len (default `v`)
  - `d=<table>` -- dispatch table name. After reading the tag, look up
    `tlv.<table>.<hex-tag>` in the typedb; that entry is itself a `pf` format
    string that is applied to the value bytes.
- `r` -- raw hexdump. Length comes from the `[N]` repeat prefix.

### Repetition and arrays

- `[N]<type>` -- repeat the next field N times (a literal array).
- `[@name]<type>` -- repeat the next field N times where N is the integer
  value of an earlier field named `name`. The earlier field must be in the
  same struct instance.
- `{N}` at the top of the format -- repeat the entire format N times.
- A leading `0` (e.g. `0xx4`) marks the format as a union: all fields share
  offset 0; the resulting display offset is `0x0` everywhere.

### Padding and alignment

- `.` -- skip one byte (no name consumed).
- `@N` -- advance to the next offset that is a multiple of N. (No name
  consumed.)
- `:N[<|>]` -- read N bits from the current byte cursor:
  - `:8>` or `:8` -- MSB-first (default)
  - `:8<` -- LSB-first

  Consecutive `:N` fields share a bit-level cursor within the current byte;
  when a non-bit field follows, the cursor snaps to the next byte boundary.

- `v(N)` / `v(N,lsb)` / `v(N,msb)` -- **bitvector**: read N individual
  bits (1..4096) and expose them as N separate 0/1 scalars. Consumes
  exactly `ceil(N/8)` bytes from the buffer. Unlike `:N`, a bitvector
  does not interact with the packed-bit cursor -- each `v(N)` field
  reads whole bytes and stands alone.

  Bit order within each byte defaults to MSB-first (bit 7 of byte 0 is
  bit 0 of the vector). Pass `,lsb` for the Intel-style order.

  Forensics / RE use cases: page-frame allocation maps, NTFS `$Bitmap`
  clusters, ext4 block/inode bitmaps, ELF `DT_FLAGS_1`, PE
  characteristics, ACL bitmasks -- anywhere you want to *see* a
  bitmap rather than collapse it to a hex number.

  ```
  > wx abcd
  > pf v(12) bits
  0x00000000 : bits = [ 1 0 1 0 1 0 1 1 | 1 1 0 0 ] (12-bit)
  > pfj "v(16) bits"
  [{"name":"bits","type":"bitvec","offset":0,"bit_width":16,"value":"1010101111001101"}]
  ```

  JSON renders the vector as a compact string of `'0'`/`'1'` characters
  alongside a `bit_width` sibling. Quiet mode (`pfq`) emits the bits
  space-separated with no decoration.

### Pointer dereference

- `*<type>` -- read the field's bytes as a pointer (8 or 4 bytes depending on
  context bits), then follow the pointer through the I/O callback and decode
  `<type>` at the dereferenced address. The displayed value shows both the
  pointer value (`*0x...`) and the dereferenced payload.

## Names grammar

A name token can be:

- `name` -- plain field name.
- `(typename)name` -- field name with an attached typedb name (used by `?`
  for the struct format and by `E` / `B` for the enum / bitfield name).

If there are more spec fields than names, the trailing fields get auto-
generated names (`field_<n>`).

## Output modes

The same parsed format can be rendered in several modes (selected by the
caller, not by the format string):

- **text** (default) -- `<offset> <name> : [endian] <value>` one field per
  line. Nested struct children are indented. When `scr.color` is enabled,
  the output is colorised inline via the active console palette: offsets
  use `pal.offset`, names use `pal.fname`, the endian marker uses
  `pal.meta`, hex/number literals use `pal.num`, and typedb labels (enum
  names, bitflag names) use `pal.flag`. Users can re-theme this via the
  standard `eco` mechanism.
- **json** -- JSON array of field objects, with nested struct fields under
  `"fields"` and the struct name under `"struct_type"`.
- **cstruct** -- C `struct { ... }` declaration mirroring the field types and
  their decoded values in comments. When invoked as `pfc <name>` against a
  typedb-registered format, the format name is included after the `struct`
  keyword (e.g. `struct elf_header { ... }`).
- **quiet** -- value-only, one per line, no names or offsets.
- **dot** -- Graphviz `digraph` with each top-level field as a record cell
  inside a single `shape=record` node. Used by `pfd`.

## Diagnostics

Parse errors are collected on `RzPfFormat::errors[]`. Each error has a
severity (`WARN` / `ERROR`), a category (`SYNTAX`, `SEMANTIC`, `RANGE`,
`DEPRECATED`, `DATA`, `DEPTH`), and a 0-based column position into the
source format string. `rz_pf_format_errors_to_string()` renders them with
caret-position lines pointing at the offending column.

The legacy `RZ_LOG_WARN` channel is preserved for backward compatibility:
every diagnostic is also emitted there. New code that wants structured
errors should walk the `errors[]` array.
