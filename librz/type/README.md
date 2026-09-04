# Type database and pf format engine

This library owns Rizin's representation of C-style types (structs, unions,
enums, typedefs, callables) and the `pf` print-format language for decoding
raw bytes through that type information.

## Public headers

| Header        | Surface                                                        |
|---------------|----------------------------------------------------------------|
| `<rz_type.h>` | `RzTypeDB`, base types, callables, format storage              |
| `<rz_pf.h>`   | `RzPfFormat`, `RzPfValue`, `RzPfCtx`, parser/reader/renderer   |

`<rz_pf.h>` is included transitively from `<rz_type.h>`, so callers that
already include the latter need not include the former explicitly.

## File map

```
base.c                  RzBaseType (struct/union/enum/typedef) lifecycle
format.c                pf format-string codegen from RzType, the inverse
                        pf -> C-declaration converter, named-format storage
function.c              RzCallable definitions (function prototypes)
helpers.c               Type comparison, size, attribute helpers
path.c                  Path-style access into nested types
serialize_*.c           Project (de)serialization of types and functions
parser/                 Tree-sitter based C type parser

pf/                     The pf (print-format) engine. All sources live
                        under this directory; only format.c stays at the
                        librz/type/ top level.
pf/pf_parser.c          Parse driver, type-spec dispatcher, reader core,
                        parsing context, public utility surface
pf/pf_parser.h          Internal alias header -- includes <rz_pf.h>, plus
                        helpers shared with pf_render.c (is_string_type,
                        is_raw_type, endian_str, pf_vasprintf) as inlines
pf/pf_internal.h        Cross-TU glue: PF_DIAG diagnostic macro, the
                        shared ReadState, and declarations of every
                        function that crosses a pf file boundary
pf/pf_parser_string.c   String/encoding spec parsing + reading (z / s / Z)
pf/pf_parser_bitfield.c Inline + typed bitfield parsing (B...)
pf/pf_parser_bitvec.c   Bitvector parsing + reading (v(N))
pf/pf_parser_array.c    Array-count resolution ([N] / [@name])
pf/pf_parser_struct.c   Nested struct / union reading (?)
pf/pf_parser_time.c     Timestamp wire-format decoders
                        (filetime, dos, hfs, oletime, webkit, cocoa, ...)
pf/pf_parser_time.h     Private API between pf_parser.c and pf_parser_time.c
pf/pf_parser_tlv.c      TLV (Tag-Length-Value) record parsing and dispatch
pf/pf_render.c          Shared render helpers (pf_field_matches,
                        pf_scalar_text, pf_render_guid) and the
                        rz_pf_render() mode dispatcher
pf/pf_render.h          Cross-TU glue for the renderers: the RenderCtx
                        record and shared-helper / per-mode declarations
pf/pf_render_text.c     Text + quiet renderers
pf/pf_render_json.c     JSON renderer (+ rz_pf_render_json entry point)
pf/pf_render_cstruct.c  C-struct renderer
pf/pf_render_dot.c      Graphviz DOT renderer
pf/pf_render_sd.c       RzStructuredData renderer (rz_pf_render_sd)
```

## `pf` architecture

The `pf` format engine is a three-stage pipeline. Each stage is a public API
entry point so callers can mix and match:

```
   parse                read                       render
  +--------+         +------------------+         +---------------------+
  | source |  -->    | format -> values |  -->    | values -> string    |
  | string |         | (RzPfFormat,     |         | (text / json /      |
  |        |         |  RzPfValue[])    |         |  cstruct / quiet /  |
  +--------+         +------------------+         |  dot / write)       |
                                                  +---------------------+
```

| Stage      | Entry point     | Inputs                                   | Output         |
|------------|-----------------|------------------------------------------|----------------|
| parse      | `rz_pf_parse`   | format string                            | `RzPfFormat *` |
| read       | `rz_pf_read`    | format, buffer, base addr, ctx           | `RzPfValue *`  |
| render     | `rz_pf_render`  | values, count, mode, opts                | `char *`       |
| all-in-one | `rz_pf_format`  | source + buf + ctx + mode + opts         | `char *`       |

### parse

The parser is a single-pass recursive-descent walker over the format string.
For each token it decides the field type and any per-field metadata
(endianness, array count, encoding, timestamp format, GUID layout, TLV
spec, etc.). The token shape is the source of truth -- there is no separate
lexer.

Diagnostics are recorded both on the `RzPfFormat::errors[]` array (with
positioned messages) and on `RZ_LOG_WARN` (for backward compatibility). The
parser uses two file-scoped pointers (`g_current_fmt`, `g_current_src`) to
let leaf helpers emit positioned diagnostics without threading a context
pointer through every signature; these are set on entry and restored on
exit so the parser is safe to call recursively from `read_nested_struct`.

TLV specs (`V(t=...,l=...,e=...,h=...,d=...)`) and TLV value reads live in
`pf_parser_tlv.c`. The two TUs cross-call through a small set of internal
helpers (`pf_emit_error`, `pf_current_fmt`, `pf_current_src`,
`pf_parse_tlv_spec`, `pf_tlv_read`) declared `extern` in `pf_parser_tlv.c`
and defined in `pf_parser.c`.

### read

The reader walks the parsed format over a byte buffer and produces one
`RzPfValue` per top-level field, with nested struct children attached. The
read pass uses a per-instance `ReadState`:

```c
typedef struct {
    int bit_cursor;             /* 0..7 for :N bit fields */
    const RzPfValue *siblings;  /* for [@name] lookups */
    int n_siblings;
} ReadState;
```

The bit cursor is scoped to a single top-level repetition and a single
nested-struct instance. When a non-bit field is read while
`bit_cursor != 0`, the cursor snaps to the next byte boundary; this is the
"snap-flush" rule.

Bitvector fields (`v(N)`) intentionally bypass the bit cursor: each
`v(N)` reads exactly `ceil(N/8)` *whole bytes* and unpacks them into
N individual 0/1 scalars. They do not pack with neighbouring `:N`
fields, and reading a `v(N)` field next to a `:N` field will flush
any partially-consumed bit cursor first. The bit-order knob (`lsb`
vs `msb`) governs the per-byte unpacking, not the byte order itself.

`[@name]` length-by-reference works by scanning `siblings[0..n_siblings)`
for an earlier field with the matching name. Lookups never cross struct
boundaries.

Pointer dereference is delegated to the caller via `RzPfCtx::read_at` so
the type subsystem stays I/O-agnostic; the disasm and core printers
forward to `rz_io_nread_at`.

### render

Rendering is a separate pass over the `RzPfValue[]`. Most modes produce a
string; `WRITE` is handled by the bridge in `librz/core` rather than
`rz_pf_render`, and the structured-data renderer returns a tree rather
than text (see below):

- **text** -- `<offset> <name> : [endian] <value>` one line per field.
  Optionally colorised via `RzPfRenderOpts::palette`; the palette holds
  ANSI-escape strings indexed by role (offset / name / endian /
  hex_literal / label / reset).
- **json** -- JSON array (via `PJ`), with nested struct children under
  `"fields"`.
- **cstruct** -- C `struct[ <name>] { ... }` mirror with decoded values in
  comments. The format name (when invoked as `pfc <name>`) follows the
  `struct` keyword; anonymous formats render as `struct { ... }`.
- **quiet** -- value-only, no offsets or names.
- **dot** -- Graphviz `digraph` record node with four column-aligned rows
  (offset / type-glyph / name / value), one column per visible field. The
  graph label is taken from `RzPfRenderOpts::graph_label`.
- **structured data** -- not a string mode: `rz_pf_render_sd()` returns an
  `RzStructuredData` tree (the generic key/value document model shared with
  `rz_bin`, ASN.1 and PKCS#7), which the caller can serialise to JSON or
  YAML or walk with the generic iterator.

`RzPfRenderOpts` additionally holds an optional `field_filter` (skip
fields whose name does not match) used by `pf.<name>.<field>` selectors.

The renderer dispatcher is `rz_pf_render()` in `pf_render.c`, which fans
out to one translation unit per mode (`pf_render_text.c`,
`pf_render_json.c`, `pf_render_cstruct.c`, `pf_render_dot.c`,
`pf_render_sd.c`). `pf_render.c` keeps only the dispatcher and the helpers
shared across modes (`pf_field_matches`, `pf_scalar_text`,
`pf_render_guid`); `pf_render.h` declares those plus the shared
`RenderCtx` record and the per-mode entry points.

## Typedb integration

Named formats are stored in `RzTypeDB::formats` (`HtSS`). `rz_pf_resolve_name`
is the canonical resolver and the only function inside the type subsystem
that callers should use to look up a format by name. The TLV dispatch table
uses a `tlv.<name>.<hex-tag>` key convention in the same hash.

When a format references a typename via `?(Name)` / `E (Name) f` /
`B (Name) f`, the reader consults `typedb->types` (for enums and bitfields)
or recursively `rz_pf_resolve_name + rz_pf_parse` (for nested struct
formats). Recursion is bounded by `RzPfCtx::max_depth` (default 32) to
catch self-referential structs cleanly.

## Defining types from `pf` formats (`pf` → C)

`format.c` also hosts the reverse helper
`rz_type_format_to_c_declaration(name, fmt_str, &error)`: it parses a
`pf` format with `rz_pf_parse()` and emits an equivalent C `struct`/`union`
declaration built from the standard fixed-width types (`uint8_t`, `int32_t`,
`float`, ...). Feeding that declaration to the C type parser (as the `tdf`
command does) registers the format as a first-class `RzBaseType`, so it then
participates in type analysis -- which a bare `pf` format never does.

The conversion is purely *structural*: it consumes only the parsed
`RzPfFormat` (field kinds, widths, array counts, pointer flags) and never a
byte buffer, so it can run without any target data. A few specifiers have no
exact static C form and are mapped best-effort: `@N` alignment carries no
storage and is dropped; an unknown-length inline string `z` becomes
`char *` (a fixed `[N]z` becomes `char[N]`); LEB128 widens to its largest
decoded integer; and `?(Name)` / `E(Name)` emit `struct Name` / `enum Name`,
which must themselves be defined types for the declaration to parse.

## Error reporting

Each `RzPfError` carries:

- `severity`: `RZ_PF_ERR_WARN` (recoverable) or `RZ_PF_ERR_ERROR`
  (structural problem)
- `category`: `SYNTAX`, `SEMANTIC`, `RANGE`, `DEPRECATED`, `DATA`, `DEPTH`
- `pos`: 0-based column into the source format string
- `message`: human-readable diagnostic

`rz_pf_format_errors_to_string()` renders the array with caret-position
lines pointing at the offending column.

## Reference

See `doc/pf.md` for the user-facing `pf` DSL reference.
