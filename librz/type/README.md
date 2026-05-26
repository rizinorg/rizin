# Type database and `pf` format engine

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
format.c                Format-string codegen from RzType; named-format storage
function.c              RzCallable definitions (function prototypes)
helpers.c               Type comparison, size, attribute helpers
path.c                  Path-style access into nested types
serialize_*.c           Project (de)serialization of types and functions
parser/                 Tree-sitter based C type parser

pf_parser.c             Main pf parser, reader, and renderers
                        (text / json / cstruct / quiet / dot / write)
pf_parser.h             Internal alias header -- includes <rz_pf.h>
pf_parser_time.c        Timestamp wire-format decoders
                        (filetime, dos, hfs, oletime, webkit, cocoa, ...)
pf_parser_time.h        Private API between pf_parser.c and pf_parser_time.c
pf_parser_tlv.c         TLV (Tag-Length-Value) record parsing and dispatch
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

`[@name]` length-by-reference works by scanning `siblings[0..n_siblings)`
for an earlier field with the matching name. Lookups never cross struct
boundaries.

Pointer dereference is delegated to the caller via `RzPfCtx::read_at` so
the type subsystem stays I/O-agnostic; the disasm and core printers
forward to `rz_io_nread_at`.

### render

Rendering is a separate pass over the `RzPfValue[]`. There are six modes;
five produce text output, one (`WRITE`) is handled by the bridge in
`librz/core` rather than `rz_pf_render`:

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

`RzPfRenderOpts` additionally holds an optional `field_filter` (skip
fields whose name does not match) used by `pf.<name>.<field>` selectors.

The renderer dispatcher is `rz_pf_render()`; each mode has its own
`render_<mode>()` function inside `pf_parser.c`.

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
