# Rizin UI regression tests

UI tests exercise the real Rizin CLI and its interactive modes through a
scripted `RzCons` backend. They use the existing `rz-test` database, worker pool,
result enum and JSON reporting, `RzSubprocess` for process isolation, and `RzDiff`
for snapshot diagnostics. No PTY, ConPTY, display server, terminal installation,
Python terminal emulator, or optional runtime dependency is required.

## Running

Build normally with `enable_rz_test=true` (the default):

```sh
meson setup build
meson compile -C build
meson test -C build rz_test_ui cons tui tui_lifecycle --print-errorlogs
```

For an installed build, run from the `test` directory:

```sh
rz-test -j 4 @ui
rz-test -j 4 tui/visual
rz-test -o ui-results.json tui
```

`rz-test -r <bindir>` expects the matching `rz-test-ui` worker in that directory,
just like the other Rizin test tools. UI files are identified by `.rzt-ui`; the
existing default `db` selection is unchanged. `README.md` files are ignored
when traversing a test directory.

The dedicated frontend also works directly from the build tree:

```sh
build/binrz/rz-test-ui/rz-test-ui -V test/tui
build/binrz/rz-test-ui/rz-test-ui -t 10 test/tui/portable
```

On Windows the executable is `build\binrz\rz-test-ui\rz-test-ui.exe`.
Meson passes this build's worker directory explicitly with `-r`, since test
launchers can change the working directory while retaining a relative `argv[0]`.
It also enables verbose failure output to show the captured screen.

Both frontends use the same worker and assertions. The dedicated frontend runs
sequentially; use `rz-test -j` for concurrency. It does not silently accept `-j`.

## Execution model

Each record gets a fresh worker process. That process calls
`rz_main_rizin_with_cons()`, which installs a per-instance `RzConsBackend` before
processing the normal CLI arguments. There is no global callback registration
or environment variable that activates a special console in production Rizin.
The callback table is copied; its user data remains borrowed.

The console routes flushed ANSI/UTF-8 output, line-editor output, input, size
queries and terminal controls through the backend. Native terminal input/output
remains the default when no backend is attached. The worker models the usual
terminal LF-to-CRLF conversion explicitly.

A script advances when Rizin requests input. At that point pending console
output has been flushed and assertions inspect the resulting screen. A named
key or UTF-8 code point is one input event. Escape-sequence continuation bytes
stay in that event; a timed probe at its end returns no input, so a lone Escape
cannot steal the next scripted key. No input is preloaded into Rizin's buffer
where a redraw could discard it.

`RESIZE` updates the backend dimensions, invokes the registered resize event,
and supplies Ctrl-L to request a redraw. `QUIT`, or reaching the end of the
script at an input boundary, writes the complete result and exits the worker.
It intentionally does not guess a sequence of `q` keys or unwind library call
frames. Therefore this tests UI behavior, not graceful application shutdown.
An application exit before the final boundary is an infrastructure failure.

The parent enforces the timeout over startup and every step, kills a stuck
worker, drains/reaps it through `RzSubprocess`, and requires both successful
worker termination and a complete versioned result record. Results use a
private temporary file so ordinary stdout/stderr cannot masquerade as protocol
messages. The parent removes that file on all paths.

The process environment fixes `TZ=UTC`, `LC_ALL=C`, `TERM=xterm-256color`, and
`RZ_NOPLUGINS=1`. Rizin receives `-N`, explicit interactive/prompt settings,
`COLOR`/`UTF8`, the test's `ARGS`, and `FILE` after `--`.

## File format

```text
NAME=visual hexdump
FILE=malloc://128
ARGS=-a x86 -b 64 -c "wx 554889e5897dfc8b07c3"
COLS=80
ROWS=24
STEPS=<<END
KEYS V<ENTER>
EXPECT_LINE 0 malloc://128
EXPECT_LINE 2 5548 89e5 897d fc8b 07c3
QUIT
END
```

A record has a nonempty `NAME` and one nonempty `STEPS` block. `RUN` separates
records. The last record need not end in `RUN`. LF and CRLF, including a missing
final newline, are accepted. Full-line comments start with `#`; inline comments
are not interpreted because `#` can be expected text.

| Header | Meaning |
| --- | --- |
| `NAME` | Required descriptive name |
| `FILE` | One filename or URI; default `malloc://128` |
| `ARGS` | Additional CLI arguments, parsed like `rz-test`, without a shell |
| `COLS`, `ROWS` | Initial dimensions; defaults 80 and 24 |
| `TIMEOUT` | Positive seconds; overrides the frontend's per-test timeout |
| `COLOR`, `UTF8` | Boolean `0` or `1`; defaults `0` |
| `BROKEN` | Expected assertion failure, `0` or `1`; default `0` |

Duplicate/unknown headers, malformed numbers, unbalanced argument quotes,
unknown steps, invalid regexes, empty/unterminated blocks, and steps after
`QUIT` reject the **whole file**, even if preceding records are valid.
Headers must precede `STEPS`. Limits are 1024 columns, 512 rows, 3600 seconds,
16 MiB per file, and 65,536 expanded steps per record. Numeric values accept
decimal or `0x` hexadecimal (a leading zero follows C integer syntax); arithmetic
expressions are not accepted.

Coordinates are zero-based. `EXPECT_AT` and `EXPECT_CELL` accept negative
columns (`-1` is the rightmost cell). Out-of-range coordinates are errors,
including in negative assertions. Border ranges are inclusive and ordered.

| Step | Meaning |
| --- | --- |
| `KEY <key>` | Exactly one literal or named key |
| `KEYS <keys>` | A sequence of literal/named key events |
| `RESIZE <cols>x<rows>` | Resize and redraw before the next checkpoint |
| `EXPECT_LINE <row> <text>` | Row contains literal text |
| `EXPECT_NOLINE <row> <text>` | Row does not contain literal text |
| `EXPECT_AT <row> <col> <text>` | Text begins at the exact cell |
| `EXPECT_CELL <row> <col> <character>` | Cell has one Unicode code point |
| `EXPECT_VLINE <col> <first-row> <last-row> <character>` | Unbroken vertical run |
| `EXPECT_HLINE <row> <first-col> <last-col> <character>` | Unbroken horizontal run |
| `EXPECT_REGEX <pattern>` | Whole screen matches the regex |
| `EXPECT_NOREGEX <pattern>` | Whole screen does not match the regex |
| `EXPECT_REGEX_AT <row> <pattern>` | Regex against one row |
| `EXPECT_SCREEN <<MARKER` | Whole-screen expectation ending at `MARKER` |
| `CAPTURE` | Save the current screen for verbose diagnostics |
| `QUIT` | Complete the test at this input boundary |
| `WAIT <milliseconds>` | Legacy checkpoint; accepted but does not sleep |

Literal assertion text may be enclosed in double quotes, useful for spaces.
It is not C-escaped: `\n` means backslash followed by `n`. Regex syntax is passed
unchanged to `RzRegex`, with significant whitespace. A regex engine error fails
the worker; it can never make a negative assertion pass. Regex/line assertions
use rows with trailing spaces removed; use cell assertions for edge padding.

Named keys are `<ENTER>`/`<RET>`, `<ESC>`, `<TAB>`, `<SPACE>`, `<BS>`, `<DEL>`,
`<UP>`, `<DOWN>`, `<LEFT>`, `<RIGHT>`, `<HOME>`, `<END>`, `<PGUP>`, `<PGDN>`, and
`<F1>` through `<F12>`. Names are case-insensitive. Other text is literal input.

## Snapshots and acceptance

```text
EXPECT_SCREEN <<SCREEN
SCREEN
```

```sh
build/binrz/rz-test-ui/rz-test-ui -a test/tui/example.rzt-ui
```

Review the resulting diff and rerun the test. The acceptance run reports the
original result and exit status; a mismatch remains nonzero until rerun.
`rz-test -i`/`-y` do not rewrite UI records; use the dedicated `-a` frontend.

Snapshot comparison strips trailing ASCII spaces per row and trailing blank
rows. Indentation and interior blank rows remain significant. Differences use
`RzDiff` unified text output.

Acceptance is a transaction per source file. Every record must finish, every
snapshot must be captured, and all non-snapshot assertions must pass. A crash,
timeout, parser error, missing capture, failed assertion or changed source
prevents replacement. Captured text colliding with a heredoc delimiter is
rejected. Multiple records and empty snapshot blocks are supported.

Only snapshot content is replaced. Other bytes, delimiters and the surrounding
LF/CRLF convention are preserved. The replacement is written to an exclusively
created temporary in the same directory and committed with rename (POSIX) or
`MoveFileExW` (Windows). A write/close/replace failure is reported and removes
the temporary. POSIX permission bits are read with `fstat()` and applied with
`fchmod()` to the open temporary descriptor, never through its pathname.
Crash durability, extended attributes and ACL preservation are not promised.
Run acceptance in a checkout whose directory is writable only by trusted users.
The source-content check detects edits during a run; it is not an atomic
compare-and-swap against concurrent editors.

## Results and scope

The shared `RzTestResult` enum provides OK, FAILED, BROKEN and FIXED. A missing
worker, incomplete script, timeout, terminal-model error or protocol error is
always FAILED, even for `BROKEN=1`. Assertion failures alone honor BROKEN.
The dedicated frontend returns nonzero for FAILED or FIXED.

Fixture reads enforce the 16 MiB limit while reading and reject embedded NULs.
Snapshot text is limited to 16 MiB per worker and per acceptance transaction;
the resulting fixture must also fit that limit. Worker JSON reads are limited
to 128 MiB to allow JSON escaping and record metadata. Fixtures execute Rizin
commands with the runner's permissions; subprocess isolation is not a sandbox.

The screen parser uses bounded incremental state, saturating CSI parameters,
checked dimensions and transactional resize. It covers cursor movement, delayed
wrapping, erasure, insert/delete characters and lines, scroll regions, reverse
index, cursor save/restore, alternate screen 1049, DEC line drawing and UTF-8.
Wide-character widths follow Rizin's `rz_str_char_fullwidth()` policy. Clipping
or erasing half a wide character does not leave an orphan continuation cell.
OSC/DCS payloads are skipped without accumulating unbounded strings. Unsupported
geometry controls and incomplete sequences at checkpoints fail the worker.

This is a **text and layout** regression suite: SGR color/attributes are not
compared. It does not emulate grapheme shaping, combining-mark composition,
emoji presentation or every terminal extension. Use ASCII, box-drawing or
Rizin's full-width policy for exact geometry fixtures. It exercises synchronous
RzCons UI interactions, not asynchronous external programs, physical terminal
drivers, terminal font rendering or shutdown destructors. Those need separate
integration tests. Fixtures should use self-contained URIs and avoid host paths,
platform-specific debugger state and terminal-dependent glyph choices.

There are 30 UI fixtures: the original visual, function-browser, bit-editor and
panel tests, plus resize, mixed input, UTF-8/color, and lone-Escape cases.
`test_rz_test_ui.c` tests parsing, assertion bounds, chunking, Unicode width,
scrolling and adversarial streams; `test_cons.c` checks backend routing.
`test_rz_test_ui.py` tests real worker exits/timeouts and snapshot transactions.
Meson registers the fixtures and lifecycle checks in the integration suite on
all platforms where CLI tests are enabled. The implementation shares the
portable subprocess facilities already required by `rz-test`; native execution
on each supported OS/compiler remains necessary to establish platform coverage.
