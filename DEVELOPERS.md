# DEVELOPERS

This file is aimed at developers who want to work on the Rizin code base.

## Documentation

There is support for Doxygen document generation in this repo.
By running `doxygen` in the root of this repository, it will autodetect the
Doxyfile and generate HTML documentation into
[doc/doxygen/html/index.html](./doc/doxygen/html/index.html).

If you're contributing code or willing to update existing code, you should use the
doxygen C-style comments to improve documentation and comments in code.
See the [Doxygen Manual](http://www.doxygen.nl/manual/index.html)
for more info. Example usage can be found [here](http://www.doxygen.nl/manual/docblocks.html).

Documentation goes into the source files (not the header files).

```c
/**
 * \brief Find the min and max addresses in an RzList of maps.
 * \param maps RzList of maps that will be searched through
 * \param min Pointer to a ut64 that the min will be stored in
 * \param max Pointer to a ut64 that the max will be stored in
 * \param skip How many maps to skip at the start of an iteration
 * \param width Divisor for the return value
 * \return (max-min)/width
 *
 * Used to determine the min & max addresses of maps and
 * scale the ascii bar to the width of the terminal
 */
static int find_min_max(RzList *maps, ut64 *min, ut64 *max, int skip, int width) { /* ... */ }
```

In order to improve the documentation and help newcomers, documenting code is mandatory.

You should add or update the documentation of:
- code written by you.
- existing Rizin code you changed.

Exceptions:
- Trivial changes.

If you have not updated the documentation, explain why.
E.g.: `Bug fix did not change the general behavior of the function. No documentation update needed.`

## Code style

### C

In order to contribute with patches or plugins, we encourage you to use the same
coding style as the rest of the code base.

* Use git-clang-format 16 to format your code. If clang-format-16 is not available on
  your Debian-based distribution, you can install it from https://apt.llvm.org/.
  You should invoke it as below (after making sure that your local copy of `dev`
  is up-to-date and your branch is up-to-date with `dev`):

```bash
git-clang-format-16 --extensions c,cpp,h,hpp,inc --style file dev
```

  There is a script available to run on all source files; you will need python and
  the gitpython python library, which you may install e.g. from pip. Invoke it as
  follows (after making sure that your local copy of `dev` is up-to-date and your
  branch is up-to-date with `dev`):

```bash
./sys/clang-format.py
```

* Lines should be at most 100 chars. A tab is considered as 8 chars. If it makes
  things more readable, you can use more than 100 characters, but this should be
  the exception, not the rule.

* Always use braces for if and while.

* In general, don't use goto. The goto statement only comes in handy when a
  function exits from multiple locations and some common work such as cleanup
  has to be done. If there is no cleanup needed, then just return directly.
* Choose label names which say what the goto does or why the goto exists.  An
  example of a good name could be "out_buffer:" if the goto frees "buffer".
  Avoid using GW-BASIC names like "err1:" and "err2:".
* Use `rz_return_*` functions to check preconditions that are caused by
  programmers' errors. Please note the difference between conditions that should
  never happen, and that are handled through `rz_return_*` functions, and
  conditions that can happen at runtime (e.g. `malloc()` returns `NULL`, input coming
  from user, etc.), and should be handled in the usual way through if-else.

```c
int check(RzCore *c, int a, int b) {
	rz_return_val_if_fail(c, false);
	rz_return_val_if_fail(a >= 0 && b >= 1, false);

	if (a == 0) {
		/* do something */
		...
	}
	... /* do something else */
}
```

* Use `rz_warn_if_reached()` macros to emit a runtime warning if the code path is reached.
  It is often useful in a switch cases handling, in the default case:

```c
switch(something) {
	case EXPECTED_CASE1:
		...
		break;
	case EXPECTED_CASE2:
		...
		break;
	case UNEXPECTED_CASE:
		rz_warn_if_reached();
		break;
	...
}
```

* Split long conditional expressions into small `static inline` functions to make them more readable:

```diff
+static inline bool inRange(RzBreakpointItem *b, ut64 addr) {
+       return (addr >= b->addr && addr < (b->addr + b->size));
+}
+
+static inline bool matchProt(RzBreakpointItem *b, int rwx) {
+       return (!rwx || (rwx && b->rwx));
+}
+
 RZ_API RzBreakpointItem *rz_bp_get_in(RzBreakpoint *bp, ut64 addr, int rwx) {
        RzBreakpointItem *b;
        RzListIter *iter;
        rz_list_foreach (bp->bps, iter, b) {
-               if (addr >= b->addr && addr < (b->addr+b->size) && \
-                       (!rwx || rwx&b->rwx))
+               if (inRange(b, addr) && matchProt(b, rwx)) {
                        return b;
+               }
        }
        return NULL;
 }
```

* Structure in the C files

The structure of the C files in Rizin must be like this:

```c
// SPDX-License-Identifier: LGPL-3.0-only
/* Copyright ... */           ## copyright
#include <rz_core.h>           ## includes
static int globals            ## const, define, global variables
static void helper(void) {}   ## static functions
RZ_IPI void internal(void) {}  ## internal apis (used only inside the library)
RZ_API void public(void) {}    ## public apis starting with constructor/destructor
```

* Why return int vs enum

The reason why many places in Rizin-land functions return int instead of an enum type is because enums can't be OR'ed; otherwise, it breaks the usage within a switch statement and swig can't handle that stuff.

```
rz_core_wrap.cxx:28612:60: error: assigning to 'RzRegisterType' from incompatible type 'long'
  arg2 = static_cast< long >(val2); if (arg1) (arg1)->type = arg2; resultobj = SWIG_Py_Void(); return resultobj; fail:
                                                           ^ ~~~~
rz_core_wrap.cxx:32103:61: error: assigning to 'RzDebugReasonType' from incompatible type 'int'
    arg2 = static_cast< int >(val2); if (arg1) (arg1)->type = arg2; resultobj = SWIG_Py_Void(); return resultobj; fail:
                                                            ^ ~~~~
3 warnings and 2 errors generated.
````

* Do not use `assert.h`, use `rz_util/rz_assert.h` instead.

* You can use `export RZ_DEBUG_ASSERT=1` to set a breakpoint when hitting an assert.

* Function names should be explicit enough to not require a comment
  explaining what it does when seen elsewhere in code.

* Use `RZ_API` define to mark exportable (public) methods only for module APIs.

* The rest of functions must be static, to avoid polluting the global space.

* Avoid using global variables, they are evil.

* Do not write ultra-large functions: split them into multiple or simplify
  the algorithm, only external-copy-pasted-not-going-to-be-maintained code
  can be accepted in this way. (gnu code, external disassemblers, etc..)

* Use the Rizin types instead of the ones in `<stdint.h>`, which are known to cause some
  portability issues. So, instead of `uint8_t`, use `ut8`, etc.. As a bonus point they
  are shorter to write.

* Never ever use `%lld` or `%llx`. This is not portable. Always use the `PFMT64x`
  macros. Those are similar to the ones in GLIB. See all macroses in `librz/include/rz_types.h`.

* Never use `offsetof()` macros - it's not supported by some compilers. Use `rz_offsetof()` instead.

* Add a single space after the `//` when writing inline comments:

```c
int sum = 0; // set sum to 0
```

* If you need bitmaps, do not shift and OR the bits manually on `ut32`. Use bit vectors from `rz_bitvector.h` instead.

### Shell Scripts

* Use `#!/bin/sh`

* Do not use bashisms `[[`, `$'...'` etc.

* Use our [shellcheck.sh](https://github.com/rizinorg/rizin/blob/master/sys/shellcheck.sh) script to check for problems and for bashisms.

### Python Scripts

* Code must run under Python 3.6 (for [Debian "wheezy" compatibility](https://github.com/rizinorg/rizin/pull/2870#issuecomment-1205338140)).

# Manage Endianness

As hackers, we need to be aware of endianness.

Endianness can become a problem when you try to process buffers or streams
of bytes and store intermediate values as integers with width larger than
a single byte.

It can seem very easy to write the following code:
```c
ut8 opcode[4] = { 0x10, 0x20, 0x30, 0x40 };
ut32 value = *(ut32*)opcode;
```
... and then continue to use "value" in the code to represent the opcode.

This needs to be avoided!

Why? What is actually happening?

When you cast the opcode stream to a unsigned int, the compiler uses the endianness
of the host to interpret the bytes and stores it in host endianness.  This leads to
very unportable code, because if you compile on a different endian machine, the
value stored in "value" might be 0x40302010 instead of 0x10203040.

## Solution

Use bitshifts and OR instructions to interpret bytes in a known endian.
Instead of casting streams of bytes to larger width integers, do the following:
```c
ut8 opcode[4] = { 0x10, 0x20, 0x30, 0x40 };
ut32 value = opcode[0] | opcode[1] << 8 | opcode[2] << 16 | opcode[3] << 24;
```
or if you prefer the other endian:
```c
ut32 value = opcode[3] | opcode[2] << 8 | opcode[1] << 16 | opcode[0] << 24;
```
This is much better because you actually know which endian your bytes are stored in
within the integer value, REGARDLESS of the host endian of the machine.

## Endian helper functions

Rizin now uses helper functions to interpret all byte streams in a known endian.

Please use these at all times, eg:
```c
  	val32 = rz_read_be32(buffer)		// reads 4 bytes from a stream in BE
  	val32 = rz_read_le32(buffer)		// reads 4 bytes from a stream in LE
  	val32 = rz_read_ble32(buffer, isbig)	// reads 4 bytes from a stream:
  						//   if isbig is true, reads in BE
  						//   otherwise reads in LE
```
There are a number of helper functions for 64, 32, 16, and 8 bit reads and writes.

(Note that 8 bit reads are equivalent to casting a single byte of the buffer
to a `ut8` value, ie endian is irrelevant).

In case of the access to the `RzBuffer *buffer` type, there are also helpers like
`rz_buf_read_bleXX()`/`rz_buf_write_bleXX()`, `rz_buf_read_bleXX_at()`/`rz_buf_write_bleXX_at()`,
and `rz_buf_read_bleXX_offset()`/`rz_buf_write_bleXX_offset()`. In
addition to them there are corresponding little-endian or big-endian-only functions
like `rz_buf_read_leXX()`/`rz_buf_read_beXX()`, `rz_buf_read_leXX_at()`/`rz_buf_read_beXX()`,
`rz_buf_read_leXX_offset()`/`rz_buf_read_beXX_offset()`, and corresponding writing functions.

## Packed structures

Due to the various differences between platforms and compilers Rizin
has a special helper macro - `RZ_PACKED()`. Instead of non-portable
`#pragma pack` or `__attribute__((packed))` it is advised to use this macro
instead. To wrap the code inside of it you just need to write:
```c
RZ_PACKED(union mystruct {
	int a;
	char b;
})
```
or in case of typedef:
```c
RZ_PACKED(typedef structmystruct {
	int a;
	char b;
})
```

## Modules

The Rizin code base is modularized into different libraries that are
found in `librz/` directory. The `binrz/` directory contains the programs
which use the libraries.

Hint: To find both the declaration and definition of a function named
*func_name*, you can use the following `git grep` command:

```bash
git grep -nWG "^[^[:blank:]].*func_name("
```

## JSON

Since many places in Rizin output JSON the special API was created, **PJ** which means "Print Json".
It allows to create nested JSON structs with a simple and short API. Full API reference is
available in `librz/include/rz_util/rz_pj.h`.

Here is the short example of how we usually use **PJ**:
```c
PJ *pj = NULL;
if (mode == RZ_OUTPUT_MODE_JSON) {
	pj = pj_new(); // creates a new instance of the API
	if (!pj) {
		return false;
	}
}
// ... some other logic
// Creating the JSON structure
if (mode == RZ_OUTPUT_MODE_JSON) {
	pj_o(pj); // creates a JSON list
	pj_ki(pj, "id", some->id); // creates an element like "id": 6
	pj_ks(pj, "name", some->name); // creates an element like "name": "bla"
	pj_end(pj); // closes a JSON list
}
// ... some other logic
// Printing the JSON on the screen
if (mode == RZ_OUTPUT_MODE_JSON) {
	rz_cons_println(pj_string(pj));
	pj_free(pj); // free the instance of the API
}
```
It will produce the following output:
```json
{"id":6,"name":"bla"}
```

## Licenses

Rizin is trying to comply with the Software Package Data Exchange® (SPDX®),
an open standard to communicate in a clear way licenses and copyrights, among
other things, of a software. All files in the repository should either have
an header specifying the copyright and the license that apply or an entry in
.reuse/dep5 file. All pieces of code copied from other projects should have
a license/copyright entry as well.

In particular, the SPDX header may look like:
```C
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LPGL-3.0-only
```

You can use the [REUSE Software](https://reuse.software/) to check the
compliance of the project and get the licenses/copyright of each file.

# Custom Pointer Modifiers

In Rizin code, there are some conventions to help developers use pointers more safely, which are defined in `librz/include/rz_types.h`:

```c
#define RZ_IN        /* do not use, implicit */
#define RZ_OUT       /* parameter is written, not read */
#define RZ_INOUT     /* parameter is read and written */
#define RZ_OWN       /* pointer ownership is transferred */
#define RZ_BORROW    /* pointer ownership is not transferred, it must not be freed by the receiver */
#define RZ_NONNULL   /* pointer cannot be null */
#define RZ_NULLABLE  /* pointer can be null */
#define RZ_DEPRECATE /* should not be used in new code and should/will be removed in the future */
```

### Usage of Modifiers

Most of these modifiers are self-explanatory, and you can see brief explanations in the comments. However, `RZ_OWN` and `RZ_BORROW` can be a bit tricky for new developers.

Sometimes it may not be immediately clear whether the object you are getting from a function shall be freed or not.
Rizin uses `RZ_OWN` and `RZ_BORROW` to indicate pointer ownership,
so you don't have to read complicated function definitions to know whether they should still free objects or not.

You can use the two modifiers in two places, and their explanations are as follows:

- **Before the return type of a function**:
  - `RZ_OWN`: The ownership of the returned object is transferred to the caller. The caller *owns* the object, so it must free it (or ensure that something else frees it).
  - `RZ_BORROW`: The ownership of the returned object is not transferred. The caller can use the object, but it does not own it, so it should not free it.
- **Before the parameter of a function**:
  - `RZ_OWN`: The ownership of the passed argument is transferred to the callee. The callee now owns the object and it is its duty to free it (or ensure that something else frees it). In any case, the caller should not care anymore about freeing that passed object.
  - `RZ_BORROW`: The ownership of the passed argument is *not* transferred to the callee, which can use it but it should not free it. After calling this function, the caller still owns the passed object and it should ensure that at some point it is freed.

### Guidelines for Functions

#### Functions Returning Pointers
- **Arguments (Pointers)**: Must have both ownership and nullability definitions specified.
- **Return Value**: Must have ownership defined and, unless otherwise specified, it is assumed to be `RZ_NULLABLE`.

#### Functions Handling `NULL` Pointers
- **Arguments (Pointers)**: Must be marked with `RZ_NULLABLE`.
- **Assertions**: There should not be any assertions on these arguments as the function is expected to handle `NULL` pointers.

### Examples:

```c
RZ_OWN MyString *capitalize_str(RZ_BORROW char *s) {
  MyString *m = RZ_NEWS(MyString);
  m->s = strdup(s);
  capitalize(m->s);
  return m;
}

int main() {
  char *s = strdup("Hello World");
  MyString *m = capitalize_str(s);
  // s was RZ_BORROW, so main MUST free it
  free(s);
  // ... use m ....
  // m was RZ_OWN, so main now has to free it
  my_string_free(m);
}
```

```c
RZ_BORROW MyString *capitalize_str(RZ_BORROW MyFile *f, RZ_OWN char *s) {
  MyString *m = RZ_NEWS(MyString);
  m->s = s;
  capitalize(m->s);
  f->m = m;
  return m;
}

int main() {
  char *s = strdup("Hello World");
  MyFile *f = create_my_file();
  MyString *m = capitalize_str(f, s);
  // s was RZ_OWN, so main does not need to free it. s is now owned by `m`
  // ... use m ....
  // m was RZ_BORROW, so main is just borrowing it from `f`, and it does not have to free it.
  my_file_free(f);
  // f was created by main and never transferred to anything else, so main needs to free it.
}
```

- You should use these modifiers consistently in both function definition and declaration.
- You should use these modifiers when and only when it makes sense. For example, if your function returns `const char *`, the caller should not free it because of the `const`. So specifying `RZ_BORROW` in this case is probably redundant.
- Since they are used as indications to developers with no special compiler-time restrictions, there is no good way to check if you have used them correctly.
