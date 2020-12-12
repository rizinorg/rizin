# DEVELOPERS

This file is aimed at developers who want to work on the Rizin code base.

## Documentation
There is support for Doxygen document generation in this repo.
By running `doxygen` in the root of this repository, it will autodetect the
Doxyfile and generate HTML documentation into
[doc/doxygen/html/index.html](./doc/doxygen/html/index.html)

If you're contributing code or willing to update existing code, you can use the
doxygen C-style comments to improve documentation and comments in code.
See the [Doxygen Manual](http://www.doxygen.nl/manual/index.html)
for more info. Example usage can be found [here](http://www.doxygen.nl/manual/docblocks.html)
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
static int findMinMax(RzList *maps, ut64 *min, ut64 *max, int skip, int width);
```

## Code style

### C

In order to contribute with patches or plugins, we encourage you to
use the same coding style as the rest of the code base.

* Tabs are used for indentation. In a switch statement, the
  cases are indented at the switch level.

```c
switch(n) {
case 1:
	break;
case 2:
	break;
default:
}
```

* Lines should be at most 100 chars. A tab is considered as 8 chars. If it makes
  things more readable, you can use more than 100 characters, but this should be
  the exception, not the rule.

* Braces open on the same line as the for/while/if/else/function/etc. Closing
  braces are put on a line of their own, except in the else of an if statement
  or in a while of a do-while statement. Always use braces for if and while.

```c
if (a == b) {
	...
}

if (a == b) {
	...
} else if (a > b) {
	...
}

if (a == b) {
	...
} else {
	do_something_else ();
}

do {
	do_something ();
} while (cond);

if (a == b) {
	b = 3;
}

```

* In general, don't use goto. The goto statement only comes in handy when a
  function exits from multiple locations and some common work such as cleanup
  has to be done. If there is no cleanup needed, then just return directly.

  Choose label names which say what the goto does or why the goto exists.  An
  example of a good name could be "out_buffer:" if the goto frees "buffer".
  Avoid using GW-BASIC names like "err1:" and "err2:".

* Use `rz_return_*` functions to check preconditions that are caused by
  programmers' errors. Please note the difference between conditions that should
  never happen, and that are handled through `rz_return_*` functions, and
  conditions that can happen at runtime (e.g. `malloc()` returns `NULL`, input coming
  from user, etc.), and should be handled in the usual way through if-else.

```c
int check(RCore *c, int a, int b) {
	rz_return_val_if_fail (c, false);
	rz_return_val_if_fail (a >= 0, b >= 1, false);

	if (a == 0) {
		/* do something */
		...
	}
	... /* do something else */
}
```

* Use a space after most of the keyword and around operators.

```c
a = b + 3;
a = (b << 3) * 5;
```

* Multiline ternary operator conditionals must be indented a-la JS way:

```diff
- ret = over ?
-         rz_debug_step_over (dbg, 1) :
-         rz_debug_step (dbg, 1);
+ ret = over
+         ? rz_debug_step_over (dbg, 1)
+         : rz_debug_step (dbg, 1);
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
+               if (inRange (b, addr) && matchProt (b, rwx)) {
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

* Do not leave trailing whitespaces at the end of line

* Do not use `assert.h`, use `rz_util/rz_assert.h` instead.

* You can use `export RZ_DEBUG_ASSERT=1` to set a breakpoint when hitting an assert.

* Do not use C99 variable declaration
    - This way we reduce the number of local variables per function
    and it's easier to find which variables are used, where and so on.

* Function names should be explicit enough to not require a comment
  explaining what it does when seen elsewhere in code.

* Use `RZ_API` define to mark exportable (public) methods only for module APIs

* The rest of functions must be static, to avoid polluting the global space.

* Avoid using global variables, they are evil.

* Do not write ultra-large functions: split them into multiple or simplify
  the algorithm, only external-copy-pasted-not-going-to-be-maintained code
  can be accepted in this way (gnu code, external disassemblers, etc..)

* See `.clang-format` for automated indentation

* Use the Rizin types instead of the ones in `<stdint.h>`, which are known to cause some
  portability issues. So, instead of `uint8_t`, use `ut8`, etc.. As a bonus point they
  are shorter to write.

* Never ever use `%lld` or `%llx`. This is not portable. Always use the `PFMT64x`
  macros. Those are similar to the ones in GLIB. See all macroses in `librz/include/rz_types.h`.

### Shell Scripts

* Use `#!/bin/sh`

* Do not use bashisms `[[`, `$'...'` etc.

* Use our [shellcheck.sh](https://github.com/rizinorg/rizin/blob/master/sys/shellcheck.sh) script to check for problems and for bashisms

# Manage Endianness

As hackers, we need to be aware of endianness.

Endianness can become a problem when you try to process buffers or streams
of bytes and store intermediate values as integers with width larger than
a single byte.

It can seem very easy to write the following code:
```c
ut8 opcode[4] = {0x10, 0x20, 0x30, 0x40};
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
ut8 opcode[4] = {0x10, 0x20, 0x30, 0x40};
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

## Packed structures

Due to the various differences between platforms and compilers Rizin
has a special helper macro - `RZ_PACKED()`. Instead of non-portable
`#pragma pack` or `__attribute__((packed))` it is advised to use this macro
instead. To wrap the code inside of it you just need to write:
```c
RZ_PACKED (union mystruct {
	int a;
	char b;
})
```
or in case of typedef:
```c
RZ_PACKED (typedef structmystruct {
	int a;
	char b;
})
```

## Modules

The Rizin code base is modularized into different libraries that are
found in `librz/` directory. The `binrz/` directory contains the programs
which use the libraries.
