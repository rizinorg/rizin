Rizin tests
=============================

Rizin uses both regression and unit tests.

# Directory Hierarchy

 * db/:          The regressions tests sources
 * unit/:        Unit tests (written in C, using minunit).
 * fuzz/:        Fuzzing helper scripts
 * bins/:        Sample binaries (fetched from the [external repository](https://github.com/rizinorg/rizin-testbins))

# Requirements

 * rizin installed and in `$PATH` (you can also use a rizin not in `$PATH`, but
   other files like calling convention files, format files, etc. must have been
   installed).
 * rz-test compiled and/or installed, which is done by default automatically
   when building Rizin.

# Usage

## Regression tests
To run regressions tests use `rz-test` from within the `test` directory.
By default it will run all tests under the `db` subdirectory, however you can
also specify which tests you want to run, by providing its name as argument to
`rz-test`.

For example, to run only the asm tests for x86_64, you can do `rz-test
db/asm/x86_64`. `rz-test` provides other interesting options that you can check
out by doing `rz-test -h`.

An option that you may find interesting, in particular when doing changes that
may affect the output of multiple tests, is the `-i` option, which enables
interactive mode. When running tests in this mode, `rz-test` will warn you for
each failed test and it will ask for your input on how to treat the issue. It
can automatically fix the test so that it matches the new output (if that is the
right behaviour!) or it can mark it as broken for you.

## Unit tests
To run unit tests, just use `ninja -C build test` (or `meson test -C build`)
from the top directory (replace `build` with the name of the directory you used
to build Rizin).

# Failure Levels

A test can have one of the following results:
* **success**: The test passed, and that was expected.
* **fixed**: The test passed, but failure was expected.
* **broken**: Failure was expected, and happened.
* **failed**: The test failed unexpectedly. This is a regression.

# Writing Assembly tests

Tests for the assembly and disassembly (in `db/asm/*`) have a different format:
General format:
```
type "assembly" opcode [offset]
```
where type can be any of:
* **a** meaning "assemble"
* **d** meaning "disassemble"
* **B** meaning "broken"
* **E** stands for cfg.bigendian=true

#### offset

Some architectures are going to assemble an instruction differently depending
on the offset it's written to. Optional.

Examples:
```
a "ret" c3
d "ret" c3
a "nop" 90 # Assembly is correct
dB "nopppp" 90 # Disassembly test is broken
```

You can merge lines:
```
adB "nop" 90
```
acts the same as
```
aB "nop" 90
dB "nop" 90
```
The filename is very important. It is used to tell rizin which architecture to use: `arch[[_cpu]_bits]`.

Examples:
- `x86_32` means `-a x86 -b 32`
- `arm_v7_64` means `-a arm -b 64`

# Writing JSON tests

The JSON tests `db/json` are executed on 3 standard files (1 ELF, 1 MachO, 1 PE). The tests need to be working on the 3 files to pass.

# Commands tests

Example commands tests for the other `db/` folders:
```sh
NAME=test_db
FILE=bins/elf/ls
CMDS=<<EOF
pd 4
EOF
EXPECT=<<EOF
        ;-- main:
        ;-- entry0:
        ;-- func.100001174:
        0x100001174      55             Push rbp
        0x100001175      4889e5         Mov  rbp, rsp
        0x100001178      4157           Push r15
EOF
RUN
```
It is also possible to match specific parts of the output in `EXPECT` and `EXPECT_ERR` using regex (with
`REGEXP_FILTER_OUT` and `REGEXP_FILTER_ERR` respectively) in case some of the test's output is dynamic:
```sh
NAME=bp rebase
FILE=bins/elf/analysis/pie
ARGS=-d
CMDS=<<EOF
aa
db main
db~main
doc
db~main
EOF
REGEXP_FILTER_OUT=([a-zA-Z="]+\s+)
EXPECT=<<EOF
x sw break enabled valid cmd="" cond="" name="main" pie"
x sw break enabled valid cmd="" cond="" name="main" pie"
EOF
RUN
```
Without the regex that filtered out the non-deterministic file path and addresses, the expected output would have been the following:

```
0x566495c5 - 0x566495c6 1 --x sw break enabled valid cmd="" cond="" name="main" module="/home/user/rizin/test/bins/elf/analysis/pie"
0x000005c5 - 0x000005c6 1 --x sw break enabled valid cmd="" cond="" name="main" module="/home/user/rizin/test/bins/elf/analysis/pie"
```

* **NAME** is the name of the test, it must be unique
* **FILE** is the path of the file used for the test
* **ARGS** (optional) are the command line argument passed to rizin (e.g -b 16)
* **CMDS** are the commands to be executed by the test
* **EXPECT** is the expected output of the test from stdout. If `REGEXP_FILTER_OUT` is used, `EXPECT` matches only the filtered output.
* **EXPECT_ERR** (optional) is the expected output of the test from stderr. Can be specified in addition or instead of `EXPECT`
* **BROKEN** (optional) is 1 if the tests is expected to be fail, 0 or unspecified otherwise
* **TIMEOUT** (optional) is the number of seconds to wait before considering the test timeout
* **REGEXP_FILTER_OUT** (optional) apply given regex on stdout before comparing the ouput to `EXPECT` (e.g. `REGEXP_FILTER_OUT=([a-zA-Z]+)`). This is similar to piping stdout to `grep -E "<regex>"` and then comparing the matched text with `EXPECT`.
* **REGEXP_FILTER_ERR** (optional) apply given regex on stderr before comparing the ouput to `EXPECT_ERR`

You must end the test by adding RUN keyword

## Advices

* For portability reasons do not use shell pipes, use `~`
* dont use `pd` if not necessary, use `pi`

# Unit tests

Assembly, JSON and commands tests are useful to test the overall behaviour of
Rizin, but to test new API or new code we suggest to write small unit tests.

The basic structure of a unit test is the following:
```C
#include "minunit.h"
#include <rz_XXXXX.h>

static bool test_my_feature(void) {
	// code to test the behaviour
	mu_end;
}

static bool all_tests() {
	mu_run_test(test_my_feature);
	return tests_passed != tests_run;
}

mu_main (all_tests)
```

Minunit provides various functions to check the actual output of a function with
the expected one. For example:

- `mu_assert_true(actual, message)` checks that `actual` evaluates to true, otherwise it prints `message` on stderr.
- `mu_assert_false(actual, message)` checks that `actual` evaluates to false, otherwise it prints `message` on stderr.
- `mu_assert_eq(actual, expected, message)` checks that the integer (ut64 at most) `actual` is equal to the integer `expected`, otherwise it prints `message` on stderr.
- `mu_assert_ptreq(actual, expected, message)` checks that the pointer `actual` is equal to `expected`.
- `mu_assert_null(actual, message)`
- `mu_assert_streq(actual, expected, message)`
- `mu_assert_memeq(actual, expected, len, message)`
- etc.

If you add a unit test file, be sure to also add it to `unit/meson.build`, so it
is compiled when you compile Rizin.

# License

The test files are licensed under GPL 3 (or later).
