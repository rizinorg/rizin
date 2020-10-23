rizin tests
=============================

Rizin uses both regression and unit tests.

# Directory Hierarchy

 * db/:          The regressions tests sources
 * unit/:        Unit tests (written in C, using minunit).
 * fuzz/:        Fuzzing helper scripts
 * bins/:        Sample binaries (fetched from the [external repository](https://github.com/rizinorg/rizin-testbins))

# Requirements

 * rizin installed and in `$PATH` (you can also use a rizin non in `$PATH`, but
   other files like calling convention files, format files, etc. must have been
   installed).
 * rz-test compiled and/or installed

# Usage

 * To run regressions tests use: `rz-test` from within the `test` directory.
 * To run unit tests, just use `meson test -C build` from the top directory
   (replace `build` with the name of the directory you used to build rizin).

# Failure Levels

A test can have one of the following results:
* success: The test passed, and that was expected.
* fixed: The test passed, but failure was expeced.
* broken: Failure was expected, and happened.
* failed: The test failed unexpectedly. This is a regression.

# Writing Assembly tests

Example tests for `db/asm/*`:

	General format:
	type "assembly" opcode [offset]

		type:
			* a stands for assemble
			* d stands for disassemble
			* B stands for broken
			* E stands for cfg.bigendian=true

		offset:
			Some architectures are going to assemble an instruction differently depending
			on the offset it's written to. Optional.

	Examples:
	a "ret" c3
	d "ret" c3
	a "nop" 90 # Assembly is correct
	dB "nopppp" 90 # Disassembly test is broken

	You can merge lines:

	adB "nop" 90

	acts the same as

	aB "nop" 90
	dB "nop" 90

        The filename is very important. It is used to tell radare which architecture to use.

        Format:
        arch[[_cpu]_bits]

	Example:
	x86_32 means -a x86 -b 32
        arm_v7_64 means what it means


# Writing JSON tests

The JSON tests `db/json` are executed on 3 standard files (1 ELF, 1 MachO, 1 PE). The tests need to be working on the 3 files to pass.

# Commands tests

Example commands tests for the other `db/` folders:

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

* **NAME** is the name of the test, it must be unique
* **FILE** is the path of the file used for the test
* **ARGS** (optional) are the command line argument passed to rizin (e.g -b 16)
* **CMDS** are the commands to be executed by the test
* **EXPECT** is the expected output of the test
* **BROKEN** (optional) is 1 if the tests is expected to be fail, 0 or unspecified otherwise
* **TIMEOUT** (optional) is the number of seconds to wait before considering the test timeout

You must end the test by adding RUN keyword

## Advices

* For portability reasons do not use shell pipes, use `~`
* dont use `pd` if not necessary, use `pi`

# Unit tests

Assembly, JSON and commands tests are useful to test the overall behaviour of
rizin, but to test new API or new code we suggest to write small unit tests.

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

int main(int argc, char **argv) {
	return all_tests();
}
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

# License

The test files are licensed under GPL 3 (or later).
