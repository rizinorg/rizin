 <!-- Filling this template is mandatory -->

**Your checklist for this pull request**
- [x] I've read the [guidelines for contributing](https://github.com/rizinorg/rizin/blob/master/DEVELOPERS.md) to this repository.
- [x] I made sure to follow the project's [coding style](https://github.com/rizinorg/rizin/blob/master/DEVELOPERS.md#code-style).
- [x] I've documented every `RZ_API` function and struct this PR changes.
- [x] I've added tests that prove my changes are effective (required for changes to `RZ_API`).
- [] I've updated the [Rizin book](https://github.com/rizinorg/book) with the relevant information (if needed).

**Detailed description**

This PR adds support for the Infineon C166 microcontroller architecture. The C166 is a 16-bit RISC microcontroller architecture that was widely used in embedded systems and automotive applications.

The implementation includes:

1. Architecture plugin definition (`arch_c166.c`)
2. Assembly/disassembly support (`asm_c166.c`)
3. Analysis plugin for C166 instructions (`analysis_c166.c`)
4. Core disassembler implementation (`c166_disas.c` and `c166_disas.h`)
5. Comprehensive opcode definitions and addressing modes (`c166_ops.h`)

Key features of this implementation:
- Support for basic arithmetic, logical, and bit manipulation operations
- Control flow analysis for jumps, branches, and function calls
- Proper handling of different C166 addressing modes
- Register profile definition for the C166 architecture

The code has been manually tested with a set of test binaries covering the main instruction categories.


**Test plan**

The implementation has been tested with several binary files containing different types of C166 instructions:
1. Arithmetic operations (ADD, ADDC, SUB, MUL, etc.)
2. Logical operations (AND, OR, XOR, etc.)
3. Control flow operations (JMPR, JB, etc.)
4. Data movement operations (MOV, MOVB, etc.)
5. Bit manipulation operations (BCLR, BSET, etc.)

Test commands used: 
# Arithmetic operations test
echo -ne "\x00\x12\x06\x01\x23\x45\x10\x34\x20\x56\x30\x78\x0B\x12" > c166_arithmetic.bin

# Logical operations test
echo -ne "\x60\x12\x66\x01\x23\x45\x70\x34\x50\x56\x91\x01" > c166_logical.bin

# Jump and branch operations test
echo -ne "\x0D\x05\x2D\xFC\x3D\x10\x8A\x20\x10\x05\x8D\x0A" > c166_branch.bin

# Data movement operations test
echo -ne "\x88\x12\x89\x34\x84\x05\x20\x00" > c166_movement.bin

# Bit operations test
echo -ne "\x0E\x20\x0F\x21\x2E\x22\x2F\x23" > c166_bit.bin

# Combined operations test
echo -ne "\x00\x12\x60\x34\x88\x56\x0D\x08\x0B\x78\x20\x56\x0F\x24\x40\x12\x2D\xFA" > c166_combined.bin


**Closing issues**
closes #53
