# RzArch

The Rizin architecture library, `RzArch`, provides comprehensive support for analyzing, disassembling, and processing instructions across multiple CPU architectures. It serves as the foundation for instruction-level analysis in the Rizin framework.

The `RzArch` structure holds all information needed for architecture-specific operations including instruction disassembly, analysis, and encoding. It manages a plugin-based system for supporting various architectures and their variants.

## What can I expect here?

- Comprehensive support for multiple CPU architectures (x86, x86_64, ARM, MIPS, PowerPC, RISC-V, and more)
- Architecture-specific instruction profiles and calling conventions
- Plugin-based architecture for extending supported platforms
- Core functions for architecture lifecycle:
  - `rz_arch_new()`: To initialize an architecture context
  - `rz_arch_disassemble()`: To convert binary instructions to assembly
  - `rz_arch_set_pc()`: To set the program counter
  - `rz_arch_free()`: To release the architecture context
- CPU profile management for different processor variants
- Instruction analysis and semantic information
- Assembly string tokenization and colorization support

## Architecture

The `RzArch` library employs a plugin-based architecture to manage various CPU instruction sets and their analysis capabilities.

The `RzArch` structure serves as the manager for the available architecture plugins. Plugins handle architecture-specific operations like disassembly, instruction analysis, and code generation.

- **`RzArch` Context**: This is the factory and plugin manager. You initialize it with a specific architecture (e.g., `rz_arch_new("x86", 64)`).
- **`RzArchConfig`**: Configuration for specific architecture instances and variants
- **`RzAnalysisOp`**: Holds semantic information about individual instructions

## Assembly String Processing

Assembly strings go through a sophisticated tokenization process that enables proper colorization and semantic analysis:

### Tokenizing

A token is a reference to a sub-string within an assembly instruction, containing:
- The byte offset where the token starts
- The length of the sub-string in bytes
- The token type (mnemonic, register, number, operator, separator, etc.)

```c
typedef struct {
	size_t start; //< byte-offset into the asm string where this token starts
	size_t len;   //< length of token in bytes
	RzAsmTokenType type;
} RzAsmToken;
```

### Tokenization Methods

1. **Generic Method**: For standard `<mnemonic> <operand> <operand>` syntax
2. **Custom Method**: For complex or architecture-specific syntax patterns using regex

### Example: x86 ADD Instruction

```asm
add r0, r1, 0x10
```

This instruction is tokenized as:

| Sub-String | Type      |
|------------|-----------|
| `add`      | mnemonic  |
| ` `        | separator |
| `r0`       | register  |
| `, `       | separator |
| `r1`       | register  |
| `, `       | separator |
| `0x10`     | number    |

### Custom Tokenization for Complex Syntax

For architecture modules with complex syntax, custom tokenization can be implemented using regex patterns:

```c
static RZ_OWN RzPVector /*<RzAsmTokenPattern *>*/ *get_token_patterns() {
	RzPVector *pvec = rz_pvector_new(rz_asm_token_pattern_free);
	
	// Add patterns for mnemonic, registers, operators, separators
	RzAsmTokenPattern *pat = RZ_NEW0(RzAsmTokenPattern);
	pat->type = RZ_ASM_TOKEN_MNEMONIC;
	pat->pattern = rz_str_dup("^((mov)|(add)|(sub)...)");
	rz_pvector_push(pvec, pat);
	
	return pvec;
}
```

Pattern matching is performed with priority ordering - first matching patterns have higher priority. Care must be taken to avoid overlapping patterns that could leave gaps in tokenization.

### Coloring

Color escape sequences are inserted before and after each token based on its type, enabling rich syntax highlighting in the console output.

## Usage and Examples

### Example: Disassembling x86-64 Instructions

```c
#include <rz_arch.h>

int main(void) {
	// Create an x86-64 architecture context
	RzArch *arch = rz_arch_new("x86", 64);
	if (!arch) {
		return 1;
	}

	// Set program counter
	rz_arch_set_pc(arch, 0x1000);

	// Instruction bytes: mov rax, 0x12345678
	ut8 code[] = { 0x48, 0xb8, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00 };

	// Disassemble the instruction
	RzAnalysisOp *op = rz_analysis_op_new();
	int size = rz_arch_disassemble(arch, op, code, sizeof(code));

	if (size > 0) {
		printf("Mnemonic: %s\n", rz_strbuf_get(&op->mnemonic));
		printf("Size: %d bytes\n", size);
	}

	// Cleanup
	rz_analysis_op_free(op);
	rz_arch_free(arch);
	return 0;
}
```

## Supported Architectures

- **x86/x86_64**: IA-32 and x86-64 (Intel/AMD)
- **ARM**: Various ARM versions (ARMv7, ARMv8, Thumb)
- **MIPS**: MIPS and MIPS64
- **PowerPC**: PowerPC and PowerPC64
- **RISC-V**: RISC-V (32-bit and 64-bit)
- **SPARC**: SPARC architectures
- **And more...**: Through the plugin system

## Architecture-Specific Information

For more details about assembly string processing and tokenization, see [doc/asm_strings.md](../../doc/asm_strings.md).

For information about instruction analysis and semantic information, see [doc/debug-internals.md](../../doc/debug-internals.md) and [doc/calling-conventions.md](../../doc/calling-conventions.md).
