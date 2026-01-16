# RzIL

The Rizin intermediate language library, `RzIL`, provides an architecture-independent intermediate representation for program analysis. It bridges low-level assembly instructions and high-level semantic analysis, enabling cross-architecture program analysis and formal verification.

The `RzIL` structure manages IL generation, analysis, and transformation across different architectures.

## What can I expect here?

- Intermediate language representation:
  - Architecture-independent code representation
  - Precise semantics for each instruction
  - Support for all major architectures
- IL operations and expressions:
  - Variable operations
  - Arithmetic and logical operations
  - Memory operations
  - Control flow
- Core functions for IL lifecycle:
  - `rz_il_new()`: To initialize an IL context
  - `rz_il_set_current_arch()`: To set architecture
  - `rz_il_step()`: To execute single step
  - `rz_il_evaluate()`: To evaluate expressions
  - `rz_il_free()`: To release the IL context
- Analysis and transformation:
  - Data flow analysis
  - Value tracking
  - Constant propagation
  - Symbolic execution
- Formal verification support:
  - SMT solver integration
  - Constraint solving
  - Path exploration

## Architecture

The IL library provides multiple layers:

- **`RzIL` Context**: Main IL manager
- **IL Operations**: Low-level IL operations
- **IL Effects**: State-changing operations
- **IL Expressions**: Compute expressions
- **Semantics Engine**: Execute IL instructions
- **Analysis Engines**: Perform analysis on IL

## Key Structures

### RzILOp
Basic IL operation (e.g., arithmetic, memory access).

### RzILEffect
State-changing operations (e.g., variable assignment).

### RzILExpr
Expression for computation (pure, no side effects).

### RzILVal
Result of IL evaluation.

## IL Operation Types

### Variable Operations
- **Set**: Assign value to variable
- **Get**: Read variable value
- **Increment/Decrement**: Update variable

### Arithmetic Operations
- Addition, subtraction, multiplication, division
- Modulo, bitwise operations
- Rotation, shifting

### Memory Operations
- Load: Read from memory
- Store: Write to memory
- Peek/Poke

### Control Flow
- Jump: Unconditional branch
- Branch: Conditional branch
- Sequence: Multiple operations

### Comparison
- Equal, not equal
- Less than, greater than
- Bitwise comparisons

## Usage Examples

### Example: Basic IL Usage

```c
#include <rz_il.h>
#include <stdio.h>

int main(void) {
	// Create IL context
	RzIL *il = rz_il_new();
	if (!il) {
		return 1;
	}

	// Set current architecture
	rz_il_set_current_arch(il, "x86", 64);

	// Create an IL expression: x + 1
	// RzILExpr *expr = rz_il_op_new_add(
	//     rz_il_op_new_var("rax"),
	//     rz_il_op_new_bitv(64, 1)
	// );

	// Evaluate expression with given variable values
	// RzILVal *result = rz_il_evaluate(il, expr);

	// Use result...

	// Cleanup
	rz_il_free(il);
	return 0;
}
```

### Example: Instruction Semantic

```c
// Instruction: add rax, rbx
// This would generate IL like:
//
// rax = rax + rbx
//
// Which is represented as IL operations:
// RzILOp *il_op = rz_il_op_new_set(
//     "rax",
//     rz_il_op_new_add(
//         rz_il_op_new_var("rax"),
//         rz_il_op_new_var("rbx")
//     )
// );

RzIL *il = rz_il_new();

// Execute the IL operation
// rz_il_execute(il, il_op);

// Get result
RzILVal *rax_value = rz_il_get_value(il, "rax");

rz_il_free(il);
```

### Example: Data Flow Analysis

```c
RzIL *il = rz_il_new();
rz_il_set_current_arch(il, "x86", 64);

// Track value of RAX through series of operations:
// rax = 0x1000
// rax = rax + 0x100
// rax = rax * 2

// After analysis, determine that rax = (0x1000 + 0x100) * 2 = 0x2200

RzILVal *final_value = rz_il_get_value(il, "rax");
if (final_value) {
	printf("Final RAX value: 0x%"PFMT64x"\n", final_value->data.u64);
}

rz_il_free(il);
```

## IL Expression Examples

### Arithmetic
```
rax = rax + rbx     // Addition
rcx = rax * 2       // Multiplication  
rdx = rax & rbx     // Bitwise AND
rsi = rax ^ rbx     // Bitwise XOR
rdi = rax << 3      // Left shift
```

### Memory Operations
```
rax = mem_load_64(0x1000)           // Load 64-bit value
mem_store_32(0x1000, eax)           // Store 32-bit value
rax = mem_load_32(rbx + 8)          // Load from computed address
```

### Conditionals
```
if (rax == 0) {
    rbx = 1
} else {
    rbx = 0
}
```

## Key Features

- **Architecture Independence**: Analyze any supported architecture
- **Precise Semantics**: Accurate instruction semantics
- **Extensible**: Add support for new operations
- **Formal Analysis**: Enable SMT-based verification
- **Performance**: Efficient IL execution
- **Debugging**: IL-level debugging support
- **Symbolic Execution**: Support for symbolic variables
- **Constraint Solving**: Integrate with SMT solvers

## Supported Operations

### Unary Operations
- Bitwise NOT
- Logical NOT
- Sign extension
- Zero extension
- Population count

### Binary Operations
- Arithmetic: +, -, *, /, %
- Bitwise: &, |, ^, <<, >>, <<<, >>>
- Comparison: ==, !=, <, >, <=, >=

### Ternary Operations
- Conditional: cond ? true_val : false_val

### Load/Store
- Memory load with various sizes
- Memory store with various sizes

## Analysis Capabilities

- **Data Flow**: Track value propagation
- **Control Flow**: Analyze execution paths
- **Reachability**: Determine reachable states
- **Invariants**: Find loop invariants
- **Value Range**: Determine possible value ranges

## Integration Points

- **RzAnalysis**: IL generation from instructions
- **RzCore**: IL-level debugging
- **SMT Solvers**: External constraint solvers
- **Symbolic Execution**: Advanced program analysis

## Use Cases

- **Program Verification**: Verify program correctness
- **Vulnerability Analysis**: Detect vulnerability patterns
- **Optimization**: Identify optimization opportunities
- **Decompilation**: Improve decompiler accuracy
- **Symbolic Execution**: Explore program paths
- **Fuzzing**: Generate test cases
