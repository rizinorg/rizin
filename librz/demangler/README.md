# RzDemangler

The Rizin demangler library, `RzDemangler`, provides functionality for converting mangled symbol names back to their original readable form. It supports multiple programming language name mangling schemes used by different compilers and platforms.

The `RzDemangler` structure manages demangling operations with support for various mangling conventions.

## What can I expect here?

- Support for multiple name mangling schemes:
  - **C++ Mangling**: Itanium/GCC and MSVC conventions
  - **Rust**: Rust v0 mangling scheme
  - **D**: D language mangling
  - **Java**: Java bytecode name schemes
  - **Objective-C**: Objective-C method mangling
- Core functions for demangling:
  - `rz_demangler_new()`: To initialize a demangler context
  - `rz_demangler_demangle()`: To demangle a symbol name
  - `rz_demangler_free()`: To release the demangler context
- Multiple demangling backends:
  - Built-in demangling for supported languages
  - External tool support (c++filt, llvm-cxxfilt)
- Symbol type detection
- Return type extraction
- Parameter information parsing

## Architecture

The demangler library uses a plugin-based architecture:

- **`RzDemangler` Context**: Main demangling coordinator
- **Language Plugins**: Handle specific mangling schemes
- **External Tools**: Support for system demangling utilities
- **Caching**: Cache demangled names for performance

## Key Structures

### RzDemangler
Main demangling context containing:
- Plugin registry
- Configuration
- Cache
- External tool references

## Supported Languages and Conventions

### C++
- **Itanium ABI**: Used by GCC, Clang, and most Unix compilers
  - Mangled names start with `_Z`
  - Example: `_Z3addii` → `add(int, int)`
- **MSVC**: Microsoft Visual C++ mangling
  - Mangled names start with `?`
  - Example: `?add@@YAHHH@Z` → `add(int, int)`

### Rust
- **v0 Mangling**: Modern Rust mangling scheme
  - Mangled names start with `_RN` or `_R`
  - Example: `_RNvMs0_NtNtCs1234_5hello5worldNtB2_3Bar3new`

### D
- D language name mangling
- Mangled names start with `_D`

### Java
- Java bytecode method/class name handling
- Supports inner classes and generic types

### Objective-C
- Objective-C method name formats
- Support for selectors and method signatures

## Usage Examples

### Example: Demangling C++ Names

```c
#include <rz_demangler.h>
#include <stdio.h>

int main(void) {
	// Create a demangler context
	RzDemangler *dem = rz_demangler_new();
	if (!dem) {
		return 1;
	}

	// Demangle C++ Itanium ABI names
	const char *mangled1 = "_Z3addii";
	const char *demangled1 = rz_demangler_demangle(dem, mangled1);
	if (demangled1) {
		printf("%s -> %s\n", mangled1, demangled1);
		free((void *)demangled1);
	}

	// Demangle MSVC mangled name
	const char *mangled2 = "?add@@YAHHH@Z";
	const char *demangled2 = rz_demangler_demangle(dem, mangled2);
	if (demangled2) {
		printf("%s -> %s\n", mangled2, demangled2);
		free((void *)demangled2);
	}

	// Demangle complex C++ name with templates
	const char *mangled3 = "_ZNSt6vectorIiE9push_backERKi";
	const char *demangled3 = rz_demangler_demangle(dem, mangled3);
	if (demangled3) {
		printf("%s -> %s\n", mangled3, demangled3);
		free((void *)demangled3);
	}

	// Cleanup
	rz_demangler_free(dem);
	return 0;
}
```

### Example: Demangling Rust Names

```c
RzDemangler *dem = rz_demangler_new();

// Rust v0 mangled name example
const char *mangled = "_RNvMs0_NtNtCs1234_5hello5worldNtB2_3Bar3new";
const char *demangled = rz_demangler_demangle(dem, mangled);

if (demangled) {
	printf("Rust mangled: %s\n", mangled);
	printf("Demangled: %s\n", demangled);
	free((void *)demangled);
}

rz_demangler_free(dem);
```

### Example: Processing Symbol Lists

```c
RzDemangler *dem = rz_demangler_new();

const char *symbols[] = {
	"_Z3addii",
	"_ZNSt3mapISsSt6vectorIiEE3atERKSs",
	"?add@@YAHHH@Z",
	"malloc",  // Not mangled
	NULL
};

for (int i = 0; symbols[i]; i++) {
	const char *demangled = rz_demangler_demangle(dem, symbols[i]);
	if (demangled) {
		printf("%s -> %s\n", symbols[i], demangled);
		free((void *)demangled);
	} else {
		printf("%s (not mangled)\n", symbols[i]);
	}
}

rz_demangler_free(dem);
```

## Common Mangling Examples

### C++ (Itanium ABI)

| Mangled | Demangled |
|---------|-----------|
| `_Z3addii` | `add(int, int)` |
| `_ZN3fooC1Ev` | `foo::foo()` |
| `_ZN3foo3barEv` | `foo::bar()` |
| `_ZN9std5vectorIiE9push_backERKi` | `std::vector<int>::push_back(int const&)` |

### C++ (MSVC)

| Mangled | Demangled |
|---------|-----------|
| `?add@@YAHHH@Z` | `int __cdecl add(int, int)` |
| `?foo@@AAXXZ` | `private: void __cdecl foo(void)` |

### Rust

| Mangled | Demangled |
|---------|-----------|
| `_RNvMs0_NtNtCs1234_5hello5worldNtB2_3Bar3new` | Associated function |

## Key Features

- **Multi-language Support**: Handle various mangling schemes
- **Robust Parsing**: Gracefully handle malformed names
- **Caching**: Improve performance with memoization
- **External Tools**: Fallback to system demangling utilities
- **Type Information**: Extract type and signature information
- **Extensible**: Add support for new mangling schemes

## Common Use Cases

1. **Symbol Resolution**: Convert mangled symbols to readable names
2. **Function Signature Analysis**: Extract parameter and return types
3. **API Documentation**: Generate human-readable function lists
4. **Cross-reference Analysis**: Match symbols between binaries
5. **Binary Comparison**: Compare symbol names across versions

## Integration with Rizin

- **RzBin**: Demangle imported/exported symbols
- **RzCore**: Display readable function names
- **RzAnalysis**: Identify function signatures
- **Symbol Display**: Show demangled names in disassembly

## Performance Considerations

- Demangled names are cached to avoid re-processing
- Caching significantly improves performance for large binaries
- For one-off demangling, consider using external tools

## Limitations and Notes

- Some mangling schemes are incomplete or proprietary
- Custom or obfuscated mangling won't be recognized
- Demanglers may produce slightly different formatting
- Some languages have multiple mangling conventions
