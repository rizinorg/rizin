# RzBin

The Rizin binary analysis library, `RzBin`, provides comprehensive functionality for parsing, analyzing, and extracting information from binary files in various formats. It serves as the core component for binary format handling in the Rizin framework.

The `RzBin` structure manages binary file objects and coordinates the extraction of metadata, symbols, sections, relocations, and other information from executables and object files.

## What can I expect here?

- Comprehensive support for multiple binary formats:
  - **Executable Formats**: ELF, PE (Windows), Mach-O (macOS), Java CLASS files
  - **Archive Formats**: ZIP, TAR, RAR, 7z
  - **Mobile Formats**: DEX (Android), APK
  - **Specialized Formats**: WASM, NES ROMs, and many others
- Plugin-based architecture for extending supported formats
- Core functions for binary lifecycle:
  - `rz_bin_new()`: To initialize a binary context
  - `rz_bin_open_buffer()`: To load a binary from a buffer
  - `rz_bin_get_info()`: To retrieve binary information
  - `rz_bin_free()`: To release the binary context
- Binary information extraction:
  - **Symbols and Imports**: Extract symbol tables and import tables
  - **Sections and Segments**: Parse binary section and segment information
  - **Relocations**: Handle relocation entries
  - **Strings**: Extract string data from binary
  - **Entry Points**: Identify program entry points
  - **Debug Information**: Extract DWARF and other debug data
  - **Type Information**: Extract type information from binaries
  - **Libraries**: List imported libraries and dependencies

## Architecture

The `RzBin` library employs a plugin-based architecture to manage various binary format parsers.

The main components are:

- **`RzBin` Context**: The factory and plugin manager. Initialize with `rz_bin_new()`
- **`RzBinFile`**: Represents a loaded binary file
- **`RzBinObject`**: The main object structure within a binary file (handles multi-object binaries)
- **Format Plugins**: Handle specific binary format parsing
- **`RzBinInfo`**: Metadata about the binary (arch, OS, entry point, etc.)

## Main Structures

### RzBin
Factory context for managing binary files and format plugins.

### RzBinFile
Represents a single binary file with associated metadata.

### RzBinObject
The actual parsed binary object containing:
- Sections (`.text`, `.data`, etc.)
- Symbols (functions, variables)
- Relocations
- String tables
- Entry points
- Debug information

### RzBinInfo
Contains metadata:
- Architecture (x86, ARM, MIPS, etc.)
- Operating system (Linux, Windows, macOS)
- Bit width (32-bit, 64-bit)
- Endianness
- Compiler information
- Entry point address

## Supported Binary Formats

### Executables
- **ELF**: Linux, BSD, and other Unix-like systems
- **PE**: Windows executables and DLLs
- **Mach-O**: macOS and iOS binaries
- **MZ**: DOS executables

### Archives and Mobile
- **ZIP/JAR**: Archive formats
- **APK**: Android packages
- **IPA**: iOS packages

### Specialized Formats
- **ELF with multiple architectures**
- **Java CLASS files**
- **WebAssembly (WASM)**
- **Nintendo Entertainment System (NES)**
- **Various game console formats**

## Usage Examples

### Example: Analyzing an ELF Binary

```c
#include <rz_bin.h>
#include <stdio.h>

int main(void) {
	// Create a binary context
	RzBin *bin = rz_bin_new();
	if (!bin) {
		return 1;
	}

	// Open a binary file
	RzBinFile *file = rz_bin_open(bin, "/usr/bin/ls", false);
	if (!file) {
		fprintf(stderr, "Failed to open binary\n");
		rz_bin_free(bin);
		return 1;
	}

	// Get binary information
	const RzBinInfo *info = rz_bin_object_get_info(file->o);
	if (info) {
		printf("Architecture: %s\n", info->arch);
		printf("Bit width: %d\n", info->bits);
		printf("Operating System: %s\n", info->os);
		printf("Entry Point: 0x%"PFMT64x"\n", info->entry);
	}

	// Get and print symbols
	RzPVector *symbols = (RzPVector *)rz_bin_object_get_symbols(file->o);
	if (symbols) {
		void **it;
		rz_pvector_foreach (symbols, it) {
			RzBinSymbol *sym = *it;
			printf("Symbol: %s @ 0x%"PFMT64x"\n", sym->name, sym->vaddr);
		}
	}

	// Cleanup
	rz_bin_free(bin);
	return 0;
}
```

### Example: Extracting Sections

```c
RzBin *bin = rz_bin_new();
RzBinFile *file = rz_bin_open(bin, "binary.elf", false);

if (file) {
	RzPVector *sections = (RzPVector *)rz_bin_object_get_sections_all(file->o);
	if (sections) {
		void **it;
		rz_pvector_foreach (sections, it) {
			RzBinSection *sec = *it;
			printf("Section: %s @ 0x%"PFMT64x" (size: %"PFMT64u")\n",
				sec->name, sec->vaddr, sec->vsize);
		}
	}
}

rz_bin_free(bin);
```

## Key Features

- **Format Detection**: Automatically detect binary format
- **Multi-object Support**: Handle binaries with multiple objects (e.g., fat binaries)
- **DWARF Support**: Extract debug information from DWARF sections
- **String Analysis**: Extract and analyze strings from binary
- **Relocation Handling**: Parse and apply relocations
- **Symbol Resolution**: Map symbols between imported and exported
- **Type Information**: Extract type information for better analysis
- **Cross-platform**: Support for binaries from different architectures and OSes

## Module Organization

- **format/**: Format-specific parsers (ELF, PE, Mach-O, etc.)
- **d/**: Debug information handlers
- **dwarf/**: DWARF parser implementation
- **pdb/**: PDB (Program Database) support for Windows
- **p/**: Plugin directory for binary format plugins
