# RzMagic

The Rizin magic library, `RzMagic`, identifies file types and provides file format information using magic number databases. It employs pattern matching against file signatures to determine file types and extract metadata.

The `RzMagic` structure manages magic database operations and file type detection.

## What can I expect here?

- File type identification:
  - Signature-based detection
  - Magic number pattern matching
  - Format-specific pattern rules
- Magic database management:
  - Load system magic databases
  - Support custom magic files
  - Efficient pattern matching
- Core functions for magic operations:
  - `rz_magic_new()`: To initialize magic context
  - `rz_magic_load()`: To load magic database
  - `rz_magic_descriptor()`: To identify file from descriptor
  - `rz_magic_buffer()`: To identify from buffer
  - `rz_magic_free()`: To release magic context
- File type information:
  - MIME type detection
  - Encoding detection
  - Format description
- Advanced features:
  - Recursive archive detection
  - Nested format identification
  - Custom magic rules

## Architecture

The magic library uses a pattern-based detection system:

- **`RzMagic` Context**: Main magic coordinator
- **Magic Database**: Loaded pattern database
- **Pattern Matcher**: Efficient pattern matching engine
- **Rule Engine**: Evaluate detection rules

## Key Structures

### RzMagic
Main magic context containing:
- Magic database
- Pattern rules
- Configuration
- Cache

### RzMagicLine
Individual magic rule with:
- Pattern offset
- Pattern bytes
- Match operation
- Result string

## Supported File Types

### Executables
- ELF (Linux binaries)
- PE (Windows binaries)
- Mach-O (macOS binaries)
- a.out (Legacy Unix)

### Archives
- ZIP files
- TAR archives
- GZIP compressed files
- BZIP2 compressed files
- RAR archives
- 7-Zip archives

### Documents
- PDF files
- Office documents (DOCX, XLSX, etc.)
- Text files
- HTML documents

### Images
- JPEG, PNG, GIF
- BMP, TIFF, ICO
- WEBP, SVG
- Various other formats

### Audio/Video
- MP3, FLAC, WAV
- MP4, AVI, MKV
- OGG, WebM

### Specialized
- Java CLASS files
- Python bytecode
- Firmware images
- Disk images

## Usage Examples

### Example: Identifying File Type from Buffer

```c
#include <rz_magic.h>
#include <stdio.h>

int main(void) {
	// Create magic context
	RzMagic *magic = rz_magic_new();
	if (!magic) {
		return 1;
	}

	// Load magic database
	if (!rz_magic_load(magic)) {
		fprintf(stderr, "Failed to load magic database\n");
		rz_magic_free(magic);
		return 1;
	}

	// Read file
	ut8 *buffer = NULL;
	int size = rz_file_slurp("/usr/bin/ls", &buffer);
	if (size <= 0) {
		fprintf(stderr, "Failed to read file\n");
		rz_magic_free(magic);
		return 1;
	}

	// Get file type from buffer
	const char *filetype = rz_magic_buffer(magic, buffer, size);
	if (filetype) {
		printf("File type: %s\n", filetype);
	}

	// Cleanup
	free(buffer);
	rz_magic_free(magic);
	return 0;
}
```

### Example: Identifying from File Descriptor

```c
RzMagic *magic = rz_magic_new();
rz_magic_load(magic);

// Open file and identify
int fd = open("/path/to/file", O_RDONLY);
if (fd >= 0) {
	const char *filetype = rz_magic_descriptor(magic, fd);
	printf("File type: %s\n", filetype);
	close(fd);
}

rz_magic_free(magic);
```

### Example: MIME Type Detection

```c
RzMagic *magic = rz_magic_new();
rz_magic_load(magic);

// Get MIME type instead of description
rz_magic_set_flags(magic, RZ_MAGIC_MIME_TYPE);
const char *mime = rz_magic_buffer(magic, buffer, size);
printf("MIME type: %s\n", mime);

rz_magic_free(magic);
```

### Example: Batch File Analysis

```c
RzMagic *magic = rz_magic_new();
rz_magic_load(magic);

// Array of file paths
const char *files[] = {
	"/usr/bin/ls",
	"/bin/bash",
	"/lib/libc.so.6",
	"/etc/passwd",
	NULL
};

// Analyze each file
for (int i = 0; files[i]; i++) {
	ut8 *buffer = NULL;
	int size = rz_file_slurp(files[i], &buffer);
	
	if (size > 0) {
		const char *type = rz_magic_buffer(magic, buffer, size);
		printf("%s: %s\n", files[i], type ? type : "unknown");
		free(buffer);
	}
}

rz_magic_free(magic);
```

## Magic Rules Format

Magic files contain rules in format:
```
offset  type      test        value           description
0       string    x           \x7fELF         ELF executable
0       string    x           MZ              PE executable
0       string    x           \xfe\xed\xfa    Mach-O executable
0       string    x           \x50\x4b\x03\x04 ZIP archive
0       string    x           \x1f\x8b        gzip compressed data
```

## Key Features

- **Fast Detection**: Efficient pattern matching
- **Accurate**: Comprehensive magic database
- **Standards-based**: Uses libmagic format
- **Customizable**: Support custom magic files
- **Extensible**: Add custom patterns
- **Format Info**: Detailed file format information
- **MIME Support**: Detect MIME types
- **Encoding Detection**: Identify file encoding

## Detection Methods

### Magic Numbers
Fixed byte sequences at specific offsets.

### Composite Rules
Multiple rules combined with operators.

### Offset-based
Match at various offsets in file.

### Type Checking
Validate against type specifications.

## Common File Signatures

| File Type | Magic Bytes | Offset |
|-----------|-----------|--------|
| ELF | `7F 45 4C 46` | 0 |
| PE | `4D 5A` | 0 |
| Mach-O | `FE ED FA` | 0 |
| ZIP | `50 4B 03 04` | 0 |
| GZIP | `1F 8B` | 0 |
| JPEG | `FF D8 FF` | 0 |
| PNG | `89 50 4E 47` | 0 |

## Output Formats

### Description
Human-readable description: "ELF 64-bit LSB executable, x86-64"

### MIME Type
MIME type string: "application/x-elf"

### Extended
Detailed information with multiple fields.

## Use Cases

- **File Validation**: Verify file format
- **Threat Detection**: Identify suspicious files
- **Archive Analysis**: Detect compressed formats
- **Format Migration**: Identify old formats
- **Malware Analysis**: Detect obfuscated files
- **Data Recovery**: Identify file types

## Integration Points

- **RzBin**: Format detection before parsing
- **RzCore**: File type commands
- **File Operations**: Identify uploaded files
- **Archive Handling**: Detect and process archives

## Performance Considerations

- Caching improves repeated detections
- Lazy loading of magic database
- Efficient pattern matching
- Minimal memory overhead

## Customization

Custom magic files can be loaded:
```c
rz_magic_load_path(magic, "/path/to/custom.magic");
```

## Limitations

- Limited to file signatures
- Cannot identify all formats
- Custom formats need custom rules
- Obfuscated files may be misidentified
