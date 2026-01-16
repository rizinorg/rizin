# RzLang

The Rizin language library, `RzLang`, provides support for embedding and extending Rizin with scripting languages. It manages language plugins and enables users to write custom analysis and automation scripts.

The `RzLang` structure coordinates language runtime environments and script execution within the Rizin framework.

## What can I expect here?

- Multi-language scripting support:
  - **Python**: Full Python 3 integration
  - **JavaScript**: Node.js/V8 integration
  - **Lua**: Lua scripting language
  - **Guile**: Scheme/Guile support
  - **Wasm**: WebAssembly scripts
- Core functions for language management:
  - `rz_lang_new()`: To initialize language context
  - `rz_lang_use()`: To select scripting language
  - `rz_lang_run_file()`: To execute script file
  - `rz_lang_run()`: To execute script string
  - `rz_lang_free()`: To release language context
- Language plugin system:
  - Load language plugins dynamically
  - Register custom functions
  - API exposure to scripts
- Script execution:
  - Execute scripts in context
  - Access Rizin functionality from scripts
  - Error handling and debugging
- Namespace and module system:
  - Import Rizin modules
  - Create custom modules
  - Plugin architecture

## Architecture

The language library uses a plugin-based architecture:

- **`RzLang` Context**: Main language coordinator
- **Language Plugins**: Handle specific languages
- **Runtime Environments**: Language-specific runtimes
- **API Bindings**: Expose Rizin to scripts
- **Module System**: Organize scriptable functions

## Key Structures

### RzLang
Main language context containing:
- Language plugins registry
- Current language selection
- Runtime state
- Configuration

### RzLangPlugin
Language plugin definition with:
- Language name
- Initialization function
- Execution functions
- Cleanup function

## Supported Languages

### Python
Full Python 3 support with access to Rizin APIs.
```python
import rz

core = rz.core_new()
core.cmd("i")  # Get binary info
```

### JavaScript
Node.js/V8 JavaScript runtime integration.
```javascript
const rz = require('rz');
const core = new rz.Core();
core.cmd('afl');  // List functions
```

### Lua
Lightweight Lua scripting for automation.
```lua
local rz = require('rz')
local core = rz.core_new()
core:cmd('aa')  -- Analyze
```

### Guile
Scheme-based scripting with Guile.
```scheme
(use-modules (rz))
(rz-core-cmd core "i")
```

## Usage Examples

### Example: Basic Language Usage

```c
#include <rz_lang.h>
#include <stdio.h>

int main(void) {
	// Create language context
	RzLang *lang = rz_lang_new();
	if (!lang) {
		return 1;
	}

	// Use Python
	if (!rz_lang_use(lang, "python")) {
		fprintf(stderr, "Python plugin not loaded\n");
		rz_lang_free(lang);
		return 1;
	}

	// Execute a simple script
	const char *script = "print('Hello from Rizin!')";
	if (!rz_lang_run(lang, script)) {
		fprintf(stderr, "Script execution failed\n");
	}

	// Cleanup
	rz_lang_free(lang);
	return 0;
}
```

### Example: Python Scripting

```c
RzLang *lang = rz_lang_new();
rz_lang_use(lang, "python");

const char *python_script = 
	"import rz\n"
	"core = rz.core_new()\n"
	"core.open('/usr/bin/ls')\n"
	"core.cmd('aa')  # Analyze\n"
	"core.cmd('afl')  # List functions\n";

rz_lang_run(lang, python_script);

rz_lang_free(lang);
```

### Example: Loading Script from File

```c
RzLang *lang = rz_lang_new();

// Use JavaScript
rz_lang_use(lang, "javascript");

// Load and execute script file
rz_lang_run_file(lang, "my_analysis.js");

rz_lang_free(lang);
```

### Example: Accessing Rizin from Script

Python example accessing Rizin API:
```python
#!/usr/bin/env python3
import rz

# Create and open binary
core = rz.core_new()
core.open('/path/to/binary')

# Perform analysis
core.cmd('aa')  # Analyze

# Get functions
functions = core.get_functions()

# Iterate and analyze
for func in functions:
    print(f"Function: {func.name} @ {hex(func.addr)}")
    
    # Get block information
    for block in func.blocks:
        print(f"  Block @ {hex(block.addr)}")
```

### Example: Custom Analysis Script

```python
#!/usr/bin/env python3
import rz

def analyze_binary(filename):
    core = rz.core_new()
    
    # Open and analyze
    core.open(filename)
    core.cmd('aa')
    
    # Find suspicious patterns
    functions = core.get_functions()
    suspicious = []
    
    for func in functions:
        # Look for functions with many cross-references
        if len(func.xrefs) > 10:
            suspicious.append(func)
    
    print(f"Found {len(suspicious)} suspicious functions")
    for func in suspicious:
        print(f"  {func.name} with {len(func.xrefs)} references")

if __name__ == '__main__':
    analyze_binary('/usr/bin/ls')
```

## Language APIs

Each language has access to Rizin functionality:

### Python
- `rz.core_new()`: Create core context
- `rz.core_open()`: Open binary
- `rz.cmd()`: Execute command
- `rz.get_functions()`: List functions
- Etc.

### JavaScript
Similar APIs available through `rz` module.

### Lua
Table-based API accessible through `rz` module.

## Common Scripting Tasks

1. **Batch Analysis**: Analyze multiple binaries
2. **Pattern Matching**: Find specific code patterns
3. **Custom Visualization**: Generate custom output
4. **Automation**: Automate repetitive tasks
5. **Integration**: Connect with external tools
6. **Testing**: Develop test automation

## Key Features

- **Multi-language**: Choose preferred scripting language
- **Full API Access**: Complete Rizin functionality from scripts
- **Error Handling**: Proper error reporting from scripts
- **Performance**: Efficient script execution
- **Extensible**: Add new languages easily
- **Debugging**: Script debugging support
- **Persistence**: Save and reuse scripts

## Plugin Development

Create custom language plugins:

1. Implement `RzLangPlugin` interface
2. Provide initialization and execution functions
3. Expose Rizin APIs to the language
4. Register plugin with language system

## Use Cases

- **Custom Analysis**: Implement domain-specific analysis
- **Automation**: Batch processing of binaries
- **Integration**: Connect Rizin with external tools
- **Research**: Prototype new analysis techniques
- **Reporting**: Generate analysis reports
- **Fuzzing**: Automated fuzzing harnesses

## Integration Points

- **RzCore**: Execute commands from scripts
- **RzAnalysis**: Access analysis results
- **RzBin**: Query binary information
- **Custom Functions**: Register from scripts
- **Event Handlers**: React to analysis events
