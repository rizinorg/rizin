# librz/config

The `config` library is the centralized configuration management system for Rizin. It abstracts various configuration settings into nodes, providing a unified interface for typed access, validation, and persistence.

## Features

- **Unified Access:** Provides a single entry point for all subsystems to manage parameters.
- **Type Safety:** Handles strings, integers, and booleans with type-specific getters and setters.
- **Validation:** Supports getter and setter callbacks for input validation and state synchronization.
- **Immutability Control:** Supports locking the configuration set (no new keys) or marking specific keys as read-only.
- **Persistence:** Integrates with SDB for serialization and deserialization of configuration states.
- **State Restoration:** `RzConfigHold` allows temporary modification of settings with easy restoration to previous states.

## Core Structures

- `RzConfigNode`: The fundamental data unit representing a single configuration item. It contains the name, flags, values (both string and integer representation), callbacks, and descriptions.
- `RzConfig`: The main container that holds the hash table and list of all configuration nodes.
- `RzConfigHold`: A utility structure used to take a "snapshot" of specific configuration values to be restored later.

## Basic Usage

The following example demonstrates how to create a configuration set, define a setter callback, and perform basic operations:

```c
#include <rz_config.h>
#include <stdio.h>

static bool on_set_arch(void *user, void *data) {
	RzConfigNode *node = (RzConfigNode *)data;
	// Only allow x86 or arm
	if (!strcmp(node->value, "x86") || !strcmp(node->value, "arm")) {
		return true;
	}
	return false; // Rejects and rolls back to the previous value
}

int main(void) {
	RzConfig *cfg = rz_config_new(NULL);

	// Set configuration values
	rz_config_set(cfg, "asm.arch", "x86");
	rz_config_set_i(cfg, "asm.bits", 64);
	rz_config_set_b(cfg, "asm.pseudo", true);

	// Retrieve configuration values
	printf("arch=%s\n", rz_config_get(cfg, "asm.arch"));
	printf("bits=%" PFMT64u "\n", rz_config_get_i(cfg, "asm.bits"));

	// Set a callback for validation
	rz_config_set_setter(cfg, "asm.arch", on_set_arch);
	rz_config_set(cfg, "asm.arch", "mips"); // This will be rejected

	// Cleanup
	rz_config_free(cfg);
	return 0;
}