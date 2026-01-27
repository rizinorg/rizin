# SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

# Makefile for jemalloc config extraction helper
#
# Usage:
#   1. Configure jemalloc first:
#      cd /path/to/jemalloc
#      ./configure [--host=<target>] [--with-lg-page=<N>]
#      make
#
#   2. Build and run this helper:
#      make JEMALLOC=/path/to/jemalloc
#      ./extract_config_450   # or extract_config_530
#
# Cross-compilation examples:
#   # ARM64 with 4KB pages
#   cd /path/to/jemalloc
#   ./configure --host=aarch64-linux-gnu --with-lg-page=12
#   make
#   cd /jemalloc-config-extractor
#   make JEMALLOC=/path/to/jemalloc CC=aarch64-linux-gnu-gcc
#
#   # ARM64 with 16KB pages
#   ./configure --host=aarch64-linux-gnu --with-lg-page=14
#   make JEMALLOC=/path/to/jemalloc CC=aarch64-linux-gnu-gcc
#
#   # ARM32 with 4KB pages
#   ./configure --host=arm-linux-gnueabihf --with-lg-page=12
#   make JEMALLOC=/path/to/jemalloc CC=arm-linux-gnueabihf-gcc
#
#   # i386 with 4KB pages
#   ./configure --host=i686-linux-gnu --with-lg-page=12
#   make JEMALLOC=/path/to/jemalloc CC=i686-linux-gnu-gcc
#
#   # RISC-V 64-bit with 4KB pages
#   ./configure --host=riscv64-linux-gnu --with-lg-page=12
#   make JEMALLOC=/path/to/jemalloc CC=riscv64-linux-gnu-gcc
#
#   # RISC-V 32-bit with 4KB pages
#   ./configure --host=riscv32-linux-gnu --with-lg-page=12
#   make JEMALLOC=/path/to/jemalloc CC=riscv32-linux-gnu-gcc

# Jemalloc root directory - REQUIRED for build targets
JEMALLOC ?=

# Only check JEMALLOC for targets that need it (not clean/help)
NEED_JEMALLOC := $(filter-out clean help,$(MAKECMDGOALS))
ifeq ($(MAKECMDGOALS),)
NEED_JEMALLOC := all
endif

ifneq ($(NEED_JEMALLOC),)
ifeq ($(JEMALLOC),)
$(error JEMALLOC is not set. Usage: make JEMALLOC=/path/to/jemalloc)
endif
endif

# Compiler (can be overridden for cross-compilation)
CC ?= gcc

# Include paths
CFLAGS += -I$(JEMALLOC)/include

# Required defines for jemalloc internal headers
CFLAGS += -D_GNU_SOURCE
CFLAGS += -D_REENTRANT

# Optimization and warnings
CFLAGS += -O0 -g -Wall

# Link with pthread (required by jemalloc mutex types)
LDFLAGS += -lpthread

# For jemalloc 5.x, we provide stub implementations for symbols referenced by
# inline functions, so no need to link against the library
LDFLAGS_530 = $(LDFLAGS)

# Detect jemalloc version to build the correct extractor
JEMALLOC_VERSION := $(shell cd $(JEMALLOC) 2>/dev/null && git describe --tags 2>/dev/null | cut -d. -f1)

ifeq ($(JEMALLOC_VERSION),4)
TARGETS := extract_config_450
else ifeq ($(JEMALLOC_VERSION),5)
TARGETS := extract_config_530
else
# Default if version can't be detected
TARGETS := extract_config_530
endif

.PHONY: all clean 450 530 help

all: $(TARGETS)

# Explicit version targets
450: extract_config_450
530: extract_config_530

extract_config_450: extract_config_450.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

extract_config_530: extract_config_530.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS_530)

clean:
	rm -f extract_config_450 extract_config_530

# Help target
help:
	@echo "jemalloc config extraction helper"
	@echo ""
	@echo "Usage:"
	@echo "  1. Configure and build jemalloc first:"
	@echo "     cd /path/to/jemalloc"
	@echo "     ./configure [--host=<target>] [--with-lg-page=<N>]"
	@echo "     make"
	@echo ""
	@echo "  2. Build and run this helper:"
	@echo "     make JEMALLOC=/path/to/jemalloc"
	@echo "     ./extract_config_450  # or extract_config_530"
	@echo ""
	@echo "Cross-compilation:"
	@echo "  make JEMALLOC=/path/to/jemalloc CC=aarch64-linux-gnu-gcc"
	@echo "  make JEMALLOC=/path/to/jemalloc CC=arm-linux-gnueabihf-gcc"
	@echo "  make JEMALLOC=/path/to/jemalloc CC=i686-linux-gnu-gcc"
	@echo "  make JEMALLOC=/path/to/jemalloc CC=riscv64-linux-gnu-gcc"
	@echo "  make JEMALLOC=/path/to/jemalloc CC=riscv32-linux-gnu-gcc"
	@echo ""
	@echo "Page size options (--with-lg-page=N):"
	@echo "   12 = 4KB pages (default)"
	@echo "   14 = 16KB pages"
	@echo "   16 = 64KB pages"
