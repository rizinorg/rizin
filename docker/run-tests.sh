#!/bin/bash
# Full test suite for rizin + rz-tracetest
set -e

echo "=========================================="
echo "  Rizin + rz-tracetest Full Test Suite"
echo "=========================================="

cd /build/rizin

# 1. Unit tests (including RZIL: il_definitions, il_vm, il_validate, il_helpers, il_reg, analysis_op)
echo ""
echo ">>> Running unit tests..."
meson test -C build --no-rebuild --suite unit --print-errorlogs || {
    echo "Unit tests had failures (some may be expected)"
}

# 2. Integration tests
echo ""
echo ">>> Running integration tests..."
meson test -C build --no-rebuild --suite integration --print-errorlogs || {
    echo "Integration tests had failures (e.g. analysis_il needs bins/elf/emulateme.arm64)"
}

# 3. DB tests (asm, disasm, analysis, esil, rzil for all archs including CRIS)
echo ""
echo ">>> Running db/rz-test (asm, analysis, esil, rzil)..."
meson test -C build --no-rebuild --suite db --print-errorlogs || {
    echo "DB tests had failures"
}

# 4. Verify rz-tracetest
echo ""
echo ">>> Verifying rz-tracetest..."
if rz-tracetest --help > /dev/null 2>&1; then
    echo "rz-tracetest OK (use: rz-tracetest <trace.frames> to validate IR)"
else
    echo "rz-tracetest check failed"
fi

# 5. RZIL-specific unit tests summary
echo ""
echo ">>> RZIL unit tests (explicit)..."
meson test -C build --no-rebuild il_definitions il_reg il_validate il_vm il_helpers analysis_op --print-errorlogs 2>/dev/null || true

echo ""
echo "=========================================="
echo "  Test run complete"
echo "=========================================="
