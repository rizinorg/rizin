#!/bin/bash
# Quick pre-push test - Run this for a fast sanity check

echo "Quick Pre-Push Test for DR Command"
echo "===================================="
echo ""

cd ~/Desktop/rizin/test || exit 1

# Test the exact failing cases from CI
echo "Testing exact CI scenarios with -N flag..."
echo ""

# Test 1: Spaces around equals
echo "1. Testing: dr rax = 0x1234"
output=$(sudo /usr/local/bin/rizin -N -d -q -c 'dr rax = 0x1234; dr rax' bins/elf/sse2-add 2>&1)
echo "$output"
if echo "$output" | grep -q "ERROR: Expected assignment"; then
    echo "❌ FAIL: Still getting parsing error!"
    exit 1
elif echo "$output" | grep -q "rax = 0x0000000000001234"; then
    echo "✅ PASS"
else
    echo "⚠️  UNEXPECTED OUTPUT"
fi
echo ""

# Test 2: Multiple assignments with various spacing
echo "2. Testing: dr rax=0x1111 rbx= 0x2222 rcx = 0x3333"
output=$(sudo /usr/local/bin/rizin -N -d -q -c 'dr rax=0x1111 rbx= 0x2222 rcx = 0x3333; dr rax rbx rcx' bins/elf/sse2-add 2>&1)
echo "$output"
if echo "$output" | grep -q "ERROR: Expected assignment"; then
    echo "❌ FAIL: Still getting parsing error!"
    exit 1
elif echo "$output" | grep -q "rbx = 0x0000000000002222"; then
    echo "✅ PASS"
else
    echo "⚠️  UNEXPECTED OUTPUT"
fi
echo ""

# Test 3: Mixed assignment and display
echo "3. Testing: dr rax=0x1111; dr rbx=0x2222; dr rax=0xAAAA rbx"
output=$(sudo /usr/local/bin/rizin -N -d -q -c 'dr rax=0x1111; dr rbx=0x2222; dr rax=0xAAAA rbx' bins/elf/sse2-add 2>&1)
echo "$output"
if echo "$output" | grep -q "ERROR: Expected assignment for 'rbx'"; then
    echo "❌ FAIL: Still getting parsing error!"
    exit 1
elif echo "$output" | grep -q "rbx = 0x0000000000002222"; then
    echo "✅ PASS"
else
    echo "⚠️  UNEXPECTED OUTPUT"
fi
echo ""

echo "===================================="
echo "Quick test complete!"
echo ""
echo "If all tests show ✅ PASS, your code is ready."
echo "If any show ❌ FAIL, there are still issues."
echo "===================================="
