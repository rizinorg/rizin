#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause
import re
import sys

def parse_sysregs(input_file):
    entries = []
    pattern = re.compile(r'^\s*(RISCV_SYSREG_(\w+))\s*=\s*(0x[0-9a-fA-F]+|\d+)')

    with open(input_file, 'r') as f:
        for line in f:
            m = pattern.match(line)
            if m:
                name  = m.group(1)   # e.g. RISCV_SYSREG_SEPC
                label = m.group(2)   # e.g. SEPC
                value = int(m.group(3), 0)
                entries.append((name, label, value))

    return entries

def generate_inc(entries, output_file):
    with open(output_file, 'w') as f:
        f.write("""
// SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause
// ***************************** AUTO-GENERATED, DO NOT TOUCH BY HAND *****************************
// AUTO-GENERATED FROM arch/RISCV/RISCVGenCSSystemOperandsEnum.inc in capstone\n\n""")
        # Write #defines
        for name, label, value in entries:
            f.write(f'#define {name} {value}\n')

        f.write('\n')

        # Write CSR_NAMES array
        f.write('static const char *CSR_NAMES[4096] = {\n')
        for name, label, value in entries:
            f.write(f'\t[{name}] = "{label.lower()}",\n')
        f.write('};\n')

        f.write('\n')

        # Undefine all constants
        for name, label, value in entries:
            f.write(f'#undef {name}\n')

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} <input_file> <output_file>')
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    entries = parse_sysregs(input_file)
    print(f'Parsed {len(entries)} RISCV_SYSREG entries.')
    generate_inc(entries, output_file)
    print(f'Generated {output_file}')
