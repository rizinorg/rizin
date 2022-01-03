parse_plugins = [
  '6502_pseudo',
  'arm_pseudo',
  'att2intel',
  'avr_pseudo',
  'chip8_pseudo',
  'tms320_pseudo',
  'dalvik_pseudo',
  'm68k_pseudo',
  'mips_pseudo',
  'ppc_pseudo',
  'v850_pseudo',
  'wasm_pseudo',
  'x86_pseudo',
]

if get_option('use_gpl')
  parse_plugins += [
    'sh_pseudo',
    'riscv_pseudo',
    'z80_pseudo'
  ]
endif

if parse_enabled_static_plugins == ['*']
  parse_enabled_static_plugins = parse_plugins
endif
if parse_enabled_shared_plugins == ['*']
  parse_enabled_shared_plugins = parse_plugins
endif

parse_static_plugins = []
parse_shared_plugins = []
foreach p : parse_plugins
  if p in parse_enabled_static_plugins + parse_enabled_shared_plugins
    subdir(p)
    if p in parse_enabled_static_plugins
      parse_static_plugins += [plugin]
    else
      parse_shared_plugins += [plugin]
    endif
  endif
endforeach
