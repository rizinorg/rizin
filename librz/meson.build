analysis_plugins = [
  '6502',
  '8051',
  'amd29k',
  'arm_cs',
  'avr',
  'bf',
  'chip8',
  'cr16',
  'dalvik',
  'ebc',
  'gb',
  'h8300',
  'hexagon',
  'i4004',
  'i8080',
  'java',
  'luac',
  'm68k_cs',
  'm680x_cs',
  'malbolge',
  'mcore',
  'mips_cs',
  'msp430',
  'null',
  'or1k',
  'pic',
  'ppc_cs',
  'propeller',
  'pyc',
  'rsp',
  'snes',
  'sparc_cs',
  'spc700',
  'sysz',
  'tms320',
  #'tms320c64x',
  'v810',
  'v850',
  'wasm',
  'x86_cs',
  'xap',
  'xcore_cs',
]

asm_plugins = [
  '6502',
  '8051',
  'amd29k',
  'arm_as',
  'arm_cs',
  'avr',
  'bf',
  'chip8',
  'cr16',
  'dalvik',
  'dcpu16',
  'ebc',
  'gb',
  'h8300',
  'hexagon',
  'i4004',
  'i8080',
  'java',
  'lh5801',
  'lm32',
  'luac',
  'm68k_cs',
  'm680x_cs',
  'malbolge',
  'mcore',
  'mcs96',
  'mips_cs',
  'msp430',
  'or1k',
  'pic',
  'ppc_as',
  'ppc_cs',
  'propeller',
  'pyc',
  'rsp',
  'snes',
  'sparc_cs',
  'spc700',
  'sysz',
  'tms320',
  'tms320c64x',
  'v810',
  'v850',
  'wasm',
  'x86_as',
  'x86_cs',
  'x86_nasm',
  'x86_nz',
  'xap',
  'xcore_cs',
]

bin_plugins = [
  'any',
  'art',
  'avr',
  'bf',
  'bflt',
  'bios',
  'bootimg',
  'cgc',
  'coff',
  'dex',
  'dmp64',
  'dol',
  'dyldcache',
  'elf',
  'elf64',
  'java',
  'le',
  'luac',
  'mach0',
  'mach064',
  'mbn',
  'mdmp',
  'menuet',
  'mz',
  'ne',
  'nes',
  'nin3ds',
  'ninds',
  'ningb',
  'ningba',
  'nro',
  'nso',
  'omf',
  'qnx',
  'p9',
  'pe',
  'pe64',
  'pebble',
  'prg',
  'psxexe',
  'pyc',
  'sfc',
  'smd',
  'sms',
  'spc700',
  'symbols',
  'te',
  'vsf',
  'wasm',
  'xbe',
  'xnu_kernelcache',
  'z64',
  'zimg',
]

bin_ldr_plugins = [
  'ldr_linux',
]

bin_xtr_plugins = [
  'xtr_fatmach0',
  'xtr_sep64',
]

bp_plugins = [
  'arm',
  'bf',
  'mips',
  'ppc',
  'sh',
  'x86'
]

core_plugins = [
  'java',
]

crypto_plugins = [
  'aes',
  'aes_cbc',
  'base64',
  'base91',
  'blowfish',
  'cps2',
  'des',
  'punycode',
  'rc2',
  'rc4',
  'rc6',
  'rol',
  'ror',
  'rot',
  'serpent',
  'xor',
]

debug_plugins = [
  'bf',
  'bochs',
  'esil',
  'gdb',
  'io',
  'native',
  'null',
  'rap',
  'winkd'
]

egg_plugins = [
  'exec',
  #'shya',
  'xor'
]

io_plugins = [
  'ar',
  'fd',
  'bfdbg',
  'bochs',
  'debug',
  'default',
  'gdb',
  'gprobe',
  'gzip',
  'http',
  'ihex',
  'srec',
  'mach',
  'malloc',
  'null',
  'procpid',
  'ptrace',
  'rzk',
  'rzpipe',
  'rzweb',
  'rap',
  'self',
  'shm',
  'sparse',
  'tcp',
  'winkd',
  'winedbg',
  'zip'
]

lang_plugins = [
  'lib',
  'pipe',
  'rust',
  'vala'
]

if host_machine.system() != 'windows'
  lang_plugins += [
    'c',
    'cpipe'
  ]
endif

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

demangler_plugins = [
  'java',
  'msvc',
  'objc',
]

if capstone_dep.version().split('.')[0].to_int() > 4
  analysis_plugins += 'riscv_cs'
  asm_plugins += 'riscv_cs'
endif

if get_option('use_gpl')
  io_plugins += 'qnx'
  debug_plugins += 'qnx'
  demangler_plugins += ['cpp', 'rust']
  analysis_plugins += [
    'arc',
    'cris',
    'mips_gnu',
    'nios2',
    'riscv',
    'sh',
    'sparc_gnu',
    'tricore',
    'vax',
    'xtensa',
    'z80',
  ]
  asm_plugins += [
    'arc',
    'cris_gnu',
    'hppa_gnu',
    'lanai_gnu',
    'mips_gnu',
    'nios2',
    'riscv',
    'sh',
    'sparc_gnu',
    'tricore',
    'vax',
    'xtensa',
    'z80',
  ]
  parse_plugins += [
    'sh_pseudo',
    'riscv_pseudo',
    'z80_pseudo'
  ]
endif

if host_machine.system() == 'windows'
  io_plugins += [
    'windbg',
    'w32dbg',
    'w32',
  ]
  debug_plugins += 'windbg'
endif

if get_option('use_swift_demangler')
  demangler_plugins += 'swift'
endif

conf_data = configuration_data()
conf_data.set('plugins_core', '&rz_core_plugin_' + ', &rz_core_plugin_'.join(core_plugins) + ', 0')
conf_data.set('plugins_analysis', '&rz_analysis_plugin_' + ', &rz_analysis_plugin_'.join(analysis_plugins) + ', 0')
conf_data.set('plugins_asm', '&rz_asm_plugin_' + ', &rz_asm_plugin_'.join(asm_plugins) + ', 0')
conf_data.set('plugins_bp', '&rz_bp_plugin_' + ', &rz_bp_plugin_'.join(bp_plugins) + ', 0')
conf_data.set('plugins_bin', '&rz_bin_plugin_' + ', &rz_bin_plugin_'.join(bin_plugins) + ', 0')
conf_data.set('plugins_bin_ldr', '&rz_bin_ldr_plugin_' + ', &rz_bin_ldr_plugin_'.join(bin_ldr_plugins) + ', 0')
conf_data.set('plugins_bin_xtr', '&rz_bin_xtr_plugin_' + ', &rz_bin_xtr_plugin_'.join(bin_xtr_plugins) + ', 0')
conf_data.set('plugins_crypto', '&rz_crypto_plugin_' + ', &rz_crypto_plugin_'.join(crypto_plugins) + ', 0')
conf_data.set('plugins_io', '&rz_io_plugin_' + ', &rz_io_plugin_'.join(io_plugins) + ', 0')
conf_data.set('plugins_debug', '&rz_debug_plugin_' + ', &rz_debug_plugin_'.join(debug_plugins) + ', 0')
conf_data.set('plugins_egg', '&rz_egg_plugin_' + ', &rz_egg_plugin_'.join(egg_plugins) + ', 0')
conf_data.set('plugins_lang', '&rz_lang_plugin_' + ', &rz_lang_plugin_'.join(lang_plugins) + ', 0')
conf_data.set('plugins_parse', '&rz_parse_plugin_' + ', &rz_parse_plugin_'.join(parse_plugins) + ', 0')
conf_data.set('plugins_demangler', '&rz_demangler_plugin_' + ', &rz_demangler_plugin_'.join(demangler_plugins))
config_h = configure_file(
  input: 'config.h.in',
  output: 'config.h',
  configuration: conf_data
)

subdir('include')

subdir('util')
subdir('demangler')
subdir('socket')
subdir('hash')
subdir('crypto')

subdir('cons')
subdir('diff')
subdir('io')
subdir('bp')
subdir('syscall')
subdir('search')
subdir('magic')
subdir('flag')
subdir('reg')
subdir('type')
subdir('bin')
subdir('config')
subdir('parse')
subdir('lang')
subdir('asm')
subdir('il')
subdir('analysis')
subdir('signature')
subdir('egg')
subdir('debug')
subdir('core')

subdir('main')


if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  cmake_mod.configure_package_config_file(
    name: 'Rizin',
    input: 'RizinConfig.cmake.in',
    install_dir: rizin_cmakedir / 'Rizin',
    configuration: conf,
  )
endif
