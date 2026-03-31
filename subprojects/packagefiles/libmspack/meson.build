project('libmspack', 'c',
  version: '0.10.1alpha',
  license : 'LGPL2',
  meson_version: '>=0.55.0',
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

# handle libmspack dependency
libmspack_files = [
  'libmspack' / 'mspack' / 'cabc.c',
  'libmspack' / 'mspack' / 'cabd.c',
  'libmspack' / 'mspack' / 'chmc.c',
  'libmspack' / 'mspack' / 'chmd.c',
  'libmspack' / 'mspack' / 'crc32.c',
  'libmspack' / 'mspack' / 'hlpc.c',
  'libmspack' / 'mspack' / 'hlpd.c',
  'libmspack' / 'mspack' / 'kwajc.c',
  'libmspack' / 'mspack' / 'kwajd.c',
  'libmspack' / 'mspack' / 'litc.c',
  'libmspack' / 'mspack' / 'litd.c',
  'libmspack' / 'mspack' / 'lzssd.c',
  'libmspack' / 'mspack' / 'lzxc.c',
  'libmspack' / 'mspack' / 'lzxd.c',
  'libmspack' / 'mspack' / 'mszipc.c',
  'libmspack' / 'mspack' / 'mszipd.c',
  'libmspack' / 'mspack' / 'oabc.c',
  'libmspack' / 'mspack' / 'oabd.c',
  'libmspack' / 'mspack' / 'qtmc.c',
  'libmspack' / 'mspack' / 'qtmd.c',
  'libmspack' / 'mspack' / 'system.c',
  'libmspack' / 'mspack' / 'szddc.c',
  'libmspack' / 'mspack' / 'szddd.c',
]

config_data = configuration_data()
if get_option('debug_prints')
  debug_c = 'libmspack' / 'mspack' / 'debug.c'
  libmspack_files += debug_c
  config_data.set('DEBUG', 1)
else
  config_data.set('DEBUG', 0)
endif

# check on headers
foreach item : [
    ['dlfcn.h', '', [], 'HAVE_DLFCN_H'],
    ['inttypes.h', '', [], 'HAVE_INTTYPES_H'],
    ['stdint.h', '', [], 'HAVE_STDINT_H'],
    ['stdio.h', '', [], 'HAVE_STDIO_H'],
    ['stdlib.h', '', [], 'HAVE_STDLIB_H'],
    ['strings.h', '', [], 'HAVE_STRINGS_H'],
    ['string.h', '', [], 'HAVE_STRING_H'],
    ['sys/stat.h', '', [], 'HAVE_SYS_STAT_H'],
    ['sys/types.h', '', [], 'HAVE_SYS_TYPES_H'],
    ['unistd.h', '', [], 'HAVE_UNISTD_H'],
  ]
  ok = cc.has_header(item[0], prefix: item[1], dependencies: item[2])
  config_data.set10(item[3], ok)
endforeach

have_unistd_h = config_data.get('HAVE_UNISTD_H')
have_stdlib_h = config_data.get('HAVE_STDLIB_H')
have_string_h = config_data.get('HAVE_STRING_H')
config_data.set10('STDC_HEADERS', have_stdlib_h == 1 and have_string_h == 1)

# check on functions
foreach item : [
    ['fseeko', '#include <stdio.h>', [], 'HAVE_FSEEKO'],
    ['mkdir', '#include <sys/stat.h>', [], 'HAVE_MKDIR'],
    ['_mkdir', '#include <direct.h>', [], 'HAVE__MKDIR'],
    ['towlower', '#include <wctype.h>', [], 'HAVE_TOWLOWER'],
  ]
  ok = cc.has_function(item[0], prefix: item[1], dependencies: item[2])
  config_data.set10(item[3], ok)
endforeach

code = '#include <sys/stat.h>\n#if @0@\n#include <unistd.h>\n#endif\nint main(void) { mkdir ("."); return 0; }'.format(have_unistd_h)
mkdir_takes_one_arg = cc.links(code, name: 'mkdir has one argument')
config_data.set10('MKDIR_TAKES_ONE_ARG', mkdir_takes_one_arg)

# check types
foreach item : [
    ['mode_t', '#include <sys/types.h>', [], 'HAVE_MODE_T'],
    ['off_t', '#include <sys/types.h>', [], 'HAVE_OFF_T'],
    ['size_t', '#include <sys/types.h>', [], 'HAVE_SIZE_T'],
  ]
  sz = cc.sizeof(item[0], prefix: item[1], dependencies: item[2])
  config_data.set10(item[3], sz > 0)
endforeach

off_t_type = 'off_t'
off_t_prfx = '#include <sys/types.h>'
if config_data.get('HAVE_OFF_T') == 1
  off_t_type = 'long int'
  off_t_prfx = ''
endif
config_data.set('SIZEOF_OFF_T', cc.sizeof(off_t_type, prefix: off_t_prfx))

# check endianness
is_big_endian = target_machine.endian() == 'big'
config_data.set10('WORDS_BIGENDIAN', is_big_endian)

if host_machine.system() == 'aix'
  config_data.set('_LARGE_FILES', 1)
  config_data.set('_LARGEFILE_SOURCE', 0)
else
  config_data.set('_LARGE_FILES', 0)
  config_data.set10('_LARGEFILE_SOURCE', host_machine.system() != 'windows')
endif

config_h = configure_file(
  input: 'config.h.inc',
  output: 'config.h',
  configuration: config_data,
)

libmspack_inc = [include_directories(['libmspack' / 'mspack', 'libmspack'])]

libmspack = static_library('libmspack', libmspack_files,
  dependencies: [],
  include_directories: libmspack_inc,
  implicit_include_directories: false
)

libmspack_dep = declare_dependency(
  link_with: libmspack,
  include_directories: libmspack_inc
)
