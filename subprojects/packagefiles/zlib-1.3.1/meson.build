project('zlib', 'c',
  version : '1.3.1',
  license : 'zlib',
  meson_version: '>=0.55.0',
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

link_args = []
compile_args = []
if cc.get_argument_syntax() == 'msvc'
  add_project_arguments(
    '-D_CRT_SECURE_NO_DEPRECATE',
    '-D_CRT_NONSTDC_NO_DEPRECATE',
    language : 'c')
elif cc.get_argument_syntax() == 'gcc'
  # Don't spam consumers of this wrap with these warnings
  compile_args += cc.get_supported_arguments('-Wno-implicit-fallthrough')
  if host_machine.system() not in ['windows', 'darwin']
    link_args += '-Wl,--version-script,@0@/zlib.map'.format(meson.current_source_dir())
  endif
endif

if cc.has_header('unistd.h')
  compile_args += '-DHAVE_UNISTD_H'
endif

if cc.has_header('stdarg.h')
  compile_args += '-DHAVE_STDARG_H'
endif

src = files([
  'adler32.c',
  'crc32.c',
  'deflate.c',
  'infback.c',
  'inffast.c',
  'inflate.c',
  'inftrees.c',
  'trees.c',
  'zutil.c',
  'compress.c',
  'uncompr.c',
  'gzclose.c',
  'gzlib.c',
  'gzread.c',
  'gzwrite.c'])

headers = files(['zconf.h', 'zlib.h'])

if host_machine.system() == 'windows'
  win = import('windows')
  win_args = []
  if cc.get_id() != 'msvc'
    win_args += '-DGCC_WINDRES'
  endif
  src += win.compile_resources('win32/zlib1.rc', args : win_args)
endif

zlib = library('z', src,
  c_args : compile_args,
  link_args : link_args,
  vs_module_defs : 'win32/zlib.def',
  install : false)

incdir = include_directories('.')

zlib_dep = declare_dependency(
  link_with : zlib,
  include_directories : incdir)
