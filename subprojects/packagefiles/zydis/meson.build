project('zydis', 'c', version: '4.1.0', meson_version: '>=0.55.0')


cc = meson.get_compiler('c')

if cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

conf_data = configuration_data()

zydis_c_args = [
  '-DZYDIS_STATIC_DEFINE',      
  '-fvisibility=hidden',     
]

if cc.get_id() in ['gcc', 'clang']
  if cc.has_argument('-w')
    add_project_arguments('-w', language: 'c')
  endif
elif cc.get_id() == 'msvc'
  add_project_arguments('/w', language: 'c') 
endif

zydis_sources = [
  'amalgamated-dist/Zydis.c'
]

if host_machine.system() == 'windows'
  zydis_c_args += ['-D_CRT_SECURE_NO_WARNINGS']
endif

zydis_includes = [
  './amalgamated-dist'
]

libzydis = static_library('zydis', zydis_sources,
  c_args: zydis_c_args,
  include_directories: zydis_includes,
  install: false,
)

zydis_dep = declare_dependency(
  link_with: libzydis,
  include_directories: zydis_includes,
)