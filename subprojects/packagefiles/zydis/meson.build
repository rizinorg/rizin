project('zydis', 'c', version: '4.1.0')

#Compiler setup
cc = meson.get_compiler('c')

if cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

conf_data = configuration_data()

zydis_c_args = [
  '-DZYDIS_STATIC_DEFINE',      
  '-fvisibility=hidden',        
]


zydis_sources = [
  'src/zydis/Formatter.c',
  'src/zydis/FormatterBuffer.c',
  'src/zydis/MetaInfo.c',
  'src/zydis/SharedData.c',
  'src/zydis/String.c',
  'src/zydis/Utils.c',
  'src/zydis/Zydis.c',
]

if host_machine.system() == 'windows'
  zydis_c_args += ['-D_CRT_SECURE_NO_WARNINGS'] # Suppress warnings about unsafe functions
endif

zydis_includes = [
  include_directories('.'),
  include_directories('include'),
]

libzydis = static_library('zydis', zydis_sources,
  c_args: zydis_c_args,
  include_directories: zydis_includes,
  install: true, # Install the library when running `meson install`
)

zydis_dep = declare_dependency(
  link_with: libzydis,
  include_directories: zydis_includes,
)

install_headers('include/Zydis', subdir: 'Zydis')
