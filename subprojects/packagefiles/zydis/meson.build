project('zydis', 'c', version: '4.1.0', meson_version: '>=0.55.0')

cc = meson.get_compiler('c')

if cc.has_argument('--std=gnu99')
  add_project_arguments('--std=gnu99', language: ['c'])
elif cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

if cc.get_argument_syntax() == 'msvc'
  if get_option('b_lto')
    add_project_arguments(
      '/GL', # Compiler optimisation for MSVC
      language: 'c',
    )
    add_project_link_arguments(
      '/LTCG', # Used for Linking when compiling with /GL
      language: 'c',
    )
  endif
endif

zydis_c_args = []

if get_option('default_library') == 'static'
  zydis_c_args += ['-DZYDIS_STATIC_BUILD']
else
  zydis_c_args += ['-DZYDIS_SHOULD_EXPORT']
endif

if cc.get_id() == 'msvc'
    add_project_arguments('/W0', language: 'c')
elif cc.has_argument('-w')
    add_project_arguments('-w', language: 'c')
endif

# Can't use custom_target() here.
# Because the amalgamate.py hard codes its output path to `zydis/amalgamated-dist`.
# and creates it when run.
# custom_target() would run the scrpt during compile time,
# but it checks the include dir during config time and fails.
# Because amalgamate.py didn't run yet and didn't create the directory.
# So use run_command here instead (executes immediatedly) and call it a day.
python3 = find_program('python3')
r = run_command(python3, 'assets/amalgamate.py', check: true)

zydis_sources = [
  'amalgamated-dist/Zydis.c'
]

zydis_includes = [
  './amalgamated-dist'
]

libzydis = library('zydis', zydis_sources,
  c_args: zydis_c_args,
  include_directories: zydis_includes,
  install: false,
)

zydis_dep = declare_dependency(
  link_with: libzydis,
  include_directories: zydis_includes,
)
