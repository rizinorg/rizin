rz_type_sources = [
  'base.c',
  'format.c',
  'function.c',
  'helpers.c',
  'path.c',
  'serialize_functions.c',
  'serialize_types.c',
  'type.c',
  'typeclass.c',
  'parser/c_cpp_parser.c',
  'parser/types_parser.c',
  'parser/types_storage.c',
]

r = run_command(py3_exe, check_meson_subproject_py, 'tree-sitter-c')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

tree_sitter_c_proj = subproject('tree-sitter-c', default_options: ['default_library=static'])
tree_sitter_c_dep = tree_sitter_c_proj.get_variable('tree_sitter_c_dep')

rz_type_inc = [
  platform_inc,
  'parser',
]

rz_type = library('rz_type', rz_type_sources,
  include_directories: rz_type_inc,
  c_args: library_cflags,
  dependencies: [
    rz_util_dep,
    tree_sitter_dep,
    tree_sitter_c_dep,
    lrt
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  link_args: library_linkflags,
  soversion: rizin_libversion
)

rz_type_dep = declare_dependency(link_with: rz_type,
                                include_directories: rz_type_inc)

pkgconfig_mod.generate(rz_type,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_type',
  filebase: 'rz_type',
  requires: [
    'rz_util',
  ],
  description: 'rizin foundation libraries'
)

conf = configuration_data()
conf.set('RZ_VERSION', rizin_version)
conf.set('RIZIN_MODULE', 'Type')
conf.set('RIZIN_MODULE_DEPS', ' '.join(['RzUtil']))
conf.set('INSTALL_INCDIR', rizin_incdir)
conf.set('INSTALL_LIBDIR', rizin_libdir)
conf.set('rizin_libname', rz_type.name())
cmake_mod.configure_package_config_file(
  name: 'Rz' + conf.get('RIZIN_MODULE'),
  input: '../RzModulesConfig.cmake.in',
  install_dir: rizin_cmakedir,
  configuration: conf,
)
