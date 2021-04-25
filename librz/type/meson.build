rz_type_sources = [
  'base.c',
  'ctype.c',
  'format.c',
  'function.c',
  'helpers.c',
  'serialize_types.c',
  'type.c',
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
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_type_dep = declare_dependency(link_with: rz_type,
                                include_directories: rz_type_inc)

pkgconfig_mod.generate(rz_type,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_type',
  filebase: 'rz_type',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
  ],
  description: 'rizin foundation libraries'
)
