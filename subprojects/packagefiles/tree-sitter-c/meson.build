project('tree-sitter-c', 'c', default_options: ['werror=false'])

ts_c_files = [
  'src/parser.c'
]

tree_sitter_dep = dependency('tree-sitter')

libtsc = static_library('tree-sitter-c', ts_c_files,
  include_directories: ['src'],
  implicit_include_directories: false,
  dependencies: tree_sitter_dep.partial_dependency(includes: true)
)

tree_sitter_c_dep = declare_dependency(
  link_with: libtsc,
  include_directories: ['src/tree_sitter'],
  dependencies: tree_sitter_dep
)
meson.override_dependency('tree-sitter-c', tree_sitter_c_dep)
