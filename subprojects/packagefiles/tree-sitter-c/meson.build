project('tree-sitter-c', version: 'f05e279aedde06a25801c3f2b2cc8ac17fac52ae', default_options: ['werror=false'])

ts_c_files = [
  'src/parser.c'
]

tree_sitter_proj = subproject('tree-sitter', default_options: ['default_library=static'])
tree_sitter_dep = tree_sitter_proj.get_variable('tree_sitter_dep')

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
