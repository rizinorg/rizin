project('rizin-grammar-c', 'c',
  license: 'MIT',
  meson_version: '>=0.55.0',
  default_options: [
    'c_std=c99',
    'werror=false'
    ]
)

ts_c_files = [
  'src/parser.c'
]

tree_sitter_dep = dependency('tree-sitter')

libtsc = static_library('rizin-grammar-c', ts_c_files,
  include_directories: ['src'],
  implicit_include_directories: false,
  dependencies: tree_sitter_dep.partial_dependency(includes: true)
)

rizin_grammar_c_dep = declare_dependency(
  link_with: libtsc,
  include_directories: ['src/tree_sitter'],
  dependencies: tree_sitter_dep
)
meson.override_dependency('rizin-grammar-c', rizin_grammar_c_dep)
