project('rizin-grammar-c', 'c',
  license: 'MIT',
  meson_version: '>=0.55.0',
  default_options: [
    'werror=false'
  ]
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

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
