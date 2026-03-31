project('rizin-shell-parser', 'c',
  license: 'LGPL-3.0-only',
  meson_version: '>=0.55.0',
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

tree_sitter_dep = dependency('tree-sitter')
grammar_js = files('grammar.js')
tree_sitter_wrap_py = files('meson_tree_sitter_generate.py')

subdir('src')

libshell_parser = static_library('shell_parser', shell_parser_files,
  include_directories: shell_parser_inc,
  dependencies: tree_sitter_dep.partial_dependency(includes: true),
  implicit_include_directories: true
)

shell_parser_dep = declare_dependency(
  link_with: libshell_parser,
  include_directories: shell_parser_inc,
  dependencies: tree_sitter_dep
)
meson.override_dependency('rizin-shell-parser', shell_parser_dep)
