project('rizin-math-parser', 'c',
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

libmath_parser = static_library('math_parser', math_parser_files,
  include_directories: math_parser_inc,
  dependencies: tree_sitter_dep.partial_dependency(includes: true),
  implicit_include_directories: true
)

math_parser_dep = declare_dependency(
  link_with: libmath_parser,
  include_directories: math_parser_inc,
  dependencies: tree_sitter_dep
)
meson.override_dependency('rizin-math-parser', math_parser_dep)
