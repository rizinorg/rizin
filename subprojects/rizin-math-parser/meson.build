project('rizin-math-parser', 'c',
  license : [ 'LGPL']
)

tree_sitter_dep = dependency('tree-sitter')
grammar_js = files('grammar.js')
tree_sitter_wrap_py = files('meson_tree_sitter_generate.py')

subdir('src')

librznum_parser = static_library('rznum_parser', rznum_parser_files,
  include_directories: rznum_parser_inc,
  dependencies: tree_sitter_dep.partial_dependency(includes: true),
  implicit_include_directories: true
)

rznum_parser_dep = declare_dependency(
  link_with: librznum_parser,
  include_directories: rznum_parser_inc,
  dependencies: tree_sitter_dep
)
meson.override_dependency('rizin-math-parser', rznum_parser_dep)
