project('tree-sitter', 'c',
  license: 'MIT',
  meson_version: '>=0.55.0',
  default_options: [
    'c_std=c99',
  ]
)

cc = meson.get_compiler('c')

tree_sitter_path = 'tree-sitter'

tree_sitter_files = ['lib/src/lib.c']

tree_sitter_inc = [include_directories('lib/src'), include_directories('lib/include')]

libtree_sitter = static_library('tree_sitter', tree_sitter_files,
  include_directories: tree_sitter_inc,
  implicit_include_directories: false,
  install: not meson.is_subproject()
)

tree_sitter_dep = declare_dependency(
  link_with: libtree_sitter,
  include_directories: tree_sitter_inc
)
