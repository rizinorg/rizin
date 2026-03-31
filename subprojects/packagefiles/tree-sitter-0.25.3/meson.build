project('tree-sitter', 'c',
  license: 'MIT',
  meson_version: '>=0.55.0',
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=gnu99')
  add_project_arguments('--std=gnu99', language: ['c'])
elif cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

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
