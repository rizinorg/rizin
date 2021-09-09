project('tree-sitter', 'c')

cc = meson.get_compiler('c')

tree_sitter_cflags = ''
if cc.has_argument('-std=gnu99')
  tree_sitter_cflags = '-std=gnu99'
elif cc.has_argument('-std=c99')
  tree_sitter_cflags = '-std=c99'
endif

tree_sitter_path = 'tree-sitter'

tree_sitter_files = ['lib/src/lib.c']

tree_sitter_inc = [include_directories('lib/src'), include_directories('lib/include')]

libtree_sitter = static_library('tree_sitter', tree_sitter_files,
  include_directories: tree_sitter_inc,
  implicit_include_directories: false,
  c_args: tree_sitter_cflags,
  install: not meson.is_subproject()
)

tree_sitter_dep = declare_dependency(
  compile_args: tree_sitter_cflags,
  link_with: libtree_sitter,
  include_directories: tree_sitter_inc
)