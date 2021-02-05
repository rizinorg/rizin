project('yxml', 'c')

libyxml = library('yxml', 'yxml.c',
  implicit_include_directories: true)

yxml_dep = declare_dependency(
  link_with: libyxml,
  include_directories: include_directories('.'),
)