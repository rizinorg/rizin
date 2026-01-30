project('yxml', 'c', version: '66507906673bc6159d5d620414479954c9c21c24')

libyxml = library('yxml', 'yxml.c',
  implicit_include_directories: true)

yxml_dep = declare_dependency(
  link_with: libyxml,
  include_directories: include_directories('.'),
)