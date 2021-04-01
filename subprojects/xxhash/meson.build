project('xxhash', 'c',
    # library files are BSD licensed. xxhsum utility is GPL licensed.
    license : [ 'BSD', 'GPL'],
    version : '0.6.5')

inc = include_directories('.')

libxxhash = library('xxhash',
    ['xxhash.c'],
    include_directories : inc,
    version : meson.project_version(),
    install : false)

xxhash_dep = declare_dependency(
    include_directories : inc,
    link_with : libxxhash)