# handle capstone dependency
capstone_dep = dependency('capstone', version: '>=3.0.4', required: get_option('use_sys_capstone'), static: is_static_build)
if not capstone_dep.found()
  capstone_version = get_option('use_capstone_version')
  if capstone_version == 'bundled'
    r = run_command(py3_exe, check_meson_subproject_py, 'capstone-bundled')
    if r.returncode() == 1 and get_option('subprojects_check')
      error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
    endif
    capstone_proj = subproject('capstone-bundled', default_options: ['default_library=static'])
  elif capstone_version == 'next'
    r = run_command(py3_exe, check_meson_subproject_py, 'capstone-next')
    if r.returncode() == 1 and get_option('subprojects_check')
      error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
    endif
    capstone_proj = subproject('capstone-next', default_options: ['default_library=static'])
  elif capstone_version == 'v3'
    r = run_command(py3_exe, check_meson_subproject_py, 'capstone-v3')
    if r.returncode() == 1 and get_option('subprojects_check')
      error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
    endif
    capstone_proj = subproject('capstone-v3', default_options: ['default_library=static'])
  elif capstone_version == 'v4'
    r = run_command(py3_exe, check_meson_subproject_py, 'capstone-v4')
    if r.returncode() == 1 and get_option('subprojects_check')
      error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
    endif
    capstone_proj = subproject('capstone-v4', default_options: ['default_library=static'])
  else
    error('Wrong capstone version selected. Please use one of the supported versions.')
  endif
  capstone_dep = capstone_proj.get_variable('capstone_dep')
endif


# handle tree-sitter
r = run_command(py3_exe, check_meson_subproject_py, 'tree-sitter')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

tree_sitter_dep = dependency('tree-sitter', required: get_option('use_sys_tree_sitter'), static: is_static_build, fallback: [])
if not tree_sitter_dep.found()
  tree_sitter_proj = subproject('tree-sitter', default_options: ['default_library=static'])
  tree_sitter_dep = tree_sitter_proj.get_variable('tree_sitter_dep')
endif


# new rizin shell parser
shell_parser_path = 'rizin-shell-parser'
shell_parser_files = [
  join_paths(shell_parser_path, 'src/parser.c'),
  join_paths(shell_parser_path, 'src/scanner.c'),
]

shell_parser_inc = [platform_inc, include_directories('rizin-shell-parser/src/tree_sitter')]

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


# handle bochs dependency
bochs_files = [
  'bochs/src/libbochs.c'
]

bochs_inc = [platform_inc, include_directories('bochs/include')]

librzbochs = static_library('rzbochs', bochs_files,
  dependencies: [rz_util_dep],
  include_directories: bochs_inc,
  implicit_include_directories: false
)

bochs_dep = declare_dependency(
  link_with: librzbochs,
  include_directories: bochs_inc
)


# handle java dependency
java_files = [
  'java/class.c',
  'java/code.c',
  'java/ops.c',
]

java_inc = [platform_inc, include_directories('java')]

librzjava = static_library('rzjava', java_files,
  dependencies: [rz_util_dep],
  include_directories: java_inc,
  implicit_include_directories: false
)

java_dep = declare_dependency(
  link_with: librzjava,
  include_directories: java_inc
)


# handle qnx dependency
qnx_files = [
  'qnx/src/core.c',
  'qnx/src/packet.c',
  'qnx/src/sigutil.c',
  'qnx/src/utils.c',
]

qnx_inc = [platform_inc, include_directories('qnx/include')]

librzqnx = static_library('rzqnx', qnx_files,
  dependencies: [rz_util_dep, rz_socket_dep],
  include_directories: qnx_inc,
  implicit_include_directories: false
)

qnx_dep = declare_dependency(
  link_with: librzqnx,
  include_directories: qnx_inc
)


# handle tcc dependency (heavily modified version)
tcc_files = [
  'tcc/libtcc.c',
  'tcc/tccgen.c',
  'tcc/tccpp.c'
]

tcc_inc = [platform_inc, include_directories('tcc')]

librztcc = static_library('rztcc', tcc_files,
  dependencies: [rz_util_dep],
  include_directories: tcc_inc,
  implicit_include_directories: false
)

tcc_dep = declare_dependency(
  link_with: librztcc,
  include_directories: tcc_inc
)


# handle lz4 dependency
lz4_dep = dependency('liblz4', required: get_option('use_sys_lz4'), static: is_static_build)
if not lz4_dep.found()
  lz4_files = [
    'lz4/lz4.c',
  ]

  lz4_inc = [platform_inc, include_directories('lz4')]

  librzlz4 = static_library('rzlz4', lz4_files,
    include_directories: lz4_inc,
    implicit_include_directories: false
  )

  lz4_dep = declare_dependency(
    link_with: librzlz4,
    include_directories: lz4_inc
  )
endif


# handle zip dependency
zip_dep = dependency('libzip', required: get_option('use_sys_zip'), static: is_static_build)
if not zip_dep.found()
  zip_files = [
    'zip/zip/zip_add.c',
    'zip/zip/zip_add_dir.c',
    'zip/zip/zip_add_entry.c',
    'zip/zip/zip_close.c',
    'zip/zip/zip_delete.c',
    'zip/zip/zip_dir_add.c',
    'zip/zip/zip_dirent.c',
    'zip/zip/zip_discard.c',
    'zip/zip/zip_entry.c',
    'zip/zip/zip_err_str.c',
    'zip/zip/zip_error.c',
    #'zip/zip/zip_error_clear.c',
    'zip/zip/zip_error_get.c',
    'zip/zip/zip_error_get_sys_type.c',
    'zip/zip/zip_error_strerror.c',
    'zip/zip/zip_error_to_str.c',
    'zip/zip/zip_extra_field.c',
    'zip/zip/zip_extra_field_api.c',
    'zip/zip/zip_fclose.c',
    'zip/zip/zip_fdopen.c',
    'zip/zip/zip_file_add.c',
    #'zip/zip/zip_file_error_clear.c',
    'zip/zip/zip_file_error_get.c',
    'zip/zip/zip_file_get_comment.c',
    'zip/zip/zip_file_get_offset.c',
    'zip/zip/zip_file_rename.c',
    'zip/zip/zip_file_replace.c',
    'zip/zip/zip_file_set_comment.c',
    'zip/zip/zip_file_strerror.c',
    'zip/zip/zip_filerange_crc.c',
    'zip/zip/zip_fopen.c',
    'zip/zip/zip_fopen_encrypted.c',
    'zip/zip/zip_fopen_index.c',
    'zip/zip/zip_fopen_index_encrypted.c',
    'zip/zip/zip_fread.c',
    'zip/zip/zip_get_archive_comment.c',
    'zip/zip/zip_get_archive_flag.c',
    'zip/zip/zip_get_compression_implementation.c',
    'zip/zip/zip_get_encryption_implementation.c',
    'zip/zip/zip_get_file_comment.c',
    'zip/zip/zip_get_name.c',
    'zip/zip/zip_get_num_entries.c',
    'zip/zip/zip_get_num_files.c',
    'zip/zip/zip_name_locate.c',
    'zip/zip/zip_new.c',
    'zip/zip/zip_open.c',
    'zip/zip/zip_rename.c',
    'zip/zip/zip_replace.c',
    'zip/zip/zip_set_archive_comment.c',
    'zip/zip/zip_set_archive_flag.c',
    'zip/zip/zip_set_default_password.c',
    'zip/zip/zip_set_file_comment.c',
    'zip/zip/zip_set_file_compression.c',
    'zip/zip/zip_set_name.c',
    'zip/zip/zip_source_buffer.c',
    'zip/zip/zip_source_close.c',
    'zip/zip/zip_source_crc.c',
    'zip/zip/zip_source_deflate.c',
    'zip/zip/zip_source_error.c',
    'zip/zip/zip_source_file.c',
    'zip/zip/zip_source_filep.c',
    'zip/zip/zip_source_free.c',
    'zip/zip/zip_source_function.c',
    'zip/zip/zip_source_layered.c',
    'zip/zip/zip_source_open.c',
    'zip/zip/zip_source_pkware.c',
    'zip/zip/zip_source_pop.c',
    'zip/zip/zip_source_read.c',
    'zip/zip/zip_source_stat.c',
    'zip/zip/zip_source_window.c',
    'zip/zip/zip_source_zip.c',
    'zip/zip/zip_source_zip_new.c',
    'zip/zip/zip_stat.c',
    'zip/zip/zip_stat_index.c',
    'zip/zip/zip_stat_init.c',
    'zip/zip/zip_strerror.c',
    'zip/zip/zip_string.c',
    'zip/zip/zip_unchange.c',
    'zip/zip/zip_unchange_all.c',
    'zip/zip/zip_unchange_archive.c',
    'zip/zip/zip_unchange_data.c',
    'zip/zip/zip_utf-8.c'
  ]

  zip_inc = [platform_inc, include_directories('zip/include')]

  librzzip = static_library('rzzip', zip_files,
    include_directories: zip_inc,
    implicit_include_directories: false,
    dependencies: zlib_dep
  )

  zip_dep = declare_dependency(
    link_with: librzzip,
    include_directories: zip_inc
  )
endif

# handle winkd dependency
winkd_files = [
  'winkd/iob_pipe.c',
  'winkd/iob_net.c',
  'winkd/kd.c',
  'winkd/transport.c',
  'winkd/winkd.c',
]

winkd_inc = [platform_inc, include_directories('winkd')]

librzwinkd = static_library('rzwinkd', winkd_files,
  dependencies: [rz_util_dep, rz_socket_dep, rz_hash_dep, rz_crypto_dep],
  include_directories: winkd_inc,
  implicit_include_directories: false
)

winkd_dep = declare_dependency(
  link_with: librzwinkd,
  include_directories: winkd_inc
)


# handle ar dependency
ar_files = [
  'ar/ar.c'
]

ar_inc = [platform_inc, include_directories(['ar'])]

librzar = static_library('rzar', ar_files,
  dependencies: [rz_util_dep],
  include_directories: ar_inc,
  implicit_include_directories: false
)

ar_dep = declare_dependency(
  link_with: librzar,
  include_directories: ar_inc
)


# handle ptrace-wrap dependency
if use_ptrace_wrap
  subdir('ptrace-wrap')
endif

if host_machine.system() == 'windows'
  subdir('w32dbg_wrap')
endif

# handle mpc dependency
mpc_files = [
  'mpc/mpc.c'
]

mpc_inc = [platform_inc, include_directories(['mpc'])]

libmpc = static_library('rzmpc', mpc_files,
  include_directories: mpc_inc,
  implicit_include_directories: false
)

mpc_dep = declare_dependency(
  link_with: libmpc,
  include_directories: mpc_inc
)

# handle yxml dependency
yxml_files = [
  'yxml/yxml.c'
]

yxml_inc = [platform_inc, include_directories(['yxml'])]

libyxml = static_library('rzyxml', yxml_files,
  include_directories: yxml_inc,
  implicit_include_directories: false
)

yxml_dep = declare_dependency(
  link_with: libyxml,
  include_directories: yxml_inc
)
