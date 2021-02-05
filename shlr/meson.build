# handle capstone dependency
capstone_dep = dependency('capstone', version: '>=3.0.4', required: get_option('use_sys_capstone'), static: is_static_build)
if not capstone_dep.found()
  capstone_version = get_option('use_capstone_version')
  if capstone_version == 'bundled'
    r = run_command(py3_exe, check_meson_subproject_py, 'capstone-bundled')
    if r.returncode() == 1 and get_option('subprojects_check')
      error('Subproject capstone-bundled is not updated. Please make sure to run `meson subprojects update` or set option `subprojects_check=false` if you want to compile against currently downloaded subproject.')
    endif
    capstone_proj = subproject('capstone-bundled', default_options: ['default_library=static'])
  elif capstone_version == 'next'
    r = run_command(py3_exe, check_meson_subproject_py, 'capstone-next')
    if r.returncode() == 1 and get_option('subprojects_check')
      error('Subproject capstone-next is not updated. Please make sure to run `meson subprojects update` or set option `subprojects_check=false` if you want to compile against currently downloaded subproject.')
    endif
    capstone_proj = subproject('capstone-next', default_options: ['default_library=static'])
  elif capstone_version == 'v3'
    capstone_proj = subproject('capstone-v3', default_options: ['default_library=static'])
  elif capstone_version == 'v4'
    capstone_proj = subproject('capstone-v4', default_options: ['default_library=static'])
  else
    error('Wrong capstone version selected. Please use one of the supported versions.')
  endif
  capstone_dep = capstone_proj.get_variable('capstone_dep')
endif


# handle tree-sitter
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
  'java/dsojson.c',
  'java/ops.c',
  #'java/main.c',
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
  lz4_proj = subproject('lz4', default_options: ['default_library=static'])
  lz4_dep = lz4_proj.get_variable('lz4_dep')
endif


# handle zip dependency
libzip_dep = dependency('libzip', required: get_option('use_sys_libzip'), static: is_static_build)
if not libzip_dep.found()
  libzip_proj = subproject('libzip', default_options: [
    'default_library=static',
    'static_runtime=@0@'.format(is_static_build)]
  )
  libzip_dep = libzip_proj.get_variable('libzip_dep')
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
