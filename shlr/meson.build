# new rizin shell parser
subdir('rizin-shell-parser')


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

if get_option('use_gpl')
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

librzwinkd_deps = [rz_util_dep, rz_socket_dep, rz_hash_dep, rz_crypto_dep]
if host_machine.system() == 'haiku'
  librzwinkd_deps += [
    cc.find_library('network')
  ]
endif

librzwinkd = static_library('rzwinkd', winkd_files,
  dependencies: librzwinkd_deps,
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
r = run_command(py3_exe, check_meson_subproject_py, 'mpc')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

mpc_proj = subproject('mpc', default_options: ['default_library=static'])
mpc_dep = mpc_proj.get_variable('mpc_dep')

# handle yxml dependency
r = run_command(py3_exe, check_meson_subproject_py, 'yxml')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

yxml_proj = subproject('yxml', default_options: ['default_library=static'])
yxml_dep = yxml_proj.get_variable('yxml_dep')
