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

# handle lz4 dependency
r = run_command(py3_exe, check_meson_subproject_py, 'lz4')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

lz4_dep = dependency('liblz4', required: get_option('use_sys_lz4'), static: is_static_build)
if not lz4_dep.found()
  lz4_proj = subproject('lz4', default_options: ['default_library=static'])
  lz4_dep = lz4_proj.get_variable('lz4_dep')
endif


# handle zip dependency
r = run_command(py3_exe, check_meson_subproject_py, 'libzip')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

libzip_dep = dependency('libzip', required: get_option('use_sys_libzip'), static: is_static_build)
if not libzip_dep.found()
  libzip_proj = subproject('libzip', default_options: [
    'default_library=static',
    'static_runtime=@0@'.format(is_static_build),
    'use_sys_openssl=@0@'.format(get_option('use_sys_libzip_openssl')),
  ])
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
