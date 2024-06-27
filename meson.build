project('rizin', 'c',
  version: 'v0.8.0',
  license: 'LGPL3',
  meson_version: '>=0.57.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
    'warning_level=1',
  ]
)

py3_exe = import('python').find_installation()
git_exe = find_program('git', required: false)
pkgconfig_mod = import('pkgconfig')

# Python scripts used during the build process
create_tags_rz_py = files('sys/create_tags_rz.py')
syscall_preprocessing_py = files('sys/syscall_preprocessing.py')
check_meson_subproject_py = files('sys/check_meson_subproject.py')
git_exe_repo_py = files('sys/meson_git_wrapper.py')
cmake_package_prefix_dir_py = files('sys/meson_cmake_prefix_dir.py')

is_static_build = get_option('static_runtime')
is_static_libs_only = get_option('default_library') == 'static'
if is_static_build and not is_static_libs_only
  error('Cannot use `static_runtime` when libraries are dynamically built. Set `--default-library=static` if you want to build statically.')
endif

# Get rizin version and compute various version parts
rizin_version = meson.project_version().split('v')[1]
rizin_version_split = rizin_version.split('.')
rizin_version_major = rizin_version_split[0].to_int()
rizin_version_minor = rizin_version_split[1].to_int()
rizin_version_patch = rizin_version_split[2].split('-')[0].to_int()
rizin_version_number = 1000000 * rizin_version_major + 1000 * rizin_version_minor + rizin_version_patch

repo = meson.current_source_dir()

rizin_libversion = '@0@.@1@'.format(rizin_version_major, rizin_version_minor)
message('rizin lib version: ' + rizin_libversion)

# system dependencies
cc = meson.get_compiler('c')
cc_native = meson.get_compiler('c', native: true)

platform_deps = []
platform_inc = ['.', 'librz', 'librz/include']
if host_machine.system() == 'windows'
  add_project_arguments('-DPSAPI_VERSION=1', language: 'c')
  platform_deps = [
    cc.find_library('ws2_32'),
    cc.find_library('wininet'),
    cc.find_library('psapi'),
  ]
endif
platform_inc = include_directories(platform_inc)

lib_name_suffix = []
lib_name_prefix = []
if is_static_libs_only and cc.get_id() == 'msvc'
  # On MSVC meson uses the .a suffix and lib as prefix, but cmake and other
  # tools expect a .lib suffix and no prefix
  # https://mesonbuild.com/FAQ.html#why-does-building-my-project-with-msvc-output-static-libraries-called-libfooa
  lib_name_suffix = 'lib'
  lib_name_prefix = ''
endif

if is_static_build
  if cc.get_id() == 'msvc'
    # Use -Db_vscrt=static_from_buildtype to avoid warnings due to multiple /M options
    if get_option('b_vscrt') == 'from_buildtype'
      warning('To avoid warnings due to multiple /M options, please also set -Db_vscrt=mt or -Db_vscrt=mtd.')
      add_project_arguments('/MT', language: 'c')
    endif
  else
    if cc.has_link_argument('-static')
      add_project_link_arguments('-static', language: 'c')
    endif
  endif
endif

if cc.has_argument('--std=gnu99')
  add_global_arguments('--std=gnu99', language: ['c', 'cpp'])
elif cc.has_argument('--std=c99')
  add_global_arguments('--std=c99', language: ['c', 'cpp'])
endif

# Sanitize correct usage of rz_strf()
if cc.has_argument('-Werror=sizeof-pointer-memaccess')
  add_global_arguments('-Werror=sizeof-pointer-memaccess', language: ['c', 'cpp'])
endif

if cc.has_argument('-Wimplicit-fallthrough=3')
  add_project_arguments('-Wimplicit-fallthrough=3', language: ['c', 'cpp'])
endif

if cc.get_id() == 'clang-cl'
  if cc.has_argument('-fcommon')
    add_project_arguments('-fcommon', language: 'c')
  endif
  add_project_arguments('-D__STDC__=1', language: 'c')
  add_project_arguments('-D_CRT_DECLARE_NONSTDC_NAMES ', language: 'c')
  add_project_arguments('-D_CRT_SECURE_NO_WARNINGS', language: 'c')
  add_project_arguments('-D_CRT_NONSTDC_NO_DEPRECATE', language: 'c')
endif

if get_option('default_library') == 'shared'
  if cc.has_argument('-fvisibility=hidden')
    add_global_arguments('-fvisibility=hidden', language: 'c')
  endif
endif

add_project_arguments(['-DRZ_PLUGIN_INCORE=1'], language: 'c')
b_sanitize_opt = get_option('b_sanitize')
if (b_sanitize_opt.contains('address') or b_sanitize_opt.contains('undefined')) and cc.get_id() == 'clang'
  add_global_arguments('-shared-libasan', language: 'c')
  add_global_link_arguments('-shared-libasan', language: 'c')
  add_global_arguments('-shared-libasan', language: 'c', native: true)
  add_global_link_arguments('-shared-libasan', language: 'c', native: true)
endif

fs = import('fs')
rizin_prefix = get_option('prefix')
rizin_bindir = get_option('bindir')
rizin_libdir = get_option('libdir')
rizin_cmakedir = rizin_libdir / 'cmake'
rizin_incdir = get_option('includedir') / 'librz'
rizin_datdir = get_option('datadir')
extra_prefix = get_option('extra_prefix')
if host_machine.system() == 'windows'
  rizin_prefix = fs.as_posix(rizin_prefix).replace('/', '\\\\')
  rizin_bindir = fs.as_posix(rizin_bindir).replace('/', '\\\\')
  rizin_libdir = fs.as_posix(rizin_libdir).replace('/', '\\\\')
  rizin_cmakedir = fs.as_posix(rizin_cmakedir).replace('/', '\\\\')
  rizin_incdir = fs.as_posix(rizin_incdir).replace('/', '\\\\')
  rizin_datdir = fs.as_posix(rizin_datdir).replace('/', '\\\\')
  rizin_datdir_rz = fs.as_posix(rizin_datdir).replace('/', '\\\\')
else
  rizin_datdir_rz = rizin_datdir / 'rizin'
endif

load_dirs = {
  'rizin_sdb': rizin_datdir_rz,
  'rizin_wwwroot': rizin_datdir_rz / 'www',
  'rizin_sigdb': rizin_datdir_rz / 'sigdb',
  'rizin_themes': rizin_datdir_rz / 'cons',
  'rizin_fortunes': rizin_datdir_rz / 'fortunes',
  'rizin_flags': rizin_datdir_rz / 'flag',
  'rizin_hud': rizin_datdir_rz / 'hud',
  'rizin_plugins': rizin_libdir / 'rizin' / 'plugins',
  'rizin_bindings': rizin_libdir / 'rizin-bindings',
}

# Calcualte BINDIR's depth to be able to find the root directory during runtime
# in portable builds
py_cmd = 'import os; from pathlib import Path; print(len(Path(os.path.normpath(r"@0@")).parents) - len(Path(os.path.normpath(r"@1@")).parents))'.format(rizin_prefix / rizin_bindir, rizin_prefix)
py_cmd = run_command(py3_exe, '-c', py_cmd, check: true)
bindir_depth = py_cmd.stdout().strip()

foreach load_dir, default_subdir : load_dirs
  val = get_option(load_dir)
  if val != ''
    set_variable(load_dir, val)
  else
    val = default_subdir
    if host_machine.system() == 'windows'
      val = fs.as_posix(val).replace('/', '\\\\')
    endif
    set_variable(load_dir, val)
  endif
endforeach

cmake_package_relative_path = run_command(py3_exe, cmake_package_prefix_dir_py, rizin_prefix, rizin_cmakedir / 'xxx', check: true).stdout().strip()

subproject_clean_error_msg = 'Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.'

# handle capstone dependency
capstone_dep = dependency('capstone', version: '>=4.0.2', required: get_option('use_sys_capstone'), static: is_static_build)
if not capstone_dep.found()
  capstone_version = get_option('use_capstone_version')
  if fs.is_file('subprojects/capstone-' + capstone_version + '.wrap')
    r = run_command(py3_exe, check_meson_subproject_py, 'capstone-' + capstone_version, check: false)
    if r.returncode() == 1 and get_option('subprojects_check')
      error(subproject_clean_error_msg)
    endif
    capstone_proj = subproject('capstone-' + capstone_version, default_options: ['default_library=static'])
  else
    error('Wrong capstone version selected. Please use one of the supported versions.')
  endif
  capstone_dep = capstone_proj.get_variable('capstone_dep')
else
  # Package managers CS version has no meta programming macros for AArch64 -> ARM64 renaming
  # (because it is outdated).
  # With this define we includeour copy of those macros.
  add_project_arguments(['-DUSE_SYS_CAPSTONE'], language: 'c')
endif

# Handle PCRE2
cpu_jit_supported = [ 'aarch64', 'arm', 'mips', 'mips64', 'ppc', 'ppc64', 'riscv32', 'riscv64', 's390x', 'x86', 'x86_64' ]
pcre2_jit_supported = target_machine.cpu_family() in cpu_jit_supported and cc.get_id() != 'tcc' and target_machine.system() != 'darwin'
if pcre2_jit_supported
  add_project_arguments(['-DSUPPORTS_PCRE2_JIT'], language: 'c')
endif

pcre2_dep_opt = get_option('use_sys_pcre2')
pcre2_dep = disabler()
if (pcre2_dep_opt.enabled() or pcre2_dep_opt.auto()) and not meson.is_cross_build()
  pcre2_dep = dependency('libpcre2-8', required: false, static: false)
  if not pcre2_dep.found()
    pcre2_dep = cc.find_library('pcre2', required: true, static: true)
  endif
else
  pcre2_dep = dependency('pcre2', version: '>=10.42', required: true, static: true)
endif

if meson.is_cross_build()
  pcre2_native_dep = dependency('pcre2_cross_native', required: true, static: true, native: true)
endif

# handle magic library
sys_magic_opt = get_option('use_sys_magic')
sys_magic = disabler()
if sys_magic_opt.enabled() or sys_magic_opt.auto()
  sys_magic = dependency('libmagic', required: false, static: is_static_build)
  if not sys_magic.found()
    sys_magic = cc.find_library('magic', required: sys_magic_opt, static: is_static_build)
  endif
endif

# handle libmspack library
sys_libmspack_opt = get_option('use_sys_libmspack')
libmspack_dep = disabler()
if sys_libmspack_opt.enabled() or sys_libmspack_opt.auto()
  libmspack_dep = dependency('libmspack', required: false, static: is_static_build)
  if not libmspack_dep.found()
    libmspack_dep = cc.find_library('mspack', required: sys_libmspack_opt, static: is_static_build)
  endif
endif
if (sys_libmspack_opt.auto() and not libmspack_dep.found()) or sys_libmspack_opt.disabled()
  libmspack_proj = subproject('libmspack', default_options: ['default_library=static'])
  libmspack_dep = libmspack_proj.get_variable('libmspack_dep')
endif

# handle xxhash library
r = run_command(py3_exe, check_meson_subproject_py, 'xxhash', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error(subproject_clean_error_msg)
endif

sys_xxhash_opt = get_option('use_sys_xxhash')
if sys_xxhash_opt.enabled() or sys_xxhash_opt.auto()
  xxhash_dep = dependency('libxxhash', required: false, static: is_static_build)
  if not xxhash_dep.found()
    xxhash_dep = cc.find_library('xxhash', required: sys_xxhash_opt, static: is_static_build)
  endif
endif
if (sys_xxhash_opt.auto() and not xxhash_dep.found()) or sys_xxhash_opt.disabled()
  xxhash_proj = subproject('xxhash', default_options: ['default_library=static'])
  xxhash_dep = xxhash_proj.get_variable('xxhash_dep')
endif

# handle libdemangle
r = run_command(py3_exe, check_meson_subproject_py, 'libdemangle', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error(subproject_clean_error_msg)
endif

libdemangle_options = ['default_library=static']
if get_option('use_gpl')
  libdemangle_options += 'use_gpl=true'
else
  libdemangle_options += 'use_gpl=false'
endif
if get_option('use_swift_demangler')
  libdemangle_options += 'use_swift_demangler=true'
else
  libdemangle_options += 'use_swift_demangler=false'
endif

libdemangle_proj = subproject('libdemangle', default_options: libdemangle_options)
libdemangle_dep = libdemangle_proj.get_variable('libdemangle_dep')

# handle blake3 algo
blake3_proj = subproject('blake3', default_options: ['default_library=static', 'werror=false'])
blake3_dep = blake3_proj.get_variable('blake3_dep')

# handle openssl library
sys_openssl = dependency('openssl', required: get_option('use_sys_openssl'), static: is_static_build)

# handle tree-sitter
r = run_command(py3_exe, check_meson_subproject_py, 'tree-sitter', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error(subproject_clean_error_msg)
endif

tree_sitter_dep = dependency('tree-sitter', required: get_option('use_sys_tree_sitter'), static: is_static_build, fallback: [])
if not tree_sitter_dep.found()
  tree_sitter_proj = subproject('tree-sitter', default_options: ['default_library=static'])
  tree_sitter_dep = tree_sitter_proj.get_variable('tree_sitter_dep')
  meson.override_dependency('tree-sitter', tree_sitter_dep)
endif

# handle tree-sitter-c
r = run_command(py3_exe, check_meson_subproject_py, 'tree-sitter-c', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error(subproject_clean_error_msg)
endif

tree_sitter_c_dep = dependency('tree-sitter-c', required: get_option('use_sys_tree_sitter'), static: is_static_build, fallback: [])
if not tree_sitter_c_dep.found()
  tree_sitter_c_proj = subproject('tree-sitter-c', default_options: ['default_library=static'])
  tree_sitter_c_dep = tree_sitter_c_proj.get_variable('tree_sitter_c_dep')
  # override done in tree sitter c subproject
endif

has_debugger = get_option('debugger')
have_ptrace = not ['windows', 'cygwin', 'sunos', 'haiku'].contains(host_machine.system())
use_ptrace_wrap = ['linux'].contains(host_machine.system())

have_ptrace = have_ptrace and has_debugger
use_ptrace_wrap = use_ptrace_wrap and has_debugger

message('HAVE_PTRACE: @0@'.format(have_ptrace))
message('USE_PTRACE_WRAP: @0@'.format(use_ptrace_wrap))

checks_level = get_option('checks_level')
if checks_level == 9999
  if get_option('buildtype') == 'release'
    checks_level = 1
  else
    checks_level = 2
  endif
endif

message('RZ_CHECKS_LEVEL: @0@'.format(checks_level))

userconf = configuration_data()
ccs = [[cc, userconf, host_machine, false]]
if meson.is_cross_build()
  userconf_native = configuration_data()
  ccs += [[cc_native, userconf_native, build_machine, true]]
endif
userconfs = []

foreach it : ccs
  it_cc = it[0]
  it_userconf = it[1]
  it_machine = it[2]
  it_native = it[3]

  # required for linux
  it_utl = it_cc.find_library('util', required: false, static: is_static_build)
  it_ldl = it_cc.find_library('dl', required: false, static: is_static_build)
  it_th = dependency('threads', required: false, static: is_static_build, native: it_native)
  have_pthread = it_th.found() and it_machine.system() != 'windows'
  if it_machine.system() == 'sunos'
    # workaround for Solaris until https://github.com/mesonbuild/meson/issues/4328 is fixed
    it_mth = declare_dependency(link_args: '-lm', native: it_native)
  else
    it_mth = it_cc.find_library('m', required: false, static: is_static_build)
  endif
  it_lrt = dependency('', required: false, native: it_native)
  if not it_cc.has_function('clock_gettime', prefix: '#include <time.h>') and it_cc.has_header_symbol('features.h', '__GLIBC__')
    it_lrt = it_cc.find_library('rt', required: true, static: is_static_build)
  endif
  have_lrt = not ['windows', 'darwin', 'openbsd', 'android', 'haiku'].contains(it_machine.system())
  if have_lrt and not it_lrt.found()
    it_lrt = it_cc.find_library('rt', required: true, static: is_static_build)
  endif
  # FreeBSD has backtrace() in libexecinfo
  it_lexecinfo = it_cc.find_library('execinfo', required: false)

  it_userconf.set('RZ_CHECKS_LEVEL', checks_level)
  it_userconf.set10('IS_PORTABLE', get_option('portable'))
  it_userconf.set10('HAVE_LIB_MAGIC', sys_magic.found())
  it_userconf.set10('USE_LIB_MAGIC', sys_magic.found())
  it_userconf.set10('HAVE_LIB_PCRE2', pcre2_dep.found())
  it_userconf.set10('USE_LIB_PCRE2', pcre2_dep.found())
  it_userconf.set10('HAVE_LIB_XXHASH', xxhash_dep.found())
  it_userconf.set10('USE_LIB_XXHASH', xxhash_dep.found())
  it_userconf.set10('DEBUGGER', has_debugger)
  if extra_prefix != ''
    it_userconf.set_quoted('EXTRA_PREFIX', extra_prefix)
  else
    it_userconf.set10('EXTRA_PREFIX', false)
  endif
  it_userconf.set('PREFIX', rizin_prefix)
  it_userconf.set('BINDIR', rizin_bindir)
  it_userconf.set('BINDIR_DEPTH', bindir_depth)
  it_userconf.set('LIBDIR', rizin_libdir)
  it_userconf.set('INCLUDEDIR', rizin_incdir)
  it_userconf.set('DATADIR_RZ', rizin_datdir_rz)
  is_ppc = it_machine.cpu_family() == 'ppc' or it_machine.cpu_family() == 'ppc64'
  it_userconf.set10('HAVE_JEMALLOC', it_machine.system() != 'windows' and (it_machine.system() != 'darwin' or not is_ppc))
  it_userconf.set('DATADIR', rizin_datdir)
  it_userconf.set('WWWROOT', rizin_wwwroot)
  it_userconf.set('SDB', rizin_sdb)
  it_userconf.set('SIGDB', rizin_sigdb)
  it_userconf.set('THEMES', rizin_themes)
  it_userconf.set('FORTUNES', rizin_fortunes)
  it_userconf.set('FLAGS', rizin_flags)
  it_userconf.set('HUD', rizin_hud)
  it_userconf.set('PLUGINS', rizin_plugins)
  it_userconf.set('BINDINGS', rizin_bindings)
  it_userconf.set10('HAVE_OPENSSL', sys_openssl.found())
  it_userconf.set10('WANT_DYLINK', true)
  it_userconf.set10('HAVE_PTRACE', have_ptrace)
  it_userconf.set10('USE_PTRACE_WRAP', use_ptrace_wrap)
  it_userconf.set10('WITH_GPL', get_option('use_gpl'))
  it_userconf.set10('WITH_SWIFT_DEMANGLER', get_option('use_swift_demangler'))
  it_userconf.set10('RZ_BUILD_DEBUG', get_option('buildtype').startswith('debug'))
  ok = it_cc.has_header_symbol('sys/personality.h', 'ADDR_NO_RANDOMIZE')
  it_userconf.set10('HAVE_DECL_ADDR_NO_RANDOMIZE', ok)
  ok = it_cc.has_header_symbol('sys/procctl.h', 'PROC_ASLR_CTL')
  it_userconf.set10('HAVE_DECL_PROCCTL_ASLR_CTL', ok)
  it_userconf.set10('HAVE_THREADS', it_th.found())
  it_userconf.set10('HAVE_PTHREAD', have_pthread)
  it_userconf.set10('HAVE_LZMA', get_option('use_lzma'))
  it_userconf.set10('HAVE_ZLIB', get_option('use_zlib'))
  it_userconf.set10('SUPPORTS_PCRE2_JIT', pcre2_jit_supported)
  it_userconf.set('N_THREAD_LIMIT', get_option('n_thread_limit'))

  if it_machine.system() == 'freebsd' or it_machine.system() == 'dragonfly'
    add_project_link_arguments('-Wl,--unresolved-symbols,ignore-in-object-files', language: 'c', native: it_native)
    add_project_link_arguments('-Wl,--allow-shlib-undefined', language: 'c', native: it_native)
  endif

  if it_machine.system() == 'darwin'
    # On older Mac OS X versions (at least Lion and older), environ is only available when compiling an executable,
    # but we will use is primarily in shared libs. Unfortunately, it_cc.links() only checks for executable compiling,
    # so this does not help us.
    # But in fact, even the environ(7) man page on macOS 11.6 still claims that environ is not avaliable for
    # shared libs (even though it seems to work) and suggests using _NSGetEnviron(), so let's just do this always.
    have_environ = false
  elif host_machine.system() == 'windows'
    code = '#include <stdlib.h>\n\nint main() { char **env = environ; }'
    have_environ = cc.links(code, name: 'have environ')
  else
    code = '#include <unistd.h>\nextern char **environ;\nint main() { char **env = environ; }'
    have_environ = it_cc.links(code, name: 'have extern char **environ')
  endif
  it_userconf.set10('HAVE_ENVIRON', have_environ)
  message('HAVE_ENVIRON: @0@'.format(have_environ))

  code = '#if __is_target_os(ios)\nint x = 0;\n#endif\nint main() { x++; }'
  is_ios = it_cc.links(code, name: 'target is ios')
  it_userconf.set10('IS_IOS', is_ios)
  message('IS_IOS: @0@'.format(is_ios))

  foreach item : [
      ['arc4random', '#include <stdlib.h>', []],
      ['arc4random_uniform', '#include <stdlib.h>', []],
      ['explicit_bzero', '#include <string.h>', []],
      ['explicit_memset', '#include <string.h>', []],
      ['clock_nanosleep', '#include <time.h>', []],
      ['clock_gettime', '#include <time.h>', [it_lrt]],
      ['sigaction', '#include <signal.h>', []],
      ['pipe', '#include <unistd.h>', []],
      ['execv', '#include <unistd.h>', []],
      ['execve', '#include <unistd.h>', []],
      ['execvp', '#include <unistd.h>', []],
      ['execl', '#include <unistd.h>', []],
      ['system', '#include <stdlib.h>', []],
      ['realpath', '#include <stdlib.h>', []],
      ['fork', '#include <unistd.h>', []],
      ['nice', '#include <unistd.h>', []],
      ['copyfile', '#include <copyfile.h>', []],
      ['strlcpy', '#include <string.h>', []],
      ['strnlen', '#include <string.h>', []],
      ['shm_open', '#include <sys/mman.h>', [it_lrt]],
      ['openpty', '', [it_utl]],
      ['forkpty', '', [it_utl]],
      ['login_tty', '', [it_utl]],
      ['pipe2', '#define _GNU_SOURCE\n#include <fcntl.h>\n#include <unistd.h>', []],
      # copy_file_range for now disable on freebsd as it s not reliable even for small chunks
      ['copy_file_range', '#ifdef __linux__\n#define _GNU_SOURCE\n#include <unistd.h>\n#endif', []],
      ['backtrace', '', [it_lexecinfo]],
      ['__builtin_bswap16', '', []],
      ['__builtin_bswap32', '', []],
      ['__builtin_bswap64', '', []],
      ['__builtin_clzll', '', []],
      ['posix_memalign', '#include <stdlib.h>', []],
      ['_aligned_malloc', '#include <malloc.h>', []],
    ]
    func = item[0]
    ok = it_cc.has_function(func, prefix: item[1], dependencies: item[2])
    it_userconf.set10('HAVE_@0@'.format(func.to_upper()), ok)
  endforeach

  foreach item : [
      ['linux/ashmem.h', '', []],
      ['sys/shm.h', '', []],
      ['sys/ipc.h', '', []],
      ['sys/mman.h', '', []],
      ['inttypes.h', '', []],
    ]
    hdr = item[0]
    ok = it_cc.has_header(hdr, prefix: item[1], dependencies: item[2])
    it_userconf.set10('HAVE_HEADER_@0@'.format(hdr.underscorify().to_upper()), ok)
  endforeach

  if it_userconf.get('HAVE_PIPE2') == 1
    add_project_arguments('-D_GNU_SOURCE', language: ['c', 'cpp'], native: it_native)
  endif
  userconfs += [[it_userconf, it_lrt, it_utl, it_ldl, it_mth, it_th]]
endforeach
userconf = userconfs[0][0]
lrt = userconfs[0][1]
utl = userconfs[0][2]
ldl = userconfs[0][3]
mth = userconfs[0][4]
th = userconfs[0][5]
if meson.is_cross_build()
  userconf_native = userconfs[1][0]
  lrt_native = userconfs[1][1]
  utl_native = userconfs[1][2]
  ldl_native = userconfs[1][3]
  mth_native = userconfs[1][4]
  th_native = userconfs[1][5]
endif

rz_userconf_h_in = files('librz/include/rz_userconf.h.in')
rz_userconf_h = configure_file(
  input: rz_userconf_h_in,
  output: 'rz_userconf.h',
  configuration: userconf,
  install_dir: rizin_incdir
)

packager = get_option('packager')
packager_version = get_option('packager_version')

message('Version Major: @0@0'.format(rizin_version_major))
message('Version Minor: @0@0'.format(rizin_version_minor))
message('Version Patch: @0@0'.format(rizin_version_patch))

versionconf = configuration_data()
versionconf.set('RZ_VERSION_MAJOR', rizin_version_major)
versionconf.set('RZ_VERSION_MINOR', rizin_version_minor)
versionconf.set('RZ_VERSION_PATCH', rizin_version_patch)
versionconf.set('RZ_VERSION_NUMBER', rizin_version_number)
versionconf.set('RZ_VERSION', rizin_version)
if packager_version != ''
  versionconf.set_quoted('RZ_PACKAGER_VERSION', packager_version)
  if packager != ''
    versionconf.set_quoted('RZ_PACKAGER', packager)
  endif
endif
rz_version_h = configure_file(
  input: 'librz/include/rz_build_version.h.in',
  output: 'rz_build_version.h',
  configuration: versionconf,
  install_dir: rizin_incdir
)

if git_exe.found() and fs.exists('.git')
  gittip_file = custom_target('gittip_file',
    build_always_stale: true,
    build_by_default: true,
    output: 'gittip',
    command: [py3_exe, git_exe_repo_py, git_exe, repo, 'rev-parse', 'HEAD'],
    install: true,
    install_dir: rizin_datdir_rz
  )
endif

# handle zlib dependency
zlib_dep = disabler()
if get_option('use_zlib')
  r = run_command(py3_exe, check_meson_subproject_py, 'zlib', check: false)
  if r.returncode() == 1 and get_option('subprojects_check')
    error(subproject_clean_error_msg)
  endif

  zlib_dep = dependency('zlib', required: get_option('use_sys_zlib'), static: is_static_build)
  if not zlib_dep.found()
    zlib_proj = subproject('zlib', default_options: ['default_library=static', 'werror=false'])
    zlib_dep = zlib_proj.get_variable('zlib_dep')
    meson.override_dependency('zlib', zlib_dep)
  endif
endif

# handle lz4 dependency
r = run_command(py3_exe, check_meson_subproject_py, 'lz4', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error(subproject_clean_error_msg)
endif

lz4_dep = dependency('liblz4', required: get_option('use_sys_lz4'), static: is_static_build)
if not lz4_dep.found()
  lz4_proj = subproject('lz4', default_options: ['default_library=static'])
  lz4_dep = lz4_proj.get_variable('lz4_dep')
endif

# handle lzma dependency
liblzma_dep = disabler()
if get_option('use_lzma')
  r = run_command(py3_exe, check_meson_subproject_py, 'lzma', check: false)
  if r.returncode() == 1 and get_option('subprojects_check')
    error(subproject_clean_error_msg)
  endif

  liblzma_dep = dependency('liblzma', required: get_option('use_sys_lzma'), static: is_static_build)
  if not liblzma_dep.found()
    liblzma_proj = subproject('liblzma', default_options: ['default_library=static'])
    liblzma_dep = liblzma_proj.get_variable('lzma_dep')
    meson.override_dependency('liblzma', liblzma_dep)
  endif
endif

# handle softfloat dependency
r = run_command(py3_exe, check_meson_subproject_py, 'softfloat', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error(subproject_clean_error_msg)
endif

softfloat_dep = dependency('softfloat', required: get_option('use_sys_softfloat'), static: is_static_build)
if not softfloat_dep.found()
  softfloat_proj = subproject('softfloat', default_options: ['default_library=static', 'warning_level=0'])
  softfloat_dep = softfloat_proj.get_variable('softfloat_dep')
endif

# handle zip dependency
r = run_command(py3_exe, check_meson_subproject_py, 'libzip', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error(subproject_clean_error_msg)
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

# handle zstd dependency
r = run_command(py3_exe, check_meson_subproject_py, 'zstd', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error(subproject_clean_error_msg)
endif

libzstd_dep = dependency('libzstd', required: get_option('use_sys_libzstd'), static: is_static_build, fallback: [])
if not libzstd_dep.found()
  zstd_proj = subproject('zstd', default_options: [
      'default_library=static',
      'static_runtime=@0@'.format(is_static_build),
  ])
  libzstd_dep = zstd_proj.get_variable('libzstd_dep')
  meson.override_dependency('zstd', libzstd_dep)
endif

# handle mpc dependency
r = run_command(py3_exe, check_meson_subproject_py, 'mpc', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error(subproject_clean_error_msg)
endif

mpc_proj = subproject('mpc', default_options: ['default_library=static'])
mpc_dep = mpc_proj.get_variable('mpc_dep')

# handle yxml dependency
r = run_command(py3_exe, check_meson_subproject_py, 'yxml', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error(subproject_clean_error_msg)
endif

yxml_proj = subproject('yxml', default_options: ['default_library=static'])
yxml_dep = yxml_proj.get_variable('yxml_dep')

use_rpath = false
use_rpath_absolute = false
if host_machine.system() != 'windows' and get_option('default_library') == 'shared'
  if get_option('local') == 'enabled'
    use_rpath = true
  elif get_option('local') == 'absolute'
    use_rpath_absolute = true
  elif get_option('local') == 'auto' and get_option('prefix') != '/usr'
    if host_machine.system() == 'openbsd'
      # OpenBSD's $ORIGIN only works in the way we would need it when running an
      # executable by its actual path, but not when run through PATH.
      # So let's use absolute rpaths there.
      use_rpath_absolute = true
    else
      use_rpath = true
    endif
  endif
endif

rpath_exe = ''
rpath_lib = ''
rpath_summary = 'disabled'
if use_rpath
  # Use bindir depth to create a path to the rootdir from bindir
  py_cmd = 'import os; print("../" * @0@)'.format(bindir_depth.to_int())
  py_cmd = run_command(py3_exe, '-c', py_cmd, check: true)
  path_to_rootdir = py_cmd.stdout().strip()

  rpath_exe = '$ORIGIN/' + path_to_rootdir + get_option('libdir')
  rpath_lib = '$ORIGIN'
  rpath_summary = 'relative'
elif use_rpath_absolute
  rpath_exe = get_option('prefix') / get_option('libdir')
  rpath_lib = get_option('prefix') / get_option('libdir')
  rpath_summary = 'absolute'
endif
# NOTE: this is to workaround an issue on Windows where unit tests don't use
# the right libraries, resulting in tests not being run properly
test_env_common_path = []
build_root = meson.current_build_dir()
if host_machine.system() == 'windows'
  test_env_common_path += [
    build_root / 'librz' / 'arch',
    build_root / 'librz' / 'bin',
    build_root / 'librz' / 'bp',
    build_root / 'librz' / 'config',
    build_root / 'librz' / 'cons',
    build_root / 'librz' / 'signature',
    build_root / 'librz' / 'core',
    build_root / 'librz' / 'demangler',
    build_root / 'librz' / 'diff',
    build_root / 'librz' / 'crypto',
    build_root / 'librz' / 'debug',
    build_root / 'librz' / 'egg',
    build_root / 'librz' / 'flag',
    build_root / 'librz' / 'hash',
    build_root / 'librz' / 'io',
    build_root / 'librz' / 'lang',
    build_root / 'librz' / 'magic',
    build_root / 'librz' / 'main',
    build_root / 'librz' / 'parse',
    build_root / 'librz' / 'reg',
    build_root / 'librz' / 'search',
    build_root / 'librz' / 'socket',
    build_root / 'librz' / 'syscall',
    build_root / 'librz' / 'type',
    build_root / 'librz' / 'util',
  ]
endif

subdir('librz')

if get_option('install_sigdb')
  r = run_command(py3_exe, check_meson_subproject_py, 'sigdb', check: false)
  if r.returncode() == 1 and get_option('subprojects_check')
    error(subproject_clean_error_msg)
  endif
  subproject('sigdb', default_options: ['sigdb_path=@0@'.format(get_option('prefix') / rizin_sigdb)])
endif

cli_option = get_option('cli')
cli_enabled = cli_option.auto() ? not meson.is_subproject() : cli_option.enabled()
if cli_enabled
  subdir('binrz')

  install_data('doc/hud',
    install_dir: rizin_hud,
    rename: 'main'
  )
endif

subdir('test')

install_data(
  'doc/fortunes.fun',
  'doc/fortunes.tips',
  install_dir: rizin_fortunes
)

dist_script = 'sys/meson_dist_script.py'
if meson.version().version_compare('>=0.49.0') and meson.version().version_compare('<0.57.0')
  meson.add_dist_script(meson.source_root() / dist_script)
else
  meson.add_dist_script(files(dist_script))
endif

summary({
  'prefix': rizin_prefix,
  'bindir': rizin_bindir,
  'libdir': rizin_libdir,
  'includedir': rizin_incdir,
  'datadir': rizin_datdir,
  'wwwroot': rizin_wwwroot,
  'sdb': rizin_sdb,
  'sigdb': rizin_sigdb,
  'themes': rizin_themes,
  'fortunes': rizin_fortunes,
  'flags': rizin_flags,
  'hud': rizin_hud,
  'plugins': rizin_plugins,
  'bindings': rizin_bindings,
}, section: 'Directories')

summary({
  'GPL code': get_option('use_gpl'),
  'Install sigdb': get_option('install_sigdb'),
  'Swift demangler': get_option('use_swift_demangler'),
  'Debugger enabled': has_debugger,
  'Capstone version': capstone_dep.version(),
  'PCRE2 version': pcre2_dep.version(),
  'PCRE2 JIT': pcre2_jit_supported,
  'System magic library': sys_magic.found() and sys_magic.type_name() != 'internal',
  'System pcre2 library': pcre2_dep.found() and pcre2_dep.type_name() != 'internal',
  'System xxhash library': xxhash_dep.found() and xxhash_dep.type_name() != 'internal',
  'System libmspack library': libmspack_dep.found() and libmspack_dep.type_name() != 'internal',
  'System openssl library': sys_openssl.found() and sys_openssl.type_name() != 'internal',
  'System capstone library': capstone_dep.found() and capstone_dep.type_name() != 'internal',
  'System tree-sitter library': tree_sitter_dep.found() and tree_sitter_dep.type_name() != 'internal',
  'System lz4 library': lz4_dep.found() and lz4_dep.type_name() != 'internal',
  'System lzma library': liblzma_dep.found() and liblzma_dep.type_name() != 'internal',
  'System softfloat library': softfloat_dep.found() and softfloat_dep.type_name() != 'internal',
  'System zlib library': zlib_dep.found() and zlib_dep.type_name() != 'internal',
  'System zstd library': libzstd_dep.found() and libzstd_dep.type_name() != 'internal',
  'System zip library': libzip_dep.found() and libzip_dep.type_name() != 'internal',
  'Use ptrace-wrap': use_ptrace_wrap,
  'Use RPATH': rpath_summary,
}, section: 'Configuration', bool_yn: true)

# output will be slightly degraded if there's only 1 crca_crc hash plugin and/or last hash plugin is a crca_crc plugin
comb_hash_plugins = []
in_crca_loop = false
foreach plugin : hash_plugins.get('list')
  if plugin.startswith('crca_crc')
    comb_hash_plugins += (in_crca_loop ? '' : 'crca_crc(') + plugin.split('_')[1].split('crc')[1]
    in_crca_loop = true
  else
    if in_crca_loop
      # add closing parenthesis to last crca_cec plugin
      parenthesized_last = []
      foreach item : comb_hash_plugins
        if item not in [comb_hash_plugins[-1]]
          parenthesized_last += item
        endif
      endforeach
      parenthesized_last += comb_hash_plugins[-1] + ')'
      comb_hash_plugins = parenthesized_last
    endif
    comb_hash_plugins += plugin
    in_crca_loop = false
  endif
endforeach

summary({
  'Arch Plugins': arch_plugins.get('list'),
  'Binary Plugins': bin_plugins.get('list'),
  'BinXtr Plugins': bin_xtr_plugins.get('list'),
  'Breakpoint Plugins': bp_plugins.get('list'),
  'Core Plugins': core_plugins.get('list'),
  'Crypto Plugins': crypto_plugins.get('list'),
  'Debug Plugins': debug_plugins.get('list'),
  'Egg Plugins': egg_plugins.get('list'),
  'IO Plugins': io_plugins.get('list'),
  'Lang Plugins': lang_plugins.get('list'),
  'Hash Plugins': comb_hash_plugins,
  'Demangler Plugins': demangler_plugins.get('list'),
}, section: 'Plugins', list_sep: ', ')
