project('rizin', 'c',
  version: 'v0.4.0-git',
  license: 'LGPL3',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
  ]
)

py3_exe = import('python').find_installation()
git_exe = find_program('git', required: false)
pkgconfig_mod = import('pkgconfig')
cmake_mod = import('cmake')

# Python scripts used during the build process
create_tags_rz_py = files('sys/create_tags_rz.py')
syscall_preprocessing_py = files('sys/syscall_preprocessing.py')
check_meson_subproject_py = files('sys/check_meson_subproject.py')
git_exe_repo_py = files('sys/meson_git_wrapper.py')
tree_sitter_wrap_py = files('sys/meson_tree_sitter_generate.py')
cmake_package_prefix_dir_py = files('sys/meson_cmake_prefix_dir.py')

is_static_build = get_option('static_runtime')
is_static_libs_only = get_option('default_library') == 'static'
if is_static_build and not is_static_libs_only
  error('Cannot use `static_runtime` when libraries are dynamically built. Set `--default-library=static` if you want to build statically.')
endif

# Get rizin version and compute various version parts
rizin_version = meson.project_version().split('v')[1]
if host_machine.system() == 'darwin'
  rizin_version = rizin_version.split('-')[0]
endif

rizin_version_split = rizin_version.split('.')
rizin_version_major = rizin_version_split[0].to_int()
rizin_version_minor = rizin_version_split[1].to_int()
rizin_version_patch = rizin_version_split[2].split('-')[0].to_int()
rizin_version_number = 1000000 * rizin_version_major + 1000 * rizin_version_minor + rizin_version_patch


repo = '.'
if meson.is_subproject()
  repo = meson.current_source_dir()
  if host_machine.system() == 'windows'
    py_cmd = 'print(__import__("os").readlink(r"@0@"))'.format(repo)
    py_cmd = run_command(py3_exe, '-c', py_cmd, check: true)
    if py_cmd.returncode() == 0
      repo = py_cmd.stdout().strip()
      message('rizin real path: ' + repo)
    endif
  endif
endif

# by default, not version commit is used
version_commit = '0'

gittip = ''

fs = import('fs')
if git_exe.found() and fs.exists('.git')
  # Get gittip
  git_rev_parse = run_command(py3_exe, git_exe_repo_py, git_exe, repo, 'rev-parse', 'HEAD', check: true)
  if git_rev_parse.returncode() == 0
    gittip = git_rev_parse.stdout().strip()
  endif
endif

if get_option('rizin_version_commit') != ''
  version_commit = get_option('rizin_version_commit')
endif

if get_option('rizin_gittip') != ''
  gittip = get_option('rizin_gittip')
endif

# Get current date
if host_machine.system() == 'windows'
  rizinbirth = run_command('cmd', '/c', 'echo %date%__%time%', check: true)
else
  rizinbirth = run_command('sh', '-c', '''
      SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(date +%s)}";
      FORMAT="+%Y-%m-%d__%H:%M:%S";
      date -u -d "@$SOURCE_DATE_EPOCH" "$FORMAT" 2>/dev/null ||
      date -u -r  "$SOURCE_DATE_EPOCH" "$FORMAT" 2>/dev/null ||
      date -u "$FORMAT"''', check: true)
endif
if rizinbirth.returncode() != 0
  rizinbirth = ''
else
  rizinbirth = rizinbirth.stdout().strip()
endif

rizin_libversion = host_machine.system() == 'windows' ? '' : rizin_version
message('rizin lib version: ' + rizin_libversion)

# system dependencies
cc = meson.get_compiler('c')
# required for linux
ldl = cc.find_library('dl', required: false, static: is_static_build)
pth = dependency('threads', required: false, static: is_static_build)
utl = cc.find_library('util', required: false, static: is_static_build)
if host_machine.system() == 'sunos'
  # workaround for Solaris until https://github.com/mesonbuild/meson/issues/4328 is fixed
  mth = declare_dependency(link_args: '-lm')
else
  mth = cc.find_library('m', required: false, static: is_static_build)
endif

platform_deps = []
platform_inc = ['.', 'librz', 'librz/include']
if host_machine.system() == 'windows'
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
  add_project_arguments('--std=gnu99', language: ['c', 'cpp'])
elif cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c', 'cpp'])
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

executable_cflags = []
executable_linkflags = []
library_cflags = ['-DRZ_PLUGIN_INCORE=1']
library_linkflags = []
b_sanitize_opt = get_option('b_sanitize')
if (b_sanitize_opt.contains('address') or b_sanitize_opt.contains('undefined')) and cc.get_id() == 'clang'
  executable_cflags += '-shared-libasan'
  executable_linkflags += '-shared-libasan'
  library_cflags += '-shared-libasan'
  library_linkflags += '-shared-libasan'
endif


rizin_prefix = get_option('prefix')
rizin_bindir = get_option('bindir')
rizin_libdir = get_option('libdir')
rizin_cmakedir = rizin_libdir / 'cmake'
rizin_incdir = get_option('includedir') / 'librz'
rizin_datdir = get_option('datadir')
if host_machine.system() == 'windows'
  rizin_prefix = fs.as_posix(rizin_prefix).replace('/', '\\\\')
  rizin_bindir = fs.as_posix(rizin_bindir).replace('/', '\\\\')
  rizin_libdir = fs.as_posix(rizin_libdir).replace('/', '\\\\')
  rizin_cmakedir = fs.as_posix(rizin_cmakedir).replace('/', '\\\\')
  rizin_incdir = fs.as_posix(rizin_incdir).replace('/', '\\\\')
  rizin_datdir = fs.as_posix(rizin_datdir).replace('/', '\\\\')
  rizin_datdir_rz = rizin_datdir
  rizin_wwwroot = rizin_datdir + '\\\\' + 'www'
  rizin_sdb = rizin_datdir
  rizin_zigns = rizin_datdir + '\\\\' + 'zigns'
  rizin_sigdb = rizin_datdir + '\\\\' + 'sigdb'
  rizin_themes = rizin_datdir + '\\\\' + 'cons'
  rizin_fortunes = rizin_datdir + '\\\\' + 'fortunes'
  rizin_flags = rizin_datdir + '\\\\' + 'flag'
  rizin_hud = rizin_datdir + '\\\\' + 'hud'
  rizin_plugins = rizin_libdir + '\\\\' + 'plugins'
  rizin_bindings = rizin_libdir + '\\\\' + 'bindings'
else
  rizin_datdir_rz = rizin_datdir / 'rizin'
  rizin_wwwroot = rizin_datdir_rz / 'www'
  rizin_sdb = rizin_datdir_rz
  rizin_zigns = rizin_datdir_rz / 'zigns'
  rizin_sigdb = rizin_datdir_rz / 'sigdb'
  rizin_themes = rizin_datdir_rz / 'cons'
  rizin_fortunes = rizin_datdir_rz / 'fortunes'
  rizin_flags = rizin_datdir_rz / 'flag'
  rizin_hud = rizin_datdir_rz / 'hud'
  rizin_plugins = rizin_libdir / 'rizin' / 'plugins'
  rizin_bindings = rizin_libdir / 'rizin-bindings'
endif

# Calcualte BINDIR's depth to be able to find the root directory during runtime
# in portable builds
py_cmd = 'import os; print(len(os.path.normpath(r"@0@").split(os.sep)) - len(os.path.normpath(r"@1@").split(os.sep)))'.format(rizin_prefix / rizin_bindir, rizin_prefix)
py_cmd = run_command(py3_exe, '-c', py_cmd, check: true)
bindir_depth = py_cmd.stdout().strip()

opts_overwrite = [
  'rizin_wwwroot',
  'rizin_sdb',
  'rizin_zigns',
  'rizin_sigdb',
  'rizin_themes',
  'rizin_fortunes',
  'rizin_flags',
  'rizin_hud',
  'rizin_plugins',
  'rizin_bindings'
]
foreach opt : opts_overwrite
  val = get_option(opt)
  if val != ''
    set_variable(opt, val)
  endif
endforeach

cmake_package_relative_path = run_command(py3_exe, cmake_package_prefix_dir_py, rizin_prefix, rizin_cmakedir / 'xxx', check: true).stdout().strip()

# handle capstone dependency
capstone_dep = dependency('capstone', version: '>=3.0.4', required: get_option('use_sys_capstone'), static: is_static_build)
if not capstone_dep.found()
  capstone_version = get_option('use_capstone_version')
  if capstone_version == 'bundled'
    r = run_command(py3_exe, check_meson_subproject_py, 'capstone-bundled', check: false)
    if r.returncode() == 1 and get_option('subprojects_check')
      error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
    endif
    capstone_proj = subproject('capstone-bundled', default_options: ['default_library=static'])
  elif capstone_version == 'next'
    r = run_command(py3_exe, check_meson_subproject_py, 'capstone-next', check: false)
    if r.returncode() == 1 and get_option('subprojects_check')
      error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
    endif
    capstone_proj = subproject('capstone-next', default_options: ['default_library=static'])
  elif capstone_version == 'v3'
    r = run_command(py3_exe, check_meson_subproject_py, 'capstone-v3', check: false)
    if r.returncode() == 1 and get_option('subprojects_check')
      error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
    endif
    capstone_proj = subproject('capstone-v3', default_options: ['default_library=static'])
  elif capstone_version == 'v4'
    r = run_command(py3_exe, check_meson_subproject_py, 'capstone-v4', check: false)
    if r.returncode() == 1 and get_option('subprojects_check')
      error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
    endif
    capstone_proj = subproject('capstone-v4', default_options: ['default_library=static'])
  else
    error('Wrong capstone version selected. Please use one of the supported versions.')
  endif
  capstone_dep = capstone_proj.get_variable('capstone_dep')
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

# handle xxhash library
r = run_command(py3_exe, check_meson_subproject_py, 'xxhash', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
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
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
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

# handle openssl library
sys_openssl = dependency('openssl', required: get_option('use_sys_openssl'), static: is_static_build)

# handle libuv library
libuv_dep = disabler()
if get_option('use_libuv')
  r = run_command(py3_exe, check_meson_subproject_py, 'libuv', check: false)
  if r.returncode() == 1 and get_option('subprojects_check')
    error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
  endif

  libuv_dep = dependency('libuv', version: '>=1.0.0', required: get_option('use_sys_libuv'), static: is_static_build)
  if not libuv_dep.found()
    libuv_proj = subproject('libuv', default_options: ['default_library=static'])
    libuv_dep = libuv_proj.get_variable('libuv_dep')
  endif
endif

# handle tree-sitter
r = run_command(py3_exe, check_meson_subproject_py, 'tree-sitter', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

tree_sitter_dep = dependency('tree-sitter', required: get_option('use_sys_tree_sitter'), static: is_static_build, fallback: [])
if not tree_sitter_dep.found()
  tree_sitter_proj = subproject('tree-sitter', default_options: ['default_library=static'])
  tree_sitter_dep = tree_sitter_proj.get_variable('tree_sitter_dep')
endif
meson.override_dependency('tree-sitter', tree_sitter_dep)

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
userconf.set('RZ_CHECKS_LEVEL', checks_level)
userconf.set10('IS_PORTABLE', get_option('portable'))
userconf.set10('HAVE_LIB_MAGIC', sys_magic.found())
userconf.set10('USE_LIB_MAGIC', sys_magic.found())
userconf.set10('HAVE_LIB_XXHASH', xxhash_dep.found())
userconf.set10('USE_LIB_XXHASH', xxhash_dep.found())
userconf.set10('DEBUGGER', has_debugger)
userconf.set('PREFIX', rizin_prefix)
userconf.set('BINDIR', rizin_bindir)
userconf.set('BINDIR_DEPTH', bindir_depth)
userconf.set('LIBDIR', rizin_libdir)
userconf.set('INCLUDEDIR', rizin_incdir)
userconf.set('DATADIR_RZ', rizin_datdir_rz)
is_ppc = host_machine.cpu_family() == 'ppc' or host_machine.cpu_family() == 'ppc64'
userconf.set10('HAVE_JEMALLOC', host_machine.system() != 'windows' and (host_machine.system() != 'darwin' or not is_ppc))
userconf.set('DATADIR', rizin_datdir)
userconf.set('WWWROOT', rizin_wwwroot)
userconf.set('SDB', rizin_sdb)
userconf.set('ZIGNS', rizin_zigns)
userconf.set('SIGDB', rizin_sigdb)
userconf.set('THEMES', rizin_themes)
userconf.set('FORTUNES', rizin_fortunes)
userconf.set('FLAGS', rizin_flags)
userconf.set('HUD', rizin_hud)
userconf.set('PLUGINS', rizin_plugins)
userconf.set('BINDINGS', rizin_bindings)
userconf.set10('HAVE_OPENSSL', sys_openssl.found())
userconf.set10('HAVE_LIBUV', libuv_dep.found())
userconf.set10('WANT_DYLINK', true)
userconf.set10('HAVE_PTRACE', have_ptrace)
userconf.set10('USE_PTRACE_WRAP', use_ptrace_wrap)
userconf.set10('WITH_GPL', get_option('use_gpl'))
userconf.set10('WITH_SWIFT_DEMANGLER', get_option('use_swift_demangler'))
userconf.set10('RZ_BUILD_DEBUG', get_option('buildtype').startswith('debug'))
ok = cc.has_header_symbol('sys/personality.h', 'ADDR_NO_RANDOMIZE')
userconf.set10('HAVE_DECL_ADDR_NO_RANDOMIZE', ok)
ok = cc.has_header_symbol('sys/procctl.h', 'PROC_ASLR_CTL')
userconf.set10('HAVE_DECL_PROCCTL_ASLR_CTL', ok)
ok = cc.has_header_symbol('linux/ashmem.h', 'ASHMEM_NAME_LEN')
userconf.set10('HAVE_DECL_ASHMEM_NAME_LEN', ok)

if host_machine.system() == 'freebsd' or host_machine.system() == 'dragonfly'
  add_project_link_arguments('-Wl,--unresolved-symbols,ignore-in-object-files', language: 'c')
  add_project_link_arguments('-Wl,--allow-shlib-undefined', language: 'c')
endif

lrt = dependency('', required: false)
if not cc.has_function('clock_gettime', prefix: '#include <time.h>') and cc.has_header_symbol('features.h', '__GLIBC__')
  lrt = cc.find_library('rt', required: true, static: is_static_build)
endif

have_lrt = not ['windows', 'darwin', 'openbsd', 'android', 'haiku'].contains(host_machine.system())
if have_lrt and not lrt.found()
  lrt = cc.find_library('rt', required: true, static: is_static_build)
endif

if host_machine.system() == 'darwin'
  # On older Mac OS X versions (at least Lion and older), environ is only available when compiling an executable,
  # but we will use is primarily in shared libs. Unfortunately, cc.links() only checks for executable compiling,
  # so this does not help us.
  # But in fact, even the environ(7) man page on macOS 11.6 still claims that environ is not avaliable for
  # shared libs (even though it seems to work) and suggests using _NSGetEnviron(), so let's just do this always.
  have_environ = false
else
  code = '#include <unistd.h>\nextern char **environ;\nint main() { char **env = environ; }'
  have_environ = cc.links(code, name: 'have extern char **environ')
endif
userconf.set10('HAVE_ENVIRON', have_environ)
message('HAVE_ENVIRON: @0@'.format(have_environ))

code = '#if __is_target_os(ios)\nint x = 0;\n#endif\nint main() { x++; }'
is_ios = cc.links(code, name: 'target is ios')
userconf.set10('IS_IOS', is_ios)
message('IS_IOS: @0@'.format(is_ios))

foreach item : [
    ['arc4random_uniform', '#include <stdlib.h>', []],
    ['explicit_bzero', '#include <string.h>', []],
    ['explicit_memset', '#include <string.h>', []],
    ['clock_nanosleep', '#include <time.h>', []],
    ['clock_gettime', '#include <time.h>', [lrt]],
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
    ['shm_open', '#include <sys/mman.h>', [lrt]],
    ['openpty', '', [utl]],
    ['forkpty', '', [utl]],
    ['login_tty', '', [utl]],
    ['pipe2', '#define _GNU_SOURCE\n#include <fcntl.h>\n#include <unistd.h>', []],
    ['copy_file_range', '#if defined(__linux__)\n#define _GNU_SOURCE\n#include <unistd.h>\n#endif', []],
  ]
  func = item[0]
  ok = cc.has_function(func, prefix: item[1], dependencies: item[2])
  userconf.set10('HAVE_@0@'.format(func.to_upper()), ok)
endforeach

if userconf.get('HAVE_PIPE2') == 1
  add_project_arguments('-D_GNU_SOURCE', language: ['c', 'cpp'])
endif

rz_userconf_h = configure_file(
  input: 'librz/include/rz_userconf.h.in',
  output: 'rz_userconf.h',
  configuration: userconf,
  install_dir: rizin_incdir
)

packager = get_option('packager')
packager_version = get_option('packager_version')

message('Version Major: @0@0'.format(rizin_version_major))
message('Version Minor: @0@0'.format(rizin_version_minor))
message('Version Patch: @0@0'.format(rizin_version_patch))
message('Version GitTip: @0@0'.format(gittip))

versionconf = configuration_data()
versionconf.set('RZ_VERSION_MAJOR', rizin_version_major)
versionconf.set('RZ_VERSION_MINOR', rizin_version_minor)
versionconf.set('RZ_VERSION_PATCH', rizin_version_patch)
versionconf.set('RZ_VERSION_NUMBER', rizin_version_number)
versionconf.set('RZ_VERSION', rizin_version)
versionconf.set('RZ_GITTIP', gittip)
versionconf.set('RZ_BIRTH', rizinbirth)
if packager_version != ''
  versionconf.set_quoted('RZ_PACKAGER_VERSION', packager_version)
  if packager != ''
    versionconf.set_quoted('RZ_PACKAGER', packager)
  endif
endif
rz_version_h = configure_file(
  input: 'librz/include/rz_version.h.in',
  output: 'rz_version.h',
  configuration: versionconf,
  install_dir: rizin_incdir
)

# handle zlib dependency
r = run_command(py3_exe, check_meson_subproject_py, 'zlib', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

zlib_dep = dependency('zlib', required: get_option('use_sys_zlib'), static: is_static_build)
if not zlib_dep.found()
  zlib_proj = subproject('zlib', default_options: ['default_library=static'])
  zlib_dep = zlib_proj.get_variable('zlib_dep')
endif

# handle lz4 dependency
r = run_command(py3_exe, check_meson_subproject_py, 'lz4', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

lz4_dep = dependency('liblz4', required: get_option('use_sys_lz4'), static: is_static_build)
if not lz4_dep.found()
  lz4_proj = subproject('lz4', default_options: ['default_library=static'])
  lz4_dep = lz4_proj.get_variable('lz4_dep')
endif

# handle zip dependency
r = run_command(py3_exe, check_meson_subproject_py, 'libzip', check: false)
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

# handle mpc dependency
r = run_command(py3_exe, check_meson_subproject_py, 'mpc', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

mpc_proj = subproject('mpc', default_options: ['default_library=static'])
mpc_dep = mpc_proj.get_variable('mpc_dep')

# handle yxml dependency
r = run_command(py3_exe, check_meson_subproject_py, 'yxml', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

yxml_proj = subproject('yxml', default_options: ['default_library=static'])
yxml_dep = yxml_proj.get_variable('yxml_dep')

# handle sdb dependency
r = run_command(py3_exe, check_meson_subproject_py, 'sdb', check: false)
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

sdb_proj = subproject('sdb', default_options: ['default_library=static', 'sdb_includedir=' + rizin_incdir])
sdb_dep = sdb_proj.get_variable('sdb_whole_dep')
sdb_exe  = sdb_proj.get_variable('sdb_native_exe')

sdb_gen_cmd = [
  sdb_exe,
  '@OUTPUT@',
  '==',
  '@INPUT@'
]

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
    build_root / 'librz' / 'analysis',
    build_root / 'librz' / 'asm',
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
    error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
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
  'zigns': rizin_zigns,
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
  'System magic library': sys_magic.found() and sys_magic.type_name() != 'internal',
  'System xxhash library': xxhash_dep.found() and xxhash_dep.type_name() != 'internal',
  'System openssl library': sys_openssl.found() and sys_openssl.type_name() != 'internal',
  'System libuv library': libuv_dep.found() and libuv_dep.type_name() != 'internal',
  'System capstone library': capstone_dep.found() and capstone_dep.type_name() != 'internal',
  'System tree-sitter library': tree_sitter_dep.found() and tree_sitter_dep.type_name() != 'internal',
  'System lz4 library': lz4_dep.found() and lz4_dep.type_name() != 'internal',
  'System zlib library': zlib_dep.found() and zlib_dep.type_name() != 'internal',
  'System zip library': libzip_dep.found() and libzip_dep.type_name() != 'internal',
  'Use ptrace-wrap': use_ptrace_wrap,
  'Use RPATH': rpath_summary,
}, section: 'Configuration', bool_yn: true)

summary({
  'Analysis Plugins': analysis_plugins,
  'Assembler Plugins': asm_plugins,
  'Binary Plugins': bin_plugins,
  'BinLdr Plugins': bin_ldr_plugins,
  'BinXtr Plugins': bin_xtr_plugins,
  'Breakpoint Plugins': bp_plugins,
  'Core Plugins': core_plugins,
  'Crypto Plugins': crypto_plugins,
  'Debug Plugins': debug_plugins,
  'Egg Plugins': egg_plugins,
  'IO Plugins': io_plugins,
  'Lang Plugins': lang_plugins,
  'Parse Plugins': parse_plugins,
  'Demangler Plugins': demangler_plugins,
}, section: 'Plugins', list_sep: ', ')
