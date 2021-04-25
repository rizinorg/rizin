project('rizin', 'c',
  version: 'v0.3.0-git',
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

# Python scripts used during the build process
create_tags_rz_py = files('sys/create_tags_rz.py')
syscall_preprocessing_py = files('sys/syscall_preprocessing.py')
check_meson_subproject_py = files('sys/check_meson_subproject.py')
git_exe_repo_py = files('sys/meson_git_wrapper.py')
tree_sitter_wrap_py = files('sys/meson_tree_sitter_generate.py')

is_static_build = get_option('static_runtime')
if is_static_build and get_option('default_library') != 'static'
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
    py_cmd = run_command(py3_exe, '-c', py_cmd)
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
  git_rev_parse = run_command(py3_exe, git_exe_repo_py, git_exe, repo, 'rev-parse', 'HEAD')
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
  rizinbirth = run_command('cmd', '/c', 'echo %date%__%time%')
else
  rizinbirth = run_command('date', '+%Y-%m-%d__%H:%M:%S')
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
platform_inc = ['.', 'librz/include']
if host_machine.system() == 'windows'
  platform_deps = [
    cc.find_library('ws2_32'),
    cc.find_library('wininet'),
    cc.find_library('psapi'),
  ]
endif
platform_inc = include_directories(platform_inc)

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

library_cflags = ['-DRZ_PLUGIN_INCORE=1']

rizin_prefix = get_option('prefix')
rizin_bindir = get_option('bindir')
rizin_libdir = get_option('libdir')
rizin_incdir = get_option('includedir') / 'librz'
rizin_datdir = get_option('datadir')
if host_machine.system() == 'windows'
  rizin_prefix = rizin_prefix / ''
  rizin_datdir_rz = rizin_datdir / ''
  rizin_wwwroot = rizin_datdir / 'www'
  rizin_sdb = rizin_datdir / ''
  rizin_zigns = rizin_datdir / 'zigns'
  rizin_themes = rizin_datdir / 'cons'
  rizin_fortunes = rizin_datdir / 'fortunes'
  rizin_flags = rizin_datdir / 'flag'
  rizin_hud = rizin_datdir / 'hud'
  rizin_plugins = rizin_libdir / 'plugins'
  rizin_extras = rizin_libdir / 'extras'
  rizin_bindings = rizin_libdir / 'bindings'
else
  rizin_datdir_rz = rizin_datdir / 'rizin'
  rizin_wwwroot = rizin_datdir_rz / rizin_version / 'www'
  rizin_sdb = rizin_datdir_rz / rizin_version
  rizin_zigns = rizin_datdir_rz / rizin_version / 'zigns'
  rizin_themes = rizin_datdir_rz / rizin_version / 'cons'
  rizin_fortunes = rizin_datdir_rz / rizin_version / 'fortunes'
  rizin_flags = rizin_datdir_rz / rizin_version / 'flag'
  rizin_hud = rizin_datdir_rz / rizin_version / 'hud'
  rizin_plugins = rizin_libdir / 'rizin' / rizin_version
  rizin_extras = rizin_libdir / 'rizin-extras' / rizin_version
  rizin_bindings = rizin_libdir / 'rizin-bindings' / rizin_version
endif

opts_overwrite = [
  'rizin_wwwroot',
  'rizin_sdb',
  'rizin_zigns',
  'rizin_themes',
  'rizin_fortunes',
  'rizin_flags',
  'rizin_hud',
  'rizin_plugins',
  'rizin_extras',
  'rizin_bindings'
]
foreach opt : opts_overwrite
  val = get_option(opt)
  if val != ''
    set_variable(opt, val)
  endif
endforeach

# load plugin configuration
subdir('librz')

conf_data = configuration_data()
conf_data.set('plugins_core', '&rz_core_plugin_' + ', &rz_core_plugin_'.join(core_plugins) + ', 0')
conf_data.set('plugins_analysis', '&rz_analysis_plugin_' + ', &rz_analysis_plugin_'.join(analysis_plugins) + ', 0')
conf_data.set('plugins_asm', '&rz_asm_plugin_' + ', &rz_asm_plugin_'.join(asm_plugins) + ', 0')
conf_data.set('plugins_bp', '&rz_bp_plugin_' + ', &rz_bp_plugin_'.join(bp_plugins) + ', 0')
conf_data.set('plugins_bin', '&rz_bin_plugin_' + ', &rz_bin_plugin_'.join(bin_plugins) + ', 0')
conf_data.set('plugins_bin_ldr', '&rz_bin_ldr_plugin_' + ', &rz_bin_ldr_plugin_'.join(bin_ldr_plugins) + ', 0')
conf_data.set('plugins_bin_xtr', '&rz_bin_xtr_plugin_' + ', &rz_bin_xtr_plugin_'.join(bin_xtr_plugins) + ', 0')
conf_data.set('plugins_crypto', '&rz_crypto_plugin_' + ', &rz_crypto_plugin_'.join(crypto_plugins) + ', 0')
conf_data.set('plugins_io', '&rz_io_plugin_' + ', &rz_io_plugin_'.join(io_plugins) + ', 0')
conf_data.set('plugins_debug', '&rz_debug_plugin_' + ', &rz_debug_plugin_'.join(debug_plugins) + ', 0')
conf_data.set('plugins_egg', '&rz_egg_plugin_' + ', &rz_egg_plugin_'.join(egg_plugins) + ', 0')
conf_data.set('plugins_lang', '&rz_lang_plugin_' + ', &rz_lang_plugin_'.join(lang_plugins) + ', 0')
conf_data.set('plugins_parse', '&rz_parse_plugin_' + ', &rz_parse_plugin_'.join(parse_plugins) + ', 0')
config_h = configure_file(
  input: 'librz/config.h.in',
  output: 'config.h',
  configuration: conf_data
)

# handle magic library
sys_magic = cc.find_library('magic', required: get_option('use_sys_magic'), static: is_static_build)

# handle xxhash library
r = run_command(py3_exe, check_meson_subproject_py, 'xxhash')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

sys_xxhash_opt = get_option('use_sys_xxhash')
if sys_xxhash_opt.enabled() or sys_xxhash_opt.auto()
  xxhash_dep = dependency('xxhash', required: false, static: is_static_build)
  if not xxhash_dep.found()
    xxhash_dep = cc.find_library('xxhash', required: sys_xxhash_opt, static: is_static_build)
  endif
endif
if sys_xxhash_opt.auto() or sys_xxhash_opt.disabled()
  xxhash_proj = subproject('xxhash', default_options: ['default_library=static'])
  xxhash_dep = xxhash_proj.get_variable('xxhash_dep')
endif

# handle openssl library
sys_openssl = dependency('openssl', required: get_option('use_sys_openssl'), static: is_static_build)

# handle libuv library
libuv_dep = disabler()
if get_option('use_libuv')
  r = run_command(py3_exe, check_meson_subproject_py, 'libuv')
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
r = run_command(py3_exe, check_meson_subproject_py, 'tree-sitter')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

tree_sitter_dep = dependency('tree-sitter', required: get_option('use_sys_tree_sitter'), static: is_static_build, fallback: [])
if not tree_sitter_dep.found()
  tree_sitter_proj = subproject('tree-sitter', default_options: ['default_library=static'])
  tree_sitter_dep = tree_sitter_proj.get_variable('tree_sitter_dep')
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
userconf.set('RZ_CHECKS_LEVEL', checks_level)
userconf.set10('IS_PORTABLE', get_option('portable'))
userconf.set10('HAVE_LIB_MAGIC', sys_magic.found())
userconf.set10('USE_LIB_MAGIC', sys_magic.found())
userconf.set10('HAVE_LIB_XXHASH', xxhash_dep.found())
userconf.set10('USE_LIB_XXHASH', xxhash_dep.found())
userconf.set10('DEBUGGER', has_debugger)
userconf.set('PREFIX', rizin_prefix)
userconf.set('LIBDIR', rizin_libdir)
userconf.set('INCLUDEDIR', rizin_incdir)
userconf.set('DATADIR_RZ', rizin_datdir_rz)
is_ppc = host_machine.cpu_family() == 'ppc' or host_machine.cpu_family() == 'ppc64'
userconf.set10('HAVE_JEMALLOC', host_machine.system() != 'windows' and (host_machine.system() != 'darwin' or not is_ppc))
userconf.set('DATADIR', rizin_datdir)
userconf.set('WWWROOT', rizin_wwwroot)
userconf.set('SDB', rizin_sdb)
userconf.set('ZIGNS', rizin_zigns)
userconf.set('THEMES', rizin_themes)
userconf.set('FORTUNES', rizin_fortunes)
userconf.set('FLAGS', rizin_flags)
userconf.set('HUD', rizin_hud)
userconf.set('PLUGINS', rizin_plugins)
userconf.set('EXTRAS', rizin_extras)
userconf.set('BINDINGS', rizin_bindings)
userconf.set10('HAVE_OPENSSL', sys_openssl.found())
userconf.set10('HAVE_LIBUV', libuv_dep.found())
userconf.set10('WANT_DYLINK', true)
userconf.set10('HAVE_PTRACE', have_ptrace)
userconf.set10('USE_PTRACE_WRAP', use_ptrace_wrap)
userconf.set10('WITH_GPL', true)
ok = cc.has_header_symbol('sys/personality.h', 'ADDR_NO_RANDOMIZE')
userconf.set10('HAVE_DECL_ADDR_NO_RANDOMIZE', ok)

if host_machine.system() == 'freebsd'
  add_project_link_arguments('-Wl,--unresolved-symbols,ignore-in-object-files', language: 'c')
endif

lrt = []
if not cc.has_function('clock_gettime', prefix: '#include <time.h>') and cc.has_header_symbol('features.h', '__GLIBC__')
  lrt = cc.find_library('rt', required: true, static: is_static_build)
endif

code = '#include <unistd.h>\nextern char **environ;\nint main() { char **env = environ; }'
have_environ = cc.links(code, name: 'have extern char **environ')
userconf.set10('HAVE_ENVIRON', have_environ)
message('HAVE_ENVIRON: @0@'.format(have_environ))

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
    ['fork', '#include <unistd.h>', []],
    ['pipe2', '#define _GNU_SOURCE\n#include <fcntl.h>\n#include <unistd.h>', []]
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

# Copy missing header
run_command(py3_exe, '-c', '__import__("shutil").copyfile("shlr/spp/config.def.h", "shlr/spp/config.h")')

pcconf = configuration_data()
pcconf.set('PREFIX', rizin_prefix)
pcconf.set('VERSION', rizin_version)
libr_pc = configure_file(
  input: 'librz/librz.pc.in',
  output: 'librz.pc',
  configuration: pcconf,
  install_dir: get_option('libdir') / 'pkgconfig'
)

# handle zlib dependency
r = run_command(py3_exe, check_meson_subproject_py, 'zlib')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

zlib_dep = dependency('zlib', required: get_option('use_sys_zlib'), static: is_static_build)
if not zlib_dep.found()
  zlib_proj = subproject('zlib', default_options: ['default_library=static'])
  zlib_dep = zlib_proj.get_variable('zlib_dep')
endif

r = run_command(py3_exe, check_meson_subproject_py, 'sdb')
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

spp_files = [
  'shlr/spp/spp.c'
]

spp_inc = [platform_inc, include_directories('shlr/spp')]

librzspp = static_library('rzspp', spp_files,
  dependencies: sdb_dep.partial_dependency(includes: true),
  include_directories: spp_inc,
  c_args: ['-DHAVE_R_UTIL', '-DUSE_R2=1'],
  implicit_include_directories: false
)

spp_dep = declare_dependency(
  link_whole: librzspp,
  include_directories: spp_inc
)

pkgcfg_sanitize_libs = ''
if get_option('b_sanitize').contains('address')
  pkgcfg_sanitize_libs += ' -lasan'
endif
if get_option('b_sanitize').contains('undefined')
  pkgcfg_sanitize_libs += ' -lubsan'
endif

use_rpath = false
if host_machine.system() != 'windows' and get_option('default_library') == 'shared'
  if get_option('local').enabled() or (get_option('local').auto() and get_option('prefix') != '/usr')
    use_rpath = true
  endif
endif

rpath_exe = ''
rpath_lib = ''
if use_rpath
  rpath_exe = '$ORIGIN/../' + get_option('libdir')
  rpath_lib = '$ORIGIN'
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
    build_root / 'librz' / 'core',
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

subdir('librz/util')
subdir('librz/socket')
subdir('librz/hash')
subdir('librz/crypto')
subdir('shlr')

subdir('librz/cons')
subdir('librz/diff')
subdir('shlr/gdb')
subdir('librz/io')
subdir('librz/bp')
subdir('librz/syscall')
subdir('librz/search')
subdir('librz/magic')
subdir('librz/flag')
subdir('librz/reg')
subdir('librz/bin')
subdir('librz/config')
subdir('librz/parse')
subdir('librz/lang')
subdir('librz/asm')
subdir('librz/type')
subdir('librz/analysis')
subdir('librz/egg')
subdir('librz/debug')
subdir('librz/core')

subdir('librz/analysis/d')
subdir('librz/asm/d')
subdir('librz/asm/cpus')
subdir('librz/asm/platforms')
subdir('librz/bin/d')
subdir('librz/syscall/d')
subdir('librz/reg/d')
subdir('librz/cons/d')
subdir('librz/magic/d')
subdir('librz/flag/d')
subdir('librz/main')

cli_option = get_option('cli')
if cli_option.auto()
  cli_enabled = not meson.is_subproject()
else
  cli_enabled = cli_option.enabled()
endif
if cli_enabled
  if get_option('blob')
    subdir('binrz/blob')
  else
    subdir('binrz/rz-hash')
    subdir('binrz/rz-run')
    subdir('binrz/rz-asm')
    subdir('binrz/rz-bin')
    subdir('binrz/rizin')
    subdir('binrz/rz-gg')
    subdir('binrz/rz-agent')
    subdir('binrz/rz-diff')
    subdir('binrz/rz-find')
    subdir('binrz/rz-sign')
    subdir('binrz/rz-ax')
  endif
  subdir('binrz/rz-pm')
  subdir('binrz/rz-test')
endif

if meson.is_subproject()
  librz_dep = declare_dependency(
    dependencies: [
      rz_analysis_dep,
      rz_asm_dep,
      rz_bin_dep,
      rz_bp_dep,
      rz_config_dep,
      rz_cons_dep,
      rz_core_dep,
      rz_main_dep,
      rz_crypto_dep,
      rz_debug_dep,
      rz_egg_dep,
      rz_flag_dep,
      rz_hash_dep,
      rz_io_dep,
      rz_lang_dep,
      rz_magic_dep,
      rz_parse_dep,
      rz_reg_dep,
      rz_search_dep,
      rz_socket_dep,
      rz_syscall_dep,
      rz_type_dep,
      rz_diff_dep,
      rz_util_dep
    ],
    include_directories: include_directories('.', 'librz/include'),
    version: rizin_version
  )
endif

if get_option('use_webui')
  install_subdir('shlr/www',
    install_dir: rizin_wwwroot,
    strip_directory: true
  )
endif

subdir('test/unit')
subdir('test/integration')

install_data(
  'doc/fortunes.fun',
  'doc/fortunes.tips',
  install_dir: rizin_fortunes
)

if cli_enabled
  install_man(
    'man/rz-agent.1',
    'man/rz-pm.1',
    'man/rz-bin.1',
    'man/rizin.1',
    'man/rz-diff.1',
    'man/rz-find.1',
    'man/rz-gg.1',
    'man/rz-hash.1',
    'man/rz-run.1',
    'man/rz-asm.1',
    'man/rz-ax.1',
    'man/rz-sign.1',
    'man/rz-esil.7',
  )

  install_data('doc/hud',
    install_dir: rizin_hud,
    rename: 'main'
  )
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
  'themes': rizin_themes,
  'fortunes': rizin_fortunes,
  'flags': rizin_flags,
  'hud': rizin_hud,
  'plugins': rizin_plugins,
  'extras': rizin_extras,
  'bindings': rizin_bindings,
}, section: 'Directories')

summary({
  'Debugger enabled': has_debugger,
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
  'Use RPATH': use_rpath,
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
}, section: 'Plugins', list_sep: ', ')
