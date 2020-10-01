project('rizin', 'c', license: 'LGPL3', meson_version: '>=0.50.1')

py3_exe = import('python').find_installation('python3')
git_exe = find_program('git', required: false)
pkgconfig_mod = import('pkgconfig')

# Get r2 version
r2_version = 'unknown-error'
r2_version_major = 0
r2_version_minor = 0
r2_version_patch = 0
r2_version_number = 0
r = run_command(py3_exe, 'sys/version.py', '--full-version')
if r.returncode() == 0
  vers = r.stdout().strip().split('\n')
  r2_version = vers[0]
  r2_version_major = vers[1]
  r2_version_minor = vers[2]
  r2_version_patch = vers[3]
  r2_version_number = vers[4]
  if host_machine.system() == 'darwin'
    r2_version = r2_version.split('-')[0]
  endif
else
  message('Cannot find project version with sys/version.py')
endif

repo = '.'
if meson.is_subproject()
  repo = meson.current_source_dir()
  if host_machine.system() == 'windows'
    py_cmd = 'print(__import__("os").readlink(r"@0@"))'.format(repo)
    py_cmd = run_command(py3_exe, '-c', py_cmd)
    if py_cmd.returncode() == 0
      repo = py_cmd.stdout().strip()
      message('r2 real path: ' + repo)
    endif
  endif
endif

# by default, not version commit is used
version_commit = '0'

gittap = ''
gittip = 'unknown'

if git_exe.found()
  # Get version_commit
  git_rev_list = run_command(git_exe, '-C', repo, 'rev-list', '--all', '--count')
  if git_rev_list.returncode() == 0
    version_commit = git_rev_list.stdout().strip()
  endif

  # Get gittap
  git_describe = run_command(git_exe, '-C', repo, 'describe', '--tags', '--match', '[0-9]*')
  if git_describe.returncode() == 0
    gittap = git_describe.stdout().strip()
  endif

  # Get gittip
  git_rev_parse = run_command(git_exe, '-C', repo, 'rev-parse', 'HEAD')
  if git_rev_parse.returncode() == 0
    gittip = git_rev_parse.stdout().strip()
  endif
endif

if get_option('r2_version_commit') != ''
  version_commit = get_option('r2_version_commit')
endif

if get_option('r2_gittap') != ''
  gittap = get_option('r2_gittap')
endif
# gittap is used for the version of each rz_ library
# in case it has not been set (e.g. a release tarball) set it
if gittap == ''
  gittap = r2_version
endif

if get_option('r2_gittip') != ''
  gittip = get_option('r2_gittip')
endif

# Get current date
if host_machine.system() == 'windows'
  r2birth = run_command('cmd', '/c', 'echo %date%__%time%')
else
  r2birth = run_command('date', '+%Y-%m-%d__%H:%M:%S')
endif
if r2birth.returncode() != 0
  r2birth = ''
else
  r2birth = r2birth.stdout().strip()
endif

r2_libversion = host_machine.system() == 'windows' ? '' : r2_version
message('r2 lib version: ' + r2_libversion)

# system dependencies
cc = meson.get_compiler('c')
# required for linux
ldl = cc.find_library('dl', required: false)
pth = dependency('threads', required: false)
utl = cc.find_library('util', required: false)
if host_machine.system() == 'sunos'
  # workaround for Solaris until https://github.com/mesonbuild/meson/issues/4328 is fixed
  mth = declare_dependency(link_args: '-lm')
else
  mth = cc.find_library('m', required: false)
endif

platform_deps = []
platform_inc = ['.', 'librz/include']
if host_machine.system() == 'windows'
  platform_deps = [cc.find_library('ws2_32'), cc.find_library('wininet'), cc.find_library('psapi')]
endif
platform_inc = include_directories(platform_inc)

if get_option('static_runtime')
  if cc.get_id() == 'msvc'
    add_project_arguments('/MT', language: 'c')
  endif
endif

if cc.get_id() == 'clang-cl'
  add_project_arguments('-D__STDC__=1', language: 'c')
  add_project_arguments('-D_CRT_DECLARE_NONSTDC_NAMES ', language: 'c')
  add_project_arguments('-D_CRT_SECURE_NO_WARNINGS', language: 'c')
  add_project_arguments('-D_CRT_NONSTDC_NO_DEPRECATE', language: 'c')
endif

if get_option('default_library') == 'shared'
  if host_machine.system() != 'windows' or cc.get_id()!='msvc' and cc.get_id()!='clang-cl'
    add_project_arguments('-fvisibility=hidden', language: 'c')
  endif
endif

library_cflags = ['-DR2_PLUGIN_INCORE=1']

if host_machine.system() == 'windows'
  r2_prefix = '.'
  r2_libdir = 'lib'
  r2_incdir = join_paths('include', 'librz')
  r2_datdir = 'share'

  opts1 = [
    'r2_libdir',
    'r2_incdir',
    'r2_datdir'
  ]
  foreach opt : opts1
    val = get_option(opt)
    if val != ''
      set_variable(opt, val)
    endif
  endforeach

  r2_wwwroot = join_paths(r2_datdir, 'www')
  r2_sdb = join_paths(r2_datdir)
  r2_zigns = join_paths(r2_datdir, 'zigns')
  r2_themes = join_paths(r2_datdir, 'cons')
  r2_fortunes = join_paths(r2_datdir, 'doc')
  r2_flags = join_paths(r2_datdir, 'flag')
  r2_hud = join_paths(r2_datdir, 'hud')

  opts2 = [
    'r2_wwwroot',
    'r2_sdb',
    'r2_zigns',
    'r2_themes',
    'r2_fortunes',
    'r2_flags',
    'r2_hud'
  ]
  foreach opt : opts2
    val = get_option(opt)
    if val != ''
      set_variable(opt, val)
    endif
  endforeach

  opts3 = [
    'r2_plugins',
    'r2_extras',
    'r2_bindings'
  ]
  r2_plugins = join_paths(r2_libdir, 'plugins')
  r2_extras = join_paths(r2_libdir, 'extras')
  r2_bindings = join_paths(r2_libdir, 'bindings')

  foreach opt : opts1 + opts2 + opts3
    val = get_variable(opt)
    val = '\\\\'.join(val.split('/'))
    set_variable(opt, val)
  endforeach
else
  r2_prefix = get_option('prefix')
  r2_libdir = get_option('libdir')
  r2_incdir = join_paths(get_option('includedir'), 'librz')
  r2_datdir = get_option('datadir')
  r2_datdir_rz = join_paths(r2_datdir, 'rizin')
  r2_wwwroot = join_paths(r2_datdir_rz, r2_version, 'www')
  r2_sdb = join_paths(r2_datdir_rz, r2_version)
  r2_zigns = join_paths(r2_datdir_rz, r2_version, 'zigns')
  r2_themes = join_paths(r2_datdir_rz, r2_version, 'cons')
  r2_fortunes = join_paths(r2_datdir, 'doc', 'rizin')
  r2_flags = join_paths(r2_datdir_rz, r2_version, 'flag')
  r2_hud = join_paths(r2_datdir_rz, r2_version, 'hud')
  r2_plugins = join_paths(r2_libdir, 'rizin', r2_version)
  r2_extras = join_paths(r2_libdir, 'rizin-extras', r2_version)
  r2_bindings = join_paths(r2_libdir, 'rizin-bindings', r2_version)
endif

r2_zsh_compdir = join_paths(r2_datdir, 'zsh', 'site-functions')

# load plugin configuration
subdir('librz')

conf_data = configuration_data()
conf_data.set('plugins_core', '&rz_core_plugin_' + ', &rz_core_plugin_'.join(core_plugins) + ', 0')
conf_data.set('plugins_anal', '&rz_anal_plugin_' + ', &rz_anal_plugin_'.join(anal_plugins) + ', 0')
conf_data.set('plugins_asm', '&rz_asm_plugin_' + ', &rz_asm_plugin_'.join(asm_plugins) + ', 0')
conf_data.set('plugins_bp', '&rz_bp_plugin_' + ', &rz_bp_plugin_'.join(bp_plugins) + ', 0')
conf_data.set('plugins_bin', '&rz_bin_plugin_' + ', &rz_bin_plugin_'.join(bin_plugins) + ', 0')
conf_data.set('plugins_bin_ldr', '&rz_bin_ldr_plugin_' + ', &rz_bin_ldr_plugin_'.join(bin_ldr_plugins) + ', 0')
conf_data.set('plugins_bin_xtr', '&rz_bin_xtr_plugin_' + ', &rz_bin_xtr_plugin_'.join(bin_xtr_plugins) + ', 0')
conf_data.set('plugins_crypto', '&rz_crypto_plugin_' + ', &rz_crypto_plugin_'.join(crypto_plugins) + ', 0')
conf_data.set('plugins_io', '&rz_io_plugin_' + ', &rz_io_plugin_'.join(io_plugins) + ', 0')
conf_data.set('plugins_fs', '&rz_fs_plugin_' + ', &rz_fs_plugin_'.join(fs_plugins) + ', 0')
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
sys_magic = cc.find_library('magic', required: false)
use_syslib_magic = false

if sys_magic.found() and get_option('use_sys_magic')
  use_syslib_magic = true
endif

# handle xxhash library
sys_xxhash = dependency('xxhash', required: false)
use_sys_xxhash = false
if not sys_xxhash.found()
  sys_xxhash = cc.find_library('xxhash', required: false)
endif

if sys_xxhash.found() and get_option('use_sys_xxhash')
  message('Using system xxhash library')
  use_sys_xxhash = true
else
  message('Using bundled xxhash library')
endif

# handle openssl library
sys_openssl = dependency('openssl', required: false)
use_sys_openssl = false
if sys_openssl.found() and get_option('use_sys_openssl')
  message('Using system openssl library')
  use_sys_openssl = true
else
  message('Using bundled openssl code')
endif

# handle libuv library
if get_option('use_libuv')
  libuv_dep = dependency('libuv', version: '>=1.0.0', required: false)
  use_libuv = libuv_dep.found()
  if not libuv_dep.found()
    warning('use_libuv option was set to true, but libuv was not found.')
  endif
else
  use_libuv = false
endif

if use_libuv
  message('Using libuv')
else
  message('Not using libuv, thus using fallback server implementations')
endif

has_debugger = get_option('debugger')
have_ptrace = not ['windows', 'cygwin', 'sunos'].contains(host_machine.system())
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

message('R2_CHECKS_LEVEL: @0@'.format(checks_level))

userconf = configuration_data()
userconf.set('R_CHECKS_LEVEL', checks_level)
userconf.set10('HAVE_LIB_MAGIC', sys_magic.found())
userconf.set10('USE_LIB_MAGIC', use_syslib_magic)
userconf.set10('HAVE_LIB_XXHASH', sys_xxhash.found())
userconf.set10('USE_LIB_XXHASH', use_sys_xxhash)
userconf.set10('DEBUGGER', has_debugger)
userconf.set('PREFIX', r2_prefix)
if host_machine.system() == 'windows'
  userconf.set('LIBDIR', r2_libdir)
  userconf.set('INCLUDEDIR', r2_incdir)
  userconf.set('DATADIR_R2', r2_datdir)
  userconf.set10('HAVE_JEMALLOC', false)
else
  userconf.set('LIBDIR', join_paths(r2_prefix, r2_libdir))
  userconf.set('INCLUDEDIR', join_paths(r2_prefix, r2_incdir))
  userconf.set('DATADIR_R2', r2_datdir_rz)
  userconf.set10('HAVE_JEMALLOC', true)
endif
userconf.set('DATADIR', join_paths(r2_prefix, r2_datdir))
userconf.set('WWWROOT', join_paths(r2_prefix, r2_wwwroot))
userconf.set('SDB', r2_sdb)
userconf.set('ZIGNS', r2_zigns)
userconf.set('THEMES', r2_themes)
userconf.set('FORTUNES', r2_fortunes)
userconf.set('FLAGS', r2_flags)
userconf.set('HUD', r2_hud)
userconf.set('PLUGINS', r2_plugins)
userconf.set('EXTRAS', r2_extras)
userconf.set('BINDINGS', r2_bindings)
userconf.set10('HAVE_OPENSSL', use_sys_openssl)
userconf.set10('HAVE_LIBUV', use_libuv)
userconf.set10('HAVE_FORK', true)
userconf.set10('WANT_DYLINK', true)
userconf.set10('HAVE_PTRACE', have_ptrace)
userconf.set10('USE_PTRACE_WRAP', use_ptrace_wrap)
userconf.set10('WITH_GPL', true)
ok = cc.has_header_symbol('sys/personality.h', 'ADDR_NO_RANDOMIZE')
userconf.set10('HAVE_DECL_ADDR_NO_RANDOMIZE', ok)

lrt = []
if not cc.has_function('clock_gettime', prefix: '#include <time.h>') and cc.has_header_symbol('features.h', '__GLIBC__')
  lrt = cc.find_library('rt', required: true)
endif

foreach item : [
    ['arc4random_uniform', '#include <stdlib.h>', []],
    ['explicit_bzero', '#include <string.h>', []],
    ['explicit_memset', '#include <string.h>', []],
    ['clock_nanosleep', '#include <time.h>', []],
    ['clock_gettime', '#include <time.h>', [lrt]],
    ['sigaction', '#include <signal.h>', []]
  ]
  func = item[0]
  ok = cc.has_function(func, prefix: item[1], dependencies: item[2])
  userconf.set10('HAVE_@0@'.format(func.to_upper()), ok)
endforeach

rz_userconf_h = configure_file(
  input: 'librz/include/rz_userconf.h.acr',
  output: 'rz_userconf.h',
  configuration: userconf,
  install_dir: join_paths(r2_incdir)
)

versionconf = configuration_data()
versionconf.set('MESON_VERSION', meson.version())
versionconf.set('VERSIONCOMMIT', version_commit)
versionconf.set('R2_VERSION_MAJOR', r2_version_major)
versionconf.set('R2_VERSION_MINOR', r2_version_minor)
versionconf.set('R2_VERSION_PATCH', r2_version_patch)
versionconf.set('R2_VERSION_NUMBER', r2_version_number)
versionconf.set('R2_VERSION', r2_version)
versionconf.set('R2_GITTAP', gittap)
versionconf.set('R2_GITTIP', gittip)
versionconf.set('R2_BIRTH', r2birth)
rz_version_h = configure_file(
  input: 'librz/include/rz_version.h.in',
  output: 'rz_version.h',
  configuration: versionconf,
  install_dir: join_paths(r2_incdir)
)

# Copy missing header
run_command(py3_exe, '-c', '__import__("shutil").copyfile("shlr/spp/config.def.h", "shlr/spp/config.h")')

pcconf = configuration_data()
pcconf.set('PREFIX', get_option('prefix'))
pcconf.set('LIBDIR', join_paths(get_option('prefix'), get_option('libdir')))
pcconf.set('VERSION', r2_version)
libr_pc = configure_file(
  input: 'librz/librz.pc.acr',
  output: 'librz.pc',
  configuration: pcconf,
  install_dir: join_paths(get_option('libdir'), 'pkgconfig')
)

# handle zlib dependency
zlib_dep = dependency('zlib', required: false)
if not zlib_dep.found() or not get_option('use_sys_zlib')
  message('Use bundled zlib')

  zlib_files = [
    'shlr/zip/zlib/adler32.c',
    'shlr/zip/zlib/compress.c',
    'shlr/zip/zlib/crc32.c',
    'shlr/zip/zlib/deflate.c',
    'shlr/zip/zlib/gzclose.c',
    'shlr/zip/zlib/gzlib.c',
    'shlr/zip/zlib/gzread.c',
    'shlr/zip/zlib/gzwrite.c',
    'shlr/zip/zlib/infback.c',
    'shlr/zip/zlib/inffast.c',
    'shlr/zip/zlib/inflate.c',
    'shlr/zip/zlib/inftrees.c',
    'shlr/zip/zlib/trees.c',
    'shlr/zip/zlib/uncompr.c',
    'shlr/zip/zlib/zutil.c'
  ]

  zlib_inc = [platform_inc, include_directories('shlr/zip/zlib')]

  librzzlib = static_library('r2zlib', zlib_files,
    include_directories: zlib_inc,
    implicit_include_directories: false
  )

  zlib_dep = declare_dependency(
    link_with: librzzlib,
    include_directories: zlib_inc
  )
else
  message('Use system-provided zlib library')
endif


# handle sdb dependency
# NOTE: copying most of the stuff from sdb to here for the moment, since we
# should use subpackages to handle this well
sdb_files = [
  'shlr/sdb/src/array.c',
  'shlr/sdb/src/base64.c',
  'shlr/sdb/src/buffer.c',
  'shlr/sdb/src/set.c',
  'shlr/sdb/src/cdb.c',
  'shlr/sdb/src/cdb_make.c',
  'shlr/sdb/src/dict.c',
  'shlr/sdb/src/diff.c',
  'shlr/sdb/src/disk.c',
  'shlr/sdb/src/fmt.c',
  'shlr/sdb/src/ht_uu.c',
  'shlr/sdb/src/ht_up.c',
  'shlr/sdb/src/ht_pp.c',
  'shlr/sdb/src/journal.c',
  'shlr/sdb/src/json.c',
  'shlr/sdb/src/lock.c',
  'shlr/sdb/src/ls.c',
  'shlr/sdb/src/match.c',
  'shlr/sdb/src/ns.c',
  'shlr/sdb/src/num.c',
  'shlr/sdb/src/query.c',
  'shlr/sdb/src/sdb.c',
  'shlr/sdb/src/sdbht.c',
  'shlr/sdb/src/util.c'
]

sdb_inc = [platform_inc, include_directories('shlr/sdb/src')]

# Create sdb_version.h
r = run_command(py3_exe, 'sys/sdb_version.py', 'shlr/sdb/config.mk')
if r.returncode() == 0
  sdb_version = r.stdout().strip().split('\n')[0]
else
  sdb_version = 'unknown'
endif
run_command(py3_exe, '-c', 'with open("shlr/sdb/src/sdb_version.h", "w") as f: f.write("#define SDB_VERSION \"' + sdb_version + '\"")')

sdb_inc_files = [
  'shlr/sdb/src/buffer.h',
  'shlr/sdb/src/cdb.h',
  'shlr/sdb/src/set.h',
  'shlr/sdb/src/cdb_make.h',
  'shlr/sdb/src/config.h',
  'shlr/sdb/src/dict.h',
  'shlr/sdb/src/ht_inc.h',
  'shlr/sdb/src/ht_pp.h',
  'shlr/sdb/src/ht_up.h',
  'shlr/sdb/src/ht_uu.h',
  'shlr/sdb/src/ls.h',
  'shlr/sdb/src/sdb.h',
  'shlr/sdb/src/sdbht.h',
  'shlr/sdb/src/sdb_version.h',
  'shlr/sdb/src/types.h'
]
install_headers(sdb_inc_files, install_dir: join_paths(r2_incdir, 'sdb'))

librzsdb = static_library('r2sdb', sdb_files,
  include_directories: sdb_inc,
  implicit_include_directories: false,
  c_args: host_machine.system() == 'windows' ? '-DSDB_API=__declspec(dllexport)' : [],
)

sdb_dep = declare_dependency(
  link_whole: librzsdb,
  include_directories: sdb_inc
)

sdb_exe = executable('sdb', ['shlr/sdb/src/main.c'] + sdb_files,
  include_directories: [
    include_directories(['shlr/sdb/src'])
  ],
  implicit_include_directories: false,
  native: true,
)

sdb_gen_cmd = [
  sdb_exe,
  '@OUTPUT@',
  '==',
  '@INPUT@'
]

# handle spp dependency
spp_files = [
  'shlr/spp/spp.c'
]

spp_inc = [platform_inc, include_directories('shlr/spp')]

librzspp = static_library('r2spp', spp_files,
  dependencies: sdb_dep,
  include_directories: spp_inc,
  c_args: ['-DHAVE_R_UTIL', '-DUSE_R2=1'],
  implicit_include_directories: false
)

spp_dep = declare_dependency(
  link_with: librzspp,
  include_directories: spp_inc
)

pkgcfg_sanitize_libs = ''
if get_option('b_sanitize').contains('address')
  pkgcfg_sanitize_libs += ' -lasan'
endif
if get_option('b_sanitize').contains('undefined')
  pkgcfg_sanitize_libs += ' -lubsan'
endif

rpath_exe = ''
rpath_lib = ''
if get_option('local') and get_option('default_library') == 'shared'
  rpath_exe = '$ORIGIN/../' + get_option('libdir')
  rpath_lib = '$ORIGIN'
endif

subdir('librz/util')
subdir('librz/socket')
subdir('librz/hash')
subdir('librz/crypto')
subdir('shlr')

subdir('librz/cons')
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
subdir('librz/anal')
subdir('librz/egg')
subdir('librz/fs')
subdir('librz/debug')
subdir('librz/core')

subdir('librz/anal/d')
subdir('librz/asm/d')
subdir('librz/bin/d')
subdir('librz/syscall/d')
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
    subdir('binrz/rz_hash')
    subdir('binrz/rz_run')
    subdir('binrz/rz_asm')
    subdir('binrz/rz_bin')
    subdir('binrz/rizin')
    subdir('binrz/rz_gg')
    subdir('binrz/rz_agent')
    subdir('binrz/rz_diff')
    subdir('binrz/rz_find')
    subdir('binrz/rz_sign')
    subdir('binrz/rz_ax')
  endif
  subdir('binrz/rz_pm')
  subdir('binrz/rz_test')
endif

if meson.is_subproject()
  librz_dep = declare_dependency(
    dependencies: [
      rz_anal_dep,
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
      rz_fs_dep,
      rz_hash_dep,
      rz_io_dep,
      rz_lang_dep,
      rz_magic_dep,
      rz_parse_dep,
      rz_reg_dep,
      rz_search_dep,
      rz_socket_dep,
      rz_syscall_dep,
      rz_util_dep
    ],
    include_directories: include_directories('.', 'librz/include'),
    version: r2_version
  )
endif

if get_option('use_webui')
  install_subdir('shlr/www',
    install_dir: r2_wwwroot,
    strip_directory: true
  )
endif

subdir('test/unit')

install_data(
  'doc/fortunes.creepy',
  'doc/fortunes.fun',
  'doc/fortunes.nsfw',
  'doc/fortunes.tips',
  install_dir: r2_fortunes
)

if cli_enabled
  install_man(
    'man/rz_agent.1',
    'man/rz-docker.1',
    'man/rz_pm.1',
    'man/rz_bin.1',
    'man/rizin.1',
    'man/rz_diff.1',
    'man/rz_find.1',
    'man/rz_gg.1',
    'man/rz_hash.1',
    'man/rz_run.1',
    'man/rz_asm.1',
    'man/rz_ax.1',
    'man/esil.7'
  )

  install_data('doc/hud',
    install_dir: r2_hud,
    rename: 'main'
  )

  install_data(
    'doc/zsh/_rz',
    'doc/zsh/_rz_bin',
    'doc/zsh/_rz_diff',
    'doc/zsh/_rz_find',
    'doc/zsh/_rz_gg',
    'doc/zsh/_rz_hash',
    'doc/zsh/_rz_asm',
    'doc/zsh/_rz_ax',
    install_dir: r2_zsh_compdir
  )

  meson.add_install_script(host_machine.system() == 'windows' ? 'sys/create_rz.bat' : 'sys/create_rz.sh')
endif
