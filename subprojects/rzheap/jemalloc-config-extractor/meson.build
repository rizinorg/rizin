project('jemalloc-config-extractor', 'c')

jemalloc_dir = get_option('jemalloc')
jemalloc_version_opt = get_option('jemalloc_version')
fs = import('fs')

if jemalloc_dir == ''
  error('jemalloc option is required. Use -Djemalloc=/path/to/jemalloc')
endif
if not fs.is_dir(jemalloc_dir)
  error('jemalloc path does not exist: ' + jemalloc_dir)
endif

jemalloc_header = join_paths(jemalloc_dir, 'include', 'jemalloc', 'jemalloc.h')
if not fs.is_file(jemalloc_header)
  error('jemalloc.h not found at: ' + jemalloc_header)
endif

jemalloc_include = include_directories(join_paths(jemalloc_dir, 'include'))
common_c_args = [
  '-D_GNU_SOURCE',
  '-D_REENTRANT',
  '-O0',
  '-g',
  '-Wall',
]
threads = dependency('threads')

jemalloc_version = ''
if jemalloc_version_opt != 'auto'
  jemalloc_version = jemalloc_version_opt
else
  jemalloc_version_raw = run_command(
    'sh',
    '-c',
    'cd "' + jemalloc_dir + '" 2>/dev/null && git describe --tags 2>/dev/null || true',
    check: false,
  ).stdout().strip()
  if jemalloc_version_raw != ''
    if jemalloc_version_raw.startswith('4.')
      jemalloc_version = '450'
    elif jemalloc_version_raw.startswith('5.')
      jemalloc_version = '530'
    endif
  endif
  if jemalloc_version == ''
    jemalloc_version_header = run_command(
      'sh',
      '-c',
      'sed -n "s/^#define JEMALLOC_VERSION \\\"\\([0-9][^\\\"]*\\)\\\"/\\1/p" "' +
        jemalloc_header +
        '" 2>/dev/null | head -n1',
      check: false,
    ).stdout().strip()
    if jemalloc_version_header != ''
      if jemalloc_version_header.startswith('4.5.')
        jemalloc_version = '450'
      elif jemalloc_version_header.startswith('5.3.')
        jemalloc_version = '530'
      elif jemalloc_version_header.startswith('4.')
        jemalloc_version = '450'
      elif jemalloc_version_header.startswith('5.')
        jemalloc_version = '530'
      endif
    endif
  endif
endif

if jemalloc_version == ''
  jemalloc_version = '530'
endif

if jemalloc_version == '450'
  message('Detected jemalloc version 450')
  executable(
    'extract_config_450',
    'extract_config_450.c',
    include_directories: jemalloc_include,
    c_args: common_c_args,
    dependencies: threads,
  )
elif jemalloc_version == '530'
  message('Detected jemalloc version 530')
  executable(
    'extract_config_530',
    'extract_config_530.c',
    include_directories: jemalloc_include,
    c_args: common_c_args,
    dependencies: threads,
  )
else
  message('Unknown jemalloc version: ' + jemalloc_version + '. Defaulting to 530')
  executable(
    'extract_config_530',
    'extract_config_530.c',
    include_directories: jemalloc_include,
    c_args: common_c_args,
    dependencies: threads,
  )
endif
