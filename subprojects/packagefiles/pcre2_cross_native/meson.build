# Copy of PCRE2 library for the native version if a cross build happens.
# Because Meson currently doesn't support subprojects to be native and non-native:
# https://github.com/mesonbuild/meson/issues/10947

project('pcre2_cross_native', 'c', version: '10.44')

cc = meson.get_compiler('c')

conf_data = configuration_data()

pcre2_chartables = configure_file(input : 'src/pcre2_chartables.c.dist',
  output : 'pcre2_chartables.c',
  configuration : conf_data)

pcre2_h = configure_file(input : 'src/pcre2.h.generic',
  output : 'pcre2.h',
  configuration : conf_data)

config_h = configure_file(input : 'src/config.h.generic',
  output : 'config.h',
  configuration : conf_data)

libpcre2_c_args = [
  '-DHAVE_CONFIG_H', # Default values from config.h
  '-DPCRE2_CODE_UNIT_WIDTH=8',
  '-DHAVE_MEMMOVE',
  '-DSUPPORT_PCRE2_8',
  '-DSUPPORT_UNICODE',
  '-fvisibility=default',
]

pcre2_files = [
  'src/pcre2_auto_possess.c',
  pcre2_chartables,
  'src/pcre2_chkdint.c',
  'src/pcre2_compile.c',
  'src/pcre2_config.c',
  'src/pcre2_context.c',
  'src/pcre2_convert.c',
  'src/pcre2_dfa_match.c',
  'src/pcre2_error.c',
  'src/pcre2_extuni.c',
  'src/pcre2_find_bracket.c',
  'src/pcre2_maketables.c',
  'src/pcre2_match.c',
  'src/pcre2_match_data.c',
  'src/pcre2_newline.c',
  'src/pcre2_ord2utf.c',
  'src/pcre2_pattern_info.c',
  'src/pcre2_script_run.c',
  'src/pcre2_serialize.c',
  'src/pcre2_string_utils.c',
  'src/pcre2_study.c',
  'src/pcre2_substitute.c',
  'src/pcre2_substring.c',
  'src/pcre2_tables.c',
  'src/pcre2_ucd.c',
  'src/pcre2_valid_utf.c',
  'src/pcre2_xclass.c',
]

cpu_jit_supported = [ 'aarch64', 'arm', 'mips', 'mips64', 'ppc', 'ppc64', 'riscv32', 'riscv64', 's390x', 'x86', 'x86_64' ]

# tcc doesn't support the MSVC asm syntax PCRE2 uses (`__asm { ... }`).
# Darwin kernel not as well, because of forbidden wx memory.
# It is used in the JIT compiler code.
if cc.get_id() != 'tcc' and target_machine.cpu_family() in cpu_jit_supported and target_machine.system() != 'darwin'
  libpcre2_c_args += ['-DSUPPORT_JIT']
  pcre2_files += ['src/pcre2_jit_compile.c']
endif

if target_machine.system() == 'openbsd'
  # jit compilation fails with "no more memory" if wx allocations are allowed.
  libpcre2_c_args += ['-DSLJIT_WX_EXECUTABLE_ALLOCATOR']
elif target_machine.system() == 'netbsd'
  # jit compilation fails with "no more memory" if wx allocations are allowed.
  libpcre2_c_args += ['-DSLJIT_PROT_EXECUTABLE_ALLOCATOR']
endif

pcre2_includes = [
  include_directories('.'),
  include_directories('src/'),
]

libpcre2_cross_native = static_library('pcre2_cross_native', pcre2_files,
  c_args: libpcre2_c_args,
  include_directories: pcre2_includes,
  install: false,
  native: true,
)

pcre2_cross_native_dep = declare_dependency(
  link_with: libpcre2_cross_native,
  include_directories: pcre2_includes,
)
