project('libzip', 'c',
  version: '1.9.2',
  license: 'BSD-3-clause',
  meson_version: '>=0.55.0',
  default_options: [
    'c_std=c99',
  ]
)

py3_exe = import('python').find_installation()
cc = meson.get_compiler('c')
is_static_build = get_option('static_runtime')

# Create config.h file
conf_data = configuration_data()
zlib_dep = dependency('zlib', required: get_option('use_sys_zlib'), static: is_static_build)
if not zlib_dep.found()
  zlib_proj = subproject('zlib', default_options: ['default_library=static'])
  zlib_dep = zlib_proj.get_variable('zlib_dep')
endif
libzip_deps = [zlib_dep]

bzip2_dep = disabler()
lzma_dep = disabler()
have_crypto = false
openssl_dep = disabler()
if host_machine.system() == 'windows'
  conf_data.set10('HAVE_CRYPTO', true)
  conf_data.set10('HAVE_WINDOWS_CRYPTO', true)
  have_crypto = true
  libzip_deps += []
else
  bzip2_dep = dependency('bzip2', required: false, static: is_static_build)
  if bzip2_dep.found()
    conf_data.set10('HAVE_LIBBZ2', true)
    libzip_deps += [bzip2_dep]
  endif
  lzma_dep = dependency('liblzma', required: false, static: is_static_build)
  if not lzma_dep.found()
    lzma_dep = cc.find_library('lzma', required: false, static: is_static_build)
  endif
  if lzma_dep.found()
    conf_data.set10('HAVE_LIBLZMA', true)
    libzip_deps += [lzma_dep]
  endif
  if get_option('use_sys_openssl')
    openssl_dep = dependency('openssl', required: false, static: is_static_build)
    if openssl_dep.found()
      conf_data.set10('HAVE_OPENSSL', true)
      conf_data.set10('HAVE_CRYPTO', true)
      have_crypto = true
      libzip_deps += [openssl_dep]
    endif
  endif
endif

underscore_functions = ['close', 'dup', 'fdopen', 'fileno', 'setmode', 'snprintf', 'strdup', 'stricmp', 'strtoi64', 'strtoui64', 'umask', 'unlink']
functions = ['clonefile', 'explicit_bzero', 'explicit_memset', 'fileno', 'fseeko', 'ftello', 'getprogname', 'localtime_r', 'mkstemp', 'setmode', 'snprintf', 'strdup', 'stricmp', 'strtoll', 'strtoull']
headers = ['stdbool.h', 'strings.h', 'unistd.h', 'dirent.h', 'fts.h', 'ndir.h', 'sys/dir.h', 'sys/ndir.h', 'sys/attr.h']
types = ['off_t', 'size_t']
# special case because clang-cl finds strcasecmp but has problem while linking
if cc.get_id() != 'clang-cl' and cc.has_function('strcasecmp')
  conf_data.set10('HAVE_STRCASECMP', true)
  have_strcasecmp = true
endif
# both arc4random_buf and arc4random are needed if any
if cc.has_function('arc4random_buf') and cc.has_function('arc4random')
  conf_data.set10('HAVE_ARC4RANDOM', true)
  have_arc4random = true
endif
foreach fcn : functions
  if cc.has_function(fcn) or cc.has_function(fcn, prefix: '#include <stdio.h>')
    conf_data.set10('HAVE_@0@'.format(fcn.to_upper()), true)
    set_variable('have_@0@'.format(fcn.to_lower()), true)
  endif
endforeach
foreach fcn : underscore_functions
  if (cc.has_function('_' + fcn) or cc.has_function('_' + fcn, prefix: '#include <stdio.h>')) and not get_variable('have_@0@'.format(fcn.to_lower()), false)
    conf_data.set10('HAVE__@0@'.format(fcn.to_upper()), true)
  endif
endforeach
foreach hdr : headers
  if cc.has_header(hdr)
    conf_data.set10('HAVE_@0@'.format(hdr.underscorify().to_upper()), true)
  endif
endforeach
foreach type : types
  sz = cc.sizeof(type)
  if sz == -1
    # Windows requires the header to find off_t
    sz = cc.sizeof(type, prefix: '#include <sys/types.h>')
  endif
  conf_data.set('SIZEOF_@0@'.format(type.underscorify().to_upper()), sz)
endforeach

ok = cc.compiles('''#include <sys/ioctl.h>
#include <linux/fs.h>
int main(int argc, char *argv[]) { unsigned long x = FICLONERANGE; }''')
if ok
  conf_data.set10('HAVE_FICLONERANGE', ok)
endif

have_nullable = cc.compiles('''
int foo(char * _Nullable bar);
int main(int argc, char *argv[]) { }''')
if have_nullable
  conf_data.set10('HAVE_NULLABLE', have_nullable)
endif

is_big_endian = host_machine.endian() == 'big'
if is_big_endian
  conf_data.set10('WORDS_BIGENDIAN', is_big_endian)
endif
if get_option('default_library') == 'shared'
  conf_data.set10('HAVE_SHARED', true)
endif
conf_data.set('CMAKE_PROJECT_NAME', 'libzip')
conf_data.set('CMAKE_PROJECT_VERSION', meson.project_version())

config_h = configure_file(
  input: 'cmake-config.h.in',
  output: 'config.h',
  configuration: conf_data,
)

# Create zipconf.h file
version_split = meson.project_version().split('.')
version_major = version_split[0].to_int()
version_minor = version_split[1].to_int()
version_patch = version_split[2].split('-')[0].to_int()

zipconf_data = configuration_data()
zipconf_data.set('libzip_VERSION', meson.project_version())
zipconf_data.set('libzip_VERSION_MAJOR', version_major)
zipconf_data.set('libzip_VERSION_MINOR', version_minor)
zipconf_data.set('libzip_VERSION_PATCH', version_patch)
if cc.has_header('limits.h')
  zipconf_data.set10('HAVE_LIMITS_H', true)
endif
if get_option('default_library') == 'static'
  zipconf_data.set10('ZIP_STATIC', true)
endif
if have_nullable
  zipconf_data.set('ZIP_NULLABLE_DEFINES', '')
else
  zipconf_data.set('ZIP_NULLABLE_DEFINES', '''#define _Nullable
#define _Nonnull''')
endif
if cc.has_header('inttypes.h')
  types_header_prefix = '''#if !defined(__STDC_FORMAT_MACROS)
#define __STDC_FORMAT_MACROS 1
#endif
#include <inttypes.h>'''
  zipconf_data.set('LIBZIP_TYPES_INCLUDE', types_header_prefix)
elif cc.has_header('stdint.h')
  types_header_prefix = '#include <stdint.h>'
  zipconf_data.set('LIBZIP_TYPES_INCLUDE', types_header_prefix)
elif cc.has_header('sys/types.h')
  types_header_prefix = '#include <sys/types.h>'
  zipconf_data.set('LIBZIP_TYPES_INCLUDE', types_header_prefix)
endif

types = ['int8_t', 'uint8_t', 'int16_t', 'uint16_t', 'int32_t', 'uint32_t', 'int64_t', 'uint64_t']
underscore_types = ['__int8', '__int16', '__int32', '__int64']
foreach t : types + underscore_types
  set_variable('have_@0@'.format(t), cc.has_type(t, prefix: types_header_prefix))
endforeach

if have_int8_t
  zipconf_data.set('ZIP_INT8_T', 'int8_t')
elif have___int8
  zipconf_data.set('ZIP_INT8_T', '__int8')
else
  zipconf_data.set('ZIP_INT8_T', 'signed char')
endif
if have_uint8_t
  zipconf_data.set('ZIP_UINT8_T', 'uint8_t')
elif have___int8
  zipconf_data.set('ZIP_UINT8_T', 'unsigned __int8')
else
  zipconf_data.set('ZIP_UINT8_T', 'unsigned char')
endif
if have_int16_t
  zipconf_data.set('ZIP_INT16_T', 'int16_t')
elif have___int16
  zipconf_data.set('ZIP_INT16_T', '__int16')
else
  zipconf_data.set('ZIP_INT16_T', 'short')
endif
if have_uint16_t
  zipconf_data.set('ZIP_UINT16_T', 'uint16_t')
elif have___int16
  zipconf_data.set('ZIP_UINT16_T', 'unsigned __int16')
else
  zipconf_data.set('ZIP_UINT16_T', 'unsigned short')
endif
if have_int32_t
  zipconf_data.set('ZIP_INT32_T', 'int32_t')
elif have___int32
  zipconf_data.set('ZIP_INT32_T', '__int32')
else
  zipconf_data.set('ZIP_INT32_T', 'long')
endif
if have_uint32_t
  zipconf_data.set('ZIP_UINT32_T', 'uint32_t')
elif have___int32
  zipconf_data.set('ZIP_UINT32_T', 'unsigned __int32')
else
  zipconf_data.set('ZIP_UINT32_T', 'unsigned long')
endif
if have_int64_t
  zipconf_data.set('ZIP_INT64_T', 'int64_t')
elif have___int64
  zipconf_data.set('ZIP_INT64_T', '__int64')
else
  zipconf_data.set('ZIP_INT64_T', 'long long')
endif
if have_uint64_t
  zipconf_data.set('ZIP_UINT64_T', 'uint64_t')
elif have___int64
  zipconf_data.set('ZIP_UINT64_T', 'unsigned __int64')
else
  zipconf_data.set('ZIP_UINT64_T', 'unsigned long long')
endif

zipconf_h = configure_file(
  input: 'cmake-zipconf.h.in',
  output: 'zipconf.h',
  configuration: zipconf_data,
)


# Create zip_err_str.c file

zip_h = files('lib/zip.h')
zipint_h = files('lib/zipint.h')
create_zip_err_str_py = files('./create_zip_err_str.py')
zip_err_str_c = custom_target('zip_err_str',
  build_by_default: true,
  output: 'zip_err_str.c',
  input: [zip_h, zipint_h],
  command: [
    py3_exe,
    create_zip_err_str_py,
    '@OUTPUT@',
    '@INPUT@',
  ],
  install: false,
)

# Build libzip library

zip_files = [
  'lib/zip_add.c',
  'lib/zip_add_dir.c',
  'lib/zip_add_entry.c',
  'lib/zip_algorithm_deflate.c',
  'lib/zip_buffer.c',
  'lib/zip_close.c',
  'lib/zip_delete.c',
  'lib/zip_dir_add.c',
  'lib/zip_dirent.c',
  'lib/zip_discard.c',
  'lib/zip_entry.c',
  'lib/zip_error.c',
  'lib/zip_error_clear.c',
  'lib/zip_error_get.c',
  'lib/zip_error_get_sys_type.c',
  'lib/zip_error_strerror.c',
  'lib/zip_error_to_str.c',
  'lib/zip_extra_field.c',
  'lib/zip_extra_field_api.c',
  'lib/zip_fclose.c',
  'lib/zip_fdopen.c',
  'lib/zip_file_add.c',
  'lib/zip_file_error_clear.c',
  'lib/zip_file_error_get.c',
  'lib/zip_file_get_comment.c',
  'lib/zip_file_get_external_attributes.c',
  'lib/zip_file_get_offset.c',
  'lib/zip_file_rename.c',
  'lib/zip_file_replace.c',
  'lib/zip_file_set_comment.c',
  'lib/zip_file_set_encryption.c',
  'lib/zip_file_set_external_attributes.c',
  'lib/zip_file_set_mtime.c',
  'lib/zip_file_strerror.c',
  'lib/zip_fopen.c',
  'lib/zip_fopen_encrypted.c',
  'lib/zip_fopen_index.c',
  'lib/zip_fopen_index_encrypted.c',
  'lib/zip_fread.c',
  'lib/zip_fseek.c',
  'lib/zip_ftell.c',
  'lib/zip_get_archive_comment.c',
  'lib/zip_get_archive_flag.c',
  'lib/zip_get_encryption_implementation.c',
  'lib/zip_get_file_comment.c',
  'lib/zip_get_name.c',
  'lib/zip_get_num_entries.c',
  'lib/zip_get_num_files.c',
  'lib/zip_hash.c',
  'lib/zip_io_util.c',
  'lib/zip_libzip_version.c',
  'lib/zip_memdup.c',
  'lib/zip_name_locate.c',
  'lib/zip_new.c',
  'lib/zip_open.c',
  'lib/zip_pkware.c',
  'lib/zip_progress.c',
  'lib/zip_rename.c',
  'lib/zip_replace.c',
  'lib/zip_set_archive_comment.c',
  'lib/zip_set_archive_flag.c',
  'lib/zip_set_default_password.c',
  'lib/zip_set_file_comment.c',
  'lib/zip_set_file_compression.c',
  'lib/zip_set_name.c',
  'lib/zip_source_accept_empty.c',
  'lib/zip_source_begin_write.c',
  'lib/zip_source_begin_write_cloning.c',
  'lib/zip_source_buffer.c',
  'lib/zip_source_call.c',
  'lib/zip_source_close.c',
  'lib/zip_source_commit_write.c',
  'lib/zip_source_compress.c',
  'lib/zip_source_crc.c',
  'lib/zip_source_error.c',
  'lib/zip_source_file_common.c',
  'lib/zip_source_file_stdio.c',
  'lib/zip_source_free.c',
  'lib/zip_source_function.c',
  'lib/zip_source_get_file_attributes.c',
  'lib/zip_source_is_deleted.c',
  'lib/zip_source_layered.c',
  'lib/zip_source_open.c',
  'lib/zip_source_pkware_decode.c',
  'lib/zip_source_pkware_encode.c',
  'lib/zip_source_read.c',
  'lib/zip_source_remove.c',
  'lib/zip_source_rollback_write.c',
  'lib/zip_source_seek.c',
  'lib/zip_source_seek_write.c',
  'lib/zip_source_stat.c',
  'lib/zip_source_supports.c',
  'lib/zip_source_tell.c',
  'lib/zip_source_tell_write.c',
  'lib/zip_source_window.c',
  'lib/zip_source_write.c',
  'lib/zip_source_zip.c',
  'lib/zip_source_zip_new.c',
  'lib/zip_stat.c',
  'lib/zip_stat_index.c',
  'lib/zip_stat_init.c',
  'lib/zip_strerror.c',
  'lib/zip_string.c',
  'lib/zip_unchange.c',
  'lib/zip_unchange_all.c',
  'lib/zip_unchange_archive.c',
  'lib/zip_unchange_data.c',
  'lib/zip_utf-8.c',
]

if host_machine.system() == 'windows'
  zip_files += [
    'lib/zip_source_file_win32.c',
    'lib/zip_source_file_win32_named.c',
    'lib/zip_source_file_win32_utf16.c',
    'lib/zip_source_file_win32_utf8.c',
    'lib/zip_source_file_win32_ansi.c',
    'lib/zip_random_win32.c',
  ]
  libzip_deps += [cc.find_library('advapi32')]
else
  zip_files += [
    'lib/zip_source_file_stdio_named.c',
    'lib/zip_random_unix.c'
  ]
endif

if bzip2_dep.found()
  zip_files += ['lib/zip_algorithm_bzip2.c']
endif
if lzma_dep.found()
  zip_files += ['lib/zip_algorithm_xz.c']
endif
if openssl_dep.found()
  zip_files += ['lib/zip_crypto_openssl.c']
endif
if host_machine.system() == 'windows' and have_crypto
  zip_files += ['lib/zip_crypto_win.c']
  libzip_deps += [cc.find_library('bcrypt')]
endif
if have_crypto
  zip_files += ['lib/zip_winzip_aes.c', 'lib/zip_source_winzip_aes_decode.c', 'lib/zip_source_winzip_aes_encode.c']
endif

zip_files += [zip_err_str_c]

zip_inc = [include_directories('lib', '.')]

libzip = library('libzip', zip_files,
  dependencies: libzip_deps,
  include_directories: zip_inc,
  implicit_include_directories: true,
  install: false,
)

libzip_dep = declare_dependency(
  link_with: libzip,
  include_directories: zip_inc,
  dependencies: libzip_deps,
)
