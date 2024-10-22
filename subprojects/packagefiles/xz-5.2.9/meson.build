# liblzma is what upstream uses for their pkg-config name
project('liblzma', 'c',
  version : '5.4.3',
  license : ['PD', 'LGPL2', 'GPL2', 'GPL3'],
  meson_version: '>=0.55.0',
)

cc = meson.get_compiler('c')

if cc.has_argument('--std=gnu99')
  add_project_arguments('--std=gnu99', language: ['c'])
elif cc.has_argument('--std=c99')
  add_project_arguments('--std=c99', language: ['c'])
endif

lzma_cflags = ['-DHAVE_CONFIG_H', '-DTUKLIB_SYMBOL_PREFIX=lzma_', '-DLZMA_API_STATIC']

cdata = configuration_data()

check_headers = [
  'byteswap.h',
  'CommonCrypto/CommonDigest.h',
  'dlfcn.h',
  'fcntl.h',
  'getopt.h',
  'inttypes.h',
  'limits.h',
  'memory.h',
  'minix/sha2.h',
  'sha256.h',
  'sha2.h',
  'stdbool.h',
  'stdint.h',
  'stdlib.h',
  'string.h',
  'strings.h',
  'sys/byteorder.h',
  'sys/endian.h',
  'sys/param.h',
  'sys/stat.h',
  'sys/time.h',
  'sys/types.h',
  'unistd.h',
]

# non x86 architectures would fail to compile if this is included, because it
# includes x86 specific code
if host_machine.cpu_family().startswith('x86')
  check_headers += ['immintrin.h']
endif

check_coders = [['decoder_arm', 'HAVE_DECODER_ARM'],
  ['decoder_armthumb', 'HAVE_DECODER_ARMTHUMB'],
  ['decoder_delta', 'HAVE_DECODER_DELTA'],
  ['decoder_ia64', 'HAVE_DECODER_IA64'],
  ['decoder_lzma1', 'HAVE_DECODER_LZMA1'],
  ['decoder_lzma2', 'HAVE_DECODER_LZMA2'],
  ['decoder_powerpc', 'HAVE_DECODER_POWERPC'],
  ['decoder_sparc', 'HAVE_DECODER_SPARC'],
  ['decoder_x86', 'HAVE_DECODER_X86'],
  ['encoder_arm', 'HAVE_ENCODER_ARM'],
  ['encoder_armthumb', 'HAVE_ENCODER_ARMTHUMB'],
  ['encoder_delta', 'HAVE_ENCODER_DELTA'],
  ['encoder_ia64', 'HAVE_ENCODER_IA64'],
  ['encoder_lzma1', 'HAVE_ENCODER_LZMA1'],
  ['encoder_lzma2', 'HAVE_ENCODER_LZMA2'],
  ['encoder_powerpc', 'HAVE_ENCODER_POWERPC'],
  ['encoder_sparc', 'HAVE_ENCODER_SPARC'],
  ['encoder_x86', 'HAVE_ENCODER_X86']
]

check_members = [
  ['struct stat', 'st_atim.tv_nsec', '#include <sys/stat.h>'],
  ['struct stat', 'st_atimespec.tv_nsec', '#include <sys/stat.h>'],
  ['struct stat', 'st_atimensec', '#include <sys/stat.h>'],
  ['struct stat', 'st_uatime', '#include <sys/stat.h>'],
  ['struct stat', 'st_atim.st__tim.tv_nsec', '#include <sys/stat.h>'],
]

check_functions = [
  'wcwidth',
  '_futime',
  'futimens',
  'getopt_long',
  'mbrtowc',
  'posix_fadvise',
]

check_types = [
  ['_Bool', ''],
  ['mbstate_t', '#include <wchar.h>'],
  ['uintptr_t', '#include <stdint.h>'],
]

if (get_option('decoder_arm') or get_option('decoder_armthumb') or
  get_option('decoder_delta') or get_option('decoder_ia64') or
  get_option('decoder_lzma1') or get_option('decoder_lzma2') or
  get_option('decoder_powerpc') or get_option('decoder_x86'))
  cdata.set('HAVE_DECODERS', 1)
endif

if (get_option('encoder_arm') or get_option('encoder_armthumb') or
  get_option('encoder_delta') or get_option('encoder_ia64') or
  get_option('encoder_lzma1') or get_option('encoder_lzma2') or
  get_option('encoder_powerpc') or get_option('encoder_x86'))
  cdata.set('HAVE_ENCODERS', 1)
endif

foreach i : check_headers
  if cc.has_header(i)
    cdata.set('HAVE_' + i.underscorify().to_upper(), 1)
  endif
endforeach

foreach i : check_coders
  if get_option(i.get(0))
    cdata.set(i.get(1), 1)
  endif
endforeach

foreach i : check_functions
  if cc.has_function(i)
    cdata.set('HAVE_@0@'.format(i.underscorify().to_upper()), 1)
  endif
endforeach

foreach i : check_members
  struct_name = i.get(0)
  member_name = i.get(1)
  prefix = i.get(2)
  if cc.has_member(struct_name, member_name, prefix: prefix)
    cdata.set('HAVE_@0@_@1@'.format(struct_name.underscorify().to_upper(), member_name.underscorify().to_upper()), 1)
  endif
endforeach

foreach i : check_types
  prefix = i.get(1)
  if cc.has_type(i.get(0), prefix: prefix)
    cdata.set('HAVE_@0@'.format(i.get(0).underscorify().to_upper()), 1)
  endif
endforeach

cdata.set('SIZEOF_SIZE_T', cc.sizeof('size_t'))

cdata.set('PACKAGE_NAME', '"liblzma"')
cdata.set('PACKAGE_URL', '"http://tukaani.org/xz/"')
cdata.set('PACKAGE_BUGREPORT', '"x@x"')
cdata.set('PACKAGE', '"xz"')
cdata.set_quoted('PACKAGE_VERSION', meson.project_version())
cdata.set_quoted('VERSION', meson.project_version())

cdata.set('ASSUME_RAM', 128)
cdata.set('HAVE_CHECK_CRC32', 1)
cdata.set('HAVE_CHECK_CRC64', 1)
cdata.set('HAVE_CHECK_SHA256', 1)
cdata.set('_GNU_SOURCE', 1)
cdata.set('_ALL_SOURCE', 1)

cdata.set('HAVE_MF_BT2', 1)
cdata.set('HAVE_MF_BT3', 1)
cdata.set('HAVE_MF_BT4', 1)
cdata.set('HAVE_MF_HC3', 1)
cdata.set('HAVE_MF_HC4', 1)

has_sysconf_cpu = cc.compiles('''#include <unistd.h>
int main(int argc, char *argv[]) { return sysconf(_SC_NPROCESSORS_ONLN); }''')
if not has_sysconf_cpu
  has_sysconf_cpu = cc.compiles('''#include <unistd.h>
int main(int argc, char *argv[]) { return sysconf(_SC_NPROC_ONLN); }''')
endif
cdata.set('TUKLIB_CPUCORES_SYSCONF', has_sysconf_cpu)

has_stdc_hdr = cc.compiles('''#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <float.h>
int main(int argc, char **argv) { return 0; }
''')
cdata.set('STDC_HEADERS', has_stdc_hdr)
cdata.set('WORDS_BIGENDIAN', host_machine.endian() == 'big')

configure_file(input : 'config.h.meson',
  output : 'config.h',
  configuration : cdata
)

confinc = include_directories('.')
subdir('src')
