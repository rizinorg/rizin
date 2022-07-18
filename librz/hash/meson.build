hash_plugins = [
	'md4',
	'md5',
	'sha1',
	'sha256',
	'sha384',
	'sha512',
	'fletcher8',
	'fletcher16',
	'fletcher32',
	'fletcher64',
	'adler32',
	'crca_crc8smbus',
	'crca_crc8cdma2000',
	'crca_crc8darc',
	'crca_crc8dvbs2',
	'crca_crc8ebu',
	'crca_crc8icode',
	'crca_crc8itu',
	'crca_crc8maxim',
	'crca_crc8rohc',
	'crca_crc8wcdma',
	'crca_crc15can',
	'crca_crc16',
	'crca_crc16citt',
	'crca_crc16usb',
	'crca_crc16hdlc',
	'crca_crc16augccitt',
	'crca_crc16buypass',
	'crca_crc16cdma2000',
	'crca_crc16dds110',
	'crca_crc16dectr',
	'crca_crc16dectx',
	'crca_crc16dnp',
	'crca_crc16en13757',
	'crca_crc16genibus',
	'crca_crc16maxim',
	'crca_crc16mcrf4xx',
	'crca_crc16riello',
	'crca_crc16t10dif',
	'crca_crc16teledisk',
	'crca_crc16tms37157',
	'crca_crca',
	'crca_crc16kermit',
	'crca_crc16modbus',
	'crca_crc16x25',
	'crca_crc16xmodem',
	'crca_crc24',
	'crca_crc32',
	'crca_crc32ecma267',
	'crca_crc32c',
	'crca_crc32bzip2',
	'crca_crc32d',
	'crca_crc32mpeg2',
	'crca_crc32posix',
	'crca_crc32q',
	'crca_crc32jamcrc',
	'crca_crc32xfer',
	'crca_crc64',
	'crca_crc64ecma182',
	'crca_crc64we',
	'crca_crc64xz',
	'crca_crc64iso',
	'xor8',
	'xor16',
	'xxhash32',
	'parity',
	'entropy',
	'entropy_fract',
]

rz_hash_sources = [
  'hash.c',
  'randomart.c',
  'p/algo_crca.c',
  'p/algo_adler32.c',
  'p/algo_fletcher.c',
  'p/algo_md4.c',
  'p/algo_md5.c',
  'p/algo_mod255.c',
  'p/algo_sha1.c',
  'p/algo_sha256.c',
  'p/algo_sha384.c',
  'p/algo_sha512.c',
  'p/algo_xor8.c',
  'p/algo_xor16.c',
  'p/algo_xxhash32.c',
  'p/algo_parity.c',
  'p/algo_entropy.c',
  'p/algo_entropy_fractional.c',
  'algorithms/mod255/mod255.c',
  'algorithms/parity/parity.c',
  'algorithms/entropy/entropy.c',
  'algorithms/adler32/adler32.c',
  'algorithms/crc/crca.c',
  'algorithms/xor/xor.c',
  'algorithms/fletcher/fletcher.c'
]

dependencies = [mth, rz_util_dep, xxhash_dep]

if sys_openssl.found()
  dependencies += [sys_openssl]
else
  rz_hash_sources += [
    'algorithms/md4/md4.c',
    'algorithms/md5/md5.c',
    'algorithms/sha1/sha1.c',
    'algorithms/sha2/sha2.c'
  ]
endif

rz_hash = library('rz_hash', rz_hash_sources,
  include_directories: [platform_inc],
  dependencies: dependencies,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_hash_dep = declare_dependency(link_with: rz_hash,
                                include_directories: [platform_inc])
meson.override_dependency('rz_hash', rz_hash_dep)

pkgconfig_mod.generate(rz_hash,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_hash',
  filebase: 'rz_hash',
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries',
  variables: [
    'plugindir=@0@'.format(rizin_plugins),
    'datdir=@0@'.format(rizin_datdir_rz),
  ],
)

if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('RIZIN_MODULE', rz_hash.name())
  conf.set('RIZIN_MODULE_DEPS', ' '.join(['rz_util']))
  conf.set('PACKAGE_RELATIVE_PATH', cmake_package_relative_path)
  conf.set('INSTALL_INCDIR', rizin_incdir)
  conf.set('INSTALL_LIBDIR', rizin_libdir)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  conf.set('rizin_libname', rz_hash.name())
  cmake_mod.configure_package_config_file(
    name: conf.get('rizin_libname'),
    input: '../RzModulesConfig.cmake.in',
    install_dir: rizin_cmakedir / conf.get('rizin_libname'),
    configuration: conf,
  )
endif
