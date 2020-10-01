rz_fs_sources = [
  'fs_file.c',
  'fs.c',
  'shell.c',
  'p/fs_cpio.c',
  'p/fs_ext2.c',
  'p/fs_fat.c',
  'p/fs_fb.c',
  #'p/fs_grub_base.c',
  'p/fs_hfs.c',
  'p/fs_hfsplus.c',
  'p/fs_io.c',
  'p/fs_iso9660.c',
  'p/fs_jfs.c',
  'p/fs_minix.c',
  'p/fs_ntfs.c',
  'p/fs_posix.c',
  'p/fs_rz.c',
  'p/fs_reiserfs.c',
  'p/fs_sfs.c',
  'p/fs_tar.c',
  'p/fs_udf.c',
  'p/fs_ufs.c',
  'p/fs_ufs2.c',
  'p/fs_xfs.c',
  #'p/part_dos.c'
]

rz_fs = library('rz_fs', rz_fs_sources,
  include_directories: platform_inc,
  c_args: library_cflags,
  dependencies: [
    rz_util_dep,
    grub_dep
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: r2_libversion
)

rz_fs_dep = declare_dependency(link_with: rz_fs,
                              include_directories: platform_inc)

pkgconfig_mod.generate(rz_fs,
  subdirs: 'librz',
  version: r2_version,
  name: 'rz_fs',
  filebase: 'rz_fs',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'radare foundation libraries'
)
