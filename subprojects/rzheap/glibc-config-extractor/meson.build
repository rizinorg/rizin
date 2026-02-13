project(
	'glibc-config-extractor',
	'c',
	version: '0.1.0',
	default_options: [
		'c_std=gnu11',
		'warning_level=2',
	]
)

glibc_dir = get_option('glibc_dir')
if glibc_dir == ''
	error('glibc_dir option is required (path to the glibc source tree).')
endif

python3 = find_program('python3')

# ---------------------------------------------------------------------------
# extract struct definitions from glibc source at configure/build time
# ---------------------------------------------------------------------------
glibc_structs_h = custom_target(
	'glibc_structs.h',
	input: files('extract_glibc_structs.py'),
	output: 'glibc_structs.h',
	command: [python3, '@INPUT0@', glibc_dir, '@OUTPUT0@'],
)

executable(
	'extract_glibc_layouts',
	'extract_glibc_layouts.c',
	glibc_structs_h,
	include_directories: include_directories('.'),
	c_args: [
		'-O0',
		'-Wall',
		'-DGLIBC_SRC_DIR="' + glibc_dir + '"',
	]
)
