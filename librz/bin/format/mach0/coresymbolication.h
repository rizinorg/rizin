#include <rz_bin.h>
#include <rz_types.h>

#ifndef _INCLUDE_R_BIN_CORESYMBOLICATION_H
#define _INCLUDE_R_BIN_CORESYMBOLICATION_H

typedef struct rz_coresym_cache_element_hdr_t {
	ut32 version;
	ut32 size;
	ut32 n_segments;
	ut32 n_sections;
	ut32 n_symbols;
	ut32 n_lined_symbols;
	ut32 n_line_info;
	ut32 f;
	ut32 g;
	ut32 h;
	ut32 file_name_off;
	ut32 version_off;
	ut32 k;
	ut8 uuid[16];
	ut32 cputype;
	ut32 cpusubtype;
	ut32 o;
	ut32 strings_off;
	ut32 p;
} RzCoreSymCacheElementHdr;

typedef struct rz_coresym_cache_element_segment_t {
	ut64 paddr;
	ut64 vaddr;
	ut64 size;
	ut64 vsize;
	char *name;
} RzCoreSymCacheElementSegment;

typedef struct rz_coresym_cache_element_section_t {
	ut64 paddr;
	ut64 vaddr;
	ut64 size;
	char *name;
} RzCoreSymCacheElementSection;

typedef struct rz_coresym_cache_element_flc_t {
	char *file;
	ut32 line;
	ut32 col;
} RzCoreSymCacheElementFLC;

typedef struct rz_coresym_cache_element_line_info_t {
	ut32 paddr;
	ut32 size;
	RzCoreSymCacheElementFLC flc;
} RzCoreSymCacheElementLineInfo;

typedef struct rz_coresym_cache_element_symbol_t {
	ut32 paddr;
	ut32 size;
	ut32 unk1;
	char *name;
	char *mangled_name;
	st32 unk2;
} RzCoreSymCacheElementSymbol;

typedef struct rz_coresym_cache_element_lined_symbol_t {
	RzCoreSymCacheElementSymbol sym;
	RzCoreSymCacheElementFLC flc;
} RzCoreSymCacheElementLinedSymbol;

typedef struct rz_coresym_cache_element_t {
	RzCoreSymCacheElementHdr *hdr;
	char *file_name;
	char *binary_version;
	RzCoreSymCacheElementSegment *segments;
	RzCoreSymCacheElementSection *sections;
	RzCoreSymCacheElementSymbol *symbols;
	RzCoreSymCacheElementLinedSymbol *lined_symbols;
	RzCoreSymCacheElementLineInfo *line_info;
} RzCoreSymCacheElement;

RZ_API RzCoreSymCacheElement *rz_coresym_cache_element_new(RzBinFile *bf, RzBuffer *buf, ut64 off, int bits);
RZ_API void rz_coresym_cache_element_free(RzCoreSymCacheElement *element);
RZ_API ut64 rz_coresym_cache_element_pa2va(RzCoreSymCacheElement *element, ut64 pa);

#endif
