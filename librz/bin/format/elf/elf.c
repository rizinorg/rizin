// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static const char *sdb_elf_p_type_cparse = "enum elf_p_type {PT_NULL=0,PT_LOAD=1,PT_DYNAMIC=2,"
					   "PT_INTERP=3,PT_NOTE=4,PT_SHLIB=5,PT_PHDR=6,PT_LOOS=0x60000000,"
					   "PT_HIOS=0x6fffffff,PT_LOPROC=0x70000000,PT_HIPROC=0x7fffffff};";

static const char *sdb_elf_p_flags_cparse = "enum elf_p_flags {PF_None=0,PF_Exec=1,"
					    "PF_Write=2,PF_Write_Exec=3,PF_Read=4,PF_Read_Exec=5,PF_Read_Write=6,"
					    "PF_Read_Write_Exec=7};";

static const char *sdb_elf_type_cparse = "enum elf_type { ET_NONE=0, ET_REL=1,"
					 " ET_EXEC=2, ET_DYN=3, ET_CORE=4, ET_LOOS=0xfe00, ET_HIOS=0xfeff,"
					 " ET_LOPROC=0xff00, ET_HIPROC=0xffff };";

static const char *sdb_elf_machine_cparse = "enum elf_machine {EM_NONE=0, EM_M32=1,"
					    " EM_SPARC=2, EM_386=3, EM_68K=4, EM_88K=5, EM_IAMCU=6, EM_860=7, EM_MIPS=8,"
					    " EM_S370=9, EM_MIPS_RS3_LE=10, EM_RS6000=11, EM_PARISC=15, EM_nCUBE=16,"
					    " EM_VPP500=17, EM_SPARC32PLUS=18, EM_960=19, EM_PPC=20, EM_PPC64=21, EM_S390=22,"
					    " EM_SPU=23, EM_V800=36, EM_FR20=37, EM_RH32=38, EM_RCE=39, EM_ARM=40,"
					    " EM_ALPHA=41, EM_SH=42, EM_SPARCV9=43, EM_TRICORE=44, EM_ARC=45, EM_H8_300=46,"
					    " EM_H8_300H=47, EM_H8S=48, EM_H8_500=49, EM_IA_64=50, EM_MIPS_X=51,"
					    " EM_COLDFIRE=52, EM_68HC12=53, EM_MMA=54, EM_PCP=55, EM_NCPU=56, EM_NDR1=57,"
					    " EM_STARCORE=58, EM_ME16=59, EM_ST100=60, EM_TINYJ=61, EM_X86_64=62, EM_PDSP=63,"
					    " EM_PDP10=64, EM_PDP11=65, EM_FX66=66, EM_ST9PLUS=67, EM_ST7=68, EM_68HC16=69,"
					    " EM_68HC11=70, EM_68HC08=71, EM_68HC05=72, EM_SVX=73, EM_ST19=74, EM_VAX=75,"
					    " EM_CRIS=76, EM_JAVELIN=77, EM_FIREPATH=78, EM_ZSP=79, EM_MMIX=80, EM_HUANY=81,"
					    " EM_PRISM=82, EM_AVR=83, EM_FR30=84, EM_D10V=85, EM_D30V=86, EM_V850=87,"
					    " EM_M32R=88, EM_MN10300=89, EM_MN10200=90, EM_PJ=91, EM_OPENRISC=92,"
					    " EM_ARC_COMPACT=93, EM_XTENSA=94, EM_VIDEOCORE=95, EM_TMM_GPP=96, EM_NS32K=97,"
					    " EM_TPC=98, EM_SNP1K=99, EM_ST200=100, EM_IP2K=101, EM_MAX=102, EM_CR=103,"
					    " EM_F2MC16=104, EM_MSP430=105, EM_BLACKFIN=106, EM_SE_C33=107, EM_SEP=108,"
					    " EM_ARCA=109, EM_UNICORE=110, EM_EXCESS=111, EM_DXP=112, EM_ALTERA_NIOS2=113,"
					    " EM_CRX=114, EM_XGATE=115, EM_C166=116, EM_M16C=117, EM_DSPIC30F=118, EM_CE=119,"
					    " EM_M32C=120, EM_TSK3000=131, EM_RS08=132, EM_SHARC=133, EM_ECOG2=134,"
					    " EM_SCORE7=135, EM_DSP24=136, EM_VIDEOCORE3=137, EM_LATTICEMICO32=138,"
					    " EM_SE_C17=139, EM_TI_C6000=140, EM_TI_C2000=141, EM_TI_C5500=142,"
					    " EM_TI_ARP32=143, EM_TI_PRU=144,"
					    " EM_MMDSP_PLUS=160, EM_CYPRESS_M8C=161, EM_R32C=162, EM_TRIMEDIA=163,"
					    " EM_QDSP6=164, EM_8051=165, EM_STXP7X=166, EM_NDS32=167,"
					    " EM_ECOG1X=168, EM_MAXQ30=169, EM_XIMO16=170, EM_MANIK=171, EM_CRAYNV2=172,"
					    " EM_RX=173, EM_METAG=174, EM_MCST_ELBRUS=175, EM_ECOG16=176, EM_CR16=177,"
					    " EM_ETPU=178, EM_SLE9X=179, EM_L10M=180, EM_K10M=181, EM_AARCH64=183,"
					    " EM_AVR32=185, EM_STM8=186, EM_TILE64=187, EM_TILEPRO=188, EM_CUDA=190,"
					    " EM_TILEGX=191, EM_CLOUDSHIELD=192, EM_COREA_1ST=193, EM_COREA_2ND=194,"
					    " EM_ARC_COMPACT2=195, EM_OPEN8=196, EM_RL78=197, EM_VIDEOCORE5=198,"
					    " EM_78KOR=199, EM_56800EX=200, EM_BA1=201, EM_BA2=202, EM_XCORE=203,"
					    " EM_MCHP_PIC=204, EM_INTEL205=205, EM_INTEL206=206, EM_INTEL207=207,"
					    " EM_INTEL208=208, EM_INTEL209=209, EM_KM32=210, EM_KMX32=211, EM_KMX16=212,"
					    " EM_KMX8=213, EM_KVARC=214, EM_CDP=215, EM_COGE=216, EM_COOL=217, EM_NORC=218,"
					    " EM_CSR_KALIMBA=219, EM_AMDGPU=224, EM_RISCV=243, EM_LANAI=244, EM_BPF=247,"
					    " EM_CSKY=252, EM_KVX=256}";

static const char *sdb_elf_class_cparse = "enum elf_class {ELFCLASSNONE=0, ELFCLASS32=1, ELFCLASS64=2};";

static const char *sdb_elf_data_cparse = "enum elf_data {ELFDATANONE=0, ELFDATA2LSB=1, ELFDATA2MSB=2};";

static const char *sdb_elf_hdr_version_cparse = "enum elf_hdr_version {EV_NONE=0, EV_CURRENT=1};";

static const char *sdb_elf_obj_version_cparse = "enum elf_obj_version {EV_NONE=0, EV_CURRENT=1};";

static const char *sdb_elf_ident_format = "[4]z[1]E[1]E[1]E.::"
					  " magic (elf_class)class (elf_data)data (elf_hdr_version)version";

static const char *sdb_elf_s_type_cparse = "enum elf_s_type {SHT_NULL=0,SHT_PROGBITS=1,"
					   "SHT_SYMTAB=2,SHT_STRTAB=3,SHT_RELA=4,SHT_HASH=5,SHT_DYNAMIC=6,SHT_NOTE=7,"
					   "SHT_NOBITS=8,SHT_REL=9,SHT_SHLIB=10,SHT_DYNSYM=11,SHT_LOOS=0x60000000,"
					   "SHT_HIOS=0x6fffffff,SHT_LOPROC=0x70000000,SHT_HIPROC=0x7fffffff};";

#if RZ_BIN_ELF64
static const char *sdb_elf_phdr_format = "[4]E[4]Eqqqqqq (elf_p_type)type (elf_p_flags)flags"
					 " offset vaddr paddr filesz memsz align";

static const char *sdb_elf_s_flags_64_cparse = "enum elf_s_flags_64 {SF64_None=0,SF64_Exec=1,"
					       "SF64_Alloc=2,SF64_Alloc_Exec=3,SF64_Write=4,SF64_Write_Exec=5,"
					       "SF64_Write_Alloc=6,SF64_Write_Alloc_Exec=7};";

static const char *sdb_elf_shdr_format = "x[4]E[8]Eqqqxxqq name (elf_s_type)type"
					 " (elf_s_flags_64)flags addr offset size link info addralign entsize";

static const char *sdb_elf_header_format = "?[2]E[2]E[4]EqqqxN2N2N2N2N2N2"
					   " (elf_ident)ident (elf_type)type (elf_machine)machine (elf_obj_version)version"
					   " entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx";
#else
static const char *sdb_elf_phdr_format = "[4]Exxxxx[4]Ex (elf_p_type)type offset vaddr paddr"
					 " filesz memsz (elf_p_flags)flags align";

static const char *sdb_elf_s_flags_32_cparse = "enum elf_s_flags_32 {SF32_None=0,SF32_Exec=1,"
					       "SF32_Alloc=2,SF32_Alloc_Exec=3,SF32_Write=4,SF32_Write_Exec=5,"
					       "SF32_Write_Alloc=6,SF32_Write_Alloc_Exec=7};";

static const char *sdb_elf_shdr_format = "x[4]E[4]Exxxxxxx name (elf_s_type)type"
					 " (elf_s_flags_32)flags addr offset size link info addralign entsize";

static const char *sdb_elf_header_format = "?[2]E[2]E[4]ExxxxN2N2N2N2N2N2"
					   " (elf_ident)ident (elf_type)type (elf_machine)machine (elf_obj_version)version"
					   " entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx";
#endif

static bool in_virtual_phdr(RzBinElfSegment *segment, ut64 addr) {
	return addr >= segment->data.p_vaddr && addr < segment->data.p_vaddr + segment->data.p_filesz;
}

static bool in_physical_phdr(RzBinElfSegment *segment, ut64 addr) {
	return addr >= segment->data.p_offset && addr < segment->data.p_offset + segment->data.p_filesz;
}

static bool init_phdr_sdb(ELFOBJ *bin) {
	return sdb_num_set(bin->kv, "elf_phdr.offset", bin->ehdr.e_phoff) &&
		sdb_num_set(bin->kv, "elf_phdr.size", sizeof(Elf_(Phdr))) &&
		sdb_set(bin->kv, "elf_p_flags.cparse", sdb_elf_p_flags_cparse) &&
		sdb_set(bin->kv, "elf_p_type.cparse", sdb_elf_p_type_cparse) &&
		sdb_set(bin->kv, "elf_phdr.format", sdb_elf_phdr_format);
}

static bool init_phdr_aux(ELFOBJ *bin, RzVector /*<Elf_(Shdr)>*/ *sections, RzBinObjectLoadOptions *options) {
	bin->segments = Elf_(rz_bin_elf_segments_new)(bin, sections, options);
	if (!bin->segments) {
		return false;
	}

	return init_phdr_sdb(bin);
}

static void init_phdr(ELFOBJ *bin, RzVector /*<Elf_(Shdr)>*/ *sections, RzBinObjectLoadOptions *options) {
	if (!bin->ehdr.e_phnum) {
		RZ_LOG_WARN("There is no program header.\n");
		return;
	}

	if (!init_phdr_aux(bin, sections, options)) {
		RZ_LOG_WARN("Failed to initialize program header.\n");
	}
}

static bool init_ehdr_sdb(ELFOBJ *bin) {
	return sdb_num_set(bin->kv, "elf_header.offset", 0) &&
		sdb_num_set(bin->kv, "elf_header.size", sizeof(Elf_(Ehdr))) &&
		sdb_set(bin->kv, "elf_class.cparse", sdb_elf_class_cparse) &&
		sdb_set(bin->kv, "elf_data.cparse", sdb_elf_data_cparse) &&
		sdb_set(bin->kv, "elf_hdr_version.cparse", sdb_elf_hdr_version_cparse) &&
		sdb_set(bin->kv, "elf_header.format", sdb_elf_header_format) &&
		sdb_set(bin->kv, "elf_ident.format", sdb_elf_ident_format) &&
		sdb_set(bin->kv, "elf_machine.cparse", sdb_elf_machine_cparse) &&
		sdb_set(bin->kv, "elf_obj_version.cparse", sdb_elf_obj_version_cparse) &&
		sdb_set(bin->kv, "elf_type.cparse", sdb_elf_type_cparse);
}

static bool init_ehdr(ELFOBJ *bin) {
	if (!Elf_(rz_bin_elf_get_ehdr)(bin)) {
		return false;
	}

	return init_ehdr_sdb(bin);
}

static bool init_shdr_sdb(ELFOBJ *bin) {
	return sdb_num_set(bin->kv, "elf_shdr.offset", bin->ehdr.e_shoff) &&
		sdb_num_set(bin->kv, "elf_shdr.size", sizeof(Elf_(Shdr))) &&
#if RZ_BIN_ELF64
		sdb_set(bin->kv, "elf_s_flags_64.cparse", sdb_elf_s_flags_64_cparse) &&
#else
		sdb_set(bin->kv, "elf_s_flags_32.cparse", sdb_elf_s_flags_32_cparse) &&
#endif
		sdb_set(bin->kv, "elf_s_type.cparse", sdb_elf_s_type_cparse) &&
		sdb_set(bin->kv, "elf_shdr.format", sdb_elf_shdr_format);
}

static bool init_shdr_aux(ELFOBJ *bin, RzBinObjectLoadOptions *options, RzVector /*<Elf_(Shdr)>*/ *sections) {
	bin->sections = Elf_(rz_bin_elf_convert_sections)(bin, options, sections);
	if (!bin->sections) {
		return false;
	}

	return init_shdr_sdb(bin);
}

static void init_shdr(ELFOBJ *bin, RzBinObjectLoadOptions *options, RzVector /*<Elf_(Shdr)>*/ *sections) {
	if (!init_shdr_aux(bin, options, sections)) {
		RZ_LOG_WARN("Failed to initialize section header.\n");
	}
}

static bool init_shstrtab_sdb(ELFOBJ *bin, ut64 offset, ut64 size) {
	return sdb_num_set(bin->kv, "elf_shstrtab.offset", offset) &&
		sdb_num_set(bin->kv, "elf_shstrtab.size", size);
}

static bool init_shstrtab_aux(ELFOBJ *bin, RzVector /*<Elf_(Shdr)>*/ *sections) {
	if (!sections) {
		return true;
	}

	Elf_(Shdr) *section = rz_vector_index_ptr(sections, bin->ehdr.e_shstrndx);
	if (!section) {
		RZ_LOG_WARN("Invalid ELF header e_shstrndx value.\n");
		return false;
	}

	bin->shstrtab = Elf_(rz_bin_elf_strtab_new)(bin, section->sh_offset, section->sh_size);
	if (!bin->shstrtab) {
		return false;
	}

	return init_shstrtab_sdb(bin, section->sh_offset, section->sh_size);
}

static void init_shstrtab(ELFOBJ *bin, RzVector /*<Elf_(Shdr)>*/ *sections) {
	if (!init_shstrtab_aux(bin, sections)) {
		RZ_LOG_WARN("Failed to initialize section string table.\n");
	}
}

static bool init_dt_dynamic_sdb(ELFOBJ *bin) {
	switch (Elf_(rz_bin_elf_has_relro)(bin)) {
	case RZ_BIN_ELF_FULL_RELRO:
		return sdb_set(bin->kv, "elf.relro", "full");
	case RZ_BIN_ELF_PART_RELRO:
		return sdb_set(bin->kv, "elf.relro", "partial");
	default:
		return sdb_set(bin->kv, "elf.relro", "no");
	}

	return false;
}

static bool init_dt_dynamic_aux(ELFOBJ *bin) {
	bin->dt_dynamic = Elf_(rz_bin_elf_dt_dynamic_new)(bin);
	if (!bin->dt_dynamic) {
		return false;
	}

	return init_dt_dynamic_sdb(bin);
}

static void init_dt_dynamic(ELFOBJ *bin) {
	if (!init_dt_dynamic_aux(bin)) {
		RZ_LOG_INFO("Failed to initialize ELF DT_DYNAMIC.\n");
	}
}

static bool init_dynstr_sdb(ELFOBJ *bin, ut64 strtab_addr, Elf_(Xword) strtab_size) {
	return sdb_num_set(bin->kv, "elf_dynstr.offset", strtab_addr) &&
		sdb_num_set(bin->kv, "elf_dynstr.size", strtab_size);
}

static bool init_dynstr_aux(ELFOBJ *bin) {
	ut64 addr;
	ut64 size;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_STRTAB, &addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_STRSZ, &size)) {
		RZ_LOG_INFO("DT_STRTAB or DT_STRSZ key not found.\n");
		return false;
	}

	ut64 offset = Elf_(rz_bin_elf_v2p)(bin, addr);
	if (offset == UT64_MAX) {
		RZ_LOG_INFO("Failed to convert DT_STRTAB to a physical offset.\n");
		return false;
	}

	bin->dynstr = Elf_(rz_bin_elf_strtab_new)(bin, offset, size);
	if (!bin->dynstr) {
		return false;
	}

	return init_dynstr_sdb(bin, offset, size);
}

static void init_dynstr(ELFOBJ *bin) {
	if (!init_dynstr_aux(bin)) {
		RZ_LOG_INFO("Failed to initialize string table for dynamic linking.\n");
	}
}

static bool init_symbols_info_aux(ELFOBJ *bin) {
	Sdb *info = Elf_(rz_bin_elf_get_symbols_info)(bin);
	if (!info) {
		return false;
	}

	return sdb_ns_set(bin->kv, "versioninfo", info);
}

static void init_symbols_info(ELFOBJ *bin) {
	if (!init_symbols_info_aux(bin)) {
		RZ_LOG_INFO("Failed to initialize GNU symbols information.\n")
	}
}

static bool init(ELFOBJ *bin, RzBinObjectLoadOptions *options) {
	/* bin is not an ELF */
	if (!init_ehdr(bin)) {
		return false;
	}

	RzVector *sections = NULL;
	if (options->elf_load_sections) {
		sections = Elf_(rz_bin_elf_sections_new)(bin);
	}

	if (!Elf_(rz_bin_elf_is_relocatable)(bin)) {
		init_phdr(bin, sections, options);
	}

	if (!Elf_(rz_bin_elf_is_relocatable)(bin) && !Elf_(rz_bin_elf_is_static)(bin)) {
		init_dt_dynamic(bin);
		init_dynstr(bin);
		init_symbols_info(bin);
	}

	if (bin->ehdr.e_type != ET_CORE) {
		bin->baddr = Elf_(rz_bin_elf_get_baddr)(bin);
		init_shstrtab(bin, sections);
		init_shdr(bin, options, sections);
	}

	bin->boffset = Elf_(rz_bin_elf_get_boffset)(bin);

	bin->relocs = Elf_(rz_bin_elf_relocs_new)(bin);
	bin->reloc_targets_map_base = Elf_(rz_bin_elf_get_targets_map_base)(bin);

	bin->notes = Elf_(rz_bin_elf_notes_new)(bin);

	bin->symbols = Elf_(rz_bin_elf_symbols_new)(bin);
	bin->bits = Elf_(rz_bin_elf_get_bits)(bin);
	bin->imports = Elf_(rz_bin_elf_analyse_imports)(bin);

	rz_vector_free(sections);

	return true;
}

RZ_OWN ELFOBJ *Elf_(rz_bin_elf_new_buf)(RZ_NONNULL RzBuffer *buf, RZ_NONNULL RzBinObjectLoadOptions *options) {
	rz_return_val_if_fail(buf && options, NULL);

	ELFOBJ *bin = RZ_NEW0(ELFOBJ);
	if (!bin) {
		return NULL;
	}

	bin->b = rz_buf_ref(buf);
	bin->kv = sdb_new0();

	bin->size = rz_buf_size(buf);

	if (!init(bin, options)) {
		Elf_(rz_bin_elf_free)(bin);
		return NULL;
	}

	return bin;
}

/**
 * \brief Free the elf binary
 * \param elf binary
 *
 * ...
 */
void Elf_(rz_bin_elf_free)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_if_fail(bin);

	rz_buf_free(bin->b);
	rz_buf_free(bin->buf_patched);

	sdb_free(bin->kv);

	rz_vector_free(bin->segments);
	rz_vector_free(bin->sections);

	Elf_(rz_bin_elf_dt_dynamic_free)(bin->dt_dynamic);

	Elf_(rz_bin_elf_strtab_free)(bin->dynstr);
	Elf_(rz_bin_elf_strtab_free)(bin->shstrtab);

	rz_vector_free(bin->relocs);

	rz_vector_free(bin->notes);

	rz_vector_free(bin->symbols);
	rz_vector_free(bin->imports);

	free(bin);
}

/**
 * \brief Convert a physical address to the virtual address
 * \param elf binary
 * \return virtual addr
 *
 * Converts a physical address to the virtual address, looking
 * at the program headers in the binary bin
 */
ut64 Elf_(rz_bin_elf_p2v)(RZ_NONNULL ELFOBJ *bin, ut64 paddr) {
	rz_return_val_if_fail(bin, UT64_MAX);

	if (!Elf_(rz_bin_elf_has_segments)(bin)) {
		if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
			return bin->baddr + paddr;
		}

		return UT64_MAX;
	}

	RzBinElfSegment *segment;
	rz_bin_elf_foreach_segments(bin, segment) {
		if (segment->data.p_type == PT_LOAD && in_physical_phdr(segment, paddr)) {
			return segment->data.p_vaddr + paddr - segment->data.p_offset;
		}
	}

	return UT64_MAX;
}

/**
 * \brief Convert a virtual address to the physical address
 * \param elf binary
 * \return virtual addr
 *
 * Converts a virtual address to the relative physical address, looking
 * at the program headers in the binary bin
 */
ut64 Elf_(rz_bin_elf_v2p)(RZ_NONNULL ELFOBJ *bin, ut64 vaddr) {
	rz_return_val_if_fail(bin, UT64_MAX);

	if (!Elf_(rz_bin_elf_has_segments)(bin)) {
		if (Elf_(rz_bin_elf_is_relocatable)(bin) && vaddr > bin->baddr) {
			return vaddr - bin->baddr;
		}

		return UT64_MAX;
	}

	RzBinElfSegment *segment;
	rz_bin_elf_foreach_segments(bin, segment) {
		if (segment->data.p_type == PT_LOAD && in_virtual_phdr(segment, vaddr)) {
			return segment->data.p_offset + vaddr - segment->data.p_vaddr;
		}
	}

	return UT64_MAX;
}
