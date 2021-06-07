// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
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
					    " EM_CSKY=252}";

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

static bool in_virtual_phdr(Elf_(Phdr) * segment, ut64 addr) {
	return addr >= segment->p_vaddr && addr < segment->p_vaddr + segment->p_filesz;
}

static bool in_physical_phdr(Elf_(Phdr) * segment, ut64 addr) {
	return addr >= segment->p_offset && addr < segment->p_offset + segment->p_filesz;
}

static void init_phdr_sdb(ELFOBJ *bin) {
	sdb_num_set(bin->kv, "elf_phdr.offset", bin->ehdr.e_phoff, 0);
	sdb_num_set(bin->kv, "elf_phdr.size", sizeof(Elf_(Phdr)), 0);
	sdb_set(bin->kv, "elf_p_flags.cparse", sdb_elf_p_flags_cparse, 0);
	sdb_set(bin->kv, "elf_p_type.cparse", sdb_elf_p_type_cparse, 0);
	sdb_set(bin->kv, "elf_phdr.format", sdb_elf_phdr_format, 0);
}

static HtUP *rel_cache_new(RzBinElfReloc *relocs, ut32 reloc_num) {
	if (!relocs || reloc_num == 0) {
		return NULL;
	}
	const int htsize = RZ_MIN(reloc_num, 1024);
	HtUP *rel_cache = ht_up_new_size(htsize, NULL, NULL, NULL);
	if (rel_cache) {
		size_t i;
		for (i = 0; i < reloc_num; i++) {
			RzBinElfReloc *tmp = relocs + i;
			ht_up_insert(rel_cache, tmp->sym, tmp);
		}
	}
	return rel_cache;
}

static void set_phdr_entry(ELFOBJ *bin, size_t phdr_entry_index, ut8 *entry) {
	size_t pos = 0;

	bin->phdr[phdr_entry_index].p_type = READ32(entry, pos);
#if RZ_BIN_ELF64
	bin->phdr[phdr_entry_index].p_flags = READ32(entry, pos);
#endif
	bin->phdr[phdr_entry_index].p_offset = RZ_BIN_ELF_READWORD(entry, pos);
	bin->phdr[phdr_entry_index].p_vaddr = RZ_BIN_ELF_READWORD(entry, pos);
	bin->phdr[phdr_entry_index].p_paddr = RZ_BIN_ELF_READWORD(entry, pos);
	bin->phdr[phdr_entry_index].p_filesz = RZ_BIN_ELF_READWORD(entry, pos);
	bin->phdr[phdr_entry_index].p_memsz = RZ_BIN_ELF_READWORD(entry, pos);
#ifndef RZ_BIN_ELF64
	bin->phdr[phdr_entry_index].p_flags = READ32(entry, pos);
#endif
	bin->phdr[phdr_entry_index].p_align = RZ_BIN_ELF_READWORD(entry, pos);
}

static bool read_phdr_entry(ELFOBJ *bin, size_t phdr_entry_index) {
	const size_t offset = bin->ehdr.e_phoff + phdr_entry_index * sizeof(Elf_(Phdr));
	ut8 phdr[sizeof(Elf_(Phdr))] = { 0 };

	if (rz_buf_read_at(bin->b, offset, phdr, sizeof(Elf_(Phdr))) < 0) {
		bprintf("read (phdr)\n");
		RZ_FREE(bin->phdr);
		return false;
	}

	set_phdr_entry(bin, phdr_entry_index, phdr);

	return true;
}

static bool read_phdr(ELFOBJ *bin, bool need_linux_kernel_hack) {
	bool phdr_found = false;

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (!read_phdr_entry(bin, i)) {
			return false;
		}

		if (need_linux_kernel_hack && bin->phdr[i].p_type == PT_PHDR) {
			phdr_found = true;
		}
	}

	if (need_linux_kernel_hack && phdr_found) {
		ut64 load_addr = Elf_(rz_bin_elf_get_baddr)(bin);
		bin->ehdr.e_phoff = Elf_(rz_bin_elf_v2p_new)(bin, load_addr + bin->ehdr.e_phoff);
		return read_phdr(bin, false);
	}

	return true;
}

/* Here is the where all the fun starts.
 * Linux kernel since 2005 calculates phdr offset wrongly
 * adding it to the load address (va of the LOAD0).
 * See `fs/binfmt_elf.c` file this line:
 *    NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
 * So after the first read, we fix the address and read it again
 */
static bool need_linux_kernel_hack(ELFOBJ *bin) {
	return bin->size > 128 * 1024 && (bin->ehdr.e_machine == EM_X86_64 || bin->ehdr.e_machine == EM_386);
}

static bool init_phdr_header(ELFOBJ *bin) {
	bin->phdr = RZ_NEWS0(Elf_(Phdr), bin->ehdr.e_phnum);
	if (!bin->phdr) {
		perror("malloc (phdr)");
		return false;
	}

	if (!read_phdr(bin, need_linux_kernel_hack(bin))) {
		return false;
	}

	return true;
}

static bool check_phdr_size(ELFOBJ *bin) {
	ut32 phdr_size;

	if (!UT32_MUL(&phdr_size, (ut32)bin->ehdr.e_phnum, sizeof(Elf_(Phdr)))) {
		return false;
	}

	if (!phdr_size || bin->ehdr.e_phoff + phdr_size > bin->size) {
		return false;
	}

	return true;
}

static bool rz_bin_elf_init_phdr(ELFOBJ *bin) {
	if (!bin->ehdr.e_phnum || !check_phdr_size(bin)) {
		return false;
	}

	init_phdr_sdb(bin);
	return init_phdr_header(bin);
}

static void init_shdr_sdb(ELFOBJ *bin) {
	sdb_num_set(bin->kv, "elf_shdr.offset", bin->ehdr.e_shoff, 0);
	sdb_num_set(bin->kv, "elf_shdr.size", sizeof(Elf_(Shdr)), 0);
#if RZ_BIN_ELF64
	sdb_set(bin->kv, "elf_s_flags_64.cparse", sdb_elf_s_flags_64_cparse, 0);
#else
	sdb_set(bin->kv, "elf_s_flags_32.cparse", sdb_elf_s_flags_32_cparse, 0);
#endif
	sdb_set(bin->kv, "elf_s_type.cparse", sdb_elf_s_type_cparse, 0);
	sdb_set(bin->kv, "elf_shdr.format", sdb_elf_shdr_format, 0);
}

static void set_shdr_entry(ELFOBJ *bin, size_t shdr_entry_index, ut8 *entry) {
	size_t pos = 0;

	bin->shdr[shdr_entry_index].sh_name = READ32(entry, pos);
	bin->shdr[shdr_entry_index].sh_type = READ32(entry, pos);
	bin->shdr[shdr_entry_index].sh_flags = RZ_BIN_ELF_READWORD(entry, pos);
	bin->shdr[shdr_entry_index].sh_addr = RZ_BIN_ELF_READWORD(entry, pos);
	bin->shdr[shdr_entry_index].sh_offset = RZ_BIN_ELF_READWORD(entry, pos);
	bin->shdr[shdr_entry_index].sh_size = RZ_BIN_ELF_READWORD(entry, pos);
	bin->shdr[shdr_entry_index].sh_link = READ32(entry, pos);
	bin->shdr[shdr_entry_index].sh_info = READ32(entry, pos);
	bin->shdr[shdr_entry_index].sh_addralign = RZ_BIN_ELF_READWORD(entry, pos);
	bin->shdr[shdr_entry_index].sh_entsize = RZ_BIN_ELF_READWORD(entry, pos);
}

static bool read_shdr_entry(ELFOBJ *bin, size_t shdr_entry_index) {
	const size_t offset = bin->ehdr.e_shoff + shdr_entry_index * sizeof(Elf_(Shdr));
	ut8 shdr[sizeof(Elf_(Shdr))] = { 0 };

	if (rz_buf_read_at(bin->b, offset, shdr, sizeof(Elf_(Shdr))) < 0) {
		bprintf("read (shdr) at 0x%" PFMT64x "\n", (ut64)bin->ehdr.e_shoff);
		RZ_FREE(bin->shdr);
		return false;
	}

	set_shdr_entry(bin, shdr_entry_index, shdr);

	return true;
}

static bool read_shdr(ELFOBJ *bin) {
	for (size_t i = 0; i < bin->ehdr.e_shnum; i++) {
		if (!read_shdr_entry(bin, i)) {
			return false;
		}
	}

	return true;
}

static bool init_shdr_header(ELFOBJ *bin) {
	bin->shdr = RZ_NEWS0(Elf_(Shdr), bin->ehdr.e_shnum);
	if (!bin->shdr) {
		perror("malloc (shdr)");
		return false;
	}

	if (!read_shdr(bin)) {
		return false;
	}

	return true;
}

static bool check_shdr_size(ELFOBJ *bin) {
	ut32 shdr_size;

	if (!UT32_MUL(&shdr_size, bin->ehdr.e_shnum, sizeof(Elf_(Shdr)))) {
		return false;
	}

	if (!shdr_size || bin->ehdr.e_shoff + shdr_size > bin->size) {
		return false;
	}

	return true;
}

static bool rz_bin_elf_init_shdr(ELFOBJ *bin) {
	if (!bin->ehdr.e_shnum || !check_shdr_size(bin)) {
		return false;
	}

	init_shdr_sdb(bin);

	return init_shdr_header(bin);
}

static void init_shstrtab_sdb(ELFOBJ *bin) {
	sdb_num_set(bin->kv, "elf_shstrtab.offset", bin->shstrtab_section->sh_offset, 0);
	sdb_num_set(bin->kv, "elf_shstrtab.size", bin->shstrtab_section->sh_size, 0);
}

static bool check_shstrtab(ELFOBJ *bin) {
	return bin->shstrtab_section->sh_offset + bin->shstrtab_section->sh_size < bin->size;
}

static bool check_shstrtab_index(ELFOBJ *bin, Elf_(Half) shstrtab_index) {
	return shstrtab_index != SHN_UNDEF && Elf_(rz_bin_elf_is_sh_index_valid)(bin, shstrtab_index);
}

static bool set_shstrtab(ELFOBJ *bin) {
	bin->shstrtab = calloc(1, bin->shstrtab_size + 1);
	if (!bin->shstrtab) {
		perror("malloc");
		return false;
	}

	int res = rz_buf_read_at(bin->b, bin->shstrtab_section->sh_offset, (ut8 *)bin->shstrtab, bin->shstrtab_section->sh_size);
	if (res < 0) {
		bprintf("read (shstrtab) at 0x%" PFMT64x "\n", (ut64)bin->shstrtab_section->sh_offset);
		RZ_FREE(bin->shstrtab);
		return false;
	}

	bin->shstrtab[bin->shstrtab_section->sh_size] = '\0';

	return true;
}

static bool rz_bin_elf_init_shstrtab(ELFOBJ *bin) {
	if (!bin->shdr) {
		return false;
	}

	Elf_(Half) shstrtab_index = bin->ehdr.e_shstrndx;
	if (!check_shstrtab_index(bin, shstrtab_index) || !bin->shdr[shstrtab_index].sh_size) {
		return false;
	}

	bin->shstrtab_section = bin->strtab_section = bin->shdr + shstrtab_index;
	bin->shstrtab_size = bin->shstrtab_section->sh_size;

	init_shstrtab_sdb(bin);

	if (!check_shstrtab(bin)) {
		return false;
	}

	if (!set_shstrtab(bin)) {
		return true;
	}

	return true;
}

static void init_ehdr_sdb(ELFOBJ *bin) {
	sdb_num_set(bin->kv, "elf_header.offset", 0, 0);
	sdb_num_set(bin->kv, "elf_header.size", sizeof(Elf_(Ehdr)), 0);
	sdb_set(bin->kv, "elf_class.cparse", sdb_elf_class_cparse, 0);
	sdb_set(bin->kv, "elf_data.cparse", sdb_elf_data_cparse, 0);
	sdb_set(bin->kv, "elf_hdr_version.cparse", sdb_elf_hdr_version_cparse, 0);
	sdb_set(bin->kv, "elf_header.format", sdb_elf_header_format, 0);
	sdb_set(bin->kv, "elf_ident.format", sdb_elf_ident_format, 0);
	sdb_set(bin->kv, "elf_machine.cparse", sdb_elf_machine_cparse, 0);
	sdb_set(bin->kv, "elf_obj_version.cparse", sdb_elf_obj_version_cparse, 0);
	sdb_set(bin->kv, "elf_type.cparse", sdb_elf_type_cparse, 0);
}

static bool is_valid_elf_ident(ut8 *e_ident) {
	return !memcmp(e_ident, ELFMAG, SELFMAG) || !memcmp(e_ident, CGCMAG, SCGCMAG);
}

static bool init_ehdr_ident(ELFOBJ *bin) {
	if (rz_buf_read_at(bin->b, 0, bin->ehdr.e_ident, EI_NIDENT) == -1) {
		bprintf("read (magic)\n");
		return false;
	}

	if (!is_valid_elf_ident(bin->ehdr.e_ident)) {
		return false;
	}

	bin->endian = bin->ehdr.e_ident[EI_DATA] == ELFDATA2MSB ? 1 : 0;

	return true;
}

static bool init_ehdr_other(ELFOBJ *bin) {
	size_t i = EI_NIDENT;
	ut8 ehdr[sizeof(Elf_(Ehdr))] = { 0 };
	rz_buf_read_at(bin->b, 0, ehdr, sizeof(ehdr));

	if (bin->size < 32) { // tinyelf != sizeof (Elf_(Ehdr)))
		bprintf("read (ehdr)\n");
		return false;
	}

	bin->ehdr.e_type = READ16(ehdr, i);
	bin->ehdr.e_machine = READ16(ehdr, i);
	bin->ehdr.e_version = READ32(ehdr, i);
	bin->ehdr.e_entry = RZ_BIN_ELF_READWORD(ehdr, i);
	bin->ehdr.e_phoff = RZ_BIN_ELF_READWORD(ehdr, i);
	bin->ehdr.e_shoff = RZ_BIN_ELF_READWORD(ehdr, i);
	bin->ehdr.e_flags = READ32(ehdr, i);
	bin->ehdr.e_ehsize = READ16(ehdr, i);
	bin->ehdr.e_phentsize = READ16(ehdr, i);
	bin->ehdr.e_phnum = READ16(ehdr, i);
	bin->ehdr.e_shentsize = READ16(ehdr, i);
	bin->ehdr.e_shnum = READ16(ehdr, i);
	bin->ehdr.e_shstrndx = READ16(ehdr, i);

	return true;
}

static bool rz_bin_elf_init_ehdr(ELFOBJ *bin) {
	init_ehdr_sdb(bin);

	if (!init_ehdr_ident(bin)) {
		return false;
	}

	if (!init_ehdr_other(bin)) {
		return false;
	}

	return true;
}

static bool check_dynstr_size(ELFOBJ *bin, size_t shdr_entry_index) {
	return bin->shdr[shdr_entry_index].sh_offset + bin->shdr[shdr_entry_index].sh_size < bin->size;
}

static bool set_dynstr(ELFOBJ *bin, size_t shdr_entry_index) {
	Elf_(Off) offset = bin->shdr[shdr_entry_index].sh_offset;
	bin->dynstr = RZ_NEWS0(char, bin->shdr[shdr_entry_index].sh_size + 1);
	bin->dynstr_size = bin->shdr[shdr_entry_index].sh_size;

	if (!bin->dynstr) {
		bprintf("Cannot allocate memory for dynamic strings\n");
		return false;
	}

	if (!check_dynstr_size(bin, shdr_entry_index)) {
		return false;
	}

	if (rz_buf_read_at(bin->b, offset, (ut8 *)bin->dynstr, bin->dynstr_size) < 0) {
		RZ_FREE(bin->dynstr);
		bin->dynstr_size = 0;
		return false;
	}

	return true;
}

static bool rz_bin_elf_init_dynstr(ELFOBJ *bin) {
	if (!bin->shdr || !bin->shstrtab) {
		return false;
	}

	for (size_t i = 0; i < bin->ehdr.e_shnum; i++) {
		if (bin->shdr[i].sh_name > bin->shstrtab_size) {
			return false;
		}

		const char *section_name = bin->shstrtab + bin->shdr[i].sh_name;

		if (bin->shdr[i].sh_type == SHT_STRTAB && !strcmp(section_name, ".dynstr")) {
			return set_dynstr(bin, i);
		}
	}

	return false;
}

static void set_default_value_dynamic_info(ELFOBJ *bin) {
	bin->dyn_info.dt_init = 0;
	bin->dyn_info.dt_fini = 0;
	bin->dyn_info.dt_pltrelsz = 0;
	bin->dyn_info.dt_pltgot = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_hash = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_gnu_hash = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_strtab = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_symtab = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_rela = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_relasz = 0;
	bin->dyn_info.dt_relaent = 0;
	bin->dyn_info.dt_strsz = 0;
	bin->dyn_info.dt_syment = 0;
	bin->dyn_info.dt_rel = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_relsz = 0;
	bin->dyn_info.dt_relent = 0;
	bin->dyn_info.dt_pltrel = RZ_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_jmprel = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_pltgot = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_mips_pltgot = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_bind_now = false;
	bin->dyn_info.dt_flags = RZ_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_flags_1 = RZ_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_rpath = RZ_BIN_ELF_XWORD_MAX;
	bin->dyn_info.dt_runpath = RZ_BIN_ELF_XWORD_MAX;
	rz_vector_init(&bin->dyn_info.dt_needed, sizeof(Elf_(Off)), NULL, NULL);
}

static bool check_dynamic_segment(ELFOBJ *bin, size_t phdr_entry_index) {
	if (bin->phdr[phdr_entry_index].p_filesz > bin->size) {
		return false;
	}

	if (bin->phdr[phdr_entry_index].p_offset + sizeof(Elf_(Dyn)) > bin->size) {
		return false;
	}

	return true;
}

static Elf_(Phdr) * get_dynamic_segment(ELFOBJ *bin) {
	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_DYNAMIC) {
			if (!check_dynamic_segment(bin, i)) {
				return NULL;
			}

			return bin->phdr + i;
		}
	}

	return NULL;
}

static size_t get_maximum_number_of_dynamic_entries(ut64 dynamic_size) {
	return dynamic_size / sizeof(Elf_(Dyn));
}

static bool fill_dynamic_entry(ELFOBJ *bin, ut64 entry_offset, Elf_(Dyn) * d) {
	ut8 tmp[sizeof(Elf_(Dyn))] = { 0 };

	if (rz_buf_read_at(bin->b, entry_offset, tmp, sizeof(Elf_(Dyn))) < 0) {
		return false;
	}

	size_t pos = 0;

	d->d_tag = RZ_BIN_ELF_READWORD(tmp, pos);
	d->d_un.d_ptr = RZ_BIN_ELF_READWORD(tmp, pos);

	return true;
}

static void fill_dynamic_entries(ELFOBJ *bin, ut64 loaded_offset, ut64 dyn_size) {
	Elf_(Dyn) d = { 0 };
	size_t number_of_entries = get_maximum_number_of_dynamic_entries(dyn_size);

	for (size_t i = 0; i < number_of_entries; i++) {
		ut64 entry_offset = loaded_offset + i * sizeof(Elf_(Dyn));
		if (!fill_dynamic_entry(bin, entry_offset, &d)) {
			break;
		}

		switch (d.d_tag) {
		case DT_NULL:
			break;
		case DT_PLTRELSZ:
			bin->dyn_info.dt_pltrelsz = d.d_un.d_val;
			break;
		case DT_PLTGOT:
			bin->dyn_info.dt_pltgot = d.d_un.d_ptr;
			break;
		case DT_HASH:
			bin->dyn_info.dt_hash = d.d_un.d_ptr;
			break;
		case DT_GNU_HASH:
			bin->dyn_info.dt_gnu_hash = d.d_un.d_ptr;
			break;
		case DT_STRTAB:
			bin->dyn_info.dt_strtab = d.d_un.d_ptr;
			break;
		case DT_SYMTAB:
			bin->dyn_info.dt_symtab = d.d_un.d_ptr;
			break;
		case DT_RELA:
			bin->dyn_info.dt_rela = d.d_un.d_ptr;
			break;
		case DT_RELASZ:
			bin->dyn_info.dt_relasz = d.d_un.d_val;
			break;
		case DT_RELAENT:
			bin->dyn_info.dt_relaent = d.d_un.d_val;
			break;
		case DT_STRSZ:
			bin->dyn_info.dt_strsz = d.d_un.d_val;
			break;
		case DT_SYMENT:
			bin->dyn_info.dt_syment = d.d_un.d_val;
			break;
		case DT_REL:
			bin->dyn_info.dt_rel = d.d_un.d_ptr;
			break;
		case DT_RELSZ:
			bin->dyn_info.dt_relsz = d.d_un.d_val;
			break;
		case DT_RELENT:
			bin->dyn_info.dt_relent = d.d_un.d_val;
			break;
		case DT_PLTREL:
			bin->dyn_info.dt_pltrel = d.d_un.d_val;
			break;
		case DT_JMPREL:
			bin->dyn_info.dt_jmprel = d.d_un.d_ptr;
			break;
		case DT_MIPS_PLTGOT:
			bin->dyn_info.dt_mips_pltgot = d.d_un.d_ptr;
			break;
		case DT_BIND_NOW:
			bin->dyn_info.dt_bind_now = true;
			break;
		case DT_FLAGS:
			bin->dyn_info.dt_flags = d.d_un.d_val;
			break;
		case DT_FLAGS_1:
			bin->dyn_info.dt_flags_1 = d.d_un.d_val;
			break;
		case DT_RPATH:
			bin->dyn_info.dt_rpath = d.d_un.d_val;
			break;
		case DT_RUNPATH:
			bin->dyn_info.dt_runpath = d.d_un.d_val;
			break;
		case DT_NEEDED:
			rz_vector_push(&bin->dyn_info.dt_needed, &d.d_un.d_val);
			break;
		case DT_INIT:
			bin->dyn_info.dt_init = d.d_un.d_ptr;
			break;
		case DT_FINI:
			bin->dyn_info.dt_fini = d.d_un.d_ptr;
			break;
		case DT_DEBUG:
		case DT_INIT_ARRAY:
		case DT_FINI_ARRAY:
		case DT_INIT_ARRAYSZ:
		case DT_FINI_ARRAYSZ:
		case DT_PREINIT_ARRAY:
		case DT_PREINIT_ARRAYSZ:
		case DT_SONAME:
			// common dynamic entries in ELF, but we don't need to
			// do anything with them.
			break;
		default:
			if ((d.d_tag >= DT_VERSYM) && (d.d_tag <= DT_VERNEEDNUM)) {
				bin->version_info[DT_VERSIONTAGIDX(d.d_tag)] = d.d_un.d_val;
			} else {
				RZ_LOG_DEBUG("Dynamic tag %" PFMT64d " not handled\n", (ut64)d.d_tag);
			}
			break;
		}

		if (d.d_tag == DT_NULL) {
			break;
		}
	}
}

static void init_dynamic_section_sdb(ELFOBJ *bin) {
	switch (Elf_(rz_bin_elf_has_relro)(bin)) {
	case RZ_BIN_ELF_FULL_RELRO:
		sdb_set(bin->kv, "elf.relro", "full", 0);
		break;
	case RZ_BIN_ELF_PART_RELRO:
		sdb_set(bin->kv, "elf.relro", "partial", 0);
		break;
	default:
		sdb_set(bin->kv, "elf.relro", "no", 0);
		break;
	}
}

static bool rz_bin_elf_init_dynamic_section(ELFOBJ *bin) {
	if (!bin->phdr) {
		return false;
	}

	set_default_value_dynamic_info(bin);

	Elf_(Phdr) *dynamic = get_dynamic_segment(bin);
	if (!dynamic) {
		return false;
	}

	Elf_(Xword) dynamic_size = dynamic->p_filesz;
	ut64 dynamic_offset = Elf_(rz_bin_elf_v2p_new)(bin, dynamic->p_vaddr);
	if (dynamic_offset == UT64_MAX) {
		return false;
	}

	if (!dynamic_size || dynamic_offset + dynamic_size > bin->size) {
		return false;
	}

	fill_dynamic_entries(bin, dynamic_offset, dynamic_size);
	init_dynamic_section_sdb(bin);

	return true;
}

static void init_strtab_sdb(ELFOBJ *bin, ut64 strtab_addr, Elf_(Xword) strtab_size) {
	sdb_num_set(bin->kv, "elf_strtab.offset", strtab_addr, 0);
	sdb_num_set(bin->kv, "elf_strtab.size", strtab_size, 0);
}

static bool read_strtab(ELFOBJ *bin, ut64 strtab_addr, Elf_(Xword) strtab_size) {
	bin->strtab_size = strtab_size;
	bin->strtab = RZ_NEWS0(char, strtab_size + 1);
	if (!bin->strtab) {
		return false;
	}

	if (rz_buf_read_at(bin->b, strtab_addr, (ut8 *)bin->strtab, strtab_size) < 0) {
		free(bin->strtab);
		return false;
	}

	return true;
}

static bool rz_bin_elf_init_strtab(ELFOBJ *bin) {
	if (bin->dyn_info.dt_strtab == RZ_BIN_ELF_ADDR_MAX || !bin->dyn_info.dt_strsz) {
		bprintf("DT_STRTAB not found or invalid\n");
		return false;
	}

	ut64 strtab_addr = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_strtab);
	Elf_(Xword) strtab_size = bin->dyn_info.dt_strsz;

	init_strtab_sdb(bin, strtab_addr, strtab_size);

	if (strtab_addr + strtab_size > bin->size) {
		return false;
	}

	return read_strtab(bin, strtab_addr, strtab_size);
}

static bool rz_bin_elf_init(ELFOBJ *bin) {
	/* bin is not an ELF */
	if (!rz_bin_elf_init_ehdr(bin)) {
		return false;
	}
	if (!rz_bin_elf_init_phdr(bin) && !Elf_(rz_bin_elf_is_relocatable)(bin)) {
		bprintf("Cannot initialize program headers\n");
	}
	if (bin->ehdr.e_type == ET_CORE) {
		if (!Elf_(rz_bin_elf_init_notes)(bin)) {
			bprintf("Cannot parse PT_NOTE segments\n");
		}
	} else {
		if (!rz_bin_elf_init_shdr(bin)) {
			bprintf("Cannot initialize section headers\n");
		}

		if (!rz_bin_elf_init_shstrtab(bin)) {
			bprintf("Cannot initialize strings table\n");
		}

		if (!rz_bin_elf_init_dynstr(bin) && !Elf_(rz_bin_elf_is_relocatable)(bin)) {
			bprintf("Cannot initialize dynamic strings\n");
		}

		bin->baddr = Elf_(rz_bin_elf_get_baddr)(bin);

		if (!Elf_(rz_bin_elf_is_relocatable)(bin) && !Elf_(rz_bin_elf_is_static)(bin)) {
			if (!rz_bin_elf_init_dynamic_section(bin) || !rz_bin_elf_init_strtab(bin)) {
				bprintf("Cannot initialize dynamic section\n");
			}
		}
	}

	bin->boffset = Elf_(rz_bin_elf_get_boffset)(bin);

	bin->imports_by_ord_size = 0;
	bin->imports_by_ord = NULL;
	bin->symbols_by_ord_size = 0;
	bin->symbols_by_ord = NULL;

	bin->g_sections = Elf_(rz_bin_elf_get_sections)(bin);
	bin->g_relocs = Elf_(rz_bin_elf_get_relocs)(bin);

	bin->rel_cache = rel_cache_new(bin->g_relocs, bin->g_reloc_num);

	sdb_ns_set(bin->kv, "versioninfo", Elf_(rz_bin_elf_get_version_info)(bin));

	return true;
}

RZ_OWN ELFOBJ *Elf_(rz_bin_elf_new_buf)(RZ_NONNULL RzBuffer *buf, bool verbose) {
	rz_return_val_if_fail(buf, NULL);

	ELFOBJ *bin = RZ_NEW0(ELFOBJ);
	if (!bin) {
		return NULL;
	}

	bin->b = rz_buf_ref(buf);
	bin->size = rz_buf_size(buf);
	bin->kv = sdb_new0();
	bin->verbose = verbose;

	if (rz_bin_elf_init(bin)) {
		return bin;
	}

	Elf_(rz_bin_elf_free)(bin);
	return NULL;
}

/**
 * \brief Free the elf binary
 * \param elf binary
 *
 * ...
 */
void Elf_(rz_bin_elf_free)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_if_fail(bin);

	free(bin->phdr);
	free(bin->shdr);
	free(bin->strtab);
	free(bin->shstrtab);
	free(bin->dynstr);

	free(bin->g_sections);
	free(bin->g_symbols);
	free(bin->g_imports);
	free(bin->g_relocs);

	if (bin->g_symbols != bin->phdr_symbols) {
		free(bin->phdr_symbols);
	}

	if (bin->g_imports != bin->phdr_imports) {
		free(bin->phdr_imports);
	}

	ht_up_free(bin->rel_cache);

	rz_vector_fini(&bin->dyn_info.dt_needed);
	rz_list_free(bin->note_segments);

	if (bin->imports_by_ord) {
		for (size_t i = 0; i < bin->imports_by_ord_size; i++) {
			rz_bin_import_free(bin->imports_by_ord[i]);
		}
		free(bin->imports_by_ord);
	}

	if (bin->symbols_by_ord) {
		for (size_t i = 0; i < bin->symbols_by_ord_size; i++) {
			rz_bin_symbol_free(bin->symbols_by_ord[i]);
		}
		free(bin->symbols_by_ord);
	}

	rz_buf_free(bin->b);
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
ut64 Elf_(rz_bin_elf_p2v_new)(RZ_NONNULL ELFOBJ *bin, ut64 paddr) {
	rz_return_val_if_fail(bin, UT64_MAX);

	if (!bin->phdr) {
		if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
			return bin->baddr + paddr;
		}

		return UT64_MAX;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		Elf_(Phdr) *segment = bin->phdr + i;

		if (segment->p_type == PT_LOAD && in_physical_phdr(segment, paddr)) {
			return segment->p_vaddr + paddr - segment->p_offset;
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
ut64 Elf_(rz_bin_elf_v2p_new)(RZ_NONNULL ELFOBJ *bin, ut64 vaddr) {
	rz_return_val_if_fail(bin, UT64_MAX);

	if (!bin->phdr) {
		if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
			return vaddr - bin->baddr;
		}

		return UT64_MAX;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		Elf_(Phdr) *segment = bin->phdr + i;

		if (segment->p_type == PT_LOAD && in_virtual_phdr(segment, vaddr)) {
			return segment->p_offset + vaddr - segment->p_vaddr;
		}
	}

	return UT64_MAX;
}
