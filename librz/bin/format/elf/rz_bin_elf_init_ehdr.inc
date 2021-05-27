// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

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

#if RZ_BIN_ELF64
static const char *sdb_elf_header_format = "?[2]E[2]E[4]EqqqxN2N2N2N2N2N2"
					   " (elf_ident)ident (elf_type)type (elf_machine)machine (elf_obj_version)version"
					   " entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx";
#else
static const char *sdb_elf_header_format = "?[2]E[2]E[4]ExxxxN2N2N2N2N2N2"
					   " (elf_ident)ident (elf_type)type (elf_machine)machine (elf_obj_version)version"
					   " entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx";
#endif

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

RZ_IPI bool Elf_(rz_bin_elf_init_ehdr)(RZ_NONNULL RZ_INOUT ELFOBJ *bin) {
	init_ehdr_sdb(bin);

	if (!init_ehdr_ident(bin)) {
		return false;
	}

	if (!init_ehdr_other(bin)) {
		return false;
	}

	return true;
}
