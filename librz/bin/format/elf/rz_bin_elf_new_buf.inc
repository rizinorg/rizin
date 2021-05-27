// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define round_up(a) ((((a) + (4) - (1)) / (4)) * (4))

static bool __is_valid_ident(ELFOBJ *bin) {
	return !strncmp((char *)bin->ehdr.e_ident, ELFMAG, SELFMAG) ||
		!strncmp((char *)bin->ehdr.e_ident, CGCMAG, SCGCMAG);
}

static bool init_ehdr(ELFOBJ *bin) {
	ut8 e_ident[EI_NIDENT];
	ut8 ehdr[sizeof(Elf_(Ehdr))] = { 0 };
	int i, len;
	if (rz_buf_read_at(bin->b, 0, e_ident, EI_NIDENT) == -1) {
		bprintf("read (magic)\n");
		return false;
	}
	sdb_set(bin->kv, "elf_type.cparse", "enum elf_type { ET_NONE=0, ET_REL=1,"
					    " ET_EXEC=2, ET_DYN=3, ET_CORE=4, ET_LOOS=0xfe00, ET_HIOS=0xfeff,"
					    " ET_LOPROC=0xff00, ET_HIPROC=0xffff };",
		0);
	sdb_set(bin->kv, "elf_machine.cparse", "enum elf_machine {EM_NONE=0, EM_M32=1,"
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
					       " EM_CSKY=252}",
		0);
	sdb_set(bin->kv, "elf_class.cparse", "enum elf_class {ELFCLASSNONE=0, ELFCLASS32=1, ELFCLASS64=2};", 0);
	sdb_set(bin->kv, "elf_data.cparse", "enum elf_data {ELFDATANONE=0, ELFDATA2LSB=1, ELFDATA2MSB=2};", 0);
	sdb_set(bin->kv, "elf_hdr_version.cparse", "enum elf_hdr_version {EV_NONE=0, EV_CURRENT=1};", 0);
	sdb_set(bin->kv, "elf_obj_version.cparse", "enum elf_obj_version {EV_NONE=0, EV_CURRENT=1};", 0);
	sdb_num_set(bin->kv, "elf_header.offset", 0, 0);
	sdb_num_set(bin->kv, "elf_header.size", sizeof(Elf_(Ehdr)), 0);
	sdb_set(bin->kv, "elf_ident.format", "[4]z[1]E[1]E[1]E.::"
					     " magic (elf_class)class (elf_data)data (elf_hdr_version)version",
		0);
#if RZ_BIN_ELF64
	sdb_set(bin->kv, "elf_header.format", "?[2]E[2]E[4]EqqqxN2N2N2N2N2N2"
					      " (elf_ident)ident (elf_type)type (elf_machine)machine (elf_obj_version)version"
					      " entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx",
		0);
#else
	sdb_set(bin->kv, "elf_header.format", "?[2]E[2]E[4]ExxxxN2N2N2N2N2N2"
					      " (elf_ident)ident (elf_type)type (elf_machine)machine (elf_obj_version)version"
					      " entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx",
		0);
#endif
	bin->endian = (e_ident[EI_DATA] == ELFDATA2MSB) ? 1 : 0;
	memset(&bin->ehdr, 0, sizeof(Elf_(Ehdr)));
	len = rz_buf_read_at(bin->b, 0, ehdr, sizeof(ehdr));
	if (len < 32) { // tinyelf != sizeof (Elf_(Ehdr))) {
		bprintf("read (ehdr)\n");
		return false;
	}
	// XXX no need to check twice
	memcpy(&bin->ehdr.e_ident, ehdr, 16);
	if (!__is_valid_ident(bin)) {
		return false;
	}
	i = 16;
	// TODO: use rz_read or rz_buf_read_ apis instead
	bin->ehdr.e_type = READ16(ehdr, i);
	bin->ehdr.e_machine = READ16(ehdr, i);
	bin->ehdr.e_version = READ32(ehdr, i);
#if RZ_BIN_ELF64
	bin->ehdr.e_entry = READ64(ehdr, i);
	bin->ehdr.e_phoff = READ64(ehdr, i);
	bin->ehdr.e_shoff = READ64(ehdr, i);
#else
	bin->ehdr.e_entry = READ32(ehdr, i);
	bin->ehdr.e_phoff = READ32(ehdr, i);
	bin->ehdr.e_shoff = READ32(ehdr, i);
#endif
	bin->ehdr.e_flags = READ32(ehdr, i);
	bin->ehdr.e_ehsize = READ16(ehdr, i);
	bin->ehdr.e_phentsize = READ16(ehdr, i);
	bin->ehdr.e_phnum = READ16(ehdr, i);
	bin->ehdr.e_shentsize = READ16(ehdr, i);
	bin->ehdr.e_shnum = READ16(ehdr, i);
	bin->ehdr.e_shstrndx = READ16(ehdr, i);
	return true;
	// [Outdated] Usage example:
	// > td `k bin/cur/info/elf_type.cparse`; td `k bin/cur/info/elf_machine.cparse`
	// > pf `k bin/cur/info/elf_header.format` @ `k bin/cur/info/elf_header.offset`
}

static bool read_phdr(ELFOBJ *bin, bool linux_kernel_hack) {
	bool phdr_found = false;
	int i;
#if RZ_BIN_ELF64
	const bool is_elf64 = true;
#else
	const bool is_elf64 = false;
#endif
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		ut8 phdr[sizeof(Elf_(Phdr))] = { 0 };
		int j = 0;
		const size_t rsize = bin->ehdr.e_phoff + i * sizeof(Elf_(Phdr));
		int len = rz_buf_read_at(bin->b, rsize, phdr, sizeof(Elf_(Phdr)));
		if (len < 1) {
			bprintf("read (phdr)\n");
			RZ_FREE(bin->phdr);
			return false;
		}
		bin->phdr[i].p_type = READ32(phdr, j);
		if (bin->phdr[i].p_type == PT_PHDR) {
			phdr_found = true;
		}

		if (is_elf64) {
			bin->phdr[i].p_flags = READ32(phdr, j);
		}
		bin->phdr[i].p_offset = RZ_BIN_ELF_READWORD(phdr, j);
		bin->phdr[i].p_vaddr = RZ_BIN_ELF_READWORD(phdr, j);
		bin->phdr[i].p_paddr = RZ_BIN_ELF_READWORD(phdr, j);
		bin->phdr[i].p_filesz = RZ_BIN_ELF_READWORD(phdr, j);
		bin->phdr[i].p_memsz = RZ_BIN_ELF_READWORD(phdr, j);
		if (!is_elf64) {
			bin->phdr[i].p_flags = READ32(phdr, j);
			//	bin->phdr[i].p_flags |= 1; tiny.elf needs this somehow :? LOAD0 is always +x for linux?
		}
		bin->phdr[i].p_align = RZ_BIN_ELF_READWORD(phdr, j);
	}
	/* Here is the where all the fun starts.
	 * Linux kernel since 2005 calculates phdr offset wrongly
	 * adding it to the load address (va of the LOAD0).
	 * See `fs/binfmt_elf.c` file this line:
	 *    NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
	 * So after the first read, we fix the address and read it again
	 */
	if (linux_kernel_hack && phdr_found) {
		ut64 load_addr = Elf_(rz_bin_elf_get_baddr)(bin);
		bin->ehdr.e_phoff = Elf_(rz_bin_elf_v2p)(bin, load_addr + bin->ehdr.e_phoff);
		return read_phdr(bin, false);
	}
	return true;
}

static int init_phdr(ELFOBJ *bin) {
	ut32 phdr_size;

	rz_return_val_if_fail(!bin->phdr, false);

	if (!bin->ehdr.e_phnum) {
		return false;
	}
	if (!UT32_MUL(&phdr_size, (ut32)bin->ehdr.e_phnum, sizeof(Elf_(Phdr)))) {
		return false;
	}
	if (!phdr_size) {
		return false;
	}
	if (phdr_size > bin->size) {
		return false;
	}
	if (phdr_size > (ut32)bin->size) {
		return false;
	}
	if (bin->ehdr.e_phoff > bin->size) {
		return false;
	}
	if (bin->ehdr.e_phoff + phdr_size > bin->size) {
		return false;
	}
	if (!(bin->phdr = RZ_NEWS0(Elf_(Phdr), bin->ehdr.e_phnum))) {
		perror("malloc (phdr)");
		return false;
	}

	bool linux_kern_hack = false;
	/* Enable this hack only for the X86 64bit ELFs */
	const int _128K = 1024 * 128;
	if (rz_buf_size(bin->b) > _128K && (bin->ehdr.e_machine == EM_X86_64 || bin->ehdr.e_machine == EM_386)) {
		linux_kern_hack = true;
	}
	if (!read_phdr(bin, linux_kern_hack)) {
		return false;
	}

	sdb_num_set(bin->kv, "elf_phdr.offset", bin->ehdr.e_phoff, 0);
	sdb_num_set(bin->kv, "elf_phdr.size", sizeof(Elf_(Phdr)), 0);
	sdb_set(bin->kv, "elf_p_type.cparse", "enum elf_p_type {PT_NULL=0,PT_LOAD=1,PT_DYNAMIC=2,"
					      "PT_INTERP=3,PT_NOTE=4,PT_SHLIB=5,PT_PHDR=6,PT_LOOS=0x60000000,"
					      "PT_HIOS=0x6fffffff,PT_LOPROC=0x70000000,PT_HIPROC=0x7fffffff};",
		0);
	sdb_set(bin->kv, "elf_p_flags.cparse", "enum elf_p_flags {PF_None=0,PF_Exec=1,"
					       "PF_Write=2,PF_Write_Exec=3,PF_Read=4,PF_Read_Exec=5,PF_Read_Write=6,"
					       "PF_Read_Write_Exec=7};",
		0);
#if RZ_BIN_ELF64
	sdb_set(bin->kv, "elf_phdr.format", "[4]E[4]Eqqqqqq (elf_p_type)type (elf_p_flags)flags"
					    " offset vaddr paddr filesz memsz align",
		0);
#else
	sdb_set(bin->kv, "elf_phdr.format", "[4]Exxxxx[4]Ex (elf_p_type)type offset vaddr paddr"
					    " filesz memsz (elf_p_flags)flags align",
		0);
#endif
	return true;
	// Usage example:
	// > td `k bin/cur/info/elf_p_type.cparse`; td `k bin/cur/info/elf_p_flags.cparse`
	// > pf `k bin/cur/info/elf_phdr.format` @ `k bin/cur/info/elf_phdr.offset`
}

/// Parse NT_PRSTATUS note
static void parse_note_prstatus(RzBinElfNote *note, Elf_(Nhdr) * nhdr, ELFOBJ *bin, ut64 offset) {
	RzBinElfPrStatusLayout *layout = Elf_(rz_bin_elf_get_prstatus_layout)(bin);
	if (!layout) {
		eprintf("Fetching registers from core file not supported for this architecture.\n");
		return;
	}
	ut8 *buf = malloc(layout->regsize);
	if (!buf) {
		return;
	}
	if (rz_buf_read_at(bin->b, offset + layout->regdelta, buf, layout->regsize) != layout->regsize) {
		free(buf);
		bprintf("Cannot read register state from CORE file\n");
		return;
	}
	note->prstatus.regstate_size = layout->regsize;
	note->prstatus.regstate = buf;
}

/// Parse NT_FILE note
static void parse_note_file(RzBinElfNote *note, Elf_(Nhdr) * nhdr, ELFOBJ *bin, ut64 offset) {
	if (nhdr->n_descsz < RZ_BIN_ELF_WORDSIZE * 2) {
		return;
	}
	ut64 n_maps = RZ_BIN_ELF_BREADWORD(bin->b, offset);
	if (n_maps > (ut64)SIZE_MAX) {
		return;
	}
	RzVector files;
	rz_vector_init(&files, sizeof(RzBinElfNoteFile), NULL, NULL);
	rz_vector_reserve(&files, n_maps);
	(void)RZ_BIN_ELF_BREADWORD(bin->b, offset); // skip page size
	ut64 offset_begin = offset;
	ut64 strings_begin = ((RZ_BIN_ELF_WORDSIZE * 3) * n_maps); // offset after the addr-array
	ut64 len_str = 0;
	while (n_maps-- && strings_begin + len_str < nhdr->n_descsz) {
		char str[512] = { 0 };
		st64 r = rz_buf_read_at(bin->b, offset_begin + strings_begin + len_str, (ut8 *)str, sizeof(str) - 1);
		if (r < 0) {
			break;
		}
		str[r] = 0;
		len_str += strlen(str) + 1;
		RzBinElfNoteFile *f = rz_vector_push(&files, NULL);
		if (!f) {
			break;
		}
		f->start_vaddr = RZ_BIN_ELF_BREADWORD(bin->b, offset);
		f->end_vaddr = RZ_BIN_ELF_BREADWORD(bin->b, offset);
		f->file_off = RZ_BIN_ELF_BREADWORD(bin->b, offset);
		f->file = strdup(str);
	}
	note->file.files_count = rz_vector_len(&files);
	note->file.files = rz_vector_flush(&files);
	rz_vector_fini(&files);
}

static void note_fini(RzBinElfNote *note) {
	switch (note->type) {
	case NT_FILE:
		for (size_t i = 0; i < note->file.files_count; i++) {
			free(note->file.files[i].file);
		}
		free(note->file.files);
		break;
	case NT_PRSTATUS:
		free(note->prstatus.regstate);
		break;
	}
}

static void note_segment_free(RzBinElfNoteSegment *seg) {
	if (!seg) {
		return;
	}
	if (seg->notes) {
		for (size_t i = 0; i < seg->notes_count; i++) {
			note_fini(&seg->notes[i]);
		}
		free(seg->notes);
	}
	free(seg);
}

/// Parse PT_NOTE segments, which are used in core files for cpu state, etc.
static bool init_notes(ELFOBJ *bin) {
	bin->note_segments = rz_list_newf((RzListFree)note_segment_free);
	if (!bin->note_segments) {
		return false;
	}
	ut16 ph, ph_num = bin->ehdr.e_phnum;
	for (ph = 0; ph < ph_num; ph++) {
		Elf_(Phdr) *p = &bin->phdr[ph];
		if (p->p_type != PT_NOTE || p->p_filesz < 9) {
			// not a note with at least size for one header
			continue;
		}
		if (p->p_offset + p->p_filesz < p->p_offset) {
			// don't overflow
			return false;
		}
		RzBinElfNoteSegment *seg = RZ_NEW0(RzBinElfNoteSegment);
		if (!seg) {
			return false;
		}
		RzVector notes;
		rz_vector_init(&notes, sizeof(RzBinElfNote), NULL, NULL);

		ut64 offset = p->p_offset;
		ut64 buf_sz = rz_buf_size(bin->b);
		while (offset + 9 < RZ_MIN(p->p_offset + p->p_filesz, buf_sz)) {
			Elf_(Nhdr) nhdr;
			nhdr.n_namesz = BREAD32(bin->b, offset);
			nhdr.n_descsz = BREAD32(bin->b, offset);
			nhdr.n_type = BREAD32(bin->b, offset);

			if (p->p_filesz < offset - p->p_offset + round_up(nhdr.n_namesz) + round_up(nhdr.n_descsz)) {
				// segment too small
				break;
			}

			// skip name, not needed for us
			offset += round_up(nhdr.n_namesz);

			RzBinElfNote *note = rz_vector_push(&notes, NULL);
			memset(note, 0, sizeof(*note));
			note->type = nhdr.n_type;

			// there are many more note types but for now we only need these:
			switch (nhdr.n_type) {
			case NT_FILE:
				parse_note_file(note, &nhdr, bin, offset);
				break;
			case NT_PRSTATUS:
				parse_note_prstatus(note, &nhdr, bin, offset);
				break;
			}

			offset += round_up(nhdr.n_descsz);
		}

		seg->notes_count = rz_vector_len(&notes);
		seg->notes = rz_vector_flush(&notes);
		rz_vector_fini(&notes);
		rz_list_push(bin->note_segments, seg);
	}
	return true;
}

static int init_shdr(ELFOBJ *bin) {
	ut32 shdr_size;
	ut8 shdr[sizeof(Elf_(Shdr))] = { 0 };
	int i, j, len;

	rz_return_val_if_fail(bin && !bin->shdr, false);

	if (!UT32_MUL(&shdr_size, bin->ehdr.e_shnum, sizeof(Elf_(Shdr)))) {
		return false;
	}
	if (shdr_size < 1) {
		return false;
	}
	if (shdr_size > bin->size) {
		return false;
	}
	if (bin->ehdr.e_shoff > bin->size) {
		return false;
	}
	if (bin->ehdr.e_shoff + shdr_size > bin->size) {
		return false;
	}
	if (!(bin->shdr = RZ_NEWS0(Elf_(Shdr), bin->ehdr.e_shnum))) {
		perror("malloc (shdr)");
		return false;
	}
	sdb_num_set(bin->kv, "elf_shdr.offset", bin->ehdr.e_shoff, 0);
	sdb_num_set(bin->kv, "elf_shdr.size", sizeof(Elf_(Shdr)), 0);
	sdb_set(bin->kv, "elf_s_type.cparse", "enum elf_s_type {SHT_NULL=0,SHT_PROGBITS=1,"
					      "SHT_SYMTAB=2,SHT_STRTAB=3,SHT_RELA=4,SHT_HASH=5,SHT_DYNAMIC=6,SHT_NOTE=7,"
					      "SHT_NOBITS=8,SHT_REL=9,SHT_SHLIB=10,SHT_DYNSYM=11,SHT_LOOS=0x60000000,"
					      "SHT_HIOS=0x6fffffff,SHT_LOPROC=0x70000000,SHT_HIPROC=0x7fffffff};",
		0);

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		j = 0;
		len = rz_buf_read_at(bin->b, bin->ehdr.e_shoff + i * sizeof(Elf_(Shdr)), shdr, sizeof(Elf_(Shdr)));
		if (len < 1) {
			bprintf("read (shdr) at 0x%" PFMT64x "\n", (ut64)bin->ehdr.e_shoff);
			RZ_FREE(bin->shdr);
			return false;
		}
		bin->shdr[i].sh_name = READ32(shdr, j);
		bin->shdr[i].sh_type = READ32(shdr, j);
		bin->shdr[i].sh_flags = RZ_BIN_ELF_READWORD(shdr, j);
		bin->shdr[i].sh_addr = RZ_BIN_ELF_READWORD(shdr, j);
		bin->shdr[i].sh_offset = RZ_BIN_ELF_READWORD(shdr, j);
		bin->shdr[i].sh_size = RZ_BIN_ELF_READWORD(shdr, j);
		bin->shdr[i].sh_link = READ32(shdr, j);
		bin->shdr[i].sh_info = READ32(shdr, j);
		bin->shdr[i].sh_addralign = RZ_BIN_ELF_READWORD(shdr, j);
		bin->shdr[i].sh_entsize = RZ_BIN_ELF_READWORD(shdr, j);
	}

#if RZ_BIN_ELF64
	sdb_set(bin->kv, "elf_s_flags_64.cparse", "enum elf_s_flags_64 {SF64_None=0,SF64_Exec=1,"
						  "SF64_Alloc=2,SF64_Alloc_Exec=3,SF64_Write=4,SF64_Write_Exec=5,"
						  "SF64_Write_Alloc=6,SF64_Write_Alloc_Exec=7};",
		0);
	sdb_set(bin->kv, "elf_shdr.format", "x[4]E[8]Eqqqxxqq name (elf_s_type)type"
					    " (elf_s_flags_64)flags addr offset size link info addralign entsize",
		0);
#else
	sdb_set(bin->kv, "elf_s_flags_32.cparse", "enum elf_s_flags_32 {SF32_None=0,SF32_Exec=1,"
						  "SF32_Alloc=2,SF32_Alloc_Exec=3,SF32_Write=4,SF32_Write_Exec=5,"
						  "SF32_Write_Alloc=6,SF32_Write_Alloc_Exec=7};",
		0);
	sdb_set(bin->kv, "elf_shdr.format", "x[4]E[4]Exxxxxxx name (elf_s_type)type"
					    " (elf_s_flags_32)flags addr offset size link info addralign entsize",
		0);
#endif
	return true;
	// Usage example:
	// > td `k bin/cur/info/elf_s_type.cparse`; td `k bin/cur/info/elf_s_flags_64.cparse`
	// > pf `k bin/cur/info/elf_shdr.format` @ `k bin/cur/info/elf_shdr.offset`
}

static int init_strtab(ELFOBJ *bin) {
	rz_return_val_if_fail(!bin->strtab, false);

	if (!bin->shdr) {
		return false;
	}

	Elf_(Half) shstrndx = bin->ehdr.e_shstrndx;
	if (shstrndx != SHN_UNDEF && !Elf_(rz_bin_elf_is_sh_index_valid)(bin, shstrndx)) {
		return false;
	}

	/* sh_size must be lower than UT32_MAX and not equal to zero, to avoid bugs on malloc() */
	if (bin->shdr[shstrndx].sh_size > UT32_MAX) {
		return false;
	}
	if (!bin->shdr[shstrndx].sh_size) {
		return false;
	}
	bin->shstrtab_section = bin->strtab_section = &bin->shdr[shstrndx];
	bin->shstrtab_size = bin->shstrtab_section->sh_size;
	if (bin->shstrtab_size > bin->size) {
		return false;
	}
	if (bin->shstrtab_section->sh_offset > bin->size) {
		return false;
	}
	if (bin->shstrtab_section->sh_offset + bin->shstrtab_section->sh_size > bin->size) {
		return false;
	}

	if (!(bin->shstrtab = calloc(1, bin->shstrtab_size + 1))) {
		perror("malloc");
		bin->shstrtab = NULL;
		return false;
	}
	int res = rz_buf_read_at(bin->b, bin->shstrtab_section->sh_offset, (ut8 *)bin->shstrtab,
		bin->shstrtab_section->sh_size);
	if (res < 1) {
		bprintf("read (shstrtab) at 0x%" PFMT64x "\n", (ut64)bin->shstrtab_section->sh_offset);
		RZ_FREE(bin->shstrtab);
		return false;
	}
	bin->shstrtab[bin->shstrtab_section->sh_size] = '\0';

	sdb_num_set(bin->kv, "elf_shstrtab.offset", bin->shstrtab_section->sh_offset, 0);
	sdb_num_set(bin->kv, "elf_shstrtab.size", bin->shstrtab_section->sh_size, 0);

	return true;
}

static bool init_dynstr(ELFOBJ *bin) {
	int i, r;
	const char *section_name = NULL;
	if (!bin || !bin->shdr) {
		return false;
	}
	if (!bin->shstrtab) {
		return false;
	}
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (bin->shdr[i].sh_name > bin->shstrtab_size) {
			return false;
		}
		section_name = &bin->shstrtab[bin->shdr[i].sh_name];
		if (bin->shdr[i].sh_type == SHT_STRTAB && !strcmp(section_name, ".dynstr")) {
			if (!(bin->dynstr = (char *)calloc(bin->shdr[i].sh_size + 1, sizeof(char)))) {
				bprintf("Cannot allocate memory for dynamic strings\n");
				return false;
			}
			if (bin->shdr[i].sh_offset > bin->size) {
				return false;
			}
			if (bin->shdr[i].sh_offset + bin->shdr[i].sh_size > bin->size) {
				return false;
			}
			if (bin->shdr[i].sh_offset + bin->shdr[i].sh_size < bin->shdr[i].sh_size) {
				return false;
			}
			r = rz_buf_read_at(bin->b, bin->shdr[i].sh_offset, (ut8 *)bin->dynstr, bin->shdr[i].sh_size);
			if (r < 1) {
				RZ_FREE(bin->dynstr);
				bin->dynstr_size = 0;
				return false;
			}
			bin->dynstr_size = bin->shdr[i].sh_size;
			return true;
		}
	}
	return false;
}

static bool fill_dynamic_entry(ELFOBJ *bin, ut64 entry_offset, Elf_(Dyn) * d) {
	ut8 sdyn[sizeof(Elf_(Dyn))] = { 0 };
	int j = 0;
	int len = rz_buf_read_at(bin->b, entry_offset, sdyn, sizeof(Elf_(Dyn)));
	if (len < 1) {
		return false;
	}

	d->d_tag = RZ_BIN_ELF_READWORD(sdyn, j);
	d->d_un.d_ptr = RZ_BIN_ELF_READWORD(sdyn, j);

	return true;
}

static size_t get_maximum_number_of_dynamic_entries(ut64 dyn_size) {
	return dyn_size / sizeof(Elf_(Dyn));
}

static void fill_dynamic_entries(ELFOBJ *bin, ut64 loaded_offset, ut64 dyn_size) {
	Elf_(Dyn) d = { 0 };
	size_t i;
	size_t number_of_entries = get_maximum_number_of_dynamic_entries(dyn_size);

	for (i = 0; i < number_of_entries; i++) {
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
		case DT_GNU_HASH:
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

static void set_default_value_dynamic_info(ELFOBJ *bin) {
	bin->dyn_info.dt_init = 0;
	bin->dyn_info.dt_fini = 0;
	bin->dyn_info.dt_pltrelsz = 0;
	bin->dyn_info.dt_pltgot = RZ_BIN_ELF_ADDR_MAX;
	bin->dyn_info.dt_hash = RZ_BIN_ELF_ADDR_MAX;
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

static void init_dynamic_section_sdb(ELFOBJ *bin, Elf_(Addr) strtabaddr, size_t strsize) {
	int r = Elf_(rz_bin_elf_has_relro)(bin);
	switch (r) {
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
	sdb_num_set(bin->kv, "elf_strtab.offset", strtabaddr, 0);
	sdb_num_set(bin->kv, "elf_strtab.size", strsize, 0);
}

static Elf_(Phdr) * get_dynamic_segment(ELFOBJ *bin) {
	int i;
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_DYNAMIC) {
			if (bin->phdr[i].p_filesz > bin->size) {
				return NULL;
			}
			if (bin->phdr[i].p_offset > bin->size) {
				return NULL;
			}
			if (bin->phdr[i].p_offset + sizeof(Elf_(Dyn)) > bin->size) {
				return NULL;
			}
			return &bin->phdr[i];
		}
	}
	return NULL;
}

static int init_dynamic_section(ELFOBJ *bin) {
	ut64 strtabaddr = 0;
	char *strtab = NULL;
	size_t strsize = 0;
	int r;
	ut64 dyn_size = 0, loaded_offset;
	set_default_value_dynamic_info(bin);

	rz_return_val_if_fail(bin, false);
	if (!bin->phdr || !bin->ehdr.e_phnum) {
		return false;
	}

	Elf_(Phdr) *dyn_phdr = get_dynamic_segment(bin);
	if (!dyn_phdr) {
		return false;
	}

	dyn_size = dyn_phdr->p_filesz;
	loaded_offset = Elf_(rz_bin_elf_v2p_new)(bin, dyn_phdr->p_vaddr);
	if (loaded_offset == UT64_MAX) {
		return false;
	}

	if (!dyn_size || loaded_offset + dyn_size > bin->size) {
		return false;
	}

	fill_dynamic_entries(bin, loaded_offset, dyn_size);

	if (bin->dyn_info.dt_strtab != RZ_BIN_ELF_ADDR_MAX) {
		strtabaddr = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_strtab);
	}

	if (bin->dyn_info.dt_strsz > 0) {
		strsize = bin->dyn_info.dt_strsz;
	}

	if (strtabaddr == UT64_MAX || strtabaddr > bin->size || strsize > ST32_MAX || !strsize || strsize > bin->size || strtabaddr + strsize > bin->size) {
		if (!strtabaddr) {
			bprintf("DT_STRTAB not found or invalid\n");
		}
		return false;
	}
	strtab = (char *)calloc(1, strsize + 1);
	if (!strtab) {
		return false;
	}
	r = rz_buf_read_at(bin->b, strtabaddr, (ut8 *)strtab, strsize);
	if (r < 1) {
		free(strtab);
		return false;
	}

	bin->strtab = strtab;
	bin->strtab_size = strsize;
	init_dynamic_section_sdb(bin, strtabaddr, strsize);
	return true;
}

static Sdb *store_versioninfo_gnu_versym(ELFOBJ *bin, Elf_(Shdr) * shdr, int sz) {
	size_t i;
	const ut64 num_entries = sz / sizeof(Elf_(Versym));
	const char *section_name = "";
	const char *link_section_name = "";
	Sdb *sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	if (!bin->version_info[DT_VERSIONTAGIDX(DT_VERSYM)]) {
		sdb_free(sdb);
		return NULL;
	}
	if (shdr->sh_link >= bin->ehdr.e_shnum) {
		sdb_free(sdb);
		return NULL;
	}
	Elf_(Shdr) *link_shdr = &bin->shdr[shdr->sh_link];
	ut8 *edata = (ut8 *)calloc(RZ_MAX(1, num_entries), 2 * sizeof(ut8));
	if (!edata) {
		sdb_free(sdb);
		return NULL;
	}
	ut16 *data = (ut16 *)calloc(RZ_MAX(1, num_entries), sizeof(ut16));
	if (!data) {
		free(edata);
		sdb_free(sdb);
		return NULL;
	}
	ut64 off = Elf_(rz_bin_elf_v2p)(bin, bin->version_info[DT_VERSIONTAGIDX(DT_VERSYM)]);
	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
		section_name = &bin->shstrtab[shdr->sh_name];
	}
	if (bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
		link_section_name = &bin->shstrtab[link_shdr->sh_name];
	}
	rz_buf_read_at(bin->b, off, edata, sizeof(ut16) * num_entries);
	sdb_set(sdb, "section_name", section_name, 0);
	sdb_num_set(sdb, "num_entries", num_entries, 0);
	sdb_num_set(sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set(sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set(sdb, "link", shdr->sh_link, 0);
	sdb_set(sdb, "link_section_name", link_section_name, 0);
	for (i = num_entries; i--;) {
		data[i] = rz_read_ble16(&edata[i * sizeof(ut16)], bin->endian);
	}
	RZ_FREE(edata);
	char *tmp_val = NULL;
	for (i = 0; i < num_entries; i += 4) {
		size_t j;
		int check_def;
		char key[32] = { 0 };

		for (j = 0; (j < 4) && (i + j) < num_entries; j++) {
			int k;
			snprintf(key, sizeof(key), "entry%zd", i + j);
			switch (data[i + j]) {
			case 0:
				sdb_set(sdb, key, "0 (*local*)", 0);
				break;
			case 1:
				sdb_set(sdb, key, "1 (*global*)", 0);
				break;
			default:
				free(tmp_val);
				tmp_val = strdup(sdb_fmt("%x ", data[i + j] & 0x7FFF));
				check_def = true;
				if (bin->version_info[DT_VERSIONTAGIDX(DT_VERNEED)]) {
					Elf_(Verneed) vn;
					ut8 svn[sizeof(Elf_(Verneed))] = { 0 };
					ut64 offset = Elf_(rz_bin_elf_v2p)(bin, bin->version_info[DT_VERSIONTAGIDX(DT_VERNEED)]);
					do {
						Elf_(Vernaux) vna;
						ut8 svna[sizeof(Elf_(Vernaux))] = { 0 };
						ut64 a_off;
						if (offset > bin->size || offset + sizeof(vn) > bin->size) {
							goto beach;
						}
						if (rz_buf_read_at(bin->b, offset, svn, sizeof(svn)) < 0) {
							bprintf("Cannot read Verneed for Versym\n");
							goto beach;
						}
						k = 0;
						vn.vn_version = READ16(svn, k);
						vn.vn_cnt = READ16(svn, k);
						vn.vn_file = READ32(svn, k);
						vn.vn_aux = READ32(svn, k);
						vn.vn_next = READ32(svn, k);
						a_off = offset + vn.vn_aux;
						do {
							if (a_off > bin->size || a_off + sizeof(vna) > bin->size) {
								goto beach;
							}
							if (rz_buf_read_at(bin->b, a_off, svna, sizeof(svna)) < 0) {
								bprintf("Cannot read Vernaux for Versym\n");
								goto beach;
							}
							k = 0;
							vna.vna_hash = READ32(svna, k);
							vna.vna_flags = READ16(svna, k);
							vna.vna_other = READ16(svna, k);
							vna.vna_name = READ32(svna, k);
							vna.vna_next = READ32(svna, k);
							a_off += vna.vna_next;
						} while (vna.vna_other != data[i + j] && vna.vna_next != 0);

						if (vna.vna_other == data[i + j]) {
							if (vna.vna_name > bin->strtab_size) {
								goto beach;
							}
							sdb_set(sdb, key, sdb_fmt("%s(%s)", tmp_val, bin->strtab + vna.vna_name), 0);
							check_def = false;
							break;
						}
						offset += vn.vn_next;
					} while (vn.vn_next);
				}

				ut64 vinfoaddr = bin->version_info[DT_VERSIONTAGIDX(DT_VERDEF)];
				if (check_def && data[i + j] != 0x8001 && vinfoaddr) {
					Elf_(Verdef) vd;
					ut8 svd[sizeof(Elf_(Verdef))] = { 0 };
					ut64 offset = Elf_(rz_bin_elf_v2p)(bin, vinfoaddr);
					if (offset > bin->size || offset + sizeof(vd) > bin->size) {
						goto beach;
					}
					do {
						if (rz_buf_read_at(bin->b, offset, svd, sizeof(svd)) < 0) {
							bprintf("Cannot read Verdef for Versym\n");
							goto beach;
						}
						k = 0;
						vd.vd_version = READ16(svd, k);
						vd.vd_flags = READ16(svd, k);
						vd.vd_ndx = READ16(svd, k);
						vd.vd_cnt = READ16(svd, k);
						vd.vd_hash = READ32(svd, k);
						vd.vd_aux = READ32(svd, k);
						vd.vd_next = READ32(svd, k);
						offset += vd.vd_next;
					} while (vd.vd_ndx != (data[i + j] & 0x7FFF) && vd.vd_next != 0);

					if (vd.vd_ndx == (data[i + j] & 0x7FFF)) {
						Elf_(Verdaux) vda;
						ut8 svda[sizeof(Elf_(Verdaux))] = { 0 };
						ut64 off_vda = offset - vd.vd_next + vd.vd_aux;
						if (off_vda > bin->size || off_vda + sizeof(vda) > bin->size) {
							goto beach;
						}
						if (rz_buf_read_at(bin->b, off_vda, svda, sizeof(svda)) < 0) {
							bprintf("Cannot read Verdaux for Versym\n");
							goto beach;
						}
						k = 0;
						vda.vda_name = READ32(svda, k);
						vda.vda_next = READ32(svda, k);
						if (vda.vda_name > bin->strtab_size) {
							goto beach;
						}
						const char *name = bin->strtab + vda.vda_name;
						if (name) {
							const char *fname = sdb_fmt("%s(%s%-*s)", tmp_val, name, (int)(12 - strlen(name)), ")");
							sdb_set(sdb, key, fname, 0);
						}
					}
				}
			}
		}
		RZ_FREE(tmp_val);
	}
beach:
	RZ_FREE(tmp_val);
	free(data);
	return sdb;
}

static char *get_ver_flags(ut32 flags) {
	static char buff[32];
	buff[0] = 0;

	if (!flags) {
		return "none";
	}
	if (flags & VER_FLG_BASE) {
		strcpy(buff, "BASE ");
	}
	if (flags & VER_FLG_WEAK) {
		if (flags & VER_FLG_BASE) {
			strcat(buff, "| ");
		}
		strcat(buff, "WEAK ");
	}

	if (flags & ~(VER_FLG_BASE | VER_FLG_WEAK)) {
		strcat(buff, "| <unknown>");
	}
	return buff;
}

static Sdb *store_versioninfo_gnu_verdef(ELFOBJ *bin, Elf_(Shdr) * shdr, int sz) {
	const char *section_name = "";
	const char *link_section_name = "";
	char *end = NULL;
	ut8 dfs[sizeof(Elf_(Verdef))] = { 0 };
	Sdb *sdb;
	ut32 cnt;
	size_t i;
	if (shdr->sh_link >= bin->ehdr.e_shnum) {
		return false;
	}
	Elf_(Shdr) *link_shdr = &bin->shdr[shdr->sh_link];
#ifdef RZ_BIN_ELF64
	if ((int)shdr->sh_size < 1 || shdr->sh_size > SIZE_MAX) {
#else
	if ((int)shdr->sh_size < 1) {
#endif
		return false;
	}
	if (shdr->sh_size < sizeof(Elf_(Verdef)) || shdr->sh_size < sizeof(Elf_(Verdaux))) {
		return false;
	}
	Elf_(Verdef) *defs = calloc(shdr->sh_size, 1);
	if (!defs) {
		bprintf("Cannot allocate memory (Check Elf_(Verdef))\n");
		return false;
	}
	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
		section_name = &bin->shstrtab[shdr->sh_name];
	}
	if (link_shdr && bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
		link_section_name = &bin->shstrtab[link_shdr->sh_name];
	}
	sdb = sdb_new0();
	end = (char *)defs + shdr->sh_size;
	sdb_set(sdb, "section_name", section_name, 0);
	sdb_num_set(sdb, "entries", shdr->sh_info, 0);
	sdb_num_set(sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set(sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set(sdb, "link", shdr->sh_link, 0);
	sdb_set(sdb, "link_section_name", link_section_name, 0);

	for (cnt = 0, i = 0; cnt < shdr->sh_info && i < shdr->sh_size; cnt++) {
		Sdb *sdb_verdef = sdb_new0();
		char *vstart = ((char *)defs) + i;
		size_t vstart_off = i;
		char key[32] = { 0 };
		Elf_(Verdef) *verdef = (Elf_(Verdef) *)vstart;
		Elf_(Verdaux) aux = { 0 };
		int j = 0;
		int isum = 0;

		if (vstart + sizeof(*verdef) > end) {
			break;
		}
		rz_buf_read_at(bin->b, shdr->sh_offset + i, dfs, sizeof(Elf_(Verdef)));
		verdef->vd_version = READ16(dfs, j);
		verdef->vd_flags = READ16(dfs, j);
		verdef->vd_ndx = READ16(dfs, j);
		verdef->vd_cnt = READ16(dfs, j);
		verdef->vd_hash = READ32(dfs, j);
		verdef->vd_aux = READ32(dfs, j);
		verdef->vd_next = READ32(dfs, j);
		int vdaux = verdef->vd_aux;
		if (vdaux < 1 || shdr->sh_size - vstart_off < vdaux) {
			sdb_free(sdb_verdef);
			goto out_error;
		}
		vstart += vdaux;
		vstart_off += vdaux;
		if (vstart > end || shdr->sh_size - sizeof(Elf_(Verdaux)) < vstart_off) {
			sdb_free(sdb_verdef);
			goto out_error;
		}

		j = 0;
		aux.vda_name = READ32(vstart, j);
		aux.vda_next = READ32(vstart, j);

		isum = i + verdef->vd_aux;
		if (aux.vda_name > bin->dynstr_size) {
			sdb_free(sdb_verdef);
			goto out_error;
		}

		sdb_num_set(sdb_verdef, "idx", i, 0);
		sdb_num_set(sdb_verdef, "vd_version", verdef->vd_version, 0);
		sdb_num_set(sdb_verdef, "vd_ndx", verdef->vd_ndx, 0);
		sdb_num_set(sdb_verdef, "vd_cnt", verdef->vd_cnt, 0);
		sdb_set(sdb_verdef, "vda_name", &bin->dynstr[aux.vda_name], 0);
		sdb_set(sdb_verdef, "flags", get_ver_flags(verdef->vd_flags), 0);

		for (j = 1; j < verdef->vd_cnt; j++) {
			int k;
			Sdb *sdb_parent = sdb_new0();
			if (shdr->sh_size - vstart_off < aux.vda_next) {
				sdb_free(sdb_verdef);
				sdb_free(sdb_parent);
				goto out_error;
			}
			isum += aux.vda_next;
			vstart += aux.vda_next;
			vstart_off += aux.vda_next;
			if (vstart > end || shdr->sh_size - sizeof(Elf_(Verdaux)) < vstart_off) {
				sdb_free(sdb_verdef);
				sdb_free(sdb_parent);
				goto out_error;
			}
			k = 0;
			aux.vda_name = READ32(vstart, k);
			aux.vda_next = READ32(vstart, k);
			if (aux.vda_name > bin->dynstr_size) {
				sdb_free(sdb_verdef);
				sdb_free(sdb_parent);
				goto out_error;
			}
			sdb_num_set(sdb_parent, "idx", isum, 0);
			sdb_num_set(sdb_parent, "parent", j, 0);
			sdb_set(sdb_parent, "vda_name", &bin->dynstr[aux.vda_name], 0);
			snprintf(key, sizeof(key), "parent%d", j - 1);
			sdb_ns_set(sdb_verdef, key, sdb_parent);
		}

		snprintf(key, sizeof(key), "verdef%u", cnt);
		sdb_ns_set(sdb, key, sdb_verdef);
		if (!verdef->vd_next || shdr->sh_size - i < verdef->vd_next) {
			sdb_free(sdb_verdef);
			goto out_error;
		}
		if ((st32)verdef->vd_next < 1) {
			bprintf("Invalid vd_next in the ELF version\n");
			break;
		}
		i += verdef->vd_next;
	}
	free(defs);
	return sdb;
out_error:
	free(defs);
	sdb_free(sdb);
	return NULL;
}

static Sdb *store_versioninfo_gnu_verneed(ELFOBJ *bin, Elf_(Shdr) * shdr, int sz) {
	ut8 *end, *need = NULL;
	const char *section_name = "";
	Elf_(Shdr) *link_shdr = NULL;
	const char *link_section_name = "";
	Sdb *sdb_vernaux = NULL;
	Sdb *sdb_version = NULL;
	Sdb *sdb = NULL;
	ut64 i;
	int cnt;

	if (!bin || !bin->dynstr) {
		return NULL;
	}
	if (shdr->sh_link >= bin->ehdr.e_shnum) {
		return NULL;
	}
#ifdef RZ_BIN_ELF64
	if ((int)shdr->sh_size < 1 || shdr->sh_size > SIZE_MAX) {
#else
	if ((int)shdr->sh_size < 1) {
#endif
		return NULL;
	}
	sdb = sdb_new0();
	if (!sdb) {
		return NULL;
	}
	link_shdr = &bin->shdr[shdr->sh_link];
	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
		section_name = &bin->shstrtab[shdr->sh_name];
	}
	if (bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
		link_section_name = &bin->shstrtab[link_shdr->sh_name];
	}
	if (!(need = (ut8 *)calloc(RZ_MAX(1, shdr->sh_size), sizeof(ut8)))) {
		bprintf("Cannot allocate memory for Elf_(Verneed)\n");
		goto beach;
	}
	end = need + shdr->sh_size;
	sdb_set(sdb, "section_name", section_name, 0);
	sdb_num_set(sdb, "num_entries", shdr->sh_info, 0);
	sdb_num_set(sdb, "addr", shdr->sh_addr, 0);
	sdb_num_set(sdb, "offset", shdr->sh_offset, 0);
	sdb_num_set(sdb, "link", shdr->sh_link, 0);
	sdb_set(sdb, "link_section_name", link_section_name, 0);

	if (shdr->sh_offset > bin->size || shdr->sh_offset + shdr->sh_size > bin->size) {
		goto beach;
	}
	if (shdr->sh_offset + shdr->sh_size < shdr->sh_size) {
		goto beach;
	}
	i = rz_buf_read_at(bin->b, shdr->sh_offset, need, shdr->sh_size);
	if (i < 1) {
		goto beach;
	}
	//XXX we should use DT_VERNEEDNUM instead of sh_info
	//TODO https://sourceware.org/ml/binutils/2014-11/msg00353.html
	for (i = 0, cnt = 0; cnt < shdr->sh_info; cnt++) {
		int j, isum;
		ut8 *vstart = need + i;
		Elf_(Verneed) vvn = { 0 };
		if (vstart + sizeof(Elf_(Verneed)) > end) {
			goto beach;
		}
		Elf_(Verneed) *entry = &vvn;
		char key[32] = { 0 };
		sdb_version = sdb_new0();
		if (!sdb_version) {
			goto beach;
		}
		j = 0;
		vvn.vn_version = READ16(vstart, j);
		vvn.vn_cnt = READ16(vstart, j);
		vvn.vn_file = READ32(vstart, j);
		vvn.vn_aux = READ32(vstart, j);
		vvn.vn_next = READ32(vstart, j);

		sdb_num_set(sdb_version, "vn_version", entry->vn_version, 0);
		sdb_num_set(sdb_version, "idx", i, 0);
		if (entry->vn_file > bin->dynstr_size) {
			goto beach;
		}
		{
			char *s = rz_str_ndup(&bin->dynstr[entry->vn_file], 16);
			sdb_set(sdb_version, "file_name", s, 0);
			free(s);
		}
		sdb_num_set(sdb_version, "cnt", entry->vn_cnt, 0);
		st32 vnaux = entry->vn_aux;
		if (vnaux < 1) {
			goto beach;
		}
		vstart += vnaux;
		ut32 vn_cnt = entry->vn_cnt;
		for (j = 0, isum = i + entry->vn_aux; j < vn_cnt && vstart + sizeof(Elf_(Vernaux)) <= end; j++) {
			int k;
			Elf_(Vernaux) *aux = NULL;
			Elf_(Vernaux) vaux = { 0 };
			aux = (Elf_(Vernaux) *)&vaux;
			k = 0;
			vaux.vna_hash = READ32(vstart, k);
			vaux.vna_flags = READ16(vstart, k);
			vaux.vna_other = READ16(vstart, k);
			vaux.vna_name = READ32(vstart, k);
			vaux.vna_next = READ32(vstart, k);
			if (aux->vna_name > bin->dynstr_size) {
				goto beach;
			}
#if 1
			sdb_vernaux = sdb_new0();
			if (!sdb_vernaux) {
				goto beach;
			}
			sdb_num_set(sdb_vernaux, "idx", isum, 0);
			if (aux->vna_name > 0 && aux->vna_name + 8 < bin->dynstr_size) {
				char name[16];
				strncpy(name, &bin->dynstr[aux->vna_name], sizeof(name) - 1);
				name[sizeof(name) - 1] = 0;
				sdb_set(sdb_vernaux, "name", name, 0);
			}
			sdb_set(sdb_vernaux, "flags", get_ver_flags(aux->vna_flags), 0);
			sdb_num_set(sdb_vernaux, "version", aux->vna_other, 0);
			isum += aux->vna_next;
			vstart += aux->vna_next;
			snprintf(key, sizeof(key), "vernaux%d", j);
			sdb_ns_set(sdb_version, key, sdb_vernaux);
#else
			char *key = rz_str_newf("vernaux%d", j);
			char *val = rz_str_newf("%d,%s", isum, get_ver_flags(aux->vna_flags));
			sdb_set(sdb_version, key, val, 0);
			free(key);
			free(val);
#endif
		}
		if ((int)entry->vn_next < 0) {
			bprintf("Invalid vn_next\n");
			break;
		}
		i += entry->vn_next;
		snprintf(key, sizeof(key), "version%d", cnt);
		sdb_ns_set(sdb, key, sdb_version);
		//if entry->vn_next is 0 it iterate infinitely
		if (!entry->vn_next) {
			break;
		}
	}
	free(need);
	return sdb;
beach:
	free(need);
	sdb_free(sdb_vernaux);
	sdb_free(sdb_version);
	sdb_free(sdb);
	return NULL;
}

static Sdb *store_versioninfo(ELFOBJ *bin) {
	Sdb *sdb_versioninfo = NULL;
	int num_verdef = 0;
	int num_verneed = 0;
	int num_versym = 0;
	size_t i;

	if (!bin || !bin->shdr) {
		return NULL;
	}
	if (!(sdb_versioninfo = sdb_new0())) {
		return NULL;
	}

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		Sdb *sdb = NULL;
		char key[32] = { 0 };
		int size = bin->shdr[i].sh_size;

		if (size - (i * sizeof(Elf_(Shdr)) > bin->size)) {
			size = bin->size - (i * sizeof(Elf_(Shdr)));
		}
		int left = size - (i * sizeof(Elf_(Shdr)));
		left = RZ_MIN(left, bin->shdr[i].sh_size);
		if (left < 0) {
			break;
		}
		switch (bin->shdr[i].sh_type) {
		case SHT_GNU_verdef:
			sdb = store_versioninfo_gnu_verdef(bin, &bin->shdr[i], left);
			snprintf(key, sizeof(key), "verdef%d", num_verdef++);
			sdb_ns_set(sdb_versioninfo, key, sdb);
			break;
		case SHT_GNU_verneed:
			sdb = store_versioninfo_gnu_verneed(bin, &bin->shdr[i], left);
			snprintf(key, sizeof(key), "verneed%d", num_verneed++);
			sdb_ns_set(sdb_versioninfo, key, sdb);
			break;
		case SHT_GNU_versym:
			sdb = store_versioninfo_gnu_versym(bin, &bin->shdr[i], left);
			snprintf(key, sizeof(key), "versym%d", num_versym++);
			sdb_ns_set(sdb_versioninfo, key, sdb);
			break;
		}
	}

	return sdb_versioninfo;
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

static bool elf_init(ELFOBJ *bin) {
	/* bin is not an ELF */
	if (!init_ehdr(bin)) {
		return false;
	}
	if (!init_phdr(bin) && !Elf_(rz_bin_elf_is_relocatable)(bin)) {
		bprintf("Cannot initialize program headers\n");
	}
	if (bin->ehdr.e_type == ET_CORE) {
		if (!init_notes(bin)) {
			bprintf("Cannot parse PT_NOTE segments\n");
		}
	} else {
		if (!init_shdr(bin)) {
			bprintf("Cannot initialize section headers\n");
		}
		if (!init_strtab(bin)) {
			bprintf("Cannot initialize strings table\n");
		}
		if (!init_dynstr(bin) && !Elf_(rz_bin_elf_is_relocatable)(bin)) {
			bprintf("Cannot initialize dynamic strings\n");
		}
		bin->baddr = Elf_(rz_bin_elf_get_baddr)(bin);
		if (!init_dynamic_section(bin) && !Elf_(rz_bin_elf_is_static)(bin) && !Elf_(rz_bin_elf_is_relocatable)(bin)) {
			bprintf("Cannot initialize dynamic section\n");
		}
	}

	bin->imports_by_ord_size = 0;
	bin->imports_by_ord = NULL;
	bin->symbols_by_ord_size = 0;
	bin->symbols_by_ord = NULL;
	bin->g_sections = Elf_(rz_bin_elf_get_sections)(bin);
	bin->boffset = Elf_(rz_bin_elf_get_boffset)(bin);
	bin->g_relocs = Elf_(rz_bin_elf_get_relocs)(bin);
	bin->rel_cache = rel_cache_new(bin->g_relocs, bin->g_reloc_num);
	sdb_ns_set(bin->kv, "versioninfo", store_versioninfo(bin));
	return true;
}

RZ_OWN ELFOBJ *Elf_(rz_bin_elf_new_buf)(RZ_NONNULL RzBuffer *buf, bool verbose) {
	rz_return_val_if_fail(buf, NULL);

	ELFOBJ *bin = RZ_NEW0(ELFOBJ);
	if (!bin) {
		return NULL;
	}

	bin->kv = sdb_new0();
	bin->size = rz_buf_size(buf);
	bin->verbose = verbose;
	bin->b = rz_buf_ref(buf);

	if (!elf_init(bin)) {
		Elf_(rz_bin_elf_free)(bin);
		return NULL;
	}

	return bin;
}
