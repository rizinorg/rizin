import sys

insn_list = [
    "MIPS_INS_ABSQ_S",
    "MIPS_INS_ADD",
    "MIPS_INS_ADDIUPC",
    "MIPS_INS_ADDIUR1SP",
    "MIPS_INS_ADDIUR2",
    "MIPS_INS_ADDIUS5",
    "MIPS_INS_ADDIUSP",
    "MIPS_INS_ADDQH",
    "MIPS_INS_ADDQH_R",
    "MIPS_INS_ADDQ",
    "MIPS_INS_ADDQ_S",
    "MIPS_INS_ADDSC",
    "MIPS_INS_ADDS_A",
    "MIPS_INS_ADDS_S",
    "MIPS_INS_ADDS_U",
    "MIPS_INS_ADDU16",
    "MIPS_INS_ADDUH",
    "MIPS_INS_ADDUH_R",
    "MIPS_INS_ADDU",
    "MIPS_INS_ADDU_S",
    "MIPS_INS_ADDVI",
    "MIPS_INS_ADDV",
    "MIPS_INS_ADDWC",
    "MIPS_INS_ADD_A",
    "MIPS_INS_ADDI",
    "MIPS_INS_ADDIU",
    "MIPS_INS_ALIGN",
    "MIPS_INS_ALUIPC",
    "MIPS_INS_AND",
    "MIPS_INS_AND16",
    "MIPS_INS_ANDI16",
    "MIPS_INS_ANDI",
    "MIPS_INS_APPEND",
    "MIPS_INS_ASUB_S",
    "MIPS_INS_ASUB_U",
    "MIPS_INS_AUI",
    "MIPS_INS_AUIPC",
    "MIPS_INS_AVER_S",
    "MIPS_INS_AVER_U",
    "MIPS_INS_AVE_S",
    "MIPS_INS_AVE_U",
    "MIPS_INS_B16",
    "MIPS_INS_BADDU",
    "MIPS_INS_BAL",
    "MIPS_INS_BALC",
    "MIPS_INS_BALIGN",
    "MIPS_INS_BBIT0",
    "MIPS_INS_BBIT032",
    "MIPS_INS_BBIT1",
    "MIPS_INS_BBIT132",
    "MIPS_INS_BC",
    "MIPS_INS_BC0F",
    "MIPS_INS_BC0FL",
    "MIPS_INS_BC0T",
    "MIPS_INS_BC0TL",
    "MIPS_INS_BC1EQZ",
    "MIPS_INS_BC1F",
    "MIPS_INS_BC1FL",
    "MIPS_INS_BC1NEZ",
    "MIPS_INS_BC1T",
    "MIPS_INS_BC1TL",
    "MIPS_INS_BC2EQZ",
    "MIPS_INS_BC2F",
    "MIPS_INS_BC2FL",
    "MIPS_INS_BC2NEZ",
    "MIPS_INS_BC2T",
    "MIPS_INS_BC2TL",
    "MIPS_INS_BC3F",
    "MIPS_INS_BC3FL",
    "MIPS_INS_BC3T",
    "MIPS_INS_BC3TL",
    "MIPS_INS_BCLRI",
    "MIPS_INS_BCLR",
    "MIPS_INS_BEQ",
    "MIPS_INS_BEQC",
    "MIPS_INS_BEQL",
    "MIPS_INS_BEQZ16",
    "MIPS_INS_BEQZALC",
    "MIPS_INS_BEQZC",
    "MIPS_INS_BGEC",
    "MIPS_INS_BGEUC",
    "MIPS_INS_BGEZ",
    "MIPS_INS_BGEZAL",
    "MIPS_INS_BGEZALC",
    "MIPS_INS_BGEZALL",
    "MIPS_INS_BGEZALS",
    "MIPS_INS_BGEZC",
    "MIPS_INS_BGEZL",
    "MIPS_INS_BGTZ",
    "MIPS_INS_BGTZALC",
    "MIPS_INS_BGTZC",
    "MIPS_INS_BGTZL",
    "MIPS_INS_BINSLI",
    "MIPS_INS_BINSL",
    "MIPS_INS_BINSRI",
    "MIPS_INS_BINSR",
    "MIPS_INS_BITREV",
    "MIPS_INS_BITSWAP",
    "MIPS_INS_BLEZ",
    "MIPS_INS_BLEZALC",
    "MIPS_INS_BLEZC",
    "MIPS_INS_BLEZL",
    "MIPS_INS_BLTC",
    "MIPS_INS_BLTUC",
    "MIPS_INS_BLTZ",
    "MIPS_INS_BLTZAL",
    "MIPS_INS_BLTZALC",
    "MIPS_INS_BLTZALL",
    "MIPS_INS_BLTZALS",
    "MIPS_INS_BLTZC",
    "MIPS_INS_BLTZL",
    "MIPS_INS_BMNZI",
    "MIPS_INS_BMNZ",
    "MIPS_INS_BMZI",
    "MIPS_INS_BMZ",
    "MIPS_INS_BNE",
    "MIPS_INS_BNEC",
    "MIPS_INS_BNEGI",
    "MIPS_INS_BNEG",
    "MIPS_INS_BNEL",
    "MIPS_INS_BNEZ16",
    "MIPS_INS_BNEZALC",
    "MIPS_INS_BNEZC",
    "MIPS_INS_BNVC",
    "MIPS_INS_BNZ",
    "MIPS_INS_BOVC",
    "MIPS_INS_BPOSGE32",
    "MIPS_INS_BREAK",
    "MIPS_INS_BREAK16",
    "MIPS_INS_BSELI",
    "MIPS_INS_BSEL",
    "MIPS_INS_BSETI",
    "MIPS_INS_BSET",
    "MIPS_INS_BZ",
    "MIPS_INS_BEQZ",
    "MIPS_INS_B",
    "MIPS_INS_BNEZ",
    "MIPS_INS_BTEQZ",
    "MIPS_INS_BTNEZ",
    "MIPS_INS_CACHE",
    "MIPS_INS_CEIL",
    "MIPS_INS_CEQI",
    "MIPS_INS_CEQ",
    "MIPS_INS_CFC1",
    "MIPS_INS_CFCMSA",
    "MIPS_INS_CINS",
    "MIPS_INS_CINS32",
    "MIPS_INS_CLASS",
    "MIPS_INS_CLEI_S",
    "MIPS_INS_CLEI_U",
    "MIPS_INS_CLE_S",
    "MIPS_INS_CLE_U",
    "MIPS_INS_CLO",
    "MIPS_INS_CLTI_S",
    "MIPS_INS_CLTI_U",
    "MIPS_INS_CLT_S",
    "MIPS_INS_CLT_U",
    "MIPS_INS_CLZ",
    "MIPS_INS_CMPGDU",
    "MIPS_INS_CMPGU",
    "MIPS_INS_CMPU",
    "MIPS_INS_CMP",
    "MIPS_INS_COPY_S",
    "MIPS_INS_COPY_U",
    "MIPS_INS_CTC1",
    "MIPS_INS_CTCMSA",
    "MIPS_INS_CVT",
    "MIPS_INS_C",
    "MIPS_INS_CMPI",
    "MIPS_INS_DADD",
    "MIPS_INS_DADDI",
    "MIPS_INS_DADDIU",
    "MIPS_INS_DADDU",
    "MIPS_INS_DAHI",
    "MIPS_INS_DALIGN",
    "MIPS_INS_DATI",
    "MIPS_INS_DAUI",
    "MIPS_INS_DBITSWAP",
    "MIPS_INS_DCLO",
    "MIPS_INS_DCLZ",
    "MIPS_INS_DDIV",
    "MIPS_INS_DDIVU",
    "MIPS_INS_DERET",
    "MIPS_INS_DEXT",
    "MIPS_INS_DEXTM",
    "MIPS_INS_DEXTU",
    "MIPS_INS_DI",
    "MIPS_INS_DINS",
    "MIPS_INS_DINSM",
    "MIPS_INS_DINSU",
    "MIPS_INS_DIV",
    "MIPS_INS_DIVU",
    "MIPS_INS_DIV_S",
    "MIPS_INS_DIV_U",
    "MIPS_INS_DLSA",
    "MIPS_INS_DMFC0",
    "MIPS_INS_DMFC1",
    "MIPS_INS_DMFC2",
    "MIPS_INS_DMOD",
    "MIPS_INS_DMODU",
    "MIPS_INS_DMTC0",
    "MIPS_INS_DMTC1",
    "MIPS_INS_DMTC2",
    "MIPS_INS_DMUH",
    "MIPS_INS_DMUHU",
    "MIPS_INS_DMUL",
    "MIPS_INS_DMULT",
    "MIPS_INS_DMULTU",
    "MIPS_INS_DMULU",
    "MIPS_INS_DOTP_S",
    "MIPS_INS_DOTP_U",
    "MIPS_INS_DPADD_S",
    "MIPS_INS_DPADD_U",
    "MIPS_INS_DPAQX_SA",
    "MIPS_INS_DPAQX_S",
    "MIPS_INS_DPAQ_SA",
    "MIPS_INS_DPAQ_S",
    "MIPS_INS_DPAU",
    "MIPS_INS_DPAX",
    "MIPS_INS_DPA",
    "MIPS_INS_DPOP",
    "MIPS_INS_DPSQX_SA",
    "MIPS_INS_DPSQX_S",
    "MIPS_INS_DPSQ_SA",
    "MIPS_INS_DPSQ_S",
    "MIPS_INS_DPSUB_S",
    "MIPS_INS_DPSUB_U",
    "MIPS_INS_DPSU",
    "MIPS_INS_DPSX",
    "MIPS_INS_DPS",
    "MIPS_INS_DROTR",
    "MIPS_INS_DROTR32",
    "MIPS_INS_DROTRV",
    "MIPS_INS_DSBH",
    "MIPS_INS_DSHD",
    "MIPS_INS_DSLL",
    "MIPS_INS_DSLL32",
    "MIPS_INS_DSLLV",
    "MIPS_INS_DSRA",
    "MIPS_INS_DSRA32",
    "MIPS_INS_DSRAV",
    "MIPS_INS_DSRL",
    "MIPS_INS_DSRL32",
    "MIPS_INS_DSRLV",
    "MIPS_INS_DSUB",
    "MIPS_INS_DSUBU",
    "MIPS_INS_EHB",
    "MIPS_INS_EI",
    "MIPS_INS_ERET",
    "MIPS_INS_EXT",
    "MIPS_INS_EXTP",
    "MIPS_INS_EXTPDP",
    "MIPS_INS_EXTPDPV",
    "MIPS_INS_EXTPV",
    "MIPS_INS_EXTRV_RS",
    "MIPS_INS_EXTRV_R",
    "MIPS_INS_EXTRV_S",
    "MIPS_INS_EXTRV",
    "MIPS_INS_EXTR_RS",
    "MIPS_INS_EXTR_R",
    "MIPS_INS_EXTR_S",
    "MIPS_INS_EXTR",
    "MIPS_INS_EXTS",
    "MIPS_INS_EXTS32",
    "MIPS_INS_ABS",
    "MIPS_INS_FADD",
    "MIPS_INS_FCAF",
    "MIPS_INS_FCEQ",
    "MIPS_INS_FCLASS",
    "MIPS_INS_FCLE",
    "MIPS_INS_FCLT",
    "MIPS_INS_FCNE",
    "MIPS_INS_FCOR",
    "MIPS_INS_FCUEQ",
    "MIPS_INS_FCULE",
    "MIPS_INS_FCULT",
    "MIPS_INS_FCUNE",
    "MIPS_INS_FCUN",
    "MIPS_INS_FDIV",
    "MIPS_INS_FEXDO",
    "MIPS_INS_FEXP2",
    "MIPS_INS_FEXUPL",
    "MIPS_INS_FEXUPR",
    "MIPS_INS_FFINT_S",
    "MIPS_INS_FFINT_U",
    "MIPS_INS_FFQL",
    "MIPS_INS_FFQR",
    "MIPS_INS_FILL",
    "MIPS_INS_FLOG2",
    "MIPS_INS_FLOOR",
    "MIPS_INS_FMADD",
    "MIPS_INS_FMAX_A",
    "MIPS_INS_FMAX",
    "MIPS_INS_FMIN_A",
    "MIPS_INS_FMIN",
    "MIPS_INS_MOV",
    "MIPS_INS_FMSUB",
    "MIPS_INS_FMUL",
    "MIPS_INS_MUL",
    "MIPS_INS_NEG",
    "MIPS_INS_FRCP",
    "MIPS_INS_FRINT",
    "MIPS_INS_FRSQRT",
    "MIPS_INS_FSAF",
    "MIPS_INS_FSEQ",
    "MIPS_INS_FSLE",
    "MIPS_INS_FSLT",
    "MIPS_INS_FSNE",
    "MIPS_INS_FSOR",
    "MIPS_INS_FSQRT",
    "MIPS_INS_SQRT",
    "MIPS_INS_FSUB",
    "MIPS_INS_SUB",
    "MIPS_INS_FSUEQ",
    "MIPS_INS_FSULE",
    "MIPS_INS_FSULT",
    "MIPS_INS_FSUNE",
    "MIPS_INS_FSUN",
    "MIPS_INS_FTINT_S",
    "MIPS_INS_FTINT_U",
    "MIPS_INS_FTQ",
    "MIPS_INS_FTRUNC_S",
    "MIPS_INS_FTRUNC_U",
    "MIPS_INS_HADD_S",
    "MIPS_INS_HADD_U",
    "MIPS_INS_HSUB_S",
    "MIPS_INS_HSUB_U",
    "MIPS_INS_ILVEV",
    "MIPS_INS_ILVL",
    "MIPS_INS_ILVOD",
    "MIPS_INS_ILVR",
    "MIPS_INS_INS",
    "MIPS_INS_INSERT",
    "MIPS_INS_INSV",
    "MIPS_INS_INSVE",
    "MIPS_INS_J",
    "MIPS_INS_JAL",
    "MIPS_INS_JALR",
    "MIPS_INS_JALRS16",
    "MIPS_INS_JALRS",
    "MIPS_INS_JALS",
    "MIPS_INS_JALX",
    "MIPS_INS_JIALC",
    "MIPS_INS_JIC",
    "MIPS_INS_JR",
    "MIPS_INS_JR16",
    "MIPS_INS_JRADDIUSP",
    "MIPS_INS_JRC",
    "MIPS_INS_JALRC",
    "MIPS_INS_LB",
    "MIPS_INS_LBU16",
    "MIPS_INS_LBUX",
    "MIPS_INS_LBU",
    "MIPS_INS_LD",
    "MIPS_INS_LDC1",
    "MIPS_INS_LDC2",
    "MIPS_INS_LDC3",
    "MIPS_INS_LDI",
    "MIPS_INS_LDL",
    "MIPS_INS_LDPC",
    "MIPS_INS_LDR",
    "MIPS_INS_LDXC1",
    "MIPS_INS_LH",
    "MIPS_INS_LHU16",
    "MIPS_INS_LHX",
    "MIPS_INS_LHU",
    "MIPS_INS_LI16",
    "MIPS_INS_LL",
    "MIPS_INS_LLD",
    "MIPS_INS_LSA",
    "MIPS_INS_LUXC1",
    "MIPS_INS_LUI",
    "MIPS_INS_LW",
    "MIPS_INS_LW16",
    "MIPS_INS_LWC1",
    "MIPS_INS_LWC2",
    "MIPS_INS_LWC3",
    "MIPS_INS_LWL",
    "MIPS_INS_LWM16",
    "MIPS_INS_LWM32",
    "MIPS_INS_LWPC",
    "MIPS_INS_LWP",
    "MIPS_INS_LWR",
    "MIPS_INS_LWUPC",
    "MIPS_INS_LWU",
    "MIPS_INS_LWX",
    "MIPS_INS_LWXC1",
    "MIPS_INS_LWXS",
    "MIPS_INS_LI",
    "MIPS_INS_MADD",
    "MIPS_INS_MADDF",
    "MIPS_INS_MADDR_Q",
    "MIPS_INS_MADDU",
    "MIPS_INS_MADDV",
    "MIPS_INS_MADD_Q",
    "MIPS_INS_MAQ_SA",
    "MIPS_INS_MAQ_S",
    "MIPS_INS_MAXA",
    "MIPS_INS_MAXI_S",
    "MIPS_INS_MAXI_U",
    "MIPS_INS_MAX_A",
    "MIPS_INS_MAX",
    "MIPS_INS_MAX_S",
    "MIPS_INS_MAX_U",
    "MIPS_INS_MFC0",
    "MIPS_INS_MFC1",
    "MIPS_INS_MFC2",
    "MIPS_INS_MFHC1",
    "MIPS_INS_MFHI",
    "MIPS_INS_MFLO",
    "MIPS_INS_MINA",
    "MIPS_INS_MINI_S",
    "MIPS_INS_MINI_U",
    "MIPS_INS_MIN_A",
    "MIPS_INS_MIN",
    "MIPS_INS_MIN_S",
    "MIPS_INS_MIN_U",
    "MIPS_INS_MOD",
    "MIPS_INS_MODSUB",
    "MIPS_INS_MODU",
    "MIPS_INS_MOD_S",
    "MIPS_INS_MOD_U",
    "MIPS_INS_MOVE",
    "MIPS_INS_MOVEP",
    "MIPS_INS_MOVF",
    "MIPS_INS_MOVN",
    "MIPS_INS_MOVT",
    "MIPS_INS_MOVZ",
    "MIPS_INS_MSUB",
    "MIPS_INS_MSUBF",
    "MIPS_INS_MSUBR_Q",
    "MIPS_INS_MSUBU",
    "MIPS_INS_MSUBV",
    "MIPS_INS_MSUB_Q",
    "MIPS_INS_MTC0",
    "MIPS_INS_MTC1",
    "MIPS_INS_MTC2",
    "MIPS_INS_MTHC1",
    "MIPS_INS_MTHI",
    "MIPS_INS_MTHLIP",
    "MIPS_INS_MTLO",
    "MIPS_INS_MTM0",
    "MIPS_INS_MTM1",
    "MIPS_INS_MTM2",
    "MIPS_INS_MTP0",
    "MIPS_INS_MTP1",
    "MIPS_INS_MTP2",
    "MIPS_INS_MUH",
    "MIPS_INS_MUHU",
    "MIPS_INS_MULEQ_S",
    "MIPS_INS_MULEU_S",
    "MIPS_INS_MULQ_RS",
    "MIPS_INS_MULQ_S",
    "MIPS_INS_MULR_Q",
    "MIPS_INS_MULSAQ_S",
    "MIPS_INS_MULSA",
    "MIPS_INS_MULT",
    "MIPS_INS_MULTU",
    "MIPS_INS_MULU",
    "MIPS_INS_MULV",
    "MIPS_INS_MUL_Q",
    "MIPS_INS_MUL_S",
    "MIPS_INS_NLOC",
    "MIPS_INS_NLZC",
    "MIPS_INS_NMADD",
    "MIPS_INS_NMSUB",
    "MIPS_INS_NOR",
    "MIPS_INS_NORI",
    "MIPS_INS_NOT16",
    "MIPS_INS_NOT",
    "MIPS_INS_OR",
    "MIPS_INS_OR16",
    "MIPS_INS_ORI",
    "MIPS_INS_PACKRL",
    "MIPS_INS_PAUSE",
    "MIPS_INS_PCKEV",
    "MIPS_INS_PCKOD",
    "MIPS_INS_PCNT",
    "MIPS_INS_PICK",
    "MIPS_INS_POP",
    "MIPS_INS_PRECEQU",
    "MIPS_INS_PRECEQ",
    "MIPS_INS_PRECEU",
    "MIPS_INS_PRECRQU_S",
    "MIPS_INS_PRECRQ",
    "MIPS_INS_PRECRQ_RS",
    "MIPS_INS_PRECR",
    "MIPS_INS_PRECR_SRA",
    "MIPS_INS_PRECR_SRA_R",
    "MIPS_INS_PREF",
    "MIPS_INS_PREPEND",
    "MIPS_INS_RADDU",
    "MIPS_INS_RDDSP",
    "MIPS_INS_RDHWR",
    "MIPS_INS_REPLV",
    "MIPS_INS_REPL",
    "MIPS_INS_RINT",
    "MIPS_INS_ROTR",
    "MIPS_INS_ROTRV",
    "MIPS_INS_ROUND",
    "MIPS_INS_SAT_S",
    "MIPS_INS_SAT_U",
    "MIPS_INS_SB",
    "MIPS_INS_SB16",
    "MIPS_INS_SC",
    "MIPS_INS_SCD",
    "MIPS_INS_SD",
    "MIPS_INS_SDBBP",
    "MIPS_INS_SDBBP16",
    "MIPS_INS_SDC1",
    "MIPS_INS_SDC2",
    "MIPS_INS_SDC3",
    "MIPS_INS_SDL",
    "MIPS_INS_SDR",
    "MIPS_INS_SDXC1",
    "MIPS_INS_SEB",
    "MIPS_INS_SEH",
    "MIPS_INS_SELEQZ",
    "MIPS_INS_SELNEZ",
    "MIPS_INS_SEL",
    "MIPS_INS_SEQ",
    "MIPS_INS_SEQI",
    "MIPS_INS_SH",
    "MIPS_INS_SH16",
    "MIPS_INS_SHF",
    "MIPS_INS_SHILO",
    "MIPS_INS_SHILOV",
    "MIPS_INS_SHLLV",
    "MIPS_INS_SHLLV_S",
    "MIPS_INS_SHLL",
    "MIPS_INS_SHLL_S",
    "MIPS_INS_SHRAV",
    "MIPS_INS_SHRAV_R",
    "MIPS_INS_SHRA",
    "MIPS_INS_SHRA_R",
    "MIPS_INS_SHRLV",
    "MIPS_INS_SHRL",
    "MIPS_INS_SLDI",
    "MIPS_INS_SLD",
    "MIPS_INS_SLL",
    "MIPS_INS_SLL16",
    "MIPS_INS_SLLI",
    "MIPS_INS_SLLV",
    "MIPS_INS_SLT",
    "MIPS_INS_SLTI",
    "MIPS_INS_SLTIU",
    "MIPS_INS_SLTU",
    "MIPS_INS_SNE",
    "MIPS_INS_SNEI",
    "MIPS_INS_SPLATI",
    "MIPS_INS_SPLAT",
    "MIPS_INS_SRA",
    "MIPS_INS_SRAI",
    "MIPS_INS_SRARI",
    "MIPS_INS_SRAR",
    "MIPS_INS_SRAV",
    "MIPS_INS_SRL",
    "MIPS_INS_SRL16",
    "MIPS_INS_SRLI",
    "MIPS_INS_SRLRI",
    "MIPS_INS_SRLR",
    "MIPS_INS_SRLV",
    "MIPS_INS_SSNOP",
    "MIPS_INS_ST",
    "MIPS_INS_SUBQH",
    "MIPS_INS_SUBQH_R",
    "MIPS_INS_SUBQ",
    "MIPS_INS_SUBQ_S",
    "MIPS_INS_SUBSUS_U",
    "MIPS_INS_SUBSUU_S",
    "MIPS_INS_SUBS_S",
    "MIPS_INS_SUBS_U",
    "MIPS_INS_SUBU16",
    "MIPS_INS_SUBUH",
    "MIPS_INS_SUBUH_R",
    "MIPS_INS_SUBU",
    "MIPS_INS_SUBU_S",
    "MIPS_INS_SUBVI",
    "MIPS_INS_SUBV",
    "MIPS_INS_SUXC1",
    "MIPS_INS_SW",
    "MIPS_INS_SW16",
    "MIPS_INS_SWC1",
    "MIPS_INS_SWC2",
    "MIPS_INS_SWC3",
    "MIPS_INS_SWL",
    "MIPS_INS_SWM16",
    "MIPS_INS_SWM32",
    "MIPS_INS_SWP",
    "MIPS_INS_SWR",
    "MIPS_INS_SWXC1",
    "MIPS_INS_SYNC",
    "MIPS_INS_SYNCI",
    "MIPS_INS_SYSCALL",
    "MIPS_INS_TEQ",
    "MIPS_INS_TEQI",
    "MIPS_INS_TGE",
    "MIPS_INS_TGEI",
    "MIPS_INS_TGEIU",
    "MIPS_INS_TGEU",
    "MIPS_INS_TLBP",
    "MIPS_INS_TLBR",
    "MIPS_INS_TLBWI",
    "MIPS_INS_TLBWR",
    "MIPS_INS_TLT",
    "MIPS_INS_TLTI",
    "MIPS_INS_TLTIU",
    "MIPS_INS_TLTU",
    "MIPS_INS_TNE",
    "MIPS_INS_TNEI",
    "MIPS_INS_TRUNC",
    "MIPS_INS_V3MULU",
    "MIPS_INS_VMM0",
    "MIPS_INS_VMULU",
    "MIPS_INS_VSHF",
    "MIPS_INS_WAIT",
    "MIPS_INS_WRDSP",
    "MIPS_INS_WSBH",
    "MIPS_INS_XOR",
    "MIPS_INS_XOR16",
    "MIPS_INS_XORI",
    "MIPS_INS_NOP",
    "MIPS_INS_NEGU",
    "MIPS_INS_JALR_HB",
    "MIPS_INS_JR_HB",
]


def generate_empty_status():
    """
    Generate empty status file with all instructions marked as unlifted
    """

    f = open("README.md", mode="w")
    f.write("# MIPS UPLIFTING STATUS\n\n")

    # generate columns
    f.write(
        "|               Instruction Name |     MIPS32 |     MIPS64 |    mMIPS32 |    mMIPS64 |\n"
        "|--------------------------------|------------|------------|------------|------------|\n"
    )

    # print empty data
    for i in range(len(insn_list)):
        f.write(
            f'| {insn_list[i]:>30} | {"[ ]":>10} | {"[ ]":>10} | {"[ ]":>10} | {"[ ]":>10} |\n'
        )

    f.close()


def load_status():
    """
    Reads current README.md file and loads current uplifting status
    @return status dictionary
    {insn_name : [mips32_status, mips64_status, mmips32_status, mmips64_status]}
    """

    f = open("README.md", mode="r")
    rows = f.read().split("\n")[4:]
    f.close()

    if len(rows) < (len(insn_list)):
        print(
            "STATUS DATA CORRUPT, REFRESH TO NEW WITH `python update_status.py new` COMMAND"
        )
        sys.exit(1)

    status = {}

    # split to seprate entries

    # parse each row
    for i in range(len(insn_list)):
        # split into column entries
        cols = rows[i].split("|")[1:]

        # get column entries
        insn_name = cols[0].strip()
        mips32_status = cols[1].strip() != "[ ]"
        mips64_status = cols[2].strip() != "[ ]"
        mmips32_status = cols[3].strip() != "[ ]"
        mmips64_status = cols[4].strip() != "[ ]"

        # fill status hash table
        status[insn_name] = [
            mips32_status,
            mips64_status,
            mmips32_status,
            mmips64_status,
        ]

    return status


def write_status(status):
    f = open("README.md", mode="w")
    f.write("# MIPS UPLIFTING STATUS\n\n")

    # generate columns
    f.write(
        "|               Instruction Name |     MIPS32 |     MIPS64 |    mMIPS32 |    mMIPS64 |\n"
        "|--------------------------------|------------|------------|------------|------------|\n"
    )

    # print empty data
    for i in range(len(insn_list)):
        mips32_status = "[x]" if status[insn_list[i]][0] == True else "[ ]"
        mips64_status = "[x]" if status[insn_list[i]][1] == True else "[ ]"
        mmips32_status = "[x]" if status[insn_list[i]][2] == True else "[ ]"
        mmips64_status = "[x]" if status[insn_list[i]][3] == True else "[ ]"

        f.write(
            f"| {insn_list[i]:>30} | {mips32_status:>10} | {mips64_status:>10} | {mmips32_status:>10} | {mmips64_status:>10} |\n"
        )

    f.close()


def update_status(args):
    """
    Update current status
    Architecture names that are not present will be marked as false
    @param args Contains arguments for update command
    """

    status = load_status()

    # process arguments
    insn_name = "MIPS_INS_" + args[0]
    arch_list = args[1:]

    # generate new status
    new_insn_status = [False, False, False, False]
    for arch in arch_list:
        if arch == "mips32":
            new_insn_status[0] = True
        if arch == "mips64":
            new_insn_status[1] = True
        if arch == "mmips32":
            new_insn_status[2] = True
        if arch == "mmips64":
            new_insn_status[3] = True

    # update instruction status
    status[insn_name] = new_insn_status
    write_status(status)

def show_status():
    status = load_status()

    # count total number of uplifted instructions
    mips32 = 0
    mips64 = 0
    mmips32 = 0
    mmips64 = 0

    for i in range(len(insn_list)):
        s = status[insn_list[i]]

        if s[0] == True:
            mips32 += 1
        if s[1] == True:
            mips64 += 1
        if s[2] == True:
            mmips32 += 1
        if s[3] == True:
            mmips64 += 1

    print(f"STATUS : MIPS32 = {mips32} | MIPS64 = {mips64} | mMIPS32 = {mmips32} | mMIPS64 = {mmips64}")

# process cmd line args
def show_help():
    print("USAGE : python status_update.py command")
    print(
        "COMMANDS : help                                        # display this help\n"
        "         : new                                         # generate new status file\n"
        "         : update <insn_name> <arch1> <arch2> ...      # update status for current arch\n"
        "         : show                                        # display total number of \n"
        "                                                       # uplifted instructions per arch\n"
        "EXAMPLES :\n"
        "         : eg: update ADDI mips32 mmips64              # mips32 and mmps64 will be marked, others will be unmarked\n"
        "         : eg: coverage mipsbins/bin/ls mips32 little  # Will load bin/ls elf file and calculate uplifting status"
    )


args = sys.argv[1:]
if(len(args) == 0):
    show_help()
else :
    if args[0] == "new":
        generate_empty_status()
    elif args[0] == "update":
        update_status(args[1:])
    elif args[0] == "show":
        show_status()
    elif args[0] == "help":
        show_help()
