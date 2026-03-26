// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

// ---------------------------------------------------------------------------
// Extended opcode size tables (prefix + sub-byte + immediates).
// All sizes are total bytes consumed (2 opcode bytes + immediates).
// 0 means unknown, fallback to 2.
// ---------------------------------------------------------------------------

// 0xFB extended table
static const ut8 fb_sizes[256] = {
	/* 00 */ 2,
	/* 01 */ 2,
	/* 02 */ 2,
	/* 03 */ 2,
	/* 04 */ 2,
	/* 05 */ 2,
	/* 06 */ 2,
	/* 07 */ 4,
	/* 08 */ 2,
	/* 09 */ 2,
	/* 0A */ 2,
	/* 0B */ 2,
	/* 0C */ 2,
	/* 0D */ 2,
	/* 0E */ 2,
	/* 0F */ 4,
	/* 10 */ 2,
	/* 11 */ 2,
	/* 12 */ 2,
	/* 13 */ 2,
	/* 14 */ 2,
	/* 15 */ 2,
	/* 16 */ 2,
	/* 17 */ 4,
	/* 18 */ 2,
	/* 19 */ 2,
	/* 1A */ 2,
	/* 1B */ 2,
	/* 1C */ 2,
	/* 1D */ 2,
	/* 1E */ 2,
	/* 1F */ 4,
	/* 20 */ 2,
	/* 21 */ 2,
	/* 22 */ 2,
	/* 23 */ 2,
	/* 24 */ 2,
	/* 25 */ 2,
	/* 26 */ 2,
	/* 27 */ 4,
	/* 28 */ 2,
	/* 29 */ 2,
	/* 2A */ 2,
	/* 2B */ 2,
	/* 2C */ 2,
	/* 2D */ 2,
	/* 2E */ 2,
	/* 2F */ 4,
	/* 30 */ 2,
	/* 31 */ 4,
	/* 32 */ 2,
	/* 33 */ 2,
	/* 34 */ 2,
	/* 35 */ 2,
	/* 36 */ 2,
	/* 37 */ 2,
	/* 38 */ 2,
	/* 39 */ 2,
	/* 3A */ 2,
	/* 3B */ 2,
	/* 3C */ 4,
	/* 3D */ 2,
	/* 3E */ 4,
	/* 3F */ 2,
	/* 40 */ 2,
	/* 41 */ 2,
	/* 42 */ 2,
	/* 43 */ 2,
	/* 44 */ 2,
	/* 45 */ 2,
	/* 46 */ 2,
	/* 47 */ 2,
	/* 48 */ 2,
	/* 49 */ 4,
	/* 4A */ 2,
	/* 4B */ 4,
	/* 4C */ 2,
	/* 4D */ 2,
	/* 4E */ 2,
	/* 4F */ 2,
	/* 50 */ 2,
	/* 51 */ 2,
	/* 52 */ 2,
	/* 53 */ 2,
	/* 54 */ 2,
	/* 55 */ 2,
	/* 56 */ 4,
	/* 57 */ 2,
	/* 58 */ 4,
	/* 59 */ 2,
	/* 5A */ 2,
	/* 5B */ 2,
	/* 5C */ 2,
	/* 5D */ 2,
	/* 5E */ 2,
	/* 5F */ 2,
	/* 60 */ 2,
	/* 61 */ 2,
	/* 62 */ 2,
	/* 63 */ 4,
	/* 64 */ 2,
	/* 65 */ 4,
	/* 66 */ 2,
	/* 67 */ 2,
	/* 68 */ 2,
	/* 69 */ 2,
	/* 6A */ 2,
	/* 6B */ 2,
	/* 6C */ 2,
	/* 6D */ 2,
	/* 6E */ 2,
	/* 6F */ 2,
	/* 70 */ 4,
	/* 71 */ 2,
	/* 72 */ 4,
	/* 73 */ 2,
	/* 74 */ 2,
	/* 75 */ 2,
	/* 76 */ 2,
	/* 77 */ 2,
	/* 78 */ 2,
	/* 79 */ 2,
	/* 7A */ 2,
	/* 7B */ 2,
	/* 7C */ 2,
	/* 7D */ 4,
	/* 7E */ 2,
	/* 7F */ 4,
	/* 80 */ 2,
	/* 81 */ 2,
	/* 82 */ 2,
	/* 83 */ 2,
	/* 84 */ 2,
	/* 85 */ 2,
	/* 86 */ 2,
	/* 87 */ 2,
	/* 88 */ 2,
	/* 89 */ 2,
	/* 8A */ 2,
	/* 8B */ 2,
	/* 8C */ 2,
	/* 8D */ 2,
	/* 8E */ 2,
	/* 8F */ 2,
	/* 90 */ 2,
	/* 91 */ 2,
	/* 92 */ 2,
	/* 93 */ 2,
	/* 94 */ 4,
	/* 95 */ 2,
	/* 96 */ 2,
	/* 97 */ 2,
	/* 98 */ 2,
	/* 99 */ 2,
	/* 9A */ 2,
	/* 9B */ 2,
	/* 9C */ 4,
	/* 9D */ 2,
	/* 9E */ 2,
	/* 9F */ 2,
	/* A0 */ 2,
	/* A1 */ 2,
	/* A2 */ 2,
	/* A3 */ 2,
	/* A4 */ 4,
	/* A5 */ 2,
	/* A6 */ 2,
	/* A7 */ 2,
	/* A8 */ 2,
	/* A9 */ 2,
	/* AA */ 2,
	/* AB */ 2,
	/* AC */ 4,
	/* AD */ 2,
	/* AE */ 2,
	/* AF */ 2,
	/* B0 */ 2,
	/* B1 */ 2,
	/* B2 */ 2,
	/* B3 */ 2,
	/* B4 */ 4,
	/* B5 */ 2,
	/* B6 */ 2,
	/* B7 */ 2,
	/* B8 */ 2,
	/* B9 */ 2,
	/* BA */ 2,
	/* BB */ 2,
	/* BC */ 4,
	/* BD */ 2,
	/* BE */ 2,
	/* BF */ 2,
	/* C0 */ 2,
	/* C1 */ 2,
	/* C2 */ 2,
	/* C3 */ 2,
	/* C4 */ 4,
	/* C5 */ 2,
	/* C6 */ 2,
	/* C7 */ 2,
	/* C8 */ 2,
	/* C9 */ 2,
	/* CA */ 2,
	/* CB */ 2,
	/* CC */ 4,
	/* CD */ 2,
	/* CE */ 4,
	/* CF */ 2,
	/* D0 */ 2,
	/* D1 */ 2,
	/* D2 */ 2,
	/* D3 */ 2,
	/* D4 */ 2,
	/* D5 */ 2,
	/* D6 */ 2,
	/* D7 */ 2,
	/* D8 */ 2,
	/* D9 */ 2,
	/* DA */ 2,
	/* DB */ 2,
	/* DC */ 2,
	/* DD */ 2,
	/* DE */ 2,
	/* DF */ 2,
	/* E0 */ 2,
	/* E1 */ 2,
	/* E2 */ 2,
	/* E3 */ 2,
	/* E4 */ 2,
	/* E5 */ 2,
	/* E6 */ 2,
	/* E7 */ 2,
	/* E8 */ 2,
	/* E9 */ 4,
	/* EA */ 2,
	/* EB */ 4,
	/* EC */ 4,
	/* ED */ 4,
	/* EE */ 4,
	/* EF */ 4,
	/* F0 */ 2,
	/* F1 */ 2,
	/* F2 */ 2,
	/* F3 */ 2,
	/* F4 */ 2,
	/* F5 */ 2,
	/* F6 */ 2,
	/* F7 */ 2,
	/* F8 */ 2,
	/* F9 */ 2,
	/* FA */ 2,
	/* FB */ 2,
	/* FC */ 2,
	/* FD */ 2,
	/* FE */ 2,
	/* FF */ 2,
};

// 0xFC extended table
static const ut8 fc_sizes[256] = {
	/* 00 */ 2,
	/* 01 */ 2,
	/* 02 */ 2,
	/* 03 */ 2,
	/* 04 */ 2,
	/* 05 */ 2,
	/* 06 */ 2,
	/* 07 */ 2,
	/* 08 */ 2,
	/* 09 */ 2,
	/* 0A */ 2,
	/* 0B */ 2,
	/* 0C */ 2,
	/* 0D */ 2,
	/* 0E */ 2,
	/* 0F */ 2,
	/* 10 */ 2,
	/* 11 */ 2,
	/* 12 */ 2,
	/* 13 */ 2,
	/* 14 */ 2,
	/* 15 */ 2,
	/* 16 */ 2,
	/* 17 */ 2,
	/* 18 */ 2,
	/* 19 */ 2,
	/* 1A */ 2,
	/* 1B */ 2,
	/* 1C */ 2,
	/* 1D */ 2,
	/* 1E */ 2,
	/* 1F */ 2,
	/* 20 */ 2,
	/* 21 */ 2,
	/* 22 */ 2,
	/* 23 */ 2,
	/* 24 */ 2,
	/* 25 */ 2,
	/* 26 */ 2,
	/* 27 */ 2,
	/* 28 */ 2,
	/* 29 */ 2,
	/* 2A */ 2,
	/* 2B */ 2,
	/* 2C */ 2,
	/* 2D */ 2,
	/* 2E */ 2,
	/* 2F */ 2,
	/* 30 */ 2,
	/* 31 */ 2,
	/* 32 */ 2,
	/* 33 */ 2,
	/* 34 */ 2,
	/* 35 */ 2,
	/* 36 */ 2,
	/* 37 */ 2,
	/* 38 */ 2,
	/* 39 */ 2,
	/* 3A */ 2,
	/* 3B */ 2,
	/* 3C */ 2,
	/* 3D */ 2,
	/* 3E */ 2,
	/* 3F */ 2,
	/* 40 */ 2,
	/* 41 */ 2,
	/* 42 */ 2,
	/* 43 */ 2,
	/* 44 */ 2,
	/* 45 */ 2,
	/* 46 */ 2,
	/* 47 */ 2,
	/* 48 */ 2,
	/* 49 */ 2,
	/* 4A */ 2,
	/* 4B */ 2,
	/* 4C */ 2,
	/* 4D */ 2,
	/* 4E */ 2,
	/* 4F */ 2,
	/* 50 */ 2,
	/* 51 */ 2,
	/* 52 */ 2,
	/* 53 */ 2,
	/* 54 */ 2,
	/* 55 */ 2,
	/* 56 */ 2,
	/* 57 */ 2,
	/* 58 */ 2,
	/* 59 */ 2,
	/* 5A */ 2,
	/* 5B */ 2,
	/* 5C */ 2,
	/* 5D */ 4,
	/* 5E */ 4,
	/* 5F */ 4,
	/* 60 */ 4,
	/* 61 */ 6,
	/* 62 */ 2,
	/* 63 */ 2,
	/* 64 */ 4,
	/* 65 */ 4,
	/* 66 */ 4,
	/* 67 */ 4,
	/* 68 */ 4,
	/* 69 */ 6,
	/* 6A */ 2,
	/* 6B */ 2,
	/* 6C */ 2,
	/* 6D */ 2,
	/* 6E */ 2,
	/* 6F */ 4,
	/* 70 */ 2,
	/* 71 */ 2,
	/* 72 */ 4,
	/* 73 */ 2,
	/* 74 */ 10,
	/* 75 */ 2,
	/* 76 */ 2,
	/* 77 */ 2,
	/* 78 */ 2,
	/* 79 */ 2,
	/* 7A */ 2,
	/* 7B */ 2,
	/* 7C */ 2,
	/* 7D */ 2,
	/* 7E */ 2,
	/* 7F */ 2,
	/* 80 */ 2,
	/* 81 */ 2,
	/* 82 */ 2,
	/* 83 */ 2,
	/* 84 */ 2,
	/* 85 */ 2,
	/* 86 */ 2,
	/* 87 */ 2,
	/* 88 */ 2,
	/* 89 */ 2,
	/* 8A */ 2,
	/* 8B */ 2,
	/* 8C */ 2,
	/* 8D */ 4,
	/* 8E */ 4,
	/* 8F */ 6,
	/* 90 */ 2,
	/* 91 */ 2,
	/* 92 */ 2,
	/* 93 */ 2,
	/* 94 */ 2,
	/* 95 */ 2,
	/* 96 */ 2,
	/* 97 */ 2,
	/* 98 */ 2,
	/* 99 */ 2,
	/* 9A */ 2,
	/* 9B */ 2,
	/* 9C */ 2,
	/* 9D */ 2,
	/* 9E */ 2,
	/* 9F */ 2,
	/* A0 */ 2,
	/* A1 */ 2,
	/* A2 */ 2,
	/* A3 */ 2,
	/* A4 */ 2,
	/* A5 */ 2,
	/* A6 */ 2,
	/* A7 */ 2,
	/* A8 */ 2,
	/* A9 */ 2,
	/* AA */ 2,
	/* AB */ 2,
	/* AC */ 2,
	/* AD */ 2,
	/* AE */ 2,
	/* AF */ 2,
	/* B0 */ 2,
	/* B1 */ 2,
	/* B2 */ 2,
	/* B3 */ 2,
	/* B4 */ 2,
	/* B5 */ 2,
	/* B6 */ 2,
	/* B7 */ 2,
	/* B8 */ 2,
	/* B9 */ 2,
	/* BA */ 2,
	/* BB */ 2,
	/* BC */ 4,
	/* BD */ 2,
	/* BE */ 2,
	/* BF */ 2,
	/* C0 */ 2,
	/* C1 */ 2,
	/* C2 */ 2,
	/* C3 */ 2,
	/* C4 */ 3,
	/* C5 */ 2,
	/* C6 */ 2,
	/* C7 */ 2,
	/* C8 */ 2,
	/* C9 */ 2,
	/* CA */ 2,
	/* CB */ 2,
	/* CC */ 2,
	/* CD */ 2,
	/* CE */ 2,
	/* CF */ 2,
	/* D0 */ 2,
	/* D1 */ 2,
	/* D2 */ 2,
	/* D3 */ 2,
	/* D4 */ 2,
	/* D5 */ 2,
	/* D6 */ 2,
	/* D7 */ 2,
	/* D8 */ 2,
	/* D9 */ 2,
	/* DA */ 2,
	/* DB */ 2,
	/* DC */ 2,
	/* DD */ 2,
	/* DE */ 2,
	/* DF */ 2,
	/* E0 */ 4,
	/* E1 */ 4,
	/* E2 */ 4,
	/* E3 */ 4,
	/* E4 */ 4,
	/* E5 */ 4,
	/* E6 */ 4,
	/* E7 */ 4,
	/* E8 */ 4,
	/* E9 */ 4,
	/* EA */ 4,
	/* EB */ 4,
	/* EC */ 4,
	/* ED */ 4,
	/* EE */ 2,
	/* EF */ 2,
	/* F0 */ 4,
	/* F1 */ 4,
	/* F2 */ 4,
	/* F3 */ 4,
	/* F4 */ 4,
	/* F5 */ 4,
	/* F6 */ 4,
	/* F7 */ 4,
	/* F8 */ 2,
	/* F9 */ 4,
	/* FA */ 2,
	/* FB */ 2,
	/* FC */ 4,
	/* FD */ 2,
	/* FE */ 2,
	/* FF */ 4,
};

// 0xFD extended table
static const ut8 fd_sizes[256] = {
	/* 00 */ 4,
	/* 01 */ 4,
	/* 02 */ 2,
	/* 03 */ 4,
	/* 04 */ 4,
	/* 05 */ 4,
	/* 06 */ 4,
	/* 07 */ 4,
	/* 08 */ 4,
	/* 09 */ 4,
	/* 0A */ 4,
	/* 0B */ 4,
	/* 0C */ 2,
	/* 0D */ 4,
	/* 0E */ 4,
	/* 0F */ 4,
	/* 10 */ 4,
	/* 11 */ 4,
	/* 12 */ 4,
	/* 13 */ 4,
	/* 14 */ 4,
	/* 15 */ 4,
	/* 16 */ 6,
	/* 17 */ 4,
	/* 18 */ 4,
	/* 19 */ 4,
	/* 1A */ 4,
	/* 1B */ 4,
	/* 1C */ 4,
	/* 1D */ 2,
	/* 1E */ 2,
	/* 1F */ 2,
	/* 20 */ 4,
	/* 21 */ 4,
	/* 22 */ 4,
	/* 23 */ 4,
	/* 24 */ 4,
	/* 25 */ 4,
	/* 26 */ 4,
	/* 27 */ 4,
	/* 28 */ 4,
	/* 29 */ 4,
	/* 2A */ 4,
	/* 2B */ 5,
	/* 2C */ 5,
	/* 2D */ 2,
	/* 2E */ 2,
	/* 2F */ 4,
	/* 30 */ 4,
	/* 31 */ 4,
	/* 32 */ 2,
	/* 33 */ 2,
	/* 34 */ 2,
	/* 35 */ 2,
	/* 36 */ 2,
	/* 37 */ 2,
	/* 38 */ 2,
	/* 39 */ 2,
	/* 3A */ 4,
	/* 3B */ 2,
	/* 3C */ 2,
	/* 3D */ 2,
	/* 3E */ 2,
	/* 3F */ 4,
	/* 40 */ 4,
	/* 41 */ 4,
	/* 42 */ 4,
	/* 43 */ 4,
	/* 44 */ 4,
	/* 45 */ 4,
	/* 46 */ 2,
	/* 47 */ 4,
	/* 48 */ 4,
	/* 49 */ 4,
	/* 4A */ 4,
	/* 4B */ 2,
	/* 4C */ 4,
	/* 4D */ 2,
	/* 4E */ 2,
	/* 4F */ 2,
	/* 50 */ 4,
	/* 51 */ 4,
	/* 52 */ 4,
	/* 53 */ 4,
	/* 54 */ 4,
	/* 55 */ 4,
	/* 56 */ 4,
	/* 57 */ 4,
	/* 58 */ 4,
	/* 59 */ 4,
	/* 5A */ 4,
	/* 5B */ 5,
	/* 5C */ 5,
	/* 5D */ 2,
	/* 5E */ 2,
	/* 5F */ 4,
	/* 60 */ 4,
	/* 61 */ 5,
	/* 62 */ 4,
	/* 63 */ 4,
	/* 64 */ 4,
	/* 65 */ 2,
	/* 66 */ 2,
	/* 67 */ 4,
	/* 68 */ 4,
	/* 69 */ 4,
	/* 6A */ 4,
	/* 6B */ 4,
	/* 6C */ 4,
	/* 6D */ 2,
	/* 6E */ 4,
	/* 6F */ 4,
	/* 70 */ 4,
	/* 71 */ 4,
	/* 72 */ 4,
	/* 73 */ 4,
	/* 74 */ 4,
	/* 75 */ 4,
	/* 76 */ 4,
	/* 77 */ 4,
	/* 78 */ 4,
	/* 79 */ 4,
	/* 7A */ 4,
	/* 7B */ 4,
	/* 7C */ 4,
	/* 7D */ 2,
	/* 7E */ 2,
	/* 7F */ 2,
	/* 80 */ 4,
	/* 81 */ 4,
	/* 82 */ 4,
	/* 83 */ 4,
	/* 84 */ 4,
	/* 85 */ 4,
	/* 86 */ 4,
	/* 87 */ 4,
	/* 88 */ 4,
	/* 89 */ 4,
	/* 8A */ 4,
	/* 8B */ 4,
	/* 8C */ 4,
	/* 8D */ 4,
	/* 8E */ 4,
	/* 8F */ 4,
	/* 90 */ 4,
	/* 91 */ 4,
	/* 92 */ 2,
	/* 93 */ 4,
	/* 94 */ 6,
	/* 95 */ 2,
	/* 96 */ 2,
	/* 97 */ 2,
	/* 98 */ 2,
	/* 99 */ 4,
	/* 9A */ 4,
	/* 9B */ 4,
	/* 9C */ 4,
	/* 9D */ 4,
	/* 9E */ 4,
	/* 9F */ 2,
	/* A0 */ 4,
	/* A1 */ 4,
	/* A2 */ 4,
	/* A3 */ 4,
	/* A4 */ 4,
	/* A5 */ 4,
	/* A6 */ 4,
	/* A7 */ 4,
	/* A8 */ 4,
	/* A9 */ 4,
	/* AA */ 4,
	/* AB */ 4,
	/* AC */ 4,
	/* AD */ 2,
	/* AE */ 2,
	/* AF */ 2,
	/* B0 */ 4,
	/* B1 */ 4,
	/* B2 */ 4,
	/* B3 */ 4,
	/* B4 */ 4,
	/* B5 */ 4,
	/* B6 */ 4,
	/* B7 */ 4,
	/* B8 */ 4,
	/* B9 */ 4,
	/* BA */ 4,
	/* BB */ 4,
	/* BC */ 4,
	/* BD */ 4,
	/* BE */ 4,
	/* BF */ 4,
	/* C0 */ 4,
	/* C1 */ 5,
	/* C2 */ 4,
	/* C3 */ 4,
	/* C4 */ 4,
	/* C5 */ 4,
	/* C6 */ 4,
	/* C7 */ 4,
	/* C8 */ 4,
	/* C9 */ 4,
	/* CA */ 4,
	/* CB */ 2,
	/* CC */ 2,
	/* CD */ 2,
	/* CE */ 2,
	/* CF */ 2,
	/* D0 */ 6,
	/* D1 */ 6,
	/* D2 */ 6,
	/* D3 */ 6,
	/* D4 */ 6,
	/* D5 */ 6,
	/* D6 */ 6,
	/* D7 */ 6,
	/* D8 */ 6,
	/* D9 */ 6,
	/* DA */ 6,
	/* DB */ 6,
	/* DC */ 6,
	/* DD */ 2,
	/* DE */ 2,
	/* DF */ 2,
	/* E0 */ 6,
	/* E1 */ 6,
	/* E2 */ 6,
	/* E3 */ 6,
	/* E4 */ 6,
	/* E5 */ 6,
	/* E6 */ 6,
	/* E7 */ 6,
	/* E8 */ 6,
	/* E9 */ 6,
	/* EA */ 6,
	/* EB */ 6,
	/* EC */ 6,
	/* ED */ 6,
	/* EE */ 6,
	/* EF */ 6,
	/* F0 */ 6,
	/* F1 */ 7,
	/* F2 */ 4,
	/* F3 */ 4,
	/* F4 */ 4,
	/* F5 */ 2,
	/* F6 */ 4,
	/* F7 */ 4,
	/* F8 */ 4,
	/* F9 */ 4,
	/* FA */ 4,
	/* FB */ 4,
	/* FC */ 4,
	/* FD */ 2,
	/* FE */ 4,
	/* FF */ 6,
};

// 0xFE extended table
static const ut8 fe_sizes[256] = {
	/* 00 */ 4,
	/* 01 */ 4,
	/* 02 */ 4,
	/* 03 */ 4,
	/* 04 */ 4,
	/* 05 */ 4,
	/* 06 */ 2,
	/* 07 */ 4,
	/* 08 */ 4,
	/* 09 */ 4,
	/* 0A */ 4,
	/* 0B */ 2,
	/* 0C */ 4,
	/* 0D */ 6,
	/* 0E */ 4,
	/* 0F */ 4,
	/* 10 */ 4,
	/* 11 */ 4,
	/* 12 */ 4,
	/* 13 */ 4,
	/* 14 */ 4,
	/* 15 */ 4,
	/* 16 */ 2,
	/* 17 */ 4,
	/* 18 */ 4,
	/* 19 */ 4,
	/* 1A */ 4,
	/* 1B */ 2,
	/* 1C */ 4,
	/* 1D */ 6,
	/* 1E */ 4,
	/* 1F */ 4,
	/* 20 */ 6,
	/* 21 */ 6,
	/* 22 */ 6,
	/* 23 */ 2,
	/* 24 */ 2,
	/* 25 */ 6,
	/* 26 */ 2,
	/* 27 */ 6,
	/* 28 */ 6,
	/* 29 */ 6,
	/* 2A */ 6,
	/* 2B */ 2,
	/* 2C */ 6,
	/* 2D */ 10,
	/* 2E */ 4,
	/* 2F */ 4,
	/* 30 */ 2,
	/* 31 */ 2,
	/* 32 */ 2,
	/* 33 */ 2,
	/* 34 */ 2,
	/* 35 */ 2,
	/* 36 */ 2,
	/* 37 */ 2,
	/* 38 */ 2,
	/* 39 */ 2,
	/* 3A */ 2,
	/* 3B */ 2,
	/* 3C */ 2,
	/* 3D */ 6,
	/* 3E */ 2,
	/* 3F */ 2,
	/* 40 */ 2,
	/* 41 */ 2,
	/* 42 */ 2,
	/* 43 */ 2,
	/* 44 */ 2,
	/* 45 */ 2,
	/* 46 */ 2,
	/* 47 */ 2,
	/* 48 */ 2,
	/* 49 */ 2,
	/* 4A */ 2,
	/* 4B */ 2,
	/* 4C */ 2,
	/* 4D */ 2,
	/* 4E */ 2,
	/* 4F */ 6,
	/* 50 */ 2,
	/* 51 */ 2,
	/* 52 */ 2,
	/* 53 */ 2,
	/* 54 */ 2,
	/* 55 */ 2,
	/* 56 */ 2,
	/* 57 */ 2,
	/* 58 */ 2,
	/* 59 */ 2,
	/* 5A */ 2,
	/* 5B */ 2,
	/* 5C */ 2,
	/* 5D */ 4,
	/* 5E */ 4,
	/* 5F */ 2,
	/* 60 */ 4,
	/* 61 */ 4,
	/* 62 */ 6,
	/* 63 */ 6,
	/* 64 */ 6,
	/* 65 */ 6,
	/* 66 */ 6,
	/* 67 */ 2,
	/* 68 */ 6,
	/* 69 */ 2,
	/* 6A */ 6,
	/* 6B */ 6,
	/* 6C */ 6,
	/* 6D */ 6,
	/* 6E */ 6,
	/* 6F */ 2,
	/* 70 */ 6,
	/* 71 */ 2,
	/* 72 */ 2,
	/* 73 */ 2,
	/* 74 */ 8,
	/* 75 */ 2,
	/* 76 */ 2,
	/* 77 */ 2,
	/* 78 */ 6,
	/* 79 */ 6,
	/* 7A */ 6,
	/* 7B */ 6,
	/* 7C */ 6,
	/* 7D */ 6,
	/* 7E */ 3,
	/* 7F */ 2,
	/* 80 */ 6,
	/* 81 */ 6,
	/* 82 */ 6,
	/* 83 */ 6,
	/* 84 */ 6,
	/* 85 */ 6,
	/* 86 */ 3,
	/* 87 */ 2,
	/* 88 */ 8,
	/* 89 */ 2,
	/* 8A */ 2,
	/* 8B */ 8,
	/* 8C */ 2,
	/* 8D */ 4,
	/* 8E */ 10,
	/* 8F */ 10,
	/* 90 */ 6,
	/* 91 */ 6,
	/* 92 */ 6,
	/* 93 */ 7,
	/* 94 */ 2,
	/* 95 */ 2,
	/* 96 */ 2,
	/* 97 */ 2,
	/* 98 */ 6,
	/* 99 */ 6,
	/* 9A */ 8,
	/* 9B */ 4,
	/* 9C */ 6,
	/* 9D */ 6,
	/* 9E */ 2,
	/* 9F */ 2,
	/* A0 */ 8,
	/* A1 */ 8,
	/* A2 */ 10,
	/* A3 */ 6,
	/* A4 */ 8,
	/* A5 */ 8,
	/* A6 */ 2,
	/* A7 */ 2,
	/* A8 */ 2,
	/* A9 */ 2,
	/* AA */ 2,
	/* AB */ 2,
	/* AC */ 2,
	/* AD */ 2,
	/* AE */ 6,
	/* AF */ 6,
	/* B0 */ 4,
	/* B1 */ 4,
	/* B2 */ 2,
	/* B3 */ 2,
	/* B4 */ 2,
	/* B5 */ 4,
	/* B6 */ 6,
	/* B7 */ 6,
	/* B8 */ 6,
	/* B9 */ 6,
	/* BA */ 6,
	/* BB */ 10,
	/* BC */ 10,
	/* BD */ 10,
	/* BE */ 10,
	/* BF */ 4,
	/* C0 */ 6,
	/* C1 */ 8,
	/* C2 */ 2,
	/* C3 */ 2,
	/* C4 */ 2,
	/* C5 */ 2,
	/* C6 */ 6,
	/* C7 */ 2,
	/* C8 */ 2,
	/* C9 */ 2,
	/* CA */ 2,
	/* CB */ 2,
	/* CC */ 2,
	/* CD */ 2,
	/* CE */ 2,
	/* CF */ 2,
	/* D0 */ 4,
	/* D1 */ 4,
	/* D2 */ 4,
	/* D3 */ 4,
	/* D4 */ 4,
	/* D5 */ 4,
	/* D6 */ 4,
	/* D7 */ 4,
	/* D8 */ 4,
	/* D9 */ 4,
	/* DA */ 4,
	/* DB */ 2,
	/* DC */ 4,
	/* DD */ 2,
	/* DE */ 2,
	/* DF */ 2,
	/* E0 */ 4,
	/* E1 */ 4,
	/* E2 */ 4,
	/* E3 */ 4,
	/* E4 */ 4,
	/* E5 */ 4,
	/* E6 */ 4,
	/* E7 */ 4,
	/* E8 */ 4,
	/* E9 */ 4,
	/* EA */ 4,
	/* EB */ 4,
	/* EC */ 4,
	/* ED */ 4,
	/* EE */ 4,
	/* EF */ 4,
	/* F0 */ 4,
	/* F1 */ 5,
	/* F2 */ 8,
	/* F3 */ 2,
	/* F4 */ 2,
	/* F5 */ 4,
	/* F6 */ 2,
	/* F7 */ 4,
	/* F8 */ 4,
	/* F9 */ 2,
	/* FA */ 2,
	/* FB */ 2,
	/* FC */ 2,
	/* FD */ 2,
	/* FE */ 2,
	/* FF */ 2,
};

// 0xFF extended table
static const ut8 ff_sizes[256] = {
	/* 00 */ 4, /* 01 */ 2, /* 02 */ 2, /* 03 */ 4,
	/* 04 */ 4, /* 05 */ 2, /* 06 */ 2, /* 07 */ 2,
	/* 08 */ 2, /* 09 */ 4, /* 0A */ 2, /* 0B */ 2,
	/* 0C */ 8, /* 0D */ 6, /* 0E */ 6, /* 0F */ 6,
	/* 10 */ 6, /* 11 */ 2, /* 12 */ 2, /* 13 */ 2,
	/* 14 */ 2, /* 15 */ 2, /* 16 */ 4, /* 17 */ 4,
	/* 18 */ 4, /* 19 */ 4, /* 1A */ 3, /* 1B */ 2,
	/* 1C */ 3, /* 1D */ 2, /* 1E */ 6, /* 1F */ 2,
	/* 20 */ 2, /* 21 */ 2, /* 22 */ 2, /* 23 */ 2,
	/* 24 */ 2, /* 25 */ 2, /* 26 */ 2, /* 27 */ 2,
	/* 28 */ 2, /* 29 */ 2, /* 2A */ 4, /* 2B */ 4,
	/* 2C */ 4, /* 2D */ 2, /* 2E */ 2, /* 2F */ 2,
	/* 30 */ 2, /* 31 */ 4, /* 32 */ 6, /* 33 */ 6,
	/* 34 */ 6, /* 35 */ 4, /* 36 */ 4, /* 37 */ 4,
	/* 38 */ 6, /* 39 */ 4, /* 3A */ 8, /* 3B */ 8,
	/* 3C */ 8, /* 3D */ 6, /* 3E */ 8, /* 3F */ 2,
	/* 40 */ 2, /* 41 */ 6, /* 42 */ 8, /* 43 */ 4,
	/* 44 */ 6, /* 45 */ 6, /* 46 */ 2,
	/* Remainder filled to 256 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 47-56 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 57-66 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 67-76 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 77-86 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 87-96 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 97-a6 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* a7-b6 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* b7-c6 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* c7-d6 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* d7-e6 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* e7-f6 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, /* f7-ff */
};

// Single-byte opcode size table (0x00–0xFF inclusive).
// Sizes include the opcode byte itself plus any fixed immediates.
// Variable-size opcodes (n/2 in the source table) are marked 1 (fallback).
static const ut8 op_sizes[256] = {
	/* 00 */ 4,
	/* 01 */ 2,
	/* 02 */ 4,
	/* 03 */ 2,
	/* 04 */ 4,
	/* 05 */ 4,
	/* 06 */ 4,
	/* 07 */ 6,
	/* 08 */ 4,
	/* 09 */ 6,
	/* 0A */ 6,
	/* 0B */ 6,
	/* 0C */ 6,
	/* 0D */ 4,
	/* 0E */ 4,
	/* 0F */ 4,
	/* 10 */ 6,
	/* 11 */ 4,
	/* 12 */ 4,
	/* 13 */ 1,
	/* 14 */ 1,
	/* 15 */ 1,
	/* 16 */ 1,
	/* 17 */ 1,
	/* 18 */ 1,
	/* 19 */ 4,
	/* 1A */ 4,
	/* 1B */ 4,
	/* 1C */ 4,
	/* 1D */ 4,
	/* 1E */ 4,
	/* 1F */ 4,
	/* 20 */ 4,
	/* 21 */ 1,
	/* 22 */ 4,
	/* 23 */ 4,
	/* 24 */ 3,
	/* 25 */ 1,
	/* 26 */ 4,
	/* 27 */ 4,
	/* 28 */ 6,
	/* 29 */ 1,
	/* 2A */ 1,
	/* 2B */ 4,
	/* 2C */ 6,
	/* 2D */ 3,
	/* 2E */ 3,
	/* 2F */ 3,
	/* 30 */ 3,
	/* 31 */ 3,
	/* 32 */ 1,
	/* 33 */ 3,
	/* 34 */ 1,
	/* 35 */ 3,
	/* 36 */ 1,
	/* 37 */ 1,
	/* 38 */ 3,
	/* 39 */ 1,
	/* 3A */ 6,
	/* 3B */ 1,
	/* 3C */ 1,
	/* 3D */ 3,
	/* 3E */ 3,
	/* 3F */ 3,
	/* 40 */ 1,
	/* 41 */ 1,
	/* 42 */ 1,
	/* 43 */ 3,
	/* 44 */ 3,
	/* 45 */ 2,
	/* 46 */ 3,
	/* 47 */ 3,
	/* 48 */ 3,
	/* 49 */ 1,
	/* 4A */ 1,
	/* 4B */ 3,
	/* 4C */ 1,
	/* 4D */ 6,
	/* 4E */ 4,
	/* 4F */ 3,
	/* 50 */ 1,
	/* 51 */ 3,
	/* 52 */ 1,
	/* 53 */ 1,
	/* 54 */ 7,
	/* 55 */ 1,
	/* 56 */ 3,
	/* 57 */ 6,
	/* 58 */ 3,
	/* 59 */ 3,
	/* 5A */ 1,
	/* 5B */ 3,
	/* 5C */ 3,
	/* 5D */ 1,
	/* 5E */ 6,
	/* 5F */ 6,
	/* 60 */ 1,
	/* 61 */ 8,
	/* 62 */ 3,
	/* 63 */ 3,
	/* 64 */ 6,
	/* 65 */ 6,
	/* 66 */ 6,
	/* 67 */ 6,
	/* 68 */ 6,
	/* 69 */ 6,
	/* 6A */ 6,
	/* 6B */ 3,
	/* 6C */ 3,
	/* 6D */ 3,
	/* 6E */ 3,
	/* 6F */ 3,
	/* 70 */ 3,
	/* 71 */ 3,
	/* 72 */ 3,
	/* 73 */ 3,
	/* 74 */ 3,
	/* 75 */ 3,
	/* 76 */ 3,
	/* 77 */ 3,
	/* 78 */ 3,
	/* 79 */ 3,
	/* 7A */ 3,
	/* 7B */ 3,
	/* 7C */ 3,
	/* 7D */ 3,
	/* 7E */ 3,
	/* 7F */ 3,
	/* 80 */ 3,
	/* 81 */ 3,
	/* 82 */ 3,
	/* 83 */ 3,
	/* 84 */ 3,
	/* 85 */ 3,
	/* 86 */ 3,
	/* 87 */ 3,
	/* 88 */ 3,
	/* 89 */ 3,
	/* 8A */ 3,
	/* 8B */ 3,
	/* 8C */ 3,
	/* 8D */ 3,
	/* 8E */ 3,
	/* 8F */ 3,
	/* 90 */ 3,
	/* 91 */ 3,
	/* 92 */ 3,
	/* 93 */ 5,
	/* 94 */ 5,
	/* 95 */ 5,
	/* 96 */ 5,
	/* 97 */ 5,
	/* 98 */ 5,
	/* 99 */ 5,
	/* 9A */ 5,
	/* 9B */ 5,
	/* 9C */ 5,
	/* 9D */ 1,
	/* 9E */ 1,
	/* 9F */ 1,
	/* A0 */ 1,
	/* A1 */ 1,
	/* A2 */ 1,
	/* A3 */ 1,
	/* A4 */ 1,
	/* A5 */ 1,
	/* A6 */ 1,
	/* A7 */ 3,
	/* A8 */ 3,
	/* A9 */ 1,
	/* AA */ 1,
	/* AB */ 1,
	/* AC */ 1,
	/* AD */ 1,
	/* AE */ 1,
	/* AF */ 1,
	/* B0 */ 1,
	/* B1 */ 1,
	/* B2 */ 1,
	/* B3 */ 1,
	/* B4 */ 1,
	/* B5 */ 1,
	/* B6 */ 1,
	/* B7 */ 1,
	/* B8 */ 1,
	/* B9 */ 1,
	/* BA */ 1,
	/* BB */ 1,
	/* BC */ 1,
	/* BD */ 1,
	/* BE */ 1,
	/* BF */ 1,
	/* C0 */ 1,
	/* C1 */ 1,
	/* C2 */ 1,
	/* C3 */ 1,
	/* C4 */ 1,
	/* C5 */ 1,
	/* C6 */ 1,
	/* C7 */ 1,
	/* C8 */ 1,
	/* C9 */ 1,
	/* CA */ 1,
	/* CB */ 1,
	/* CC */ 1,
	/* CD */ 1,
	/* CE */ 1,
	/* CF */ 1,
	/* D0 */ 1,
	/* D1 */ 1,
	/* D2 */ 1,
	/* D3 */ 1,
	/* D4 */ 1,
	/* D5 */ 1,
	/* D6 */ 1,
	/* D7 */ 1,
	/* D8 */ 1,
	/* D9 */ 1,
	/* DA */ 2,
	/* DB */ 2,
	/* DC */ 2,
	/* DD */ 1,
	/* DE */ 1,
	/* DF */ 1,
	/* E0 */ 1,
	/* E1 */ 1,
	/* E2 */ 1,
	/* E3 */ 1,
	/* E4 */ 1,
	/* E5 */ 1,
	/* E6 */ 1,
	/* E7 */ 1,
	/* E8 */ 1,
	/* E9 */ 1,
	/* EA */ 1,
	/* EB */ 1,
	/* EC */ 1,
	/* ED */ 1,
	/* EE */ 1,
	/* EF */ 1,
	/* F0 */ 1,
	/* F1 */ 1,
	/* F2 */ 1,
	/* F3 */ 3,
	/* F4 */ 2,
	/* F5 */ 5,
	/* F6 */ 9,
	/* F7 */ 5,
	/* F8 */ 3,
	/* F9 */ 5,
	/* FA */ 9,
	/* FB */ 1,
	/* FC */ 1,
	/* FD */ 1,
	/* FE */ 1,
	/* FF */ 1,
};

// Helper: classify extended (two-byte) opcodes
static void classify_extended(ut8 prefix, ut8 sub, RzAnalysisOp *op) {
	// Defaults
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;

	switch (prefix) {

	// 0xFB extended space
	case 0xFB:
		switch (sub) {
		// Push [FC0D134] slots
		case 0x00:
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x08:
		case 0x0C:
		case 0x0D:
		case 0x0E:
		case 0x10:
		case 0x14:
		case 0x15:
		case 0x16:
		case 0x18:
		case 0x1C:
		case 0x1D:
		case 0x1E:
		case 0x20:
		case 0x24:
		case 0x25:
		case 0x26:
		case 0x28:
		case 0x77:
		case 0x78:
		case 0x79:
		case 0x7A:
		case 0x7B:
		case 0x7C:
		case 0x83:
		case 0x95:
		case 0x9D:
		case 0xA1:
		case 0xA2:
		case 0xA3:
		case 0xA5:
		case 0xA9:
		case 0xAA:
		case 0xAB:
		case 0xAD:
		case 0xB5:
		case 0xB6:
		case 0xB7:
		case 0xB8:
		case 0xBB:
		case 0xBD:
		case 0xC1:
		case 0xC2:
		case 0xC3:
		case 0xC5:
		case 0xC6:
		case 0xCD:
		case 0xD3:
		case 0xDA:
		case 0xDB:
		case 0xDC:
		case 0xDD:
		case 0xDE:
		case 0xDF:
		case 0xE2:
		case 0xE3:
		case 0xE4:
		case 0xE5:
		case 0xEA:
		case 0xF1:
		case 0xF8:
		case 0xF9:
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			break;
		// Push with offset (MOV-like loads into result reg)
		case 0x07:
		case 0x0F:
		case 0x17:
		case 0x1F:
		case 0x27:
		case 0x2F:
		case 0x94:
		case 0x9C:
		case 0xA4:
		case 0xAC:
		case 0xB4:
		case 0xBC:
		case 0xC4:
		case 0xCC:
		case 0xCE:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		// Arithmetic / integer ops
		case 0x98: // Push Pop1+Pop2 (ADD on stack)
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case 0xD1: // vbaCyMulI2
			op->type = RZ_ANALYSIS_OP_TYPE_MUL;
			break;
		case 0xF0: // vbaStrCat
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		// Comparisons
		case 0x6B:
		case 0x6C: // Push (Pop1 > Pop2)
		case 0x6D:
		case 0x6E: // Push (Pop1 >= Pop2)
		case 0x81:
		case 0x82: // vbaVarLike / vbaVarTextLike
		case 0xD2: // vbaObjIs
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		// Length
		case 0xEB:
		case 0xEC: // vbaLenVar / vbaLenBstr
			op->type = RZ_ANALYSIS_OP_TYPE_LENGTH;
			break;
		// Type casts / conversions
		case 0xFC:
		case 0xFD: // vbaStrI2
		case 0xFE: // vbaStrI4
		case 0xFF: // vbaStrR4
			op->type = RZ_ANALYSIS_OP_TYPE_CAST;
			break;
		// File I/O
		case 0xFA: // vbaFileSeek
		case 0xFB: // vbaNameFile
			op->type = RZ_ANALYSIS_OP_TYPE_IO;
			break;
		// Fixed-float ops
		case 0xE0: // vbaCyFix
		case 0xE8: // vbaCyInt
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
			break;
		}
		break;

	case 0xFC:
		switch (sub) {
		// NOP
		case 0x14: // No Operation
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		// IDE beginning of line
		case 0xC4:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		// Push / load
		case 0x03:
		case 0x09:
		case 0x0C:
		case 0x0E:
		case 0x15:
		case 0x1E:
		case 0x36:
		case 0x37:
		case 0x4A:
		case 0x4C:
		case 0x63:
		case 0x68:
		case 0x6B:
		case 0x6C:
		case 0x6E:
		case 0x70:
		case 0x9E:
		case 0x9F:
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			break;
		// String concatenation
		case 0xF0: // vbaStrCat
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		// String length
		case 0xEB: // vbaLenVar
		case 0xEC: // vbaLenBstr
		case 0xED: // vbaLenVarB
			op->type = RZ_ANALYSIS_OP_TYPE_LENGTH;
			break;
		// Comparisons
		case 0x6F: // vbaCheckTypeVar
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		// Bitwise NOT
		case 0x50:
		case 0x51: // Not#2
		case 0x52: // Not#4
			op->type = RZ_ANALYSIS_OP_TYPE_NOT;
			break;
		// Type conversions
		case 0x1A:
		case 0x22:
		case 0x2A:
		case 0x32: // vbaI2Var/I4Var/R8Var
		case 0x0A: // vbaCyVar
		case 0x4E:
		case 0x4F: // vbaDateVar
		case 0x56:
		case 0x57: // vbaBoolVar/BoolStr
		case 0x58:
		case 0x5A: // vbaStrToUnicode/Ansi
		case 0x1B:
		case 0x23:
		case 0x2B:
		case 0x43: // Str conversions
			op->type = RZ_ANALYSIS_OP_TYPE_CAST;
			break;
		// Calls: vbaGet3/4, vbaPut3/4
		case 0x75:
		case 0x76:
		case 0x77:
		case 0x78:
		case 0x69:
		case 0x6A:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			break;
		// I/O
		case 0x62: // kernel GetLastError
		case 0xBF:
		case 0xC0: // vbaLineInputVar/Str
			op->type = RZ_ANALYSIS_OP_TYPE_IO;
			break;
		// MOV / memory
		case 0xBB:
		case 0xBC:
		case 0xBD: // vbaMidStmt*
		case 0xF7: // SysFreeString / string assign
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		// Return / exit proc
		case 0xCE:
		case 0xCF:
		case 0xD0:
		case 0xD1:
		case 0xD3:
		case 0xD4:
		case 0xD5:
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			break;
		// Memory move operations (many-indexed)
		case 0x16:
		case 0x17:
		case 0x18:
		case 0x19:
		case 0x1C:
		case 0x1D:
		case 0x1F:
		case 0x20:
		case 0x21:
		case 0x24:
		case 0x25:
		case 0x26:
		case 0x27:
		case 0x28:
		case 0x29:
		case 0x2C:
		case 0x2D:
		case 0x2E:
		case 0x2F:
		case 0x30:
		case 0x31:
		case 0x38:
		case 0x39:
		case 0x3A:
		case 0x3B:
		case 0x3C:
		case 0x3D:
		case 0x3E:
		case 0x3F:
		case 0x40:
		case 0x41:
		case 0xFC:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
			break;
		}
		break;

	case 0xFD:
		switch (sub) {
		// Conditional branch: If Pop=0
		case 0x04:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			break;
		// Conditional branch: If Pop<>0
		case 0x07:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			break;
		// Unconditional branch
		case 0x03:
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			break;
		// Push / load
		case 0x12:
		case 0x13:
		case 0x17:
		case 0x18:
		case 0x1E:
		case 0x1F:
		case 0x3F:
		case 0x4E:
		case 0x4F:
		case 0x62:
		case 0x65:
		case 0x66:
		case 0x6D:
		case 0x7E:
		case 0x7F:
		case 0x92:
		case 0x97:
		case 0x98:
		case 0xAE:
		case 0xAF:
		case 0xDE:
		case 0xDF:
		case 0xA6:
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			break;
		// MOV / memory operations
		case 0x00: // vbaVarCopy
		case 0x01: // [arg]=SysAllocStringByteLen
		case 0x0F: // Pop [arg+0C]; Push EAX (return by ref)
		case 0x27: // SysFreeString [[arg]]; [[arg]]=Pop
		case 0x2F: // SysFreeString [arg]; [arg]=0
		case 0x31: // [[arg]]=SysAllocStringByteLen
		case 0x3A: // write to struct member
		case 0x47: // write with offset
		// case 0x4F: // write, longer
		case 0x64: // SysFreeString [arg]; [arg]=[stack]
		case 0x91: // [SR]+imm#2=SysAllocStringByteLen
		case 0xF0: // vbaVarCopy
		case 0x9A:
		case 0x9B:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		// Calls
		case 0xF2:
		case 0xF3:
		case 0xF4:
		case 0xF6:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			break;
		// COM method dispatch (Push [arg]; Call [[[arg]]+8]; [[arg]]=0)
		case 0x9C:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			break;
		// Return
		case 0xFF: // vbaRecDestruct
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			break;
		// Type casts
		case 0x67:
		case 0xF7:
		case 0xF8:
		case 0xF9:
		case 0xFA:
		case 0xFB:
		case 0xFC:
		case 0xFD:
		case 0xFE:
		case 0xF5:
			op->type = RZ_ANALYSIS_OP_TYPE_CAST;
			break;
		// IDE / debug begin-of-line
		case 0x26:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		// Comparisons
		case 0x05:
		case 0x08:
		case 0x09:
		case 0x0A:
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		// FPU/array memory (large group – MOV-like)
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		}
		break;

	case 0xFE:
		switch (sub) {
		// Call variants
		case 0x21:
		case 0x22:
		case 0x25:
		case 0x27:
		case 0x28:
		case 0x29:
		case 0x2A:
		case 0x2C:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			break;
		// Return / exit proc
		case 0xCF: // vbaErase (used as end)
		case 0xD0:
		case 0xD1: // exit pcode engine group
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			break;
		// IDE beginning of line
		case 0xC4:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		// Push / load
		case 0x06:
		case 0x0B:
		case 0x16:
		case 0x1B:
		case 0x26:
		case 0x2B:
		case 0x5F:
		case 0x69:
		case 0x71:
		case 0x7F:
		case 0x87:
		case 0x94:
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			break;
		// Push literal immediates (many slots in 0x30-0x4F are placeholders)
		case 0x30:
		case 0x31:
		case 0x32:
		case 0x33:
		case 0x34:
		case 0x35:
		case 0x36:
		case 0x37:
		case 0x38:
		case 0x39:
		case 0x3A:
		case 0x3B:
		case 0x3C:
		case 0x3E:
		case 0x3F:
		case 0x40:
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x45:
		case 0x46:
		case 0x47:
		case 0x48:
		case 0x49:
		case 0x4A:
		case 0x4B:
		case 0x4C:
		case 0x50:
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x56:
		case 0x57:
		case 0x58:
		case 0x59:
		case 0x5A:
		case 0x5B:
		case 0x5C:
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			break;
		// Push literal bytes (B5-BE area = Push imm variants)
		case 0xB5:
		case 0xB6:
		case 0xB7:
		case 0xB8:
		case 0xB9:
		case 0xBA:
		case 0xBB:
		case 0xBC:
		case 0xBD:
		case 0xBE:
		case 0xBF:
		case 0xC0:
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			break;
		// I/O
		case 0x5D: // vbaFileOpen
		case 0x5E: // vbaFileLock
			op->type = RZ_ANALYSIS_OP_TYPE_IO;
			break;
		// String comparisons
		case 0xFB:
		case 0xFC:
		case 0xFD:
		case 0xFE:
		case 0xFF: // vbaInStrB, vbaInStrVarB, vbaInStr, vbaInStrVar, vbaStrComp
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		// Type check
		case 0x8D: // vbaCheckType
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		// Comparison (integer)
		case 0x4D:
		case 0x4E: // vbaFileLock-adjacent comparisons
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		// Date/string conversion
		case 0xC9: // vbaDateStr
			op->type = RZ_ANALYSIS_OP_TYPE_CAST;
			break;
		// vbaRecAssign / vbaRecDestructAnsi
		case 0xF5:
		case 0xF6:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		// MOV-like string/struct ops
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x05:
		case 0x07:
		case 0x08:
		case 0x09:
		case 0x0A:
		case 0x0C:
		case 0x0E:
		case 0x0F:
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
		case 0x14:
		case 0x15:
		case 0x17:
		case 0x18:
		case 0x19:
		case 0x1A:
		case 0x1C:
		case 0x1D:
		case 0x1E:
		case 0x1F:
		case 0x20:
		case 0x23:
		case 0x24:
		case 0x2E:
		case 0x2F:
		case 0x60:
		case 0x61:
		case 0xB0:
		case 0xB1:
		case 0xF7:
		case 0xF8:
		case 0xF9:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		// Duplicate case , donot remove comments for now
		// Array / erase ops
		// case 0x60: case 0x62: // vbaErase variants
		// op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		// break;
		// vbaVarDup
		// case 0xF8:
		// op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		// break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
			break;
		}
		break;

	case 0xFF:
		switch (sub) {
		// vbaStrCompVar
		case 0x00:
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		// Array moves / copies
		case 0x01:
		case 0x02:
		case 0x03:
		case 0x04:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		// Push / load
		case 0x05:
		case 0x11:
		case 0x1F:
		case 0x20:
		case 0x21:
		case 0x22:
		case 0x23:
		case 0x24:
		case 0x25:
		case 0x26:
		case 0x27:
		case 0x28:
		case 0x29:
		case 0x3F:
		case 0x40:
		case 0x46:
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			break;
		// Push imm#1
		case 0x1A:
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			break;
		// IDE beginning of line
		case 0x1C:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		// File write / read
		case 0x0F: // vbaWriteFile
		case 0x10: // vbaInputFile
		case 0x12:
		case 0x13:
		case 0x14:
		case 0x15: // Get/PutFxStr3/4
		case 0x16:
		case 0x17:
		case 0x18:
		case 0x19: // GetOwner3/4 / PutOwner3/4
			op->type = RZ_ANALYSIS_OP_TYPE_IO;
			break;
		// vbaRecDestruct
		case 0x2A:
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
			break;
		// vbaBoolVarNull
		case 0x1B:
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
			break;
		// vbaEraseKeepData / vbaErase
		case 0x31:
		case 0x38:
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
			break;
		// vbaUdtVar / vbaAryVar
		case 0x35:
		case 0x36:
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
			break;
		// vbaCVarAryUdt (MOV-like deep copy)
		case 0x3A:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		// Array rebase
		case 0x0A:
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
			break;
		// Call dispatch
		case 0x08:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
			break;
		}
		break;

	default:
		break;
	}
}

// Main analysis callback
static int mspcode_op(RzAnalysis *ana, RzAnalysisOp *op, ut64 addr,
	const ut8 *b, int len, RzAnalysisOpMask mask) {
	if (len < 1) {
		return 0;
	}

	op->size = 1;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;

	ut8 opcode = b[0];

	// Two-byte escape prefix space: 0xFB – 0xFF
	if (opcode >= 0xFB) {
		if (len < 2) {
			op->size = 1;
			return 1;
		}
		ut8 sub = b[1];
		ut8 esz = 2;
		switch (opcode) {
		case 0xFB: esz = fb_sizes[sub]; break;
		case 0xFC: esz = fc_sizes[sub]; break;
		case 0xFD: esz = fd_sizes[sub]; break;
		case 0xFE: esz = fe_sizes[sub]; break;
		case 0xFF: esz = ff_sizes[sub]; break;
		}
		if (esz == 0) {
			esz = 2;
		}
		op->size = (int)esz;

		classify_extended(opcode, sub, op);

		// Resolve branch targets for known jump sub-opcodes in 0xFD
		if (opcode == 0xFD) {
			if ((sub == 0x04 || sub == 0x07) && len >= 4) {
				// conditional jump: 2 opcode bytes + 2-byte signed offset
				st16 offset = (st16)rz_read_le16(b + 2);
				op->jump = addr + op->size + offset;
				op->fail = addr + op->size;
			} else if (sub == 0x03 && len >= 4) {
				st16 offset = (st16)rz_read_le16(b + 2);
				op->jump = addr + op->size + offset;
			}
		}

		return op->size;
	}

	// Single-byte opcode space (0x00 – 0xFA)
	op->size = (int)op_sizes[opcode];
	if (op->size == 0) {
		op->size = 1;
	}

	switch (opcode) {

	// IDE markers / debug line info
	case 0x00: // IDE beginning of line with imm#1 byte codes
	case 0x02: // IDE beginning of line with imm#1 byte codes
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;

	// Push [FC0D134] (load well-known global)
	case 0x01:
	case 0x03:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Push arg / Push ptr / Push [SR]+arg
	case 0x04: // Push arg
	case 0x05: // Push ptr
	case 0x06: // Push [SR]+arg
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Push [arg1]+imm#2
	case 0x07:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// [SR]=[arg]   (store into SR register)
	case 0x08:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// Call instructions (ptr1, check stack, optional push EAX)
	case 0x0A: // Call ptr1; check stack (no return value)
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		if (len >= 6) {
			ut32 target = rz_read_le32(b + 2);
			op->jump = (ut64)target;
		}
		break;

	case 0x0B: // Call ptr1; check stack; Push EAX
	case 0x5E: // same encoding, alias
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		if (len >= 6) {
			ut32 target = rz_read_le32(b + 2);
			op->jump = (ut64)target;
		}
		break;

	case 0x0C: // make call (IDE version)
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;

	// Procedure end / return
	case 0x13: // end proc (seen in table at 0x13 = idx 13)
	case 0x14: // end proc
	case 0x15: // (end proc area)
	case 0x16: // exit procedure
	case 0x17: // exit pcode engine group
	case 0x18: // exit pcode engine group
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;

	// [SR]=[[arg]]  / load through pointer
	case 0x19:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// Push [arg]; Call [[[arg]]+8]; [[arg]]=0 (COM method dispatch)
	case 0x1A:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;

	// Push ptr
	case 0x1B:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Conditional branch: If Pop=0
	case 0x1C:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		if (len >= 4) {
			st16 offset = (st16)rz_read_le16(b + 2);
			op->jump = addr + op->size + offset;
			op->fail = addr + op->size;
		}
		break;

	// Conditional branch: If Pop<>0
	case 0x1D:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		if (len >= 4) {
			st16 offset = (st16)rz_read_le16(b + 2);
			op->jump = addr + op->size + offset;
			op->fail = addr + op->size;
		}
		break;

	// Unconditional branch: ESI=ProcPC+imm#2
	case 0x1E:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		if (len >= 4) {
			st16 offset = (st16)rz_read_le16(b + 2);
			op->jump = addr + op->size + offset;
		}
		break;

	// vbaRecUniToAnsi / vbaRecAnsiToUni
	case 0x1F:
	case 0x20:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;

	// [SR]=[stack2]
	case 0x21:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// SysFreeString family / string moves
	case 0x23: // SysFreeString [arg]; [arg]=[stack]
	case 0x2F: // SysFreeString [arg]; [arg]=0
	case 0x31: // SysFreeString [arg]; [arg]=Pop
	case 0x43: // [arg]=SysAllocStringByteLen(Pop, [Pop-4]); SysFreeString Pop
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// [Pop] [SR]
	case 0x24:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// Pop [arg+0C]; Push EAX  (return by reference helper)
	case 0x26:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// PushVarError 80020004 (missing optional argument marker)
	case 0x27:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// PushVarInteger imm2#2
	case 0x28:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// vbaStrCat
	case 0x2A:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;

	// Variable-size free / cleanup ops (size is data-dependent)
	case 0x29: // (variable) push/call variant
	case 0x32: // Do SysFreeString [arg_n] n/2 times
	case 0x36: // Free imm1#2/2 variants
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		op->size = 1;
		break;

	// vbaStrToAnsi
	case 0x34:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;

	// PushVarString ptr2
	case 0x3A:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// FP exception checks / GetLastError
	case 0x39: // check for 64-bit fp exception
	case 0x3B: // check for 64-bit fp exception
	case 0x3C: // kernel GetLastError
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;

	// Push vbaCastObj(Pop, [FUN+imm#2*4])
	case 0x3D:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;

	// Push#4 [arg]; [arg]=0
	case 0x3E:
	case 0x51: // alias
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// vbaR8Var / vbaI2Var (type conversions)
	case 0x42: // vbaR8Var
	case 0x55: // vbaI2Var
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;

	// vbaLenBstr
	case 0x4A:
		op->type = RZ_ANALYSIS_OP_TYPE_LENGTH;
		break;

	// vbaLBound
	case 0x4C:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;

	// [arg]=vbaVarDup(Pop)
	case 0x4E:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// vbaMidStmtBstr (string mid-assignment)
	case 0x4F:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// vbaI4Str
	case 0x50:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;

	// vbaErase
	case 0x5A:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;

	// [SR]=[[arg]]
	case 0x48:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// [SR]=[[SR]+imm#2]
	case 0x58:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// vbaLsetFixstr
	case 0x47:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// vbaVarMove
	case 0x57:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// Push#2 [arg] / Push#4 [arg]
	case 0x6B: // Push#2 [arg]
	case 0x6C: // Push#4 [arg]
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// FPU loads (push long real / push quadword real)
	case 0x6E: // fld#4 [arg]
	case 0x6F: // Fld#8 [arg]
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Integer pop / store
	case 0x70: // Pop#2 [arg]
	case 0x71: // Pop#4 [arg]
	case 0x75: // Pop [arg]
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;

	// FPU stores (pop real / pop quadword)
	case 0x73: // Fstp#4 [arg]
	case 0x74: // Fstp#8 [arg]
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;

	// Pop#2 [[SR]+arg*4]
	case 0x7A:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;

	// Push [arg]  (0x80 variant)
	case 0x80:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Push#2 [[SR]+imm#2] / Push#4 [[SR]+imm#2]
	case 0x89: // Push#2 [[SR]+imm#2]
	case 0x8A: // Push#4 [[SR]+imm#2]
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Pop#2 [[SR]+imm#2]
	case 0x8E:
	case 0x8F:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;

	// Push#2 [[arg1]+imm#2] / Push#4 [[arg1]+imm#2]
	case 0x93:
	case 0x94:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Pop#2 / Pop#4 [[arg1]+imm#2]
	case 0x98:
	case 0x99:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;

	// Integer comparisons: GT(#2), GT(#4), GE
	case 0xDA: // Push (Pop1 > Pop2) #2
	case 0xDB: // Push (Pop1 > Pop2) #4
	case 0xDC: // Push (Pop1 >= Pop2)
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;

	// Verify [stack] high word is 0000
	case 0xE4:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;

	// Push [SR]+arg
	case 0x56:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// [SR]=[arg]
	case 0x62:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// Push imm#1  (literal byte)
	case 0xF4:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Push imm#4  (literal dword)
	case 0xF5:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Push imm2; Push imm1  /  PushQWord imm
	case 0xF6:
	case 0xF7:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Fild imm (FPU Load Integer) / Fld imm (FPU Load Real)
	case 0xF8:
	case 0xF9:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Large literal (9 bytes total)
	case 0xFA:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Escape prefixes consumed above (0xFB-0xFF) – should not reach here
	case 0xFB:
	case 0xFC:
	case 0xFD:
	case 0xFE:
	case 0xFF:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		op->size = 1;
		break;

	// Everything not explicitly listed
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}

	return op->size;
}

// Plugin descriptor
RzAnalysisPlugin rz_analysis_plugin_mspcode = {
	.name = "mspcode",
	.arch = "mspcode",
	.license = "LGPL3",
	.bits = 32,
	.desc = "Microsoft VBA P-Code (mspcode) analysis plugin",
	.op = &mspcode_op,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_mspcode,
	.version = RZ_ANALYSIS_PLUGIN_VERSION,
};
#endif
