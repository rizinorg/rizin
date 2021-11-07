// SPDX-FileCopyrightText: 2021 borzacchiello <lucaborza@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_str_search.h>
#include <rz_util/rz_utf8.h>
#include <rz_util/rz_utf16.h>
#include <rz_util/rz_utf32.h>
#include <rz_util/rz_ebcdic.h>

typedef enum {
	SKIP_STRING,
	RETRY_ASCII,
	STRING_OK,
} FalsePositiveResult;

/**
 * much port from https://github.com/hsivonen/chardetng, but not not very 
 * suitable for rizin
 * /
// clang-format off
static const ut8 unicode_class[256] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
	0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x00,0x00,0x00,0x00,0x00,
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x00,0x00,0x00,0x00,0x00,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0x00,0x3e,0x3c,0x3c,0x3c,0x3c,0x3b,0x3c,0x3c,0x3e,0x3c,0x3b,0x3f,0x3b,0x3d,0x3c,
	0x3e,0x3f,0x3d,0x3d,0x3c,0x3e,0x3d,0x3b,0x3c,0x3d,0x3c,0x3b,0x3e,0x3e,0x3e,0x3e,
	0x9e,0x9f,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,
	0xbc,0xae,0xaf,0xb0,0xb1,0xb2,0xb3,0x3f,0xb4,0xb5,0xb6,0xb7,0xb8,0xbc,0xbc,0x1b,
	0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,
	0x3c,0x2e,0x2f,0x30,0x31,0x32,0x33,0x3f,0x34,0x35,0x36,0x37,0x38,0x3c,0x3c,0x3a,
};

static const ut8 WESTERN_ASCII = 27;
static const ut8 WESTERN_NON_ASCII = 32;

static const ut8 WESTERN[2752] = {
                                                                                                                     18,  3,  0,254, 74,  0,  5,254,254,  2, 25,254,149,  4,254, 66,148,254,  0,254,122,238,  8,  1, 20, 13,254, 35, 20,  3,  1,  0, //  ,
                                                                                                                      0,  3,  0,  0,  0,  0,  0,  5,  2,  0, 86,  9, 76,  0,  0,  0,241,  0,  0, 49,  0,  0,  0,  0, 11,  2,  0, 34,  0,  1,  2,  0, // a,
                                                                                                                     19,  0,  0,  5,  5,  0,  0,  8, 13,  5,  0, 34, 22,  0,  0,  0,  4,  0,  0,  0,  6,  1,  3,  3, 42, 37,  8,  8,  0, 67,  0,  0, // b,
                                                                                                                      0,  0,  0,  9,  6,  1,  0, 22, 10,  1,  0, 19, 54,  1,  0,  1, 18,  3,  1,  2, 40,  7,  0,  0,  6,  0,  3,  5,  1, 34,  0,  0, // c,
                                                                                                                      0,  0,  0,  5,  5,  0,  0, 12, 45, 16,  1,  6, 42,  0, 13,  3, 10,  0,  2,  0, 66, 11,  5,  8, 33,104,  3,  4,  0, 19,  0,  0, // d,
                                                                                                                     63,  5,  0,  0,  0,  0,  2, 33, 15,  1,  3,  0, 87,  0,  0,  0,  0,  0,  1, 21,  0,  0,  0, 49,  1, 11,  0,  3,  0,  9,  1,  0, // e,
                                                                                                                      0,  0,  0,  8,  8,  0,  0, 10,  2,  7,  0,162, 23,  0, 13,  0,  4,  0,  0,  0,  1,  3,  0,  0, 15,  4,  0,  0,  0,  4,  0,  0, // f,
                                                                                                                      1,  0,  0, 14, 16, 24,  0, 29, 11, 41,  0, 13, 86,  0, 14,  9,  3,  0,  0,  0, 20,  8,  7,  7, 13, 37, 14,  0,  0, 12,  0,  0, // g,
                                                                                                                      1,  0,  0,  0,  0,  0,  0, 47,  2,  0,  0,  0,  1,  0,  7,  0,  0,  0,  0,  0,  0,  0,  0, 29, 20,  0,  0,  0,  0, 45,  0,  0, // h,
                                                                                                                      5,  4,  0,166,120,  0,  0,144,  0,  2,  3, 88,254,  0,  0,  0,  0,  0,  0,  3, 28,107,  0,112,  8,  2, 44, 32,  0,  3,  3,  0, // i,
                                                                                                                      0,  0,  0,  0,  0,  0,  0, 39,  9,  0,  0,  2,  1,  0,  2,  0,  0,  0,  0,  4,  0,  0,  0, 16, 18, 44,  0,  0,  0,  0,  0,255, // j,
                                                                                                                      0,  2,  0,  0,  1,  0,  0, 48, 31, 32,  1, 60,  1,  0,  4,  0,  1,  0,  0,  0,  1,  3,  0,  2, 20, 47,  0,  0,  0, 20,  0,  0, // k,
                                                                                                                      4,  0,  0, 12, 16,  0,  0, 54, 40, 48,  0, 64, 36,  0, 39,  6, 12,  3,  0,  0, 27,  9,  3, 24, 42, 33,  2,  9,  7, 77,  0,  0, // l,
                                                                                                                      0,  0,  0, 14,  5,  4,  0, 60, 11,  4,  3, 48, 30,  7, 28,  1, 10,  1,  0,  0, 24, 41,  3,  3, 19, 24,  1,  8,  2, 36,  0,  0, // m,
                                                                                                                      1,  1,  0, 24, 91, 16,  0,132, 62, 73,  1, 56, 71, 33, 78,  7, 35,  2,  3,  0, 94,254, 10, 21, 33, 38, 24, 21,  1, 61,  0,  0, // n,
                                                                                                                      0,  1,  0,  0,  0,  0,254,  6,  0,  1, 27,  0, 13,  0,  0, 84,127,  0,  0, 62,  0,  1,  0,  0,  2,  0,  0,  0,  0,  0,  0,  0, // o,
                                                                                                                      0,  0,  0,  5,  2,  0,  0,  9, 15,  0,  0,  4, 34,  0,  6,  0,  6,  0,  0,  0, 20, 12,  9, 28, 10, 22,  0,  3,  0,  7,  0,  0, // p,
                                                                                                                      0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  1, 33,  1,  0,  0,  0,  0,  0,  0,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,255,255, // q,
                                                                                                                      0,  0,  0, 83, 62,  1,  0,198,139,125,  0,229, 94, 54,190, 38, 18,  1,  0,  0,176, 24, 16, 29,193,181, 13, 13,  2,131,  0,  0, // r,
                                                                                                                      1,  0,  0, 41, 34,  0,  0, 41, 24, 42,  0, 68,113, 15,159,  6, 43, 19,  4, 58, 14, 18,  1,  4, 48, 42,  4, 12,  9, 20,  0,  0, // s,
                                                                                                                      7,  1,  0, 14, 20,  8,  0, 56, 37, 31,  0,104, 67, 14,113,  3, 50,  9,  5,  0, 89,  7, 19, 22, 13, 14, 40, 12, 15, 18,  0,  0, // t,
                                                                                                                      0,  1,  5,  1,  2,  0,  0, 30,  0,  0,  1, 15,  2,  0,  1,  0,  1,  0,  0,  2,  4,  0,  0, 36,  0,  0,  0,  0,  0,  0,  0,  0, // u,
                                                                                                                      0,  2,  0,  1,  6,  0,  0, 29, 33, 13,  0, 19, 46,  0, 15,  0,  7,  0,  1, 31,  2,  2,  3,  1, 32, 27,  0,  0,  1,  1,  0,  0, // v,
                                                                                                                      0,  0,  0,  0,  0,  0,  0,  0,  2,  0,  0,  3,  0,  0,  4,  0,  0,  0,  0,  0,  0,  2,  0,  0,  1,  0,  0,  0,  0,  0,  0,255, // w,
                                                                                                                      0,  0,  0,  1, 16,  0,  0, 23,  0,  0,  0,  3, 14,  0,  0,  0,  2,  3,  0,  0,  0,  6,  0,  0,  0,  0,  0,  0,  0,  0,255,  0, // x,
                                                                                                                      0,  0,  0,  0,  0,  0,  0, 58,  8,  0,  0,  1,  1, 62,  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  6, 82,  0,  0,  0,  0,  0,255, // y,
                                                                                                                      0,  0,  0,  0,  2,  0,  0,  0, 14,  0,  0,  7,  3,  0,  6,  0,  3,  5,  0,  0,  0,  0,  4,  0,  1,  0,  0,  0,  0,  0,  0,  0, // z,
          0, 29,  0,  0,  0, 15,  0,  0,  0, 11,  0,  0,  0,  0,  0, 20,  0,  0,  0,  0,  0, 37,  0,  0,  0,  0,  0,  0,255,255,  0,  0,255,255,  4,  0,  0,255,255,  0,255,  0,255,  0,  0,255,255,255,  0,  0,  0,  8,  0,255,  0,  0,  2,  0,  0, // ß,
          6,  2,  0,  0,  0,  1,  0,  0,  0,  1,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0, 10,  1,  0,  0,  0,  0,  0,  0,  0,255,  0,  1,  0,  0,  0,  0,  0,255,  0,  0,  0,  0,  0,  0,  0,255,255,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, // š,
          3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,255,  0,  0,  0,  0,  0,  0,  0,  0,  0,255,  0,  0,255,255,255,  0,  0,  0,255,255,255,  0,255,255,255,255,  0,  0,255,255,255,255,255,255,  0,255,255,255,  0,255,255, // œ,
        107,  0, 22, 16, 18, 14,  6, 24, 46, 15,  2,  0, 42, 18, 17,  0, 36,  0, 34,  4,254,  1,  2,  0,  0,  1,  0,  0,  0,255,  0,  0,  0,  0,  0,255,255,  0,  0,  0,  0,  0,  0,  0,255,  0,  0,  0,255,255,255,255,255,  0,  0,255,  0,  0,  0, // à,
         41,  0, 10,  8, 21, 34,  5,  5, 60, 18,  5,  1, 29, 42, 26,  2, 16,  0, 27,  9, 43, 28,  7,  0,  0,  1,  4,  0,  0,255,  0,  0,255,255,255,  0,255,  0,  0,  0,  0,255,  0,  0,  0,  0,  0,  0,  0,  0,255,255,255,  0,  0,  0,  0,  0,255, // á,
         24,  0,  1,  2,  0,  0,  0,  0,  7,  0,  0,  0,  3,  1,  0,  0,  0,  0,  2,  0,  5,  0,  1,  0,  0,  0,  0,255,  0,255,  0,  0,  0,255,  0,255,  0,  0,  0,  2,  0,255,  0,255,  0,  0,  0,  0,255,  0,255,255,255,255,255,  0,255,  0,255, // â,
          0,  0,  0,  1,  2,  3,  0,  1,  2, 12,  0,  0,  1,  7, 29,  4,  1,255, 11, 66, 11,  0,  1,  0,  0,  0,  0,255,  0,255,255,255,  0,  0,  0,255,255,127,255,255,255,255,255,  0,  0,255,  0,  0,255,255,  0,255,255,255,255,255,255,255,255, // ã,
        134,  1, 11,  0, 25,  6, 15, 11, 61, 24,123, 95,114, 68, 53,  1, 49,  0, 60, 98,198,  0, 88, 29,  0,  6, 12,  0,  0,255,  0,255,  0,  0,118,  0,255,  0,255,  0,255,  0,255,  0,255,255,  0,255,255,  0,255,  2,255,255,255,  0,  0,  0,255, // ä,
        156,  0, 12, 14, 19,  3, 12, 47, 17,  3, 12,  5, 30, 47, 22,  0,205,  0,184, 70, 19,  0, 22,  8,  0,  6,  1,255,  0,255,255,  0,255,  0,  0,  0,  0,  0,255,  0,255,  0,255,  0,  0,255,255,255,255,255,255,  0,  0,255,255,255,255,255,255, // å,
         26,  0,  7,  0,  4,  0, 23,  8, 15,  0, 18, 19, 56, 23, 24,  0,  9,  0, 82, 37, 24,  0, 71,  0,  0,  0,  0,255,  0,255,255,  0,255,255,  0,  0,  0,  0,255,  0,255,255,255,  0,255,255,  0,255,255,255,255,  0,  0,255,255,255,255,  0,255, // æ,
         17,112,  0,  2,  0, 15,  0,  0,  0, 35,  0,  0,  2,  0, 59,  9,  1,  0, 36,  0,  0,  8,  0,  0,  0,  0,  0,255,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,255,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,255,255, // ç,
        254,  0,  9, 14, 20,  0, 15,  6, 70,144, 14, 45, 47, 92, 16,  3,123,  0, 38, 23,115, 52, 22, 42,  2, 80, 19,255,  0,255,  0,  0,255,255,  0,255,255,  0, 10,  0,  0,  0,  0,  0,  0,  0,  0,  0,255,  0,255,255,255,  0,  0,  0,  1,255,255, // è,
        152,  2, 19, 24, 85,  0, 29, 23, 26, 25,  2,  9, 43, 60, 62,  1, 32,  0,122, 45,169, 15, 13, 30,  7,  4,  8,  0,  0,255,  0,  0,  0,  0,  0,255,  0,  0,  0,  2,  0,  0,  0,  0,  0,  0,  1,255,  0,  0,  0,  0,255,  0,  0,  0,  0,  0,  0, // é,
          5,  0,  0,  3,  7,  0,  0, 10,  2,  3,  0, 26,  6,  6, 20,  1,  2,  0, 20,  1, 11,  5,  5,  2,  0,  0,  1,255,  0,255,255,255,  0,255,255,255,255,  0,  0,  0,  0,  0,255,  0,  0,  0,  0,255,  0,  0,255,255,255,  0,255,  0,  0,  0,255, // ê,
         36,  2, 23, 15, 36,143,  5, 23, 52, 52, 66, 48, 92, 57,216, 10,125, 35, 89, 58,254,  9, 24, 14,  0,  0,  8,255,  0,255,  0,255,255,255,  0,  0,255,  1,  0,  0,  0,  0,  0,255,  0,  0,  0,255,255,255,  0,  0,  0,  0,255,  0,  0,  0,255, // ë,
         12,  0,  1,  4,  6,  0,  3, 21, 10,  0,  0,  0, 18,  8,  4,  0,  1,  0, 65, 35,  8,  3,  0,  0,  0,  0,  0,255,  0,255,  0,  0,255,255,255,255,255,255,  0,  0,  0,255,  0,  0,  0,255,  0,  0,255,  0,255,255,255,  0,255,255,  0,  0,255, // ì,
         40, 72,  7, 10, 16,  2, 23, 10, 34,  0,  0,  1, 34, 15, 21,  1,  3,  0,203, 28, 58, 23, 11,  0, 10,  0,  2,  0,  0,  0,  0,  0,  0,255,  0,255,255,  0,  0,  0,  0,255,  0,  0,255,255,  1,255,  0,255,255,  0,255,255,  0,255,  2,  0,255, // í,
          6,  5,  1,  9,  5,  0,  0,  0, 22,  0,  9,  8,  8,  6,  9,  1, 10,  0, 20,  6,182,  0, 13,  0,  0, 24,  1,255,  0,255,255,255,  0,  0,255,  0,255,  0,255,  0,  0,  0,  0,  0,  0,  0,  0,  0,255,  0,255,255,255,255,255,  0,255,255,255, // î,
          0,  6,  0,  0,  0,  4,  0,  0,  0,  0,  0,  0,  0,  0,  0,  3,  0,  0,  0,  0,  0,  9,  0,  0,  0,  0,  0,255,255,  0,  0,  0,  0,255,  0,255,  0,  0,  0,  0,  0,  0,255,  0,  0,  0,  0,255,  0,  0,  0,  0,255,255,  0,  0,  0,255,255, // ï,
          0,254,  0,  0,  0, 26,  0,  0,  0, 61,  0,  0,  0,  0,  0, 14,  0,  0,  0,  0,  0, 25,  0,  0,  0,  0,  0,255,255,255,  0,  0,  0,  0,  0,  0,255,255,  0,  0,  0,255,  0,  1,  0,  0,  0,255,  0,  0,  0,  0,  0,  0,  0,255,  0,255,255, // ñ,
         20,  0, 56, 43,  8,162, 14,  3, 23, 19,  2,118, 31, 26, 46,  0, 20,  0, 23,  6, 24, 19,  6, 21,  5, 27, 63,255,  0,255,  0,  0,255,255,255,255,255,  3,  0,255,255,255,  0,  0,255,  0,  0,  0,  0,255,  0,255,255,  0,255,255,  0,255,255, // ò,
         67,  0, 12, 15,  9,  7,  8, 66, 13,254,  3, 23, 14, 16, 16,  0,  8,  0, 29, 11, 26,  0,  5,  5,  1, 10, 13,255,  0,255,255,  0,255,  0,  0,255,255,  1,255,  0,255,255,  0,  0,255,  0,  1,  0,  0,  0,  0,255,255,255,  0,255,255,  0,255, // ó,
         18,  3,  3, 12,  1,  0,  2,  0,  7,  0,  1,  0,  2,  2,  8,  0,  6,  0,  6,  7,  4,  0,  2,  0,  0,  0,  1,255,  0,  0,255,  0,  0,255,255,255,  0,  0,  0,  0,  0,255,255,  0,  0,  0,  0,  0,  0,  0,255,255,255,255,  0,  0,255,255,255, // ô,
         29,  2,  0,  0,  0,  0,  0,  0,  5,  2, 22, 30, 25, 38, 19,  0, 33,255,  4, 39, 24,  0, 88,  0,  0,  0,  0,255,  0,255,255,  0,255,  0,255,255,255, 36,255,255,255,255,255,  0,255,255,  0,255,  0,  0,  6,  0,255,255,255,  0,  0,  0,255, // õ,
         44,  0, 33,  0, 25,  0,142,  5, 46, 10, 25, 32, 26, 13,  6,  0,  3,  0, 30,  8, 35,  0, 25,  5,  0, 44,  7,  0,  0,255,255,  0,255,255, 73,  0,255,  0,  0,  0,255,255,255,255,255,  0,  0,255,  0,  0,  0, 39,  0,255,255,255,  0,  0,  0, // ö,
         52,  0, 21,  0, 57,  0,119, 12, 47,  3, 59, 33, 45, 15, 12,  0,  3,  0, 52, 82, 49,  1, 11,  0,  0,  0,  0,  0,255,  0,255,255,255,255,255,  0,  0,  0,255,  0,255,255,255,  0,255,255,  0,255,255,255,255,  0,  0,255,255,255,255,255,  0, // ø,
         25,  0,  4,  3, 53,  0,  0,  2, 12, 72,  0,  0, 30,  0,  0,254,  0,  0,  6,  3,  3,  0,  0,  0,  0,  0,  0,255,  0,255,  0,255,  0,255,255,255,255,  0,  0,  0,  0,255,  0,255,255,255,255,  0,255,  0,  0,255,255,  0,  0,  0,  0,  0,  0, // ù,
         19,  2,  1,  7,  9,  1, 12,  5,  9, 41,  1,  0, 10,  7,  9,  0,  8,  0, 12, 28,  8,  0,  0,  0,  0,  1,  0,255,  0,255,255,  0,255,255,255,255,  0,  0,255,  0,255,255,255,  0,255,255,  0,  0,  0,255,  0,255,255,  0,  0,255,255,  0,255, // ú,
          0,  0,  0,  0,  1,  5,  0,  0,  1,  0,  0,  0,  0,  0,  0, 45,  0,  0,  3,  1,  1,  0,  0,  0,  0,  0,  0,  0,  0,255,255,255,  0,255,255,255,255,  0,255,  0,255,255,255,  0,  0,255,255,255,255,  0,255,255,255,  0,255,  0,  0,255,  0, // û,
         95,  2, 19,  0,  6,  2,121,  9, 15,  1,  5, 44, 18, 26,  7,  0, 11,  2, 68, 49, 20,  0,  2, 17,  0,  0,  6,  0,  0,255,  0,255,255,255,  0,255,255,  0,255,  0,255,  0,255,255,255,  0,  0,255,255,255,  0,  0,255,  0,  0,  0, 31,  0,  0, // ü,
          1,  1,  0,  0,  2,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,255,  0,  0,  0,  0,  0,  0,  0,  0,255,  0,  0,255,255,  0,  0,255,  0,255,  0,255,255,255,255,  0,  0,  0,  0,255,  0,  0,  0,  0,  0,255, // ž,
          0,  0,  0,  0,  0,  0,255,  0,  0,255,  0,  0,  0,  0,  0,  0,  0,255,  0,  0,  0,  0,  0,  0,255,255,  0,255,255,255,255,255,255,  0,255,  0,255,255,255,255,255,255,255,255,255,255,255,255,255,  0,  0,255,  0,255,255,255,  0,  0,  0, // ÿ,
      //   ,  a,  b,  c,  d,  e,  f,  g,  h,  i,  j,  k,  l,  m,  n,  o,  p,  q,  r,  s,  t,  u,  v,  w,  x,  y,  z,  ß,  š,  œ,  à,  á,  â,  ã,  ä,  å,  æ,  ç,  è,  é,  ê,  ë,  ì,  í,  î,  ï,  ñ,  ò,  ó,  ô,  õ,  ö,  ø,  ù,  ú,  û,  ü,  ž,  ÿ,
};
// clang-format on

static inline int compute_index(ut8 x, ut8 y, ut8 ascii_classes, ut8 non_ascii_classes) {
	if (x < ascii_classes && y < ascii_classes) {
		return -1;
	}
	if (y >= ascii_classes) {
		return (ascii_classes * non_ascii_classes + (ascii_classes + non_ascii_classes) * (y - ascii_classes) + x);
	}
	return (y * non_ascii_classes + x - ascii_classes);
}

static const int IMPLAUSIBILITY_PENALTY = -220;
static const int ASCII_DIGIT = 100;

static ut64 score_step(const ut8 current_class, const ut8 previous_class, const ut8 *t, const ut8 ascii_classes, const ut8 non_ascii_classes) {
	ut8 stored_boundary = ascii_classes + non_ascii_classes;
	if (current_class < stored_boundary) {
		if (previous_class < stored_boundary) {
			int i = compute_index(previous_class, current_class, ascii_classes, non_ascii_classes);
			if (i != -1) {
				int x = t[i];
				return x == 255 ? IMPLAUSIBILITY_PENALTY : x;
			}
			return 0;
		} else {
			if (current_class == 0 || current_class == ASCII_DIGIT) {
				return 0;
			}
			ut8 unstored = previous_class - stored_boundary;
			switch (unstored) {
			case 0:
			case 3:
				return 0;
			case 1:
			case 2: return IMPLAUSIBILITY_PENALTY;
			case 4: return current_class < ascii_classes ? IMPLAUSIBILITY_PENALTY : 0;
			case 5: return current_class < ascii_classes ? 0 : IMPLAUSIBILITY_PENALTY;
			default:
				return 0;
			}
		}
	} else {
		if (previous_class < stored_boundary) {
			if (current_class == 0 || current_class == ASCII_DIGIT) {
				return 0;
			} else {
				ut8 unstored = current_class - stored_boundary;
				switch (unstored) {
				case 0:
				case 3:
					return 0;
				case 1:
				case 2: return IMPLAUSIBILITY_PENALTY;
				case 4: return previous_class < ascii_classes ? IMPLAUSIBILITY_PENALTY : 0;
				case 5: return previous_class < ascii_classes ? 0 : IMPLAUSIBILITY_PENALTY;
				default:
					return 0;
				}
			}
		} else {
			return current_class == ASCII_DIGIT || previous_class == ASCII_DIGIT ? 0 : IMPLAUSIBILITY_PENALTY;
		}
	}
}

enum LatinCaseState {
	Space,
	Upper,
	Lower,
	AllCaps,
};

static const int IMPLAUSIBLE_LATIN_CASE_TRANSITION_PENALTY = -180;

static st64 score(const RzRune *buff, const size_t len, const ut8 *class_tbl, const ut8 *t, const ut8 ascii_classes, const ut8 non_ascii_classes) {
	const ut8 stored_boundary = ascii_classes + non_ascii_classes;
	int score = 0;
	ut32 prev_non_ascii = 0;
	enum LatinCaseState case_state = Space;
	ut8 prev = 0;
	for (size_t i = 0; i < len; i++) {
		RzRune b = buff[i];
		ut8 class = class_tbl[b];
		if (class == 0xff) {
			return -1;
		}
		ut8 caseless_class = class & 0x7F;
		bool ascii = b < 0x80;
		bool ascii_pair = prev_non_ascii == 0 && ascii;
		bool latin_alphabetic = caseless_class > 0 && caseless_class < stored_boundary;

		int non_ascii_penalty = 0;
		if (prev_non_ascii >= 0 && prev_non_ascii <= 2) {
			non_ascii_penalty = 0;
		} else if (prev_non_ascii == 3) {
			non_ascii_penalty = -5;
		} else if (prev_non_ascii == 4) {
			non_ascii_penalty = -20;
		} else {
			non_ascii_penalty = -200;
		}
		score += non_ascii_penalty;

		if (!latin_alphabetic) {
			case_state = Space;
		} else if (class >> 7 == 0) {
			if (case_state == AllCaps && !ascii_pair) {
				score += IMPLAUSIBLE_LATIN_CASE_TRANSITION_PENALTY;
			}
			case_state = Lower;
		} else {
			switch (case_state) {
			case Space:
				case_state = Upper;
				break;
			case Upper:
			case AllCaps:
				case_state = AllCaps;
			case Lower:
				if (!ascii_pair) {
					score += IMPLAUSIBLE_LATIN_CASE_TRANSITION_PENALTY;
				}
				case_state = Upper;
				break;
			default: break;
			}
		}

		if (!(ascii_pair || (ascii && prev == 0) || (caseless_class == 0 && prev_non_ascii == 0))) {
			score += score_step(caseless_class, prev, t, ascii_classes, non_ascii_classes);
		}

		if (ascii) {
			prev_non_ascii = 0;
		} else {
			prev_non_ascii++;
		}
		prev = caseless_class;
	}

	return score;
}

static inline st64 score_unicode_western(const RzRune *buff, const size_t len) {
	return score(buff, len, unicode_class, WESTERN, WESTERN_ASCII, WESTERN_NON_ASCII);
}

/**
 * Free a RzDetectedString
 */
RZ_API void rz_detected_string_free(RzDetectedString *str) {
	if (str) {
		free(str->string);
		free(str);
	}
}

static inline bool is_c_escape_sequence(char ch) {
	return strchr("\b\v\f\n\r\t\a\033\\", ch);
}

static FalsePositiveResult reduce_false_positives(const RzUtilStrScanOptions *opt, ut8 *str, int size, RzStrEnc str_type) {
	int i, num_blocks, *block_list;
	int *freq_list = NULL, expected_ascii, actual_ascii, num_chars;

	switch (str_type) {
	case RZ_STRING_ENC_8BIT: {
		for (i = 0; i < size; i++) {
			char ch = str[i];
			if (!is_c_escape_sequence(ch)) {
				if (!IS_PRINTABLE(str[i])) {
					return SKIP_STRING;
				}
			}
		}
		break;
	}
	case RZ_STRING_ENC_UTF8:
	case RZ_STRING_ENC_UTF16LE:
	case RZ_STRING_ENC_UTF32LE:
		num_blocks = 0;
		block_list = rz_utf_block_list((const ut8 *)str, size - 1,
			str_type == RZ_STRING_ENC_UTF16LE ? &freq_list : NULL);
		if (block_list) {
			for (i = 0; block_list[i] != -1; i++) {
				num_blocks++;
			}
		}
		if (freq_list) {
			num_chars = 0;
			actual_ascii = 0;
			for (i = 0; freq_list[i] != -1; i++) {
				num_chars += freq_list[i];
				if (!block_list[i]) { // ASCII
					actual_ascii = freq_list[i];
				}
			}
			free(freq_list);
			expected_ascii = num_blocks ? num_chars / num_blocks : 0;
			if (actual_ascii > expected_ascii) {
				free(block_list);
				return RETRY_ASCII;
			}
		}
		free(block_list);
		if (num_blocks > opt->max_uni_blocks) {
			return SKIP_STRING;
		}
		break;
	default:
		break;
	}

	return STRING_OK;
}

static ut64 adjust_offset(RzStrEnc str_type, const ut8 *buf, const ut64 str_start) {
	switch (str_type) {
	case RZ_STRING_ENC_UTF16LE:
		if (str_start > 1) {
			const ut8 *p = buf + str_start - 2;
			if (p[0] == 0xff && p[1] == 0xfe) {
				return 2; // \xff\xfe
			}
		}
		break;
	case RZ_STRING_ENC_UTF16BE:
		if (str_start > 1) {
			const ut8 *p = buf + str_start - 2;
			if (p[0] == 0xfe && p[1] == 0xff) {
				return 2; // \xfe\xff
			}
		}
		break;
	case RZ_STRING_ENC_UTF32LE:
		if (str_start > 3) {
			const ut8 *p = buf + str_start - 4;
			if (p[0] == 0xff && p[1] == 0xfe && !p[2] && !p[3]) {
				return 4; // \xff\xfe\x00\x00
			}
		}
		break;
	case RZ_STRING_ENC_UTF32BE:
		if (str_start > 3) {
			const ut8 *p = buf + str_start - 4;
			if (!p[0] && !p[1] && p[2] == 0xfe && p[3] == 0xff) {
				return 4; // \x00\x00\xfe\xff
			}
		}
		break;
	default:
		break;
	}

	return 0;
}

static RzDetectedString *process_one_string(const ut8 *buf, const ut64 from, ut64 needle, const ut64 to,
	RzStrEnc str_type, bool ascii_only, const RzUtilStrScanOptions *opt) {

	rz_return_val_if_fail(str_type != RZ_STRING_ENC_GUESS, NULL);

	ut8 *tmp = malloc(opt->buf_size);
	if (!tmp) {
		return NULL;
	}
	ut64 str_addr = needle;
	int rc, i, runes;

	/* Eat a whole C string */
	runes = 0;
	rc = 0;
	for (i = 0; i < opt->buf_size - 4 && needle < to; i += rc) {
		RzRune r = { 0 };

		if (str_type == RZ_STRING_ENC_UTF32LE) {
			rc = rz_utf32le_decode(buf + needle - from, to - needle, &r);
			if (rc) {
				rc = 4;
			}
		} else if (str_type == RZ_STRING_ENC_UTF16LE) {
			rc = rz_utf16le_decode(buf + needle - from, to - needle, &r);
			if (rc == 1) {
				rc = 2;
			}
		} else if (str_type == RZ_STRING_ENC_UTF32BE) {
			rc = rz_utf32be_decode(buf + needle - from, to - needle, &r);
			if (rc) {
				rc = 4;
			}
		} else if (str_type == RZ_STRING_ENC_UTF16BE) {
			rc = rz_utf16be_decode(buf + needle - from, to - needle, &r);
			if (rc == 1) {
				rc = 2;
			}
		} else if (str_type == RZ_STRING_ENC_IBM037) {
			rc = rz_str_ibm037_to_unicode(*(buf + needle - from), &r);
		} else if (str_type == RZ_STRING_ENC_IBM290) {
			rc = rz_str_ibm290_to_unicode(*(buf + needle - from), &r);
		} else if (str_type == RZ_STRING_ENC_EBCDIC_ES) {
			rc = rz_str_ebcdic_es_to_unicode(*(buf + needle - from), &r);
		} else if (str_type == RZ_STRING_ENC_EBCDIC_UK) {
			rc = rz_str_ebcdic_uk_to_unicode(*(buf + needle - from), &r);
		} else if (str_type == RZ_STRING_ENC_EBCDIC_US) {
			rc = rz_str_ebcdic_us_to_unicode(*(buf + needle - from), &r);
		} else {
			rc = rz_utf8_decode(buf + needle - from, to - needle, &r);
			if (rc > 1) {
				str_type = RZ_STRING_ENC_UTF8;
			}
		}

		/* Invalid sequence detected */
		if (!rc || (ascii_only && r > 0x7f)) {
			needle++;
			break;
		}

		needle += rc;

		if (rz_isprint(r) && r != '\\') {
			if (str_type == RZ_STRING_ENC_UTF32LE || str_type == RZ_STRING_ENC_UTF32BE) {
				if (r == 0xff) {
					r = 0;
				}
			}
			rc = rz_utf8_encode(tmp + i, r);
			runes++;
		} else if (r && r < 0x100 && is_c_escape_sequence((char)r)) {
			if ((i + 32) < opt->buf_size && r < 93) {
				rc = rz_utf8_encode(tmp + i, r);
			} else {
				// string too long
				break;
			}
			runes++;
		} else {
			/* \0 marks the end of C-strings */
			break;
		}
	}

	if (runes >= opt->min_str_length) {
		FalsePositiveResult false_positive_result = reduce_false_positives(opt, tmp, i - 1, str_type);
		if (false_positive_result == SKIP_STRING) {
			free(tmp);
			return NULL;
		} else if (false_positive_result == RETRY_ASCII) {
			free(tmp);
			return process_one_string(buf, from, str_addr, to, str_type, true, opt);
		}

		RzDetectedString *ds = RZ_NEW0(RzDetectedString);
		if (!ds) {
			free(tmp);
			return NULL;
		}
		ds->type = str_type;
		ds->length = runes;
		ds->size = needle - str_addr;
		ds->addr = str_addr;

		ut64 off_adj = adjust_offset(str_type, buf, ds->addr - from);
		ds->addr -= off_adj;
		ds->size += off_adj;

		ds->string = rz_str_ndup((const char *)tmp, i);
		free(tmp);
		return ds;
	}

	free(tmp);
	return NULL;
}

static inline bool can_be_utf16_le(ut8 *buf, ut64 size) {
	int rc = rz_utf8_decode(buf, size, NULL);
	if (!rc) {
		return false;
	}

	if (size - rc < 5) {
		return false;
	}
	char *w = (char *)buf + rc;
	return !w[0] && w[1] && !w[2] && w[3] && !w[4];
}

static inline bool can_be_utf16_be(ut8 *buf, ut64 size) {
	if (size < 7) {
		return false;
	}
	return !buf[0] && buf[1] && !buf[2] && buf[3] && !buf[4] && buf[5] && !buf[6];
}

static inline bool can_be_utf32_le(ut8 *buf, ut64 size) {
	int rc = rz_utf8_decode(buf, size, NULL);
	if (!rc) {
		return false;
	}

	if (size - rc < 5) {
		return false;
	}
	char *w = (char *)buf + rc;
	return !w[0] && !w[1] && !w[2] && w[3] && !w[4];
}

static inline bool can_be_utf32_be(ut8 *buf, ut64 size) {
	if (size < 7) {
		return false;
	}
	return !buf[0] && !buf[1] && !buf[2] && buf[3] && !buf[4] && !buf[5] && !buf[6];
}

static inline bool can_be_ebcdic(ut8 *buf, ut64 size) {
	return buf[0] < 0x20 || buf[0] > 0x3f;
}

/**
 * \brief Look for strings in an RzBuffer.
 * \param buf_to_scan Pointer to a RzBuffer to scan
 * \param list Pointer to a list that will be populated with the found strings
 * \param opt Pointer to a RzUtilStrScanOptions that specifies search parameters
 * \param from Minimum address to scan
 * \param to Maximum address to scan
 * \param type Type of strings to search
 * \return Number of strings found
 *
 * Used to look for strings in a give RzBuffer. The function can also automatically detect string types.
 */
RZ_API int rz_scan_strings(RzBuffer *buf_to_scan, RzList *list, const RzUtilStrScanOptions *opt,
	const ut64 from, const ut64 to, RzStrEnc type) {
	rz_return_val_if_fail(opt || list || buf_to_scan, -1);

	if (from == to) {
		return 0;
	}
	if (from > to) {
		RZ_LOG_ERROR("Invalid range to find strings 0x%" PFMT64x " .. 0x%" PFMT64x "\n", from, to);
		return -1;
	}

	ut64 needle;
	int count = 0;
	RzStrEnc str_type = type;

	int len = to - from;
	ut8 *buf = calloc(len, 1);
	if (!buf) {
		return -1;
	}

	rz_buf_read_at(buf_to_scan, from, buf, len);

	needle = from;
	ut8 *ptr;
	ut64 size;
	while (needle < to) {
		ptr = buf + needle - from;
		size = to - needle;
		if (type == RZ_STRING_ENC_GUESS) {
			if (can_be_utf32_le(ptr, size)) {
				str_type = RZ_STRING_ENC_UTF32LE;
			} else if (can_be_utf16_le(ptr, size)) {
				str_type = RZ_STRING_ENC_UTF16LE;
			} else if (can_be_utf32_be(ptr, size)) {
				if (to - needle > 3 && can_be_utf32_le(ptr + 3, size - 3)) {
					// The string can be either utf32-le or utf32-be
					RzDetectedString *ds_le = process_one_string(buf, from, needle + 3, to, RZ_STRING_ENC_UTF32LE, false, opt);
					RzDetectedString *ds_be = process_one_string(buf, from, needle, to, RZ_STRING_ENC_UTF32BE, false, opt);

					RzDetectedString *to_add = NULL;
					RzDetectedString *to_delete = NULL;
					ut64 needle_offset = 0;

					if (!ds_le && !ds_be) {
						needle++;
						continue;
					} else if (!ds_be) {
						to_add = ds_le;
						needle_offset = ds_le->size + 3;
					} else if (!ds_le) {
						to_add = ds_be;
						needle_offset = ds_be->size;
					} else if (!opt->prefer_big_endian) {
						to_add = ds_le;
						to_delete = ds_be;
						needle_offset = ds_le->size + 3;
					} else {
						to_add = ds_be;
						to_delete = ds_le;
						needle_offset = ds_le->size;
					}

					count++;
					needle += needle_offset;
					rz_list_append(list, to_add);
					rz_detected_string_free(to_delete);
					continue;
				}
				str_type = RZ_STRING_ENC_UTF32BE;
			} else if (can_be_utf16_be(ptr, size)) {
				if (to - needle > 1 && can_be_utf16_le(ptr + 1, size - 1)) {
					// The string can be either utf16-le or utf16-be
					RzDetectedString *ds_le = process_one_string(buf, from, needle + 1, to, RZ_STRING_ENC_UTF16LE, false, opt);
					RzDetectedString *ds_be = process_one_string(buf, from, needle, to, RZ_STRING_ENC_UTF16BE, false, opt);

					RzDetectedString *to_add = NULL;
					RzDetectedString *to_delete = NULL;
					ut64 needle_offset = 0;

					if (!ds_le && !ds_be) {
						needle++;
						continue;
					} else if (!ds_be) {
						to_add = ds_le;
						needle_offset = ds_le->size + 1;
					} else if (!ds_le) {
						to_add = ds_be;
						needle_offset = ds_be->size;
					} else if (!opt->prefer_big_endian) {
						to_add = ds_le;
						to_delete = ds_be;
						needle_offset = ds_le->size + 1;
					} else {
						to_add = ds_be;
						to_delete = ds_le;
						needle_offset = ds_le->size;
					}

					count++;
					needle += needle_offset;
					rz_list_append(list, to_add);
					rz_detected_string_free(to_delete);
					continue;
				}
				str_type = RZ_STRING_ENC_UTF16BE;
			} else {
				RzRune r;
				int rc = rz_utf8_decode(ptr, size, &r);
				if (!rc || (rc == 2 && !rz_isprint(r))) {
					if (can_be_ebcdic(ptr, size)) {
						str_type = RZ_STRING_ENC_IBM037;
					} else {
						needle++;
						continue;
					}
				} else {
					RzDetectedString *ds = process_one_string(buf, from, needle, to, RZ_STRING_ENC_UTF8, false, opt);
					if (!ds) {
						str_type = RZ_STRING_ENC_IBM037;
					} else {
						str_type = RZ_STRING_ENC_8BIT;
					}
				}
			}
		} else if (type == RZ_STRING_ENC_UTF8) {
			str_type = RZ_STRING_ENC_8BIT; // initial assumption
		}

		RzDetectedString *ds = process_one_string(buf, from, needle, to, str_type, false, opt);
		if (!ds) {
			needle++;
			continue;
		}

		if (type == RZ_STRING_ENC_GUESS && str_type == RZ_STRING_ENC_IBM037) {
			RzRune *runes = RZ_NEWS(RzRune, ds->size);
			for (size_t i = 0; i < ds->size; i++) {
				rz_str_ibm037_to_unicode(ptr[i], &runes[i]);
			}
			int sco = score_unicode_western(runes, ds->size);
			if (sco < 0) {
				needle++;
				continue;
			} else {
				eprintf("%s score: %d\n", ds->string, sco);
			}
		}

		count++;
		rz_list_append(list, ds);
		needle += ds->size;
	}
	free(buf);
	return count;
}
