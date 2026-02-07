// SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

/*
 *

 *********************************************** AUTO-GENERATED CODE, DO NOT EDIT BY HAND!  * ***********************************************

 * RISC-V Extension Parser Using a Trie trick
 * Generated from arch/RISCV/RISCVGenSubtargetInfo.inc in Capstone sources
 *
 * This function parses a single RISC-V extension name and ORs the corresponding
 * feature flags with an accumulator 'mode'.
 *
 * Trie Diagram:
 * ROOT
 * ├── a  [RISCV_FeatureStdExtA]
 * ├── c  [RISCV_FeatureStdExtC]
 * ├── d  [RISCV_FeatureStdExtD]
 * ├── f  [RISCV_FeatureStdExtF]
 * ├── h  [RISCV_FeatureStdExtH]
 * ├── i  [RISCV_FeatureStdExtI]
 * ├── m  [RISCV_FeatureStdExtM]
 * ├── s
 * │   ├── m
 * │   │   ├── a
 * │   │   │   └── i
 * │   │   │       └── a  [RISCV_FeatureStdExtSmaia]
 * │   │   └── e
 * │   │       └── p
 * │   │           └── m
 * │   │               └── p  [RISCV_FeatureStdExtSmepmp]
 * │   ├── s
 * │   │   └── a
 * │   │       └── i
 * │   │           └── a  [RISCV_FeatureStdExtSsaia]
 * │   └── v
 * │       ├── i
 * │       │   └── n
 * │       │       └── v
 * │       │           └── a
 * │       │               └── l  [RISCV_FeatureStdExtSvinval]
 * │       ├── n
 * │       │   └── a
 * │       │       └── p
 * │       │           └── o
 * │       │               └── t  [RISCV_FeatureStdExtSvnapot]
 * │       └── p
 * │           └── b
 * │               └── m
 * │                   └── t  [RISCV_FeatureStdExtSvpbmt]
 * ├── v  [RISCV_FeatureStdExtV]
 * └── z
 *     ├── a
 *     │   ├── 1
 *     │   │   └── 2
 *     │   │       └── 8
 *     │   │           └── r
 *     │   │               └── s  [RISCV_FeatureStdExtZa128rs]
 *     │   ├── 6
 *     │   │   └── 4
 *     │   │       └── r
 *     │   │           └── s  [RISCV_FeatureStdExtZa64rs]
 *     │   ├── c
 *     │   │   └── a
 *     │   │       └── s  [RISCV_FeatureStdExtZacas]
 *     │   └── w
 *     │       └── r
 *     │           └── s  [RISCV_FeatureStdExtZawrs]
 *     ├── b
 *     │   ├── a  [RISCV_FeatureStdExtZba]
 *     │   ├── b  [RISCV_FeatureStdExtZbb]
 *     │   ├── c  [RISCV_FeatureStdExtZbc]
 *     │   ├── k
 *     │   │   ├── b  [RISCV_FeatureStdExtZbkb]
 *     │   │   ├── c  [RISCV_FeatureStdExtZbkc]
 *     │   │   └── x  [RISCV_FeatureStdExtZbkx]
 *     │   └── s  [RISCV_FeatureStdExtZbs]
 *     ├── c
 *     │   ├── a  [RISCV_FeatureStdExtZca]
 *     │   ├── b  [RISCV_FeatureStdExtZcb]
 *     │   ├── d  [RISCV_FeatureStdExtZcd]
 *     │   ├── e  [RISCV_FeatureStdExtZce]
 *     │   ├── f  [RISCV_FeatureStdExtZcf]
 *     │   └── m
 *     │       ├── o
 *     │       │   └── p  [RISCV_FeatureStdExtZcmop]
 *     │       ├── p  [RISCV_FeatureStdExtZcmp]
 *     │       └── t  [RISCV_FeatureStdExtZcmt]
 *     ├── d
 *     │   └── i
 *     │       └── n
 *     │           └── x  [RISCV_FeatureStdExtZdinx]
 *     ├── f
 *     │   ├── a  [RISCV_FeatureStdExtZfa]
 *     │   ├── b
 *     │   │   └── f
 *     │   │       └── m
 *     │   │           └── i
 *     │   │               └── n  [RISCV_FeatureStdExtZfbfmin]
 *     │   ├── h  [RISCV_FeatureStdExtZfh]
 *     │   │   └── m
 *     │   │       └── i
 *     │   │           └── n  [RISCV_FeatureStdExtZfhmin]
 *     │   └── i
 *     │       └── n
 *     │           └── x  [RISCV_FeatureStdExtZfinx]
 *     ├── h
 *     │   └── i
 *     │       └── n
 *     │           └── x  [RISCV_FeatureStdExtZhinx]
 *     │               └── m
 *     │                   └── i
 *     │                       └── n  [RISCV_FeatureStdExtZhinxmin]
 *     ├── i
 *     │   ├── c
 *     │   │   ├── 6
 *     │   │   │   └── 4
 *     │   │   │       └── b  [RISCV_FeatureStdExtZic64b]
 *     │   │   ├── b
 *     │   │   │   └── o
 *     │   │   │       ├── m  [RISCV_FeatureStdExtZicbom]
 *     │   │   │       ├── p  [RISCV_FeatureStdExtZicbop]
 *     │   │   │       └── z  [RISCV_FeatureStdExtZicboz]
 *     │   │   ├── c
 *     │   │   │   ├── a
 *     │   │   │   │   └── m
 *     │   │   │   │       └── o
 *     │   │   │   │           └── a  [RISCV_FeatureStdExtZiccamoa]
 *     │   │   │   ├── i
 *     │   │   │   │   └── f  [RISCV_FeatureStdExtZiccif]
 *     │   │   │   ├── l
 *     │   │   │   │   └── s
 *     │   │   │   │       └── m  [RISCV_FeatureStdExtZicclsm]
 *     │   │   │   └── r
 *     │   │   │       └── s
 *     │   │   │           └── e  [RISCV_FeatureStdExtZiccrse]
 *     │   │   ├── f
 *     │   │   │   └── i
 *     │   │   │       ├── l
 *     │   │   │       │   └── p  [RISCV_FeatureStdExtZicfilp]
 *     │   │   │       └── s
 *     │   │   │           └── s  [RISCV_FeatureStdExtZicfiss]
 *     │   │   ├── n
 *     │   │   │   └── t
 *     │   │   │       └── r  [RISCV_FeatureStdExtZicntr]
 *     │   │   ├── o
 *     │   │   │   └── n
 *     │   │   │       └── d  [RISCV_FeatureStdExtZicond]
 *     │   │   └── s
 *     │   │       └── r  [RISCV_FeatureStdExtZicsr]
 *     │   ├── f
 *     │   │   └── e
 *     │   │       └── n
 *     │   │           └── c
 *     │   │               └── e
 *     │   │                   └── i  [RISCV_FeatureStdExtZifencei]
 *     │   ├── h
 *     │   │   ├── i
 *     │   │   │   └── n
 *     │   │   │       └── t
 *     │   │   │           ├── n
 *     │   │   │           │   └── t
 *     │   │   │           │       └── l  [RISCV_FeatureStdExtZihintntl]
 *     │   │   │           └── p
 *     │   │   │               └── a
 *     │   │   │                   └── u
 *     │   │   │                       └── s
 *     │   │   │                           └── e  [RISCV_FeatureStdExtZihintpause]
 *     │   │   └── p
 *     │   │       └── m  [RISCV_FeatureStdExtZihpm]
 *     │   └── m
 *     │       └── o
 *     │           └── p  [RISCV_FeatureStdExtZimop]
 *     ├── k  [RISCV_FeatureStdExtZk]
 *     │   ├── n  [RISCV_FeatureStdExtZkn]
 *     │   │   ├── d  [RISCV_FeatureStdExtZknd]
 *     │   │   ├── e  [RISCV_FeatureStdExtZkne]
 *     │   │   └── h  [RISCV_FeatureStdExtZknh]
 *     │   ├── r  [RISCV_FeatureStdExtZkr]
 *     │   ├── s  [RISCV_FeatureStdExtZks]
 *     │   │   ├── e
 *     │   │   │   └── d  [RISCV_FeatureStdExtZksed]
 *     │   │   └── h  [RISCV_FeatureStdExtZksh]
 *     │   └── t  [RISCV_FeatureStdExtZkt]
 *     ├── m
 *     │   └── m
 *     │       └── u
 *     │           └── l  [RISCV_FeatureStdExtZmmul]
 *     ├── t
 *     │   └── s
 *     │       └── o  [RISCV_FeatureStdExtZtso]
 *     └── v
 *         ├── b
 *         │   ├── b  [RISCV_FeatureStdExtZvbb]
 *         │   └── c  [RISCV_FeatureStdExtZvbc]
 *         ├── e
 *         │   ├── 3
 *         │   │   └── 2
 *         │   │       ├── f  [RISCV_FeatureStdExtZve32f]
 *         │   │       └── x  [RISCV_FeatureStdExtZve32x]
 *         │   └── 6
 *         │       └── 4
 *         │           ├── d  [RISCV_FeatureStdExtZve64d]
 *         │           ├── f  [RISCV_FeatureStdExtZve64f]
 *         │           └── x  [RISCV_FeatureStdExtZve64x]
 *         ├── f
 *         │   ├── b
 *         │   │   └── f
 *         │   │       ├── m
 *         │   │       │   └── i
 *         │   │       │       └── n  [RISCV_FeatureStdExtZvfbfmin]
 *         │   │       └── w
 *         │   │           └── m
 *         │   │               └── a  [RISCV_FeatureStdExtZvfbfwma]
 *         │   └── h  [RISCV_FeatureStdExtZvfh]
 *         │       └── m
 *         │           └── i
 *         │               └── n  [RISCV_FeatureStdExtZvfhmin]
 *         ├── k
 *         │   ├── b  [RISCV_FeatureStdExtZvkb]
 *         │   ├── g  [RISCV_FeatureStdExtZvkg]
 *         │   ├── n  [RISCV_FeatureStdExtZvkn]
 *         │   │   ├── c  [RISCV_FeatureStdExtZvknc]
 *         │   │   ├── e
 *         │   │   │   └── d  [RISCV_FeatureStdExtZvkned]
 *         │   │   ├── g  [RISCV_FeatureStdExtZvkng]
 *         │   │   └── h
 *         │   │       ├── a  [RISCV_FeatureStdExtZvknha]
 *         │   │       └── b  [RISCV_FeatureStdExtZvknhb]
 *         │   ├── s  [RISCV_FeatureStdExtZvks]
 *         │   │   ├── c  [RISCV_FeatureStdExtZvksc]
 *         │   │   ├── e
 *         │   │   │   └── d  [RISCV_FeatureStdExtZvksed]
 *         │   │   ├── g  [RISCV_FeatureStdExtZvksg]
 *         │   │   └── h  [RISCV_FeatureStdExtZvksh]
 *         │   └── t  [RISCV_FeatureStdExtZvkt]
 *         └── l
 *             ├── 1
 *             │   ├── 0
 *             │   │   └── 2
 *             │   │       └── 4
 *             │   │           └── b  [RISCV_FeatureStdExtZvl1024b]
 *             │   ├── 2
 *             │   │   └── 8
 *             │   │       └── b  [RISCV_FeatureStdExtZvl128b]
 *             │   └── 6
 *             │       └── 3
 *             │           └── 8
 *             │               └── 4
 *             │                   └── b  [RISCV_FeatureStdExtZvl16384b]
 *             ├── 2
 *             │   ├── 0
 *             │   │   └── 4
 *             │   │       └── 8
 *             │   │           └── b  [RISCV_FeatureStdExtZvl2048b]
 *             │   └── 5
 *             │       └── 6
 *             │           └── b  [RISCV_FeatureStdExtZvl256b]
 *             ├── 3
 *             │   └── 2
 *             │       ├── 7
 *             │       │   └── 6
 *             │       │       └── 8
 *             │       │           └── b  [RISCV_FeatureStdExtZvl32768b]
 *             │       └── b  [RISCV_FeatureStdExtZvl32b]
 *             ├── 4
 *             │   └── 0
 *             │       └── 9
 *             │           └── 6
 *             │               └── b  [RISCV_FeatureStdExtZvl4096b]
 *             ├── 5
 *             │   └── 1
 *             │       └── 2
 *             │           └── b  [RISCV_FeatureStdExtZvl512b]
 *             ├── 6
 *             │   ├── 4
 *             │   │   └── b  [RISCV_FeatureStdExtZvl64b]
 *             │   └── 5
 *             │       └── 5
 *             │           └── 3
 *             │               └── 6
 *             │                   └── b  [RISCV_FeatureStdExtZvl65536b]
 *             └── 8
 *                 └── 1
 *                     └── 9
 *                         └── 2
 *                             └── b  [RISCV_FeatureStdExtZvl8192b]
 */

#define RISCV_FeatureStdExtA 0

#define RISCV_FeatureStdExtC 1

#define RISCV_FeatureStdExtD 2

#define RISCV_FeatureStdExtF 3

#define RISCV_FeatureStdExtH 4

#define RISCV_FeatureStdExtI 5

#define RISCV_FeatureStdExtM 6

#define RISCV_FeatureStdExtSmaia 7

#define RISCV_FeatureStdExtSmepmp 8

#define RISCV_FeatureStdExtSsaia 9

#define RISCV_FeatureStdExtSvinval 10

#define RISCV_FeatureStdExtSvnapot 11

#define RISCV_FeatureStdExtSvpbmt 12

#define RISCV_FeatureStdExtV 13

#define RISCV_FeatureStdExtZa64rs 14

#define RISCV_FeatureStdExtZa128rs 15

#define RISCV_FeatureStdExtZacas 16

#define RISCV_FeatureStdExtZawrs 17

#define RISCV_FeatureStdExtZba 18

#define RISCV_FeatureStdExtZbb 19

#define RISCV_FeatureStdExtZbc 20

#define RISCV_FeatureStdExtZbkb 21

#define RISCV_FeatureStdExtZbkc 22

#define RISCV_FeatureStdExtZbkx 23

#define RISCV_FeatureStdExtZbs 24

#define RISCV_FeatureStdExtZca 25

#define RISCV_FeatureStdExtZcb 26

#define RISCV_FeatureStdExtZcd 27

#define RISCV_FeatureStdExtZce 28

#define RISCV_FeatureStdExtZcf 29

#define RISCV_FeatureStdExtZcmop 30

#define RISCV_FeatureStdExtZcmp 31

#define RISCV_FeatureStdExtZcmt 32

#define RISCV_FeatureStdExtZdinx 33

#define RISCV_FeatureStdExtZfa 34

#define RISCV_FeatureStdExtZfbfmin 35

#define RISCV_FeatureStdExtZfh 36

#define RISCV_FeatureStdExtZfhmin 37

#define RISCV_FeatureStdExtZfinx 38

#define RISCV_FeatureStdExtZhinx 39

#define RISCV_FeatureStdExtZhinxmin 40

#define RISCV_FeatureStdExtZic64b 41

#define RISCV_FeatureStdExtZicbom 42

#define RISCV_FeatureStdExtZicbop 43

#define RISCV_FeatureStdExtZicboz 44

#define RISCV_FeatureStdExtZiccamoa 45

#define RISCV_FeatureStdExtZiccif 46

#define RISCV_FeatureStdExtZicclsm 47

#define RISCV_FeatureStdExtZiccrse 48

#define RISCV_FeatureStdExtZicfilp 49

#define RISCV_FeatureStdExtZicfiss 50

#define RISCV_FeatureStdExtZicntr 51

#define RISCV_FeatureStdExtZicond 52

#define RISCV_FeatureStdExtZicsr 53

#define RISCV_FeatureStdExtZifencei 54

#define RISCV_FeatureStdExtZihintntl 55

#define RISCV_FeatureStdExtZihintpause 56

#define RISCV_FeatureStdExtZihpm 57

#define RISCV_FeatureStdExtZimop 58

#define RISCV_FeatureStdExtZk 59

#define RISCV_FeatureStdExtZkn 60

#define RISCV_FeatureStdExtZknd 61

#define RISCV_FeatureStdExtZkne 62

#define RISCV_FeatureStdExtZknh 63

#define RISCV_FeatureStdExtZkr 64

#define RISCV_FeatureStdExtZks 65

#define RISCV_FeatureStdExtZksed 66

#define RISCV_FeatureStdExtZksh 67

#define RISCV_FeatureStdExtZkt 68

#define RISCV_FeatureStdExtZmmul 69

#define RISCV_FeatureStdExtZtso 70

#define RISCV_FeatureStdExtZvbb 71

#define RISCV_FeatureStdExtZvbc 72

#define RISCV_FeatureStdExtZve32f 73

#define RISCV_FeatureStdExtZve32x 74

#define RISCV_FeatureStdExtZve64d 75

#define RISCV_FeatureStdExtZve64f 76

#define RISCV_FeatureStdExtZve64x 77

#define RISCV_FeatureStdExtZvfbfmin 78

#define RISCV_FeatureStdExtZvfbfwma 79

#define RISCV_FeatureStdExtZvfh 80

#define RISCV_FeatureStdExtZvfhmin 81

#define RISCV_FeatureStdExtZvkb 82

#define RISCV_FeatureStdExtZvkg 83

#define RISCV_FeatureStdExtZvkn 84

#define RISCV_FeatureStdExtZvknc 85

#define RISCV_FeatureStdExtZvkned 86

#define RISCV_FeatureStdExtZvkng 87

#define RISCV_FeatureStdExtZvknha 88

#define RISCV_FeatureStdExtZvknhb 89

#define RISCV_FeatureStdExtZvks 90

#define RISCV_FeatureStdExtZvksc 91

#define RISCV_FeatureStdExtZvksed 92

#define RISCV_FeatureStdExtZvksg 93

#define RISCV_FeatureStdExtZvksh 94

#define RISCV_FeatureStdExtZvkt 95

#define RISCV_FeatureStdExtZvl32b 96

#define RISCV_FeatureStdExtZvl64b 97

#define RISCV_FeatureStdExtZvl128b 98

#define RISCV_FeatureStdExtZvl256b 99

#define RISCV_FeatureStdExtZvl512b 100

#define RISCV_FeatureStdExtZvl1024b 101

#define RISCV_FeatureStdExtZvl2048b 102

#define RISCV_FeatureStdExtZvl4096b 103

#define RISCV_FeatureStdExtZvl8192b 104

#define RISCV_FeatureStdExtZvl16384b 105

#define RISCV_FeatureStdExtZvl32768b 106

#define RISCV_FeatureStdExtZvl65536b 107
/* Parse result enum - indicates why parsing stopped */
typedef enum {
	RISCV_EXT_PARSE_END_OF_STRING, /* Stopped at '\0' - valid extension found */
	RISCV_EXT_PARSE_STOPPED_AT_NUMBER, /* Stopped at a digit - valid extension found */
	RISCV_EXT_PARSE_STOPPED_AT_UNDERSCORE, /* Stopped at '_' - valid extension found */
	RISCV_EXT_PARSE_STOPPED_AT_UNEXPECTED, /* Stopped at unexpected char - valid extension found */
	RISCV_EXT_PARSE_NO_MATCH_END_OF_STRING, /* Reached '\0' - no valid extension */
	RISCV_EXT_PARSE_NO_MATCH_NUMBER, /* Hit number - no valid extension at this point */
	RISCV_EXT_PARSE_NO_MATCH_UNDERSCORE, /* Hit underscore - no valid extension at this point */
	RISCV_EXT_PARSE_NO_MATCH_UNEXPECTED, /* Hit unexpected char - no valid extension */
} riscv_extension_parse_result_t;

/* Macro: Stop parsing with a matched extension */
#ifndef MATCH_CALLBACK
#define MATCH_CALLBACK(feature_enum)
#endif

#ifndef FINI_EXT_CALLBACKS
#define FINI_EXT_CALLBACKS()
#endif

#define STOP_WITH_MATCH(feature_enum) \
	do { \
		MATCH_CALLBACK(feature_enum); \
		*idx = (size_t)(p - ext_name); \
		*mode = feature_enum; \
		FINI_EXT_CALLBACKS(); \
		if (*p == '\0') { \
			return RISCV_EXT_PARSE_END_OF_STRING; \
		} else if (*p >= '0' && *p <= '9') { \
			return RISCV_EXT_PARSE_STOPPED_AT_NUMBER; \
		} else if (*p == '_') { \
			return RISCV_EXT_PARSE_STOPPED_AT_UNDERSCORE; \
		} else { \
			return RISCV_EXT_PARSE_STOPPED_AT_UNEXPECTED; \
		} \
	} while (0)

/* Macro: Stop parsing without a match */
#define STOP_WITHOUT_MATCH() \
	do { \
		*idx = (size_t)(p - ext_name); \
		if (*p == '\0') { \
			return RISCV_EXT_PARSE_NO_MATCH_END_OF_STRING; \
		} else if (*p >= '0' && *p <= '9') { \
			return RISCV_EXT_PARSE_NO_MATCH_NUMBER; \
		} else if (*p == '_') { \
			return RISCV_EXT_PARSE_NO_MATCH_UNDERSCORE; \
		} else { \
			return RISCV_EXT_PARSE_NO_MATCH_UNEXPECTED; \
		} \
	} while (0)

/**
 * Main parse routine: Try to consume a RISC-V extension name from the architecture string at a given position.
 *
 * @param arch_str: The full architecture string
 * @param idx: Pointer to current index (will be updated to show consumed length)
 * @param mode: Pointer to the feature accumulator (will be ORed with the feature flag if extension found)
 * @return: Parse result indicating why parsing stopped and whether a match was found
 *
 * Stopping conditions:
 *   - '\0' (end of string)
 *   - '0'-'9' (version number)
 *   - '_' (extension separator)
 *   - Any unexpected character
 *
 * The function uses a trie-based approach for efficient parsing.
 * State comments show the current position in the trie:
 *   'abc...' means we've matched 'abc' and are looking for more
 *   'abc(!x)' means we've matched 'abc' but encountered unexpected char instead of 'x'
 */
#ifndef INIT_EXT_CALLBACKS
#define INIT_EXT_CALLBACKS()
#endif

static inline riscv_extension_parse_result_t
try_consume_riscv_ext_from(const char *ext_name, size_t *idx, ut64 *mode) {
	if (!ext_name || !idx || !mode) {
		return RISCV_EXT_PARSE_NO_MATCH_END_OF_STRING;
	}

	INIT_EXT_CALLBACKS();
	const char *p = ext_name + *idx;

	if (*p == '\0') {
		return RISCV_EXT_PARSE_NO_MATCH_END_OF_STRING;
	}

	/* State: '' expecting [acdfhimsvz] */
	if (*p == 'a') {
		p++;
		STOP_WITH_MATCH(RISCV_FeatureStdExtA);
	} else if (*p == 'c') {
		p++;
		STOP_WITH_MATCH(RISCV_FeatureStdExtC);
	} else if (*p == 'd') {
		p++;
		STOP_WITH_MATCH(RISCV_FeatureStdExtD);
	} else if (*p == 'f') {
		p++;
		STOP_WITH_MATCH(RISCV_FeatureStdExtF);
	} else if (*p == 'h') {
		p++;
		STOP_WITH_MATCH(RISCV_FeatureStdExtH);
	} else if (*p == 'i') {
		p++;
		STOP_WITH_MATCH(RISCV_FeatureStdExtI);
	} else if (*p == 'm') {
		p++;
		STOP_WITH_MATCH(RISCV_FeatureStdExtM);
	} else if (*p == 's') {
		p++;
		/* State: 's' expecting [msv] */
		if (*p == 'm') {
			p++;
			/* State: 'sm' expecting [ae] */
			if (*p == 'a') {
				p++;
				/* State: 'sma' expecting [i] */
				if (*p == 'i') {
					p++;
					/* State: 'smai' expecting [a] */
					if (*p == 'a') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtSmaia);
					} else {
						/* Unexpected char at 'smai', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'sma', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'e') {
				p++;
				/* State: 'sme' expecting [p] */
				if (*p == 'p') {
					p++;
					/* State: 'smep' expecting [m] */
					if (*p == 'm') {
						p++;
						/* State: 'smepm' expecting [p] */
						if (*p == 'p') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtSmepmp);
						} else {
							/* Unexpected char at 'smepm', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'smep', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'sme', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'sm', no match */
				STOP_WITHOUT_MATCH();
			}
		} else if (*p == 's') {
			p++;
			/* State: 'ss' expecting [a] */
			if (*p == 'a') {
				p++;
				/* State: 'ssa' expecting [i] */
				if (*p == 'i') {
					p++;
					/* State: 'ssai' expecting [a] */
					if (*p == 'a') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtSsaia);
					} else {
						/* Unexpected char at 'ssai', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'ssa', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'ss', no match */
				STOP_WITHOUT_MATCH();
			}
		} else if (*p == 'v') {
			p++;
			/* State: 'sv' expecting [inp] */
			if (*p == 'i') {
				p++;
				/* State: 'svi' expecting [n] */
				if (*p == 'n') {
					p++;
					/* State: 'svin' expecting [v] */
					if (*p == 'v') {
						p++;
						/* State: 'svinv' expecting [a] */
						if (*p == 'a') {
							p++;
							/* State: 'svinva' expecting [l] */
							if (*p == 'l') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtSvinval);
							} else {
								/* Unexpected char at 'svinva', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'svinv', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'svin', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'svi', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'n') {
				p++;
				/* State: 'svn' expecting [a] */
				if (*p == 'a') {
					p++;
					/* State: 'svna' expecting [p] */
					if (*p == 'p') {
						p++;
						/* State: 'svnap' expecting [o] */
						if (*p == 'o') {
							p++;
							/* State: 'svnapo' expecting [t] */
							if (*p == 't') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtSvnapot);
							} else {
								/* Unexpected char at 'svnapo', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'svnap', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'svna', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'svn', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'p') {
				p++;
				/* State: 'svp' expecting [b] */
				if (*p == 'b') {
					p++;
					/* State: 'svpb' expecting [m] */
					if (*p == 'm') {
						p++;
						/* State: 'svpbm' expecting [t] */
						if (*p == 't') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtSvpbmt);
						} else {
							/* Unexpected char at 'svpbm', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'svpb', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'svp', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'sv', no match */
				STOP_WITHOUT_MATCH();
			}
		} else {
			/* Unexpected char at 's', no match */
			STOP_WITHOUT_MATCH();
		}
	} else if (*p == 'v') {
		p++;
		STOP_WITH_MATCH(RISCV_FeatureStdExtV);
	} else if (*p == 'z') {
		p++;
		/* State: 'z' expecting [abcdfhikmtv] */
		if (*p == 'a') {
			p++;
			/* State: 'za' expecting [16cw] */
			if (*p == '1') {
				p++;
				/* State: 'za1' expecting [2] */
				if (*p == '2') {
					p++;
					/* State: 'za12' expecting [8] */
					if (*p == '8') {
						p++;
						/* State: 'za128' expecting [r] */
						if (*p == 'r') {
							p++;
							/* State: 'za128r' expecting [s] */
							if (*p == 's') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtZa128rs);
							} else {
								/* Unexpected char at 'za128r', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'za128', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'za12', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'za1', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == '6') {
				p++;
				/* State: 'za6' expecting [4] */
				if (*p == '4') {
					p++;
					/* State: 'za64' expecting [r] */
					if (*p == 'r') {
						p++;
						/* State: 'za64r' expecting [s] */
						if (*p == 's') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZa64rs);
						} else {
							/* Unexpected char at 'za64r', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'za64', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'za6', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'c') {
				p++;
				/* State: 'zac' expecting [a] */
				if (*p == 'a') {
					p++;
					/* State: 'zaca' expecting [s] */
					if (*p == 's') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZacas);
					} else {
						/* Unexpected char at 'zaca', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zac', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'w') {
				p++;
				/* State: 'zaw' expecting [r] */
				if (*p == 'r') {
					p++;
					/* State: 'zawr' expecting [s] */
					if (*p == 's') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZawrs);
					} else {
						/* Unexpected char at 'zawr', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zaw', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'za', no match */
				STOP_WITHOUT_MATCH();
			}
		} else if (*p == 'b') {
			p++;
			/* State: 'zb' expecting [abcks] */
			if (*p == 'a') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZba);
			} else if (*p == 'b') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZbb);
			} else if (*p == 'c') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZbc);
			} else if (*p == 'k') {
				p++;
				/* State: 'zbk' expecting [bcx] */
				if (*p == 'b') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZbkb);
				} else if (*p == 'c') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZbkc);
				} else if (*p == 'x') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZbkx);
				} else {
					/* Unexpected char at 'zbk', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 's') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZbs);
			} else {
				/* Unexpected char at 'zb', no match */
				STOP_WITHOUT_MATCH();
			}
		} else if (*p == 'c') {
			p++;
			/* State: 'zc' expecting [abdefm] */
			if (*p == 'a') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZca);
			} else if (*p == 'b') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZcb);
			} else if (*p == 'd') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZcd);
			} else if (*p == 'e') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZce);
			} else if (*p == 'f') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZcf);
			} else if (*p == 'm') {
				p++;
				/* State: 'zcm' expecting [opt] */
				if (*p == 'o') {
					p++;
					/* State: 'zcmo' expecting [p] */
					if (*p == 'p') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZcmop);
					} else {
						/* Unexpected char at 'zcmo', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == 'p') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZcmp);
				} else if (*p == 't') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZcmt);
				} else {
					/* Unexpected char at 'zcm', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'zc', no match */
				STOP_WITHOUT_MATCH();
			}
		} else if (*p == 'd') {
			p++;
			/* State: 'zd' expecting [i] */
			if (*p == 'i') {
				p++;
				/* State: 'zdi' expecting [n] */
				if (*p == 'n') {
					p++;
					/* State: 'zdin' expecting [x] */
					if (*p == 'x') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZdinx);
					} else {
						/* Unexpected char at 'zdin', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zdi', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'zd', no match */
				STOP_WITHOUT_MATCH();
			}
		} else if (*p == 'f') {
			p++;
			/* State: 'zf' expecting [abhi] */
			if (*p == 'a') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZfa);
			} else if (*p == 'b') {
				p++;
				/* State: 'zfb' expecting [f] */
				if (*p == 'f') {
					p++;
					/* State: 'zfbf' expecting [m] */
					if (*p == 'm') {
						p++;
						/* State: 'zfbfm' expecting [i] */
						if (*p == 'i') {
							p++;
							/* State: 'zfbfmi' expecting [n] */
							if (*p == 'n') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtZfbfmin);
							} else {
								/* Unexpected char at 'zfbfmi', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zfbfm', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zfbf', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zfb', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'h') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZfh);

				/* State: 'zfh' expecting [m] */
				if (*p == 'm') {
					p++;
					/* State: 'zfhm' expecting [i] */
					if (*p == 'i') {
						p++;
						/* State: 'zfhmi' expecting [n] */
						if (*p == 'n') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZfhmin);
						} else {
							/* Unexpected char at 'zfhmi', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zfhm', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char, but 'zfh' was valid */
					STOP_WITH_MATCH(RISCV_FeatureStdExtZfh);
				}
			} else if (*p == 'i') {
				p++;
				/* State: 'zfi' expecting [n] */
				if (*p == 'n') {
					p++;
					/* State: 'zfin' expecting [x] */
					if (*p == 'x') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZfinx);
					} else {
						/* Unexpected char at 'zfin', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zfi', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'zf', no match */
				STOP_WITHOUT_MATCH();
			}
		} else if (*p == 'h') {
			p++;
			/* State: 'zh' expecting [i] */
			if (*p == 'i') {
				p++;
				/* State: 'zhi' expecting [n] */
				if (*p == 'n') {
					p++;
					/* State: 'zhin' expecting [x] */
					if (*p == 'x') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZhinx);

						/* State: 'zhinx' expecting [m] */
						if (*p == 'm') {
							p++;
							/* State: 'zhinxm' expecting [i] */
							if (*p == 'i') {
								p++;
								/* State: 'zhinxmi' expecting [n] */
								if (*p == 'n') {
									p++;
									STOP_WITH_MATCH(RISCV_FeatureStdExtZhinxmin);
								} else {
									/* Unexpected char at 'zhinxmi', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zhinxm', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char, but 'zhinx' was valid */
							STOP_WITH_MATCH(RISCV_FeatureStdExtZhinx);
						}
					} else {
						/* Unexpected char at 'zhin', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zhi', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'zh', no match */
				STOP_WITHOUT_MATCH();
			}
		} else if (*p == 'i') {
			p++;
			/* State: 'zi' expecting [cfhm] */
			if (*p == 'c') {
				p++;
				/* State: 'zic' expecting [6bcfnos] */
				if (*p == '6') {
					p++;
					/* State: 'zic6' expecting [4] */
					if (*p == '4') {
						p++;
						/* State: 'zic64' expecting [b] */
						if (*p == 'b') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZic64b);
						} else {
							/* Unexpected char at 'zic64', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zic6', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == 'b') {
					p++;
					/* State: 'zicb' expecting [o] */
					if (*p == 'o') {
						p++;
						/* State: 'zicbo' expecting [mpz] */
						if (*p == 'm') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZicbom);
						} else if (*p == 'p') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZicbop);
						} else if (*p == 'z') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZicboz);
						} else {
							/* Unexpected char at 'zicbo', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zicb', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == 'c') {
					p++;
					/* State: 'zicc' expecting [ailr] */
					if (*p == 'a') {
						p++;
						/* State: 'zicca' expecting [m] */
						if (*p == 'm') {
							p++;
							/* State: 'ziccam' expecting [o] */
							if (*p == 'o') {
								p++;
								/* State: 'ziccamo' expecting [a] */
								if (*p == 'a') {
									p++;
									STOP_WITH_MATCH(RISCV_FeatureStdExtZiccamoa);
								} else {
									/* Unexpected char at 'ziccamo', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'ziccam', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zicca', no match */
							STOP_WITHOUT_MATCH();
						}
					} else if (*p == 'i') {
						p++;
						/* State: 'zicci' expecting [f] */
						if (*p == 'f') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZiccif);
						} else {
							/* Unexpected char at 'zicci', no match */
							STOP_WITHOUT_MATCH();
						}
					} else if (*p == 'l') {
						p++;
						/* State: 'ziccl' expecting [s] */
						if (*p == 's') {
							p++;
							/* State: 'ziccls' expecting [m] */
							if (*p == 'm') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtZicclsm);
							} else {
								/* Unexpected char at 'ziccls', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'ziccl', no match */
							STOP_WITHOUT_MATCH();
						}
					} else if (*p == 'r') {
						p++;
						/* State: 'ziccr' expecting [s] */
						if (*p == 's') {
							p++;
							/* State: 'ziccrs' expecting [e] */
							if (*p == 'e') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtZiccrse);
							} else {
								/* Unexpected char at 'ziccrs', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'ziccr', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zicc', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == 'f') {
					p++;
					/* State: 'zicf' expecting [i] */
					if (*p == 'i') {
						p++;
						/* State: 'zicfi' expecting [ls] */
						if (*p == 'l') {
							p++;
							/* State: 'zicfil' expecting [p] */
							if (*p == 'p') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtZicfilp);
							} else {
								/* Unexpected char at 'zicfil', no match */
								STOP_WITHOUT_MATCH();
							}
						} else if (*p == 's') {
							p++;
							/* State: 'zicfis' expecting [s] */
							if (*p == 's') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtZicfiss);
							} else {
								/* Unexpected char at 'zicfis', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zicfi', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zicf', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == 'n') {
					p++;
					/* State: 'zicn' expecting [t] */
					if (*p == 't') {
						p++;
						/* State: 'zicnt' expecting [r] */
						if (*p == 'r') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZicntr);
						} else {
							/* Unexpected char at 'zicnt', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zicn', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == 'o') {
					p++;
					/* State: 'zico' expecting [n] */
					if (*p == 'n') {
						p++;
						/* State: 'zicon' expecting [d] */
						if (*p == 'd') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZicond);
						} else {
							/* Unexpected char at 'zicon', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zico', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == 's') {
					p++;
					/* State: 'zics' expecting [r] */
					if (*p == 'r') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZicsr);
					} else {
						/* Unexpected char at 'zics', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zic', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'f') {
				p++;
				/* State: 'zif' expecting [e] */
				if (*p == 'e') {
					p++;
					/* State: 'zife' expecting [n] */
					if (*p == 'n') {
						p++;
						/* State: 'zifen' expecting [c] */
						if (*p == 'c') {
							p++;
							/* State: 'zifenc' expecting [e] */
							if (*p == 'e') {
								p++;
								/* State: 'zifence' expecting [i] */
								if (*p == 'i') {
									p++;
									STOP_WITH_MATCH(RISCV_FeatureStdExtZifencei);
								} else {
									/* Unexpected char at 'zifence', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zifenc', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zifen', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zife', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zif', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'h') {
				p++;
				/* State: 'zih' expecting [ip] */
				if (*p == 'i') {
					p++;
					/* State: 'zihi' expecting [n] */
					if (*p == 'n') {
						p++;
						/* State: 'zihin' expecting [t] */
						if (*p == 't') {
							p++;
							/* State: 'zihint' expecting [np] */
							if (*p == 'n') {
								p++;
								/* State: 'zihintn' expecting [t] */
								if (*p == 't') {
									p++;
									/* State: 'zihintnt' expecting [l] */
									if (*p == 'l') {
										p++;
										STOP_WITH_MATCH(RISCV_FeatureStdExtZihintntl);
									} else {
										/* Unexpected char at 'zihintnt', no match */
										STOP_WITHOUT_MATCH();
									}
								} else {
									/* Unexpected char at 'zihintn', no match */
									STOP_WITHOUT_MATCH();
								}
							} else if (*p == 'p') {
								p++;
								/* State: 'zihintp' expecting [a] */
								if (*p == 'a') {
									p++;
									/* State: 'zihintpa' expecting [u] */
									if (*p == 'u') {
										p++;
										/* State: 'zihintpau' expecting [s] */
										if (*p == 's') {
											p++;
											/* State: 'zihintpaus' expecting [e] */
											if (*p == 'e') {
												p++;
												STOP_WITH_MATCH(RISCV_FeatureStdExtZihintpause);
											} else {
												/* Unexpected char at 'zihintpaus', no match */
												STOP_WITHOUT_MATCH();
											}
										} else {
											/* Unexpected char at 'zihintpau', no match */
											STOP_WITHOUT_MATCH();
										}
									} else {
										/* Unexpected char at 'zihintpa', no match */
										STOP_WITHOUT_MATCH();
									}
								} else {
									/* Unexpected char at 'zihintp', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zihint', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zihin', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zihi', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == 'p') {
					p++;
					/* State: 'zihp' expecting [m] */
					if (*p == 'm') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZihpm);
					} else {
						/* Unexpected char at 'zihp', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zih', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'm') {
				p++;
				/* State: 'zim' expecting [o] */
				if (*p == 'o') {
					p++;
					/* State: 'zimo' expecting [p] */
					if (*p == 'p') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZimop);
					} else {
						/* Unexpected char at 'zimo', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zim', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'zi', no match */
				STOP_WITHOUT_MATCH();
			}
		} else if (*p == 'k') {
			p++;
			STOP_WITH_MATCH(RISCV_FeatureStdExtZk);

			/* State: 'zk' expecting [nrst] */
			if (*p == 'n') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZkn);

				/* State: 'zkn' expecting [deh] */
				if (*p == 'd') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZknd);
				} else if (*p == 'e') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZkne);
				} else if (*p == 'h') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZknh);
				} else {
					/* Unexpected char, but 'zkn' was valid */
					STOP_WITH_MATCH(RISCV_FeatureStdExtZkn);
				}
			} else if (*p == 'r') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZkr);
			} else if (*p == 's') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZks);

				/* State: 'zks' expecting [eh] */
				if (*p == 'e') {
					p++;
					/* State: 'zkse' expecting [d] */
					if (*p == 'd') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZksed);
					} else {
						/* Unexpected char at 'zkse', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == 'h') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZksh);
				} else {
					/* Unexpected char, but 'zks' was valid */
					STOP_WITH_MATCH(RISCV_FeatureStdExtZks);
				}
			} else if (*p == 't') {
				p++;
				STOP_WITH_MATCH(RISCV_FeatureStdExtZkt);
			} else {
				/* Unexpected char, but 'zk' was valid */
				STOP_WITH_MATCH(RISCV_FeatureStdExtZk);
			}
		} else if (*p == 'm') {
			p++;
			/* State: 'zm' expecting [m] */
			if (*p == 'm') {
				p++;
				/* State: 'zmm' expecting [u] */
				if (*p == 'u') {
					p++;
					/* State: 'zmmu' expecting [l] */
					if (*p == 'l') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZmmul);
					} else {
						/* Unexpected char at 'zmmu', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zmm', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'zm', no match */
				STOP_WITHOUT_MATCH();
			}
		} else if (*p == 't') {
			p++;
			/* State: 'zt' expecting [s] */
			if (*p == 's') {
				p++;
				/* State: 'zts' expecting [o] */
				if (*p == 'o') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZtso);
				} else {
					/* Unexpected char at 'zts', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'zt', no match */
				STOP_WITHOUT_MATCH();
			}
		} else if (*p == 'v') {
			p++;
			/* State: 'zv' expecting [befkl] */
			if (*p == 'b') {
				p++;
				/* State: 'zvb' expecting [bc] */
				if (*p == 'b') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZvbb);
				} else if (*p == 'c') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZvbc);
				} else {
					/* Unexpected char at 'zvb', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'e') {
				p++;
				/* State: 'zve' expecting [36] */
				if (*p == '3') {
					p++;
					/* State: 'zve3' expecting [2] */
					if (*p == '2') {
						p++;
						/* State: 'zve32' expecting [fx] */
						if (*p == 'f') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZve32f);
						} else if (*p == 'x') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZve32x);
						} else {
							/* Unexpected char at 'zve32', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zve3', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == '6') {
					p++;
					/* State: 'zve6' expecting [4] */
					if (*p == '4') {
						p++;
						/* State: 'zve64' expecting [dfx] */
						if (*p == 'd') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZve64d);
						} else if (*p == 'f') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZve64f);
						} else if (*p == 'x') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZve64x);
						} else {
							/* Unexpected char at 'zve64', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zve6', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zve', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'f') {
				p++;
				/* State: 'zvf' expecting [bh] */
				if (*p == 'b') {
					p++;
					/* State: 'zvfb' expecting [f] */
					if (*p == 'f') {
						p++;
						/* State: 'zvfbf' expecting [mw] */
						if (*p == 'm') {
							p++;
							/* State: 'zvfbfm' expecting [i] */
							if (*p == 'i') {
								p++;
								/* State: 'zvfbfmi' expecting [n] */
								if (*p == 'n') {
									p++;
									STOP_WITH_MATCH(RISCV_FeatureStdExtZvfbfmin);
								} else {
									/* Unexpected char at 'zvfbfmi', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zvfbfm', no match */
								STOP_WITHOUT_MATCH();
							}
						} else if (*p == 'w') {
							p++;
							/* State: 'zvfbfw' expecting [m] */
							if (*p == 'm') {
								p++;
								/* State: 'zvfbfwm' expecting [a] */
								if (*p == 'a') {
									p++;
									STOP_WITH_MATCH(RISCV_FeatureStdExtZvfbfwma);
								} else {
									/* Unexpected char at 'zvfbfwm', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zvfbfw', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zvfbf', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zvfb', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == 'h') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZvfh);

					/* State: 'zvfh' expecting [m] */
					if (*p == 'm') {
						p++;
						/* State: 'zvfhm' expecting [i] */
						if (*p == 'i') {
							p++;
							/* State: 'zvfhmi' expecting [n] */
							if (*p == 'n') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtZvfhmin);
							} else {
								/* Unexpected char at 'zvfhmi', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zvfhm', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char, but 'zvfh' was valid */
						STOP_WITH_MATCH(RISCV_FeatureStdExtZvfh);
					}
				} else {
					/* Unexpected char at 'zvf', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'k') {
				p++;
				/* State: 'zvk' expecting [bgnst] */
				if (*p == 'b') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZvkb);
				} else if (*p == 'g') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZvkg);
				} else if (*p == 'n') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZvkn);

					/* State: 'zvkn' expecting [cegh] */
					if (*p == 'c') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZvknc);
					} else if (*p == 'e') {
						p++;
						/* State: 'zvkne' expecting [d] */
						if (*p == 'd') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZvkned);
						} else {
							/* Unexpected char at 'zvkne', no match */
							STOP_WITHOUT_MATCH();
						}
					} else if (*p == 'g') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZvkng);
					} else if (*p == 'h') {
						p++;
						/* State: 'zvknh' expecting [ab] */
						if (*p == 'a') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZvknha);
						} else if (*p == 'b') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZvknhb);
						} else {
							/* Unexpected char at 'zvknh', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char, but 'zvkn' was valid */
						STOP_WITH_MATCH(RISCV_FeatureStdExtZvkn);
					}
				} else if (*p == 's') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZvks);

					/* State: 'zvks' expecting [cegh] */
					if (*p == 'c') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZvksc);
					} else if (*p == 'e') {
						p++;
						/* State: 'zvkse' expecting [d] */
						if (*p == 'd') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZvksed);
						} else {
							/* Unexpected char at 'zvkse', no match */
							STOP_WITHOUT_MATCH();
						}
					} else if (*p == 'g') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZvksg);
					} else if (*p == 'h') {
						p++;
						STOP_WITH_MATCH(RISCV_FeatureStdExtZvksh);
					} else {
						/* Unexpected char, but 'zvks' was valid */
						STOP_WITH_MATCH(RISCV_FeatureStdExtZvks);
					}
				} else if (*p == 't') {
					p++;
					STOP_WITH_MATCH(RISCV_FeatureStdExtZvkt);
				} else {
					/* Unexpected char at 'zvk', no match */
					STOP_WITHOUT_MATCH();
				}
			} else if (*p == 'l') {
				p++;
				/* State: 'zvl' expecting [1234568] */
				if (*p == '1') {
					p++;
					/* State: 'zvl1' expecting [026] */
					if (*p == '0') {
						p++;
						/* State: 'zvl10' expecting [2] */
						if (*p == '2') {
							p++;
							/* State: 'zvl102' expecting [4] */
							if (*p == '4') {
								p++;
								/* State: 'zvl1024' expecting [b] */
								if (*p == 'b') {
									p++;
									STOP_WITH_MATCH(RISCV_FeatureStdExtZvl1024b);
								} else {
									/* Unexpected char at 'zvl1024', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zvl102', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zvl10', no match */
							STOP_WITHOUT_MATCH();
						}
					} else if (*p == '2') {
						p++;
						/* State: 'zvl12' expecting [8] */
						if (*p == '8') {
							p++;
							/* State: 'zvl128' expecting [b] */
							if (*p == 'b') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtZvl128b);
							} else {
								/* Unexpected char at 'zvl128', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zvl12', no match */
							STOP_WITHOUT_MATCH();
						}
					} else if (*p == '6') {
						p++;
						/* State: 'zvl16' expecting [3] */
						if (*p == '3') {
							p++;
							/* State: 'zvl163' expecting [8] */
							if (*p == '8') {
								p++;
								/* State: 'zvl1638' expecting [4] */
								if (*p == '4') {
									p++;
									/* State: 'zvl16384' expecting [b] */
									if (*p == 'b') {
										p++;
										STOP_WITH_MATCH(RISCV_FeatureStdExtZvl16384b);
									} else {
										/* Unexpected char at 'zvl16384', no match */
										STOP_WITHOUT_MATCH();
									}
								} else {
									/* Unexpected char at 'zvl1638', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zvl163', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zvl16', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zvl1', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == '2') {
					p++;
					/* State: 'zvl2' expecting [05] */
					if (*p == '0') {
						p++;
						/* State: 'zvl20' expecting [4] */
						if (*p == '4') {
							p++;
							/* State: 'zvl204' expecting [8] */
							if (*p == '8') {
								p++;
								/* State: 'zvl2048' expecting [b] */
								if (*p == 'b') {
									p++;
									STOP_WITH_MATCH(RISCV_FeatureStdExtZvl2048b);
								} else {
									/* Unexpected char at 'zvl2048', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zvl204', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zvl20', no match */
							STOP_WITHOUT_MATCH();
						}
					} else if (*p == '5') {
						p++;
						/* State: 'zvl25' expecting [6] */
						if (*p == '6') {
							p++;
							/* State: 'zvl256' expecting [b] */
							if (*p == 'b') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtZvl256b);
							} else {
								/* Unexpected char at 'zvl256', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zvl25', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zvl2', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == '3') {
					p++;
					/* State: 'zvl3' expecting [2] */
					if (*p == '2') {
						p++;
						/* State: 'zvl32' expecting [7b] */
						if (*p == '7') {
							p++;
							/* State: 'zvl327' expecting [6] */
							if (*p == '6') {
								p++;
								/* State: 'zvl3276' expecting [8] */
								if (*p == '8') {
									p++;
									/* State: 'zvl32768' expecting [b] */
									if (*p == 'b') {
										p++;
										STOP_WITH_MATCH(RISCV_FeatureStdExtZvl32768b);
									} else {
										/* Unexpected char at 'zvl32768', no match */
										STOP_WITHOUT_MATCH();
									}
								} else {
									/* Unexpected char at 'zvl3276', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zvl327', no match */
								STOP_WITHOUT_MATCH();
							}
						} else if (*p == 'b') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZvl32b);
						} else {
							/* Unexpected char at 'zvl32', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zvl3', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == '4') {
					p++;
					/* State: 'zvl4' expecting [0] */
					if (*p == '0') {
						p++;
						/* State: 'zvl40' expecting [9] */
						if (*p == '9') {
							p++;
							/* State: 'zvl409' expecting [6] */
							if (*p == '6') {
								p++;
								/* State: 'zvl4096' expecting [b] */
								if (*p == 'b') {
									p++;
									STOP_WITH_MATCH(RISCV_FeatureStdExtZvl4096b);
								} else {
									/* Unexpected char at 'zvl4096', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zvl409', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zvl40', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zvl4', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == '5') {
					p++;
					/* State: 'zvl5' expecting [1] */
					if (*p == '1') {
						p++;
						/* State: 'zvl51' expecting [2] */
						if (*p == '2') {
							p++;
							/* State: 'zvl512' expecting [b] */
							if (*p == 'b') {
								p++;
								STOP_WITH_MATCH(RISCV_FeatureStdExtZvl512b);
							} else {
								/* Unexpected char at 'zvl512', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zvl51', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zvl5', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == '6') {
					p++;
					/* State: 'zvl6' expecting [45] */
					if (*p == '4') {
						p++;
						/* State: 'zvl64' expecting [b] */
						if (*p == 'b') {
							p++;
							STOP_WITH_MATCH(RISCV_FeatureStdExtZvl64b);
						} else {
							/* Unexpected char at 'zvl64', no match */
							STOP_WITHOUT_MATCH();
						}
					} else if (*p == '5') {
						p++;
						/* State: 'zvl65' expecting [5] */
						if (*p == '5') {
							p++;
							/* State: 'zvl655' expecting [3] */
							if (*p == '3') {
								p++;
								/* State: 'zvl6553' expecting [6] */
								if (*p == '6') {
									p++;
									/* State: 'zvl65536' expecting [b] */
									if (*p == 'b') {
										p++;
										STOP_WITH_MATCH(RISCV_FeatureStdExtZvl65536b);
									} else {
										/* Unexpected char at 'zvl65536', no match */
										STOP_WITHOUT_MATCH();
									}
								} else {
									/* Unexpected char at 'zvl6553', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zvl655', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zvl65', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zvl6', no match */
						STOP_WITHOUT_MATCH();
					}
				} else if (*p == '8') {
					p++;
					/* State: 'zvl8' expecting [1] */
					if (*p == '1') {
						p++;
						/* State: 'zvl81' expecting [9] */
						if (*p == '9') {
							p++;
							/* State: 'zvl819' expecting [2] */
							if (*p == '2') {
								p++;
								/* State: 'zvl8192' expecting [b] */
								if (*p == 'b') {
									p++;
									STOP_WITH_MATCH(RISCV_FeatureStdExtZvl8192b);
								} else {
									/* Unexpected char at 'zvl8192', no match */
									STOP_WITHOUT_MATCH();
								}
							} else {
								/* Unexpected char at 'zvl819', no match */
								STOP_WITHOUT_MATCH();
							}
						} else {
							/* Unexpected char at 'zvl81', no match */
							STOP_WITHOUT_MATCH();
						}
					} else {
						/* Unexpected char at 'zvl8', no match */
						STOP_WITHOUT_MATCH();
					}
				} else {
					/* Unexpected char at 'zvl', no match */
					STOP_WITHOUT_MATCH();
				}
			} else {
				/* Unexpected char at 'zv', no match */
				STOP_WITHOUT_MATCH();
			}
		} else {
			/* Unexpected char at 'z', no match */
			STOP_WITHOUT_MATCH();
		}
	} else {
		/* Unexpected char at '', no match */
		STOP_WITHOUT_MATCH();
	}

	/* Should not reach here */
	STOP_WITHOUT_MATCH();
}

/* Cleanup macros */
#undef STOP_WITH_MATCH
#undef STOP_WITHOUT_MATCH

/* Example usage:
 *
 * ut64 features = 0;
 * riscv_extension_parse_result_t result;
 * size_t idx = 0;
 * const char *arch = "i2p1_m2p0_zicsr";
 *
 * // Parse "i" from "i2p1_m2p0_zicsr"
 * result = try_consume_riscv_ext_from(arch, &idx, &features);
 * // idx is now 1, result is RISCV_EXT_PARSE_STOPPED_AT_NUMBER
 *
 * // Skip version "2p1_" by setting idx = 5
 * idx = 5; // now at 'm'
 * result = try_consume_riscv_ext_from(arch, &idx, &features);
 * // idx is now 6, result is RISCV_EXT_PARSE_STOPPED_AT_NUMBER
 *
 * // Skip version "2p0_" by setting idx = 10
 * idx = 10; // now at 'z'
 * result = try_consume_riscv_ext_from(arch, &idx, &features);
 * // idx is now 15, result is RISCV_EXT_PARSE_END_OF_STRING
 */
