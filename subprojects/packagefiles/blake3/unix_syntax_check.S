#if defined(__ELF__) && defined(__linux__)
.section .note.GNU-stack,"",%progbits
#endif

#if defined(__ELF__) && defined(__CET__) && defined(__has_include)
#if __has_include(<cet.h>)
#include <cet.h>
#endif
#endif

#if !defined(_CET_ENDBR)
#define _CET_ENDBR
#endif

.intel_syntax noprefix
.global _blake3_hash_many_avx2
.global blake3_hash_many_avx2
#ifdef __APPLE__
.text
#else
.section .text
#endif
        .p2align  6
        mov r10d, dword ptr [rsp+0x110+8*rax]
        jc 3f
        nop
        nop
3:
        nop
        nop
