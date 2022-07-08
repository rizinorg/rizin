// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_WINDOWS_H
#define RZ_WINDOWS_H
/*
 * This file is to be included whenever access to
 * Windows APIs and type definitions is necessary.
 * You should avoid including this file in often used
 * header files as it will slow down compilation.
 */
#if __WINDOWS__ || _WIN32 || _MSC_VER
#include <sdkddkver.h>
#ifdef NTDDI_WIN10_TH2
/* Avoid using Developer Preview and default to Windows 10/Windows Server 2016 */
#undef _WIN32_WINNT
#undef NTDDI_VERSION
#define _WIN32_WINNT  _WIN32_WINNT_WIN10
#define NTDDI_VERSION NTDDI_WIN10
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define NOGDICAPMASKS    // CC_*, LC_*, PC_*, CP_*, TC_*, RC_
#define NOWINMESSAGES    // WM_ *, EM_ *, LB_ *, CB_ *
#define NOWINSTYLES      // WS_*, CS_*, ES_*, LBS_*, SBS_*, CBS_*
#define NOSYSMETRICS     // SM_*
#define NOMENUS          // MF_*
#define NOICONS          // IDI_*
#define NOKEYSTATES      // MK_*
#define NOSYSCOMMANDS    // SC_*
#define NORASTEROPS      // Binary and Tertiary raster ops
#define NOSHOWWINDOW     // SW_*
#define OEMRESOURCE      // OEM Resource values
#define NOATOM           // Atom Manager routines
#define NOCOLOR          // Screen colors
#define NOCTLMGR         // Control and Dialog routines
#define NODRAWTEXT       // DrawText() and DT_*
#define NOGDI            // All GDI defines and routines
#define NOKERNEL         // All KERNEL defines and routines
#define NOMB             // MB_* and MessageBox()
#define NOMEMMGR         // GMEM_*, LMEM_*, GHND, LHND, associated routines
#define NOMETAFILE       // typedef METAFILEPICT
#define NOMINMAX         // Macros min(a,b) and max(a,b)
#define NOOPENFILE       // OpenFile(), OemToAnsi, AnsiToOem, and OF_*
#define NOSCROLL         // SB_* and scrolling routines
#define NOSOUND          // Sound driver routines
#define NOSYSPARAMSINFO  // System Parameter information definitions
#define NOTEXTMETRIC     // typedef TEXTMETRIC and associated routines
#define NOWH             // SetWindowsHook and WH_*
#define NOCOMM           // COMM driver routines
#define NOKANJI          // Kanji support stuff.
#define NOHELP           // Help engine interface.
#define NOPROFILER       // Profiler interface.
#define NODEFERWINDOWPOS // DeferWindowPos routines
#define NOMCX            // Modem Configuration Extensions
#define NOIME            // Input Method Manager
/* Includes windows.h */
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#undef USE_SOCKETS
#define __addr_t_defined
#include <direct.h>
/* Windows <=8 compatibility */
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0
#endif
#include <VersionHelpers.h>
#endif
#endif
