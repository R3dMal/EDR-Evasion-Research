#pragma once
#include "common.h"

typedef struct _SYSCALL_TABLE {
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtCreateThreadEx;
    SYSCALL_ENTRY NtWaitForSingleObject;
    SYSCALL_ENTRY NtFreeVirtualMemory;
    SYSCALL_ENTRY NtClose;
    SYSCALL_ENTRY NtOpenProcess;
} SYSCALL_TABLE, *PSYSCALL_TABLE;

PVOID GetNtdllBase(void);
BOOL ResolveSyscall(PVOID ntdll_base, DWORD func_hash, PSYSCALL_ENTRY entry);
BOOL InitSyscallTable(PSYSCALL_TABLE table);

extern void SetSyscallEntry(DWORD ssn, PVOID syscall_addr);
extern NTSTATUS DoSyscall(...);
