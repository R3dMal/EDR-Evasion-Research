#include "api_hash.h"
#include <intrin.h>

DWORD HashStringA(const char *str) {
    DWORD hash = 5381;
    while (*str)
        hash = ((hash << 5) + hash) + (unsigned char)*str++;
    return hash;
}

static DWORD HashStringW_Lower(const WCHAR *str, USHORT len_bytes) {
    DWORD hash = 5381;
    USHORT count = len_bytes / sizeof(WCHAR);
    for (USHORT i = 0; i < count; i++) {
        WCHAR c = str[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        hash = ((hash << 5) + hash) + (unsigned char)c;
    }
    return hash;
}

PVOID GetModuleByHash(DWORD module_hash) {
    PPEB2 peb = (PPEB2)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY2 entry = CONTAINING_RECORD(
            curr, LDR_DATA_TABLE_ENTRY2, InLoadOrderLinks);
        if (entry->BaseDllName.Buffer) {
            DWORD h = HashStringW_Lower(
                entry->BaseDllName.Buffer, entry->BaseDllName.Length);
            if (h == module_hash)
                return entry->DllBase;
        }
        curr = curr->Flink;
    }
    return NULL;
}

PVOID GetFuncByHash(DWORD func_hash) {
    /* Search all loaded modules for a function matching the hash */
    PPEB2 peb = (PPEB2)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY2 entry = CONTAINING_RECORD(
            curr, LDR_DATA_TABLE_ENTRY2, InLoadOrderLinks);
        if (entry->DllBase) {
            PVOID func = ResolveExportByHash(entry->DllBase, func_hash);
            if (func) return func;
        }
        curr = curr->Flink;
    }
    return NULL;
}

PVOID ResolveExportByHash(PVOID module_base, DWORD func_hash) {
    PBYTE base = (PBYTE)module_base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_rva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + export_rva);
    PDWORD addr_table = (PDWORD)(base + exports->AddressOfFunctions);
    PDWORD name_table = (PDWORD)(base + exports->AddressOfNames);
    PWORD  ord_table  = (PWORD)(base + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char *name = (char *)(base + name_table[i]);
        if (HashStringA(name) == func_hash)
            return (PVOID)(base + addr_table[ord_table[i]]);
    }
    return NULL;
}
