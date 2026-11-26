/*
 * PE Sanitizer — Post-build tool
 *
 * Removes forensic artifacts from the PE:
 *   - TimeDateStamp (compilation timestamp)
 *   - Rich Header (identifies compiler/linker version)
 *   - Debug directory (PDB path, build GUID)
 *
 * Usage: pe_sanitize.exe <file.exe>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned long long ULONGLONG;

#pragma pack(push, 1)
typedef struct {
    WORD  e_magic;
    WORD  e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    WORD  e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    WORD  e_res[4];
    WORD  e_oemid, e_oeminfo;
    WORD  e_res2[10];
    DWORD e_lfanew;
} DOS_HEADER;
#pragma pack(pop)

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file.exe>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "r+b");
    if (!f) { printf("[!] Cannot open %s\n", argv[1]); return 1; }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    BYTE *buf = (BYTE *)malloc(file_size);
    fread(buf, 1, file_size, f);

    DOS_HEADER *dos = (DOS_HEADER *)buf;
    if (dos->e_magic != 0x5A4D) {
        printf("[!] Not a PE file\n");
        free(buf); fclose(f);
        return 1;
    }

    /* 1. Zero Rich Header (between DOS stub and PE signature) */
    DWORD rich_end = 0;
    for (DWORD i = 0x80; i < (DWORD)dos->e_lfanew - 4; i += 4) {
        if (*(DWORD *)(buf + i) == 0x68636952) {  /* "Rich" */
            rich_end = i + 8;  /* "Rich" + XOR key */
            /* Zero from after DOS header to Rich end */
            memset(buf + 0x80, 0, rich_end - 0x80);
            printf("[+] Rich header zeroed (0x80 - 0x%X)\n", rich_end);
            break;
        }
    }

    /* 2. Zero PE TimeDateStamp */
    DWORD pe_offset = dos->e_lfanew;
    if (pe_offset + 8 < (DWORD)file_size) {
        DWORD *timestamp = (DWORD *)(buf + pe_offset + 8);
        printf("[+] TimeDateStamp was: 0x%08X\n", *timestamp);
        *timestamp = 0;
        printf("[+] TimeDateStamp zeroed\n");
    }

    /* 3. Zero debug directory if present */
    /* PE32+ optional header debug directory is at offset 0x70 from optional header start */
    WORD opt_magic = *(WORD *)(buf + pe_offset + 24);
    DWORD debug_rva = 0, debug_size = 0;
    if (opt_magic == 0x020B) {  /* PE32+ */
        debug_rva  = *(DWORD *)(buf + pe_offset + 24 + 0xA8);
        debug_size = *(DWORD *)(buf + pe_offset + 24 + 0xAC);
        /* Zero the directory entry */
        *(DWORD *)(buf + pe_offset + 24 + 0xA8) = 0;
        *(DWORD *)(buf + pe_offset + 24 + 0xAC) = 0;
        if (debug_rva) printf("[+] Debug directory entry zeroed\n");
    }

    /* Write back */
    fseek(f, 0, SEEK_SET);
    fwrite(buf, 1, file_size, f);
    fclose(f);
    free(buf);

    printf("[+] PE sanitized: %s\n", argv[1]);
    return 0;
}
