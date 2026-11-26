/*
 * Hash Generator Utility
 *
 * Computes djb2 hashes for API function names. Use this to generate
 * hash constants for new functions you want to resolve.
 *
 * Build:  cl hash_gen.c /Fe:hash_gen.exe
 * Usage:  hash_gen.exe NtAllocateVirtualMemory LoadLibraryA kernel32.dll
 */

#include <stdio.h>
#include <string.h>

typedef unsigned int DWORD;

DWORD djb2_hash(const char *str) {
    DWORD hash = 5381;
    while (*str)
        hash = ((hash << 5) + hash) + (unsigned char)*str++;
    return hash;
}

DWORD djb2_hash_lower(const char *str) {
    DWORD hash = 5381;
    while (*str) {
        unsigned char c = *str++;
        if (c >= 'A' && c <= 'Z') c += 32;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <name1> [name2] [name3] ...\n", argv[0]);
        printf("  Computes djb2 hashes for #define constants.\n");
        printf("  Add --lower for case-insensitive (module names).\n");
        return 1;
    }

    int use_lower = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lower") == 0) {
            use_lower = 1;
            continue;
        }

        DWORD h = use_lower ? djb2_hash_lower(argv[i]) : djb2_hash(argv[i]);

        char upper[256];
        int j;
        for (j = 0; argv[i][j] && j < 255; j++) {
            char c = argv[i][j];
            if (c >= 'a' && c <= 'z') c -= 32;
            if (c == '.') c = '_';
            upper[j] = c;
        }
        upper[j] = '\0';

        printf("#define H_%-40s 0x%08x\n", upper, h);
    }

    return 0;
}
