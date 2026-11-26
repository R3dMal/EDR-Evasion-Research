#include "crypto.h"

void XorCrypt(PBYTE data, SIZE_T data_len, PBYTE key, SIZE_T key_len) {
    for (SIZE_T i = 0; i < data_len; i++)
        data[i] ^= key[i % key_len];
}

void Rc4(PBYTE data, SIZE_T data_len, PBYTE key, SIZE_T key_len) {
    BYTE state[256];
    for (int i = 0; i < 256; i++) state[i] = (BYTE)i;
    BYTE j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + state[i] + key[i % key_len];
        BYTE tmp = state[i]; state[i] = state[j]; state[j] = tmp;
    }
    BYTE si = 0; j = 0;
    for (SIZE_T k = 0; k < data_len; k++) {
        si++;
        j += state[si];
        BYTE tmp = state[si]; state[si] = state[j]; state[j] = tmp;
        data[k] ^= state[(BYTE)(state[si] + state[j])];
    }
}
