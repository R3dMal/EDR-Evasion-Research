#pragma once
#include <windows.h>

void XorCrypt(PBYTE data, SIZE_T data_len, PBYTE key, SIZE_T key_len);
void Rc4(PBYTE data, SIZE_T data_len, PBYTE key, SIZE_T key_len);
