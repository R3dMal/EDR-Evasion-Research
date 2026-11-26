# EDR Evasion Research Framework

> **For authorized security research, red team engagements, and educational purposes only.**

## Disclaimer

This project is a **security research framework** developed to study and document Endpoint Detection and Response (EDR) evasion techniques on Windows x64 systems. It is intended exclusively for:

- Authorized penetration testing engagements with written scope agreements
- Red team / adversary simulation exercises within corporate security programs
- Academic research on endpoint security and detection engineering
- Development and validation of EDR detection rules and countermeasures

**Unauthorized use of this software against systems you do not own or have explicit written permission to test is illegal and unethical.** The author assumes no liability for misuse. Users are solely responsible for ensuring compliance with all applicable laws and regulations.

---

## Overview

This framework implements a complete adversary simulation chain for Windows x64, covering the full lifecycle from payload delivery to in-memory execution with defense evasion. Every module is designed to be toggled independently via compile-time configuration, allowing researchers to study each technique in isolation or in combination.

### Kill Chain

```
Environment Check → Telemetry Patching → NTDLL Unhooking → Syscall Resolution
     → Payload Decryption → Injection (self / remote / module stomp)
          → Sleep Obfuscation Loop → Stack Spoofing
```

---

## Architecture

```
src/
├── core/                 # Foundation layer
│   ├── common.h          # NT structures, syscall types, hash constants
│   ├── config.h          # Compile-time feature toggles
│   ├── winapi.c/h        # Dynamic Win32 API resolution (clean IAT)
│   ├── api_hash.c/h      # PEB-walking function resolution by djb2 hash
│   ├── obfstr.h          # Runtime string deobfuscation (XOR 0x55)
│   ├── crypto.c/h        # XOR and RC4 payload encryption/decryption
│   └── hellsgate.c/h     # Hell's Gate / Halo's Gate syscall resolution
│
├── evasion/              # Defense evasion modules
│   ├── ntdll_unhook.c/h  # Restore hooked ntdll .text from clean copy
│   ├── telemetry.c/h     # ETW and AMSI patching
│   ├── env_keying.c/h    # Anti-sandbox, anti-debug, environmental keying
│   ├── sleep_obf.c/h     # Ekko-style encrypted sleep obfuscation
│   └── stackspoof.c/h    # Thread call stack spoofing
│
├── injection/            # Code execution modules
│   ├── inject_remote.c/h # Remote process injection via indirect syscalls
│   ├── module_stomp.c/h  # DLL hollowing (module stomping)
│   └── ppid_spoof.c/h    # Parent PID spoofing for process creation
│
├── tools/                # Build utilities
│   ├── bin2header.c      # Convert binary payload → C header array
│   ├── encrypt_payload.c # Encrypt raw payload (XOR / RC4)
│   ├── hash_gen.c        # Compute djb2 hashes for API names
│   └── pe_sanitize.c     # Strip PE metadata (timestamps, Rich header, debug)
│
├── standalone.c          # Main entry point (self-contained dropper)
├── stub.c                # Position-independent stub for PE backdooring
└── payload.h             # (generated) Encrypted payload as C byte array

asm/
└── syscalls.x64.s        # Indirect syscall stub (GAS/Intel syntax)

scripts/
├── gui_builder.py        # GUI for config generation and compilation
├── pe_backdoor.py        # Inject payload into legitimate PE64 binaries
├── html_smuggle.py       # HTML smuggling payload delivery page
└── ASF_Builder.spec       # PyInstaller spec for portable GUI build
```

---

## Module Documentation

### Core Layer

#### Dynamic API Resolution (`winapi.c/h`)

Resolves all Win32 API functions at runtime through a global `g_Api` struct. The two bootstrap functions (`GetModuleHandleA`, `GetProcAddress`) are resolved via PEB walking and djb2 hash matching — no static imports required. All subsequent APIs are resolved using obfuscated function name strings (XOR 0x55), decrypted on the stack and zeroed after use.

**Result:** The compiled binary's Import Address Table (IAT) contains zero suspicious entries. Static analysis tools and YARA rules targeting `VirtualAlloc`, `CreateRemoteThread`, etc. in the IAT will not flag this binary.

#### Hell's Gate / Halo's Gate (`hellsgate.c/h`)

Extracts System Service Numbers (SSNs) from ntdll export function prologues by pattern matching the `mov r10, rcx; mov eax, <SSN>` sequence. If a function is hooked by an EDR (inline JMP patch), the prologue won't match — **Halo's Gate** searches neighboring Nt* functions by ordinal offset to find an unhooked one and calculates the target SSN arithmetically.

**Indirect Syscalls:** Instead of executing the `syscall` instruction from our own code (detectable via call-stack origin analysis), the stub in `asm/syscalls.x64.s` jumps to the legitimate `syscall; ret` gadget inside ntdll. The return address on the stack points to ntdll, not our module.

**Supported syscalls:** `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtWaitForSingleObject`, `NtFreeVirtualMemory`, `NtClose`, `NtOpenProcess`, `NtCreateSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection`.

#### API Hashing (`api_hash.c/h`)

Resolves exported functions by walking the Process Environment Block (PEB) `InLoadOrderModuleList`, parsing each module's export table, and matching function names by djb2 hash. Includes `GetFuncByHash()` which searches across all loaded modules — used by `WinApiInit()` to bootstrap without any import.

#### String Obfuscation (`obfstr.h`)

All sensitive strings (DLL names, API names) are stored as XOR-encrypted `unsigned char` arrays with key `0x55`. Decrypted on the stack at call sites, then zeroed with `SecureZeroMemory()`. Defeats `strings`, static YARA rules, and basic disassembly string cross-referencing.

#### Payload Cryptography (`crypto.c/h`)

- **XOR:** Cyclic multi-byte XOR. Simple, reversible, sufficient to defeat static signature matching.
- **RC4:** Standard RC4 stream cipher. Provides stronger encryption for payload-at-rest.

Both operate in-place on the buffer.

---

### Evasion Layer

#### NTDLL Unhooking (`ntdll_unhook.c/h`)

EDRs hook ntdll by patching inline JMP instructions at the start of Nt* functions. This module restores the original code using two methods:

1. **KnownDlls** (primary): Opens `\KnownDlls\ntdll.dll` section object via `NtOpenSection` + `NtMapViewOfSection` — no file I/O, harder to monitor.
2. **Disk read** (fallback): Reads `ntdll.dll` from `%SystemRoot%\System32\` via `CreateFileW` + `CreateFileMappingW`, maps it, and overwrites the in-memory `.text` section.

Path is resolved dynamically via `GetSystemDirectoryW` — no hardcoded drive letters.

#### Telemetry Patching (`telemetry.c/h`)

- **ETW:** Patches `EtwEventWrite` and `EtwEventWriteFull` in ntdll with `xor eax, eax; ret` — all ETW events from the process are silently dropped.
- **AMSI:** Patches `AmsiScanBuffer` in `amsi.dll` to return `E_INVALIDARG` — in-memory script scanning is bypassed.

Both patches are applied via dynamically resolved API pointers.

#### Environmental Keying (`env_keying.c/h`)

Three-layer environment validation:

| Check | Technique | Purpose |
|-------|-----------|---------|
| **Anti-sandbox** | CPU count, RAM size, uptime, analysis tool process enumeration, CPUID hypervisor flag | Detect automated analysis environments |
| **Anti-debug** | `PEB.BeingDebugged`, `NtQueryInformationProcess(DebugPort)`, RDTSC timing delta | Detect active debugging sessions |
| **Environmental keying** | Hostname, username, domain matching against compile-time targets | Execute only on intended target systems |

All Win32 API calls are routed through `g_Api` dynamic resolution.

#### Sleep Obfuscation (`sleep_obf.c/h`)

Implements the **Ekko** technique:

1. Changes memory pages to `PAGE_NOACCESS` via indirect syscall
2. Encrypts all executable pages with RC4 (`SystemFunction032` from advapi32)
3. Sleeps via `WaitForSingleObjectEx` on a signaled event (timer-based)
4. Decrypts pages and restores `PAGE_EXECUTE_READ`

**Purpose:** While the implant sleeps, its code pages are encrypted and non-executable — memory scanners cannot signature-match or dump the payload.

#### Stack Spoofing (`stackspoof.c/h`)

Walks the current thread's call stack using `RtlCaptureContext` / `RtlVirtualUnwind`, identifies frames with return addresses outside ntdll/kernel32 (i.e., our code), and replaces them with `ret` gadgets from legitimate modules. The original addresses are saved and restored after the sensitive operation.

**Purpose:** EDRs inspect call stacks on API calls and syscalls. Anomalous return addresses (pointing to unbacked/private memory) trigger alerts. Stack spoofing makes the call stack appear as if the call originated from legitimate OS code.

---

### Injection Layer

#### Self-Injection (`standalone.c`)

The default mode: decrypts the embedded payload and injects it into the current process using indirect syscalls (`NtAllocateVirtualMemory` → `NtWriteVirtualMemory` → `NtProtectVirtualMemory` → `NtCreateThreadEx`). No file I/O at runtime — the encrypted payload is compiled into the binary via `payload.h`.

#### Remote Process Injection (`inject_remote.c/h`)

Finds a target process by name (e.g., `explorer.exe`), opens a handle via `NtOpenProcess`, and performs classic remote injection — all via indirect syscalls. The process enumeration uses dynamically resolved `CreateToolhelp32Snapshot` / `Process32FirstW` / `Process32NextW`.

#### Module Stomping (`module_stomp.c/h`)

Loads a sacrificial DLL (selectable: `xpsprint.dll`, `dbghelp.dll`, `winscard.dll`, `mstscax.dll`) and overwrites its `.text` section with the shellcode. The memory region remains file-backed by the legitimate DLL — memory scanners see a valid module, not a suspicious private allocation.

#### PPID Spoofing (`ppid_spoof.c/h`)

Creates a new process with a spoofed parent using `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. The child process appears as a legitimate descendant of a system process (e.g., `svchost.exe`, `explorer.exe`) rather than the actual parent.

---

### Build Pipeline

#### Payload Preparation

```
raw_payload.bin → encrypt_payload.exe (XOR/RC4) → payload_enc.bin
                → bin2header.exe → src/payload.h (embedded C array)
```

#### Compilation (MinGW x86_64)

```bash
# Automated build
build_ultimate.bat

# Manual
x86_64-w64-mingw32-gcc -c asm/syscalls.x64.s -o build/syscalls.o
x86_64-w64-mingw32-gcc -O2 -s -mwindows -fno-ident \
    -fno-asynchronous-unwind-tables \
    src/standalone.c src/core/*.c src/evasion/*.c src/injection/*.c \
    build/syscalls.o -o build/implant.exe -lntdll
```

#### PE Sanitization (`pe_sanitize.c`)

Strips identifying metadata from the compiled binary:
- PE timestamp → zeroed
- Rich header → removed
- Debug directory → removed
- Linker version → zeroed

#### GUI Builder (`scripts/gui_builder.py`)

Point-and-click interface (CustomTkinter) for:
- Generating `config.h` with selected feature toggles
- Encrypting payloads (XOR/RC4)
- Compiling the final binary
- Running PE sanitization

---

### Delivery Tools

#### PE Backdooring (`scripts/pe_backdoor.py`)

Injects an encrypted payload into a legitimate PE64 binary by:
1. Adding a new `.text0` section containing a position-independent ASM stub
2. The stub at runtime: patches ETW/AMSI, decrypts the payload, executes it as a new thread, then jumps to the original entry point
3. The host application runs normally — the payload executes silently in the background

#### HTML Smuggling (`scripts/html_smuggle.py`)

Generates an HTML page that reconstructs the executable from base64 JavaScript, creates an in-memory ZIP archive, and triggers a browser download. The page mimics a legitimate document-sharing interface. Payload data is chunked to evade pattern matching on the base64 blob.

---

## Configuration

All features are toggled in `src/core/config.h`:

```c
#define ENABLE_UNHOOK            1    // NTDLL unhooking
#define ENABLE_ETW_PATCH         1    // ETW event silencing
#define ENABLE_AMSI_PATCH        1    // AMSI bypass
#define ENABLE_ANTI_SANDBOX      1    // Sandbox detection
#define ENABLE_ANTI_DEBUG        1    // Debugger detection
#define ENABLE_ENV_KEYING        0    // Target-specific execution
#define ENABLE_SLEEP_OBF         1    // Encrypted sleep
#define ENABLE_STACK_SPOOF       1    // Call stack spoofing
#define ENABLE_DECOY             1    // Open decoy application
#define ENABLE_DELAY_EXEC        1    // Initial execution delay
#define INJECT_SELF              1    // Self-injection mode
#define INJECT_REMOTE            0    // Remote process injection
#define INJECT_STOMP             0    // Module stomping
#define PAYLOAD_USE_RC4          0    // RC4 (1) or XOR (0) decryption
```

---

## Detection Opportunities

This section is intended for **blue team** and **detection engineering** use — understanding what this framework does enables writing better detection rules.

| Technique | Detection Vector |
|-----------|-----------------|
| Indirect syscalls | Syscall origin not matching ntdll `.text` range (requires kernel telemetry) |
| NTDLL unhooking | `NtMapViewOfSection` on `\KnownDlls\ntdll.dll`; `.text` section hash mismatch |
| ETW patching | Periodic integrity check of `EtwEventWrite` prologue bytes |
| AMSI patching | `AmsiScanBuffer` prologue integrity monitoring |
| Sleep obfuscation | PAGE_NOACCESS on previously executable regions; `SystemFunction032` calls |
| Stack spoofing | Frame pointer chain validation; `ret` gadget prevalence in return addresses |
| Module stomping | `.text` section hash mismatch in loaded DLLs; memory vs disk comparison |
| PPID spoofing | Process creation with `EXTENDED_STARTUPINFO_PRESENT` where parent ≠ actual parent |
| API hashing | Absence of common Win32 imports in IAT combined with `__readgsqword(0x60)` patterns |

---

## Requirements

- **Build:** MinGW-w64 (x86_64-w64-mingw32-gcc) or MSVC x64 with MASM
- **Target:** Windows 10/11 x64
- **Python tools:** Python 3.8+, CustomTkinter (for GUI builder only)

---

## Legal Notice

This software is provided "as is" without warranty of any kind. It is designed for authorized security testing and research. The techniques documented here are well-known in the security community and are published for defensive research purposes — to help security teams understand, detect, and mitigate these attack vectors.

**Do not use this software without explicit written authorization from the system owner.**

---

## References

- [Hell's Gate](https://github.com/am0nsec/HellsGate) — am0nsec, smelly__vx
- [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md) — Sektor7
- [Ekko Sleep Obfuscation](https://github.com/Cracked5pider/Ekko) — C5pider
- [Module Stomping](https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing) — Forrest Orr
- [Stack Spoofing](https://github.com/mgeeky/ThreadStackSpoofer) — mgeeky
- [PE Backdooring](https://www.ired.team/offensive-security/code-injection-process-injection/backdooring-portable-executables-pe-with-shellcode) — ired.team

## License

For authorized security research only. No warranty. See [Disclaimer](#disclaimer).
