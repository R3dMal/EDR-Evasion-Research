@echo off
REM =====================================================
REM  Package ASF Builder — creates portable distribution
REM  Output: dist\ASF_Builder\  (ready to zip & share)
REM =====================================================

echo [*] Installing dependencies...
pip install pyinstaller customtkinter >nul 2>&1

echo [*] Building ASF_Builder.exe with PyInstaller...
pyinstaller --onefile --noconsole --name "ASF_Builder" ^
    --collect-all customtkinter ^
    gui_builder.py
if %errorlevel% neq 0 ( echo [!] PyInstaller failed & exit /b 1 )

echo [*] Creating portable distribution...
set DIST=dist\ASF_Builder_Portable
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"

REM Copy the exe
copy dist\ASF_Builder.exe "%DIST%\" >nul

REM Copy source files needed for compilation
xcopy /E /I /Q src "%DIST%\src" >nul
xcopy /E /I /Q asm "%DIST%\asm" >nul
xcopy /E /I /Q tools "%DIST%\tools" >nul
mkdir "%DIST%\build" 2>nul

REM Copy GCC portable toolchain from MSYS2
echo [*] Copying GCC toolchain (this may take a minute)...
set GCC_SRC=C:\msys64\ucrt64
set GCC_DST=%DIST%\gcc

mkdir "%GCC_DST%\bin" 2>nul
mkdir "%GCC_DST%\lib\gcc" 2>nul
mkdir "%GCC_DST%\x86_64-w64-mingw32\lib" 2>nul
mkdir "%GCC_DST%\include" 2>nul

REM Core gcc binaries
copy "%GCC_SRC%\bin\gcc.exe" "%GCC_DST%\bin\" >nul
copy "%GCC_SRC%\bin\cc1.exe" "%GCC_DST%\bin\" >nul 2>nul
copy "%GCC_SRC%\bin\as.exe" "%GCC_DST%\bin\" >nul
copy "%GCC_SRC%\bin\ld.exe" "%GCC_DST%\bin\" >nul
copy "%GCC_SRC%\bin\collect2.exe" "%GCC_DST%\bin\" >nul 2>nul

REM All DLLs gcc needs at runtime
copy "%GCC_SRC%\bin\*.dll" "%GCC_DST%\bin\" >nul 2>nul

REM GCC internal libraries and specs
xcopy /E /I /Q "%GCC_SRC%\lib\gcc" "%GCC_DST%\lib\gcc" >nul 2>nul

REM Linker support (crt objects, default libs)
xcopy /E /I /Q "%GCC_SRC%\x86_64-w64-mingw32\lib" "%GCC_DST%\x86_64-w64-mingw32\lib" >nul 2>nul

REM MinGW headers
xcopy /E /I /Q "%GCC_SRC%\x86_64-w64-mingw32\include" "%GCC_DST%\x86_64-w64-mingw32\include" >nul 2>nul

REM Include dir
xcopy /E /I /Q "%GCC_SRC%\include" "%GCC_DST%\include" >nul 2>nul

echo.
echo [+] ============================================
echo [+]  Portable package ready!
echo [+]  Location: %DIST%\
echo [+] ============================================
echo [+]
echo [+]  Contents:
echo [+]    ASF_Builder.exe  - GUI builder
echo [+]    gcc\             - Portable GCC compiler
echo [+]    src\             - Loader source code
echo [+]    asm\             - Syscall stubs
echo [+]    tools\           - bin2header, pe_sanitize
echo [+]    build\           - Output directory
echo [+]
echo [+]  To distribute: zip the ASF_Builder_Portable folder.
echo [+]  The user unzips, opens ASF_Builder.exe, done.
echo [+] ============================================

REM Show size
echo.
for /f "tokens=3" %%a in ('dir /s "%DIST%" ^| findstr "File(s)"') do echo Total size: %%a bytes
