#pragma once
#include <windows.h>
#include "config.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

/* djb2 API hash constants */
#define H_NTALLOCATEVIRTUALMEMORY       0x6793c34c
#define H_NTPROTECTVIRTUALMEMORY        0x082962c8
#define H_NTWRITEVIRTUALMEMORY          0x95f3a792
#define H_NTCREATETHREADEX              0xcb0c2130
#define H_NTWAITFORSINGLEOBJECT         0x4c6dc63c
#define H_NTFREEVIRTUALMEMORY           0x471aa7e9
#define H_NTCLOSE                       0x8b8e133d
#define H_NTOPENPROCESS                 0x5003c058
#define H_NTCREATESECTION               0x7b8960ac
#define H_NTMAPVIEWOFSECTION            0x354c8b9e
#define H_NTUNMAPVIEWOFSECTION          0x1cf24dba
#define H_LOADLIBRARYA                  0x5fbff0fb
#define H_GETPROCADDRESS                0xcf31bb1f
#define H_VIRTUALALLOC                  0x382c0f97
#define H_VIRTUALPROTECT                0x844ff18d
#define H_VIRTUALFREE                   0x668fcf2e
#define H_FLUSHINSTRUCTIONCACHE         0xb7dceddd

/* NT structures */
typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _PEB_LDR_DATA2 {
    ULONG      Length;
    BOOL       Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA2, *PPEB_LDR_DATA2;

typedef struct _LDR_DATA_TABLE_ENTRY2 {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG       Flags;
    USHORT      LoadCount;
    USHORT      TlsIndex;
    LIST_ENTRY  HashLinks;
    PVOID       SectionPointer;
    ULONG       CheckSum;
    ULONG       TimeDateStamp;
} LDR_DATA_TABLE_ENTRY2, *PLDR_DATA_TABLE_ENTRY2;

typedef struct _PEB2 {
    BYTE             InheritedAddressSpace;
    BYTE             ReadImageFileExecOptions;
    BYTE             BeingDebugged;
    BYTE             BitField;
    BYTE             Padding0[4];
    PVOID            Mutant;
    PVOID            ImageBaseAddress;
    PPEB_LDR_DATA2   Ldr;
} PEB2, *PPEB2;

typedef struct _SYSCALL_ENTRY {
    DWORD  dwSSN;
    PVOID  pSyscallAddr;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

/* NT function signatures */
typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fnNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *fnNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *fnNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *fnNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *fnNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *fnNtOpenProcess)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
typedef NTSTATUS (NTAPI *fnNtCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *fnNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnNtUnmapViewOfSection)(HANDLE, PVOID);

/* Win32 function signatures */
typedef HMODULE (WINAPI *fnLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fnGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *fnVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL    (WINAPI *fnFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef BOOL    (WINAPI *fnDllMain)(HINSTANCE, DWORD, LPVOID);
