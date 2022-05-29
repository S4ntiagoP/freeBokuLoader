#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef SW2_HEADER_H_
#define SW2_HEADER_H_

#include <windows.h>

#define SW2_SEED 0x1337C0DE
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

typedef struct _SW2_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
    PVOID SyscallAddress;
} SW2_SYSCALL_ENTRY, *PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
    DWORD Count;
    SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, *PSW2_SYSCALL_LIST;

typedef struct _SW2_PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} SW2_PEB_LDR_DATA, *PSW2_PEB_LDR_DATA;

typedef struct _SW2_LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
} SW2_LDR_DATA_TABLE_ENTRY, *PSW2_LDR_DATA_TABLE_ENTRY;

typedef struct _SW2_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PSW2_PEB_LDR_DATA Ldr;
} SW2_PEB, *PSW2_PEB;

DWORD SW2_HashSyscall(
    IN PCSTR FunctionName);

PVOID GetSyscallAddress(
    IN PVOID nt_api_address,
    IN ULONG32 size_of_ntapi);

BOOL SW2_PopulateSyscallList(VOID);

BOOL local_is_wow64(VOID);

PVOID getIP(VOID);

void SyscallNotFound(VOID);

#if defined(__GNUC__)
DWORD SW2_GetSyscallNumber(IN DWORD FunctionHash) asm ("SW2_GetSyscallNumber");
PVOID SW3_GetSyscallAddress(IN DWORD FunctionHash) asm ("SW3_GetSyscallAddress");
#else
DWORD SW2_GetSyscallNumber(IN DWORD FunctionHash);
PVOID SW3_GetSyscallAddress(IN DWORD FunctionHash);
#endif

//typedef struct _IO_STATUS_BLOCK
//{
//  union
//  {
//      NTSTATUS Status;
//      VOID*    Pointer;
//  };
//  ULONG_PTR Information;
//} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

//typedef struct _UNICODE_STRING
//{
//  USHORT Length;
//  USHORT MaximumLength;
//  PWSTR  Buffer;
//} UNICODE_STRING, *PUNICODE_STRING;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

//typedef struct _OBJECT_ATTRIBUTES
//{
//  ULONG           Length;
//  HANDLE          RootDirectory;
//  PUNICODE_STRING ObjectName;
//  ULONG           Attributes;
//  PVOID           SecurityDescriptor;
//  PVOID           SecurityQualityOfService;
//} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    MemorySharedCommitInformation,
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

//typedef struct _CLIENT_ID
//{
//  HANDLE UniqueProcess;
//  HANDLE UniqueThread;
//} CLIENT_ID, *PCLIENT_ID;

//typedef enum _PROCESSINFOCLASS
//{
//  ProcessBasicInformation = 0,
//  ProcessDebugPort = 7,
//  ProcessWow64Information = 26,
//  ProcessImageFileName = 27,
//  ProcessBreakOnTermination = 29
//} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
    IN PVOID            ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG            Reserved);

NTSTATUS NtQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL);

NTSTATUS NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType);

NTSTATUS NtUnmapViewOfSection(
  HANDLE ProcessHandle,
  PVOID  BaseAddress);

#endif
