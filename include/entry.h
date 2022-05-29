
#include <windows.h>
#include <winternl.h>

PVOID get_ip(VOID);

BOOL free_udrl(VOID);

BOOL is_valid_pe(
    PVOID base_address,
    SIZE_T region_size);

BOOL free_region(
    PVOID base_address,
    SIZE_T region_size,
    BOOL is_mapped);

WINBASEAPI int __cdecl MSVCRT$memcmp(const void *_Buf1,const void *_Buf2,size_t _Size);
#define memcmp MSVCRT$memcmp

#define RVA(type, base_addr, rva) (type)((ULONG_PTR) base_addr + rva)

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

#define MZ 0x5A4D

#ifndef NT_SUCCESS
 #define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifdef _WIN64
 #define PEB_OFFSET 0x60
 #define READ_MEMLOC __readgsqword
#else
 #define PEB_OFFSET 0x30
 #define READ_MEMLOC __readfsdword
#endif

#define MEM_COMMIT 0x1000
//#define MEM_IMAGE 0x1000000
#define MEM_MAPPED 0x40000
#define PAGE_NOACCESS 0x01
#define PAGE_GUARD 0x100

#if defined(BOF)
 #define PRINT(...) { \
     BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
 }
#else
 #define PRINT(...) { \
     fprintf(stdout, __VA_ARGS__); \
     fprintf(stdout, "\n"); \
 }
#endif

#if defined(BOF)
 #define PRINT_ERR(...) { \
     BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__); \
 }
#else
 #define PRINT_ERR(...) { \
     fprintf(stdout, __VA_ARGS__); \
     fprintf(stdout, "\n"); \
 }
#endif

#if defined(DEBUG) && defined(BOF)
 #define DPRINT(...) { \
     BeaconPrintf(CALLBACK_OUTPUT, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); \
 }
#elif defined(DEBUG) && !defined(BOF)
 #define DPRINT(...) { \
     fprintf(stderr, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
     fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT(...)
#endif

#if defined(DEBUG) && defined(BOF)
 #define DPRINT_ERR(...) { \
     BeaconPrintf(CALLBACK_ERROR, "ERROR: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__); \
 }
#elif defined(DEBUG) && !defined(BOF)
 #define DPRINT_ERR(...) { \
     fprintf(stderr, "ERROR: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
     fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT_ERR(...)
#endif

#ifdef _M_IX86
 // x86 has conflicting types with these functions
 #define NtClose _NtClose
#endif
