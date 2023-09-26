// dllMemcpyMon.c
#include <windows.h>
#include <stdio.h>
#include <detours.h>
#include "dllmemcpymon.h"

// The type of the memcpy function.
typedef void* (__cdecl *memcpy_t)(void* dest, const void* src, size_t count);

// The original memcpy function.
memcpy_t original_memcpy;

// The bufPtr variable
DLLMEMCPYMON_API unsigned char* bufPtr = NULL;

// Our hook function for memcpy.
DLLMEMCPYMON_API void* __cdecl My_memcpy(void* dest, const void* src, size_t count)
{
    // Check if dest points to the buf array
    if (dest == bufPtr)
    {
        printf("memcpy called with dest pointing to buf array\n");
    }

    // MZ signature and its size
    unsigned char mzSignature[] = {0x4d, 0x5a}; // MZ in ASCII
    size_t signatureSize = sizeof(mzSignature);

    // Check if the data being copied contains the MZ signature
    for (size_t i = 0; i <= count - signatureSize; i++)
    {
        if (memcmp((char*)src + i, mzSignature, signatureSize) == 0)
        {
            printf("MZ signature detected in memcpy\n");

            // Print some basic information
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)((char*)src + i);
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((char*)dosHeader + dosHeader->e_lfanew);
            printf("Size of code: %d\n", ntHeaders->OptionalHeader.SizeOfCode);
            printf("Address of entry point: %x\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);
            break;
        }
    }

    // Call the original memcpy function.
    return original_memcpy(dest, src, count);
}

// Function to set bufPtr
DLLMEMCPYMON_API void setBufPtr(unsigned char* ptr)
{
    bufPtr = ptr;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Get the address of the original memcpy function.
        original_memcpy = (memcpy_t)GetProcAddress(GetModuleHandle("msvcrt.dll"), "memcpy");

        // Replace the original memcpy function with our hook function.
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach((PVOID*)&original_memcpy, (PVOID)My_memcpy);
        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}