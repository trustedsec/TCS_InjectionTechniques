// dllLoadLibraryMon.c
#include <windows.h>
#include <stdio.h>
#include <detours.h>

// The type of the LoadLibraryA function.
typedef HMODULE(WINAPI *LoadLibraryA_t)(LPCSTR lpFileName);

// The original LoadLibraryA function.
LoadLibraryA_t original_LoadLibraryA;

// Our hook function for LoadLibraryA.
HMODULE WINAPI My_LoadLibraryA(LPCSTR lpFileName)
{
    printf("LoadLibraryA called with argument: %s\n", lpFileName);

    // Call the original LoadLibraryA function.
    return original_LoadLibraryA(lpFileName);
}

// The type of the LoadLibraryW function.
typedef HMODULE(WINAPI *LoadLibraryW_t)(LPCWSTR lpFileName);

// The original LoadLibraryW function.
LoadLibraryW_t original_LoadLibraryW;

// Our hook function for LoadLibraryW.
HMODULE WINAPI My_LoadLibraryW(LPCWSTR lpFileName)
{
    wprintf(L"LoadLibraryW called with argument: %s\n", lpFileName);

    // Call the original LoadLibraryW function.
    return original_LoadLibraryW(lpFileName);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Get the address of the original LoadLibraryW function.
        original_LoadLibraryW = (LoadLibraryW_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

        // Replace the original LoadLibraryW function with our hook function.
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach((PVOID*)&original_LoadLibraryW, (PVOID)My_LoadLibraryW);
        DetourTransactionCommit();

        // Get the address of the original LoadLibraryA function.
        original_LoadLibraryA = (LoadLibraryA_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

        // Replace the original LoadLibraryA function with our hook function.
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach((PVOID*)&original_LoadLibraryA, (PVOID)My_LoadLibraryA);
        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}