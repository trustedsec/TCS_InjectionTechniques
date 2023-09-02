// dllLoadLibraryMon.c
#include <windows.h>
#include <stdio.h>
#include <detours.h>

// The type of the LoadLibrary function.
typedef HMODULE(WINAPI *LoadLibraryW_t)(LPCWSTR lpFileName);

// The original LoadLibrary function.
LoadLibraryW_t original_LoadLibraryW;

// Our hook function.
HMODULE WINAPI My_LoadLibraryW(LPCWSTR lpFileName)
{
    printf("LoadLibrary called with argument: %ws\n", lpFileName);

    // Call the original LoadLibrary function.
    return original_LoadLibraryW(lpFileName);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Get the address of the original LoadLibrary function.
        original_LoadLibraryW = (LoadLibraryW_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

        // Replace the original LoadLibrary function with our hook function.
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach((PVOID*)&original_LoadLibraryW, (PVOID)My_LoadLibraryW);
        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}