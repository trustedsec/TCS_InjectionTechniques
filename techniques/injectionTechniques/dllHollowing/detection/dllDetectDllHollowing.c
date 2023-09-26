// dllHollowingMon.c
#include <windows.h>
#include <stdio.h>
#include <detours.h>

// Original function pointers
static BOOL (WINAPI *trueVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = VirtualProtect;
static BOOL (WINAPI *trueWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) = WriteProcessMemory;
static HANDLE (WINAPI *trueCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = CreateRemoteThread;
static HMODULE (WINAPI *trueLoadLibraryA)(LPCSTR lpLibFileName) = LoadLibrary;

// Hooked VirtualProtect function
BOOL WINAPI hookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    printf("VirtualProtect called with address: %p, size: %zu, new protection: %d\n", lpAddress, dwSize, flNewProtect);
    return trueVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

// Hooked WriteProcessMemory function
BOOL WINAPI hookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    printf("WriteProcessMemory called with process: %p, base address: %p, buffer: %p, size: %zu\n", hProcess, lpBaseAddress, lpBuffer, nSize);
    return trueWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

// Hooked CreateRemoteThread function
HANDLE WINAPI hookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    printf("CreateRemoteThread called with process: %p, start address: %p\n", hProcess, lpStartAddress);
    return trueCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

// Hooked LoadLibrary function
HMODULE WINAPI hookedLoadLibraryA(LPCSTR lpLibFileName)
{
    if (_stricmp(lpLibFileName, "C:\\Windows\\SYSTEM32\\amsi.dll") == 0)
    {
        printf("amsi.dll is being loaded.\n");
        // Perform any other action you want here
    }
    else
    {
        printf("LoadLibraryA called with library name: %s\n", lpLibFileName);
    }
    return trueLoadLibraryA(lpLibFileName);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    LONG error;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        // Hook the functions
        error = DetourAttach((PVOID*)trueVirtualProtect, hookedVirtualProtect);
        if (error != NO_ERROR) {
            printf("Failed to hook VirtualProtect. Error: %d\n", error);
            return FALSE;
}

        error = DetourAttach((PVOID*)trueWriteProcessMemory, hookedWriteProcessMemory);
        if (error != NO_ERROR) {
            printf("Failed to hook WriteProcessMemory. Error: %d\n", error);
            return FALSE;
}

        error = DetourAttach((PVOID*)trueCreateRemoteThread, hookedCreateRemoteThread);
        if (error != NO_ERROR) {
            printf("Failed to hook CreateRemoteThread. Error: %d\n", error);
            return FALSE;
}

        error = DetourAttach((PVOID*)trueLoadLibraryA, hookedLoadLibraryA);
        if (error != NO_ERROR) {
            printf("Failed to hook LoadLibraryA. Error: %d\n", error);
            return FALSE;
}

        error = DetourTransactionCommit();
        if (error != NO_ERROR) {
            printf("Failed to commit detour transaction. Error: %d\n", error);
            return FALSE;
}

        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach((PVOID*)&trueVirtualProtect, hookedVirtualProtect);
        DetourDetach((PVOID*)&trueWriteProcessMemory, hookedWriteProcessMemory);
        DetourDetach((PVOID*)&trueCreateRemoteThread, hookedCreateRemoteThread);
        DetourDetach((PVOID*)&trueLoadLibraryA, hookedLoadLibraryA);

        DetourTransactionCommit();
        break;
    }
    return TRUE;
}