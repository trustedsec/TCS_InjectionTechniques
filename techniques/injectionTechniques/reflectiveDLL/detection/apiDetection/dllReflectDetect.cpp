#include <Windows.h>
#include <detours.h>
#include <iostream>

typedef LPVOID(WINAPI* FuncVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
FuncVirtualAlloc pVirtualAlloc = VirtualAlloc;

typedef BOOL(WINAPI* FuncReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
FuncReadProcessMemory pReadProcessMemory = ReadProcessMemory;

typedef HMODULE(WINAPI* FuncLoadLibraryA)(LPCSTR);
FuncLoadLibraryA pLoadLibraryA = LoadLibraryA;

typedef HANDLE(WINAPI* FuncOpenProcess)(DWORD, BOOL, DWORD);
FuncOpenProcess pOpenProcess = OpenProcess;

typedef FARPROC(WINAPI* FuncGetProcAddress)(HMODULE, LPCSTR);
FuncGetProcAddress pGetProcAddress = GetProcAddress;

typedef HANDLE(WINAPI* FuncCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
FuncCreateRemoteThread pCreateRemoteThread = CreateRemoteThread;

// memcpy
//typedef void* (WINAPI* FuncMemcpy)(void*, const void*, size_t);
//FuncMemcpy pMemcpy = memcpy;

// CreateProcessA
typedef BOOL(WINAPI* FuncCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
FuncCreateProcessA pCreateProcessA = CreateProcessA;

// VirtualProtect
typedef BOOL(WINAPI* FuncVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
FuncVirtualProtect pVirtualProtect = VirtualProtect;

// VirtualAllocEx
typedef LPVOID(WINAPI* FuncVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
FuncVirtualAllocEx pVirtualAllocEx = VirtualAllocEx;

// WriteProcessMemory
typedef BOOL(WINAPI* FuncWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
FuncWriteProcessMemory pWriteProcessMemory = WriteProcessMemory;




LPVOID WINAPI HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    std::cout << "Intercepted VirtualAlloc called!" << std::endl;
    std::cout << "Size: " << dwSize << std::endl;
    LPVOID result = pVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    return result;
}

BOOL WINAPI HookedReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    std::cout << "Intercepted ReadProcessMemory called!" << std::endl;
    BOOL result = pReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    return result;
}

HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName)
{
    std::cout << "Intercepted LoadLibraryA called!" << std::endl;
    std::cout << "Library: " << lpLibFileName << std::endl;
    HMODULE result = pLoadLibraryA(lpLibFileName);
    return result;
}

HANDLE WINAPI HookedOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    std::cout << "Intercepted OpenProcess called!" << std::endl;
    HANDLE result = pOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    return result;
}

LPVOID WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    std::cout << "Intercepted GetProcAddress called!" << std::endl;
    LPVOID result = pGetProcAddress(hModule, lpProcName);
    return result;
}

HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    std::cout << "Intercepted CreateRemoteThread called!" << std::endl;
    HANDLE result = pCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    return result;
}

//void HookedMemcpy(void* dest, const void* src, size_t count)
//{
//    std::cout << "Intercepted memcpy called!" << std::endl;
//    pMemcpy(dest, src, count);
//}

BOOL WINAPI HookedCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    std::cout << "Intercepted CreateProcessA called!" << std::endl;
    BOOL result = pCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    return result;
}

BOOL WINAPI HookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    std::cout << "Intercepted VirtualProtect called!" << std::endl;
    BOOL result = pVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    return result;
}

LPVOID WINAPI HookedVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    std::cout << "Intercepted VirtualAllocEx called!" << std::endl;
    LPVOID result = pVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    return result;
}

BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    std::cout << "Intercepted WriteProcessMemory called!" << std::endl;
    BOOL result = pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    return result;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach(&(PVOID&)pVirtualAlloc, HookedVirtualAlloc);
        DetourAttach(&(PVOID&)pReadProcessMemory, HookedReadProcessMemory);
        DetourAttach(&(PVOID&)pLoadLibraryA, HookedLoadLibraryA);
        DetourAttach(&(PVOID&)pOpenProcess, HookedOpenProcess);
       // DetourAttach(&(PVOID&)pGetProcAddress, HookedGetProcAddress);
        DetourAttach(&(PVOID&)pCreateRemoteThread, HookedCreateRemoteThread);
       // DetourAttach(&(PVOID&)pMemcpy, HookedMemcpy);
        DetourAttach(&(PVOID&)pCreateProcessA, HookedCreateProcessA);
        DetourAttach(&(PVOID&)pVirtualProtect, HookedVirtualProtect);
        DetourAttach(&(PVOID&)pVirtualAllocEx, HookedVirtualAllocEx);
        DetourAttach(&(PVOID&)pWriteProcessMemory, HookedWriteProcessMemory);

        DetourTransactionCommit();
        break;
    }
    case DLL_PROCESS_DETACH:
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach(&(PVOID&)pVirtualAlloc, HookedVirtualAlloc);
        DetourDetach(&(PVOID&)pReadProcessMemory, HookedReadProcessMemory);
        DetourDetach(&(PVOID&)pLoadLibraryA, HookedLoadLibraryA);
        DetourDetach(&(PVOID&)pOpenProcess, HookedOpenProcess);
       // DetourDetach(&(PVOID&)pGetProcAddress, HookedGetProcAddress);
        DetourDetach(&(PVOID&)pCreateRemoteThread, HookedCreateRemoteThread);
       // DetourDetach(&(PVOID&)pMemcpy, HookedMemcpy);
        DetourDetach(&(PVOID&)pCreateProcessA, HookedCreateProcessA);
        DetourDetach(&(PVOID&)pVirtualProtect, HookedVirtualProtect);
        DetourDetach(&(PVOID&)pVirtualAllocEx, HookedVirtualAllocEx);
        DetourDetach(&(PVOID&)pWriteProcessMemory, HookedWriteProcessMemory);

        DetourTransactionCommit();
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}