#include <Windows.h>
#include <detours.h>
#include <iostream>

typedef LPVOID(WINAPI* FuncVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
FuncVirtualAlloc pVirtualAlloc = VirtualAlloc;

typedef BOOL(WINAPI* FuncReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
FuncReadProcessMemory pReadProcessMemory = ReadProcessMemory;

typedef HMODULE(WINAPI* FuncLoadLibraryA)(LPCSTR);
FuncLoadLibraryA pLoadLibraryA = LoadLibraryA;

typedef FARPROC(WINAPI* FuncGetProcAddress)(HMODULE, LPCSTR);
FuncGetProcAddress pGetProcAddress = GetProcAddress;

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

FARPROC WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    std::cout << "Intercepted GetProcAddress called!" << std::endl;
    std::cout << "Function: " << lpProcName << std::endl;
    FARPROC result = pGetProcAddress(hModule, lpProcName);
    return result;
}

int main()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)pVirtualAlloc, HookedVirtualAlloc);
    DetourAttach(&(PVOID&)pReadProcessMemory, HookedReadProcessMemory);
    DetourAttach(&(PVOID&)pLoadLibraryA, HookedLoadLibraryA);
    DetourAttach(&(PVOID&)pGetProcAddress, HookedGetProcAddress);

    DetourTransactionCommit();

    // Run the reflect_dll.exe here
    system("C:\\Users\\loki\\Desktop\\reflect_dll.exe");
    

    getchar();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)pVirtualAlloc, HookedVirtualAlloc);
    DetourDetach(&(PVOID&)pReadProcessMemory, HookedReadProcessMemory);
    DetourDetach(&(PVOID&)pLoadLibraryA, HookedLoadLibraryA);
    DetourDetach(&(PVOID&)pGetProcAddress, HookedGetProcAddress);

    DetourTransactionCommit();

    return 0;
}