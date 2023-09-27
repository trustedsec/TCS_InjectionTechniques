// Code taken modified and taken from https://blog.securehat.co.uk/process-injection/detecting-process-injection-using-microsoft-detour-hooks

#include <windows.h>
#include "detours.h"

BOOL loadLibraryCalled = FALSE; // detected
BOOL virtualAllocCalled = FALSE; // detected
BOOL getProcAddressCalled = FALSE; // detected
//BOOL createRemoteThreadCalled = FALSE; // not detected
//BOOL memcpyCalled = FALSE; // not detected
//BOOL readProcessMemoryCalled = FALSE; // not detected
BOOL createProcessCalled = FALSE; // detected
//BOOL virtualProtectCalled = FALSE; // detected
//BOOL virtualAllocExCalled = FALSE; // detected
//BOOL writeProcessMemoryCalled = FALSE; // detected


// Hooked API calls related to standard process injection
HMODULE(WINAPI* oLoadLibrary)(LPCSTR) = LoadLibraryA;
LPVOID(WINAPI* oVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD) = VirtualAlloc;
FARPROC(WINAPI* oGetProcAddress)(HMODULE, LPCSTR) = GetProcAddress;
//void* (WINAPI* omemcpy)(void*, const void*, size_t) = memcpy;
//HANDLE(WINAPI* oCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateRemoteThread;
//BOOL(WINAPI* oReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = ReadProcessMemory;
BOOL(WINAPI* oCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;
//BOOL(WINAPI* oVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) = VirtualProtect;
//LPVOID(WINAPI* oVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = VirtualAllocEx;
//BOOL(WINAPI* oWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = WriteProcessMemory;


// Our hook function for LoadLibrary
HMODULE WINAPI hookedLoadLibrary(LPCSTR lpLibFileName)
{
    loadLibraryCalled = TRUE;
//    if (loadLibraryCalled && virtualAllocCalled && getProcAddressCalled) {
//        MessageBoxW(HWND_DESKTOP, L"Reflective injection detected. Killing Process.", L"Ghetto EDR", MB_OK);
//        DWORD killPid = GetCurrentProcessId();
//        HANDLE hKillProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, killPid);
//        TerminateProcess(hKillProcess, 0);
//    }
    return oLoadLibrary(lpLibFileName);
}

// Our hook function for VirtualAlloc
LPVOID WINAPI hookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    virtualAllocCalled = TRUE;
//    if (virtualAllocCalled && loadLibraryCalled) {
//        MessageBoxW(HWND_DESKTOP, L"Reflective injection detected. Killing Process.", L"Ghetto EDR", MB_OK);
//        DWORD killPid = GetCurrentProcessId();
//        HANDLE hKillProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, killPid);
//        TerminateProcess(hKillProcess, 0);
//    }
    return oVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

// Our hook function for GetProcAddress
FARPROC WINAPI hookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    getProcAddressCalled = TRUE;
//    if (getProcAddressCalled) {
//        MessageBoxW(HWND_DESKTOP, L"Reflective injection detected(GetProcAddress). Killing Process.", L"Ghetto EDR", MB_OK);
//        DWORD killPid = GetCurrentProcessId();
//        HANDLE hKillProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, killPid);
//        TerminateProcess(hKillProcess, 0);
//    }
    return oGetProcAddress(hModule, lpProcName);
}

// Our hook function for memcpy
//void* hookedMemcpy(void* dest, const void* src, size_t count)
//{
//    memcpyCalled = TRUE;
//    if (memcpyCalled) {
//        MessageBoxW(HWND_DESKTOP, L"Reflective injection detected(memcpy). Killing Process.", L"Ghetto EDR", MB_OK);
//        //DWORD killPid = GetCurrentProcessId();
//        //HANDLE hKillProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, killPid);
//        //TerminateProcess(hKillProcess, 0);
//    }
//    return omemcpy(dest, src, count);
//}

// Our hook function for CreateRemoteThread
//HANDLE WINAPI hookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
//{
//    // Check if CreateRemoteThread has been called
//    createRemoteThreadCalled = TRUE;
//    if (CreateRemoteThread) {
//        MessageBoxW(HWND_DESKTOP, L"Reflective injection detected(CreateRemoteThread). Killing Process.", L"Ghetto EDR", MB_OK);
//        DWORD killPid = GetCurrentProcessId();
//        HANDLE hKillProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, killPid);
//        TerminateProcess(hKillProcess, 0);
//    }
//    return oCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
//}

// Our hook function for ReadProcessMemory
//BOOL WINAPI hookedReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
//{
//    readProcessMemoryCalled = TRUE;
//    if (readProcessMemoryCalled) {
//        MessageBoxW(HWND_DESKTOP, L"Reflective injection detected(ReadProcessMemory). Killing Process.", L"Ghetto EDR", MB_OK);
//        //DWORD killPid = GetCurrentProcessId();
//        //HANDLE hKillProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, killPid);
//        //TerminateProcess(hKillProcess, 0);
//    }
//    return oReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
//}

// our hook function for createProcess
BOOL WINAPI hookedCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    createProcessCalled = TRUE;
    if (createProcessCalled && loadLibraryCalled && virtualAllocCalled && getProcAddressCalled) {
        MessageBoxW(HWND_DESKTOP, L"Reflective injection detected (the best detection logic on earth, look at source code to find out). Killing Process.", L"Ghetto EDR", MB_OK);
        DWORD killPid = GetCurrentProcessId();
        HANDLE hKillProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, killPid);
        TerminateProcess(hKillProcess, 0);
    }
    return oCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
        dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

// Our hook function for VirtualProtect
//BOOL WINAPI hookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
//{
//    virtualProtectCalled = TRUE;
//    if (virtualProtectCalled) {
//        MessageBoxW(HWND_DESKTOP, L"Reflective injection detected(VirtualProtect). Killing Process.", L"Ghetto EDR", MB_OK);
//        //DWORD killPid = GetCurrentProcessId();
//        //HANDLE hKillProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, killPid);
//        //TerminateProcess(hKillProcess, 0);
//    }
//    return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
//}

// Our hook function for VirtualAllocEx
//LPVOID WINAPI hookedVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
//{
//    virtualAllocExCalled = TRUE;
//    if (virtualAllocExCalled) {
//        MessageBoxW(HWND_DESKTOP, L"Reflective injection detected(VirtualAllocEx). Killing Process.", L"Ghetto EDR", MB_OK);
//        //DWORD killPid = GetCurrentProcessId();
//        //HANDLE hKillProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, killPid);
//        //TerminateProcess(hKillProcess, 0);
//    }
//    return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
//}

// Our hook function for WriteProcessMemory
//BOOL WINAPI hookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
//{
//    writeProcessMemoryCalled = TRUE;
//    if (writeProcessMemoryCalled) {
//        MessageBoxW(HWND_DESKTOP, L"Reflective injection detected(WriteProcessMemory). Killing Process.", L"Ghetto EDR", MB_OK);
//        //DWORD killPid = GetCurrentProcessId();
//        //HANDLE hKillProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, killPid);
//        //TerminateProcess(hKillProcess, 0);
//    }
//    return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
//}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // Apply our hooks
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)oLoadLibrary, hookedLoadLibrary);
        DetourAttach(&(PVOID&)oVirtualAlloc, hookedVirtualAlloc);
        DetourAttach(&(PVOID&)oGetProcAddress, hookedGetProcAddress);
        //DetourAttach(&(PVOID&)omemcpy, hookedMemcpy);
        //DetourAttach(&(PVOID&)oCreateRemoteThread, hookedCreateRemoteThread);
        //DetourAttach(&(PVOID&)oReadProcessMemory, hookedReadProcessMemory);
        DetourAttach(&(PVOID&)oCreateProcessA, hookedCreateProcessA);
        //DetourAttach(&(PVOID&)oVirtualProtect, hookedVirtualProtect);
        //DetourAttach(&(PVOID&)oVirtualAllocEx, hookedVirtualAllocEx);
        //DetourAttach(&(PVOID&)oWriteProcessMemory, hookedWriteProcessMemory);

        LONG lError = DetourTransactionCommit();
        if (lError != NO_ERROR) {
            MessageBoxW(HWND_DESKTOP, L"Could not add detour", L"Detour Error", MB_OK);
            return FALSE;
        }
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}