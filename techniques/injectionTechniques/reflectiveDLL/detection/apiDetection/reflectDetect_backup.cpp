#include <windows.h>
#include "detours.h"

BOOL openProcessCalled = FALSE;
BOOL virtualAllocExCalled = FALSE;
BOOL writeProcessMemoryCalled = FALSE;
BOOL createRemoteThreadExCalled = FALSE;

// Hooked API calls related to standard process injection
LPVOID(WINAPI* oOpenProcess)(DWORD, BOOL, DWORD) = OpenProcess;
LPVOID(WINAPI* oVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = VirtualAllocEx;
BOOL(WINAPI* oWriteProcessMemory)(HANDLE, LPVOID,LPCVOID,SIZE_T,SIZE_T*) = WriteProcessMemory;
HANDLE(WINAPI* oCreateRemoteThreadEx)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD) = CreateRemoteThreadEx;

// Our hook function for OpenProcess
LPVOID WINAPI hookedOpenProcess(DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwProcessId)
{
    openProcessCalled = TRUE;
    return oOpenProcess(dwDesiredAccess,bInheritHandle,dwProcessId);
}

// Our hook function for VirtualAllocEx
LPVOID WINAPI hookedVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    virtualAllocExCalled = TRUE;
    return oVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

// Our hook function for WriteProcessMemory
BOOL WINAPI hookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    writeProcessMemoryCalled = TRUE;
    return oWriteProcessMemory(hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesWritten);
}

// Our hook function for CreateRemoteThreadEx
HANDLE WINAPI hookedCreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId)
{
    // Naive logic to see if the APIs related process injection have been called
    // This is a very hacky PoC chaeck 
    if (openProcessCalled && virtualAllocExCalled && writeProcessMemoryCalled) {
    
        // Setup to reflective injection detected. Kill the process
		    MessageBox(HWND_DESKTOP, L"Reflective injection detected. Killing Process.", L"Poor Mans NGAV", MB_OK);
        DWORD killPid = GetCurrentProcessId();
        HANDLE hKillProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, killPid);
        TerminateProcess(hKillProcess, 0);
    }
    return oCreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList,lpThreadId);
}

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
        DetourAttach(&(PVOID&)oOpenProcess, hookedOpenProcess);
        DetourAttach(&(PVOID&)oVirtualAllocEx, hookedVirtualAllocEx);
        DetourAttach(&(PVOID&)oWriteProcessMemory, hookedWriteProcessMemory);
        DetourAttach(&(PVOID&)oCreateRemoteThreadEx, hookedCreateRemoteThreadEx);

        LONG lError = DetourTransactionCommit();
        if (lError != NO_ERROR) {
            MessageBox(HWND_DESKTOP, L"Could not add detour", L"Detour Error", MB_OK);
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