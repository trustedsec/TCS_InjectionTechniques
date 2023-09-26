// dllHollowingMonLoader.c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

int monitorProcess(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL)
    {
        printf("OpenProcess failed for PID %d. Error: %d\n", pid, GetLastError());
        return -1;
    }

    
    char* dllPath = "C:\\Windows\\System32\\dllDetectDllHollowing.dll";
    

    void* pDllPath = VirtualAllocEx(hProcess, 0, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    SIZE_T bytesWritten;
    WriteProcessMemory(hProcess, pDllPath, (void*)dllPath, strlen(dllPath) + 1, &bytesWritten);


    FARPROC hLoadLibrary = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, pDllPath, 0, NULL);

    if (hThread != NULL)
    {
        printf("Successfully injected DLL into process %d\n", pid);
    }
    else
    {
        printf("Failed to inject DLL into process %d. Error: %d\n", pid, GetLastError());
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pDllPath, strlen(dllPath) + 1, MEM_RELEASE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

int main()
{
    while (1) // Infinite loop
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            printf("CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError());
            return 1;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);

        if (!Process32First(hSnapshot, &pe))
        {
            printf("Process32First failed. Error: %d\n", GetLastError());
            CloseHandle(hSnapshot);
            return 1;
        }

        do
        {
            // Check if the process name matches the one we're looking for
            if (_stricmp(pe.szExeFile, "dll_hollowing_cs.exe") == 0)
            {
                if (monitorProcess(pe.th32ProcessID) == -1)
                {
                    printf("Skipping PID %d\n", pe.th32ProcessID);
                }
            }
        } while (Process32Next(hSnapshot, &pe));

        CloseHandle(hSnapshot);

        Sleep(1000); // Wait for 1 second before checking again
    }

    return 0;
}