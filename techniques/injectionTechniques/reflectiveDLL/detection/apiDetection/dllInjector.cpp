#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <set>

// Injects the DLL at dllPath into the process with processId
BOOL InjectDLL(DWORD processId, const char* dllPath)
{
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL)
    {
        std::cout << "OpenProcess failed: " << GetLastError() << std::endl;
        return FALSE;
    }

    std::cout << "OpenProcess called!" << std::endl;

    // Allocate memory in the target process for the DLL's path
    LPVOID dllPathAddress = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (dllPathAddress == NULL)
    {
        std::cout << "VirtualAllocEx failed: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    std::cout << "VirtualAllocEx called!" << std::endl;

    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, dllPathAddress, dllPath, strlen(dllPath) + 1, NULL))
    {
        std::cout << "WriteProcessMemory failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    std::cout << "WriteProcessMemory called!" << std::endl;

    // Get the address of the LoadLibrary function
    LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddress == NULL)
    {
        std::cout << "GetProcAddress failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    std::cout << "GetProcAddress called!" << std::endl;

    // Create a remote thread that calls LoadLibraryA with the address of the DLL path as argument
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddress, 0, NULL);
    if (hThread == NULL)
    {
        std::cout << "CreateRemoteThread failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    std::cout << "CreateRemoteThread called!" << std::endl;

    // Wait for the remote thread to terminate
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

void InjectIntoNewProcesses(const char* dllPath)
{
    std::set<DWORD> knownProcessIds;

    while (true)
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            std::cout << "CreateToolhelp32Snapshot failed: " << GetLastError() << std::endl;
            return;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);

        if (!Process32First(hSnapshot, &pe))
        {
            std::cout << "Process32First failed: " << GetLastError() << std::endl;
            CloseHandle(hSnapshot);
            return;
        }

        do
        {
            // Check if this is a reflect_dll process and we haven't injected into it yet
            if (_stricmp(pe.szExeFile, "reflect_dll.exe") == 0 && knownProcessIds.find(pe.th32ProcessID) == knownProcessIds.end())
            {
                if (InjectDLL(pe.th32ProcessID, dllPath))
                {
                    std::cout << "Injected into reflect_dll process: " << pe.th32ProcessID << std::endl;
                    knownProcessIds.insert(pe.th32ProcessID);
                }
                else
                {
                    std::cout << "Failed to inject into reflect_dll process: " << pe.th32ProcessID << std::endl;
                }
            }
        } while (Process32Next(hSnapshot, &pe));

        CloseHandle(hSnapshot);

        // Wait a bit before scanning for processes again
        Sleep(1000);
    }
}

int main()
{
    const char* dllPath = "C:\\Users\\loki\\Desktop\\demoDll.dll"; // Replace with the path to your DLL
    InjectIntoNewProcesses(dllPath);

    return 0;
}