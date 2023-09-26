// monitorEntryPoint.c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

int monitorProcess(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL)
    {
        printf("OpenProcess failed for PID %d. Error: %d\n", pid, GetLastError());
        return -1;
    }

    // Get the base address of the module
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        printf("EnumProcessModules failed. Error: %d\n", GetLastError());
        return -1;
    }

    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
    {
        char szModName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char)))
        {
            // Check if this module is amsi.dll
            if (strstr(szModName, "amsi.dll") != NULL)
            {
                // Get the module information to find the entry point
                MODULEINFO modInfo;
                if (!GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
                {
                    printf("GetModuleInformation failed. Error: %d\n", GetLastError());
                    return -1;
                }

                // Print the entry point address and size
                printf("Entry point address: %p\n", modInfo.EntryPoint);
                printf("Size of the module: %lu\n", modInfo.SizeOfImage);

                // Store the original entry point contents
                unsigned char originalEntryPoint[1024];
                SIZE_T bytesRead;
                if (!ReadProcessMemory(hProcess, modInfo.EntryPoint, originalEntryPoint, sizeof(originalEntryPoint), &bytesRead))
                {
                    printf("ReadProcessMemory failed. Error: %d\n", GetLastError());
                    return -1;
                }

                while (1)
                {
                    // Compare the current entry point contents with the original
                    unsigned char currentEntryPoint[1024];
                    if (!ReadProcessMemory(hProcess, modInfo.EntryPoint, currentEntryPoint, sizeof(currentEntryPoint), &bytesRead))
                    {
                        printf("ReadProcessMemory failed. Error: %d\n", GetLastError());
                        return -1;
                    }

                    if (memcmp(originalEntryPoint, currentEntryPoint, sizeof(originalEntryPoint)) != 0)
                    {
                        printf("Shellcode has been loaded into the entry point!\n");
                        break;
                    }

                    Sleep(100); // Wait for 100 milliseconds before checking again
                }
            }
        }
    }

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
            // Monitor all processes
            if (monitorProcess(pe.th32ProcessID) == -1)
            {
                printf("Skipping PID %d\n", pe.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe));

        CloseHandle(hSnapshot);

        Sleep(1000); // Wait for 1 second before checking again
    }

    return 0;
}