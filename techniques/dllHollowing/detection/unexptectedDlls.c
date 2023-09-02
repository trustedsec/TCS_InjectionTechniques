#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <tlhelp32.h>

void checkProcesses() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    HANDLE hProcess;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i;

    // Take a snapshot of all processes in the system.
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError());
        return;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hSnapshot, &pe32)) { // Returns the first process in the snapshot
        printf("Process32First failed. Error: %d\n", GetLastError()); // Returns the last error that occurred
        CloseHandle(hSnapshot); // Must clean up the snapshot object!
        return;
    }

    // Now walk the snapshot of processes
    do {
        // Open the process
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);  // Returns a handle to an existing process object
        if (hProcess != NULL) {
            // Get a list of all the modules in this process.
            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) { // Returns a list of all the modules in the specified process
                for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) { // cbNeeded is the number of bytes required to store all module handles in the lphModule array
                    TCHAR szModName[MAX_PATH];
                    // Get the full path to the module's file.
                    if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {  // Returns the fully qualified path for the file containing the specified module
                        // Check for anomalies in DLL loads
                        // This is a simple check and may not catch all cases
                        // A real-world implementation would need to be much more sophisticated
                        // TODO: Implement the actual check
                    }
                }
            }
            CloseHandle(hProcess);
        }
    } while (Process32Next(hSnapshot, &pe32)); // Returns the next process in the snapshot

    CloseHandle(hSnapshot);
}

int main() { // TODO: Implement the actual check
    while (1) {  // Infinite loop
        checkProcesses();  // Check for anomalies in DLL loads
        Sleep(1000); // Check every second
    }

    return 0;
}