#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void checkProcesses() { // TODO: Implement the actual check
    HANDLE hSnapshot; // Handle to a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes
    PROCESSENTRY32 pe32; // Contains information about a process encountered in a system snapshot

    // Take a snapshot of all processes in the system.
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError());
        return;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process and exit if unsuccessful
    if (!Process32First(hSnapshot, &pe32)) {
        printf("Process32First failed. Error: %d\n", GetLastError());
        CloseHandle(hSnapshot); // Must clean up the snapshot object!
        return;
    }

    // Now walk the snapshot of processes
    do {
        // Check if the process is suspicious
        if (_stricmp(pe32.szExeFile, "amsi.dll") == 0) {
            printf("Suspicious process detected: %s (PID: %d)\n", pe32.szExeFile, pe32.th32ProcessID);
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
}

int main() {
    while (1) {
        checkProcesses();
        Sleep(1000); // Check every second
    }

    return 0;
}