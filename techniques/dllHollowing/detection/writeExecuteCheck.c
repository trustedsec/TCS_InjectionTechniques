/*
 * This function checks all running processes and prints a warning if a process has a memory region that is both
 * executable and writable. This is a common technique used by malware to inject code into other processes.
 *
 * This function is not used in the final version of the program, but is included here for reference.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void checkProcesses() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed (%d)\n", GetLastError());
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        printf("Process32First failed (%d)\n", GetLastError());
        CloseHandle(hSnapshot);
        return;
    }

    do {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

        if (hProcess != NULL) {
            if (VirtualQueryEx(hProcess, NULL, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if ((mbi.Protect & PAGE_EXECUTE_READWRITE) && (mbi.Type & MEM_PRIVATE)) {
                    printf("Suspicious process detected: %s (PID: %d)\n", pe32.szExeFile, pe32.th32ProcessID);
                }
            }

            CloseHandle(hProcess);
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
}

int main() {
    while(1) {
        checkProcesses();
        Sleep(5000); // Sleep for 5 seconds
    }
    return 0;
}