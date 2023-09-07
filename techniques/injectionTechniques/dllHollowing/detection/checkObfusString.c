#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void checkProcesses() { // 
    HANDLE hSnapshot; // Handle to a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes
    PROCESSENTRY32 pe32; // Contains information about a process encountered in a system snapshot
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;

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
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID); // Returns a handle to an existing process object
        if (hProcess != NULL) { // Check if the process is suspicious
            DWORD dwAddress = 0; // Address of the first byte of the region to be queried
            while (VirtualQueryEx(hProcess, (LPVOID)dwAddress, &mbi, sizeof(mbi))) { // Returns information about a range of pages in the virtual address space of the specified process
                if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)) { // Check if the memory region is executable
                    BYTE *buffer = (BYTE*)malloc(mbi.RegionSize); // Allocate memory for the buffer
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, NULL)) { // Reads data from an area of memory in a specified process
                        for (SIZE_T i = 0; i < mbi.RegionSize - 4; i++) { // Check if the memory region contains the string "PPPP"
                            if (buffer[i] == 0x80 && buffer[i+1] == 0x80 && buffer[i+2] == 0x80 && buffer[i+3] == 0x80) { // TODO: Implement the actual check
                                printf("Suspicious process detected: %s (PID: %d)\n", pe32.szExeFile, pe32.th32ProcessID); // Print out the name of the process
                                break;
                            }
                        }
                    }
                    free(buffer);
                }
                dwAddress += mbi.RegionSize;
            }
            CloseHandle(hProcess);
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