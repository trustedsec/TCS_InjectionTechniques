#include <windows.h>
#include <psapi.h>
#include <stdio.h>

void searchForSequence(unsigned char* buffer, SIZE_T size) {
    unsigned char sequence[] = {0xc0, 0xa8, 0x1c, 0x85};
    SIZE_T sequenceLength = sizeof(sequence);

    for (SIZE_T i = 0; i < size - sequenceLength + 1; i++) {
        if (memcmp(buffer + i, sequence, sequenceLength) == 0) {
            printf("Found sequence at position %llu\n", i);
        }
    }
}

void dumpShellcodeAndSearchSequence(HANDLE process, MODULEINFO mi) {
    unsigned char* buffer = (unsigned char*)malloc(mi.SizeOfImage);
    SIZE_T bytesRead;

    if (ReadProcessMemory(process, mi.lpBaseOfDll, buffer, mi.SizeOfImage, &bytesRead)) {
        // Search for the sequence in the buffer
        searchForSequence(buffer, bytesRead);
    }

    free(buffer);
}

void checkForDllHollowing(DWORD processID) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (NULL == process)
        return;

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];

            if (GetModuleFileNameEx(process, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                // Check if the module is amsi.dll and the process is dll_hollowing.exe
                if (strstr(szModName, "amsi.dll") != NULL && strstr(szModName, "dll_hollowing.exe") != NULL) {
                    MODULEINFO mi;
                    if (GetModuleInformation(process, hMods[i], &mi, sizeof(mi))) {
                        dumpShellcodeAndSearchSequence(process, mi);
                    }
                }
            }
        }
    }

    CloseHandle(process);
}

int main() {
    DWORD aProcesses[1024], cbNeeded, cProcesses;

    while (1) { // Run indefinitely
        if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
            return 1;

        cProcesses = cbNeeded / sizeof(DWORD);

        for (unsigned int i = 0; i < cProcesses; i++) {
            if (aProcesses[i] != 0) {
                checkForDllHollowing(aProcesses[i]);
            }
        }

        Sleep(1000); // Wait for a second before checking again
    }

    return 0;
}